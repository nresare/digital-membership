use anyhow::Context;
use cms::builder::{SignedDataBuilder, SignerInfoBuilder, create_signing_time_attribute};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::{
    Ia5StringRef, ObjectIdentifier, PrintableStringRef, TeletexStringRef, Utf8StringRef,
};
use der::{Decode, DecodePem, Encode, Tag, Tagged};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use signature::{Keypair, Signer, Verifier};
use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;

const WWDR_G4_PEM: &[u8] = include_bytes!("certificates/AppleWWDRCAG4.pem");
// Matches the Authority Key Identifier in passes issued by WWDR G4.
const WWDR_G4_SUBJECT_KEY_ID: [u8; 20] = [
    0x5b, 0xd9, 0xfa, 0x1d, 0xe7, 0x9a, 0x1a, 0x0b, 0xa3, 0x99, 0x76, 0x22, 0x50, 0x86, 0x3e, 0x91,
    0xc8, 0x5b, 0x77, 0xa8,
];
const USER_ID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.1");
const ORGANIZATIONAL_UNIT_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const AUTHORITY_KEY_IDENTIFIER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const SUBJECT_KEY_IDENTIFIER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA256_WITH_RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

const ICON_SIZES: [(&str, u32); 3] = [("icon.png", 29), ("icon@2x.png", 58), ("icon@3x.png", 87)];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletConfig {
    pub key_path: PathBuf,
    /// PEM Pass Type certificate.
    pub cert_path: PathBuf,
    pub intermediate_cert_path: Option<PathBuf>,
    #[serde(default = "default_org_name")]
    pub org_name: String,
}

fn default_org_name() -> String {
    "Digital Membership".to_string()
}

pub(crate) struct WalletPass {
    certificate: x509_cert::Certificate,
    private_key: BlindedRsaSigningKey,
    certificate_chain: Vec<x509_cert::Certificate>,
    pass_type_identifier: String,
    team_identifier: String,
    organization_name: String,
}

impl WalletPass {
    pub(crate) fn load(config: WalletConfig) -> anyhow::Result<Self> {
        let key_bytes = std::fs::read(&config.key_path).with_context(|| {
            format!("failed to read Wallet key '{}'", config.key_path.display())
        })?;
        let key_text = std::str::from_utf8(&key_bytes)
            .context("failed to parse Wallet private key as PEM: file is not UTF-8")?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(key_text)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(key_text))
            .context("failed to parse Wallet private key as unencrypted PKCS#8 or PKCS#1 PEM")?;
        private_key
            .validate()
            .context("Wallet private key failed RSA validation")?;
        let certificate = read_pem_certificate(&config.cert_path, "cert_path")?;
        let certificate_public_key = certificate_public_key(&certificate)
            .context("failed to read RSA public key from Wallet certificate")?;
        anyhow::ensure!(
            certificate_public_key == RsaPublicKey::from(&private_key),
            "Wallet private key does not match the certificate in cert_path"
        );
        let intermediate = match &config.intermediate_cert_path {
            Some(path) => read_pem_certificate(path, "intermediate_cert_path")?,
            None => embedded_intermediate(&certificate)?,
        };
        anyhow::ensure!(
            certificate.tbs_certificate.issuer == intermediate.tbs_certificate.subject
                && verify_certificate_signature(&certificate, &intermediate).is_ok(),
            "Wallet intermediate certificate did not issue the certificate in cert_path; \
             configure intermediate_cert_path with the matching PEM certificate, probably available from \
             https://www.apple.com/certificateauthority/"
        );
        let pass_type_identifier = subject_identifier(&certificate, USER_ID_OID, "UID")?;
        anyhow::ensure!(
            pass_type_identifier.starts_with("pass.") && pass_type_identifier.len() > 5,
            "Wallet certificate subject UID must be a Pass Type identifier starting with 'pass.'"
        );
        let team_identifier = subject_identifier(&certificate, ORGANIZATIONAL_UNIT_NAME_OID, "OU")?;
        anyhow::ensure!(
            !config.org_name.trim().is_empty(),
            "wallet.org_name must not be empty"
        );
        Ok(Self {
            certificate,
            private_key: BlindedRsaSigningKey(SigningKey::new(private_key)),
            certificate_chain: vec![intermediate],
            pass_type_identifier,
            team_identifier,
            organization_name: config.org_name,
        })
    }

    pub(crate) fn build(&self, name: &str, credential: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut files = BTreeMap::new();
        let pass = PassJson {
            format_version: 1,
            pass_type_identifier: &self.pass_type_identifier,
            serial_number: to_hex(&Sha256::digest(credential)),
            team_identifier: &self.team_identifier,
            organization_name: &self.organization_name,
            description: "Digital membership card",
            logo_text: &self.organization_name,
            foreground_color: "rgb(255, 255, 255)",
            background_color: "rgb(25, 55, 95)",
            generic: Generic {
                primary_fields: [PassField {
                    key: "memberName",
                    label: "MEMBER",
                    value: name,
                }],
            },
            barcodes: [Barcode {
                format: "PKBarcodeFormatQR",
                message: credential.iter().map(|byte| char::from(*byte)).collect(),
                message_encoding: "iso-8859-1",
            }],
        };
        files.insert("pass.json".to_string(), serde_json::to_vec(&pass)?);
        for (filename, size) in ICON_SIZES {
            files.insert(filename.to_string(), solid_icon(size)?);
        }

        let manifest: BTreeMap<&str, String> = files
            .iter()
            .map(|(name, contents)| (name.as_str(), to_hex(&Sha1::digest(contents))))
            .collect();
        let manifest = serde_json::to_vec(&manifest)?;
        let signature = self.sign(&manifest)?;

        let mut output = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut output);
            let options = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644);
            for (name, contents) in files {
                zip.start_file(name, options)?;
                zip.write_all(&contents)?;
            }
            zip.start_file("manifest.json", options)?;
            zip.write_all(&manifest)?;
            zip.start_file("signature", options)?;
            zip.write_all(&signature)?;
            zip.finish()?;
        }
        Ok(output.into_inner())
    }

    fn sign(&self, manifest: &[u8]) -> anyhow::Result<Vec<u8>> {
        let content = EncapsulatedContentInfo {
            econtent_type: DATA_OID,
            econtent: None,
        };
        let digest_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: SHA256_OID,
            parameters: None,
        };
        let signer_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: self.certificate.tbs_certificate.issuer.clone(),
            serial_number: self.certificate.tbs_certificate.serial_number.clone(),
        });
        let manifest_digest = Sha256::digest(manifest);
        let mut signer = SignerInfoBuilder::new(
            &self.private_key,
            signer_identifier,
            digest_algorithm.clone(),
            &content,
            Some(&manifest_digest),
        )
        .map_err(cms_error)?;
        let signing_time = create_signing_time_attribute().map_err(cms_error)?;
        signer
            .add_signed_attribute(signing_time)
            .map_err(cms_error)?;

        let mut signed_data = SignedDataBuilder::new(&content);
        signed_data
            .add_digest_algorithm(digest_algorithm)
            .map_err(cms_error)?
            .add_certificate(CertificateChoices::Certificate(self.certificate.clone()))
            .map_err(cms_error)?;
        for certificate in &self.certificate_chain {
            signed_data
                .add_certificate(CertificateChoices::Certificate(certificate.clone()))
                .map_err(cms_error)?;
        }
        Ok(signed_data
            .add_signer_info::<BlindedRsaSigningKey, rsa::pkcs1v15::Signature>(signer)
            .map_err(cms_error)?
            .build()
            .map_err(cms_error)?
            .to_der()?)
    }
}

/// The stable `rsa` crate's `Signer` implementation does not blind PKCS#1 v1.5
/// private-key operations. Wallet issuance is network-facing, so use the
/// randomized API to mask timing variation while implementing the interface
/// expected by the CMS builder.
struct BlindedRsaSigningKey(SigningKey<Sha256>);

impl Keypair for BlindedRsaSigningKey {
    type VerifyingKey = VerifyingKey<Sha256>;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl x509_cert::spki::DynSignatureAlgorithmIdentifier for BlindedRsaSigningKey {
    fn signature_algorithm_identifier(
        &self,
    ) -> x509_cert::spki::Result<x509_cert::spki::AlgorithmIdentifierOwned> {
        self.0.signature_algorithm_identifier()
    }
}

impl Signer<rsa::pkcs1v15::Signature> for BlindedRsaSigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<rsa::pkcs1v15::Signature, signature::Error> {
        let mut rng = rand::rngs::OsRng;
        let signature = self
            .0
            .as_ref()
            .sign_with_rng(
                &mut rng,
                Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(message),
            )
            .map_err(|_| signature::Error::new())?;
        rsa::pkcs1v15::Signature::try_from(signature.as_slice())
    }
}

fn cms_error(error: cms::builder::Error) -> anyhow::Error {
    anyhow::anyhow!("failed to build Wallet CMS signature: {error}")
}

fn read_pem_certificate(path: &Path, setting: &str) -> anyhow::Result<x509_cert::Certificate> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read Wallet {setting} '{}'", path.display()))?;
    let mut certificates = x509_cert::Certificate::load_pem_chain(&bytes).with_context(|| {
        format!(
            "failed to parse Wallet {setting} '{}' as PEM",
            path.display()
        )
    })?;
    anyhow::ensure!(
        certificates.len() == 1,
        "Wallet {setting} must contain exactly one PEM certificate; use intermediate_cert_path for a separate intermediate"
    );
    Ok(certificates.remove(0))
}

fn embedded_intermediate(
    certificate: &x509_cert::Certificate,
) -> anyhow::Result<x509_cert::Certificate> {
    let authority_key_id = authority_key_identifier(certificate)?;
    anyhow::ensure!(
        authority_key_id.as_deref() == Some(WWDR_G4_SUBJECT_KEY_ID.as_slice()),
        "Wallet certificate Authority Key Identifier ({}) does not reference the embedded WWDR G4 certificate; \
         use intermediate_cert_path to configure the matching PEM intermediate certificate, \
         which is probably available from https://www.apple.com/certificateauthority/",
        authority_key_id
            .as_ref()
            .map(|id| to_hex(id))
            .unwrap_or_else(|| "missing".into())
    );
    let intermediate = x509_cert::Certificate::from_pem(WWDR_G4_PEM)
        .context("failed to parse embedded WWDR G4 certificate")?;
    anyhow::ensure!(
        subject_key_identifier(&intermediate)?.as_deref()
            == Some(WWDR_G4_SUBJECT_KEY_ID.as_slice()),
        "embedded WWDR G4 certificate has an unexpected Subject Key Identifier"
    );
    Ok(intermediate)
}

fn subject_identifier(
    certificate: &x509_cert::Certificate,
    oid: ObjectIdentifier,
    label: &str,
) -> anyhow::Result<String> {
    let mut entries = certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|entry| entry.oid == oid);
    let entry = entries
        .next()
        .with_context(|| format!("Wallet certificate subject is missing {label}"))?;
    anyhow::ensure!(
        entries.next().is_none(),
        "Wallet certificate subject contains multiple {label} values"
    );
    let value = attribute_string(&entry.value)
        .with_context(|| format!("Wallet certificate subject {label} is not a supported string"))?;
    anyhow::ensure!(
        !value.trim().is_empty(),
        "Wallet certificate subject {label} must not be empty"
    );
    Ok(value)
}

fn attribute_string(value: &der::asn1::Any) -> der::Result<String> {
    Ok(match value.tag() {
        Tag::Utf8String => Utf8StringRef::try_from(value)?.as_str(),
        Tag::PrintableString => PrintableStringRef::try_from(value)?.as_str(),
        Tag::Ia5String => Ia5StringRef::try_from(value)?.as_str(),
        Tag::TeletexString => TeletexStringRef::try_from(value)?.as_str(),
        tag => return Err(tag.value_error()),
    }
    .to_string())
}

fn authority_key_identifier(
    certificate: &x509_cert::Certificate,
) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(extension) = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id == AUTHORITY_KEY_IDENTIFIER_OID)
        })
    else {
        return Ok(None);
    };
    let authority =
        x509_cert::ext::pkix::AuthorityKeyIdentifier::from_der(extension.extn_value.as_bytes())?;
    Ok(authority.key_identifier.map(|id| id.as_bytes().to_vec()))
}

fn subject_key_identifier(certificate: &x509_cert::Certificate) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(extension) = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id == SUBJECT_KEY_IDENTIFIER_OID)
        })
    else {
        return Ok(None);
    };
    let identifier =
        x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes())?;
    Ok(Some(identifier.0.as_bytes().to_vec()))
}

fn certificate_public_key(certificate: &x509_cert::Certificate) -> anyhow::Result<RsaPublicKey> {
    Ok(RsaPublicKey::from_public_key_der(
        &certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()?,
    )?)
}

fn verify_certificate_signature(
    certificate: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        certificate.signature_algorithm.oid == SHA256_WITH_RSA_OID
            && certificate.tbs_certificate.signature.oid == SHA256_WITH_RSA_OID,
        "Wallet certificate uses unsupported signature algorithm {}; expected SHA-256 with RSA",
        certificate.signature_algorithm.oid
    );
    let public_key = certificate_public_key(issuer)?;
    let signature = rsa::pkcs1v15::Signature::try_from(
        certificate
            .signature
            .as_bytes()
            .context("Wallet certificate signature has unused bits")?,
    )?;
    VerifyingKey::<Sha256>::new(public_key)
        .verify(&certificate.tbs_certificate.to_der()?, &signature)?;
    Ok(())
}

fn solid_icon(size: u32) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut encoder = png::Encoder::new(&mut output, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    let pixel = [25, 55, 95, 255];
    let image = pixel.repeat((size * size) as usize);
    writer.write_image_data(&image)?;
    writer.finish()?;
    Ok(output)
}

fn to_hex(contents: &[u8]) -> String {
    contents.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassJson<'a> {
    format_version: u8,
    pass_type_identifier: &'a str,
    serial_number: String,
    team_identifier: &'a str,
    organization_name: &'a str,
    description: &'static str,
    logo_text: &'a str,
    foreground_color: &'static str,
    background_color: &'static str,
    generic: Generic<'a>,
    barcodes: [Barcode; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Generic<'a> {
    primary_fields: [PassField<'a>; 1],
}

#[derive(Serialize)]
struct PassField<'a> {
    key: &'static str,
    label: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Barcode {
    format: &'static str,
    message: String,
    message_encoding: &'static str,
}

#[cfg(test)]
#[path = "wallet_tests.rs"]
mod tests;
