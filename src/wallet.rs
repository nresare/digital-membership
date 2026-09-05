use anyhow::Context;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
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
    certificate: X509,
    private_key: PKey<Private>,
    certificate_chain: Vec<X509>,
    pass_type_identifier: String,
    team_identifier: String,
    organization_name: String,
}

impl WalletPass {
    pub(crate) fn load(config: WalletConfig) -> anyhow::Result<Self> {
        let key_bytes = std::fs::read(&config.key_path).with_context(|| {
            format!("failed to read Wallet key '{}'", config.key_path.display())
        })?;
        let private_key = PKey::private_key_from_pem_callback(&key_bytes, |_| {
            // Encrypted keys are unsupported; never prompt on server startup.
            Ok(0)
        })
        .context("failed to parse Wallet private key as unencrypted PEM")?;
        let certificate = read_pem_certificate(&config.cert_path, "cert_path")?;
        anyhow::ensure!(
            certificate.public_key()?.public_eq(&private_key),
            "Wallet private key does not match the certificate in cert_path"
        );
        let intermediate = match &config.intermediate_cert_path {
            Some(path) => read_pem_certificate(path, "intermediate_cert_path")?,
            None => embedded_intermediate(&certificate)?,
        };
        anyhow::ensure!(
            certificate.issuer_name().to_der()? == intermediate.subject_name().to_der()?
                && certificate.verify(intermediate.public_key()?.as_ref())?,
            "Wallet intermediate certificate did not issue the certificate in cert_path; \
             configure intermediate_cert_path with the matching PEM certificate, probably available from \
             https://www.apple.com/certificateauthority/"
        );
        let pass_type_identifier = subject_identifier(&certificate, Nid::USERID, "UID")?;
        anyhow::ensure!(
            pass_type_identifier.starts_with("pass.") && pass_type_identifier.len() > 5,
            "Wallet certificate subject UID must be a Pass Type identifier starting with 'pass.'"
        );
        let team_identifier = subject_identifier(&certificate, Nid::ORGANIZATIONALUNITNAME, "OU")?;
        anyhow::ensure!(
            !config.org_name.trim().is_empty(),
            "wallet.org_name must not be empty"
        );
        Ok(Self {
            certificate,
            private_key,
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
        let mut certificates = Stack::new()?;
        for certificate in &self.certificate_chain {
            certificates.push(certificate.clone())?;
        }
        let signature = Pkcs7::sign(
            &self.certificate,
            &self.private_key,
            &certificates,
            manifest,
            Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY,
        )?;
        Ok(signature.to_der()?)
    }
}

fn read_pem_certificate(path: &Path, setting: &str) -> anyhow::Result<X509> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read Wallet {setting} '{}'", path.display()))?;
    let mut certificates = X509::stack_from_pem(&bytes).with_context(|| {
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

fn embedded_intermediate(certificate: &X509) -> anyhow::Result<X509> {
    let authority_key_id = certificate.authority_key_id();
    anyhow::ensure!(
        authority_key_id.as_ref().map(|id| id.as_slice())
            == Some(WWDR_G4_SUBJECT_KEY_ID.as_slice()),
        "Wallet certificate Authority Key Identifier ({}) does not reference the embedded WWDR G4 certificate; \
         use intermediate_cert_path to configure the matching PEM intermediate certificate, \
         which is probably available from https://www.apple.com/certificateauthority/",
        authority_key_id
            .as_ref()
            .map(|id| to_hex(id.as_slice()))
            .unwrap_or_else(|| "missing".into())
    );
    X509::from_pem(WWDR_G4_PEM).context("failed to parse embedded WWDR G4 certificate")
}

fn subject_identifier(certificate: &X509, nid: Nid, label: &str) -> anyhow::Result<String> {
    let mut entries = certificate.subject_name().entries_by_nid(nid);
    let entry = entries
        .next()
        .with_context(|| format!("Wallet certificate subject is missing {label}"))?;
    anyhow::ensure!(
        entries.next().is_none(),
        "Wallet certificate subject contains multiple {label} values"
    );
    let value = entry.data().to_string()?;
    anyhow::ensure!(
        !value.trim().is_empty(),
        "Wallet certificate subject {label} must not be empty"
    );
    Ok(value)
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
mod tests {
    use super::{WalletPass, to_hex};
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkcs7::Pkcs7;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};
    use serde_json::Value;
    use sha1::{Digest as _, Sha1};
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read};
    use zip::ZipArchive;

    #[test]
    fn builds_signed_pass_with_byte_preserving_qr_payload() {
        let (private_key, certificate) = self_signed_certificate("Pass signer");
        let (_, wwdr_certificate) = self_signed_certificate("Test WWDR");
        let wallet = WalletPass {
            certificate,
            private_key,
            certificate_chain: vec![wwdr_certificate],
            pass_type_identifier: "pass.example.membership".into(),
            team_identifier: "TEAM123456".into(),
            organization_name: "Example Membership".into(),
        };
        let credential: Vec<u8> = (0..=255).collect();

        let bytes = wallet.build("Alice Smith", &credential).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut files = BTreeMap::new();
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).unwrap();
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();
            files.insert(file.name().to_string(), contents);
        }

        for required in [
            "pass.json",
            "icon.png",
            "icon@2x.png",
            "icon@3x.png",
            "manifest.json",
            "signature",
        ] {
            assert!(files.contains_key(required), "missing {required}");
        }
        Pkcs7::from_der(&files["signature"]).unwrap();

        let manifest: BTreeMap<String, String> =
            serde_json::from_slice(&files["manifest.json"]).unwrap();
        for (name, expected_hash) in manifest {
            assert_eq!(to_hex(&Sha1::digest(&files[&name])), expected_hash);
        }

        let pass: Value = serde_json::from_slice(&files["pass.json"]).unwrap();
        assert_eq!(pass["generic"]["primaryFields"][0]["value"], "Alice Smith");
        assert_eq!(pass["barcodes"][0]["messageEncoding"], "iso-8859-1");
        let decoded: Vec<u8> = pass["barcodes"][0]["message"]
            .as_str()
            .unwrap()
            .chars()
            .map(|character| u8::try_from(u32::from(character)).unwrap())
            .collect();
        assert_eq!(decoded, credential);
    }

    #[test]
    fn loads_pem_identity_with_explicit_intermediate_and_rejects_invalid_inputs() {
        use super::WalletConfig;
        let directory = std::env::temp_dir().join(format!("wallet-pem-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let key_path = directory.join("key.pem");
        let cert_path = directory.join("chain.pem");
        let (issuer_key, issuer) = self_signed_certificate("Test intermediate");
        let (key, _) = self_signed_certificate("Pass signer");
        let mut subject = X509NameBuilder::new().unwrap();
        subject
            .append_entry_by_text("UID", "pass.example.test")
            .unwrap();
        subject.append_entry_by_text("OU", "ABCDE12345").unwrap();
        let mut leaf = X509::builder().unwrap();
        leaf.set_version(2).unwrap();
        leaf.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(2).unwrap()).unwrap())
            .unwrap();
        leaf.set_subject_name(&subject.build()).unwrap();
        leaf.set_issuer_name(issuer.subject_name()).unwrap();
        leaf.set_pubkey(&key).unwrap();
        leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        leaf.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        leaf.sign(&issuer_key, MessageDigest::sha256()).unwrap();
        let leaf = leaf.build();
        let intermediate_path = directory.join("intermediate.pem");
        std::fs::write(&intermediate_path, issuer.to_pem().unwrap()).unwrap();
        let config = || WalletConfig {
            key_path: key_path.clone(),
            cert_path: cert_path.clone(),
            intermediate_cert_path: Some(intermediate_path.clone()),
            org_name: "Test".into(),
        };
        std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        std::fs::write(&cert_path, leaf.to_pem().unwrap()).unwrap();
        let wallet = super::WalletPass::load(config()).unwrap();
        assert_eq!(wallet.pass_type_identifier, "pass.example.test");
        assert_eq!(wallet.team_identifier, "ABCDE12345");
        let bytes = wallet.build("Alice Smith", b"test credential").unwrap();
        let mut zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut manifest = Vec::new();
        zip.by_name("manifest.json")
            .unwrap()
            .read_to_end(&mut manifest)
            .unwrap();
        let mut signature = Vec::new();
        zip.by_name("signature")
            .unwrap()
            .read_to_end(&mut signature)
            .unwrap();
        let signature = Pkcs7::from_der(&signature).unwrap();
        assert_eq!(signature.signed().unwrap().certificates().unwrap().len(), 2);
        signature
            .verify(
                &openssl::stack::Stack::new().unwrap(),
                &openssl::x509::store::X509StoreBuilder::new()
                    .unwrap()
                    .build(),
                Some(&manifest),
                None,
                openssl::pkcs7::Pkcs7Flags::NOVERIFY,
            )
            .unwrap();
        let mut without_override = config();
        without_override.intermediate_cert_path = None;
        let error = super::WalletPass::load(without_override)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("intermediate_cert_path"));
        assert!(error.contains("https://www.apple.com/certificateauthority/"));
        std::fs::write(&intermediate_path, leaf.to_pem().unwrap()).unwrap();
        assert!(
            super::WalletPass::load(config())
                .err()
                .unwrap()
                .to_string()
                .contains("did not issue")
        );
        std::fs::write(&intermediate_path, issuer.to_pem().unwrap()).unwrap();
        std::fs::write(&key_path, issuer_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        assert!(
            super::WalletPass::load(config())
                .err()
                .unwrap()
                .to_string()
                .contains("does not match")
        );
        std::fs::write(
            &cert_path,
            [issuer.to_pem().unwrap(), leaf.to_pem().unwrap()].concat(),
        )
        .unwrap();
        assert!(
            super::WalletPass::load(config())
                .err()
                .unwrap()
                .to_string()
                .contains("exactly one PEM certificate")
        );
        assert!(
            super::subject_identifier(&issuer, openssl::nid::Nid::USERID, "UID")
                .unwrap_err()
                .to_string()
                .contains("missing UID")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn selects_embedded_intermediate_by_authority_key_id() {
        use openssl::x509::extension::AuthorityKeyIdentifier;
        let intermediate = X509::from_pem(super::WWDR_G4_PEM).unwrap();
        assert_eq!(
            intermediate.subject_key_id().unwrap().as_slice(),
            super::WWDR_G4_SUBJECT_KEY_ID
        );
        let (key, _) = self_signed_certificate("Test key");
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(3).unwrap()).unwrap())
            .unwrap();
        certificate
            .set_subject_name(intermediate.subject_name())
            .unwrap();
        certificate
            .set_issuer_name(intermediate.subject_name())
            .unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let authority = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&certificate.x509v3_context(Some(&intermediate), None))
            .unwrap();
        certificate.append_extension(authority).unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();
        assert_eq!(
            super::embedded_intermediate(&certificate)
                .unwrap()
                .to_der()
                .unwrap(),
            intermediate.to_der().unwrap()
        );
        // The intermediate's AKI points to Apple's root, not to WWDR G4.
        let error = super::embedded_intermediate(&intermediate)
            .unwrap_err()
            .to_string();
        assert!(error.contains("intermediate_cert_path"));
        assert!(error.contains("https://www.apple.com/certificateauthority/"));
    }

    fn self_signed_certificate(common_name: &str) -> (PKey<Private>, X509) {
        let private_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        let serial = Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap();
        certificate.set_serial_number(&serial).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&private_key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate
            .sign(&private_key, MessageDigest::sha256())
            .unwrap();
        (private_key, certificate.build())
    }
}
