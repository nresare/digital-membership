use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkcs12::Pkcs12;
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

const ICON_SIZES: [(&str, u32); 3] = [("icon.png", 29), ("icon@2x.png", 58), ("icon@3x.png", 87)];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletConfig {
    #[serde(rename = "pkcs12")]
    pub pkcs12_path: PathBuf,
    #[serde(default)]
    pub pkcs12_password: String,
    #[serde(rename = "wwdr_certificate")]
    pub wwdr_certificate_path: PathBuf,
    pub pass_type_identifier: String,
    pub team_identifier: String,
    #[serde(default = "default_organization_name")]
    pub organization_name: String,
}

fn default_organization_name() -> String {
    "Digital Membership".to_string()
}

pub(crate) struct WalletPass {
    certificate: X509,
    private_key: PKey<Private>,
    wwdr_certificate: X509,
    pass_type_identifier: String,
    team_identifier: String,
    organization_name: String,
}

impl WalletPass {
    pub(crate) fn load(config: WalletConfig) -> anyhow::Result<Self> {
        let identity_bytes = std::fs::read(&config.pkcs12_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to read Wallet PKCS#12 identity '{}': {error}",
                config.pkcs12_path.display()
            )
        })?;
        let identity = Pkcs12::from_der(&identity_bytes)
            .and_then(|pkcs12| pkcs12.parse2(&config.pkcs12_password))
            .map_err(|error| anyhow::anyhow!("failed to parse Wallet PKCS#12 identity: {error}"))?;
        let certificate = identity
            .cert
            .ok_or_else(|| anyhow::anyhow!("Wallet PKCS#12 identity contains no certificate"))?;
        let private_key = identity
            .pkey
            .ok_or_else(|| anyhow::anyhow!("Wallet PKCS#12 identity contains no private key"))?;
        let wwdr_certificate =
            read_certificate(&config.wwdr_certificate_path).map_err(|error| {
                anyhow::anyhow!(
                    "failed to read WWDR certificate '{}': {error}",
                    config.wwdr_certificate_path.display()
                )
            })?;

        Ok(Self {
            certificate,
            private_key,
            wwdr_certificate,
            pass_type_identifier: config.pass_type_identifier,
            team_identifier: config.team_identifier,
            organization_name: config.organization_name,
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
        certificates.push(self.wwdr_certificate.clone())?;
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

fn read_certificate(path: &Path) -> anyhow::Result<X509> {
    let bytes = std::fs::read(path)?;
    X509::from_pem(&bytes)
        .or_else(|_| X509::from_der(&bytes))
        .map_err(Into::into)
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
            wwdr_certificate,
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
