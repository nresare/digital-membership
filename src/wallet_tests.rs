use super::*;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::OctetString;
use der::pem::LineEnding;
use der::{Decode, Encode, EncodePem};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use signature::{Keypair, Verifier};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use zip::ZipArchive;

fn test_identity() -> (
    RsaPrivateKey,
    x509_cert::Certificate,
    x509_cert::Certificate,
) {
    let mut rng = rand::thread_rng();
    let intermediate_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let intermediate_signer = SigningKey::<Sha256>::new(intermediate_key);
    let intermediate_name = Name::from_str("CN=Test intermediate").unwrap();
    let intermediate_public_key =
        SubjectPublicKeyInfoOwned::from_key(intermediate_signer.verifying_key()).unwrap();
    let intermediate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        intermediate_name.clone(),
        intermediate_public_key,
        &intermediate_signer,
    )
    .unwrap()
    .build::<rsa::pkcs1v15::Signature>()
    .unwrap();

    let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let public_key = SubjectPublicKeyInfoOwned::from_key(RsaPublicKey::from(&private_key)).unwrap();
    let leaf = CertificateBuilder::new(
        Profile::Leaf {
            issuer: intermediate_name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        Name::from_str("UID=pass.example.test,OU=ABCDE12345,CN=Pass signer").unwrap(),
        public_key,
        &intermediate_signer,
    )
    .unwrap()
    .build::<rsa::pkcs1v15::Signature>()
    .unwrap();

    (private_key, leaf, intermediate)
}

fn wallet() -> WalletPass {
    let (private_key, certificate, intermediate) = test_identity();
    WalletPass {
        certificate,
        private_key: BlindedRsaSigningKey(SigningKey::new(private_key)),
        certificate_chain: vec![intermediate],
        pass_type_identifier: "pass.example.membership".into(),
        team_identifier: "TEAM123456".into(),
        organization_name: "Example Membership".into(),
    }
}

fn archive_files(bytes: Vec<u8>) -> BTreeMap<String, Vec<u8>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut files = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        files.insert(file.name().to_string(), contents);
    }
    files
}

#[test]
fn builds_signed_pass_with_byte_preserving_qr_payload() {
    let wallet = wallet();
    let credential: Vec<u8> = (0..=255).collect();
    let files = archive_files(wallet.build("Alice Smith", &credential).unwrap());

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
    verify_cms_signature(&files["signature"], &files["manifest.json"]);

    let manifest: BTreeMap<String, String> =
        serde_json::from_slice(&files["manifest.json"]).unwrap();
    for (name, expected_hash) in manifest {
        assert_eq!(to_hex(&Sha1::digest(&files[&name])), expected_hash);
    }

    let pass: serde_json::Value = serde_json::from_slice(&files["pass.json"]).unwrap();
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

fn verify_cms_signature(signature: &[u8], manifest: &[u8]) {
    let content_info = ContentInfo::from_der(signature).unwrap();
    let signed_data = content_info.content.decode_as::<SignedData>().unwrap();
    assert!(signed_data.encap_content_info.econtent.is_none());
    assert_eq!(signed_data.certificates.as_ref().unwrap().0.len(), 2);
    assert_eq!(signed_data.signer_infos.0.len(), 1);

    let signer = signed_data.signer_infos.0.get(0).unwrap();
    let attributes = signer.signed_attrs.as_ref().unwrap();
    let message_digest_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    let digest_attribute = attributes
        .iter()
        .find(|attribute| attribute.oid == message_digest_oid)
        .unwrap();
    let encoded_digest = digest_attribute.values.get(0).unwrap();
    let encoded_digest = encoded_digest.decode_as::<OctetString>().unwrap();
    assert_eq!(
        encoded_digest.as_bytes(),
        Sha256::digest(manifest).as_slice()
    );

    let certificate = signed_data
        .certificates
        .as_ref()
        .unwrap()
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate)
                if certificate.tbs_certificate.serial_number == SerialNumber::from(2u32) =>
            {
                Some(certificate)
            }
            _ => None,
        })
        .next()
        .unwrap();
    let public_key = certificate_public_key(certificate).unwrap();
    let signature = rsa::pkcs1v15::Signature::try_from(signer.signature.as_bytes()).unwrap();
    VerifyingKey::<Sha256>::new(public_key)
        .verify(&attributes.to_der().unwrap(), &signature)
        .unwrap();
}

#[test]
fn loads_pem_identity_with_explicit_intermediate_and_rejects_invalid_inputs() {
    let directory = std::env::temp_dir().join(format!("wallet-pem-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let key_path = directory.join("key.pem");
    let cert_path = directory.join("cert.pem");
    let intermediate_path = directory.join("intermediate.pem");
    let (private_key, certificate, intermediate) = test_identity();
    std::fs::write(
        &key_path,
        private_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::write(&cert_path, certificate.to_pem(LineEnding::LF).unwrap()).unwrap();
    std::fs::write(
        &intermediate_path,
        intermediate.to_pem(LineEnding::LF).unwrap(),
    )
    .unwrap();
    let config = || WalletConfig {
        key_path: key_path.clone(),
        cert_path: cert_path.clone(),
        intermediate_cert_path: Some(intermediate_path.clone()),
        org_name: "Test".into(),
    };

    let wallet = WalletPass::load(config()).unwrap();
    assert_eq!(wallet.pass_type_identifier, "pass.example.test");
    assert_eq!(wallet.team_identifier, "ABCDE12345");
    let files = archive_files(wallet.build("Alice Smith", b"test credential").unwrap());
    verify_cms_signature(&files["signature"], &files["manifest.json"]);

    std::fs::write(
        &key_path,
        private_key.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    WalletPass::load(config()).expect("PKCS#1 PEM key should also be accepted");

    let mut without_override = config();
    without_override.intermediate_cert_path = None;
    let error = WalletPass::load(without_override)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("intermediate_cert_path"));
    assert!(error.contains("https://www.apple.com/certificateauthority/"));

    std::fs::write(
        &intermediate_path,
        certificate.to_pem(LineEnding::LF).unwrap(),
    )
    .unwrap();
    assert!(
        WalletPass::load(config())
            .err()
            .unwrap()
            .to_string()
            .contains("did not issue")
    );
    std::fs::write(
        &intermediate_path,
        intermediate.to_pem(LineEnding::LF).unwrap(),
    )
    .unwrap();

    let wrong_key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    std::fs::write(
        &key_path,
        wrong_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(
        WalletPass::load(config())
            .err()
            .unwrap()
            .to_string()
            .contains("does not match")
    );

    std::fs::write(
        &cert_path,
        format!(
            "{}{}",
            certificate.to_pem(LineEnding::LF).unwrap(),
            intermediate.to_pem(LineEnding::LF).unwrap()
        ),
    )
    .unwrap();
    assert!(
        WalletPass::load(config())
            .err()
            .unwrap()
            .to_string()
            .contains("exactly one")
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn selects_embedded_intermediate_by_authority_key_id() {
    let (_, mut certificate, _) = test_identity();
    let authority = x509_cert::ext::pkix::AuthorityKeyIdentifier {
        key_identifier: Some(OctetString::new(WWDR_G4_SUBJECT_KEY_ID).unwrap()),
        ..Default::default()
    };
    let extension = certificate
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|extension| extension.extn_id == AUTHORITY_KEY_IDENTIFIER_OID)
        .unwrap();
    extension.extn_value = OctetString::new(authority.to_der().unwrap()).unwrap();

    let intermediate = embedded_intermediate(&certificate).unwrap();
    assert_eq!(
        subject_key_identifier(&intermediate).unwrap().unwrap(),
        WWDR_G4_SUBJECT_KEY_ID
    );
    let error = embedded_intermediate(&intermediate)
        .unwrap_err()
        .to_string();
    assert!(error.contains("intermediate_cert_path"));
    assert!(error.contains("https://www.apple.com/certificateauthority/"));
}
