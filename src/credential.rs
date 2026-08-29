use blst::min_sig::SecretKey;
use namecompress::Table;

use crate::error::AppError;

pub const BLS_CIPHERSUITE: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const DOMAIN_PREFIX: &[u8] = b"digital-membership/v1\0";
const VERSION: u8 = 1;
const MAX_NAME_BYTES: usize = 255;
const MAX_FLAG_BYTES: usize = 255;
const MAX_FLAG: u32 = (MAX_FLAG_BYTES as u32 * 8) - 1;

pub fn encode_credential(
    name: &str,
    flags: &[u32],
    key_id: u8,
    name_model: &Table,
    signing_key: &SecretKey,
) -> Result<Vec<u8>, AppError> {
    validate_name(name)?;
    if key_id > 7 {
        return Err(AppError::Internal(format!(
            "key ID {key_id} is outside the supported range 0..=7"
        )));
    }

    let flag_bytes = encode_flags(flags)?;
    let compressed_name = namecompress::compress(name_model, name)
        .map_err(|error| AppError::BadRequest(format!("name cannot be compressed: {error}")))?;
    let length_code = match flag_bytes.len() {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    };
    let header = (VERSION << 5) | (key_id << 2) | length_code;

    let extended_length = usize::from(flag_bytes.len() >= 3);
    let mut unsigned =
        Vec::with_capacity(1 + extended_length + flag_bytes.len() + compressed_name.len());
    unsigned.push(header);
    if flag_bytes.len() >= 3 {
        unsigned.push(flag_bytes.len() as u8);
    }
    unsigned.extend_from_slice(&flag_bytes);
    unsigned.extend_from_slice(&compressed_name);

    let mut message = Vec::with_capacity(DOMAIN_PREFIX.len() + unsigned.len());
    message.extend_from_slice(DOMAIN_PREFIX);
    message.extend_from_slice(&unsigned);
    let signature = signing_key.sign(&message, BLS_CIPHERSUITE.as_bytes(), &[]);

    let mut credential = Vec::with_capacity(unsigned.len() + signature.to_bytes().len());
    credential.extend_from_slice(&unsigned);
    credential.extend_from_slice(&signature.to_bytes());
    Ok(credential)
}

fn validate_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::BadRequest("name must not be empty".to_string()));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(AppError::BadRequest(format!(
            "name must be at most {MAX_NAME_BYTES} UTF-8 bytes"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "name must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn encode_flags(flags: &[u32]) -> Result<Vec<u8>, AppError> {
    let Some(highest) = flags.iter().copied().max() else {
        return Ok(Vec::new());
    };
    if highest > MAX_FLAG {
        return Err(AppError::BadRequest(format!(
            "flag number must be between 0 and {MAX_FLAG}"
        )));
    }

    let mut bytes = vec![0_u8; highest as usize / 8 + 1];
    for &flag in flags {
        let byte_index = flag as usize / 8;
        let bit_index = flag % 8;
        bytes[byte_index] |= 1 << bit_index;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{BLS_CIPHERSUITE, DOMAIN_PREFIX, encode_credential};
    use crate::test_name_model;
    use blst::BLST_ERROR;
    use blst::min_sig::{SecretKey, Signature};
    use namecompress::Table;

    fn signing_key() -> SecretKey {
        SecretKey::key_gen_v5(&[42_u8; 32], &[], &[]).unwrap()
    }

    fn decoded_name(model: &Table, credential: &[u8], name_offset: usize) -> String {
        let signature_offset = credential.len() - 48;
        namecompress::decompress(model, &credential[name_offset..signature_offset]).unwrap()
    }

    #[test]
    fn compresses_name_and_encodes_header_and_flags() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential("John Smith", &[0, 5], 2, &model, &key).unwrap();

        assert_eq!(&credential[..2], b"\x29\x21");
        assert_eq!(decoded_name(&model, &credential, 2), "John Smith");
        assert!(credential.len() < 60);
    }

    #[test]
    fn encodes_little_endian_flag_bitset() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential("A", &[0, 5, 9], 0, &model, &key).unwrap();

        assert_eq!(&credential[..3], b"\x22\x21\x02");
        assert_eq!(decoded_name(&model, &credential, 3), "A");
    }

    #[test]
    fn uses_extended_flag_length() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential("A", &[16], 0, &model, &key).unwrap();

        assert_eq!(&credential[..5], b"\x23\x03\x00\x00\x01");
        assert_eq!(decoded_name(&model, &credential, 5), "A");
    }

    #[test]
    fn signs_domain_prefix_and_unsigned_credential() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential("Alice", &[0, 5], 2, &model, &key).unwrap();
        let signature_offset = credential.len() - 48;
        let mut message = DOMAIN_PREFIX.to_vec();
        message.extend_from_slice(&credential[..signature_offset]);
        let signature = Signature::from_bytes(&credential[signature_offset..]).unwrap();

        assert_eq!(
            signature.verify(
                true,
                &message,
                BLS_CIPHERSUITE.as_bytes(),
                &[],
                &key.sk_to_pk(),
                true,
            ),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    #[test]
    fn rejects_invalid_name_and_flag_values() {
        let key = signing_key();
        let model = test_name_model();

        assert!(encode_credential("", &[], 0, &model, &key).is_err());
        assert!(encode_credential("line\nbreak", &[], 0, &model, &key).is_err());
        assert!(encode_credential(&"x".repeat(256), &[], 0, &model, &key).is_err());
        assert!(encode_credential("Alice", &[2040], 0, &model, &key).is_err());
    }
}
