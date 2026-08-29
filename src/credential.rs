use ed25519_dalek::{Signer, SigningKey};

use crate::error::AppError;

const DOMAIN_PREFIX: &[u8] = b"digital-membership/v1\0";
const VERSION: u8 = 1;
const MAX_NAME_BYTES: usize = 255;
const MAX_FLAG_BYTES: usize = 255;
const MAX_FLAG: u32 = (MAX_FLAG_BYTES as u32 * 8) - 1;

pub fn encode_credential(
    name: &str,
    flags: &[u32],
    key_id: u8,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, AppError> {
    validate_name(name)?;
    if key_id > 7 {
        return Err(AppError::Internal(format!(
            "key ID {key_id} is outside the supported range 0..=7"
        )));
    }

    let flag_bytes = encode_flags(flags)?;
    let length_code = match flag_bytes.len() {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    };
    let header = (VERSION << 5) | (key_id << 2) | length_code;

    let extended_length = usize::from(flag_bytes.len() >= 3);
    let mut unsigned = Vec::with_capacity(1 + extended_length + flag_bytes.len() + name.len());
    unsigned.push(header);
    if flag_bytes.len() >= 3 {
        unsigned.push(flag_bytes.len() as u8);
    }
    unsigned.extend_from_slice(&flag_bytes);
    unsigned.extend_from_slice(name.as_bytes());

    let mut message = Vec::with_capacity(DOMAIN_PREFIX.len() + unsigned.len());
    message.extend_from_slice(DOMAIN_PREFIX);
    message.extend_from_slice(&unsigned);
    let signature = signing_key.sign(&message);

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
    use super::{DOMAIN_PREFIX, encode_credential};
    use ed25519_dalek::{Signature, SigningKey, Verifier};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42_u8; 32])
    }

    #[test]
    fn encodes_example_header_flags_and_name() {
        let key = signing_key();
        let credential = encode_credential("Alice", &[0, 5], 2, &key).unwrap();

        assert_eq!(&credential[..7], b"\x29\x21Alice");
        assert_eq!(credential.len(), 71);
    }

    #[test]
    fn encodes_little_endian_flag_bitset() {
        let key = signing_key();
        let credential = encode_credential("A", &[0, 5, 9], 0, &key).unwrap();

        assert_eq!(&credential[..4], b"\x22\x21\x02A");
    }

    #[test]
    fn uses_extended_flag_length() {
        let key = signing_key();
        let credential = encode_credential("A", &[16], 0, &key).unwrap();

        assert_eq!(&credential[..6], b"\x23\x03\x00\x00\x01A");
    }

    #[test]
    fn signs_domain_prefix_and_unsigned_credential() {
        let key = signing_key();
        let credential = encode_credential("Alice", &[0, 5], 2, &key).unwrap();
        let signature_offset = credential.len() - 64;
        let mut message = DOMAIN_PREFIX.to_vec();
        message.extend_from_slice(&credential[..signature_offset]);
        let signature = Signature::from_slice(&credential[signature_offset..]).unwrap();

        key.verifying_key().verify(&message, &signature).unwrap();
    }

    #[test]
    fn rejects_invalid_name_and_flag_values() {
        let key = signing_key();

        assert!(encode_credential("", &[], 0, &key).is_err());
        assert!(encode_credential("line\nbreak", &[], 0, &key).is_err());
        assert!(encode_credential(&"x".repeat(256), &[], 0, &key).is_err());
        assert!(encode_credential("Alice", &[2040], 0, &key).is_err());
    }
}
