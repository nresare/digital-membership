use blst::min_sig::SecretKey;
use namecompress::Table;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;

pub const BLS_CIPHERSUITE: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const DOMAIN_PREFIX: &[u8] = b"digital-membership/v1\0";
const VERSION: u8 = 1;
const MAX_NAME_BYTES: usize = 255;
const MAX_FLAG_BYTES: usize = 255;
const MAX_FLAG: u32 = (MAX_FLAG_BYTES as u32 * 8) - 1;

/// Unix day number of the format epoch, `2026-01-01T00:00:00Z`. Unix time
/// excludes leap seconds, so dividing a timestamp by the length of a day is an
/// exact conversion and no calendar arithmetic is needed.
const EPOCH_UNIX_DAY: u64 = 20454;
const SECONDS_PER_DAY: u64 = 86400;
const MAX_ISSUE_DAY: u16 = 0x1fff;

/// The maximum number of bytes an integer identifier may occupy, which is also
/// the largest ID code that selects the integer form.
const MAX_IDENTIFIER_BYTES: usize = 6;
const TEXT_IDENTIFIER_CODE: u8 = 7;
const MAX_IDENTIFIER_TEXT_BYTES: usize = 255;

/// An opaque, issuer-assigned handle for a member. Numbers are carried as a
/// minimal big-endian integer and text as a length-prefixed UTF-8 string, so an
/// issuer that already has identifiers of either shape can use them unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Identifier {
    #[default]
    None,
    Number(u64),
    Text(String),
}

pub fn encode_credential(
    name: &str,
    flags: &[u32],
    identifier: &Identifier,
    issue_day: u16,
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
    if issue_day > MAX_ISSUE_DAY {
        return Err(AppError::Internal(format!(
            "issue day {issue_day} is outside the representable range 0..={MAX_ISSUE_DAY}"
        )));
    }

    let flag_bytes = encode_flags(flags)?;
    let (id_code, identifier_bytes) = encode_identifier(identifier)?;
    let compressed_name = namecompress::compress(name_model, name)
        .map_err(|error| AppError::BadRequest(format!("name cannot be compressed: {error}")))?;
    let length_code = match flag_bytes.len() {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    };
    let header = (VERSION << 5) | (key_id << 2) | length_code;
    let issuance_word = (issue_day << 3) | u16::from(id_code);

    let extended_length = usize::from(flag_bytes.len() >= 3);
    let mut unsigned = Vec::with_capacity(
        1 + extended_length + 2 + identifier_bytes.len() + flag_bytes.len() + compressed_name.len(),
    );
    unsigned.push(header);
    if flag_bytes.len() >= 3 {
        unsigned.push(flag_bytes.len() as u8);
    }
    unsigned.extend_from_slice(&issuance_word.to_be_bytes());
    unsigned.extend_from_slice(&identifier_bytes);
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

/// The issue day for the current UTC day.
pub fn issue_day_now() -> Result<u16, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Internal("system clock is before the Unix epoch".to_string()))?;
    issue_day(now.as_secs())
}

/// Converts a Unix timestamp in seconds to an issue day.
fn issue_day(unix_seconds: u64) -> Result<u16, AppError> {
    let day = unix_seconds / SECONDS_PER_DAY;
    let day = day
        .checked_sub(EPOCH_UNIX_DAY)
        .filter(|day| *day <= u64::from(MAX_ISSUE_DAY));
    day.map(|day| day as u16).ok_or_else(|| {
        AppError::Internal(
            "system clock is outside the range of representable issue days, 2026-01-01 through 2048-06-05"
                .to_string(),
        )
    })
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

/// Returns the ID code for the issuance word and the identifier bytes that
/// follow it.
fn encode_identifier(identifier: &Identifier) -> Result<(u8, Vec<u8>), AppError> {
    match identifier {
        Identifier::None => Ok((0, Vec::new())),
        Identifier::Number(value) => {
            // The shortest big-endian encoding, which for zero is a single zero
            // byte because an empty one would mean no identifier at all.
            let leading = (value.leading_zeros() as usize / 8).min(7);
            let bytes = &value.to_be_bytes()[leading..];
            if bytes.len() > MAX_IDENTIFIER_BYTES {
                return Err(AppError::BadRequest(format!(
                    "numeric member identifier must be less than 2^{}",
                    MAX_IDENTIFIER_BYTES * 8
                )));
            }
            Ok((bytes.len() as u8, bytes.to_vec()))
        }
        Identifier::Text(text) => {
            if text.is_empty() {
                return Err(AppError::BadRequest(
                    "member identifier must not be empty".to_string(),
                ));
            }
            if text.len() > MAX_IDENTIFIER_TEXT_BYTES {
                return Err(AppError::BadRequest(format!(
                    "member identifier must be at most {MAX_IDENTIFIER_TEXT_BYTES} UTF-8 bytes"
                )));
            }
            if text.chars().any(char::is_control) {
                return Err(AppError::BadRequest(
                    "member identifier must not contain control characters".to_string(),
                ));
            }
            let mut bytes = Vec::with_capacity(1 + text.len());
            bytes.push(text.len() as u8);
            bytes.extend_from_slice(text.as_bytes());
            Ok((TEXT_IDENTIFIER_CODE, bytes))
        }
    }
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
    use super::{
        BLS_CIPHERSUITE, DOMAIN_PREFIX, EPOCH_UNIX_DAY, Identifier, MAX_ISSUE_DAY, SECONDS_PER_DAY,
        encode_credential, issue_day,
    };
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
    fn encodes_the_specification_example() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential(
            "John Smith",
            &[0, 5],
            &Identifier::Number(4242),
            241,
            2,
            &model,
            &key,
        )
        .unwrap();

        assert_eq!(&credential[..6], b"\x29\x07\x8a\x10\x92\x21");
        assert_eq!(decoded_name(&model, &credential, 6), "John Smith");
        assert!(credential.len() < 62);
    }

    #[test]
    fn omits_identifier_bytes_when_there_is_no_identifier() {
        let key = signing_key();
        let model = test_name_model();
        let credential =
            encode_credential("A", &[0, 5, 9], &Identifier::None, 0, 0, &model, &key).unwrap();

        assert_eq!(&credential[..5], b"\x22\x00\x00\x21\x02");
        assert_eq!(decoded_name(&model, &credential, 5), "A");
    }

    #[test]
    fn encodes_numeric_identifiers_in_the_fewest_bytes() {
        let key = signing_key();
        let model = test_name_model();
        let encode =
            |identifier| encode_credential("A", &[], &identifier, 1, 0, &model, &key).unwrap();

        // Zero still occupies one byte: an empty encoding would mean no
        // identifier at all.
        assert_eq!(encode(Identifier::Number(0))[..4], *b"\x20\x00\x09\x00");
        assert_eq!(encode(Identifier::Number(255))[..4], *b"\x20\x00\x09\xff");
        assert_eq!(
            encode(Identifier::Number(256))[..5],
            *b"\x20\x00\x0a\x01\x00"
        );
        assert_eq!(
            encode(Identifier::Number((1 << 48) - 1))[..9],
            *b"\x20\x00\x0e\xff\xff\xff\xff\xff\xff"
        );
    }

    #[test]
    fn encodes_text_identifiers_with_a_length_prefix() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential(
            "A",
            &[],
            &Identifier::Text("AB-99".to_string()),
            1,
            0,
            &model,
            &key,
        )
        .unwrap();

        assert_eq!(&credential[..9], b"\x20\x00\x0f\x05AB-99");
        assert_eq!(decoded_name(&model, &credential, 9), "A");
    }

    #[test]
    fn uses_extended_flag_length() {
        let key = signing_key();
        let model = test_name_model();
        let credential =
            encode_credential("A", &[16], &Identifier::None, 0, 0, &model, &key).unwrap();

        assert_eq!(&credential[..7], b"\x23\x03\x00\x00\x00\x00\x01");
        assert_eq!(decoded_name(&model, &credential, 7), "A");
    }

    #[test]
    fn packs_the_issue_day_above_the_id_code() {
        let key = signing_key();
        let model = test_name_model();
        let credential =
            encode_credential("A", &[], &Identifier::None, MAX_ISSUE_DAY, 0, &model, &key).unwrap();

        assert_eq!(&credential[..3], b"\x20\xff\xf8");
    }

    #[test]
    fn derives_the_issue_day_from_a_unix_timestamp() {
        let epoch = EPOCH_UNIX_DAY * SECONDS_PER_DAY;

        assert_eq!(issue_day(epoch).unwrap(), 0);
        assert_eq!(issue_day(epoch + SECONDS_PER_DAY - 1).unwrap(), 0);
        assert_eq!(issue_day(epoch + SECONDS_PER_DAY).unwrap(), 1);
        // 2026-08-30, the day used by the example in the specification.
        assert_eq!(issue_day(1_788_048_000).unwrap(), 241);
        assert_eq!(issue_day(1_788_048_000 + SECONDS_PER_DAY - 1).unwrap(), 241);
        assert_eq!(
            issue_day(epoch + u64::from(MAX_ISSUE_DAY) * SECONDS_PER_DAY).unwrap(),
            MAX_ISSUE_DAY
        );

        assert!(issue_day(epoch - 1).is_err());
        assert!(issue_day(epoch + (u64::from(MAX_ISSUE_DAY) + 1) * SECONDS_PER_DAY).is_err());
    }

    #[test]
    fn signs_domain_prefix_and_unsigned_credential() {
        let key = signing_key();
        let model = test_name_model();
        let credential = encode_credential(
            "Alice",
            &[0, 5],
            &Identifier::Text("AB-99".to_string()),
            241,
            2,
            &model,
            &key,
        )
        .unwrap();
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
    fn rejects_invalid_name_flag_and_identifier_values() {
        let key = signing_key();
        let model = test_name_model();
        let encode = |name: &str, flags: &[u32], identifier: Identifier| {
            encode_credential(name, flags, &identifier, 0, 0, &model, &key)
        };

        assert!(encode("", &[], Identifier::None).is_err());
        assert!(encode("line\nbreak", &[], Identifier::None).is_err());
        assert!(encode(&"x".repeat(256), &[], Identifier::None).is_err());
        assert!(encode("Alice", &[2040], Identifier::None).is_err());
        assert!(encode("Alice", &[], Identifier::Number(1 << 48)).is_err());
        assert!(encode("Alice", &[], Identifier::Text(String::new())).is_err());
        assert!(encode("Alice", &[], Identifier::Text("a\nb".to_string())).is_err());
        assert!(encode("Alice", &[], Identifier::Text("x".repeat(256))).is_err());
    }
}
