use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blst::min_sig::SecretKey;
use serde::Deserialize;

use crate::credential::BLS_CIPHERSUITE;

/// Length of the serialised BLS12-381 scalar carried in a signing key file.
pub const SECRET_KEY_BYTES: usize = 32;

/// A BLS12-381 signing key, kept as a newtype so that callers outside this crate
/// never handle raw `blst` types.
pub struct SigningKey(SecretKey);

/// A parsed signing key file.
///
/// Deliberately without a `Debug` derive: the secret must not reach a log line
/// through a stray `{:?}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    ciphersuite: String,
    secret_key: String,
}

impl SigningKey {
    pub fn generate() -> anyhow::Result<Self> {
        let mut ikm = [0_u8; 32];
        getrandom::fill(&mut ikm)
            .map_err(|error| anyhow::anyhow!("failed to generate signing key material: {error}"))?;
        let key = SecretKey::key_gen_v5(&ikm, &[], &[])
            .map_err(|error| anyhow::anyhow!("failed to generate BLS signing key: {error:?}"))?;
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        self.0.to_bytes()
    }

    /// Serialises the key as a self-describing TOML document.
    ///
    /// draft-irtf-cfrg-bls-signature defines the ciphersuite identifier but neither
    /// a secret key serialisation nor a container format, so the container is ours:
    /// the draft's identifier names the scheme the scalar belongs to, and the scalar
    /// itself is unpadded URL-safe Base64, the same alphabet as the public key.
    pub fn to_key_file(&self) -> String {
        format!(
            "# digital-membership signing key. Treat this file as a secret.\n\
             # ciphersuite identifiers are defined by draft-irtf-cfrg-bls-signature.\n\
             ciphersuite = \"{BLS_CIPHERSUITE}\"\n\
             secret_key = \"{}\"\n",
            URL_SAFE_NO_PAD.encode(self.to_bytes())
        )
    }

    /// Parses a key file, rejecting a key belonging to a different ciphersuite.
    ///
    /// This is what the self-describing format buys: a key generated for another
    /// BLS scheme fails loudly here instead of silently producing signatures that
    /// no verifier accepts.
    pub fn from_key_file(contents: &str) -> anyhow::Result<Self> {
        let key_file: KeyFile = toml::from_str(contents)
            .map_err(|error| anyhow::anyhow!("could not parse signing key: {error}"))?;
        if key_file.ciphersuite != BLS_CIPHERSUITE {
            anyhow::bail!(
                "signing key is for ciphersuite '{}', but this service signs with '{BLS_CIPHERSUITE}'",
                key_file.ciphersuite
            );
        }

        let bytes = URL_SAFE_NO_PAD
            .decode(key_file.secret_key.trim())
            .map_err(|error| anyhow::anyhow!("signing key is not valid Base64: {error}"))?;
        if bytes.len() != SECRET_KEY_BYTES {
            anyhow::bail!(
                "signing key is {} bytes, expected {SECRET_KEY_BYTES}",
                bytes.len()
            );
        }
        let key = SecretKey::from_bytes(&bytes)
            .map_err(|error| anyhow::anyhow!("signing key is not a valid BLS scalar: {error:?}"))?;
        Ok(Self(key))
    }

    /// The verification key as served by `/api/provision`: the 96-byte compressed
    /// G2 point in unpadded URL-safe Base64.
    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.sk_to_pk().to_bytes())
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.0
    }
}

/// Redacting `Debug`: the secret scalar must never reach a log line, but the type
/// still needs `Debug` to appear in `Result` assertions and error paths.
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public_key", &self.public_key_base64())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
impl From<SecretKey> for SigningKey {
    fn from(key: SecretKey) -> Self {
        Self(key)
    }
}

#[cfg(test)]
mod tests {
    use super::{SECRET_KEY_BYTES, SigningKey};
    use crate::credential::BLS_CIPHERSUITE;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn generates_distinct_keys() {
        let first = SigningKey::generate().unwrap();
        let second = SigningKey::generate().unwrap();

        assert_eq!(first.to_bytes().len(), SECRET_KEY_BYTES);
        assert_ne!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn key_file_is_ascii_and_names_its_ciphersuite() {
        let key = SigningKey::generate().unwrap();

        let contents = key.to_key_file();
        assert!(contents.is_ascii());
        assert!(contents.contains(&format!("ciphersuite = \"{BLS_CIPHERSUITE}\"")));
        assert!(contents.ends_with('\n'));
    }

    #[test]
    fn key_file_round_trips() {
        let key = SigningKey::generate().unwrap();

        let parsed = SigningKey::from_key_file(&key.to_key_file()).unwrap();

        assert_eq!(parsed.to_bytes(), key.to_bytes());
        assert_eq!(parsed.public_key_base64(), key.public_key_base64());
    }

    #[test]
    fn rejects_a_key_from_another_ciphersuite() {
        let key = SigningKey::generate().unwrap();
        let contents = key.to_key_file().replace(
            BLS_CIPHERSUITE,
            "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
        );

        let error = SigningKey::from_key_file(&contents)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"),
            "{error}"
        );
        assert!(error.contains(BLS_CIPHERSUITE), "{error}");
    }

    #[test]
    fn rejects_a_truncated_scalar() {
        let key = SigningKey::generate().unwrap();
        let short = URL_SAFE_NO_PAD.encode(&key.to_bytes()[..16]);
        let contents = format!("ciphersuite = \"{BLS_CIPHERSUITE}\"\nsecret_key = \"{short}\"\n");

        let error = SigningKey::from_key_file(&contents)
            .unwrap_err()
            .to_string();

        assert!(error.contains("16 bytes"), "{error}");
    }

    #[test]
    fn rejects_a_malformed_file() {
        let key = SigningKey::generate().unwrap();

        // Not TOML at all: the bare Base64 scalar the previous format used.
        let error = SigningKey::from_key_file(&URL_SAFE_NO_PAD.encode(key.to_bytes()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not parse signing key"), "{error}");

        // Valid TOML, but not a key file.
        let error = SigningKey::from_key_file("secret_key = \"abc\"\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("ciphersuite"), "{error}");

        // Right shape, but the scalar is not Base64.
        let contents =
            format!("ciphersuite = \"{BLS_CIPHERSUITE}\"\nsecret_key = \"not base64!\"\n");
        let error = SigningKey::from_key_file(&contents)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not valid Base64"), "{error}");
    }

    #[test]
    fn debug_output_does_not_leak_the_secret() {
        let key = SigningKey::generate().unwrap();

        let rendered = format!("{key:?}");

        assert!(rendered.contains(&key.public_key_base64()));
        assert!(!rendered.contains(&URL_SAFE_NO_PAD.encode(key.to_bytes())));
    }

    #[test]
    fn public_key_is_a_compressed_g2_point() {
        let key = SigningKey::generate().unwrap();

        let encoded = key.public_key_base64();
        assert_eq!(URL_SAFE_NO_PAD.decode(&encoded).unwrap().len(), 96);
        assert!(!encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'));
    }
}
