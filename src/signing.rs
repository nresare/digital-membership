use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blst::min_sig::SecretKey;

/// Length of the serialised BLS12-381 scalar written to a signing key file.
pub const SECRET_KEY_BYTES: usize = 32;

/// A BLS12-381 signing key, kept as a newtype so that callers outside this crate
/// never handle raw `blst` types.
pub struct SigningKey(SecretKey);

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

    /// The verification key as served by `/api/provision`: the 96-byte compressed
    /// G2 point in unpadded URL-safe Base64.
    pub fn public_key_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.sk_to_pk().to_bytes())
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.0
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
    fn public_key_is_a_compressed_g2_point() {
        let key = SigningKey::generate().unwrap();

        let encoded = key.public_key_base64();
        assert_eq!(URL_SAFE_NO_PAD.decode(&encoded).unwrap().len(), 96);
        assert!(!encoded.contains('=') && !encoded.contains('+') && !encoded.contains('/'));
    }
}
