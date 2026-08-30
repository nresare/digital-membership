use namecompress::Table;
use serde::Deserialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

use crate::error::AppError;
use crate::signing::SigningKey;

const XZ_MAGIC: &[u8] = b"\xfd7zXZ\0";

/// The highest flag number the binary format can carry: three bits in the header
/// plus its 255-byte limit on flag data.
const MAX_FLAG: usize = 2042;

/// One issuer as written in the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// Short identifier, used as the first path segment of the issuer's
    /// endpoints and therefore restricted to characters that need no escaping.
    pub id: String,

    /// Human-readable name of the issuer, published by `/api/{id}/provision` so
    /// a scanner can show whose credential it is verifying.
    pub description: String,

    /// Path to the signing key written by `--key-gen`.
    pub signing_key_path: PathBuf,

    /// Path to the `namecompress` model table, optionally XZ-compressed.
    pub name_model: PathBuf,

    /// Labels for this issuer's flags, where the position in the list is the
    /// flag number. An empty label leaves that flag number without a name; it
    /// can still be asserted by number.
    #[serde(default)]
    pub flags: Vec<String>,
}

impl IssuerConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.id.is_empty() {
            anyhow::bail!("issuer.id must not be empty");
        }
        // The id is a path segment, so keep it to characters that survive a URL
        // unescaped and cannot be confused with a neighbouring segment.
        if let Some(character) = self
            .id
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
        {
            anyhow::bail!(
                "issuer.id '{}' contains '{character}'; only ASCII letters, digits, '-' and '_' are allowed",
                self.id
            );
        }
        if self.description.is_empty() {
            anyhow::bail!("issuer '{}' must have a description", self.id);
        }
        if self.signing_key_path.as_os_str().is_empty() {
            anyhow::bail!("issuer '{}' must have a signing_key_path", self.id);
        }
        if self.name_model.as_os_str().is_empty() {
            anyhow::bail!("issuer '{}' must have a name_model", self.id);
        }
        if self.flags.len() > MAX_FLAG + 1 {
            anyhow::bail!(
                "issuer '{}' declares {} flags, but the highest supported flag number is {MAX_FLAG}",
                self.id,
                self.flags.len()
            );
        }
        for (number, label) in self.flags.iter().enumerate() {
            if label.is_empty() {
                continue;
            }
            // A label that reads as a number would make `flags=7` ambiguous
            // between the label and the flag number.
            if label.parse::<u32>().is_ok() {
                anyhow::bail!(
                    "issuer '{}' labels flag {number} '{label}', which would be ambiguous with a flag number",
                    self.id
                );
            }
            if let Some(earlier) = self.flags[..number].iter().position(|other| other == label) {
                anyhow::bail!(
                    "issuer '{}' uses the flag label '{label}' for both flag {earlier} and flag {number}",
                    self.id
                );
            }
        }
        Ok(())
    }
}

/// A flag as named by a request: either its number, or a label the issuer
/// defines for it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum FlagRef {
    Number(u32),
    Label(String),
}

impl FlagRef {
    /// Parses one comma-separated query-string element. A value that reads as a
    /// number is a flag number; anything else is a label, which the issuer
    /// resolves later.
    pub(crate) fn parse(value: &str) -> Self {
        value
            .parse::<u32>()
            .map_or_else(|_| Self::Label(value.to_string()), Self::Number)
    }
}

/// An issuer with its key and name model loaded and ready to sign.
pub(crate) struct Issuer {
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) signing_key: SigningKey,
    pub(crate) name_model: Table,
    pub(crate) compressed_name_model: Arc<[u8]>,
    pub(crate) flags: Vec<String>,
}

impl Issuer {
    pub(crate) fn load(config: IssuerConfig) -> anyhow::Result<Self> {
        let key_file = std::fs::read_to_string(&config.signing_key_path).map_err(|error| {
            anyhow::anyhow!(
                "issuer '{}': failed to read signing key '{}': {error}",
                config.id,
                config.signing_key_path.display()
            )
        })?;
        let signing_key = SigningKey::from_key_file(&key_file).map_err(|error| {
            anyhow::anyhow!(
                "issuer '{}': signing key '{}' is invalid: {error}",
                config.id,
                config.signing_key_path.display()
            )
        })?;
        let (name_model, compressed_name_model) = load_name_model(&config.name_model)
            .map_err(|error| anyhow::anyhow!("issuer '{}': {error}", config.id))?;

        Ok(Self {
            id: config.id,
            description: config.description,
            signing_key,
            name_model,
            compressed_name_model: compressed_name_model.into(),
            flags: config.flags,
        })
    }

    /// The path the issuer's name model is served from, as published by its
    /// provisioning endpoint.
    pub(crate) fn name_model_url(&self) -> String {
        format!("/api/{}/model/model.ncmp.xz", self.id)
    }

    /// Turns the flags named by a request into flag numbers.
    pub(crate) fn resolve_flags(&self, flags: &[FlagRef]) -> Result<Vec<u32>, AppError> {
        flags
            .iter()
            .map(|flag| match flag {
                FlagRef::Number(number) => Ok(*number),
                FlagRef::Label(label) => self.flag_number(label),
            })
            .collect()
    }

    fn flag_number(&self, label: &str) -> Result<u32, AppError> {
        self.flags
            .iter()
            .position(|candidate| !candidate.is_empty() && candidate == label)
            .map(|number| number as u32)
            .ok_or_else(|| {
                AppError::BadRequest(format!(
                    "issuer '{}' defines no flag labelled '{label}'",
                    self.id
                ))
            })
    }
}

/// Reads a `namecompress` model, accepting it either XZ-compressed or plain, and
/// returns the parsed table alongside the compressed bytes served to scanners.
fn load_name_model(path: &Path) -> anyhow::Result<(Table, Vec<u8>)> {
    let configured = std::fs::read(path).map_err(|error| {
        anyhow::anyhow!("failed to read name model '{}': {error}", path.display())
    })?;

    let (model_bytes, compressed) = if configured.starts_with(XZ_MAGIC) {
        let mut decompressed = Vec::new();
        XzDecoder::new(configured.as_slice())
            .read_to_end(&mut decompressed)
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to decompress xz name model '{}': {error}",
                    path.display()
                )
            })?;
        (decompressed, configured)
    } else {
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&configured).map_err(|error| {
            anyhow::anyhow!(
                "failed to compress name model '{}': {error}",
                path.display()
            )
        })?;
        let compressed = encoder.finish().map_err(|error| {
            anyhow::anyhow!(
                "failed to finish compressing name model '{}': {error}",
                path.display()
            )
        })?;
        (configured, compressed)
    };

    let model = Table::load(&model_bytes).map_err(|error| {
        anyhow::anyhow!("failed to load name model '{}': {error}", path.display())
    })?;
    Ok((model, compressed))
}

#[cfg(test)]
mod tests {
    use super::{FlagRef, Issuer, IssuerConfig};
    use crate::signing::SigningKey;
    use crate::test_name_model;
    use blst::min_sig::SecretKey;
    use std::sync::Arc;

    fn config(id: &str, flags: &[&str]) -> IssuerConfig {
        IssuerConfig {
            id: id.to_string(),
            description: "Example Society".to_string(),
            signing_key_path: "key.secret".into(),
            name_model: "names.ncmp".into(),
            flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
        }
    }

    fn issuer(flags: &[&str]) -> Issuer {
        let key: SigningKey = SecretKey::key_gen_v5(&[7_u8; 32], &[], &[]).unwrap().into();
        Issuer {
            id: "example".to_string(),
            description: "Example Society".to_string(),
            signing_key: key,
            name_model: test_name_model(),
            compressed_name_model: Arc::from(Vec::new()),
            flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
        }
    }

    #[test]
    fn resolves_flags_by_label_and_by_number() {
        let issuer = issuer(&["member", "", "vegetarian"]);

        let flags = issuer
            .resolve_flags(&[
                FlagRef::Label("vegetarian".to_string()),
                FlagRef::Number(1),
                FlagRef::Number(64),
            ])
            .unwrap();

        assert_eq!(flags, [2, 1, 64]);
    }

    #[test]
    fn rejects_an_unknown_or_unlabelled_flag() {
        let issuer = issuer(&["member", "", "vegetarian"]);

        assert!(
            issuer
                .resolve_flags(&[FlagRef::Label("committee".to_string())])
                .is_err()
        );
        // The empty label at flag 1 names nothing, not the empty string.
        assert!(
            issuer
                .resolve_flags(&[FlagRef::Label(String::new())])
                .is_err()
        );
    }

    #[test]
    fn parses_query_elements_as_numbers_or_labels() {
        assert_eq!(FlagRef::parse("9"), FlagRef::Number(9));
        assert_eq!(
            FlagRef::parse("vegetarian"),
            FlagRef::Label("vegetarian".to_string())
        );
        assert_eq!(FlagRef::parse("-1"), FlagRef::Label("-1".to_string()));
    }

    #[test]
    fn name_model_url_is_under_the_issuer_path() {
        assert_eq!(
            issuer(&[]).name_model_url(),
            "/api/example/model/model.ncmp.xz"
        );
    }

    #[test]
    fn accepts_a_well_formed_issuer() {
        config("example-1_2", &["member", "", "vegetarian"])
            .validate()
            .unwrap();
    }

    #[test]
    fn rejects_an_id_that_would_need_url_escaping() {
        let error = config("two words", &[]).validate().unwrap_err().to_string();
        assert!(error.contains("issuer.id"), "{error}");

        assert!(config("a/b", &[]).validate().is_err());
        assert!(config("", &[]).validate().is_err());
    }

    #[test]
    fn rejects_duplicate_and_numeric_flag_labels() {
        let error = config("example", &["member", "member"])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(error.contains("flag 0 and flag 1"), "{error}");

        let error = config("example", &["7"])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(error.contains("ambiguous"), "{error}");

        // Repeated empty labels are gaps, not duplicates.
        config("example", &["member", "", ""]).validate().unwrap();
    }

    #[test]
    fn rejects_missing_required_fields() {
        let mut missing_description = config("example", &[]);
        missing_description.description = String::new();
        assert!(missing_description.validate().is_err());

        let mut missing_key = config("example", &[]);
        missing_key.signing_key_path = "".into();
        assert!(missing_key.validate().is_err());

        let mut missing_model = config("example", &[]);
        missing_model.name_model = "".into();
        assert!(missing_model.validate().is_err());
    }
}
