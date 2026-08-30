use anyhow::Context;
use digital_membership::WalletConfig;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,

    /// Path to the `namecompress` model table, optionally XZ-compressed.
    pub name_model: PathBuf,

    pub wallet: Option<WalletConfig>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("could not read config file '{}'", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("could not parse config file '{}'", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.name_model.as_os_str().is_empty() {
            anyhow::bail!("name_model must not be empty");
        }
        if let Some(wallet) = &self.wallet {
            if wallet.pass_type_identifier.is_empty() {
                anyhow::bail!("wallet.pass_type_identifier must not be empty");
            }
            if wallet.team_identifier.is_empty() {
                anyhow::bail!("wallet.team_identifier must not be empty");
            }
            if wallet.organization_name.is_empty() {
                anyhow::bail!("wallet.organization_name must not be empty");
            }
        }
        Ok(())
    }
}

fn default_bind_address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn parse(content: &str) -> anyhow::Result<Config> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn bind_address_defaults_to_all_interfaces() {
        let config = parse(r#"name_model = "names.ncmp""#).unwrap();

        assert_eq!(config.bind_address.to_string(), "0.0.0.0:8080");
        assert!(config.wallet.is_none());
    }

    #[test]
    fn name_model_is_required() {
        let error = parse(r#"bind_address = "127.0.0.1:9000""#).unwrap_err();

        assert!(error.to_string().contains("name_model"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let error = parse(
            r#"
            name_model = "names.ncmp"
            name_modle = "names.ncmp"
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("name_modle"));
    }

    #[test]
    fn wallet_section_requires_every_field() {
        let error = parse(
            r#"
            name_model = "names.ncmp"

            [wallet]
            pkcs12 = "pass.p12"
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("wwdr_certificate"));
    }

    #[test]
    fn example_config_is_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/digital-membership.toml");
        parse(&std::fs::read_to_string(path).unwrap()).expect("example config should be valid");
    }

    #[test]
    fn wallet_section_is_parsed() {
        let config = parse(
            r#"
            bind_address = "127.0.0.1:9000"
            name_model = "/config/english.ncmp.xz"

            [wallet]
            pkcs12 = "/secrets/pass.p12"
            wwdr_certificate = "/secrets/AppleWWDR.pem"
            pass_type_identifier = "pass.example.digital-membership"
            team_identifier = "ABCDE12345"
            "#,
        )
        .unwrap();

        assert_eq!(config.bind_address.to_string(), "127.0.0.1:9000");
        let wallet = config.wallet.unwrap();
        assert_eq!(wallet.team_identifier, "ABCDE12345");
        assert_eq!(wallet.organization_name, "Digital Membership");
    }
}
