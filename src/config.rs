use anyhow::Context;
use digital_membership::{IssuerConfig, WalletConfig};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: SocketAddr,

    /// The issuers this instance signs for, each served under `/api/{id}/`.
    #[serde(default, rename = "issuer")]
    pub issuers: Vec<IssuerConfig>,

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
        if self.issuers.is_empty() {
            anyhow::bail!("at least one [[issuer]] must be configured");
        }
        for (index, issuer) in self.issuers.iter().enumerate() {
            issuer.validate()?;
            if self.issuers[..index]
                .iter()
                .any(|earlier| earlier.id == issuer.id)
            {
                anyhow::bail!("issuer id '{}' is configured more than once", issuer.id);
            }
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

    const ISSUER: &str = r#"
        [[issuer]]
        id = "example"
        description = "Example Membership Society"
        signing_key_path = "example.secret"
        name_model = "names.ncmp"
    "#;

    fn parse(content: &str) -> anyhow::Result<Config> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn bind_address_defaults_to_all_interfaces() {
        let config = parse(ISSUER).unwrap();

        assert_eq!(config.bind_address.to_string(), "0.0.0.0:8080");
        assert!(config.wallet.is_none());
    }

    #[test]
    fn at_least_one_issuer_is_required() {
        let error = parse(r#"bind_address = "127.0.0.1:9000""#).unwrap_err();

        assert!(error.to_string().contains("[[issuer]]"), "{error}");
    }

    #[test]
    fn issuers_are_parsed_in_order_with_their_flag_labels() {
        let config = parse(
            r#"
            [[issuer]]
            id = "example"
            description = "Example Membership Society"
            signing_key_path = "example.secret"
            name_model = "names.ncmp"
            flags = ["member", "", "vegetarian"]

            [[issuer]]
            id = "choir"
            description = "Example Choral Society"
            signing_key_path = "choir.secret"
            name_model = "names.ncmp"
            "#,
        )
        .unwrap();

        assert_eq!(config.issuers.len(), 2);
        assert_eq!(config.issuers[0].id, "example");
        assert_eq!(config.issuers[0].flags, ["member", "", "vegetarian"]);
        assert_eq!(config.issuers[1].id, "choir");
        assert!(config.issuers[1].flags.is_empty());
    }

    #[test]
    fn issuer_ids_must_be_unique() {
        let error = parse(&format!("{ISSUER}{ISSUER}")).unwrap_err().to_string();

        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn issuer_problems_are_reported() {
        let error = parse(
            r#"
            [[issuer]]
            id = "example"
            description = ""
            signing_key_path = "example.secret"
            name_model = "names.ncmp"
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("description"), "{error}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let error = parse(&format!("{ISSUER}\nname_modle = \"names.ncmp\"\n"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("name_modle"), "{error}");

        let error = parse(
            r#"
            [[issuer]]
            id = "example"
            description = "Example Membership Society"
            signing_key_path = "example.secret"
            name_modle = "names.ncmp"
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("name_modle"), "{error}");
    }

    #[test]
    fn wallet_section_requires_every_field() {
        let error = parse(&format!("{ISSUER}\n[wallet]\npkcs12 = \"pass.p12\"\n")).unwrap_err();

        assert!(error.to_string().contains("wwdr_certificate"));
    }

    #[test]
    fn example_config_is_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/digital-membership.toml");
        parse(&std::fs::read_to_string(path).unwrap()).expect("example config should be valid");
    }

    #[test]
    fn wallet_section_is_parsed() {
        let config = parse(&format!(
            r#"
            bind_address = "127.0.0.1:9000"
            {ISSUER}

            [wallet]
            pkcs12 = "/secrets/pass.p12"
            wwdr_certificate = "/secrets/AppleWWDR.pem"
            pass_type_identifier = "pass.example.digital-membership"
            team_identifier = "ABCDE12345"
            "#
        ))
        .unwrap();

        assert_eq!(config.bind_address.to_string(), "127.0.0.1:9000");
        let wallet = config.wallet.unwrap();
        assert_eq!(wallet.team_identifier, "ABCDE12345");
        assert_eq!(wallet.organization_name, "Digital Membership");
    }
}
