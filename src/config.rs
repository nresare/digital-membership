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
        if let Some(wallet) = &self.wallet
            && wallet.org_name.trim().is_empty()
        {
            anyhow::bail!("wallet.org_name must not be empty");
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
        name = "Example Membership Society"
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
            name = "Example Membership Society"
            signing_key_path = "example.secret"
            name_model = "names.ncmp"
            flags = ["member", "", "vegetarian"]

            [[issuer]]
            id = "choir"
            name = "Example Choral Society"
            description = "Sings on Tuesdays"
            signing_key_path = "choir.secret"
            name_model = "names.ncmp"
            "#,
        )
        .unwrap();

        assert_eq!(config.issuers.len(), 2);
        assert_eq!(config.issuers[0].id, "example");
        assert_eq!(config.issuers[0].name, "Example Membership Society");
        assert_eq!(config.issuers[0].description, None);
        assert_eq!(config.issuers[0].flags, ["member", "", "vegetarian"]);
        assert_eq!(config.issuers[1].id, "choir");
        assert_eq!(
            config.issuers[1].description.as_deref(),
            Some("Sings on Tuesdays")
        );
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
            name = ""
            signing_key_path = "example.secret"
            name_model = "names.ncmp"
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("must have a name"), "{error}");
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
            name = "Example Membership Society"
            signing_key_path = "example.secret"
            name_modle = "names.ncmp"
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("name_modle"), "{error}");
    }

    #[test]
    fn wallet_section_requires_key_and_cert_paths() {
        let error = parse(&format!("{ISSUER}\n[wallet]\nkey_path = \"key.pem\"\n")).unwrap_err();

        assert!(error.to_string().contains("cert_path"));
    }

    #[test]
    fn wallet_accepts_intermediate_override() {
        let config = parse(&format!(
            r#"{ISSUER}
            [wallet]
            key_path = "key.pem"
            cert_path = "pass.pem"
            intermediate_cert_path = "wwdr.pem"
        "#
        ))
        .unwrap();
        assert_eq!(
            config.wallet.unwrap().intermediate_cert_path,
            Some("wwdr.pem".into())
        );
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
            key_path = "/secrets/key.pem"
            cert_path = "/config/cert.pem"
            "#
        ))
        .unwrap();

        assert_eq!(config.bind_address.to_string(), "127.0.0.1:9000");
        let wallet = config.wallet.unwrap();
        assert_eq!(
            wallet.key_path,
            std::path::PathBuf::from("/secrets/key.pem")
        );
        assert_eq!(wallet.org_name, "Digital Membership");
        assert!(wallet.intermediate_cert_path.is_none());
    }
}
