use clap::Parser;
use digital_membership::{AppState, WalletConfig, app};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind_address: SocketAddr,

    #[arg(long, value_name = "PATH")]
    name_model: PathBuf,

    /// PKCS#12 identity containing the Apple Pass Type certificate and private key.
    #[arg(long, value_name = "PATH")]
    wallet_pkcs12: Option<PathBuf>,

    /// Apple Worldwide Developer Relations intermediate certificate (PEM or DER).
    #[arg(long, value_name = "PATH")]
    wallet_wwdr_certificate: Option<PathBuf>,

    #[arg(long)]
    wallet_pass_type_identifier: Option<String>,

    #[arg(long)]
    wallet_team_identifier: Option<String>,

    #[arg(long, default_value = "Digital Membership")]
    wallet_organization_name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "digital_membership=debug,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run().await {
        error!("{error:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    info!(
        version = VERSION,
        address = %cli.bind_address,
        name_model = %cli.name_model.display(),
        "starting digital-membership"
    );

    let wallet_config = wallet_config(&cli)?;
    let state = AppState::generate_with_wallet(&cli.name_model, wallet_config)?;
    let listener = tokio::net::TcpListener::bind(cli.bind_address).await?;
    info!(address = %cli.bind_address, "listening");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

fn wallet_config(cli: &Cli) -> anyhow::Result<Option<WalletConfig>> {
    let wallet_requested = cli.wallet_pkcs12.is_some()
        || cli.wallet_wwdr_certificate.is_some()
        || cli.wallet_pass_type_identifier.is_some()
        || cli.wallet_team_identifier.is_some();
    if !wallet_requested {
        return Ok(None);
    }

    let missing = [
        ("--wallet-pkcs12", cli.wallet_pkcs12.is_none()),
        (
            "--wallet-wwdr-certificate",
            cli.wallet_wwdr_certificate.is_none(),
        ),
        (
            "--wallet-pass-type-identifier",
            cli.wallet_pass_type_identifier.is_none(),
        ),
        (
            "--wallet-team-identifier",
            cli.wallet_team_identifier.is_none(),
        ),
    ]
    .into_iter()
    .filter_map(|(name, is_missing)| is_missing.then_some(name))
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "incomplete Apple Wallet configuration; missing {}",
            missing.join(", ")
        );
    }

    Ok(Some(WalletConfig {
        pkcs12_path: cli.wallet_pkcs12.clone().unwrap(),
        pkcs12_password: std::env::var("DIGITAL_MEMBERSHIP_WALLET_P12_PASSWORD")
            .unwrap_or_default(),
        wwdr_certificate_path: cli.wallet_wwdr_certificate.clone().unwrap(),
        pass_type_identifier: cli.wallet_pass_type_identifier.clone().unwrap(),
        team_identifier: cli.wallet_team_identifier.clone().unwrap(),
        organization_name: cli.wallet_organization_name.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{Cli, wallet_config};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn requires_name_model_path() {
        assert!(Cli::try_parse_from(["digital-membership"]).is_err());

        let cli = Cli::try_parse_from(["digital-membership", "--name-model", "models/names.ncmp"])
            .unwrap();
        assert_eq!(cli.name_model, PathBuf::from("models/names.ncmp"));
    }

    #[test]
    fn wallet_configuration_is_optional_but_atomic() {
        let cli =
            Cli::try_parse_from(["digital-membership", "--name-model", "names.ncmp"]).unwrap();
        assert!(wallet_config(&cli).unwrap().is_none());

        let cli = Cli::try_parse_from([
            "digital-membership",
            "--name-model",
            "names.ncmp",
            "--wallet-pkcs12",
            "pass.p12",
        ])
        .unwrap();
        assert!(
            wallet_config(&cli)
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
    }
}
