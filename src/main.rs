mod config;

use crate::config::Config;
use clap::Parser;
use digital_membership::{AppState, app};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
struct Cli {
    #[arg(
        short = 'c',
        long = "config-file",
        value_name = "PATH",
        default_value = "/config/digital-membership.toml"
    )]
    config_path: PathBuf,
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
    let config = Config::load(&cli.config_path)?;
    info!(
        version = VERSION,
        config_path = %cli.config_path.display(),
        address = %config.bind_address,
        name_model = %config.name_model.display(),
        wallet = config.wallet.is_some(),
        "starting digital-membership"
    );

    let state = AppState::generate_with_wallet(&config.name_model, config.wallet)?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    info!(address = %config.bind_address, "listening");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn config_path_defaults_to_deployment_location() {
        let cli = Cli::try_parse_from(["digital-membership"]).unwrap();
        assert_eq!(
            cli.config_path,
            PathBuf::from("/config/digital-membership.toml")
        );

        let cli =
            Cli::try_parse_from(["digital-membership", "-c", "digital-membership.toml"]).unwrap();
        assert_eq!(cli.config_path, PathBuf::from("digital-membership.toml"));
    }
}
