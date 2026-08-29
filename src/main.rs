use clap::Parser;
use digital_membership::{AppState, app};
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

    let state = AppState::generate(&cli.name_model)?;
    let listener = tokio::net::TcpListener::bind(cli.bind_address).await?;
    info!(address = %cli.bind_address, "listening");
    axum::serve(listener, app(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn requires_name_model_path() {
        assert!(Cli::try_parse_from(["digital-membership"]).is_err());

        let cli = Cli::try_parse_from(["digital-membership", "--name-model", "models/names.ncmp"])
            .unwrap();
        assert_eq!(cli.name_model, PathBuf::from("models/names.ncmp"));
    }
}
