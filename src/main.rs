use clap::Parser;
use digital_membership::{AppState, app};
use std::net::SocketAddr;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind_address: SocketAddr,
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
    info!(version = VERSION, address = %cli.bind_address, "starting digital-membership");

    let state = AppState::generate()?;
    let listener = tokio::net::TcpListener::bind(cli.bind_address).await?;
    info!(address = %cli.bind_address, "listening");
    axum::serve(listener, app(state)).await?;
    Ok(())
}
