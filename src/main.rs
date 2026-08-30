mod config;

use crate::config::Config;
use clap::Parser;
use digital_membership::{AppState, SigningKey, app};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_SIGNING_KEY_PATH: &str = "signing-key.secret";

#[derive(Debug, Parser)]
struct Cli {
    #[arg(
        short = 'c',
        long = "config-file",
        value_name = "PATH",
        default_value = "/config/digital-membership.toml"
    )]
    config_path: PathBuf,

    /// Generate a signing key, write it to PATH, print its public key and exit.
    #[arg(
        long = "key-gen",
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = DEFAULT_SIGNING_KEY_PATH,
    )]
    key_gen: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "digital_membership=debug,tower_http=info,axum::rejection=trace",
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_writer(std::io::stderr),
        )
        .init();

    if let Err(error) = run().await {
        error!("{error:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(path) = &cli.key_gen {
        return generate_key(path);
    }

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

/// Writes a freshly generated signing key to `path` and prints its public key to
/// stdout. The key file is the only copy of the secret, so an existing file is
/// never overwritten: replacing it would silently invalidate every credential
/// already issued under it.
fn generate_key(path: &Path) -> anyhow::Result<()> {
    let key = SigningKey::generate()?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => anyhow::anyhow!(
            "signing key '{}' already exists; remove it first to replace the key, \
             which invalidates every credential issued under it",
            path.display()
        ),
        _ => anyhow::anyhow!("failed to create signing key '{}': {error}", path.display()),
    })?;
    file.write_all(format!("{}\n", key.secret_base64()).as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            anyhow::anyhow!("failed to write signing key '{}': {error}", path.display())
        })?;

    info!(path = %path.display(), "wrote signing key");
    println!("{}", key.public_key_base64());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cli, generate_key};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn key_gen_is_off_by_default_and_has_a_default_path() {
        let cli = Cli::try_parse_from(["digital-membership"]).unwrap();
        assert!(cli.key_gen.is_none());

        let cli = Cli::try_parse_from(["digital-membership", "--key-gen"]).unwrap();
        assert_eq!(cli.key_gen, Some(PathBuf::from("signing-key.secret")));

        let cli = Cli::try_parse_from(["digital-membership", "--key-gen", "other.secret"]).unwrap();
        assert_eq!(cli.key_gen, Some(PathBuf::from("other.secret")));
    }

    #[test]
    fn key_gen_writes_a_secret_and_refuses_to_overwrite_it() {
        let path = std::env::temp_dir().join(format!(
            "digital-membership-key-gen-{}.secret",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        generate_key(&path).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.is_ascii());
        assert!(written.ends_with('\n'));
        assert_eq!(
            URL_SAFE_NO_PAD.decode(written.trim_end()).unwrap().len(),
            32
        );

        let error = generate_key(&path).unwrap_err().to_string();
        std::fs::remove_file(&path).unwrap();
        assert!(error.contains("already exists"), "{error}");
    }

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
