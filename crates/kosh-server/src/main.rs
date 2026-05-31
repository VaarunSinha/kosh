use clap::{Parser, Subcommand};
use kosh_server::api::auth::{mint_token, ACCESS_TTL_SECONDS};
use kosh_server::{app, config::ServerConfig, db, AppState};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "kosh-server", about = "Kosh team-sync server", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP server (default when no subcommand is given)
    Serve,
    /// Mint a JWT access token for a user (out-of-band provisioning)
    ///
    /// Reads KOSH_JWT_SECRET from the environment. The printed token can be
    /// handed to a new team member who runs `kosh login --server <url>
    /// --token <token>`.
    ///
    /// Example:
    ///   kosh-server issue-token --user 550e8400-e29b-41d4-a716-446655440000
    IssueToken {
        /// User UUID the token will be issued for
        #[arg(long)]
        user: Uuid,
        /// Token lifetime in seconds (default: 3600)
        #[arg(long, default_value_t = ACCESS_TTL_SECONDS)]
        ttl: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => serve().await,
        Commands::IssueToken { user, ttl } => issue_token(user, ttl),
    }
}

async fn serve() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = ServerConfig::from_env()?;

    // Run migrations as the admin role (they CREATE ROLE kosh_app, enable RLS).
    db::run_migrations(&cfg.database_url).await?;

    // Handle requests as the non-superuser app role so RLS is enforced.
    let pool = db::connect(&cfg.app_database_url, 10).await?;
    let state = AppState {
        pool,
        jwt_secret: Arc::from(cfg.jwt_secret.as_str()),
    };

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("kosh-server listening on {}", cfg.bind_addr);
    axum::serve(listener, app(state)).await?;
    Ok(())
}

fn issue_token(user: Uuid, ttl: i64) -> anyhow::Result<()> {
    let secret = std::env::var("KOSH_JWT_SECRET")
        .map_err(|_| anyhow::anyhow!("KOSH_JWT_SECRET is not set"))?;
    if secret.is_empty() {
        anyhow::bail!("KOSH_JWT_SECRET must not be empty");
    }

    let token = mint_token(user, &secret, ttl)?;
    println!("{token}");
    Ok(())
}
