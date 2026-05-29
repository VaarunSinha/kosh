use kosh_server::{app, config::ServerConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = ServerConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("kosh-server listening on {}", cfg.bind_addr);
    axum::serve(listener, app()).await?;
    Ok(())
}
