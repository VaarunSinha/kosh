use kosh_server::{app, config::ServerConfig, db, AppState};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
