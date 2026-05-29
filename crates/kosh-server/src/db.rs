//! Database connection + migrations.
//!
//! Runtime queries (not compile-time `query!`) are used throughout so the build
//! never needs a live database or an offline `.sqlx` cache.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Embedded migrations from `crates/kosh-server/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Open a connection pool to `url`.
pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
}

/// Run all migrations against an **admin/superuser** connection.
///
/// Migrations create the `kosh_app` role, enable RLS, etc., so they must not be
/// run as `kosh_app` itself.
pub async fn run_migrations(admin_url: &str) -> anyhow::Result<()> {
    let pool = connect(admin_url, 1).await?;
    MIGRATOR.run(&pool).await?;
    pool.close().await;
    Ok(())
}
