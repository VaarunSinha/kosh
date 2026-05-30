//! Database connection + migrations.
//!
//! Runtime queries (not compile-time `query!`) are used throughout so the build
//! never needs a live database or an offline `.sqlx` cache.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

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

/// Append a row to the append-only `audit_log`.
///
/// Works with either a pool or a `&mut *tx`. `audit_log` is not under RLS and
/// the `kosh_app` role has INSERT but not UPDATE/DELETE, so history is
/// tamper-evident. Optional columns (`ref_id`, `environment`) may be `None`.
#[allow(clippy::too_many_arguments)]
pub async fn record_audit<'e, E>(
    executor: E,
    workspace_id: Option<Uuid>,
    user_id: Option<Uuid>,
    event: &str,
    ref_id: Option<&str>,
    environment: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO audit_log (workspace_id, user_id, event, ref_id, environment) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(workspace_id)
    .bind(user_id)
    .bind(event)
    .bind(ref_id)
    .bind(environment)
    .execute(executor)
    .await?;
    Ok(())
}
