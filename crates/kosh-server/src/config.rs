//! Server configuration, loaded from the environment.

use anyhow::Context;

/// Runtime configuration for `kosh-server`.
///
/// Two database URLs are used deliberately:
/// - `database_url` is an **admin/superuser** connection used once at startup
///   to run migrations (which `CREATE ROLE kosh_app`, etc.).
/// - `app_database_url` is the **non-superuser `kosh_app`** connection used for
///   all request handling. This is required because Postgres superusers bypass
///   Row-Level Security — isolation only holds when we connect as `kosh_app`.
///
/// If `KOSH_APP_DATABASE_URL` is unset, both fall back to `DATABASE_URL` (fine
/// for local dev where you may run everything as one role, but RLS will only be
/// truly enforced when a non-superuser app role is used).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub database_url: String,
    pub app_database_url: String,
    pub jwt_secret: String,
    pub bind_addr: String,
}

impl ServerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
        let app_database_url =
            std::env::var("KOSH_APP_DATABASE_URL").unwrap_or_else(|_| database_url.clone());
        let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET must be set")?;
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        Ok(Self {
            database_url,
            app_database_url,
            jwt_secret,
            bind_addr,
        })
    }
}
