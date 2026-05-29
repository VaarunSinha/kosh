//! Kosh self-hostable team-sync server.
//!
//! Zero-knowledge: the server only ever stores ciphertext (encrypted secret
//! blobs), encrypted per-member env keys, and members' public keys. Plaintext
//! secrets and plaintext env private keys never reach the server.

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod middleware;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;

/// Shared application state, cloned into every handler and middleware.
#[derive(Clone)]
pub struct AppState {
    /// Pool connected as the non-superuser `kosh_app` role (RLS enforced).
    pub pool: PgPool,
    /// HMAC secret used to sign and verify access tokens.
    pub jwt_secret: Arc<str>,
}

/// Liveness probe. Used by load balancers and the test harness.
async fn health() -> &'static str {
    "ok"
}

/// Build the application router.
///
/// `/health` is public; the `/auth/*` routes sit behind the Bearer-token
/// authentication middleware. Workspace/secret/team routes are mounted in later
/// milestones.
pub fn app(state: AppState) -> Router {
    let protected = Router::new()
        .route("/auth/refresh", post(api::auth::refresh_token))
        .route("/auth/logout", post(api::auth::logout))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
}
