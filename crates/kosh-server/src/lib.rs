//! Kosh self-hostable team-sync server.
//!
//! Zero-knowledge: the server only ever stores ciphertext (encrypted secret
//! blobs), encrypted per-member env keys, and members' public keys. Plaintext
//! secrets and plaintext env private keys never reach the server.

pub mod config;
pub mod error;

use axum::{routing::get, Router};

/// Liveness probe. Used by load balancers and the test harness.
async fn health() -> &'static str {
    "ok"
}

/// Build the application router.
///
/// For now this only serves `/health`; protected API routes (with the auth and
/// workspace-isolation layers) are mounted in later milestones.
pub fn app() -> Router {
    Router::new().route("/health", get(health))
}
