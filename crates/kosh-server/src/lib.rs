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
    routing::{delete, get, post, put},
    Router,
};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

/// Shared application state, cloned into every handler and middleware.
#[derive(Clone)]
pub struct AppState {
    /// Pool connected as the non-superuser `kosh_app` role (RLS enforced).
    pub pool: PgPool,
    /// HMAC secret used to sign and verify access tokens.
    pub jwt_secret: Arc<str>,
}

impl AppState {
    /// Begin a transaction scoped to a workspace and user.
    ///
    /// Sets the `app.workspace_id` and `app.user_id` GUCs (transaction-local)
    /// that the Row-Level Security policies key on. All workspace-scoped data
    /// access must go through a transaction opened here; otherwise the unset
    /// GUC fails closed and queries return zero rows.
    pub async fn workspace_tx(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // `SET LOCAL` cannot take a bind parameter; `set_config(_, _, true)` is
        // the parameterized, transaction-local equivalent.
        sqlx::query("SELECT set_config('app.user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('app.workspace_id', $1, true)")
            .bind(workspace_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Begin a transaction scoped to a user but not a single workspace.
    ///
    /// Sets only `app.user_id`, which lets the caller read their own membership
    /// rows across workspaces (the `members` RLS policy allows `user_id =
    /// app.user_id`). Used by the non-scoped workspace-collection routes
    /// (list/create), where there is no single `app.workspace_id`.
    pub async fn user_tx(&self, user_id: Uuid) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}

/// Liveness probe. Used by load balancers and the test harness.
async fn health() -> &'static str {
    "ok"
}

/// Build the application router.
///
/// `/health` is public. Everything else requires a valid Bearer token
/// (`require_auth`). Workspace-scoped routes additionally pass through
/// `require_workspace`, which proves membership and injects the caller's role.
/// Layering order is: `require_auth` (outermost) → `require_workspace` →
/// handler, so the membership check always sees an authenticated user.
pub fn app(state: AppState) -> Router {
    // Workspace-scoped routes: auth + membership.
    let scoped = Router::new()
        .route(
            "/workspaces/{workspace_id}",
            get(api::workspaces::get).delete(api::workspaces::delete),
        )
        .route(
            "/workspaces/{workspace_id}/environments",
            get(api::workspaces::list_envs).post(api::workspaces::create_env),
        )
        .route(
            "/workspaces/{workspace_id}/environments/{environment_id}",
            delete(api::workspaces::delete_env),
        )
        .route(
            "/workspaces/{workspace_id}/environments/{environment_id}/secrets",
            get(api::secrets::list_secrets).post(api::secrets::upload_secret),
        )
        .route(
            "/workspaces/{workspace_id}/environments/{environment_id}/secrets/{ref_id}",
            get(api::secrets::download_secret)
                .put(api::secrets::update_secret)
                .delete(api::secrets::delete_secret),
        )
        .route(
            "/workspaces/{workspace_id}/environments/{environment_id}/secrets/{ref_id}/rotate",
            post(api::secrets::flag_rotation),
        )
        .route(
            "/workspaces/{workspace_id}/rotations",
            get(api::secrets::list_rotation_due),
        )
        .route(
            "/workspaces/{workspace_id}/members",
            get(api::team::list_members).post(api::team::invite_member),
        )
        .route(
            "/workspaces/{workspace_id}/members/{member_user_id}",
            put(api::team::update_member_role).delete(api::team::remove_member),
        )
        .route(
            "/workspaces/{workspace_id}/environments/{environment_id}/keys/{member_user_id}",
            get(api::team::get_env_key).put(api::team::upload_env_key),
        )
        .route("/workspaces/{workspace_id}/audit", get(api::audit::list))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_workspace,
        ));

    // Collection + auth routes: auth only.
    let protected = Router::new()
        .route(
            "/workspaces",
            get(api::workspaces::list).post(api::workspaces::create),
        )
        .route("/auth/refresh", post(api::auth::refresh_token))
        .route("/auth/logout", post(api::auth::logout))
        .route("/users/me/public-key", put(api::team::upload_public_key))
        .route(
            "/users/{user_id}/public-key",
            get(api::team::get_public_key),
        )
        .merge(scoped)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
}
