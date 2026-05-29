//! Per-workspace isolation + role authorization.
//!
//! For any `/workspaces/{workspace_id}/...` route this middleware:
//! 1. Confirms the authenticated caller is a member of that workspace (else
//!    [`ApiError::Forbidden`]).
//! 2. Resolves the caller's [`Role`] and injects a [`WorkspaceContext`] into the
//!    request extensions for downstream handlers and role gates.
//!
//! The actual data-access isolation is enforced by Postgres Row-Level Security:
//! handlers run their queries inside a transaction opened with
//! [`crate::AppState::workspace_tx`], which sets the `app.workspace_id` /
//! `app.user_id` GUCs the RLS policies key on. An unset GUC fails closed (zero
//! rows), so a missing `SET LOCAL` can never leak another workspace's data.

use crate::api::auth::AuthUser;
use crate::error::ApiError;
use crate::AppState;
use axum::extract::{Path, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use kosh_core::models::Role;
use std::collections::HashMap;
use uuid::Uuid;

/// The resolved workspace + the caller's role within it.
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceContext {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub role: Role,
}

/// Parse a role string (as stored in the `members.role` column) into a [`Role`].
pub fn parse_role(s: &str) -> Option<Role> {
    match s {
        "owner" => Some(Role::Owner),
        "admin" => Some(Role::Admin),
        "developer" => Some(Role::Developer),
        "readonly" => Some(Role::Readonly),
        "ci" => Some(Role::Ci),
        _ => None,
    }
}

/// Capability checks layered on top of [`Role`].
pub trait RoleExt {
    /// Every member can read their workspace's data.
    fn can_read(&self) -> bool;
    /// Create/update/delete secrets and flag rotations.
    fn can_write_secrets(&self) -> bool;
    /// Invite/remove members and change roles.
    fn can_manage_members(&self) -> bool;
    /// Create/delete environments.
    fn can_manage_envs(&self) -> bool;
    /// Destructive workspace-level operations (delete the workspace).
    fn is_owner(&self) -> bool;
}

impl RoleExt for Role {
    fn can_read(&self) -> bool {
        true
    }

    fn can_write_secrets(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin | Role::Developer)
    }

    fn can_manage_members(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    fn can_manage_envs(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    fn is_owner(&self) -> bool {
        matches!(self, Role::Owner)
    }
}

/// Membership-gating middleware for workspace-scoped routes.
///
/// Must run *after* [`crate::middleware::require_auth`], which supplies the
/// [`AuthUser`] extension.
pub async fn require_workspace(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(params): Path<HashMap<String, String>>,
    mut req: Request,
    next: Next,
) -> Response {
    match resolve(&state, user.0, &params, &mut req).await {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

async fn resolve(
    state: &AppState,
    user_id: Uuid,
    params: &HashMap<String, String>,
    req: &mut Request,
) -> Result<(), ApiError> {
    let workspace_id = params
        .get("workspace_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::WorkspaceNotFound("invalid workspace id".into()))?;

    // Resolve membership inside a scoped transaction so the RLS GUCs are set
    // (the members table is itself under RLS).
    let mut tx = state.workspace_tx(workspace_id, user_id).await?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM members WHERE workspace_id = $1 AND user_id = $2")
            .bind(workspace_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
    // Read-only check; nothing to persist.
    let _ = tx.rollback().await;

    let role = row
        .and_then(|(r,)| parse_role(&r))
        .ok_or_else(|| ApiError::Forbidden("not a member of this workspace".into()))?;

    req.extensions_mut().insert(WorkspaceContext {
        workspace_id,
        user_id,
        role,
    });
    Ok(())
}
