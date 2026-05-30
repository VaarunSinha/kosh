//! Workspace and environment endpoints.
//!
//! The workspace *collection* routes (`GET`/`POST /workspaces`) are gated only
//! by authentication: a user spans many workspaces, so they run under
//! [`AppState::user_tx`] (only `app.user_id` set). The workspace-*scoped* routes
//! (`GET`/`DELETE /workspaces/{id}` and the environment routes) sit behind
//! [`crate::middleware::require_workspace`], which proves membership and injects
//! a [`WorkspaceContext`]; they run under [`AppState::workspace_tx`] so RLS
//! confines every query to that one workspace.

use crate::api::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::middleware::isolation::parse_role;
use crate::middleware::{RoleExt, WorkspaceContext};
use crate::{db, AppState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use kosh_core::models::{EnvName, Role};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateWorkspaceRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceResponse {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEnvRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct EnvResponse {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// Map a unique-constraint violation to a 409 Conflict; pass anything else
/// through as the underlying database error.
fn map_unique(err: sqlx::Error, what: &str) -> ApiError {
    if let sqlx::Error::Database(ref db_err) = err {
        if db_err.is_unique_violation() {
            return ApiError::Conflict(format!("{what} already exists"));
        }
    }
    ApiError::Database(err)
}

/// `GET /workspaces` — list the workspaces the caller belongs to.
pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> ApiResult<Json<Vec<WorkspaceResponse>>> {
    let mut tx = state.user_tx(user.0).await?;
    let rows = sqlx::query(
        "SELECT w.id, w.name, w.owner_id, w.created_at, m.role \
         FROM workspaces w \
         JOIN members m ON m.workspace_id = w.id \
         WHERE m.user_id = $1 \
         ORDER BY w.created_at",
    )
    .bind(user.0)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.rollback().await;

    let out = rows
        .into_iter()
        .map(|r| {
            let role_s: String = r.get("role");
            WorkspaceResponse {
                id: r.get("id"),
                name: r.get("name"),
                owner_id: r.get("owner_id"),
                role: parse_role(&role_s).unwrap_or(Role::Readonly),
                created_at: r.get("created_at"),
            }
        })
        .collect();
    Ok(Json(out))
}

/// `POST /workspaces` — create a workspace; the creator becomes its owner.
pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateWorkspaceRequest>,
) -> ApiResult<(StatusCode, Json<WorkspaceResponse>)> {
    let name = req.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::Validation(
            "workspace name must be 1-100 characters".into(),
        ));
    }

    let mut tx = state.user_tx(user.0).await?;
    let row = sqlx::query(
        "INSERT INTO workspaces (name, owner_id) VALUES ($1, $2) RETURNING id, created_at",
    )
    .bind(name)
    .bind(user.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| map_unique(e, "workspace"))?;

    let id: Uuid = row.get("id");
    let created_at: DateTime<Utc> = row.get("created_at");

    // Scope to the new workspace so the members WITH CHECK policy is satisfied.
    sqlx::query("SELECT set_config('app.workspace_id', $1, true)")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO members (workspace_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(id)
        .bind(user.0)
        .execute(&mut *tx)
        .await?;

    db::record_audit(
        &mut *tx,
        Some(id),
        Some(user.0),
        "workspace.created",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(WorkspaceResponse {
            id,
            name: name.to_string(),
            owner_id: user.0,
            role: Role::Owner,
            created_at,
        }),
    ))
}

/// `GET /workspaces/{workspace_id}` — fetch a single workspace.
pub async fn get(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
) -> ApiResult<Json<WorkspaceResponse>> {
    let row = sqlx::query("SELECT id, name, owner_id, created_at FROM workspaces WHERE id = $1")
        .bind(ctx.workspace_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::WorkspaceNotFound(ctx.workspace_id.to_string()))?;

    Ok(Json(WorkspaceResponse {
        id: row.get("id"),
        name: row.get("name"),
        owner_id: row.get("owner_id"),
        role: ctx.role,
        created_at: row.get("created_at"),
    }))
}

/// `DELETE /workspaces/{workspace_id}` — owner-only; cascades to all children.
pub async fn delete(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
) -> ApiResult<StatusCode> {
    if !ctx.role.is_owner() {
        return Err(ApiError::Forbidden(
            "only the workspace owner can delete it".into(),
        ));
    }

    // Record the event before the cascade removes the workspace.
    db::record_audit(
        &state.pool,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "workspace.deleted",
        None,
        None,
    )
    .await?;
    sqlx::query("DELETE FROM workspaces WHERE id = $1")
        .bind(ctx.workspace_id)
        .execute(&state.pool)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /workspaces/{workspace_id}/environments` — list environments.
pub async fn list_envs(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
) -> ApiResult<Json<Vec<EnvResponse>>> {
    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let rows = sqlx::query("SELECT id, name, created_at FROM environments ORDER BY name")
        .fetch_all(&mut *tx)
        .await?;
    let _ = tx.rollback().await;

    let out = rows
        .into_iter()
        .map(|r| EnvResponse {
            id: r.get("id"),
            name: r.get("name"),
            created_at: r.get("created_at"),
        })
        .collect();
    Ok(Json(out))
}

/// `POST /workspaces/{workspace_id}/environments` — create an environment.
pub async fn create_env(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Json(req): Json<CreateEnvRequest>,
) -> ApiResult<(StatusCode, Json<EnvResponse>)> {
    if !ctx.role.can_manage_envs() {
        return Err(ApiError::Forbidden(
            "your role cannot manage environments".into(),
        ));
    }
    let name = EnvName::parse(&req.name)
        .map_err(|_| ApiError::Validation(format!("invalid environment name: {}", req.name)))?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let row = sqlx::query(
        "INSERT INTO environments (workspace_id, name) VALUES ($1, $2) RETURNING id, created_at",
    )
    .bind(ctx.workspace_id)
    .bind(name.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| map_unique(e, "environment"))?;

    let id: Uuid = row.get("id");
    let created_at: DateTime<Utc> = row.get("created_at");

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "env.created",
        None,
        Some(name.as_str()),
    )
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(EnvResponse {
            id,
            name: name.to_string(),
            created_at,
        }),
    ))
}

/// `DELETE /workspaces/{workspace_id}/environments/{environment_id}`.
pub async fn delete_env(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<StatusCode> {
    if !ctx.role.can_manage_envs() {
        return Err(ApiError::Forbidden(
            "your role cannot manage environments".into(),
        ));
    }
    let env_id = params
        .get("environment_id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::EnvNotFound("invalid environment id".into()))?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let res = sqlx::query("DELETE FROM environments WHERE id = $1")
        .bind(env_id)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::EnvNotFound(env_id.to_string()));
    }
    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "env.deleted",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
