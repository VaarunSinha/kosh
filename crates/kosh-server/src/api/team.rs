//! Team membership, per-member env-key exchange, and public-key publishing.
//!
//! Env keys and public keys are **ciphertext / public material only**: the
//! server stores the env private key already encrypted to each member's public
//! key (`encrypted_env_key`) and members' public keys, never any plaintext
//! private key.

use crate::api::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::middleware::isolation::parse_role;
use crate::middleware::{RoleExt, WorkspaceContext};
use crate::{db, AppState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use kosh_core::models::Role;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub user_id: Uuid,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct MemberResponse {
    pub user_id: Uuid,
    pub role: Role,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct EnvKeyRequest {
    /// The env private key, encrypted to the member's public key (base64).
    pub encrypted_env_key: String,
}

#[derive(Debug, Serialize)]
pub struct EnvKeyResponse {
    pub member_user_id: Uuid,
    pub encrypted_env_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyRequest {
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub user_id: Uuid,
    pub public_key: String,
}

fn parse_role_or_400(s: &str) -> ApiResult<Role> {
    parse_role(s).ok_or_else(|| ApiError::Validation(format!("invalid role: {s}")))
}

fn user_param(params: &HashMap<String, String>, key: &str) -> ApiResult<Uuid> {
    params
        .get(key)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ApiError::Validation(format!("invalid {key}")))
}

/// `GET /workspaces/{workspace_id}/members` — list members.
pub async fn list_members(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
) -> ApiResult<Json<Vec<MemberResponse>>> {
    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let rows = sqlx::query("SELECT user_id, role, joined_at FROM members ORDER BY joined_at")
        .fetch_all(&mut *tx)
        .await?;
    let _ = tx.rollback().await;

    let out = rows
        .into_iter()
        .map(|r| {
            let role_s: String = r.get("role");
            MemberResponse {
                user_id: r.get("user_id"),
                role: parse_role(&role_s).unwrap_or(Role::Readonly),
                joined_at: r.get("joined_at"),
            }
        })
        .collect();
    Ok(Json(out))
}

/// `POST /workspaces/{workspace_id}/members` — invite a member by user id.
pub async fn invite_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Json(req): Json<InviteMemberRequest>,
) -> ApiResult<(StatusCode, Json<MemberResponse>)> {
    if !ctx.role.can_manage_members() {
        return Err(ApiError::Forbidden(
            "your role cannot manage members".into(),
        ));
    }
    let role = parse_role_or_400(&req.role)?;
    // Only an owner may grant the owner role.
    if role.is_owner() && !ctx.role.is_owner() {
        return Err(ApiError::Forbidden(
            "only the owner can grant the owner role".into(),
        ));
    }

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let row = sqlx::query(
        "INSERT INTO members (workspace_id, user_id, role) VALUES ($1, $2, $3) \
         RETURNING user_id, role, joined_at",
    )
    .bind(ctx.workspace_id)
    .bind(req.user_id)
    .bind(req.role)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref d) if d.is_unique_violation() => {
            ApiError::Conflict(format!("{} is already a member", req.user_id))
        }
        other => ApiError::Database(other),
    })?;

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "member.invited",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    let role_s: String = row.get("role");
    Ok((
        StatusCode::CREATED,
        Json(MemberResponse {
            user_id: row.get("user_id"),
            role: parse_role(&role_s).unwrap_or(role),
            joined_at: row.get("joined_at"),
        }),
    ))
}

/// `PUT /workspaces/{workspace_id}/members/{member_user_id}` — change a role.
pub async fn update_member_role(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
    Json(req): Json<UpdateRoleRequest>,
) -> ApiResult<Json<MemberResponse>> {
    if !ctx.role.can_manage_members() {
        return Err(ApiError::Forbidden(
            "your role cannot manage members".into(),
        ));
    }
    let target = user_param(&params, "member_user_id")?;
    let new_role = parse_role_or_400(&req.role)?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;

    // Inspect the current role; touching an owner requires being an owner.
    let current: Option<(String,)> =
        sqlx::query_as("SELECT role FROM members WHERE workspace_id = $1 AND user_id = $2")
            .bind(ctx.workspace_id)
            .bind(target)
            .fetch_optional(&mut *tx)
            .await?;
    let current = current
        .and_then(|(r,)| parse_role(&r))
        .ok_or_else(|| ApiError::Forbidden("no such member".into()))?;
    if (current.is_owner() || new_role.is_owner()) && !ctx.role.is_owner() {
        return Err(ApiError::Forbidden(
            "only the owner can change owner roles".into(),
        ));
    }

    let row = sqlx::query(
        "UPDATE members SET role = $1 WHERE workspace_id = $2 AND user_id = $3 \
         RETURNING user_id, role, joined_at",
    )
    .bind(&req.role)
    .bind(ctx.workspace_id)
    .bind(target)
    .fetch_one(&mut *tx)
    .await?;

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "member.role_changed",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    let role_s: String = row.get("role");
    Ok(Json(MemberResponse {
        user_id: row.get("user_id"),
        role: parse_role(&role_s).unwrap_or(new_role),
        joined_at: row.get("joined_at"),
    }))
}

/// `DELETE /workspaces/{workspace_id}/members/{member_user_id}` — remove member.
pub async fn remove_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<StatusCode> {
    if !ctx.role.can_manage_members() {
        return Err(ApiError::Forbidden(
            "your role cannot manage members".into(),
        ));
    }
    let target = user_param(&params, "member_user_id")?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let current: Option<(String,)> =
        sqlx::query_as("SELECT role FROM members WHERE workspace_id = $1 AND user_id = $2")
            .bind(ctx.workspace_id)
            .bind(target)
            .fetch_optional(&mut *tx)
            .await?;
    let current = current
        .and_then(|(r,)| parse_role(&r))
        .ok_or_else(|| ApiError::Forbidden("no such member".into()))?;
    // The founding owner cannot be removed; only an owner may remove an owner.
    if current.is_owner() {
        return Err(ApiError::Forbidden(
            "cannot remove the workspace owner".into(),
        ));
    }

    sqlx::query("DELETE FROM members WHERE workspace_id = $1 AND user_id = $2")
        .bind(ctx.workspace_id)
        .bind(target)
        .execute(&mut *tx)
        .await?;
    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "member.removed",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Resolve a member row id from a user id within the scoped workspace.
async fn member_id_for(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Uuid> {
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM members WHERE workspace_id = $1 AND user_id = $2")
            .bind(workspace_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await?;
    row.map(|(id,)| id)
        .ok_or_else(|| ApiError::Forbidden("target is not a member".into()))
}

/// `PUT .../environments/{environment_id}/keys/{member_user_id}` — store the
/// env private key encrypted to that member's public key.
pub async fn upload_env_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
    Json(req): Json<EnvKeyRequest>,
) -> ApiResult<StatusCode> {
    if !ctx.role.can_write_secrets() {
        return Err(ApiError::Forbidden(
            "your role cannot distribute env keys".into(),
        ));
    }
    let env_id = user_param(&params, "environment_id")?;
    let member_user_id = user_param(&params, "member_user_id")?;
    let blob = STANDARD
        .decode(req.encrypted_env_key.trim())
        .map_err(|_| ApiError::Validation("encrypted_env_key must be base64".into()))?;
    if blob.is_empty() {
        return Err(ApiError::Validation(
            "encrypted_env_key must not be empty".into(),
        ));
    }

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let member_id = member_id_for(&mut tx, ctx.workspace_id, member_user_id).await?;

    sqlx::query(
        "INSERT INTO env_keys (workspace_id, environment_id, member_id, encrypted_env_key) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (environment_id, member_id) \
         DO UPDATE SET encrypted_env_key = EXCLUDED.encrypted_env_key",
    )
    .bind(ctx.workspace_id)
    .bind(env_id)
    .bind(member_id)
    .bind(&blob)
    .execute(&mut *tx)
    .await?;

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "sync.push",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET .../environments/{environment_id}/keys/{member_user_id}` — fetch a
/// member's encrypted env key. A member may fetch their own; managers any.
pub async fn get_env_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<Json<EnvKeyResponse>> {
    let env_id = user_param(&params, "environment_id")?;
    let member_user_id = user_param(&params, "member_user_id")?;
    if member_user_id != ctx.user_id && !ctx.role.can_manage_members() {
        return Err(ApiError::Forbidden(
            "cannot read another member's env key".into(),
        ));
    }

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let member_id = member_id_for(&mut tx, ctx.workspace_id, member_user_id).await?;
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT encrypted_env_key FROM env_keys WHERE environment_id = $1 AND member_id = $2",
    )
    .bind(env_id)
    .bind(member_id)
    .fetch_optional(&mut *tx)
    .await?;
    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "sync.pull",
        None,
        None,
    )
    .await?;
    tx.commit().await?;

    let blob = row
        .map(|(b,)| b)
        .ok_or_else(|| ApiError::EnvNotFound("no env key for this member".into()))?;

    Ok(Json(EnvKeyResponse {
        member_user_id,
        encrypted_env_key: STANDARD.encode(&blob),
    }))
}

/// `PUT /users/me/public-key` — publish the caller's public key.
pub async fn upload_public_key(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<PublicKeyRequest>,
) -> ApiResult<StatusCode> {
    let key = STANDARD
        .decode(req.public_key.trim())
        .map_err(|_| ApiError::Validation("public_key must be base64".into()))?;
    if key.is_empty() {
        return Err(ApiError::Validation("public_key must not be empty".into()));
    }

    sqlx::query(
        "INSERT INTO user_public_keys (user_id, public_key) VALUES ($1, $2) \
         ON CONFLICT (user_id) DO UPDATE SET public_key = EXCLUDED.public_key, uploaded_at = NOW()",
    )
    .bind(user.0)
    .bind(&key)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /users/{user_id}/public-key` — fetch a user's public key (public info).
pub async fn get_public_key(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<Json<PublicKeyResponse>> {
    let user_id = user_param(&params, "user_id")?;
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT public_key FROM user_public_keys WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let key = row
        .map(|(k,)| k)
        .ok_or_else(|| ApiError::SecretNotFound(format!("no public key for {user_id}")))?;

    Ok(Json(PublicKeyResponse {
        user_id,
        public_key: STANDARD.encode(&key),
    }))
}
