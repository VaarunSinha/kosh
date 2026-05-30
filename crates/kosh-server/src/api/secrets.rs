//! Secret endpoints. **Zero-knowledge**: the server stores and returns only the
//! opaque `encrypted_blob` (ciphertext, base64-encoded in JSON). It never
//! decrypts, inspects, or logs plaintext. All access runs under
//! [`AppState::workspace_tx`] so Row-Level Security confines every row to the
//! caller's workspace.

use crate::error::{ApiError, ApiResult};
use crate::middleware::{RoleExt, WorkspaceContext};
use crate::{db, AppState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use kosh_core::models::KeyName;
use kosh_core::reference::RefId;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct UploadSecretRequest {
    pub ref_id: String,
    pub key_name: String,
    /// Ciphertext, base64-encoded. The server never decodes its meaning.
    pub encrypted_blob: String,
    pub rotation_due_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecretRequest {
    pub encrypted_blob: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct FlagRotationRequest {
    /// When the rotation becomes due; defaults to now if omitted.
    pub rotation_due_at: Option<DateTime<Utc>>,
}

/// Metadata view of a secret — never includes the ciphertext.
#[derive(Debug, Serialize)]
pub struct SecretMeta {
    pub ref_id: String,
    pub key_name: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rotation_due_at: Option<DateTime<Utc>>,
}

/// Full view including the base64 ciphertext, returned on download.
#[derive(Debug, Serialize)]
pub struct SecretBlob {
    pub ref_id: String,
    pub key_name: String,
    pub encrypted_blob: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rotation_due_at: Option<DateTime<Utc>>,
}

fn meta_from_row(r: &sqlx::postgres::PgRow) -> SecretMeta {
    SecretMeta {
        ref_id: r.get("ref_id"),
        key_name: r.get("key_name"),
        created_by: r.get("created_by"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        rotation_due_at: r.get("rotation_due_at"),
    }
}

/// Decode + validate an incoming base64 blob into raw ciphertext bytes.
fn decode_blob(b64: &str) -> ApiResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(b64.trim())
        .map_err(|_| ApiError::Validation("encrypted_blob must be valid base64".into()))?;
    if bytes.is_empty() {
        return Err(ApiError::Validation(
            "encrypted_blob must not be empty".into(),
        ));
    }
    Ok(bytes)
}

/// Extract a UUID path parameter by name.
fn uuid_param(params: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    params.get(key).and_then(|s| Uuid::parse_str(s).ok())
}

/// Confirm the environment exists in the caller's workspace (RLS-scoped).
async fn ensure_env(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    environment_id: Uuid,
) -> ApiResult<()> {
    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM environments WHERE id = $1")
        .bind(environment_id)
        .fetch_optional(&mut **tx)
        .await?;
    exists
        .map(|_| ())
        .ok_or_else(|| ApiError::EnvNotFound(environment_id.to_string()))
}

/// `GET .../environments/{environment_id}/secrets` — list secret metadata.
pub async fn list_secrets(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<Json<Vec<SecretMeta>>> {
    let env_id = uuid_param(&params, "environment_id")
        .ok_or_else(|| ApiError::EnvNotFound("invalid".into()))?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    ensure_env(&mut tx, env_id).await?;
    let rows = sqlx::query(
        "SELECT ref_id, key_name, created_by, created_at, updated_at, rotation_due_at \
         FROM secrets WHERE environment_id = $1 ORDER BY key_name",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.rollback().await;

    Ok(Json(rows.iter().map(meta_from_row).collect()))
}

/// `POST .../environments/{environment_id}/secrets` — upload a new secret.
pub async fn upload_secret(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
    Json(req): Json<UploadSecretRequest>,
) -> ApiResult<(StatusCode, Json<SecretMeta>)> {
    if !ctx.role.can_write_secrets() {
        return Err(ApiError::Forbidden("your role cannot write secrets".into()));
    }
    let env_id = uuid_param(&params, "environment_id")
        .ok_or_else(|| ApiError::EnvNotFound("invalid".into()))?;
    let ref_id = RefId::parse(&req.ref_id)
        .ok_or_else(|| ApiError::Validation(format!("invalid ref_id: {}", req.ref_id)))?;
    let key_name = KeyName::parse(&req.key_name)
        .map_err(|_| ApiError::Validation(format!("invalid key_name: {}", req.key_name)))?;
    let blob = decode_blob(&req.encrypted_blob)?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    ensure_env(&mut tx, env_id).await?;
    let row = sqlx::query(
        "INSERT INTO secrets \
         (workspace_id, environment_id, ref_id, key_name, encrypted_blob, created_by, rotation_due_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING ref_id, key_name, created_by, created_at, updated_at, rotation_due_at",
    )
    .bind(ctx.workspace_id)
    .bind(env_id)
    .bind(ref_id.as_str())
    .bind(key_name.as_str())
    .bind(&blob)
    .bind(ctx.user_id)
    .bind(req.rotation_due_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref d) if d.is_unique_violation() => {
            ApiError::Conflict(format!("secret {} already exists", ref_id.as_str()))
        }
        other => ApiError::Database(other),
    })?;

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "secret.created",
        Some(ref_id.as_str()),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(meta_from_row(&row))))
}

/// `GET .../secrets/{ref_id}` — download the ciphertext for one secret.
pub async fn download_secret(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<Json<SecretBlob>> {
    let env_id = uuid_param(&params, "environment_id")
        .ok_or_else(|| ApiError::EnvNotFound("invalid".into()))?;
    let ref_id = params
        .get("ref_id")
        .cloned()
        .ok_or_else(|| ApiError::SecretNotFound("missing ref_id".into()))?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let row = sqlx::query(
        "SELECT ref_id, key_name, encrypted_blob, created_at, updated_at, rotation_due_at \
         FROM secrets WHERE environment_id = $1 AND ref_id = $2",
    )
    .bind(env_id)
    .bind(&ref_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::SecretNotFound(ref_id.clone()))?;

    let blob: Vec<u8> = row.get("encrypted_blob");
    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "secret.accessed",
        Some(&ref_id),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(Json(SecretBlob {
        ref_id: row.get("ref_id"),
        key_name: row.get("key_name"),
        encrypted_blob: STANDARD.encode(&blob),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        rotation_due_at: row.get("rotation_due_at"),
    }))
}

/// `PUT .../secrets/{ref_id}` — replace the ciphertext of an existing secret.
pub async fn update_secret(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
    Json(req): Json<UpdateSecretRequest>,
) -> ApiResult<Json<SecretMeta>> {
    if !ctx.role.can_write_secrets() {
        return Err(ApiError::Forbidden("your role cannot write secrets".into()));
    }
    let env_id = uuid_param(&params, "environment_id")
        .ok_or_else(|| ApiError::EnvNotFound("invalid".into()))?;
    let ref_id = params
        .get("ref_id")
        .cloned()
        .ok_or_else(|| ApiError::SecretNotFound("missing ref_id".into()))?;
    let blob = decode_blob(&req.encrypted_blob)?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let row = sqlx::query(
        "UPDATE secrets SET encrypted_blob = $1, updated_at = NOW() \
         WHERE environment_id = $2 AND ref_id = $3 \
         RETURNING ref_id, key_name, created_by, created_at, updated_at, rotation_due_at",
    )
    .bind(&blob)
    .bind(env_id)
    .bind(&ref_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::SecretNotFound(ref_id.clone()))?;

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "secret.updated",
        Some(&ref_id),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(Json(meta_from_row(&row)))
}

/// `DELETE .../secrets/{ref_id}` — remove a secret.
pub async fn delete_secret(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
) -> ApiResult<StatusCode> {
    if !ctx.role.can_write_secrets() {
        return Err(ApiError::Forbidden("your role cannot write secrets".into()));
    }
    let env_id = uuid_param(&params, "environment_id")
        .ok_or_else(|| ApiError::EnvNotFound("invalid".into()))?;
    let ref_id = params
        .get("ref_id")
        .cloned()
        .ok_or_else(|| ApiError::SecretNotFound("missing ref_id".into()))?;

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let res = sqlx::query("DELETE FROM secrets WHERE environment_id = $1 AND ref_id = $2")
        .bind(env_id)
        .bind(&ref_id)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::SecretNotFound(ref_id));
    }
    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "secret.deleted",
        Some(&ref_id),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST .../secrets/{ref_id}/rotate` — flag a secret as due for rotation.
pub async fn flag_rotation(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
    Path(params): Path<HashMap<String, String>>,
    body: Option<Json<FlagRotationRequest>>,
) -> ApiResult<Json<SecretMeta>> {
    if !ctx.role.can_write_secrets() {
        return Err(ApiError::Forbidden("your role cannot write secrets".into()));
    }
    let env_id = uuid_param(&params, "environment_id")
        .ok_or_else(|| ApiError::EnvNotFound("invalid".into()))?;
    let ref_id = params
        .get("ref_id")
        .cloned()
        .ok_or_else(|| ApiError::SecretNotFound("missing ref_id".into()))?;
    let due_at = body
        .and_then(|Json(b)| b.rotation_due_at)
        .unwrap_or_else(Utc::now);

    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let row = sqlx::query(
        "UPDATE secrets SET rotation_due_at = $1 \
         WHERE environment_id = $2 AND ref_id = $3 \
         RETURNING ref_id, key_name, created_by, created_at, updated_at, rotation_due_at",
    )
    .bind(due_at)
    .bind(env_id)
    .bind(&ref_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::SecretNotFound(ref_id.clone()))?;

    db::record_audit(
        &mut *tx,
        Some(ctx.workspace_id),
        Some(ctx.user_id),
        "key.rotated",
        Some(&ref_id),
        None,
    )
    .await?;
    tx.commit().await?;

    Ok(Json(meta_from_row(&row)))
}

/// `GET /workspaces/{workspace_id}/rotations` — secrets whose rotation is due.
pub async fn list_rotation_due(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
) -> ApiResult<Json<Vec<SecretMeta>>> {
    let mut tx = state.workspace_tx(ctx.workspace_id, ctx.user_id).await?;
    let rows = sqlx::query(
        "SELECT ref_id, key_name, created_by, created_at, updated_at, rotation_due_at \
         FROM secrets WHERE rotation_due_at IS NOT NULL AND rotation_due_at <= NOW() \
         ORDER BY rotation_due_at",
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.rollback().await;

    Ok(Json(rows.iter().map(meta_from_row).collect()))
}
