//! Audit-log reading. The log is append-only at the database level
//! (`kosh_app` has INSERT but not UPDATE/DELETE); this module only reads it.

use crate::error::{ApiError, ApiResult};
use crate::middleware::{RoleExt, WorkspaceContext};
use crate::AppState;
use axum::extract::State;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: Option<Uuid>,
    pub event: String,
    pub ref_id: Option<String>,
    pub environment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// `GET /workspaces/{workspace_id}/audit` — recent audit events (owner/admin).
///
/// `audit_log` is not under RLS, so the handler restricts to the scoped
/// workspace explicitly and gates on the manage-members capability.
pub async fn list(
    State(state): State<AppState>,
    Extension(ctx): Extension<WorkspaceContext>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    if !ctx.role.can_manage_members() {
        return Err(ApiError::Forbidden(
            "your role cannot read the audit log".into(),
        ));
    }

    let rows = sqlx::query(
        "SELECT id, user_id, event, ref_id, environment, created_at \
         FROM audit_log WHERE workspace_id = $1 \
         ORDER BY id DESC LIMIT 200",
    )
    .bind(ctx.workspace_id)
    .fetch_all(&state.pool)
    .await?;

    let out = rows
        .into_iter()
        .map(|r| AuditEntry {
            id: r.get("id"),
            user_id: r.get("user_id"),
            event: r.get("event"),
            ref_id: r.get("ref_id"),
            environment: r.get("environment"),
            created_at: r.get("created_at"),
        })
        .collect();
    Ok(Json(out))
}
