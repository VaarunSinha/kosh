//! HTTP-aware error type for the server.
//!
//! The server has its own error enum (not `kosh_core::KoshError`) because it
//! must map cleanly onto HTTP status codes and a JSON body. Where it makes
//! sense we reuse the shared `KE-*` code namespace from `kosh-core`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Token validated but is past its expiry.
    #[error("[KE-502] AUTH_EXPIRED")]
    AuthExpired,
    /// Missing/malformed/badly-signed/revoked token.
    #[error("[KE-503] AUTH_INVALID: {0}")]
    AuthInvalid(String),
    /// Authenticated, but not allowed to touch this resource.
    #[error("[KE-504] FORBIDDEN: {0}")]
    Forbidden(String),
    #[error("[KE-509] WORKSPACE_NOT_FOUND: {0}")]
    WorkspaceNotFound(String),
    #[error("[KE-510] ENV_NOT_FOUND: {0}")]
    EnvNotFound(String),
    #[error("[KE-102] SECRET_NOT_FOUND: {0}")]
    SecretNotFound(String),
    /// Unique-constraint / duplicate resource.
    #[error("[KE-505] CONFLICT: {0}")]
    Conflict(String),
    /// Request body failed validation (bad env/key name, empty blob, etc.).
    #[error("[KE-604] VALIDATION: {0}")]
    Validation(String),
    /// Unexpected database failure. Inner error is logged, never returned.
    #[error("[KE-508] SERVER_ERROR")]
    Database(#[from] sqlx::Error),
    /// Catch-all internal failure. Inner detail is logged, never returned.
    #[error("[KE-508] SERVER_ERROR")]
    Internal(#[from] anyhow::Error),
}

/// JSON error envelope returned to clients.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    /// HTTP status + stable `KE-*` code for this error.
    pub fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::AuthExpired => (StatusCode::UNAUTHORIZED, "KE-502"),
            ApiError::AuthInvalid(_) => (StatusCode::UNAUTHORIZED, "KE-503"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "KE-504"),
            ApiError::WorkspaceNotFound(_) => (StatusCode::NOT_FOUND, "KE-509"),
            ApiError::EnvNotFound(_) => (StatusCode::NOT_FOUND, "KE-510"),
            ApiError::SecretNotFound(_) => (StatusCode::NOT_FOUND, "KE-102"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "KE-505"),
            ApiError::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "KE-604"),
            ApiError::Database(_) | ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "KE-508")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        // Internal failures must not leak their cause to the client; log it.
        let message = match &self {
            ApiError::Database(e) => {
                tracing::error!(error = %e, "database error");
                "internal server error".to_string()
            }
            ApiError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                "internal server error".to_string()
            }
            other => other.to_string(),
        };
        (status, Json(ErrorBody { code, message })).into_response()
    }
}

/// Convenience alias for handler results.
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_and_code_mapping() {
        assert_eq!(
            ApiError::AuthExpired.parts(),
            (StatusCode::UNAUTHORIZED, "KE-502")
        );
        assert_eq!(
            ApiError::AuthInvalid("bad sig".into()).parts(),
            (StatusCode::UNAUTHORIZED, "KE-503")
        );
        assert_eq!(
            ApiError::Forbidden("not a member".into()).parts(),
            (StatusCode::FORBIDDEN, "KE-504")
        );
        assert_eq!(
            ApiError::WorkspaceNotFound("acme".into()).parts(),
            (StatusCode::NOT_FOUND, "KE-509")
        );
        assert_eq!(
            ApiError::Validation("bad env name".into()).parts(),
            (StatusCode::UNPROCESSABLE_ENTITY, "KE-604")
        );
        assert_eq!(
            ApiError::Internal(anyhow::anyhow!("boom")).parts(),
            (StatusCode::INTERNAL_SERVER_ERROR, "KE-508")
        );
    }

    #[test]
    fn test_internal_error_does_not_leak_cause() {
        // The Display of an internal error must not contain the inner detail.
        let e = ApiError::Internal(anyhow::anyhow!("secret connection string"));
        assert!(!e.to_string().contains("secret connection string"));
        assert_eq!(e.to_string(), "[KE-508] SERVER_ERROR");
    }
}
