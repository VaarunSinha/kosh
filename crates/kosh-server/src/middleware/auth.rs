//! Bearer-token authentication middleware.
//!
//! Extracts and validates the `Authorization: Bearer <jwt>` header, rejects
//! tokens whose `jti` appears in `revoked_tokens`, and injects the decoded
//! [`Claims`] and [`AuthUser`] into the request extensions for downstream
//! handlers.

use crate::api::auth::{validate_token, AuthUser};
use crate::error::ApiError;
use crate::AppState;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Authenticate the request or short-circuit with an `ApiError` response.
pub async fn require_auth(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match authenticate(&state, &mut req).await {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

async fn authenticate(state: &AppState, req: &mut Request) -> Result<(), ApiError> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::AuthInvalid("missing Authorization header".into()))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::AuthInvalid("expected Bearer token".into()))?
        .trim();

    let claims = validate_token(token, &state.jwt_secret)?;

    // Reject tokens that have been explicitly revoked (logout).
    let revoked: Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT jti FROM revoked_tokens WHERE jti = $1")
            .bind(claims.jti)
            .fetch_optional(&state.pool)
            .await?;
    if revoked.is_some() {
        return Err(ApiError::AuthInvalid("token has been revoked".into()));
    }

    req.extensions_mut().insert(AuthUser(claims.sub));
    req.extensions_mut().insert(claims);
    Ok(())
}
