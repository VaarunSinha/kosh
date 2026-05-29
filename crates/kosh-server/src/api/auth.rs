//! JWT minting/validation and the `/auth/refresh` + `/auth/logout` handlers.
//!
//! Identity is the JWT `sub` claim (a user UUID). There is no password/user
//! table: tokens are minted out-of-band (a test helper mints them here). Logout
//! is implemented by recording the token's `jti` in `revoked_tokens` so the auth
//! middleware can reject it for the remainder of its lifetime.

use crate::error::{ApiError, ApiResult};
use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, TimeZone, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default access-token lifetime (1 hour).
pub const ACCESS_TTL_SECONDS: i64 = 3600;

/// JWT payload. `sub` is the user UUID; `jti` lets us revoke a single token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub jti: Uuid,
    pub iat: i64,
    pub exp: i64,
}

/// The authenticated caller, injected into request extensions by the middleware.
#[derive(Debug, Clone, Copy)]
pub struct AuthUser(pub Uuid);

/// Response body for token-issuing endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
}

/// Mint a signed HS256 token for `user_id`, valid for `ttl_seconds`.
///
/// Each call produces a fresh `jti` so tokens can be revoked individually.
pub fn mint_token(user_id: Uuid, secret: &str, ttl_seconds: i64) -> ApiResult<String> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        jti: Uuid::new_v4(),
        iat: now,
        exp: now + ttl_seconds,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("token encoding failed: {e}")))
}

/// Validate a token's signature and expiry, returning its claims.
///
/// Expired tokens map to [`ApiError::AuthExpired`]; everything else (bad
/// signature, malformed, wrong algorithm) maps to [`ApiError::AuthInvalid`].
pub fn validate_token(token: &str, secret: &str) -> ApiResult<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => ApiError::AuthExpired,
        _ => ApiError::AuthInvalid(e.to_string()),
    })
}

/// `POST /auth/refresh` — issue a fresh token for the already-authenticated user.
pub async fn refresh_token(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> ApiResult<Json<TokenResponse>> {
    let token = mint_token(user.0, &state.jwt_secret, ACCESS_TTL_SECONDS)?;
    Ok(Json(TokenResponse { token }))
}

/// `POST /auth/logout` — revoke the presented token by recording its `jti`.
///
/// The row is retained until the token would have expired anyway; a periodic
/// sweep (out of scope here) can purge `expires_at < now()`.
pub async fn logout(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<StatusCode> {
    let expires_at: DateTime<Utc> = Utc
        .timestamp_opt(claims.exp, 0)
        .single()
        .unwrap_or_else(Utc::now);

    sqlx::query(
        "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) \
         ON CONFLICT (jti) DO NOTHING",
    )
    .bind(claims.jti)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
