//! Thin async HTTP client for the Kosh team-sync server.
//!
//! Every method maps onto one server endpoint. Request/response field names
//! mirror the server's structs verbatim (see `kosh-server/src/api/*`). The
//! server is zero-knowledge: this client uploads only ciphertext (secret blobs,
//! wrapped env keys) and public keys, and decrypts strictly locally.

// Several client methods are wired up across later milestones (sync, team).
// TODO: drop once every method has a caller.
#![allow(dead_code)]

use anyhow::{anyhow, Context as _};
use base64::Engine as _;
use kosh_core::config::Config;
use kosh_core::keychain::Keychain;
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

/// A workspace as returned by the server (extra fields are ignored).
#[derive(Debug, Deserialize)]
pub struct WorkspaceDto {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub role: String,
}

/// An environment as returned by the server.
#[derive(Debug, Deserialize)]
pub struct EnvDto {
    pub id: Uuid,
    pub name: String,
}

/// Secret metadata (no ciphertext).
#[derive(Debug, Deserialize)]
pub struct SecretMetaDto {
    pub ref_id: String,
    pub key_name: String,
}

/// Secret download including the base64 ciphertext.
#[derive(Debug, Deserialize)]
pub struct SecretBlobDto {
    pub ref_id: String,
    pub key_name: String,
    pub encrypted_blob: String,
}

/// A workspace member.
#[derive(Debug, Deserialize)]
pub struct MemberDto {
    pub user_id: Uuid,
    pub role: String,
}

/// A member's wrapped env key (base64 ciphertext).
#[derive(Debug, Deserialize)]
pub struct EnvKeyDto {
    pub member_user_id: Uuid,
    pub encrypted_env_key: String,
}

/// A user's published public key (base64).
#[derive(Debug, Deserialize)]
pub struct PublicKeyDto {
    pub user_id: Uuid,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
}

/// The server's `{ "code", "message" }` error envelope.
#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// HTTP client bound to one server + bearer token.
pub struct ServerClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl ServerClient {
    /// Build a client for an explicit base URL + token (used by `kosh login`).
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    /// Build a client from the persisted config (`server_url`) and the token in
    /// the OS keychain. Errors with a `kosh login` hint when either is missing.
    pub fn from_config(kc: &Keychain) -> anyhow::Result<Self> {
        let cfg = Config::load().ok();
        let base_url = cfg
            .and_then(|c| c.server_url)
            .ok_or_else(|| anyhow!("no Kosh server configured — run `kosh login` first"))?;
        let token = kc
            .get_server_token()
            .map_err(|_| anyhow!("not logged in — run `kosh login` first"))?;
        Ok(Self::new(&base_url, &token))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// The caller's own user id, read from the JWT `sub` claim. The signature is
    /// not verified here — the server is the authority; we only need to know
    /// which member row (`/keys/{me}`) is ours. Errors if the token is malformed.
    pub fn user_id(&self) -> anyhow::Result<Uuid> {
        let payload = self
            .token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow!("malformed token: missing payload segment"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .context("decoding token payload")?;
        #[derive(Deserialize)]
        struct Sub {
            sub: Uuid,
        }
        let claims: Sub = serde_json::from_slice(&bytes).context("parsing token claims")?;
        Ok(claims.sub)
    }

    // ---- auth -------------------------------------------------------------

    /// `POST /auth/refresh` — verify the token and obtain a fresh one.
    pub async fn refresh(&self) -> anyhow::Result<String> {
        let resp = self
            .http
            .post(self.url("/auth/refresh"))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("request to /auth/refresh failed")?;
        let body: TokenResponse = handle(resp).await?;
        Ok(body.token)
    }

    /// `POST /auth/logout` — revoke the current token server-side.
    pub async fn logout(&self) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(self.url("/auth/logout"))
            .bearer_auth(&self.token)
            .send()
            .await
            .context("request to /auth/logout failed")?;
        expect_success(resp).await
    }

    // ---- workspaces / environments ---------------------------------------

    pub async fn list_workspaces(&self) -> anyhow::Result<Vec<WorkspaceDto>> {
        let resp = self
            .http
            .get(self.url("/workspaces"))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle(resp).await
    }

    pub async fn create_workspace(&self, name: &str) -> anyhow::Result<WorkspaceDto> {
        let resp = self
            .http
            .post(self.url("/workspaces"))
            .bearer_auth(&self.token)
            .json(&json!({ "name": name }))
            .send()
            .await?;
        handle(resp).await
    }

    pub async fn list_envs(&self, ws: Uuid) -> anyhow::Result<Vec<EnvDto>> {
        let resp = self
            .http
            .get(self.url(&format!("/workspaces/{ws}/environments")))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle(resp).await
    }

    pub async fn create_env(&self, ws: Uuid, name: &str) -> anyhow::Result<EnvDto> {
        let resp = self
            .http
            .post(self.url(&format!("/workspaces/{ws}/environments")))
            .bearer_auth(&self.token)
            .json(&json!({ "name": name }))
            .send()
            .await?;
        handle(resp).await
    }

    // ---- secrets ----------------------------------------------------------

    pub async fn list_secrets(&self, ws: Uuid, env: Uuid) -> anyhow::Result<Vec<SecretMetaDto>> {
        let resp = self
            .http
            .get(self.url(&format!("/workspaces/{ws}/environments/{env}/secrets")))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle(resp).await
    }

    pub async fn get_secret(
        &self,
        ws: Uuid,
        env: Uuid,
        ref_id: &str,
    ) -> anyhow::Result<SecretBlobDto> {
        let resp = self
            .http
            .get(self.url(&format!(
                "/workspaces/{ws}/environments/{env}/secrets/{ref_id}"
            )))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle(resp).await
    }

    /// `POST` a new secret. Returns `false` if the ref already exists (409).
    pub async fn upload_secret(
        &self,
        ws: Uuid,
        env: Uuid,
        ref_id: &str,
        key_name: &str,
        blob_b64: &str,
    ) -> anyhow::Result<bool> {
        let resp = self
            .http
            .post(self.url(&format!("/workspaces/{ws}/environments/{env}/secrets")))
            .bearer_auth(&self.token)
            .json(&json!({
                "ref_id": ref_id,
                "key_name": key_name,
                "encrypted_blob": blob_b64,
            }))
            .send()
            .await?;
        if resp.status() == StatusCode::CONFLICT {
            return Ok(false);
        }
        expect_success(resp).await.map(|_| true)
    }

    /// `PUT` updates the ciphertext of an existing secret.
    pub async fn update_secret(
        &self,
        ws: Uuid,
        env: Uuid,
        ref_id: &str,
        blob_b64: &str,
    ) -> anyhow::Result<()> {
        let resp = self
            .http
            .put(self.url(&format!(
                "/workspaces/{ws}/environments/{env}/secrets/{ref_id}"
            )))
            .bearer_auth(&self.token)
            .json(&json!({ "encrypted_blob": blob_b64 }))
            .send()
            .await?;
        expect_success(resp).await
    }

    pub async fn delete_secret(&self, ws: Uuid, env: Uuid, ref_id: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .delete(self.url(&format!(
                "/workspaces/{ws}/environments/{env}/secrets/{ref_id}"
            )))
            .bearer_auth(&self.token)
            .send()
            .await?;
        expect_success(resp).await
    }

    // ---- team / keys ------------------------------------------------------

    pub async fn list_members(&self, ws: Uuid) -> anyhow::Result<Vec<MemberDto>> {
        let resp = self
            .http
            .get(self.url(&format!("/workspaces/{ws}/members")))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle(resp).await
    }

    pub async fn invite_member(
        &self,
        ws: Uuid,
        user_id: Uuid,
        role: &str,
    ) -> anyhow::Result<MemberDto> {
        let resp = self
            .http
            .post(self.url(&format!("/workspaces/{ws}/members")))
            .bearer_auth(&self.token)
            .json(&json!({ "user_id": user_id, "role": role }))
            .send()
            .await?;
        handle(resp).await
    }

    /// `GET /users/{id}/public-key` — `None` when the user has not published one.
    pub async fn get_public_key(&self, user_id: Uuid) -> anyhow::Result<Option<PublicKeyDto>> {
        let resp = self
            .http
            .get(self.url(&format!("/users/{user_id}/public-key")))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle_opt(resp).await
    }

    /// `PUT /users/me/public-key` — publish the caller's public key (base64).
    pub async fn put_public_key(&self, public_key_b64: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .put(self.url("/users/me/public-key"))
            .bearer_auth(&self.token)
            .json(&json!({ "public_key": public_key_b64 }))
            .send()
            .await?;
        expect_success(resp).await
    }

    /// `GET …/keys/{member}` — the member's wrapped env key, or `None` (404).
    pub async fn get_env_key(
        &self,
        ws: Uuid,
        env: Uuid,
        member: Uuid,
    ) -> anyhow::Result<Option<EnvKeyDto>> {
        let resp = self
            .http
            .get(self.url(&format!(
                "/workspaces/{ws}/environments/{env}/keys/{member}"
            )))
            .bearer_auth(&self.token)
            .send()
            .await?;
        handle_opt(resp).await
    }

    /// `PUT …/keys/{member}` — upload an env key wrapped to the member (base64).
    pub async fn put_env_key(
        &self,
        ws: Uuid,
        env: Uuid,
        member: Uuid,
        enc_b64: &str,
    ) -> anyhow::Result<()> {
        let resp = self
            .http
            .put(self.url(&format!(
                "/workspaces/{ws}/environments/{env}/keys/{member}"
            )))
            .bearer_auth(&self.token)
            .json(&json!({ "encrypted_env_key": enc_b64 }))
            .send()
            .await?;
        expect_success(resp).await
    }
}

/// Decode a successful JSON response or convert the error envelope.
async fn handle<T: DeserializeOwned>(resp: Response) -> anyhow::Result<T> {
    let status = resp.status();
    if status.is_success() {
        resp.json::<T>().await.context("decoding server response")
    } else {
        Err(error_from(resp, status).await)
    }
}

/// Like [`handle`] but maps 404 to `Ok(None)`.
async fn handle_opt<T: DeserializeOwned>(resp: Response) -> anyhow::Result<Option<T>> {
    let status = resp.status();
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status.is_success() {
        resp.json::<T>()
            .await
            .map(Some)
            .context("decoding server response")
    } else {
        Err(error_from(resp, status).await)
    }
}

/// Assert a no-content (or otherwise success) response.
async fn expect_success(resp: Response) -> anyhow::Result<()> {
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(error_from(resp, status).await)
    }
}

/// Build an `anyhow` error from the server's `{code,message}` envelope.
async fn error_from(resp: Response, status: StatusCode) -> anyhow::Error {
    let body = resp.text().await.unwrap_or_default();
    anyhow!(format_error(status.as_u16(), &body))
}

/// Format a human-readable error from an HTTP status and raw response body,
/// decoding the server's `{code,message}` envelope when present.
fn format_error(status: u16, body: &str) -> String {
    match serde_json::from_str::<ErrorBody>(body) {
        Ok(b) => format!("server error {} [{}]: {}", status, b.code, b.message),
        Err(_) => format!("server error {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::format_error;

    #[test]
    fn formats_error_envelope() {
        let body = r#"{"code":"KE-504","message":"not a member"}"#;
        assert_eq!(
            format_error(403, body),
            "server error 403 [KE-504]: not a member"
        );
    }

    #[test]
    fn falls_back_when_body_is_not_an_envelope() {
        assert_eq!(format_error(500, "boom"), "server error 500");
        assert_eq!(format_error(502, ""), "server error 502");
    }
}
