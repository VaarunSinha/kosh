mod common;

use uuid::Uuid;

/// A valid Bearer token is accepted and `/auth/refresh` returns a new token.
#[tokio::test]
async fn valid_token_can_refresh() {
    let server = common::spawn().await;
    let user = Uuid::new_v4();
    let token = server.token(user);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/auth/refresh", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let new_token = body["token"].as_str().expect("token in body");
    assert!(!new_token.is_empty());
    assert_ne!(new_token, token, "refresh should mint a fresh token");
}

/// A request with no Authorization header is rejected with 401 / KE-503.
#[tokio::test]
async fn missing_token_is_unauthorized() {
    let server = common::spawn().await;

    let resp = reqwest::Client::new()
        .post(format!("{}/auth/refresh", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-503");
}

/// An expired token is rejected with 401 / KE-502.
#[tokio::test]
async fn expired_token_is_unauthorized() {
    let server = common::spawn().await;
    let user = Uuid::new_v4();
    // TTL in the past => already expired.
    let token = server.token_with_ttl(user, -3600);

    let resp = reqwest::Client::new()
        .post(format!("{}/auth/refresh", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-502");
}

/// A token signed with the wrong secret (tampered) is rejected with KE-503.
#[tokio::test]
async fn tampered_token_is_unauthorized() {
    let server = common::spawn().await;
    let user = Uuid::new_v4();
    // Mint with a different secret than the server validates against.
    let token =
        kosh_server::api::auth::mint_token(user, "a-totally-different-secret", 3600).unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/auth/refresh", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-503");
}

/// After logout, the same token can no longer be used (revoked => KE-503).
#[tokio::test]
async fn logout_revokes_token() {
    let server = common::spawn().await;
    let user = Uuid::new_v4();
    let token = server.token(user);
    let client = reqwest::Client::new();

    // Token works before logout.
    let resp = client
        .post(format!("{}/auth/refresh", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Logout revokes the presented token.
    let resp = client
        .post(format!("{}/auth/logout", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // The revoked token is now rejected.
    let resp = client
        .post(format!("{}/auth/refresh", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-503");
}
