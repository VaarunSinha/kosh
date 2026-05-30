mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use uuid::Uuid;

/// Create a workspace + environment as `owner`; returns (owner_token, ws_id, env_id).
async fn setup(
    server: &common::TestServer,
    client: &reqwest::Client,
    owner: Uuid,
) -> (String, String, String) {
    let token = server.token(owner);
    let ws: serde_json::Value = client
        .post(format!("{}/workspaces", server.base_url))
        .bearer_auth(&token)
        .json(&json!({ "name": "acme" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ws_id = ws["id"].as_str().unwrap().to_string();
    let env: serde_json::Value = client
        .post(format!(
            "{}/workspaces/{ws_id}/environments",
            server.base_url
        ))
        .bearer_auth(&token)
        .json(&json!({ "name": "dev" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (token, ws_id, env["id"].as_str().unwrap().to_string())
}

/// Owner invites a member, lists members, changes role, and removes them.
#[tokio::test]
async fn member_management_lifecycle() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let owner = Uuid::new_v4();
    let (owner_token, ws_id, _env) = setup(&server, &client, owner).await;
    let members_url = format!("{}/workspaces/{ws_id}/members", server.base_url);

    let member = Uuid::new_v4();
    let resp = client
        .post(&members_url)
        .bearer_auth(&owner_token)
        .json(&json!({ "user_id": member, "role": "developer" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // List now has owner + the new member.
    let list: serde_json::Value = client
        .get(&members_url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);

    // A developer cannot invite others.
    let dev_token = server.token(member);
    let resp = client
        .post(&members_url)
        .bearer_auth(&dev_token)
        .json(&json!({ "user_id": Uuid::new_v4(), "role": "readonly" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Owner promotes the member to admin.
    let resp = client
        .put(format!("{members_url}/{member}"))
        .bearer_auth(&owner_token)
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["role"], "admin");

    // Owner removes the member.
    let resp = client
        .delete(format!("{members_url}/{member}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // The owner cannot be removed.
    let resp = client
        .delete(format!("{members_url}/{owner}"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

/// An env key uploaded for a member round-trips back to that member unchanged.
#[tokio::test]
async fn env_key_exchange_roundtrip() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let owner = Uuid::new_v4();
    let (owner_token, ws_id, env_id) = setup(&server, &client, owner).await;

    // Invite a member to receive the env key.
    let member = Uuid::new_v4();
    client
        .post(format!("{}/workspaces/{ws_id}/members", server.base_url))
        .bearer_auth(&owner_token)
        .json(&json!({ "user_id": member, "role": "developer" }))
        .send()
        .await
        .unwrap();

    let key_url = format!(
        "{}/workspaces/{ws_id}/environments/{env_id}/keys/{member}",
        server.base_url
    );
    let ciphertext: Vec<u8> = vec![10u8, 20, 0, 255, 200, 7];
    let resp = client
        .put(&key_url)
        .bearer_auth(&owner_token)
        .json(&json!({ "encrypted_env_key": STANDARD.encode(&ciphertext) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // The member fetches their own env key.
    let member_token = server.token(member);
    let got: serde_json::Value = client
        .get(&key_url)
        .bearer_auth(&member_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(got["encrypted_env_key"].as_str().unwrap())
            .unwrap(),
        ciphertext
    );

    // A stranger (non-member) cannot read it.
    let stranger = server.token(Uuid::new_v4());
    let resp = client
        .get(&key_url)
        .bearer_auth(&stranger)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

/// A public key can be published and fetched back unchanged.
#[tokio::test]
async fn public_key_publish_and_fetch() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let user = Uuid::new_v4();
    let token = server.token(user);

    let pubkey: Vec<u8> = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    let resp = client
        .put(format!("{}/users/me/public-key", server.base_url))
        .bearer_auth(&token)
        .json(&json!({ "public_key": STANDARD.encode(&pubkey) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Any authenticated user can fetch it (public material).
    let other = server.token(Uuid::new_v4());
    let got: serde_json::Value = client
        .get(format!("{}/users/{user}/public-key", server.base_url))
        .bearer_auth(&other)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(got["public_key"].as_str().unwrap())
            .unwrap(),
        pubkey
    );
}

/// Owners can read the audit log; developers cannot.
#[tokio::test]
async fn audit_log_is_readable_by_owner_only() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let owner = Uuid::new_v4();
    let (owner_token, ws_id, _env) = setup(&server, &client, owner).await;
    let audit_url = format!("{}/workspaces/{ws_id}/audit", server.base_url);

    // Creating the workspace + env already produced audit rows.
    let entries: serde_json::Value = client
        .get(&audit_url)
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = entries.as_array().unwrap();
    assert!(!arr.is_empty(), "expected some audit entries");
    let events: Vec<&str> = arr.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert!(events.contains(&"workspace.created"));
    assert!(events.contains(&"env.created"));

    // A developer member cannot read the audit log.
    let dev = Uuid::new_v4();
    client
        .post(format!("{}/workspaces/{ws_id}/members", server.base_url))
        .bearer_auth(&owner_token)
        .json(&json!({ "user_id": dev, "role": "developer" }))
        .send()
        .await
        .unwrap();
    let resp = client
        .get(&audit_url)
        .bearer_auth(server.token(dev))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

/// The audit log is append-only: the kosh_app role may not UPDATE or DELETE it.
#[tokio::test]
async fn audit_log_is_append_only() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    // Generate at least one audit row.
    let _ = setup(&server, &client, Uuid::new_v4()).await;

    let upd = sqlx::query("UPDATE audit_log SET event = 'tampered'")
        .execute(&server.pool)
        .await;
    assert!(
        upd.is_err(),
        "kosh_app must not be able to UPDATE audit_log"
    );

    let del = sqlx::query("DELETE FROM audit_log")
        .execute(&server.pool)
        .await;
    assert!(
        del.is_err(),
        "kosh_app must not be able to DELETE audit_log"
    );
}
