mod common;

use serde_json::json;
use uuid::Uuid;

/// Create a workspace via the API and return its JSON body.
async fn create_workspace(
    server: &common::TestServer,
    client: &reqwest::Client,
    token: &str,
    name: &str,
) -> serde_json::Value {
    let resp = client
        .post(format!("{}/workspaces", server.base_url))
        .bearer_auth(token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create workspace should return 201");
    resp.json().await.unwrap()
}

/// Creating a workspace makes the caller its owner and it shows in their list.
#[tokio::test]
async fn create_and_list_workspace() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let user = Uuid::new_v4();
    let token = server.token(user);

    let ws = create_workspace(&server, &client, &token, "acme").await;
    assert_eq!(ws["name"], "acme");
    assert_eq!(ws["role"], "owner");
    assert_eq!(ws["owner_id"], user.to_string());

    let resp = client
        .get(format!("{}/workspaces", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["name"], "acme");
}

/// A member can GET a workspace; a non-member is forbidden (KE-504).
#[tokio::test]
async fn nonmember_cannot_access_workspace() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let owner = Uuid::new_v4();
    let owner_token = server.token(owner);
    let ws = create_workspace(&server, &client, &owner_token, "acme").await;
    let ws_id = ws["id"].as_str().unwrap();

    // Owner can read it.
    let resp = client
        .get(format!("{}/workspaces/{ws_id}", server.base_url))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A different (non-member) user cannot.
    let stranger_token = server.token(Uuid::new_v4());
    let resp = client
        .get(format!("{}/workspaces/{ws_id}", server.base_url))
        .bearer_auth(&stranger_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-504");
}

/// Duplicate workspace name for the same owner is a 409 Conflict.
#[tokio::test]
async fn duplicate_workspace_is_conflict() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let token = server.token(Uuid::new_v4());

    create_workspace(&server, &client, &token, "acme").await;
    let resp = client
        .post(format!("{}/workspaces", server.base_url))
        .bearer_auth(&token)
        .json(&json!({ "name": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-505");
}

/// Environments can be created, listed, and deleted; bad names are rejected.
#[tokio::test]
async fn environment_lifecycle() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let token = server.token(Uuid::new_v4());
    let ws = create_workspace(&server, &client, &token, "acme").await;
    let ws_id = ws["id"].as_str().unwrap();
    let envs_url = format!("{}/workspaces/{ws_id}/environments", server.base_url);

    // Invalid env name => 422.
    let resp = client
        .post(&envs_url)
        .bearer_auth(&token)
        .json(&json!({ "name": "Production" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);

    // Valid env => 201.
    let resp = client
        .post(&envs_url)
        .bearer_auth(&token)
        .json(&json!({ "name": "dev" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let env: serde_json::Value = resp.json().await.unwrap();
    let env_id = env["id"].as_str().unwrap();
    assert_eq!(env["name"], "dev");

    // List shows it.
    let resp = client
        .get(&envs_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Delete it.
    let resp = client
        .delete(format!("{envs_url}/{env_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// A developer (non-admin) cannot manage environments; only the owner can
/// delete the workspace.
#[tokio::test]
async fn role_gates_are_enforced() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let owner = Uuid::new_v4();
    let owner_token = server.token(owner);
    let ws = create_workspace(&server, &client, &owner_token, "acme").await;
    let ws_id = ws["id"].as_str().unwrap();
    let ws_uuid = Uuid::parse_str(ws_id).unwrap();

    // Add a developer member directly (team endpoints come later).
    let dev = Uuid::new_v4();
    sqlx::query("INSERT INTO members (workspace_id, user_id, role) VALUES ($1, $2, 'developer')")
        .bind(ws_uuid)
        .bind(dev)
        .execute(&server.admin_pool)
        .await
        .unwrap();
    let dev_token = server.token(dev);

    // Developer cannot create an environment.
    let resp = client
        .post(format!(
            "{}/workspaces/{ws_id}/environments",
            server.base_url
        ))
        .bearer_auth(&dev_token)
        .json(&json!({ "name": "dev" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Developer cannot delete the workspace.
    let resp = client
        .delete(format!("{}/workspaces/{ws_id}", server.base_url))
        .bearer_auth(&dev_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Owner can delete it.
    let resp = client
        .delete(format!("{}/workspaces/{ws_id}", server.base_url))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}
