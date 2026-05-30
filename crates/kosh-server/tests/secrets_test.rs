mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use uuid::Uuid;

/// Create a workspace + environment as `user`, returning (token, ws_id, env_id).
async fn setup(
    server: &common::TestServer,
    client: &reqwest::Client,
    user: Uuid,
) -> (String, String, String) {
    let token = server.token(user);
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
    let env_id = env["id"].as_str().unwrap().to_string();

    (token, ws_id, env_id)
}

/// Upload then download a secret and confirm the ciphertext is byte-for-byte
/// identical — the server is a pure ciphertext store.
#[tokio::test]
async fn upload_download_preserves_ciphertext() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let (token, ws_id, env_id) = setup(&server, &client, Uuid::new_v4()).await;
    let secrets_url = format!(
        "{}/workspaces/{ws_id}/environments/{env_id}/secrets",
        server.base_url
    );

    // Arbitrary binary ciphertext (includes a zero byte and high bytes).
    let ciphertext: Vec<u8> = vec![0u8, 1, 2, 250, 251, 255, 42, 7, 0, 99];
    let b64 = STANDARD.encode(&ciphertext);

    let resp = client
        .post(&secrets_url)
        .bearer_auth(&token)
        .json(&json!({
            "ref_id": "KOSH:a3f9c2b1",
            "key_name": "OPENAI_API_KEY",
            "encrypted_blob": b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let dl: serde_json::Value = client
        .get(format!("{secrets_url}/KOSH:a3f9c2b1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let got = STANDARD
        .decode(dl["encrypted_blob"].as_str().unwrap())
        .unwrap();
    assert_eq!(got, ciphertext, "ciphertext must round-trip unchanged");
    assert_eq!(dl["key_name"], "OPENAI_API_KEY");
}

/// An empty blob is rejected with 422.
#[tokio::test]
async fn empty_blob_is_rejected() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let (token, ws_id, env_id) = setup(&server, &client, Uuid::new_v4()).await;

    let resp = client
        .post(format!(
            "{}/workspaces/{ws_id}/environments/{env_id}/secrets",
            server.base_url
        ))
        .bearer_auth(&token)
        .json(&json!({
            "ref_id": "KOSH:deadbeef",
            "key_name": "TOKEN",
            "encrypted_blob": "",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422);
}

/// Upload, update, then delete a secret; the deleted secret 404s.
#[tokio::test]
async fn update_then_delete_secret() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let (token, ws_id, env_id) = setup(&server, &client, Uuid::new_v4()).await;
    let base = format!(
        "{}/workspaces/{ws_id}/environments/{env_id}/secrets",
        server.base_url
    );
    let one = format!("{base}/KOSH:00ff00ff");

    client
        .post(&base)
        .bearer_auth(&token)
        .json(&json!({
            "ref_id": "KOSH:00ff00ff",
            "key_name": "DB_URL",
            "encrypted_blob": STANDARD.encode([1u8, 2, 3]),
        }))
        .send()
        .await
        .unwrap();

    // Update the ciphertext.
    let new_ct = STANDARD.encode([9u8, 8, 7, 6]);
    let resp = client
        .put(&one)
        .bearer_auth(&token)
        .json(&json!({ "encrypted_blob": new_ct }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let dl: serde_json::Value = client
        .get(&one)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        STANDARD
            .decode(dl["encrypted_blob"].as_str().unwrap())
            .unwrap(),
        vec![9u8, 8, 7, 6]
    );

    // Delete it.
    let resp = client
        .delete(&one)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Now gone.
    let resp = client.get(&one).bearer_auth(&token).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

/// Duplicate ref_id in the same environment is a 409 Conflict.
#[tokio::test]
async fn duplicate_secret_is_conflict() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let (token, ws_id, env_id) = setup(&server, &client, Uuid::new_v4()).await;
    let base = format!(
        "{}/workspaces/{ws_id}/environments/{env_id}/secrets",
        server.base_url
    );
    let payload = json!({
        "ref_id": "KOSH:11223344",
        "key_name": "K",
        "encrypted_blob": STANDARD.encode([1u8]),
    });

    let r1 = client
        .post(&base)
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 201);
    let r2 = client
        .post(&base)
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 409);
}

/// Flagging rotation surfaces the secret in the workspace rotation list.
#[tokio::test]
async fn rotation_flagging_and_listing() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let (token, ws_id, env_id) = setup(&server, &client, Uuid::new_v4()).await;
    let base = format!(
        "{}/workspaces/{ws_id}/environments/{env_id}/secrets",
        server.base_url
    );

    client
        .post(&base)
        .bearer_auth(&token)
        .json(&json!({
            "ref_id": "KOSH:abcdef01",
            "key_name": "ROTATE_ME",
            "encrypted_blob": STANDARD.encode([5u8, 5]),
        }))
        .send()
        .await
        .unwrap();

    // Flag rotation as due in the past so it shows immediately.
    let resp = client
        .post(format!("{base}/KOSH:abcdef01/rotate"))
        .bearer_auth(&token)
        .json(&json!({ "rotation_due_at": "2020-01-01T00:00:00Z" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let due: serde_json::Value = client
        .get(format!("{}/workspaces/{ws_id}/rotations", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = due.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ref_id"], "KOSH:abcdef01");
}

/// A readonly member cannot upload secrets (KE-504), but can download them.
#[tokio::test]
async fn readonly_cannot_write_secrets() {
    let server = common::spawn().await;
    let client = reqwest::Client::new();
    let owner = Uuid::new_v4();
    let (owner_token, ws_id, env_id) = setup(&server, &client, owner).await;
    let base = format!(
        "{}/workspaces/{ws_id}/environments/{env_id}/secrets",
        server.base_url
    );

    // Owner seeds a secret.
    client
        .post(&base)
        .bearer_auth(&owner_token)
        .json(&json!({
            "ref_id": "KOSH:cafebabe",
            "key_name": "SHARED",
            "encrypted_blob": STANDARD.encode([7u8, 7, 7]),
        }))
        .send()
        .await
        .unwrap();

    // Add a readonly member.
    let viewer = Uuid::new_v4();
    sqlx::query("INSERT INTO members (workspace_id, user_id, role) VALUES ($1, $2, 'readonly')")
        .bind(Uuid::parse_str(&ws_id).unwrap())
        .bind(viewer)
        .execute(&server.admin_pool)
        .await
        .unwrap();
    let viewer_token = server.token(viewer);

    // Readonly can download.
    let resp = client
        .get(format!("{base}/KOSH:cafebabe"))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Readonly cannot upload.
    let resp = client
        .post(&base)
        .bearer_auth(&viewer_token)
        .json(&json!({
            "ref_id": "KOSH:00000001",
            "key_name": "NOPE",
            "encrypted_blob": STANDARD.encode([1u8]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "KE-504");
}
