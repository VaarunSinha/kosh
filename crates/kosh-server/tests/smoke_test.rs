mod common;

use sqlx::Row;

/// Migrations apply, the kosh_app role can connect, and the schema exists.
#[tokio::test]
async fn migrations_apply_and_schema_exists() {
    let server = common::spawn().await;

    let tables: Vec<String> = sqlx::query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )
    .fetch_all(&server.admin_pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| r.get::<String, _>("tablename"))
    .collect();

    for expected in [
        "audit_log",
        "env_keys",
        "environments",
        "members",
        "revoked_tokens",
        "secrets",
        "user_public_keys",
        "workspaces",
    ] {
        assert!(
            tables.contains(&expected.to_string()),
            "missing table {expected}"
        );
    }
}

/// RLS is enabled on the per-workspace child tables.
#[tokio::test]
async fn rls_enabled_on_child_tables() {
    let server = common::spawn().await;

    let rows = sqlx::query(
        "SELECT relname FROM pg_class \
         WHERE relrowsecurity = true AND relname = ANY($1) ORDER BY relname",
    )
    .bind(vec![
        "environments".to_string(),
        "secrets".to_string(),
        "members".to_string(),
        "env_keys".to_string(),
    ])
    .fetch_all(&server.admin_pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 4, "expected RLS on all 4 child tables");
}

/// The HTTP server is up and /health responds 200.
#[tokio::test]
async fn health_endpoint_returns_ok() {
    let server = common::spawn().await;

    let resp = reqwest::get(format!("{}/health", server.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
