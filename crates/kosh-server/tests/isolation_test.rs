mod common;

use sqlx::Row;
use uuid::Uuid;

/// Seed two workspaces, each with one environment and one secret, using the
/// admin pool (which bypasses RLS). Returns the two workspace ids.
async fn seed_two_workspaces(admin: &sqlx::PgPool) -> (Uuid, Uuid) {
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();

    let mut ids = Vec::new();
    for (name, owner) in [("alpha", user_a), ("beta", user_b)] {
        let ws: Uuid =
            sqlx::query("INSERT INTO workspaces (name, owner_id) VALUES ($1, $2) RETURNING id")
                .bind(name)
                .bind(owner)
                .fetch_one(admin)
                .await
                .unwrap()
                .get("id");

        let env: Uuid = sqlx::query(
            "INSERT INTO environments (workspace_id, name) VALUES ($1, 'dev') RETURNING id",
        )
        .bind(ws)
        .fetch_one(admin)
        .await
        .unwrap()
        .get("id");

        sqlx::query(
            "INSERT INTO secrets \
             (workspace_id, environment_id, ref_id, key_name, encrypted_blob, created_by) \
             VALUES ($1, $2, $3, 'API_KEY', $4, $5)",
        )
        .bind(ws)
        .bind(env)
        .bind(format!("KOSH:{name}"))
        .bind(vec![1u8, 2, 3, 4])
        .bind(owner)
        .execute(admin)
        .await
        .unwrap();

        ids.push(ws);
    }
    (ids[0], ids[1])
}

/// With `app.workspace_id` scoped to workspace A, the kosh_app role sees only
/// A's secret — workspace B's row is invisible. RLS enforced against real PG.
#[tokio::test]
async fn rls_isolates_secrets_across_workspaces() {
    let server = common::spawn().await;
    let (ws_a, ws_b) = seed_two_workspaces(&server.admin_pool).await;

    // Scope to workspace A.
    let mut tx = server.pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.workspace_id', $1, true)")
        .bind(ws_a.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();

    let rows = sqlx::query("SELECT workspace_id FROM secrets")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    assert_eq!(rows.len(), 1, "should see exactly one workspace's secret");
    let seen: Uuid = rows[0].get("workspace_id");
    assert_eq!(seen, ws_a, "must only see workspace A's secret");
    assert_ne!(seen, ws_b, "must NOT see workspace B's secret");
}

/// Without the `app.workspace_id` GUC set, the kosh_app role sees zero rows —
/// the policy fails closed rather than exposing everything.
#[tokio::test]
async fn rls_fails_closed_with_unset_guc() {
    let server = common::spawn().await;
    let (_ws_a, _ws_b) = seed_two_workspaces(&server.admin_pool).await;

    // No set_config: GUC is unset -> NULL -> comparison never true.
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM secrets")
        .fetch_one(&server.pool)
        .await
        .unwrap()
        .get("n");

    assert_eq!(count, 0, "unset workspace GUC must yield zero rows");
}
