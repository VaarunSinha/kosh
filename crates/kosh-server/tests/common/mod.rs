//! Shared integration-test harness: spins up a real Postgres in Docker
//! (testcontainers), runs migrations as admin, and serves the app on an
//! ephemeral port. Requires Docker to be running.

#![allow(dead_code)]

use kosh_server::api::auth::{mint_token, ACCESS_TTL_SECONDS};
use kosh_server::{app, db, AppState};
use sqlx::PgPool;
use std::sync::Arc;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{runners::AsyncRunner, ContainerAsync};
use uuid::Uuid;

/// Fixed signing secret used by the test harness.
pub const TEST_JWT_SECRET: &str = "test-secret-do-not-use-in-prod";

/// A running test server backed by a fresh, migrated Postgres container.
pub struct TestServer {
    /// Base URL of the spawned HTTP server, e.g. `http://127.0.0.1:54321`.
    pub base_url: String,
    /// Pool connected as the non-superuser `kosh_app` role (RLS enforced).
    pub pool: PgPool,
    /// Pool connected as the admin/superuser role (RLS bypassed; for setup).
    pub admin_pool: PgPool,
    /// Signing secret the server validates tokens against.
    pub jwt_secret: String,
    // Held to keep the container alive for the lifetime of the test.
    _container: ContainerAsync<Postgres>,
}

impl TestServer {
    /// Mint a valid access token for `user` using the harness secret.
    pub fn token(&self, user: Uuid) -> String {
        mint_token(user, &self.jwt_secret, ACCESS_TTL_SECONDS).expect("mint token")
    }

    /// Mint a token for `user` with a custom TTL (e.g. negative => expired).
    pub fn token_with_ttl(&self, user: Uuid, ttl_seconds: i64) -> String {
        mint_token(user, &self.jwt_secret, ttl_seconds).expect("mint token")
    }
}

/// Boot a Postgres container, migrate it, connect both pools, and spawn the app.
pub async fn spawn() -> TestServer {
    let container = Postgres::default()
        .start()
        .await
        .expect("failed to start postgres container (is Docker running?)");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();

    let admin_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    db::run_migrations(&admin_url)
        .await
        .expect("migrations failed");

    let app_url = format!("postgres://kosh_app:kosh_app@{host}:{port}/postgres");
    let pool = db::connect(&app_url, 5)
        .await
        .expect("kosh_app connect failed");
    let admin_pool = db::connect(&admin_url, 2)
        .await
        .expect("admin connect failed");

    let state = AppState {
        pool: pool.clone(),
        jwt_secret: Arc::from(TEST_JWT_SECRET),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app(state)).await.unwrap();
    });

    TestServer {
        base_url,
        pool,
        admin_pool,
        jwt_secret: TEST_JWT_SECRET.to_string(),
        _container: container,
    }
}
