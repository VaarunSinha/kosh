//! Live-server harness for the CLI integration tests: boots a real Postgres in
//! Docker (testcontainers), runs migrations, spawns the real `kosh-server` app
//! on an ephemeral port, and drives the real `kosh` binary against it. Requires
//! Docker to be running.

#![allow(dead_code)]

use assert_cmd::Command;
use kosh_server::api::auth::{mint_token, ACCESS_TTL_SECONDS};
use kosh_server::{app, db, AppState};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{runners::AsyncRunner, ContainerAsync};
use uuid::Uuid;

const TEST_JWT_SECRET: &str = "test-secret-do-not-use-in-prod";

/// A running test server backed by a fresh, migrated Postgres container.
pub struct TestServer {
    pub base_url: String,
    jwt_secret: String,
    _container: ContainerAsync<Postgres>,
}

impl TestServer {
    /// Mint a valid access token for `user`.
    pub fn token(&self, user: Uuid) -> String {
        mint_token(user, &self.jwt_secret, ACCESS_TTL_SECONDS).expect("mint token")
    }
}

/// Boot Postgres, migrate, connect the `kosh_app` (RLS) pool, and spawn the app.
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

    let state = AppState {
        pool,
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
        jwt_secret: TEST_JWT_SECRET.to_string(),
        _container: container,
    }
}

/// An isolated local Kosh installation: its own `$KOSH_HOME`, file-backed
/// keychain, and working directory (where `.env` and config live). Models one
/// developer's machine; multiple of these model a team.
pub struct Device {
    pub dir: tempfile::TempDir,
}

impl Device {
    pub fn new() -> Self {
        Self {
            dir: tempfile::TempDir::new().unwrap(),
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    fn kc_path(&self) -> PathBuf {
        self.path().join("kc.json")
    }

    /// A `kosh` command rooted at this device (own home + keychain + cwd).
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("kosh").unwrap();
        cmd.current_dir(self.path())
            .env("KOSH_HOME", self.path())
            .env("KOSH_KEYCHAIN_FILE", self.kc_path());
        cmd
    }

    /// `kosh init` + `kosh login` against the given server/token.
    pub fn init_and_login(&self, base_url: &str, token: &str) {
        self.cmd().arg("init").assert().success();
        self.cmd()
            .args(["login", "--server", base_url, "--token", token])
            .assert()
            .success();
    }

    /// Decrypt the secret referenced by `key_name` in this device's local state,
    /// using whichever key the .env env resolves to, and return the plaintext.
    /// Reads ciphertext + identity straight from the file-backed keychain so the
    /// assertion is independent of the redactor.
    pub fn decrypt_local(&self, workspace: &str, env: &str, key_name: &str) -> String {
        use kosh_core::crypto;
        use kosh_core::env_file::EnvFile;

        let envf = EnvFile::load(&self.path().join(".env")).expect("load .env");
        let ref_id = envf
            .references()
            .get(key_name)
            .cloned()
            .unwrap_or_else(|| panic!("no ref for {key_name} in .env"));

        let map: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(self.kc_path()).unwrap()).unwrap();

        let id_str = map
            .get(&format!("kosh::env/{workspace}/{env}"))
            .unwrap_or_else(|| panic!("no env key stored for {workspace}/{env}"));
        let identity = crypto::identity_from_string(id_str).expect("parse env identity");

        let blob_hex = map
            .get(&format!("kosh::{}", ref_id.hex()))
            .expect("no ciphertext stored for ref");
        let blob = hex::decode(blob_hex).expect("hex decode blob");

        let plain = crypto::decrypt_with_identity(&blob, &identity, ref_id.as_str())
            .expect("decrypt with env identity");
        String::from_utf8(plain.as_bytes().to_vec()).expect("utf8 plaintext")
    }

    /// Erase synced state (env key + secret blobs + `.env`) while keeping the
    /// user key and server token so the device can still authenticate and sync
    /// again. Used by the roundtrip test to simulate a fresh machine that
    /// hasn't pulled from the server yet.
    pub fn wipe_synced_state(&self) {
        let kc_path = self.kc_path();
        if kc_path.exists() {
            let raw = std::fs::read_to_string(&kc_path).unwrap();
            let mut map: std::collections::BTreeMap<String, String> =
                serde_json::from_str(&raw).unwrap_or_default();
            map.retain(|k, _| k == "kosh::user/private_key" || k == "kosh::server/token");
            std::fs::write(&kc_path, serde_json::to_string_pretty(&map).unwrap()).unwrap();
        }
        let dot_env = self.path().join(".env");
        if dot_env.exists() {
            std::fs::remove_file(dot_env).unwrap();
        }
    }
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}
