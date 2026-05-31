/// Live-server integration tests for `kosh sync` and `kosh team`.
///
/// These tests require Docker. They spin up a real Postgres container, run
/// migrations, start the real `kosh-server` app on an ephemeral port, and
/// drive the real `kosh` binary via `assert_cmd`.
mod common;

use predicates::str::contains;
use uuid::Uuid;

/// A secret pushed by user A survives a full wipe of local state and is
/// recovered byte-for-byte by a subsequent `kosh sync --pull`.
#[tokio::test(flavor = "multi_thread")]
async fn test_sync_roundtrip() {
    let srv = common::spawn().await;
    let uid_a = Uuid::new_v4();
    let token_a = srv.token(uid_a);

    let dev = common::Device::new();
    dev.init_and_login(&srv.base_url, &token_a);

    // Write a plain .env and encrypt it.
    std::fs::write(dev.path().join(".env"), "API_TOKEN=super-secret-value\n").unwrap();
    dev.cmd().args(["add", "--file", ".env"]).assert().success();

    // Sync push: creates workspace + env, generates env key, migrates secret,
    // uploads ciphertext.
    dev.cmd()
        .args(["-w", "acme", "-e", "dev", "sync", "--push"])
        .assert()
        .success();

    // Simulate a fresh machine: keep user key + token, drop everything else.
    dev.wipe_synced_state();

    // Sync pull: re-downloads env key (wrapped to our public key) + ciphertext.
    dev.cmd()
        .args(["-w", "acme", "-e", "dev", "sync", "--pull"])
        .assert()
        .success();

    // Verify the plaintext was recovered correctly.
    let plain = dev.decrypt_local("acme", "dev", "API_TOKEN");
    assert_eq!(plain, "super-secret-value");
}

/// User A creates an env and invites user B. After A runs `kosh team
/// grant-env`, B can pull and decrypt the secret on a separate device.
#[tokio::test(flavor = "multi_thread")]
async fn test_team_sharing() {
    let srv = common::spawn().await;
    let uid_a = Uuid::new_v4();
    let uid_b = Uuid::new_v4();
    let token_a = srv.token(uid_a);
    let token_b = srv.token(uid_b);

    // ── A sets up the workspace, adds a secret, and syncs. ──────────────────
    let dev_a = common::Device::new();
    dev_a.init_and_login(&srv.base_url, &token_a);

    std::fs::write(dev_a.path().join(".env"), "DB_PASS=hunter2\n").unwrap();
    dev_a
        .cmd()
        .args(["add", "--file", ".env"])
        .assert()
        .success();
    dev_a
        .cmd()
        .args(["-w", "acme", "-e", "dev", "sync"])
        .assert()
        .success();

    // ── A invites B as developer. ────────────────────────────────────────────
    dev_a
        .cmd()
        .args([
            "-w",
            "acme",
            "team",
            "invite",
            &uid_b.to_string(),
            "--role",
            "developer",
        ])
        .assert()
        .success();

    // ── B initialises and syncs for the first time. ──────────────────────────
    // This publishes B's public key and pulls the ciphertext (but no env key
    // has been granted yet, so B can't decrypt yet).
    let dev_b = common::Device::new();
    dev_b.init_and_login(&srv.base_url, &token_b);
    dev_b
        .cmd()
        .args(["-w", "acme", "-e", "dev", "sync"])
        .assert()
        .success();

    // ── A grants B access to the env key. ────────────────────────────────────
    dev_a
        .cmd()
        .args([
            "-w",
            "acme",
            "-e",
            "dev",
            "team",
            "grant-env",
            &uid_b.to_string(),
        ])
        .assert()
        .success();

    // ── B syncs again: unwraps the env key, re-pulls ciphertext. ─────────────
    dev_b
        .cmd()
        .args(["-w", "acme", "-e", "dev", "sync"])
        .assert()
        .success();

    // Verify B can decrypt the secret A uploaded.
    let plain = dev_b.decrypt_local("acme", "dev", "DB_PASS");
    assert_eq!(plain, "hunter2");
}

/// A readonly member's attempt to push secrets is rejected by the server with
/// KE-504 (Forbidden).
#[tokio::test(flavor = "multi_thread")]
async fn test_readonly_push_forbidden() {
    let srv = common::spawn().await;
    let uid_a = Uuid::new_v4();
    let uid_c = Uuid::new_v4();
    let token_a = srv.token(uid_a);
    let token_c = srv.token(uid_c);

    // ── A creates the workspace and pushes a secret. ─────────────────────────
    let dev_a = common::Device::new();
    dev_a.init_and_login(&srv.base_url, &token_a);

    std::fs::write(dev_a.path().join(".env"), "CORP_SECRET=xyz\n").unwrap();
    dev_a
        .cmd()
        .args(["add", "--file", ".env"])
        .assert()
        .success();
    dev_a
        .cmd()
        .args(["-w", "corp", "-e", "prod", "sync"])
        .assert()
        .success();

    // ── A invites C as readonly. ─────────────────────────────────────────────
    dev_a
        .cmd()
        .args([
            "-w",
            "corp",
            "team",
            "invite",
            &uid_c.to_string(),
            "--role",
            "readonly",
        ])
        .assert()
        .success();

    // ── C initialises and pulls (readonly pull should succeed). ──────────────
    let dev_c = common::Device::new();
    dev_c.init_and_login(&srv.base_url, &token_c);
    dev_c
        .cmd()
        .args(["-w", "corp", "-e", "prod", "sync", "--pull"])
        .assert()
        .success();

    // ── C adds a local secret (encrypted to their own user key, no env key). ─
    std::fs::write(dev_c.path().join("extra.env"), "HACK=pwned\n").unwrap();
    dev_c
        .cmd()
        .args(["add", "--file", "extra.env"])
        .assert()
        .success();

    // Copy the ref from extra.env into .env so sync picks it up.
    let extra_content = std::fs::read_to_string(dev_c.path().join("extra.env")).unwrap();
    let dot_env = dev_c.path().join(".env");
    let mut current = if dot_env.exists() {
        std::fs::read_to_string(&dot_env).unwrap()
    } else {
        String::new()
    };
    current.push_str(&extra_content);
    std::fs::write(&dot_env, &current).unwrap();

    // ── C tries to push — server must reject with KE-504. ────────────────────
    dev_c
        .cmd()
        .args(["-w", "corp", "-e", "prod", "sync", "--push"])
        .assert()
        .failure()
        .stderr(contains("KE-504"));
}
