use assert_cmd::Command;
use kosh_core::crypto;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn kosh() -> Command {
    Command::cargo_bin("kosh").unwrap()
}

/// A `kosh` invocation isolated to `dir`: its own `$KOSH_HOME`, a file-backed
/// keychain at `kc.json`, and `dir` as the working directory (so `.env` and the
/// config live there). This is what lets the real binary be driven across
/// multiple invocations without touching the developer's OS keychain.
fn kosh_in(dir: &Path) -> Command {
    let mut cmd = kosh();
    cmd.current_dir(dir)
        .env("KOSH_HOME", dir)
        .env("KOSH_KEYCHAIN_FILE", dir.join("kc.json"));
    cmd
}

/// Seed the file-backed keychain directly (no env-var mutation in the test
/// process, which would leak into concurrently-running tests). `entries` are
/// `(account, value)` pairs stored under the default `kosh` service.
fn seed_keychain(dir: &Path, entries: &[(&str, &str)]) {
    let map: std::collections::BTreeMap<String, String> = entries
        .iter()
        .map(|(acct, val)| (format!("kosh::{acct}"), val.to_string()))
        .collect();
    fs::write(
        dir.join("kc.json"),
        serde_json::to_string_pretty(&map).unwrap(),
    )
    .unwrap();
}

/// Remove a single account from the file-backed keychain, preserving all other
/// entries (e.g. stored secret ciphertext).
fn remove_keychain_entry(dir: &Path, account: &str) {
    let path = dir.join("kc.json");
    let mut map: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    map.remove(&format!("kosh::{account}"));
    fs::write(&path, serde_json::to_string_pretty(&map).unwrap()).unwrap();
}

#[test]
fn test_kosh_add_file_replaces_plain_secrets() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    fs::write(&env_path, "OPENAI_API_KEY=sk-proj-test123\nNODE_ENV=dev\n").unwrap();

    kosh()
        .arg("add")
        .arg("--file")
        .arg(&env_path)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("KOSH:"));
}

#[test]
fn test_kosh_run_blocks_env_dump() {
    kosh()
        .args(["run", "--", "printenv"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("KE-400"))
        .stderr(predicate::str::contains("BLOCKED_COMMAND"));
}

#[test]
fn test_kosh_run_blocks_bash() {
    kosh()
        .args(["run", "--", "bash"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("KE-400"));
}

/// Solo mode (no per-env key): a secret added with the user key decrypts under
/// the user key when `kosh run` injects it. Behaviour must be unchanged by the
/// introduction of per-env keys.
#[test]
fn test_solo_add_then_run_decrypts() {
    let dir = TempDir::new().unwrap();
    let (user_id, _) = crypto::generate_keypair();
    seed_keychain(
        dir.path(),
        &[("user/private_key", &crypto::identity_to_string(&user_id))],
    );
    fs::write(dir.path().join(".env"), "API_TOKEN=super-secret-value\n").unwrap();

    kosh_in(dir.path())
        .args(["add", "--file", ".env"])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_TOKEN -> KOSH:"));

    // `kosh run` reads every ref in .env, decrypts it, and injects it. Success
    // proves the ciphertext round-tripped under the user key.
    kosh_in(dir.path())
        .args(["run", "--", "true"])
        .assert()
        .success();
}

/// Team mode: when a per-env key exists locally, secrets are encrypted to the
/// ENV key, not the user key. We prove this by removing the user key after the
/// add — decryption on `kosh run` must still succeed using the env key alone.
#[test]
fn test_env_key_used_when_present() {
    let dir = TempDir::new().unwrap();
    let (user_id, _) = crypto::generate_keypair();
    let (env_id, _) = crypto::generate_keypair();
    // Default workspace/env resolve to local/dev → account env/local/dev.
    seed_keychain(
        dir.path(),
        &[
            ("user/private_key", &crypto::identity_to_string(&user_id)),
            ("env/local/dev", &crypto::identity_to_string(&env_id)),
        ],
    );
    fs::write(dir.path().join(".env"), "DB_PASSWORD=hunter2\n").unwrap();

    kosh_in(dir.path())
        .args(["add", "--file", ".env"])
        .assert()
        .success();

    // Drop ONLY the user key, leaving the env key and the stored secret intact.
    // If `add` had (incorrectly) encrypted to the user key, decryption would now
    // be impossible; success below proves the env key was used throughout.
    remove_keychain_entry(dir.path(), "user/private_key");

    kosh_in(dir.path())
        .args(["run", "--", "true"])
        .assert()
        .success();
}
