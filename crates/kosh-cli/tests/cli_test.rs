use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn kosh() -> Command {
    Command::cargo_bin("kosh").unwrap()
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
