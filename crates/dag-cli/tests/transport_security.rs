//! CLI-level guardrails around plaintext node and HTTP replication transports.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn node_info_refuses_remote_plaintext_before_sending_a_token() {
    #[allow(deprecated)]
    let mut command = Command::cargo_bin("dag").unwrap();
    command
        .args([
            "node",
            "info",
            "--remote",
            "grpc://192.0.2.10:7411",
            "--token",
            "must-not-be-logged-0123456789abcdef01",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing plaintext transport"))
        .stderr(predicate::str::contains("must-not-be-logged-0123456789abcdef01").not());
}

#[test]
fn node_server_refuses_remote_plaintext_even_with_a_legacy_token() {
    let directory = tempfile::tempdir().unwrap();
    #[allow(deprecated)]
    let mut command = Command::cargo_bin("dag").unwrap();
    command
        .args([
            "--data-dir",
            directory.path().to_str().unwrap(),
            "node",
            "serve",
            "--listen",
            "0.0.0.0:0",
            "--token",
            "must-not-be-logged-0123456789abcdef01",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing plaintext transport"))
        .stderr(predicate::str::contains("must-not-be-logged-0123456789abcdef01").not());
}

#[test]
fn transport_escape_hatches_and_scoped_auth_file_are_visible_in_help() {
    #[allow(deprecated)]
    let mut serve = Command::cargo_bin("dag").unwrap();
    serve
        .args(["node", "serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--auth-file"))
        .stdout(predicate::str::contains("--allow-insecure-transport"))
        .stdout(predicate::str::contains("--allow-exec-jobs"));

    #[allow(deprecated)]
    let mut sync = Command::cargo_bin("dag").unwrap();
    sync.args(["sync", "push", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--allow-insecure-transport"));

    #[allow(deprecated)]
    let mut info = Command::cargo_bin("dag").unwrap();
    info.args(["node", "info", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("platform native roots"));
}
