//! Backup safety properties that depend on top-level CLI routing.

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn backup_create_does_not_initialize_a_missing_source_directory() {
    let root = tempdir().unwrap();
    let missing = root.path().join("typo-live");
    let snapshot = root.path().join("snapshot");

    let output = Command::cargo_bin("dag")
        .unwrap()
        .arg("--data-dir")
        .arg(&missing)
        .args(["backup", "create", "--out"])
        .arg(&snapshot)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("resolving data directory"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!missing.exists(), "a source typo must not be initialized");
    assert!(
        !snapshot.exists(),
        "a source typo must not publish a backup"
    );
}
