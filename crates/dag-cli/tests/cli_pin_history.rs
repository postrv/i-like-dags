//! `--pin-history`: the one-flag flight recorder, end to end through the
//! binary. A superseded version's bytes survive collection for the review
//! window — because of the pin, not by luck.

use assert_cmd::prelude::*;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn dag(data_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("dag").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

fn put(data_dir: &Path, body: &str) -> String {
    let out = dag(data_dir)
        .args(["put", "--data", body])
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn age(data_dir: &Path, cid_hex: &str) {
    // Shard layout: <2 hex>/<62 hex>.
    let path = data_dir
        .join("data")
        .join(&cid_hex[..2])
        .join(&cid_hex[2..]);
    let hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    filetime::set_file_mtime(path, hour_ago).unwrap();
}

#[test]
fn a_pinned_history_version_survives_collection_and_expires_after_the_window() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let v1 = put(data, "deploy config v1");
    let v2 = put(data, "deploy config v2");

    // The deploy hook, two calls exactly as the README promises: update
    // (create) with the flag.
    dag(data)
        .args([
            "pointer",
            "create",
            "--id",
            "configs/prod",
            "--cid",
            &v1,
            "--pin-history",
            "3600",
        ])
        .assert()
        .success();
    dag(data)
        .args([
            "pointer",
            "update",
            "--id",
            "configs/prod",
            "--cid",
            &v2,
            "--pin-history",
            "3600",
        ])
        .assert()
        .success();

    // The recorder pins exist, named by pointer and sequence.
    let pins = dag(data).args(["pin", "list", "--json"]).output().unwrap();
    let listing = String::from_utf8(pins.stdout).unwrap();
    assert!(listing.contains("history/configs/prod/1"), "{listing}");
    assert!(listing.contains("history/configs/prod/2"), "{listing}");

    // Recovery gate, then collect with everything aged and no youth shield:
    // v1 is superseded — without its pin it would be gone.
    age(data, &v1);
    age(data, &v2);
    dag(data).arg("recover").assert().success();
    dag(data)
        .args(["gc", "run", "--min-age-secs", "0"])
        .assert()
        .success();

    for (cid, body) in [(&v1, "deploy config v1"), (&v2, "deploy config v2")] {
        let out = dag(data)
            .args(["get", "--cid", cid, "--raw"])
            .output()
            .unwrap();
        assert!(out.status.success(), "superseded version was collected");
        assert_eq!(String::from_utf8(out.stdout).unwrap(), *body);
    }

    // The refusal that keeps the flag honest: a zero TTL is not a review
    // window, and silently pinning forever would be worse than erroring.
    let out = dag(data)
        .args([
            "pointer",
            "update",
            "--id",
            "configs/prod",
            "--cid",
            &v1,
            "--pin-history",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("positive TTL"), "{stderr}");
}
