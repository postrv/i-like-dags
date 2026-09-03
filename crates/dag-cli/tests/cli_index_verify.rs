//! `dag index verify` through the real binary.
//!
//! Two properties an operator depends on and neither of which held:
//!
//! 1. The scan must re-hash the directory it was pointed at. The index records
//!    absolute paths, so a copy verified beside its source used to re-hash the
//!    *source* and report the copy clean, and a restore whose source was gone
//!    used to report a byte-perfect backup as entirely corrupt.
//! 2. The command must fail when the data does. It returned 0 unconditionally,
//!    so a cron job alerting on exit status would never have fired.

use assert_cmd::Command;
use dag_core::Cid;
use dag_storage::ChunkLocation;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn dag(data_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("dag").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

/// Store `body` and return its CID.
fn put(data_dir: &Path, body: &str) -> String {
    let out = dag(data_dir)
        .args(["put", "--json", "--data", body])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The published on-disk layout: `<data_dir>/data/<first two hex>/<rest>`.
fn chunk_path(data_dir: &Path, cid: &str) -> PathBuf {
    let (prefix, rest) = cid.split_at(2);
    data_dir.join("data").join(prefix).join(rest)
}

fn verify(data_dir: &Path) -> std::process::Output {
    dag(data_dir)
        .args(["index", "verify", "--json"])
        .output()
        .unwrap()
}

fn copy_dir_all(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_all(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

#[test]
fn a_clean_store_verifies_and_exits_zero() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    put(&data_dir, "one");
    put(&data_dir, "two");

    let out = verify(&data_dir);
    assert!(
        out.status.success(),
        "a clean store must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["total_chunks"], 2);
    assert_eq!(report["valid_chunks"], 2);
    assert_eq!(report["invalid_chunks"], 0);
    assert_eq!(report["invalid_reports_truncated"], false);
    assert_eq!(report["invalid_report_limit"], 1024);
}

/// The exit code is the whole point of running this from cron.
#[test]
fn corruption_exits_65_and_names_what_rotted() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    let good = put(&data_dir, "intact");
    let bad = put(&data_dir, "about to rot");

    std::fs::write(chunk_path(&data_dir, &bad), b"rot").unwrap();

    let out = verify(&data_dir);
    assert_eq!(
        out.status.code(),
        Some(65),
        "corrupt data must exit 65, like `dag verify`; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The report still goes to stdout — the exit code is a verdict on it, not
    // a replacement for it.
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["invalid_chunks"], 1);
    assert_eq!(report["corrupt_chunks"], 1);
    assert_eq!(report["missing_chunks"], 0);
    let invalid = report["invalid_reports"].as_array().unwrap();
    assert_eq!(invalid.len(), 1);
    assert_eq!(report["invalid_reports_truncated"], false);
    assert_eq!(invalid[0]["cid"], bad);
    assert_ne!(invalid[0]["cid"], good);
}

/// Absent bytes need restoring; rotted bytes need replacing. The report must
/// say which.
#[test]
fn a_missing_chunk_is_distinguished_from_a_corrupt_one() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    let gone = put(&data_dir, "deleted behind the store's back");
    let rotted = put(&data_dir, "overwritten behind the store's back");

    std::fs::remove_file(chunk_path(&data_dir, &gone)).unwrap();
    std::fs::write(chunk_path(&data_dir, &rotted), b"nonsense").unwrap();

    let out = verify(&data_dir);
    assert_eq!(out.status.code(), Some(65));

    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["invalid_chunks"], 2);
    assert_eq!(report["missing_chunks"], 1);
    assert_eq!(report["corrupt_chunks"], 1);
}

#[test]
fn truncated_diagnostics_still_report_the_complete_invalid_count() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    let rows = dag_storage::integrity::MAX_INTEGRITY_REPORTS + 3;

    {
        let control = dag_control::Control::open(&data_dir).unwrap();
        let index = control.store.get_index().expect("test store has an index");
        let entries = (0..rows)
            .map(|number| {
                let cid = Cid::compute(&number.to_be_bytes());
                let location = ChunkLocation {
                    path: format!("/missing/{cid}"),
                    length: 1,
                    sha256_hash: cid.to_hex(),
                };
                (cid, location)
            })
            .collect::<Vec<_>>();
        index.insert_many(&entries).unwrap();
    }

    let json_out = verify(&data_dir);
    assert_eq!(json_out.status.code(), Some(65));
    let report: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(report["invalid_chunks"], rows);
    assert_eq!(report["invalid_reports"].as_array().unwrap().len(), 1_024);
    assert_eq!(report["invalid_reports_truncated"], true);
    assert_eq!(report["invalid_report_limit"], 1_024);
    assert!(String::from_utf8_lossy(&json_out.stderr).contains(&format!("{rows} of {rows}")));

    let text_out = dag(&data_dir).args(["index", "verify"]).output().unwrap();
    assert_eq!(text_out.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&text_out.stdout)
        .contains("per-chunk diagnostics truncated at 1024; aggregate counts are complete"));
}

/// A restore verified next to its source must be checked on its own terms.
#[test]
fn a_copy_is_verified_against_itself_not_its_source() {
    let temp = tempdir().unwrap();
    let original = temp.path().join("original");
    let restored = temp.path().join("restored");

    put(&original, "alpha");
    let victim = put(&original, "beta");
    put(&original, "gamma");

    // Each `dag` invocation exits before the next, so the redb file is closed
    // and safe to copy — exactly what an operator's `cp -R` sees.
    copy_dir_all(&original, &restored);

    // A faithful copy is clean.
    let out = verify(&restored);
    assert!(
        out.status.success(),
        "a byte-perfect restore must verify clean: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["valid_chunks"], 3);

    // Damage the copy only. The original still holds good bytes at the very
    // path the copy's index records, which is what used to mask this.
    std::fs::write(chunk_path(&restored, &victim), b"rot").unwrap();

    let out = verify(&restored);
    assert_eq!(
        out.status.code(),
        Some(65),
        "the copy's own damage must be found"
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["invalid_chunks"], 1);

    // And the source is untouched and still verifies.
    let out = verify(&original);
    assert!(out.status.success(), "the source must be unaffected");
}
