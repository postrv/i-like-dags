//! Losing `control.redb` and getting the deployment back, through the binary.
//!
//! The measured failure this covers: delete `control.redb`, leave `data/`
//! intact, and the old partial recovery sequence recovered nothing while
//! reporting success — `pointer rebuild` said 0 pointers, `pin rebuild` said 0
//! pins, and `status` said "recovered: yes". The complete offline `recover`
//! command must instead reconcile every safety-relevant table from one bounded
//! store inventory before it can certify the GC gate. Because legacy control
//! records are unsigned ordinary content, a lost database also requires the
//! operator's explicit `--trust-unfiled-control-events` decision.
//!
//! These tests drive the real binary, because the silent zero was a
//! command-line experience: the API was doing exactly what it said.

use std::path::Path;

use assert_cmd::Command;
use dag_control::Control;
use dag_core::{ContentStore, PinScope, PinTarget};
use serde_json::Value;
use tempfile::TempDir;

fn dag(data_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("dag").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

/// Run a command expected to succeed and parse its JSON stdout.
fn json(cmd: &mut Command) -> Value {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// A data directory with one pointer and one pin, then closed.
///
/// Built through `Control` rather than the CLI so this test is about recovery
/// rather than about the flags `put` happens to take today.
fn populated() -> (TempDir, String) {
    let temp = TempDir::new().unwrap();
    let cid = {
        let control = Control::open(temp.path()).unwrap();
        let cid = control.store.put_chunk(b"the artifact", None).unwrap();
        control.pointer_log.create("model", cid.clone()).unwrap();
        control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(cid.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        cid.to_hex()
    };
    (temp, cid)
}

/// Delete the control database. redb locks the file to one handle, so every
/// `Control` must be closed first — which is why `populated` returns nothing
/// but hex.
fn lose_the_database(dir: &Path) {
    std::fs::remove_file(dir.join("control.redb")).unwrap();
    assert!(dir.join("data").exists(), "the chunk store went too");
}

#[test]
fn table_rebuild_does_not_silently_promote_store_records() {
    let (temp, cid) = populated();
    lose_the_database(temp.path());

    let table_only = json(dag(temp.path()).args(["pointer", "rebuild", "--json"]));
    assert_eq!(table_only["source"], "events");
    assert_eq!(table_only["rebuilt_count"], 0);

    let unresolved = dag(temp.path())
        .args(["pointer", "resolve", "--id", "model", "--json"])
        .output()
        .unwrap();
    assert!(
        !unresolved.status.success(),
        "table-only repair silently trusted unsigned store content"
    );

    let trusted = json(dag(temp.path()).args([
        "pointer",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(trusted["source"], "store");
    assert_eq!(trusted["fell_back"], false);
    assert_eq!(trusted["rebuilt_count"], 1);

    // The explicit trust decision genuinely reconstructs the pointer.
    let resolved = dag(temp.path())
        .args(["pointer", "resolve", "--id", "model", "--json"])
        .output()
        .unwrap();
    assert!(resolved.status.success());
    let value: Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(value["cid"].as_str().unwrap(), cid);
}

#[test]
fn a_lost_database_is_recovered_end_to_end() {
    let (temp, cid) = populated();
    lose_the_database(temp.path());

    let refused = dag(temp.path())
        .args([
            "recover",
            "--max-objects",
            "100000",
            "--max-bytes",
            "1073741824",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "lost-database recovery promoted unsigned store records without explicit trust"
    );
    let refusal = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refusal.contains("--trust-unfiled-control-events"),
        "refusal did not explain the required trust decision: {refusal}"
    );

    let recovery = json(dag(temp.path()).args([
        "recover",
        "--max-objects",
        "100000",
        "--max-bytes",
        "1073741824",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(recovery["pointer_events_adopted"], 1);
    assert_eq!(recovery["pin_events_adopted"], 1);
    assert_eq!(recovery["job_events_adopted"], 0);
    assert_eq!(recovery["recovered"], true);

    // Every safety-relevant phase completed against the rebuilt chunk index,
    // so GC is unblocked — which is the whole reason recovery exists.
    let status = json(dag(temp.path()).args(["status", "--json"]));
    assert_eq!(status["recovered"], true);
    assert_eq!(status["pointers"], 1);
    assert_eq!(status["pins"], 1);
    assert_eq!(status["active_pins"], 1);

    // The pin is protecting its target again, not merely listed.
    let gc = json(dag(temp.path()).args(["gc", "status", "--cid", &cid, "--json"]));
    assert_eq!(
        gc["protected"], true,
        "a recovered pin protects nothing: {gc}"
    );
}

/// `--from-store` is the explicit route, for when the table is *not* empty but
/// is suspect. It reports `fell_back: false` — an operator reading the output
/// should be able to tell a chosen scan from an automatic one.
#[test]
fn from_store_is_available_explicitly() {
    let (temp, _cid) = populated();

    let pointers = json(dag(temp.path()).args([
        "pointer",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(pointers["source"], "store");
    assert_eq!(pointers["fell_back"], false);
    assert_eq!(pointers["rebuilt_count"], 1);

    let pins = json(dag(temp.path()).args([
        "pin",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(pins["source"], "store");
    assert_eq!(pins["fell_back"], false);
    assert_eq!(pins["heads_rebuilt"], 1);

    let jobs = json(dag(temp.path()).args([
        "job",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(jobs["source"], "store");
    assert_eq!(jobs["heads_rebuilt"], 0);
}

/// An empty deployment must not be dragged through a store scan, and must not
/// be reported as if one had happened. "Nothing to recover" and "the log that
/// says what to recover is gone" are different answers.
#[test]
fn an_empty_deployment_does_not_pretend_to_have_fallen_back() {
    let temp = TempDir::new().unwrap();
    drop(Control::open(temp.path()).unwrap());

    let pointers = json(dag(temp.path()).args(["pointer", "rebuild", "--json"]));
    assert_eq!(pointers["source"], "events");
    assert_eq!(pointers["rebuilt_count"], 0);

    let pins = json(dag(temp.path()).args(["pin", "rebuild", "--json"]));
    assert_eq!(pins["heads_rebuilt"], 0);
    assert!(pins.get("fell_back").is_none(), "{pins}");
}

/// Seam 1 through the binary: `control.redb` restored from an old backup over a
/// newer `data/`. The table remembers seq 2; `data/` holds the seq-3 event. The
/// plain table rebuild stops at seq 2; the explicit trusted store scan must
/// adopt the stranded event and say it used the store rather than the table.
#[test]
fn a_truncated_table_requires_an_explicit_trusted_store_scan() {
    use dag_core::ContentStore;

    let temp = TempDir::new().unwrap();
    let db = temp.path().join("control.redb");
    let snap = temp.path().join("snap.redb");

    // seq 1, 2 — then snapshot the database mid-history.
    {
        let control = Control::open(temp.path()).unwrap();
        let v1 = control.store.put_chunk(b"v1", None).unwrap();
        let v2 = control.store.put_chunk(b"v2", None).unwrap();
        control.pointer_log.create("model", v1).unwrap();
        control.pointer_log.update("model", v2).unwrap();
    }
    std::fs::copy(&db, &snap).unwrap();

    // Advance to seq 3, then restore the seq-2 snapshot over the seq-3 `data/`.
    let v3 = {
        let control = Control::open(temp.path()).unwrap();
        let v3 = control.store.put_chunk(b"v3", None).unwrap();
        control.pointer_log.update("model", v3.clone()).unwrap();
        v3.to_hex()
    };
    std::fs::copy(&snap, &db).unwrap();

    let table_only = json(dag(temp.path()).args(["pointer", "rebuild", "--json"]));
    assert_eq!(table_only["source"], "events", "{table_only}");
    assert_eq!(table_only["rebuilt_count"], 1, "{table_only}");

    let out = json(dag(temp.path()).args([
        "pointer",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(out["source"], "store", "{out}");
    assert_eq!(out["fell_back"], false, "{out}");
    assert_eq!(out["events_skipped"], 0, "{out}");
    assert_eq!(out["rebuilt_count"], 1, "{out}");

    // The pointer resolves at the seq the store proved, not the truncated seq 2.
    let resolved = json(dag(temp.path()).args(["pointer", "resolve", "--id", "model", "--json"]));
    assert_eq!(resolved["cid"].as_str().unwrap(), v3);
}
