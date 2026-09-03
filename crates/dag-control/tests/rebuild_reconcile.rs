//! Seam 1: a *partially* lost control database.
//!
//! The store-scan fallback that recovers a wholly-lost `control.redb`
//! (`rebuild_from_store.rs`) fires only when the ordinary table rebuild
//! recovers *zero*. The case it misses: the events table holds some rows but
//! the store holds more — the ordinary artefact of restoring `control.redb`
//! from an old backup over a newer `data/`. The table rebuild then recovers a
//! head that is behind the store and reports success, stranding every later
//! event that is sitting in the content store.
//!
//! These tests build exactly that state — snapshot the database mid-history,
//! advance it, restore the snapshot over the advanced `data/` — and demand the
//! recovery reconcile the two rather than trust the truncated table.

use std::path::Path;

use dag_control::{Control, CONTROL_DB_FILE};
use dag_core::{
    ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, PinScope, PinState, PinTarget,
};
use tempfile::TempDir;

fn job_spec(id: &str, code_ref: &str) -> JobSpec {
    JobSpec {
        job_id: JobId::from(id),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["out".into()],
        code_ref: code_ref.into(),
        policy: JobPolicy::default(),
        config: None,
    }
}

fn db(dir: &Path) -> std::path::PathBuf {
    dir.join(CONTROL_DB_FILE)
}

fn snapshot(dir: &Path) -> std::path::PathBuf {
    let to = dir.join("control.redb.snapshot");
    std::fs::copy(db(dir), &to).unwrap();
    to
}

fn restore(dir: &Path, snap: &Path) {
    std::fs::copy(snap, db(dir)).unwrap();
}

/// A pointer's head must come back at the sequence the *store* proves, not the
/// stale sequence the restored-from-backup table remembers.
#[test]
fn a_truncated_pointer_table_is_reconciled_against_the_store() {
    let temp = TempDir::new().unwrap();

    {
        let control = Control::open(temp.path()).unwrap();
        let v1 = control.store.put_chunk(b"one", None).unwrap();
        let v2 = control.store.put_chunk(b"two", None).unwrap();
        control.pointer_log.create("model", v1).unwrap();
        control.pointer_log.update("model", v2).unwrap();
    }

    // Snapshot the database while the pointer is at seq 2.
    let snap = snapshot(temp.path());

    // Advance to seq 3: data/ gains the seq-3 event, the live database learns
    // of it.
    let v3 = {
        let control = Control::open(temp.path()).unwrap();
        let v3 = control.store.put_chunk(b"three", None).unwrap();
        control.pointer_log.update("model", v3.clone()).unwrap();
        v3
    };

    // Restore the seq-2 snapshot over the seq-3 data directory. The table now
    // knows seq 1..2; data/ holds seq 1..3.
    restore(temp.path(), &snap);

    let control = Control::open(temp.path()).unwrap();

    // The reconcile heals the head to seq 3 and says the store held an event
    // the table lacked.
    let report = control.rebuild_pointers_reconciled().unwrap();
    assert_eq!(report.from_table, 1, "{report:?}");
    assert!(
        report.store.events_added >= 1,
        "the seq-3 event in the store was never adopted: {report:?}"
    );

    assert_eq!(
        control.pointer_log.get_head("model").unwrap().seq,
        3,
        "recovery stopped at the truncated table instead of reconciling with the store"
    );
    assert_eq!(control.pointer_log.resolve("model").unwrap(), v3);
    let history = control.pointer_log.history("model", 1..4).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[2].new, v3);
}

/// A truncated pin table must likewise pick up the deactivation event the
/// store proves happened — a pin restored from an old backup would otherwise
/// come back *active* and re-protect content the operator had released.
#[test]
fn a_truncated_pin_table_is_reconciled_against_the_store() {
    let temp = TempDir::new().unwrap();

    {
        let control = Control::open(temp.path()).unwrap();
        let target = control.store.put_chunk(b"content", None).unwrap();
        control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
    }

    // Snapshot while the pin is active at seq 1.
    let snap = snapshot(temp.path());

    // Deactivate: seq 2 lands in data/ and the live database.
    {
        let control = Control::open(temp.path()).unwrap();
        control.pin_log.deactivate("keep", None).unwrap();
    }

    // Restore the seq-1 snapshot over the seq-2 data directory.
    restore(temp.path(), &snap);

    let control = Control::open(temp.path()).unwrap();
    let report = control.rebuild_pins_reconciled().unwrap();
    assert!(
        report.store.events_added >= 1,
        "the seq-2 deactivation in the store was never adopted: {report:?}"
    );

    let head = control.pin_log.head("keep").unwrap();
    assert_eq!(
        head.event.seq, 2,
        "the pin came back at the truncated seq 1"
    );
    assert!(
        matches!(head.event.state, PinState::Deactivated),
        "a pin restored from an old backup re-protected released content"
    );
}

/// A truncated job table must pick up the job the store proves.
#[test]
fn a_truncated_job_table_is_reconciled_against_the_store() {
    let temp = TempDir::new().unwrap();

    {
        let control = Control::open(temp.path()).unwrap();
        control.create_job(job_spec("digest", "hash")).unwrap();
    }

    // Snapshot with the job present exactly once.
    let snap = snapshot(temp.path());

    // A second job lands in data/ and the live database.
    {
        let control = Control::open(temp.path()).unwrap();
        control.create_job(job_spec("join", "concat")).unwrap();
    }

    restore(temp.path(), &snap);

    let control = Control::open(temp.path()).unwrap();
    let report = control.rebuild_jobs_reconciled().unwrap();
    assert!(
        report.store.events_added >= 1,
        "the second job's event in the store was never adopted: {report:?}"
    );

    let mut jobs: Vec<String> = control
        .job_log
        .list_jobs()
        .unwrap()
        .into_iter()
        .map(|j| j.spec.job_id.to_string())
        .collect();
    jobs.sort();
    assert_eq!(
        jobs,
        vec!["digest", "join"],
        "the job the store proved was never recovered"
    );
}

/// The store scan must never *lower* a head. If the head is ahead of what the
/// store can re-prove — a suffix of event bytes is missing — the head stays
/// put rather than regressing to the shorter chain the store happens to hold.
/// A shorter, agreeing chain is less evidence, not divergence.
#[test]
fn a_store_scan_never_regresses_a_head_it_cannot_reprove() {
    let temp = TempDir::new().unwrap();

    let (v3, seq3_cid) = {
        let control = Control::open(temp.path()).unwrap();
        let v1 = control.store.put_chunk(b"one", None).unwrap();
        let v2 = control.store.put_chunk(b"two", None).unwrap();
        let v3 = control.store.put_chunk(b"three", None).unwrap();
        control.pointer_log.create("model", v1).unwrap();
        control.pointer_log.update("model", v2).unwrap();
        control.pointer_log.update("model", v3.clone()).unwrap();
        let seq3_cid = control
            .pointer_log
            .event_cids()
            .unwrap()
            .into_iter()
            .find(|(id, seq, _)| id == "model" && *seq == 3)
            .unwrap()
            .2;
        (v3, seq3_cid)
    };

    // Lose the seq-3 *event* bytes but leave the table (heads + event mappings)
    // intact, so the head is at seq 3 while the store can only prove seq 1..2.
    {
        use dag_storage::GcCapableStore;
        let control = Control::open(temp.path()).unwrap();
        control.store.delete_chunk(&seq3_cid).unwrap();
    }

    let control = Control::open(temp.path()).unwrap();
    // The explicit store-scan path (`pointer rebuild --from-store`). It must
    // not drag the head back to seq 2.
    let report = control.rebuild_pointers_from_store().unwrap();

    assert_eq!(
        control.pointer_log.get_head("model").unwrap().seq,
        3,
        "the store scan regressed a good head to the shorter store chain: {report:?}"
    );
    assert_eq!(control.pointer_log.resolve("model").unwrap(), v3);
}

/// Divergence — the table and the store disagree about what sits at a given
/// (id, seq) — must be refused loudly and never silently picked. The table's
/// history is kept and the store chain is reported as skipped.
#[test]
fn reconcile_refuses_divergence_and_keeps_the_table_history() {
    let source = TempDir::new().unwrap();
    let dest = TempDir::new().unwrap();

    // Two "shared" pointers with different seq-1 CIDs. Move the source's event
    // bytes into the destination's store (unfiled), then reconcile there.
    let control_src = Control::open(source.path()).unwrap();
    let control_dest = Control::open(dest.path()).unwrap();

    let a = control_src.store.put_chunk(b"source value", None).unwrap();
    control_src.pointer_log.create("shared", a).unwrap();

    let b = control_dest.store.put_chunk(b"dest value", None).unwrap();
    control_dest
        .pointer_log
        .create("shared", b.clone())
        .unwrap();

    for (_, _, cid) in control_src.pointer_log.event_cids().unwrap() {
        let bytes = control_src.store.get_chunk(&cid).unwrap();
        control_dest.store.put_chunk(&bytes, None).unwrap();
    }

    let report = control_dest.rebuild_pointers_reconciled().unwrap();
    assert!(
        report.store.skipped.iter().any(|s| s.contains("shared")),
        "divergence was not reported: {report:?}"
    );
    // The destination kept its own history, silently picking neither side.
    assert_eq!(control_dest.pointer_log.resolve("shared").unwrap(), b);
}
