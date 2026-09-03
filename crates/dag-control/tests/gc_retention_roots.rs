//! What collection must never take: content a user named, evidence a pin
//! covers, and the control plane's own history.
//!
//! Every test here corresponds to a defect found in the 2026-07 review, and
//! each one failed before the fix. Two of them deliberately reach into
//! dimensions the rest of the suite never touches — wall-clock age and the
//! subtree expansion ceiling — because that is precisely where the defects
//! hid.

use std::time::{Duration, SystemTime};

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::{ControlError, GcRequest};
use dag_core::{Cid, ContentStore, Entry, Link, PinScope, PinTarget};

/// Satisfy the M6 recovery gate so `run_gc` will proceed.
fn recovered(tc: &TestControl) -> Result<()> {
    tc.control.recovery_state.mark_complete_for_test()?;
    Ok(())
}

fn request() -> GcRequest {
    GcRequest {
        node_id: "local".into(),
        dry_run: false,
        max_delete: 0,
        min_age_secs: 0,
        system_protection: true,
    }
}

/// Backdate every chunk file so age-gated protection has expired.
///
/// The review found two defects that only appear once content is older than a
/// threshold, and no test in the suite had ever aged a chunk. This is that
/// missing lever.
fn age_all_chunks(tc: &TestControl, by: Duration) -> Result<()> {
    let when = filetime::FileTime::from_system_time(SystemTime::now() - by);
    for entry in walkdir(&tc.path().join("data"))? {
        filetime::set_file_mtime(&entry, when)?;
    }
    Ok(())
}

fn walkdir(root: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// Build a chain of `len` linked entries and return (root, all cids).
fn linked_chain(tc: &TestControl, len: usize) -> Result<(Cid, Vec<Cid>)> {
    let mut cids = Vec::with_capacity(len);
    let mut prev: Option<Cid> = None;
    for i in 0..len {
        let entry = Entry {
            payload: format!("node {i}").into_bytes(),
            links: prev
                .take()
                .map(|p| vec![Link::new(p, None)])
                .unwrap_or_default(),
            meta: None,
        };
        let cid = tc.control.store.put_entry(&entry)?;
        cids.push(cid.clone());
        prev = Some(cid);
    }
    let root = cids.last().unwrap().clone();
    Ok((root, cids))
}

// ---- A0: a pointer is a retention root ---------------------------------

#[test]
fn a_pointer_head_survives_collection() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let cid = tc
        .control
        .store
        .put_chunk(b"production config v7: db=prod-01", None)?;
    tc.control
        .pointer_log
        .create("deploy/prod/config", cid.clone())?;

    tc.control.run_gc(&request())?;

    assert!(
        tc.control.store.has_chunk(&cid)?,
        "a pointer resolved to this chunk; collection must not leave the name dangling"
    );
    Ok(())
}

#[test]
fn a_pointer_head_protects_what_it_links_to() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let leaf = tc.control.store.put_chunk(b"training data", None)?;
    let card = tc.control.store.put_entry(&Entry {
        payload: b"dataset card".to_vec(),
        links: vec![Link::named(leaf.clone(), "data")],
        meta: None,
    })?;
    tc.control
        .pointer_log
        .create("datasets/current", card.clone())?;

    tc.control.run_gc(&request())?;

    assert!(
        tc.control.store.has_chunk(&card)?,
        "the named entry survives"
    );
    assert!(
        tc.control.store.has_chunk(&leaf)?,
        "protecting only the head would leave the evidence beneath it collectable"
    );
    Ok(())
}

#[test]
fn an_unreferenced_chunk_is_still_collected() -> Result<()> {
    // The companion to the two above: if everything survived, they would pass
    // for the wrong reason.
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let orphan = tc.control.store.put_chunk(b"nobody names this", None)?;
    let report = tc.control.run_gc(&request())?;

    assert!(
        !tc.control.store.has_chunk(&orphan)?,
        "unreferenced content is free"
    );
    assert!(report.chunks_deleted >= 1);
    Ok(())
}

// ---- A2: the control plane's own history is not collectable ------------

#[test]
fn control_plane_history_survives_at_any_age() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let cid = tc.control.store.put_chunk(b"payload", None)?;
    tc.control.pointer_log.create("names/thing", cid.clone())?;
    tc.control.pointer_log.update("names/thing", cid.clone())?;
    tc.control.pin_log.create(
        "hold",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        Some("test".into()),
    )?;

    // Older than any protection window the system has ever had.
    age_all_chunks(&tc, Duration::from_secs(60 * 24 * 60 * 60))?;

    tc.control.run_gc(&request())?;

    // The history must still be readable, and recovery must still be possible.
    assert_eq!(
        tc.control
            .pointer_log
            .history("names/thing", 1..u64::MAX)?
            .len(),
        2,
        "pointer history is append-only, not append-only-for-a-while"
    );
    tc.control
        .pointer_log
        .rebuild_from_events()
        .expect("pointer rebuild must remain possible after collection");
    tc.control
        .pin_log
        .rebuild(false)
        .expect("pin rebuild must remain possible after collection");
    Ok(())
}

// ---- A1: expansion that hits the ceiling must not silently truncate ----

#[test]
fn a_pin_too_large_to_expand_blocks_collection_rather_than_truncating() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let (root, cids) = linked_chain(&tc, 40)?;
    // Publication validates the complete closure under the limit in force at
    // that moment. Publish legitimately, then simulate an operator lowering
    // the runtime GC expansion budget below an already-valid hold.
    tc.control.set_max_subtree_expansion(10_000);

    tc.control.pin_log.create(
        "matter/legal-hold",
        PinTarget::Subtree {
            root: root.clone(),
            max_depth: None,
        },
        PinScope::Global,
        None,
        Some("test".into()),
    )?;
    tc.control.set_max_subtree_expansion(10);

    let err = tc
        .control
        .run_gc(&request())
        .expect_err("collecting against a snapshot we know is partial is how pinned data dies");

    match err {
        ControlError::RetentionIncomplete { ref pin_id, .. } => {
            // Pointer heads, applicable pins, and frozen active-work inputs
            // now share one globally bounded closure walk, so the failure
            // names that authoritative root set rather than guessing which
            // individual root spent the budget.
            assert_eq!(pin_id, "GC pointer/pin/active-work roots (shared closure)")
        }
        other => panic!("expected RetentionIncomplete, got {other:?}"),
    }

    for cid in &cids {
        assert!(
            tc.control.store.has_chunk(cid)?,
            "nothing may be collected while retention is known to be partial"
        );
    }
    Ok(())
}

#[test]
fn a_pin_within_the_ceiling_protects_every_node() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let (root, cids) = linked_chain(&tc, 40)?;
    tc.control.set_max_subtree_expansion(10_000);

    tc.control.pin_log.create(
        "matter/legal-hold",
        PinTarget::Subtree {
            root,
            max_depth: None,
        },
        PinScope::Global,
        None,
        Some("test".into()),
    )?;

    tc.control.run_gc(&request())?;

    for cid in &cids {
        assert!(
            tc.control.store.has_chunk(cid)?,
            "every node under an active subtree pin survives"
        );
    }
    Ok(())
}

// ---- E1: the report has to be a disposition record --------------------

#[test]
fn the_report_names_what_it_collected() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let orphan = tc.control.store.put_chunk(b"collect me", None)?;
    let report = tc.control.run_gc(&request())?;

    let named: Vec<&Cid> = report.collected.iter().map(|c| &c.cid).collect();
    assert!(
        named.contains(&&orphan),
        "a disposition record that does not name what it destroyed is not a record"
    );
    let record = report.collected.iter().find(|c| c.cid == orphan).unwrap();
    assert_eq!(record.bytes, b"collect me".len());
    Ok(())
}

#[test]
fn a_dry_run_names_what_it_would_collect_without_collecting() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let orphan = tc.control.store.put_chunk(b"collect me", None)?;
    let report = tc.control.run_gc(&GcRequest {
        dry_run: true,
        ..request()
    })?;

    assert!(report.collected.iter().any(|c| c.cid == orphan));
    assert!(
        tc.control.store.has_chunk(&orphan)?,
        "a dry run reports and does not delete"
    );
    Ok(())
}
