//! Pin → retention → collection integration.
//!
//! These exercise the full pipeline against a real `Control`, which is where
//! they belong: they used to live inside the CLI binary's test module, where
//! they hand-assembled a store and a pin log at paths nothing else used.

use std::time::Duration;

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::GcRequest;
use dag_core::{ContentStore, Entry, Link, PinScope, PinTarget};
use dag_storage::{GarbageCollector, GcConfig, SystemDataPolicy};

/// Collect with pins honoured but the system-data policy off, so the test sees
/// pin behaviour rather than blanket protection of the control-plane logs.
fn collect_ignoring_system_data(tc: &TestControl, node_id: &str) -> Result<dag_core::GcReport> {
    // Mirrors `Control::run_gc`: recompute retention before deciding what to
    // delete, rather than trusting the cached snapshot.
    tc.control.retention.refresh_cache()?;
    let protected = tc.control.retention.protected_set(node_id)?;
    let config = GcConfig {
        node_id: Some(node_id.to_string()),
        system_policy: SystemDataPolicy {
            enabled: false,
            protect_node_links: false,
        },
        max_deletions: 0,
        max_examined: 0,
        max_bytes_examined: 0,
        dry_run: false,
        min_chunk_age: Duration::ZERO,
        collect_details: false,
    };
    Ok(GarbageCollector::new(tc.control.store.clone()).collect(&protected, &config)?)
}

#[test]
fn global_pin_protects_its_target() -> Result<()> {
    let tc = TestControl::new()?;
    let cid = tc.control.store.put_chunk(b"protected content", None)?;

    tc.control.pin_log.create(
        "keep",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        Some("test".into()),
    )?;

    let report = collect_ignoring_system_data(&tc, "any-node")?;

    assert!(report.protected_by_pins >= 1);
    assert!(
        tc.control.store.has_chunk(&cid)?,
        "a pinned chunk must survive collection"
    );
    Ok(())
}

#[test]
fn deactivating_a_pin_releases_its_target() -> Result<()> {
    let tc = TestControl::new()?;
    let cid = tc.control.store.put_chunk(b"transient content", None)?;

    tc.control.pin_log.create(
        "keep",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        None,
    )?;
    assert!(tc.control.retention.protected_set("n")?.contains(&cid));

    tc.control.pin_log.deactivate("keep", None)?;

    collect_ignoring_system_data(&tc, "n")?;
    assert!(
        !tc.control.store.has_chunk(&cid)?,
        "a released chunk should be collectable"
    );
    Ok(())
}

#[test]
fn local_pins_apply_only_to_their_node() -> Result<()> {
    let tc = TestControl::new()?;
    let local = tc.control.store.put_chunk(b"node-local content", None)?;
    let global = tc.control.store.put_chunk(b"global content", None)?;

    tc.control.pin_log.create(
        "local-pin",
        PinTarget::Direct(local.clone()),
        PinScope::Local {
            node_id: "node-a".into(),
        },
        None,
        None,
    )?;
    tc.control.pin_log.create(
        "global-pin",
        PinTarget::Direct(global.clone()),
        PinScope::Global,
        None,
        None,
    )?;

    let on_a = tc.control.retention.protected_set("node-a")?;
    assert!(on_a.contains(&local));
    assert!(on_a.contains(&global));

    let on_b = tc.control.retention.protected_set("node-b")?;
    assert!(
        !on_b.contains(&local),
        "a node-local pin must not protect content on another node"
    );
    assert!(on_b.contains(&global));
    Ok(())
}

#[test]
fn expired_pins_stop_protecting() -> Result<()> {
    let tc = TestControl::new()?;
    let cid = tc
        .control
        .store
        .put_chunk(b"content with a deadline", None)?;

    // Absolute expiry in the past (R5): already expired when written.
    tc.control.pin_log.create(
        "expired",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        Some(dag_control::now_unix() - 3600),
        None,
    )?;

    assert!(
        !tc.control.retention.protected_set("n")?.contains(&cid),
        "an expired pin provides no retention"
    );

    collect_ignoring_system_data(&tc, "n")?;
    assert!(!tc.control.store.has_chunk(&cid)?);
    Ok(())
}

#[test]
fn subtree_pins_protect_everything_reachable() -> Result<()> {
    let tc = TestControl::new()?;
    let store = &tc.control.store;

    let child_a = store.put_chunk(b"child a", None)?;
    let child_b = store.put_chunk(b"child b", None)?;
    let parent = store.put_entry(&Entry::new(
        b"parent".to_vec(),
        vec![
            Link::named(child_a.clone(), "a"),
            Link::named(child_b.clone(), "b"),
        ],
        None,
    ))?;

    tc.control.pin_log.create(
        "subtree",
        PinTarget::Subtree {
            root: parent.clone(),
            max_depth: None,
        },
        PinScope::Global,
        None,
        None,
    )?;

    let protected = tc.control.retention.protected_set("n")?;
    for cid in [&parent, &child_a, &child_b] {
        assert!(
            protected.contains(cid),
            "subtree pin must reach {}",
            cid.to_hex()
        );
    }

    collect_ignoring_system_data(&tc, "n")?;
    for cid in [&parent, &child_a, &child_b] {
        assert!(store.has_chunk(cid)?, "{} should survive", cid.to_hex());
    }
    Ok(())
}

#[test]
fn collection_through_control_requires_recovery() -> Result<()> {
    let tc = TestControl::new()?;
    tc.control.store.put_chunk(b"anything", None)?;

    let request = GcRequest {
        dry_run: true,
        min_age_secs: 0,
        ..Default::default()
    };

    let refused = tc.control.run_gc(&request);
    assert!(
        matches!(refused, Err(dag_control::ControlError::NotRecovered)),
        "collection must refuse before recovery completes"
    );

    tc.control.recovery_state.mark_complete_for_test()?;

    let report = tc.control.run_gc(&request)?;
    assert!(report.dry_run);
    Ok(())
}

#[test]
fn system_data_policy_protects_control_logs() -> Result<()> {
    let tc = TestControl::new()?;
    let cid = tc.control.store.put_chunk(b"unreferenced", None)?;

    // Pin events are stored as entries in the same store, so a collection with
    // the policy enabled must not remove the control plane's own history.
    tc.control.pin_log.create(
        "some-pin",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        None,
    )?;
    let pin_event_cid = tc.control.pin_log.head("some-pin")?.event_cid;

    tc.control.recovery_state.mark_complete_for_test()?;

    let report = tc.control.run_gc(&GcRequest {
        min_age_secs: 0,
        ..Default::default()
    })?;

    assert!(
        tc.control.store.has_chunk(&pin_event_cid)?,
        "the pin log's own events must survive collection"
    );
    assert_eq!(report.errors, Vec::<String>::new());
    Ok(())
}

#[test]
fn a_pin_created_after_the_cache_warmed_is_still_honoured() -> Result<()> {
    let tc = TestControl::new()?;
    let cid = tc.control.store.put_chunk(b"pinned moments ago", None)?;

    // Warm the retention cache, as any status query would.
    let _ = tc.control.retention_status(&cid, None)?;

    tc.control.pin_log.create(
        "just-in-time",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        None,
    )?;

    tc.control.recovery_state.mark_complete_for_test()?;

    // The cache TTL is minutes long. Collection must not act on a snapshot
    // taken before this pin existed, or it would delete content pinned
    // seconds ago — exactly what a "Pin, then Collect" sequence in the
    // console would do.
    tc.control.run_gc(&GcRequest {
        min_age_secs: 0,
        system_protection: false,
        ..Default::default()
    })?;

    assert!(
        tc.control.store.has_chunk(&cid)?,
        "a pin created since the last cache refresh must still protect its target"
    );
    Ok(())
}

/// The chunked-file product claim: one subtree pin on a manifest retains
/// every chunk of the file it describes, and releasing the pin releases
/// them all to collection.
#[test]
fn a_subtree_pin_retains_a_whole_chunked_file() -> Result<()> {
    let tc = TestControl::new()?;

    // A ~200 KiB "file" split into many small chunks.
    let mut data = Vec::new();
    let mut state: u64 = 12345;
    while data.len() < 200 * 1024 {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        data.extend_from_slice(&state.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes());
    }
    let config = dag_core::ChunkerConfig {
        min_size: 1024,
        avg_size: 4096,
        max_size: 16384,
        links_per_manifest: 8, // force a parts level, so depth > 1 is covered
    };
    let report = dag_core::file::split(
        tc.control.store.as_ref(),
        std::io::Cursor::new(data.clone()),
        None,
        &config,
    )?;
    assert!(
        report.chunks > 10,
        "want many chunks, got {}",
        report.chunks
    );
    assert!(
        report.depth > 1,
        "want a parts level, got depth {}",
        report.depth
    );

    // Pin the manifest's subtree.
    tc.control.pin_log.create(
        "release/model",
        PinTarget::Subtree {
            root: report.cid.clone(),
            max_depth: None,
        },
        PinScope::Global,
        None,
        None,
    )?;

    // Everything reachable from the manifest — data chunks, parts, the root.
    let mut file_chunks = std::collections::HashSet::new();
    let mut queue = vec![report.cid.clone()];
    while let Some(cid) = queue.pop() {
        if !file_chunks.insert(cid.clone()) {
            continue;
        }
        if let Ok(links) = tc.control.store.get_links(&cid) {
            queue.extend(links.into_iter().map(|l| l.target));
        }
    }

    // Collection may take unrelated content (with system protection off, the
    // pin log's own event entry is fair game) but must not touch the file.
    collect_ignoring_system_data(&tc, "node")?;
    for cid in &file_chunks {
        assert!(
            tc.control.store.has_chunk(cid)?,
            "pinned file chunk {} was collected",
            cid
        );
    }

    // And the file must still reassemble, byte-identical.
    let mut out = Vec::new();
    dag_core::file::join(tc.control.store.as_ref(), &report.cid, &mut out)?;
    assert_eq!(out, data);

    // Release the pin: now the whole tree is collectable.
    tc.control.pin_log.deactivate("release/model", None)?;
    let after = collect_ignoring_system_data(&tc, "node")?;
    assert!(
        after.chunks_deleted as u64 > report.chunks,
        "expected the data chunks and manifest nodes to be collected, got {}",
        after.chunks_deleted
    );
    assert!(!tc.control.store.has_chunk(&report.cid)?);
    Ok(())
}
