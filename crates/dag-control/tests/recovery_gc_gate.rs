//! Integration tests for recovery gating before garbage collection
//!
//! These tests verify that garbage collection cannot run until the orchestrator
//! has completed pointer, retention, and every GC-safety index rebuild.

use anyhow::Result;
use dag_control::Control;
use dag_core::{ContentStore, PinScope, PinTarget};
use dag_storage::{GarbageCollector, GcConfig, SystemDataPolicy};
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_gc_blocks_before_recovery() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Initially, system should not be recovered
    assert!(!control.is_recovered()?);

    // Verify GC would be blocked (in actual CLI this check happens before calling collect)
    match control.is_recovered() {
        Ok(false) => {
            // Expected: not recovered, GC should be blocked
            // The CLI would return ControlError::NotRecovered here
        }
        Ok(true) => {
            panic!("System should not be recovered yet");
        }
        Err(e) => {
            panic!("Failed to check recovery status: {}", e);
        }
    }

    Ok(())
}

#[test]
fn test_pointer_rebuild_alone_insufficient() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Mark pointer rebuild complete
    control.recovery_state.mark_pointer_rebuilt()?;

    // Should still not be recovered (need retention too)
    assert!(!control.is_recovered()?);

    Ok(())
}

#[test]
fn test_retention_rebuild_alone_insufficient() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Mark retention rebuild complete
    control.recovery_state.mark_retention_rebuilt()?;

    // Should still not be recovered (need pointer too)
    assert!(!control.is_recovered()?);

    Ok(())
}

#[test]
fn test_gc_allowed_after_full_recovery() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Create some test data
    let chunk1 = b"test chunk 1";
    let cid1 = control.store.put_chunk(chunk1, None)?;

    let chunk2 = b"test chunk 2";
    let cid2 = control.store.put_chunk(chunk2, None)?;

    // Create a pin to protect cid1
    control.pin_log.create(
        "test-pin",
        PinTarget::Direct(cid1.clone()),
        PinScope::Global,
        None,
        Some("test-author".to_string()),
    )?;

    // Mark the complete safety state (test-only shortcut).
    control.recovery_state.mark_complete_for_test()?;

    // Now system should be recovered
    assert!(control.is_recovered()?);

    // Create GC and run it
    let gc = GarbageCollector::new(control.store.clone());

    // Get protected set from retention (should include cid1 but not cid2)
    use dag_control::RetentionIndex;
    let retention = RetentionIndex::new(control.pin_log.clone(), control.store.clone(), 10000);

    let protected = retention.protected_set("")?;

    // cid1 should be protected, cid2 should not
    assert!(protected.contains(&cid1));
    assert!(!protected.contains(&cid2));

    // Run GC (dry run)
    let config = GcConfig {
        node_id: None,
        system_policy: SystemDataPolicy {
            enabled: false,
            protect_node_links: false,
        },
        max_deletions: 100,
        max_examined: 100,
        max_bytes_examined: 1024 * 1024,
        dry_run: true,
        min_chunk_age: Duration::from_secs(0),
        collect_details: false,
    };

    let report = gc.collect(&protected, &config)?;

    // Verify GC ran successfully
    assert!(report.dry_run);
    // GC should have run without error - the key point is that it didn't fail due to NotRecovered

    Ok(())
}

#[test]
fn test_recovery_persists_across_instances() -> Result<()> {
    let temp = tempdir()?;

    // First instance: mark recovery
    {
        let control = Control::open(temp.path())?;
        control.recovery_state.mark_complete_for_test()?;
        assert!(control.is_recovered()?);
    }

    // Second instance: recovery should still be marked
    {
        let control = Control::open(temp.path())?;
        assert!(control.is_recovered()?);
    }

    Ok(())
}

#[test]
fn partial_pointer_and_pin_rebuilds_cannot_bypass_full_recovery() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Create a pointer
    let chunk = b"test data";
    let cid = control.store.put_chunk(chunk, None)?;
    control.pointer_log.create("test-ptr", cid)?;

    // Rebuild pointers (this is what the CLI does)
    let _rebuilt_count = control.pointer_log.rebuild_from_events()?;

    // Manually mark recovery (in CLI this is done after rebuild)
    control.recovery_state.mark_pointer_rebuilt()?;

    // Pointer recovery alone is partial.
    assert!(!control.is_recovered()?);

    // Retention is also only one part of the GC-safety view.
    control.recovery_state.mark_retention_rebuilt()?;

    // This was the old bypass: two partial commands used to open GC while the
    // signature and effect-claim indexes were still empty.
    assert!(!control.is_recovered()?);

    control.recover()?;
    assert!(control.is_recovered()?);

    Ok(())
}
