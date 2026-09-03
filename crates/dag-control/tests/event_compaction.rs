//! Integration tests for event journal compaction
//!
//! This module tests that the EventBus compaction feature correctly:
//! - Deletes old events while keeping the most recent N
//! - Updates earliest_seq to reflect the cutoff
//! - Produces valid JSON output for the compaction report
//! - Handles edge cases like leading trim vs gap detection

use anyhow::Result;
use dag_control::{CompactionReport, Event, EventBus};
use dag_core::Cid;
use tempfile::tempdir;

#[test]
fn test_event_compaction_deletes_old() -> Result<()> {
    let temp = tempdir()?;
    let db = std::sync::Arc::new(redb::Database::create(temp.path().join("events.redb"))?);
    let bus = EventBus::with_journal(100, db)?;

    // Emit 200 events
    for i in 0..200 {
        bus.emit(Event::PointerUpdate {
            id: format!("ptr-{}", i),
            new: Cid::compute(&[i as u8]),
            ts: chrono::Utc::now().timestamp(),
        });
    }

    // Flush to ensure all events are persisted

    // Verify we have 200 events
    let all_events = bus.replay_from(0)?;
    assert_eq!(
        all_events.len(),
        200,
        "Should have 200 events before compaction"
    );

    // Compact to keep only last 50
    let report = bus.compact_keep_last(50)?;

    // Verify report shows 150 deleted, 50 kept
    assert_eq!(report.events_deleted, 150, "Should delete 150 old events");
    assert_eq!(report.events_kept, 50, "Should keep 50 recent events");
    assert_eq!(report.cutoff_seq, 150, "Cutoff should be at seq 150");
    assert_eq!(report.current_seq, 200, "Current seq should still be 200");

    // Replay from 0 should now return only 50 events
    let remaining = bus.replay_from(0)?;
    assert_eq!(
        remaining.len(),
        50,
        "Should have 50 events after compaction"
    );

    // First event should have seq == cutoff (150)
    assert_eq!(
        remaining[0].seq, 150,
        "First remaining event should be at cutoff seq"
    );

    // Last event should be seq 199
    assert_eq!(remaining[49].seq, 199, "Last event should be seq 199");

    Ok(())
}

#[test]
fn test_earliest_seq_updates_after_compaction() -> Result<()> {
    let temp = tempdir()?;
    let db = std::sync::Arc::new(redb::Database::create(temp.path().join("events.redb"))?);
    let bus = EventBus::with_journal(100, db)?;

    // Initially earliest_seq should be 0
    assert_eq!(bus.earliest_seq(), 0, "Initial earliest_seq should be 0");

    // Emit 100 events
    for i in 0..100 {
        bus.emit(Event::PinEvent {
            id: format!("pin-{}", i),
            action: "created".to_string(),
            ts: chrono::Utc::now().timestamp(),
        });
    }

    // Compact to keep last 30
    let report = bus.compact_keep_last(30)?;
    assert_eq!(report.cutoff_seq, 70, "Cutoff should be 70");

    // earliest_seq should now be 70
    assert_eq!(
        bus.earliest_seq(),
        70,
        "earliest_seq should update to cutoff"
    );

    // Compact again to keep last 10
    let report2 = bus.compact_keep_last(10)?;
    assert_eq!(report2.cutoff_seq, 90, "Second cutoff should be 90");

    // earliest_seq should now be 90
    assert_eq!(
        bus.earliest_seq(),
        90,
        "earliest_seq should update to new cutoff"
    );

    Ok(())
}

#[test]
fn test_tail_no_gap_warning_on_leading_trim() -> Result<()> {
    let temp = tempdir()?;
    let db = std::sync::Arc::new(redb::Database::create(temp.path().join("events.redb"))?);
    let bus = EventBus::with_journal(100, db)?;

    // Emit 50 events
    for i in 0..50 {
        bus.emit(Event::JobRun {
            job: format!("job-{}", i),
            run: format!("run-{}", i),
            status: dag_core::RunStatus::Pending,
            ts: chrono::Utc::now().timestamp(),
        });
    }

    // Compact to keep last 20
    bus.compact_keep_last(20)?;

    // Replay from 0 should return events starting at seq 30 (cutoff)
    let events = bus.replay_from(0)?;
    assert_eq!(events.len(), 20, "Should have 20 events");
    assert_eq!(events[0].seq, 30, "First event should be at seq 30");

    // This is NOT a gap - it's a policy-driven leading trim
    // The key point is: earliest_seq tells us where the journal starts
    // Replay from 0 should succeed and return events from earliest_seq onward

    // Verify we can replay from earliest_seq explicitly
    let events_from_earliest = bus.replay_from(bus.earliest_seq())?;
    assert_eq!(
        events_from_earliest.len(),
        20,
        "Replay from earliest_seq should work"
    );
    assert_eq!(
        events_from_earliest[0].seq, 30,
        "Should start at earliest_seq"
    );

    // Verify replaying from within the compacted range returns empty
    let events_from_deleted = bus.replay_from(10)?;
    assert_eq!(
        events_from_deleted.len(),
        20,
        "Replay from deleted range should return events from earliest_seq onward"
    );

    Ok(())
}

#[test]
fn test_compact_json_schema() -> Result<()> {
    let temp = tempdir()?;
    let db = std::sync::Arc::new(redb::Database::create(temp.path().join("events.redb"))?);
    let bus = EventBus::with_journal(100, db)?;

    // Emit 100 events
    for i in 0..100 {
        bus.emit(Event::StorageHealth {
            check: format!("integrity-{}", i),
            ok: true,
            ts: chrono::Utc::now().timestamp(),
        });
    }

    // Compact and get report
    let report = bus.compact_keep_last(25)?;

    // Verify report fields
    assert_eq!(report.events_deleted, 75);
    assert_eq!(report.cutoff_seq, 75);
    assert_eq!(report.current_seq, 100);
    assert_eq!(report.events_kept, 25);

    // Serialize to JSON and verify structure
    let json = serde_json::to_value(&report)?;

    assert!(
        json.get("events_deleted").is_some(),
        "JSON should have events_deleted"
    );
    assert!(
        json.get("cutoff_seq").is_some(),
        "JSON should have cutoff_seq"
    );
    assert!(
        json.get("current_seq").is_some(),
        "JSON should have current_seq"
    );
    assert!(
        json.get("events_kept").is_some(),
        "JSON should have events_kept"
    );

    // Verify values in JSON
    assert_eq!(json["events_deleted"].as_u64().unwrap(), 75);
    assert_eq!(json["cutoff_seq"].as_u64().unwrap(), 75);
    assert_eq!(json["current_seq"].as_u64().unwrap(), 100);
    assert_eq!(json["events_kept"].as_u64().unwrap(), 25);

    // Verify it round-trips
    let json_str = serde_json::to_string(&report)?;
    let parsed: CompactionReport = serde_json::from_str(&json_str)?;
    assert_eq!(parsed.events_deleted, 75);
    assert_eq!(parsed.cutoff_seq, 75);

    Ok(())
}
