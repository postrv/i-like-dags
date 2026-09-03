//! Replaying a window of the journal must stop reading at the limit, and must
//! say so when the requested start no longer survives.
//!
//! At HEAD `replay_from` deserialised every row from `since_seq` into a `Vec`
//! and both callers trimmed afterwards, so `since_seq=0&limit=10` on a large
//! journal materialised the whole journal to return ten rows. And after a
//! compaction, a request from seq 0 returned whatever survived with no
//! indication that the prefix was gone.

use std::sync::Arc;

use anyhow::Result;
use dag_control::{Event, EventBus};
use dag_core::Cid;
use tempfile::tempdir;

fn bus(dir: &std::path::Path) -> Result<(Arc<redb::Database>, EventBus)> {
    let db = Arc::new(redb::Database::create(dir.join("control.redb"))?);
    let bus = EventBus::with_journal_retention(1024, db.clone(), None)?;
    Ok((db, bus))
}

fn pointer(i: u64) -> Event {
    Event::PointerUpdate {
        id: format!("ptr-{i}"),
        new: Cid::compute(&i.to_be_bytes()),
        ts: 0,
    }
}

fn pin(i: u64) -> Event {
    Event::PinEvent {
        id: format!("pin-{i}"),
        action: "created".into(),
        ts: 0,
    }
}

fn all(_: &Event) -> bool {
    true
}

#[test]
fn limit_returns_the_newest_matching_events_oldest_first() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..100 {
        bus.emit(pointer(i));
    }

    let window = bus.replay(0, Some(3), &all)?;
    let seqs: Vec<u64> = window.events.iter().map(|e| e.seq).collect();
    assert_eq!(
        seqs,
        vec![97, 98, 99],
        "`--limit 3` on a tail should be the newest three, oldest first"
    );
    assert!(window.truncated.is_none());

    Ok(())
}

#[test]
fn limit_is_counted_after_filtering() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..50 {
        bus.emit(pointer(i));
        bus.emit(pin(i));
    }

    let only_pins = |e: &Event| matches!(e, Event::PinEvent { .. });
    let window = bus.replay(0, Some(4), &only_pins)?;

    assert_eq!(window.events.len(), 4, "limit should count matching events");
    assert!(window
        .events
        .iter()
        .all(|e| matches!(e.event, Event::PinEvent { .. })));

    Ok(())
}

#[test]
fn selective_replay_has_an_explicit_scan_budget() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..20 {
        bus.emit(pointer(i));
    }

    let no_matches = |_event: &Event| false;
    let window = bus.replay_with_scan_limit(0, Some(10), Some(7), &no_matches)?;
    assert!(window.events.is_empty());
    assert_eq!(window.scanned, 7);
    assert!(
        window.scan_truncated,
        "an empty filtered answer must disclose that older rows were not inspected"
    );

    let complete = bus.replay_with_scan_limit(13, Some(10), Some(7), &no_matches)?;
    assert_eq!(complete.scanned, 7);
    assert!(!complete.scan_truncated);

    Ok(())
}

#[test]
fn no_limit_returns_everything_from_since_seq() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..20 {
        bus.emit(pointer(i));
    }

    let window = bus.replay(5, None, &all)?;
    assert_eq!(window.events.len(), 15);
    assert_eq!(window.events[0].seq, 5);

    Ok(())
}

#[test]
fn a_request_older_than_the_journal_is_reported_as_truncated() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..150 {
        bus.emit(pointer(i));
    }
    bus.compact_keep_last(50)?;

    let window = bus.replay(0, None, &all)?;
    let truncated = window
        .truncated
        .expect("asking from seq 0 after a compaction must report the missing prefix");

    assert_eq!(truncated.requested_seq, 0);
    assert_eq!(truncated.earliest_seq, 100);
    assert_eq!(truncated.missing, 100);
    assert_eq!(window.earliest_seq, 100);
    assert_eq!(window.events.len(), 50);

    Ok(())
}

#[test]
fn a_request_the_journal_can_satisfy_is_not_reported_as_truncated() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..150 {
        bus.emit(pointer(i));
    }
    bus.compact_keep_last(50)?;

    assert!(bus.replay(100, None, &all)?.truncated.is_none());
    assert!(bus.replay(125, None, &all)?.truncated.is_none());

    Ok(())
}

/// The limit must bound the *work*, not just the answer.
#[test]
fn limit_bounds_rows_read_not_just_rows_returned() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..800 {
        bus.emit(pointer(i));
    }

    let start = std::time::Instant::now();
    let window = bus.replay(0, Some(10), &all)?;
    let bounded = start.elapsed();

    let start = std::time::Instant::now();
    let everything = bus.replay(0, None, &all)?;
    let unbounded = start.elapsed();

    assert_eq!(window.events.len(), 10);
    assert_eq!(everything.events.len(), 800);

    // Reading 10 rows cannot take a comparable share of reading 800 unless the
    // limit is being applied after the fact. Measured at 49x; asserting 10x
    // leaves room for a loaded machine without letting a regression through.
    assert!(
        bounded * 10 < unbounded,
        "limited replay took {bounded:?} against {unbounded:?} unlimited; \
         the limit is not stopping the read"
    );

    Ok(())
}

/// Dry-run is what an operator uses before a destructive operation, so its
/// count has to be a count. At HEAD it reported the cutoff sequence number.
#[test]
fn compaction_preview_counts_events_not_sequence_numbers() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = bus(temp.path())?;

    for i in 0..200 {
        bus.emit(pointer(i));
    }

    let preview = bus.plan_compaction(50)?;
    assert!(preview.dry_run);
    assert_eq!(preview.events_deleted, 150);
    assert_eq!(preview.events_kept, 50);
    assert_eq!(preview.cutoff_seq, 150);

    let applied = bus.compact_keep_last(50)?;
    assert!(!applied.dry_run);
    assert_eq!(applied.events_deleted, preview.events_deleted);
    assert_eq!(applied.events_kept, preview.events_kept);

    // Second preview: there is nothing left to drop, and it must say so.
    let again = bus.plan_compaction(50)?;
    assert_eq!(
        again.events_deleted, 0,
        "a second dry-run reported {} events to drop when none remain",
        again.events_deleted
    );
    assert_eq!(again.events_kept, 50);

    Ok(())
}
