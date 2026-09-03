//! Integration tests for event journal replay functionality

use anyhow::Result;
use dag_control::Control;
use dag_core::{ContentStore, PinScope, PinTarget};
use tempfile::tempdir;

#[test]
fn test_replay_from_sequence_number() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Emit 10 events
    for i in 0..10 {
        let chunk = format!("chunk-{}", i);
        let cid = control.store.put_chunk(chunk.as_bytes(), None)?;

        control.pointer_log.create(&format!("ptr-{}", i), cid)?;
    }

    // Flush journal to ensure all events are persisted

    // Verify current seq is 10
    assert_eq!(control.event_bus.current_seq(), 10);

    // Replay all events
    let envelopes = control.event_bus.replay_from(0)?;
    assert_eq!(envelopes.len(), 10);
    assert_eq!(envelopes[0].seq, 0);
    assert_eq!(envelopes[9].seq, 9);

    // Replay from seq 5
    let envelopes = control.event_bus.replay_from(5)?;
    assert_eq!(envelopes.len(), 5);
    assert_eq!(envelopes[0].seq, 5);
    assert_eq!(envelopes[4].seq, 9);

    Ok(())
}

#[test]
fn test_replay_persists_across_restarts() -> Result<()> {
    let temp = tempdir()?;
    let data_path = temp.path().to_path_buf();

    // Session 1: Emit 50 events
    {
        let control = Control::open(&data_path)?;

        for i in 0..50 {
            let chunk = format!("chunk-{}", i);
            let cid = control.store.put_chunk(chunk.as_bytes(), None)?;

            control.pointer_log.create(&format!("ptr-{}", i), cid)?;
        }

        // Flush journal before closing

        assert_eq!(control.event_bus.current_seq(), 50);

        // Explicitly drop control before re-opening
        drop(control);
    }

    // Session 2: Verify replay and add more events
    {
        let control = Control::open(&data_path)?;

        // Verify seq continued from previous session
        assert_eq!(control.event_bus.current_seq(), 50);

        // Replay all events from session 1
        let envelopes = control.event_bus.replay_from(0)?;
        assert_eq!(envelopes.len(), 50);
        assert_eq!(envelopes[0].seq, 0);
        assert_eq!(envelopes[49].seq, 49);

        // Add more events in this session
        for i in 50..60 {
            let chunk = format!("chunk-{}", i);
            let cid = control.store.put_chunk(chunk.as_bytes(), None)?;

            control.pointer_log.create(&format!("ptr-{}", i), cid)?;
        }

        // Flush journal before replay

        assert_eq!(control.event_bus.current_seq(), 60);

        // Replay from start of session 2
        let envelopes = control.event_bus.replay_from(50)?;
        assert_eq!(envelopes.len(), 10);
        assert_eq!(envelopes[0].seq, 50);
        assert_eq!(envelopes[9].seq, 59);

        // Clean drop
        drop(control);
    }

    Ok(())
}

#[test]
fn test_replay_with_multiple_event_types() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Emit different event types
    let chunk = b"test";
    let cid = control.store.put_chunk(chunk, None)?;

    // Pointer events
    control.pointer_log.create("ptr1", cid.clone())?;
    control.pointer_log.update("ptr1", cid.clone())?;

    // Pin events
    control.pin_log.create(
        "pin1",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        Some("author".to_string()),
    )?;
    control
        .pin_log
        .deactivate("pin1", Some("author".to_string()))?;

    // Job events would go here if we had a job created

    // Flush journal before replay

    // Verify all events are in journal
    let envelopes = control.event_bus.replay_from(0)?;
    assert!(envelopes.len() >= 4); // At least pointer create/update + pin create/deactivate

    // Verify sequence continuity
    for i in 1..envelopes.len() {
        assert_eq!(
            envelopes[i].seq,
            envelopes[i - 1].seq + 1,
            "Sequence gap detected at index {}",
            i
        );
    }

    Ok(())
}

#[test]
fn test_gap_detection_helper() {
    use dag_control::{Event, EventEnvelope};

    fn detect_gaps(envelopes: &[EventEnvelope]) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        for window in envelopes.windows(2) {
            let expected_next = window[0].seq + 1;
            if window[1].seq != expected_next {
                gaps.push((window[0].seq, window[1].seq));
            }
        }
        gaps
    }

    // Test with continuous sequence
    let continuous = vec![
        EventEnvelope {
            v: dag_control::events::ENVELOPE_SCHEMA_VERSION,
            seq: 0,
            envelope_ts: 100,
            event: Event::StorageHealth {
                check: "test".to_string(),
                ok: true,
                ts: 100,
            },
        },
        EventEnvelope {
            v: dag_control::events::ENVELOPE_SCHEMA_VERSION,
            seq: 1,
            envelope_ts: 101,
            event: Event::StorageHealth {
                check: "test".to_string(),
                ok: true,
                ts: 101,
            },
        },
    ];
    assert_eq!(detect_gaps(&continuous), vec![]);

    // Test with gap
    let with_gap = vec![
        EventEnvelope {
            v: dag_control::events::ENVELOPE_SCHEMA_VERSION,
            seq: 0,
            envelope_ts: 100,
            event: Event::StorageHealth {
                check: "test".to_string(),
                ok: true,
                ts: 100,
            },
        },
        EventEnvelope {
            v: dag_control::events::ENVELOPE_SCHEMA_VERSION,
            seq: 3, // Gap: missing 1, 2
            envelope_ts: 103,
            event: Event::StorageHealth {
                check: "test".to_string(),
                ok: true,
                ts: 103,
            },
        },
    ];
    assert_eq!(detect_gaps(&with_gap), vec![(0, 3)]);
}
