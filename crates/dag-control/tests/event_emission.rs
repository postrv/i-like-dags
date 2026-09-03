//! Integration tests for event emission from logs
//!
//! Tests verify that pointer, pin, and job operations emit events through the event bus.

use anyhow::Result;
use dag_control::{Control, EventEnvelope};
use dag_core::ContentStore;
use tempfile::tempdir;

/// Helper to receive an event with timeout, preventing test hangs
fn recv_within(
    rx: &mut tokio::sync::broadcast::Receiver<EventEnvelope>,
    max_ms: u64,
) -> EventEnvelope {
    use std::{thread, time::Duration};
    let start = std::time::Instant::now();
    loop {
        match rx.try_recv() {
            Ok(env) => return env,
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                if start.elapsed().as_millis() as u64 > max_ms {
                    panic!("timeout waiting for event after {}ms", max_ms);
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("unexpected recv error: {e:?}"),
        }
    }
}

#[test]
fn test_pointer_create_emits_event() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Subscribe to events before creating pointer
    let mut rx = control.event_bus.subscribe();

    // Create a chunk and pointer
    let chunk = b"test data";
    let cid = control.store.put_chunk(chunk, None)?;
    control.pointer_log.create("test-ptr", cid.clone())?;

    // Check for emitted event with timeout to prevent hangs
    let envelope = recv_within(&mut rx, 500);
    match envelope.event {
        dag_control::Event::PointerUpdate { id, new, .. } => {
            assert_eq!(id, "test-ptr");
            assert_eq!(new, cid);
        }
        other => panic!("Expected PointerUpdate, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_pointer_update_emits_event() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Create initial pointer
    let chunk1 = b"data 1";
    let cid1 = control.store.put_chunk(chunk1, None)?;
    control.pointer_log.create("test-ptr", cid1)?;

    // Subscribe after creation
    let mut rx = control.event_bus.subscribe();

    // Update pointer
    let chunk2 = b"data 2";
    let cid2 = control.store.put_chunk(chunk2, None)?;
    control.pointer_log.update("test-ptr", cid2.clone())?;

    // Check for update event with timeout to prevent hangs
    let envelope = recv_within(&mut rx, 500);
    match envelope.event {
        dag_control::Event::PointerUpdate { id, new, .. } => {
            assert_eq!(id, "test-ptr");
            assert_eq!(new, cid2);
        }
        other => panic!("Expected PointerUpdate, got {:?}", other),
    }

    Ok(())
}

#[test]
fn test_multiple_subscribers_receive_events() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    // Create two subscribers
    let mut rx1 = control.event_bus.subscribe();
    let mut rx2 = control.event_bus.subscribe();

    assert_eq!(control.event_bus.subscriber_count(), 2);

    // Create pointer
    let chunk = b"test data";
    let cid = control.store.put_chunk(chunk, None)?;
    control.pointer_log.create("test-ptr", cid.clone())?;

    // Both subscribers should receive the event (with timeout)
    let _ = recv_within(&mut rx1, 500);
    let _ = recv_within(&mut rx2, 500);

    Ok(())
}
