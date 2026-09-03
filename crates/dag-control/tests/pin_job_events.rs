//! Integration tests for pin and job event emission
//!
//! This module tests that PinLog and JobLog correctly emit events to the event bus.

use anyhow::Result;
use dag_control::{Control, Event, EventEnvelope};
use dag_core::{
    ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, PinScope, PinTarget, RunStatus,
};
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
fn test_pin_create_and_deactivate_emit() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let mut rx = control.event_bus.subscribe();

    // Create test data
    let chunk = b"test chunk data";
    let cid = control.store.put_chunk(chunk, None)?;

    // Create pin
    control.pin_log.create(
        "test-pin",
        PinTarget::Direct(cid.clone()),
        PinScope::Global,
        None,
        Some("test-author".to_string()),
    )?;

    // Check created event with timeout to prevent hangs
    let envelope = recv_within(&mut rx, 500);
    match envelope.event {
        Event::PinEvent { id, action, .. } => {
            assert_eq!(id, "test-pin");
            assert_eq!(action, "created");
        }
        other => panic!("Expected PinEvent created, got {:?}", other),
    }

    // Deactivate pin
    control
        .pin_log
        .deactivate("test-pin", Some("test-author".to_string()))?;

    // Check deactivated event with timeout to prevent hangs
    let envelope = recv_within(&mut rx, 500);
    match envelope.event {
        Event::PinEvent { id, action, .. } => {
            assert_eq!(id, "test-pin");
            assert_eq!(action, "deactivated");
        }
        other => panic!("Expected PinEvent deactivated, got {:?}", other),
    }

    Ok(())
}

#[test]
fn job_trigger_emits_a_pending_event() -> Result<()> {
    // Previously ignored as a "test infrastructure issue". The cause was
    // hand-building a JobLog on a bare EventBus instead of letting
    // Control::open wire the bus to its journal, so emitted events had nowhere
    // to go.
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let mut rx = control.event_bus.subscribe();

    let cid = control.store.put_chunk(b"input data", None)?;
    let job_id = control.create_job(hash_job("test-job", cid))?;
    control.trigger_job(job_id)?;

    let envelope = recv_within(&mut rx, 1000);
    match envelope.event {
        Event::JobRun { job, status, .. } => {
            assert_eq!(job, "test-job");
            assert!(matches!(status, RunStatus::Pending));
        }
        other => panic!("expected JobRun Pending, got {:?}", other),
    }
    Ok(())
}

#[test]
fn job_run_lifecycle_emits_each_transition() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let mut rx = control.event_bus.subscribe();

    let cid = control.store.put_chunk(b"input data", None)?;
    let job_id = control.create_job(hash_job("lifecycle-job", cid))?;

    let run_id = control.job_log.trigger_job(&job_id, "test")?;
    expect_status(&mut rx, "lifecycle-job", RunStatus::Pending);
    let claim = control
        .job_log
        .claim_pending_run(&job_id, &run_id, "worker-1", 60)?;
    let prepared = control.job_log.claimed_run(&claim)?;

    control
        .job_log
        .record_claimed_run_started(&claim, &prepared.manifest)?;
    expect_status(&mut rx, "lifecycle-job", RunStatus::Running);

    let output = control.store.put_chunk(b"result data", None)?;
    control.job_log.record_claimed_run_completed(
        &claim,
        vec![("result".to_string(), output)],
        RunStatus::Succeeded,
        None,
    )?;
    expect_status(&mut rx, "lifecycle-job", RunStatus::Succeeded);

    Ok(())
}

/// A minimal deterministic job over one static input.
fn hash_job(id: &str, input: dag_core::Cid) -> JobSpec {
    JobSpec {
        job_id: JobId::from(id.to_string()),
        placement: Some("node1".to_string()),
        inputs: JobInput::new().with_static(input),
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["result".to_string()],
        code_ref: "hash".to_string(),
        policy: JobPolicy::default(),
        config: None,
    }
}

/// Await the next JobRun event and assert its job and status.
fn expect_status(
    rx: &mut tokio::sync::broadcast::Receiver<EventEnvelope>,
    expected_job: &str,
    expected: RunStatus,
) {
    let envelope = recv_within(rx, 1000);
    match envelope.event {
        Event::JobRun { job, status, .. } => {
            assert_eq!(job, expected_job);
            assert_eq!(
                std::mem::discriminant(&status),
                std::mem::discriminant(&expected),
                "expected {:?}, got {:?}",
                expected,
                status
            );
        }
        other => panic!("expected JobRun, got {:?}", other),
    }
}
