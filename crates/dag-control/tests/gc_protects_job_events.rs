//! The job log's event entries are control-plane history, and collection must
//! not take them.
//!
//! `JobLog` stores each job event as an ordinary entry in the content store,
//! and `JobLog::rebuild_from_store` recovers job specs from exactly those
//! entries after a lost `control.redb`. If a default `dag gc run` collects
//! them as unpinned chunks, that recovery path is a dead end. This is the same
//! species as the review's A2 defect (append-only history collectable), one
//! log over: pointer and pin events were already protected; job events were
//! not.

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::{Control, GcRequest, CONTROL_DB_FILE};
use dag_core::{ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec};
use tempfile::TempDir;

/// Satisfy the M6 recovery gate so `run_gc` will proceed.
fn mark_recovered(control: &Control) -> Result<()> {
    control.recovery_state.mark_complete_for_test()?;
    Ok(())
}

/// Collect everything unprotected, with system protection on — the default a
/// bare `dag gc run` uses.
fn request() -> GcRequest {
    GcRequest {
        node_id: "local".into(),
        dry_run: false,
        max_delete: 0,
        min_age_secs: 0,
        system_protection: true,
    }
}

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

#[test]
fn job_event_entries_survive_default_collection() -> Result<()> {
    let tc = TestControl::new()?;
    mark_recovered(&tc.control)?;

    tc.control.create_job(job_spec("digest", "hash"))?;
    tc.control.create_job(job_spec("join", "concat"))?;

    let events = tc.control.job_log.event_cids()?;
    assert!(
        !events.is_empty(),
        "sanity: creating jobs must have recorded job events"
    );

    tc.control.run_gc(&request())?;

    for (job_id, seq, cid) in &events {
        assert!(
            tc.control.store.has_chunk(cid)?,
            "job event ({job_id}, seq {seq}) was collected as ordinary content; \
             job recovery has nothing to rebuild from"
        );
    }
    Ok(())
}

#[test]
fn a_job_spec_survives_gc_then_a_database_loss() -> Result<()> {
    // The full recovery story: a job's event entry must still be in the store
    // after collection, so that when the database is lost it can be rebuilt.
    let temp = TempDir::new()?;

    {
        let control = Control::open(temp.path())?;
        mark_recovered(&control)?;
        control.create_job(job_spec("digest", "hash"))?;
        control.run_gc(&request())?;
    } // drop Control, releasing the redb file lock

    // Lose the database, keep the chunk store.
    std::fs::remove_file(temp.path().join(CONTROL_DB_FILE))?;

    let control = Control::open(temp.path())?;
    let report = control.rebuild_jobs_from_store()?;
    assert!(
        report.heads_rebuilt >= 1,
        "the job spec's event entry was collected before the database was lost, \
         so store-scan recovery found nothing: {report:?}"
    );

    let head = control.job_log.get_job(&JobId::from("digest"))?;
    let head = head.expect("the 'digest' job spec did not come back from the store");
    assert_eq!(head.spec.code_ref, "hash");
    Ok(())
}
