//! End-to-end job tests driving the same code path the CLI and HTTP API use.
//!
//! These go through `dag_jobs::execute_once` against a real `Control` rather
//! than hand-assembling a runner, a scheduler and mock traits — the earlier
//! version of this file mocked out `PinCreator`, which is precisely why a bug
//! that made every pinning job single-use went unnoticed.

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::Scheduler;
use dag_core::{
    CachePolicy, ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, RunStatus,
    TriggerPolicy,
};

fn hash_job(policy: JobPolicy) -> JobSpec {
    JobSpec {
        job_id: JobId::from("hash-pointer-job"),
        placement: Some("test-node".into()),
        inputs: JobInput::new().with_pointer("data-ptr"),
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["hash".into()],
        code_ref: "hash".into(),
        policy,
        config: None,
    }
}

#[tokio::test]
async fn deterministic_job_reruns_and_reproduces_its_output() -> Result<()> {
    let tc = TestControl::new()?;
    let control = &tc.control;

    let initial = control.store.put_chunk(b"initial data", None)?;
    control.pointer_log.create("data-ptr", initial)?;

    let spec = hash_job(JobPolicy {
        cache_outputs: CachePolicy::Pin { ttl: Some(3600) },
        trigger: TriggerPolicy::OnPointerUpdate,
    });
    let job_id = spec.job_id.clone();
    control.create_job(spec)?;
    control.subscribe_pointer("data-ptr", job_id.clone())?;

    let updated = control.store.put_chunk(b"updated data", None)?;
    control.pointer_log.update("data-ptr", updated.clone())?;

    let first = dag_jobs::execute_once(control, &job_id).await?;
    assert_eq!(first.outputs.len(), 1);
    assert_eq!(first.outputs[0].0, "hash");

    // The run's manifest must record the pointer head it actually read.
    let runs = control.job_log.get_job_runs(&job_id, None)?;
    assert_eq!(runs.len(), 1);
    assert!(matches!(runs[0].status, RunStatus::Succeeded));
    assert_eq!(runs[0].manifest.pointer_heads.len(), 1);
    assert_eq!(runs[0].manifest.pointer_heads[0].head_cid, updated);

    // The policy pinned the output against the *real* pin log.
    let expected_pin =
        dag_jobs::runner::output_pin_id(job_id.as_ref(), "hash", &first.outputs[0].1);
    assert!(
        control.pin_log.head(&expected_pin).is_ok(),
        "job output should be pinned by policy"
    );

    // Regression: a second run used to collide on a fixed pin ID and fail.
    let second = dag_jobs::execute_once(control, &job_id).await?;
    assert_eq!(
        second.outputs[0].1, first.outputs[0].1,
        "deterministic job must reproduce its output (J1)"
    );
    assert_eq!(control.job_log.get_job_runs(&job_id, None)?.len(), 2);

    Ok(())
}

#[tokio::test]
async fn side_effecting_job_reuses_its_first_run_artifact() -> Result<()> {
    let tc = TestControl::new()?;
    let control = &tc.control;

    let spec = JobSpec {
        job_id: JobId::from("fetch-job"),
        placement: Some("test-node".into()),
        inputs: JobInput::new(),
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["artifact".into()],
        code_ref: "fake_fetch".into(),
        policy: JobPolicy::default(),
        config: None,
    };
    let job_id = spec.job_id.clone();
    control.create_job(spec)?;

    let first = dag_jobs::execute_once(control, &job_id).await?;
    assert_eq!(first.outputs[0].0, "artifact");
    let artifact = control.store.get_chunk(&first.outputs[0].1)?;
    // The default runner's `fake_fetch` is a test double, and its output says
    // so in its own bytes — nothing here reached the network.
    assert_eq!(artifact, dag_jobs::SIMULATED_FETCH_PAYLOAD);

    // Identical inputs, so the effect cache must serve the first-run CID
    // rather than re-performing the effect (J2).
    let second = dag_jobs::execute_once(control, &job_id).await?;
    assert_eq!(second.outputs[0].1, first.outputs[0].1);

    let runs = control.job_log.get_job_runs(&job_id, None)?;
    assert_eq!(runs.len(), 2);
    assert!(runs
        .iter()
        .all(|r| matches!(r.status, RunStatus::Succeeded)));

    Ok(())
}

#[tokio::test]
async fn pointer_update_triggers_subscribed_jobs() -> Result<()> {
    let tc = TestControl::new()?;
    let control = &tc.control;

    let initial = control.store.put_chunk(b"v1", None)?;
    control.pointer_log.create("data-ptr", initial)?;

    let spec = hash_job(JobPolicy {
        cache_outputs: CachePolicy::None,
        trigger: TriggerPolicy::OnPointerUpdate,
    });
    let job_id = spec.job_id.clone();
    control.create_job(spec)?;
    control.subscribe_pointer("data-ptr", job_id.clone())?;

    let scheduler = Scheduler::new(control.job_log.clone(), control.pointer_log.clone());

    let next = control.store.put_chunk(b"v2", None)?;
    control.pointer_log.update("data-ptr", next.clone())?;

    let triggered = scheduler.trigger_jobs_for_pointer("data-ptr")?;
    assert_eq!(triggered.len(), 1, "subscribed job should be enqueued");

    let manifest = scheduler.resolve_inputs(&job_id)?;
    assert_eq!(manifest.pointer_heads[0].head_cid, next);
    assert_eq!(manifest.pointer_heads[0].log_seq, 2);

    Ok(())
}

#[tokio::test]
async fn job_failure_is_recorded_and_returned() -> Result<()> {
    let tc = TestControl::new()?;
    let control = &tc.control;

    let spec = JobSpec {
        job_id: JobId::from("broken-job"),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["out".into()],
        code_ref: "no-such-adapter".into(),
        policy: JobPolicy::default(),
        config: None,
    };
    let job_id = spec.job_id.clone();
    control.create_job(spec)?;

    let result = dag_jobs::execute_once(control, &job_id).await;
    assert!(result.is_err(), "unknown adapter should fail the run");

    let runs = control.job_log.get_job_runs(&job_id, None)?;
    assert_eq!(runs.len(), 1);
    assert!(
        matches!(runs[0].status, RunStatus::Failed { .. }),
        "failure must be recorded, not silently dropped: {:?}",
        runs[0].status
    );

    Ok(())
}

/// Every shipped example must parse into a `JobSpec` and name an adapter this
/// binary registers. The specs are the first thing a new user runs, so a
/// rename or a dropped adapter has to fail here rather than in their terminal.
#[test]
fn the_shipped_example_specs_parse_and_name_real_adapters() -> Result<()> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let known: Vec<&str> = dag_jobs::builtin_adapters()
        .iter()
        .map(|a| a.name)
        .collect();

    let mut seen = 0;
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let spec: JobSpec = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        assert!(
            known.contains(&spec.code_ref.as_str()),
            "{}: code_ref {:?} is not a built-in adapter",
            path.display(),
            spec.code_ref
        );
        seen += 1;
    }
    assert!(seen >= 4, "expected the example specs to still be there");

    Ok(())
}

/// The simulated adapter's example must not read as a working URL fetcher —
/// the previous one was named "fetch-homepage" and handed back `fake data`.
#[test]
fn the_simulated_fetch_example_says_it_is_simulated() -> Result<()> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/job.simulated-fetch.json");
    let raw = std::fs::read_to_string(&path)?;
    let spec: JobSpec = serde_json::from_str(&raw)?;

    assert_eq!(spec.code_ref, "fake_fetch");
    assert!(
        spec.job_id.to_string().contains("simulated"),
        "the job id is what shows up in `dag job list`: {}",
        spec.job_id
    );
    assert!(
        raw.contains("NOT A REAL FETCH"),
        "the spec file itself must warn; JSON has no comments"
    );

    Ok(())
}
