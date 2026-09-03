//! Production scheduler semantics: policy-created work is durable, a worker
//! consumes the existing Pending run, and pointer updates enqueue once.

use dag_control::Control;
use dag_core::{
    ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, RunStatus, TriggerPolicy,
};
use dag_jobs::{work_once, Capabilities, WorkerOptions, WorkerRunOutcome};

fn spec(id: &str, inputs: JobInput, trigger: TriggerPolicy) -> JobSpec {
    JobSpec {
        job_id: JobId::from(id),
        placement: None,
        inputs,
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["hash".to_string()],
        code_ref: "hash".to_string(),
        policy: JobPolicy {
            trigger,
            ..JobPolicy::default()
        },
        config: None,
    }
}

#[tokio::test]
async fn on_create_makes_one_pending_run_and_worker_consumes_that_run() {
    let temp = tempfile::tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let input = control.store.put_chunk(b"input", None).unwrap();
    let job = spec(
        "on-create",
        JobInput::new().with_static(input),
        TriggerPolicy::OnCreate,
    );
    control.create_job(job.clone()).unwrap();

    let before = control.runs(job.job_id.clone(), 10).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].run_id.0, 1);
    assert!(matches!(before[0].status, RunStatus::Pending));

    let cycle = work_once(&control, &WorkerOptions::default(), Capabilities::none())
        .await
        .unwrap();
    assert!(matches!(
        cycle.run,
        Some(WorkerRunOutcome::Succeeded { ref run_id, .. }) if run_id == "1"
    ));

    let after = control.runs(job.job_id.clone(), 10).unwrap();
    assert_eq!(after.len(), 1, "worker must not create a second run");
    assert!(matches!(after[0].status, RunStatus::Succeeded));

    let idle = work_once(&control, &WorkerOptions::default(), Capabilities::none())
        .await
        .unwrap();
    assert!(idle.was_idle());
    assert_eq!(control.runs(job.job_id, 10).unwrap().len(), 1);
}

#[tokio::test]
async fn pointer_commit_durably_enqueues_one_run_with_the_updated_head() {
    let temp = tempfile::tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let first = control.store.put_chunk(b"first", None).unwrap();
    let second = control.store.put_chunk(b"second", None).unwrap();
    control.pointer_log.create("release", first).unwrap();

    let job = spec(
        "on-pointer",
        JobInput::new().with_pointer("release"),
        TriggerPolicy::OnPointerUpdate,
    );
    control.create_job(job.clone()).unwrap();
    control
        .subscribe_pointer("release", job.job_id.clone())
        .unwrap();
    assert!(control.runs(job.job_id.clone(), 10).unwrap().is_empty());

    control
        .pointer_log
        .update("release", second.clone())
        .unwrap();
    assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (1, 0));

    let cycle = work_once(&control, &WorkerOptions::default(), Capabilities::none())
        .await
        .unwrap();
    assert_eq!(cycle.triggers.enqueued, 1);
    assert!(matches!(
        cycle.run,
        Some(WorkerRunOutcome::Succeeded { .. })
    ));
    assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (0, 0));

    let runs = control.runs(job.job_id.clone(), 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].manifest.pointer_heads.len(), 1);
    assert_eq!(runs[0].manifest.pointer_heads[0].head_cid, second);
    assert_eq!(runs[0].manifest.pointer_heads[0].log_seq, 2);

    // A second drain sees neither the intent nor a duplicate run.
    let idle = work_once(&control, &WorkerOptions::default(), Capabilities::none())
        .await
        .unwrap();
    assert!(idle.was_idle());
    assert_eq!(control.runs(job.job_id, 10).unwrap().len(), 1);
}

#[tokio::test]
async fn an_unsubscribed_pointer_never_enqueues_the_job() {
    let temp = tempfile::tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let first = control.store.put_chunk(b"first", None).unwrap();
    let second = control.store.put_chunk(b"second", None).unwrap();
    control.pointer_log.create("release", first).unwrap();
    let job = spec(
        "unsubscribed",
        JobInput::new().with_pointer("release"),
        TriggerPolicy::OnPointerUpdate,
    );
    control.create_job(job.clone()).unwrap();
    control
        .subscribe_pointer("release", job.job_id.clone())
        .unwrap();
    assert!(control
        .unsubscribe_pointer("release", job.job_id.clone())
        .unwrap());
    assert!(!control
        .unsubscribe_pointer("release", job.job_id.clone())
        .unwrap());

    control.pointer_log.update("release", second).unwrap();

    assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (0, 0));
    assert!(control.runs(job.job_id, 10).unwrap().is_empty());
}

#[tokio::test]
async fn explicit_subscription_survives_inert_manual_policy_and_reactivates() {
    let temp = tempfile::tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let first = control.store.put_chunk(b"first", None).unwrap();
    let second = control.store.put_chunk(b"second", None).unwrap();
    let third = control.store.put_chunk(b"third", None).unwrap();
    control.pointer_log.create("release", first).unwrap();
    let original = spec(
        "policy-cycle",
        JobInput::new().with_pointer("release"),
        TriggerPolicy::OnPointerUpdate,
    );
    control.create_job(original.clone()).unwrap();
    control
        .subscribe_pointer("release", original.job_id.clone())
        .unwrap();

    let mut manual = original.clone();
    manual.policy.trigger = TriggerPolicy::Manual;
    control.update_job(manual).unwrap();
    control.pointer_log.update("release", second).unwrap();
    assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (0, 0));

    control.update_job(original.clone()).unwrap();
    control.pointer_log.update("release", third).unwrap();
    assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (1, 0));
}

#[tokio::test]
async fn safe_worker_leaves_withheld_exec_pending_and_runs_eligible_work() {
    let temp = tempfile::tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let input = control.store.put_chunk(b"input", None).unwrap();

    let exec = spec(
        "a-exec",
        JobInput::new().with_static(input.clone()),
        TriggerPolicy::OnCreate,
    );
    let mut exec = exec;
    exec.code_ref = "exec".to_string();
    let hash = spec(
        "z-hash",
        JobInput::new().with_static(input),
        TriggerPolicy::OnCreate,
    );
    control.create_job(exec.clone()).unwrap();
    control.create_job(hash.clone()).unwrap();

    let cycle = work_once(&control, &WorkerOptions::default(), Capabilities::none())
        .await
        .unwrap();
    assert!(matches!(
        cycle.run,
        Some(WorkerRunOutcome::Succeeded { ref job_id, .. }) if job_id == "z-hash"
    ));
    assert!(matches!(
        control.runs(exec.job_id, 10).unwrap()[0].status,
        RunStatus::Pending
    ));
    assert!(matches!(
        control.runs(hash.job_id, 10).unwrap()[0].status,
        RunStatus::Succeeded
    ));
}

#[tokio::test]
async fn changing_a_job_after_enqueue_executes_the_original_revision() {
    let temp = tempfile::tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let input = control.store.put_chunk(b"input", None).unwrap();
    let original = spec(
        "changed-after-enqueue",
        JobInput::new().with_static(input.clone()),
        TriggerPolicy::OnCreate,
    );
    control.create_job(original.clone()).unwrap();

    let mut changed = original.clone();
    let replacement_input = control.store.put_chunk(b"replacement", None).unwrap();
    changed.inputs = JobInput::new().with_static(replacement_input);
    changed.declared_outputs = vec!["stdout".to_string()];
    changed.code_ref = "exec".to_string();
    changed.config = Some(serde_json::json!({
        "command": "sh",
        "args": ["-c", "printf replacement"],
        "capture_stdout": true
    }));
    control.update_job(changed).unwrap();

    let claim = control
        .job_log
        .claim_next_pending_for_code_refs("safe-worker", 60, &["hash"])
        .unwrap()
        .expect("the queued hash revision should remain claimable after its head becomes exec");

    let outcome = dag_jobs::Execution::new(&control)
        .capabilities(Capabilities::none())
        .run_claimed(&claim)
        .await
        .expect("the filed hash revision, not the new exec head, must run");
    assert_eq!(outcome.revision.event_seq, 1);
    assert_eq!(outcome.revision.code_ref, "hash");
    assert_eq!(outcome.outputs[0].0, "hash");
    let run = &control.runs(original.job_id, 10).unwrap()[0];
    assert!(matches!(run.status, RunStatus::Succeeded));
    assert_eq!(run.revision.as_ref().unwrap(), &outcome.revision);
    assert_eq!(run.manifest.static_inputs, vec![input]);
}

#[tokio::test]
async fn reopening_fails_a_running_run_even_when_its_lease_was_unexpired() {
    let temp = tempfile::tempdir().unwrap();
    let job_id = JobId::from("restart-fence");
    {
        let control = Control::open(temp.path()).unwrap();
        let input = control.store.put_chunk(b"input", None).unwrap();
        let job = spec(
            job_id.as_ref(),
            JobInput::new().with_static(input),
            TriggerPolicy::OnCreate,
        );
        control.create_job(job).unwrap();
        let claim = control
            .job_log
            .claim_pending_run(&job_id, &dag_core::RunId(1), "departed-worker", 3600)
            .unwrap();
        let prepared = control.job_log.claimed_run(&claim).unwrap();
        control
            .job_log
            .record_claimed_run_started(&claim, &prepared.manifest)
            .unwrap();
    }

    let reopened = Control::open(temp.path()).unwrap();
    let runs = reopened.runs(job_id, 1).unwrap();
    let RunStatus::Failed { message } = &runs[0].status else {
        panic!("orphaned running row must fail closed on reopen");
    };
    assert!(message.contains("process owning this running job exited"));
    assert_eq!(reopened.job_log.active_run_counts().unwrap(), (0, 0));
}

#[test]
fn reopening_releases_an_unstarted_exact_claim_and_token_can_cancel_it() {
    let temp = tempfile::tempdir().unwrap();
    let job_id = JobId::from("pending-reclaim");
    let revision = {
        let control = Control::open(temp.path()).unwrap();
        let input = control.store.put_chunk(b"input", None).unwrap();
        control
            .create_job(spec(
                job_id.as_ref(),
                JobInput::new().with_static(input),
                TriggerPolicy::OnCreate,
            ))
            .unwrap();
        let claim = control
            .job_log
            .claim_pending_run(&job_id, &dag_core::RunId(1), "departed-worker", 3600)
            .unwrap();
        let revision = control.job_log.claimed_run(&claim).unwrap().revision;
        assert!(control
            .job_log
            .claim_pending_run(&job_id, &dag_core::RunId(1), "other-worker", 60)
            .is_err());
        revision
    };

    let reopened = Control::open(temp.path()).unwrap();
    let claim = reopened
        .job_log
        .claim_pending_run(&job_id, &dag_core::RunId(1), "replacement-worker", 60)
        .expect("startup must release a lease whose adapter never started");
    assert_eq!(
        reopened.job_log.claimed_run(&claim).unwrap().revision,
        revision,
        "reclaiming a pending lease must not change its immutable revision"
    );
    reopened
        .job_log
        .record_claimed_run_completed(
            &claim,
            Vec::new(),
            RunStatus::Failed {
                message: "cancelled before execution".to_string(),
            },
            None,
        )
        .unwrap();
    assert_eq!(reopened.job_log.active_run_counts().unwrap(), (0, 0));
    assert!(matches!(
        reopened.runs(job_id, 1).unwrap()[0].status,
        RunStatus::Failed { .. }
    ));
}
