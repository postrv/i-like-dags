//! Queue admission binds a complete input snapshot before allocating a run.
//!
//! An unresolvable pointer therefore fails admission without consuming a run
//! ID or leaving an ambiguous Pending record.

use dag_core::{
    CachePolicy, Determinism, JobId, JobInput, JobPolicy, JobSpec, RunStatus, TriggerPolicy,
};

fn spec_with_pointer_input(id: &str, pointer: &str) -> JobSpec {
    JobSpec {
        job_id: JobId::from(id),
        placement: None,
        inputs: JobInput {
            static_inputs: vec![],
            pointer_inputs: vec![pointer.to_string()],
        },
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["out".into()],
        code_ref: "hash".into(),
        policy: JobPolicy {
            cache_outputs: CachePolicy::None,
            trigger: TriggerPolicy::Manual,
        },
        config: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unresolvable_input_fails_before_a_run_is_queued() {
    let temp = tempfile::tempdir().unwrap();
    let control = dag_control::Control::open(temp.path()).unwrap();
    let id = JobId::from("needs-a-pointer");
    control
        .create_job(spec_with_pointer_input("needs-a-pointer", "never/created"))
        .unwrap();

    let err = dag_jobs::execute_once(&control, &id)
        .await
        .expect_err("an unresolvable pointer input must fail the run");
    assert!(
        err.to_string().contains("never/created"),
        "the error should name the input: {err}"
    );

    assert!(control.runs(id.clone(), 10).unwrap().is_empty());
    assert_eq!(
        control.job_log.get_job(&id).unwrap().unwrap().trigger_count,
        0
    );
}

/// The positive control: a run that *does* resolve still records normally,
/// and says the adapter ran here.
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_run_records_succeeded_and_executed() {
    let temp = tempfile::tempdir().unwrap();
    let control = dag_control::Control::open(temp.path()).unwrap();
    let id = JobId::from("plain");
    control
        .create_job(JobSpec {
            job_id: id.clone(),
            placement: None,
            inputs: JobInput::new(),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["hash".into()],
            code_ref: "hash".into(),
            policy: JobPolicy {
                cache_outputs: CachePolicy::None,
                trigger: TriggerPolicy::Manual,
            },
            config: None,
        })
        .unwrap();

    let outcome = dag_jobs::execute_once(&control, &id).await.unwrap();
    assert_eq!(outcome.origin, dag_core::RunOrigin::Executed);

    let runs = control.runs(id, 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert!(matches!(runs[0].status, RunStatus::Succeeded));
    assert_eq!(runs[0].origin, dag_core::RunOrigin::Executed);
}
