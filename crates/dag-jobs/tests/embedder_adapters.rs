//! The embedder's bargain, kept: caller-supplied adapters get the whole
//! provenance lifecycle — run records, manifests, the effect cache, output
//! pinning — and the capability gate does not move an inch.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dag_core::{
    CachePolicy, ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, TriggerPolicy,
};
use dag_jobs::{Execution, JobAdapter, JobContext, RunError};

/// A side-effecting adapter an embedder might bring: counts invocations so
/// the effect cache's promise (J2) is observable.
struct CountingAdapter {
    invocations: AtomicUsize,
}

#[async_trait::async_trait]
impl JobAdapter for CountingAdapter {
    fn name(&self) -> &'static str {
        "embedder-llm"
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, dag_core::Cid)>, RunError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        // Deterministic bytes derived from the inputs, standing in for a
        // model call's response.
        let body = format!("response to {} inputs", ctx.manifest.static_inputs.len());
        let cid = store
            .put_chunk(body.as_bytes(), None)
            .map_err(|e| RunError::Invalid(e.to_string()))?;
        Ok(vec![("response".to_string(), cid)])
    }

    fn is_deterministic(&self) -> bool {
        false
    }

    fn effect_spec(&self, _ctx: &JobContext<'_>) -> Option<String> {
        Some("model=demo;temp=0".to_string())
    }
}

fn spec(job_id: &str, code_ref: &str, input: dag_core::Cid) -> JobSpec {
    JobSpec {
        job_id: JobId::from(job_id.to_string()),
        placement: None,
        inputs: JobInput {
            static_inputs: vec![input],
            pointer_inputs: vec![],
        },
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["response".to_string()],
        code_ref: code_ref.to_string(),
        policy: JobPolicy {
            cache_outputs: CachePolicy::None,
            trigger: TriggerPolicy::Manual,
        },
        config: None,
    }
}

#[tokio::test]
async fn a_custom_adapter_gets_the_full_lifecycle_and_the_effect_cache() {
    let temp = tempfile::tempdir().unwrap();
    let control = dag_control::Control::open(temp.path()).unwrap();
    let input = control.store.put_chunk(b"prompt", None).unwrap();

    let job_id = JobId::from("llm-step".to_string());
    control
        .job_log
        .create_job(spec("llm-step", "embedder-llm", input))
        .unwrap();

    let adapter = Arc::new(CountingAdapter {
        invocations: AtomicUsize::new(0),
    });

    // First run executes the adapter…
    let first = Execution::new(&control)
        .adapter(adapter.clone())
        .run(&job_id)
        .await
        .unwrap();
    assert_eq!(adapter.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(first.outputs.len(), 1);

    // …and the run was *recorded*: id, manifest, status, outputs — the
    // provenance half a hand-built JobRunner always skipped.
    let runs = control.job_log.get_job_runs(&job_id, Some(10)).unwrap();
    assert_eq!(runs.len(), 1);
    assert!(matches!(runs[0].status, dag_core::RunStatus::Succeeded));
    assert_eq!(runs[0].manifest.static_inputs.len(), 1);
    assert_eq!(runs[0].outputs, first.outputs);

    // A second run with identical inputs is a cache hit (J2): same outputs,
    // no second invocation — the embedder's LLM call was not re-billed.
    let second = Execution::new(&control)
        .adapter(adapter.clone())
        .run(&job_id)
        .await
        .unwrap();
    assert_eq!(adapter.invocations.load(Ordering::SeqCst), 1, "re-invoked");
    assert_eq!(second.outputs, first.outputs);
    assert_eq!(
        control
            .job_log
            .get_job_runs(&job_id, Some(10))
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn shadowing_a_builtin_name_is_refused_before_anything_runs() {
    struct Imposter;
    #[async_trait::async_trait]
    impl JobAdapter for Imposter {
        fn name(&self) -> &'static str {
            "hash" // a built-in
        }
        async fn run(
            &self,
            _store: &Arc<dyn ContentStore>,
            _ctx: &JobContext<'_>,
        ) -> Result<Vec<(String, dag_core::Cid)>, RunError> {
            unreachable!("a shadowing adapter must never run")
        }
        fn is_deterministic(&self) -> bool {
            true
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let control = dag_control::Control::open(temp.path()).unwrap();
    let input = control.store.put_chunk(b"data", None).unwrap();
    let job_id = JobId::from("hashed".to_string());
    control
        .job_log
        .create_job(spec("hashed", "hash", input))
        .unwrap();

    let err = Execution::new(&control)
        .adapter(Arc::new(Imposter))
        .run(&job_id)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("hash"), "{msg}");
    assert!(msg.contains("shadow"), "{msg}");

    // Refused before the lifecycle started: no run was recorded.
    assert!(control
        .job_log
        .get_job_runs(&job_id, Some(10))
        .unwrap()
        .is_empty());
}

#[cfg(feature = "exec")]
#[tokio::test]
async fn a_withheld_exec_cannot_be_shadowed_either() {
    struct FakeExec;
    #[async_trait::async_trait]
    impl JobAdapter for FakeExec {
        fn name(&self) -> &'static str {
            "exec"
        }
        async fn run(
            &self,
            _store: &Arc<dyn ContentStore>,
            _ctx: &JobContext<'_>,
        ) -> Result<Vec<(String, dag_core::Cid)>, RunError> {
            unreachable!()
        }
        fn is_deterministic(&self) -> bool {
            false
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let control = dag_control::Control::open(temp.path()).unwrap();
    let input = control.store.put_chunk(b"data", None).unwrap();
    let job_id = JobId::from("sneaky".to_string());
    control
        .job_log
        .create_job(spec("sneaky", "exec", input))
        .unwrap();

    // No capabilities granted; the built-in exec is withheld — and the name
    // stays reserved even so.
    let err = Execution::new(&control)
        .adapter(Arc::new(FakeExec))
        .run(&job_id)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("shadow"), "{err}");
}
