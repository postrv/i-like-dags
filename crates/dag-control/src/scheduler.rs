//! Minimal job scheduler for M5
//!
//! This module implements a basic scheduler that can trigger jobs
//! based on pointer updates. For M5, this is a simplified implementation
//! without full event-driven architecture.

use crate::error::Result;
use dag_core::{ContentStore, InputManifest, JobId};
use std::sync::Arc;

use crate::{JobLog, PointerLog};

/// Minimal scheduler for triggering jobs
///
/// The scheduler only resolves *names* to CIDs; it never reads content, which
/// is why it holds no store. Fetching and validating the bytes those CIDs point
/// at is the runner's job, and keeping the split explicit means the scheduler
/// stays cheap to call.
pub struct Scheduler<S: ContentStore> {
    job_log: Arc<JobLog>,
    pointer_log: Arc<PointerLog<S>>,
}

impl<S: ContentStore + 'static> Scheduler<S> {
    /// Create a new scheduler
    pub fn new(job_log: Arc<JobLog>, pointer_log: Arc<PointerLog<S>>) -> Self {
        Self {
            job_log,
            pointer_log,
        }
    }

    /// Resolve inputs for a job (including pointer resolution)
    ///
    /// Creates an InputManifest with all pointer inputs resolved to their current heads.
    /// The manifest captures log_seq for each pointer to enable replay fidelity.
    pub fn resolve_inputs(&self, job_id: &JobId) -> Result<InputManifest> {
        let head = self
            .job_log
            .get_job(job_id)?
            .ok_or_else(|| dag_core::JobError::JobNotFound(job_id.to_string()))?;

        self.resolve_spec_inputs(&head.spec)
    }

    fn resolve_spec_inputs(&self, spec: &dag_core::JobSpec) -> Result<InputManifest> {
        // Static inputs are copied directly
        let static_inputs = spec.inputs.static_inputs.clone();

        // Resolve pointer inputs with sequence tracking for replay fidelity
        let mut pointer_heads = Vec::new();
        for pointer_id in &spec.inputs.pointer_inputs {
            let pointer_head = self.pointer_log.get_head(pointer_id)?;

            pointer_heads.push(dag_core::ResolvedPointer {
                pointer_id: pointer_id.clone(),
                head_cid: pointer_head.current_cid,
                log_seq: pointer_head.seq,
            });
        }

        Ok(InputManifest {
            static_inputs,
            pointer_heads,
            resolved_at_unix: current_timestamp(),
        })
    }

    /// Trigger all jobs subscribed to a pointer
    pub fn trigger_jobs_for_pointer(&self, pointer_id: &str) -> Result<Vec<dag_core::RunId>> {
        let subscribed_jobs = self.job_log.get_pointer_subscriptions(pointer_id)?;

        let mut run_ids = Vec::new();
        for job_id in subscribed_jobs {
            let reason = format!("pointer_update:{}", pointer_id);
            let run_id = self
                .job_log
                .trigger_job_resolved(&job_id, &reason, |spec| self.resolve_spec_inputs(spec))?;
            run_ids.push(run_id);
        }

        Ok(run_ids)
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    crate::now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JobLog, PointerLog};
    use dag_core::{Determinism, JobInput, JobPolicy, JobSpec, TriggerPolicy};
    use dag_storage::FsStore;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Arc<FsStore>, Scheduler<FsStore>) {
        let temp = TempDir::new().unwrap();

        let store = Arc::new(FsStore::new(temp.path().join("data")).unwrap());
        let db = Arc::new(redb::Database::create(temp.path().join("control.redb")).unwrap());

        let bus = crate::EventBus::with_journal(100, db.clone()).unwrap();

        let job_log = Arc::new(
            JobLog::new(db.clone(), store.clone())
                .unwrap()
                .with_event_bus(bus.clone()),
        );
        let pointer_log = Arc::new(
            PointerLog::new(store.clone(), db)
                .unwrap()
                .with_event_bus(bus.clone()),
        );

        let scheduler = Scheduler::new(job_log, pointer_log);

        (temp, store, scheduler)
    }

    #[test]
    fn test_resolve_inputs_with_pointers() {
        let (_temp, store, scheduler) = setup();

        // Create some content
        let cid1 = store.put_chunk(b"static input", None).unwrap();
        let cid2 = store.put_chunk(b"pointer target", None).unwrap();

        // Create a pointer
        scheduler
            .pointer_log
            .create("test-ptr", cid2.clone())
            .unwrap();

        // Create a job with both static and pointer inputs
        let spec = JobSpec {
            job_id: JobId::from("test-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new()
                .with_static(cid1.clone())
                .with_pointer("test-ptr"),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["output".into()],
            code_ref: "hash".into(),
            policy: JobPolicy {
                trigger: TriggerPolicy::OnPointerUpdate,
                ..JobPolicy::default()
            },
            config: None,
        };

        scheduler.job_log.create_job(spec.clone()).unwrap();

        // Resolve inputs
        let manifest = scheduler.resolve_inputs(&spec.job_id).unwrap();

        assert_eq!(manifest.static_inputs.len(), 1);
        assert_eq!(manifest.pointer_heads.len(), 1);
        assert_eq!(manifest.static_inputs[0], cid1);
        assert_eq!(manifest.pointer_heads[0].head_cid, cid2);
        assert_eq!(manifest.pointer_heads[0].pointer_id, "test-ptr");

        // Test flattened view
        let flat = manifest.flattened();
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0], cid1);
        assert_eq!(flat[1], cid2);
    }

    #[test]
    fn test_trigger_jobs_for_pointer() {
        let (_temp, store, scheduler) = setup();

        // Create content and pointer
        let cid = store.put_chunk(b"data", None).unwrap();
        scheduler
            .pointer_log
            .create("trigger-ptr", cid.clone())
            .unwrap();

        // Create two jobs
        let spec1 = JobSpec {
            job_id: JobId::from("job1"),
            placement: Some("node1".into()),
            inputs: JobInput::new().with_pointer("trigger-ptr"),
            determinism: Determinism::Deterministic,
            declared_outputs: vec![],
            code_ref: "hash".into(),
            policy: JobPolicy {
                trigger: TriggerPolicy::OnPointerUpdate,
                ..JobPolicy::default()
            },
            config: None,
        };

        let spec2 = JobSpec {
            job_id: JobId::from("job2"),
            placement: Some("node1".into()),
            inputs: JobInput::new().with_pointer("trigger-ptr"),
            determinism: Determinism::Deterministic,
            declared_outputs: vec![],
            code_ref: "concat".into(),
            policy: JobPolicy {
                trigger: TriggerPolicy::OnPointerUpdate,
                ..JobPolicy::default()
            },
            config: None,
        };

        scheduler.job_log.create_job(spec1.clone()).unwrap();
        scheduler.job_log.create_job(spec2.clone()).unwrap();

        // Subscribe jobs to pointer
        scheduler
            .job_log
            .subscribe_pointer("trigger-ptr", &spec1.job_id)
            .unwrap();
        scheduler
            .job_log
            .subscribe_pointer("trigger-ptr", &spec2.job_id)
            .unwrap();

        // Trigger jobs
        let run_ids = scheduler.trigger_jobs_for_pointer("trigger-ptr").unwrap();

        assert_eq!(run_ids.len(), 2);

        // Verify runs were created
        let runs1 = scheduler.job_log.get_job_runs(&spec1.job_id, None).unwrap();
        let runs2 = scheduler.job_log.get_job_runs(&spec2.job_id, None).unwrap();

        assert_eq!(runs1.len(), 1);
        assert_eq!(runs2.len(), 1);
    }
}
