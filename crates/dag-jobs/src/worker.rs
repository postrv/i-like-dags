//! Durable background job worker.
//!
//! Pointer updates write trigger intents in the same redb commit as the new
//! pointer head. This worker drains those intents through idempotent receipts,
//! claims Pending runs under a lease, and executes the already-existing run.
//! A crash before Running allows the same run to be reclaimed; a crash after
//! Running fails it closed and never automatically repeats an uncertain side
//! effect.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use dag_control::blocking::offload;
use dag_control::{Control, TriggerDrainReport};

use crate::{Capabilities, Execution, Result};

/// Runtime policy for a background worker.
#[derive(Debug, Clone)]
pub struct WorkerOptions {
    /// Stable operator-visible identity recorded on each run.
    pub worker_id: String,
    /// Claim lifetime. Execution heartbeats every third of this interval.
    pub lease_seconds: u64,
    /// Delay when no work is available.
    pub poll_interval: Duration,
    /// Maximum pointer-trigger intents converted per cycle.
    pub trigger_batch: usize,
}

impl Default for WorkerOptions {
    fn default() -> Self {
        Self {
            worker_id: format!("local-{}", std::process::id()),
            lease_seconds: 60,
            poll_interval: Duration::from_millis(250),
            trigger_batch: 256,
        }
    }
}

/// Outcome of the one run a cycle may execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerRunOutcome {
    Succeeded {
        job_id: String,
        run_id: String,
    },
    /// Adapter and resolution failures are already recorded on the run; they
    /// are operational outcomes, not reasons to stop the worker loop.
    Failed {
        job_id: String,
        run_id: String,
        error: String,
    },
}

/// Observable work completed in one scheduler cycle.
#[derive(Debug, Clone)]
pub struct WorkCycle {
    pub triggers: TriggerDrainReport,
    pub expired_running_runs: u32,
    pub run: Option<WorkerRunOutcome>,
}

impl WorkCycle {
    pub fn was_idle(&self) -> bool {
        self.triggers.examined == 0 && self.expired_running_runs == 0 && self.run.is_none()
    }
}

/// Drain trigger intents, expire abandoned claims, and execute at most one
/// pending run. Keeping the cycle bounded gives shutdown and health tasks a
/// chance to run even under a permanently non-empty queue.
pub async fn work_once(
    control: &Control,
    options: &WorkerOptions,
    capabilities: Capabilities,
) -> Result<WorkCycle> {
    let triggers = offload(|| control.drain_job_trigger_queue(options.trigger_batch))?;
    let expired_running_runs = offload(|| control.job_log.expire_run_claims())?;
    let runnable: Vec<&str> = crate::builtin_adapters()
        .into_iter()
        .filter(|adapter| adapter.name != "exec" || capabilities.exec)
        .map(|adapter| adapter.name)
        .collect();
    let claim = offload(|| {
        control.job_log.claim_next_pending_for_code_refs(
            &options.worker_id,
            options.lease_seconds,
            &runnable,
        )
    })?;

    let run = match claim {
        None => None,
        Some(claim) => {
            let job_id = claim.job_id.to_string();
            let run_id = claim.run_id.to_string();
            match Execution::new(control)
                .capabilities(capabilities)
                .run_claimed(&claim)
                .await
            {
                Ok(_) => Some(WorkerRunOutcome::Succeeded { job_id, run_id }),
                Err(error) => Some(WorkerRunOutcome::Failed {
                    job_id,
                    run_id,
                    error: error.to_string(),
                }),
            }
        }
    };

    Ok(WorkCycle {
        triggers,
        expired_running_runs,
        run,
    })
}

/// Run until `shutdown` resolves. Transient scheduler errors are logged and
/// retried with a bounded delay; a malformed job fails its own run and the
/// worker continues to the next one.
pub async fn run_worker_until<F>(
    control: Arc<Control>,
    options: WorkerOptions,
    capabilities: Capabilities,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    if options.poll_interval.is_zero() {
        return Err(crate::RunError::Invalid(
            "worker poll interval must be non-zero".to_string(),
        ));
    }
    if options.trigger_batch == 0 {
        return Err(crate::RunError::Invalid(
            "worker trigger batch must be non-zero".to_string(),
        ));
    }

    tokio::pin!(shutdown);
    loop {
        // Once a run is claimed, let it reach a recorded terminal state.
        // Dropping the future on the first shutdown signal abandons a Running
        // side effect and leaves it to fail only after lease expiry. Shutdown
        // is observed between bounded cycles instead.
        let outcome = work_once(&control, &options, capabilities).await;

        let delay = match outcome {
            Ok(cycle) => {
                if let Some(ref run) = cycle.run {
                    match run {
                        WorkerRunOutcome::Succeeded { job_id, run_id } => {
                            tracing::info!(%job_id, %run_id, "background job succeeded");
                        }
                        WorkerRunOutcome::Failed {
                            job_id,
                            run_id,
                            error,
                        } => {
                            tracing::error!(%job_id, %run_id, %error, "background job failed");
                        }
                    }
                }
                if cycle.triggers.dead_lettered > 0 {
                    tracing::error!(
                        count = cycle.triggers.dead_lettered,
                        "job trigger intents moved to the dead-letter table"
                    );
                }
                if cycle.expired_running_runs > 0 {
                    tracing::error!(
                        count = cycle.expired_running_runs,
                        "job runs failed after worker lease expiry"
                    );
                }
                if cycle.was_idle() {
                    options.poll_interval
                } else {
                    Duration::ZERO
                }
            }
            Err(error) => {
                tracing::error!(%error, "background job scheduler cycle failed; retrying");
                options.poll_interval.max(Duration::from_secs(1))
            }
        };

        if delay.is_zero() {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                _ = tokio::task::yield_now() => {}
            }
            continue;
        }
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(delay) => {}
        }
    }
}
