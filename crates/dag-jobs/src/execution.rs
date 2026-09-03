//! End-to-end execution of a single job run against a [`Control`] plane.
//!
//! Both the CLI and the HTTP API drive job runs through [`execute_once`], so
//! there is exactly one implementation of the trigger → resolve → execute →
//! record lifecycle. Previously this lived in the CLI and the run lifecycle
//! could only be exercised by shelling out.

use std::sync::Arc;

use crate::error::Contextualize;
use crate::Result;
use dag_control::blocking::offload;
use dag_control::{now_unix, Control, ControlError, EffectCache, PinCreator, RunClaim};
use dag_core::{
    Cid, InputManifest, JobError, JobId, JobRevision, ResolvedPointer, RunId, RunOrigin, RunStatus,
};

use crate::adapters::{
    AttestAdapter, ConcatAdapter, EchoAdapter, FakeFetchAdapter, HashAdapter,
    SIMULATED_FETCH_PAYLOAD, SIMULATED_FETCH_URL,
};
use crate::runner::JobRunner;

/// What an execution is permitted to do beyond pure computation over content.
///
/// Defaults to nothing. This is a deny-by-default gate rather than a flag on
/// the runner because the caller who must *not* grant `exec` — the HTTP
/// server — should get the safe behaviour by writing no code at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Permit the `exec` adapter to run local commands.
    ///
    /// Granting this allows any job whose `code_ref` is `exec` to run its
    /// configured command with the privileges of this process. Never grant it
    /// on a path reachable from an unauthenticated network surface — see the
    /// [`crate::exec`] threat model.
    pub exec: bool,
}

impl Capabilities {
    /// Grant nothing. Equivalent to [`Default`], spelled out for call sites
    /// where the intent should be obvious.
    pub fn none() -> Self {
        Self::default()
    }

    /// Grant local command execution.
    pub fn with_exec(mut self) -> Self {
        self.exec = true;
        self
    }
}

/// A runner with every capability-free adapter registered.
///
/// `code_ref` in a [`dag_core::JobSpec`] selects among these by name:
/// `hash`, `concat`, `attest`, `echo`, `fake_fetch`. Notably *not* `exec` —
/// use [`runner_with_capabilities`] for that.
///
/// `fake_fetch` is a **test double**, not a fetcher: it makes no network
/// request and emits [`SIMULATED_FETCH_PAYLOAD`], which says so in its own
/// bytes. See [`builtin_adapters`], which reports it as simulated.
pub fn default_runner(control: &Control) -> JobRunner {
    runner_with_capabilities(control, Capabilities::none())
}

/// A runner with the built-in adapters plus whatever `caps` permits.
pub fn runner_with_capabilities(control: &Control, caps: Capabilities) -> JobRunner {
    let mut runner = JobRunner::new(control.store.clone());
    runner.register_adapter(Arc::new(HashAdapter));
    runner.register_adapter(Arc::new(ConcatAdapter));
    runner.register_adapter(Arc::new(AttestAdapter));
    runner.register_adapter(Arc::new(EchoAdapter::new("default-echo".into())));
    // A test double. Its payload says so, because the operator who reaches it
    // by copying an example spec never reads this line.
    runner.register_adapter(Arc::new(FakeFetchAdapter::new(
        SIMULATED_FETCH_PAYLOAD.to_vec(),
        SIMULATED_FETCH_URL.into(),
    )));

    match caps.exec {
        #[cfg(all(feature = "exec", unix))]
        true => runner.register_adapter(Arc::new(crate::exec::ExecAdapter)),

        // Built with exec, but this caller did not ask for it. Say so plainly:
        // this is the path the HTTP API always takes.
        #[cfg(all(feature = "exec", unix))]
        false => runner.withhold_adapter(
            "exec",
            "running local commands requires the exec capability, which this \
             caller did not grant (the HTTP API never does — it is \
             unauthenticated). From the CLI, pass `--allow-exec`.",
        ),

        // Not built with exec at all.
        #[cfg(not(all(feature = "exec", unix)))]
        _ => runner.withhold_adapter(
            "exec",
            "this binary has no contained exec adapter; it requires both the `exec` cargo \
             feature and Unix process-group support",
        ),
    }

    runner
}

/// What `dag job adapters` and `GET /api/adapters` report about one built-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AdapterInfo {
    /// The `code_ref` a [`dag_core::JobSpec`] sets to select this adapter.
    pub name: &'static str,
    /// Identical inputs must produce identical outputs (J1).
    pub deterministic: bool,
    /// The adapter only *simulates* the work its name describes.
    ///
    /// A simulated adapter is a test double kept in the default runner so the
    /// side-effecting paths are exercisable without a network. Its outputs are
    /// fabricated. This flag exists so no surface can list one next to a real
    /// adapter without saying so.
    pub simulated: bool,
    /// One line an operator can act on.
    pub summary: &'static str,
}

/// The adapters [`default_runner`] registers.
///
/// `exec` is listed only when the feature is compiled in, so
/// `dag job adapters` tells the operator what this binary can actually do.
pub fn builtin_adapters() -> Vec<AdapterInfo> {
    let real = |name, deterministic, summary| AdapterInfo {
        name,
        deterministic,
        simulated: false,
        summary,
    };

    let mut adapters = vec![
        real("hash", true, "SHA-256 over the concatenated input bytes"),
        real("concat", true, "concatenates the input bytes in order"),
        real(
            "attest",
            true,
            "records what this run resolved, as an attestation/v1 entry",
        ),
        real("echo", true, "emits a fixed string; a wiring smoke test"),
        AdapterInfo {
            name: "fake_fetch",
            deterministic: false,
            simulated: true,
            summary: "a test double for the effect cache, NOT a fetcher: \
                      makes no network request, returns fixed bytes that say so",
        },
    ];
    // `cfg!` rather than `#[cfg]`: the attribute form leaves `adapters`
    // needlessly mutable in a build without the feature, which is a warning,
    // and CI's `-D warnings` only ever sees the all-features build.
    if cfg!(all(feature = "exec", unix)) {
        adapters.push(real(
            "exec",
            false,
            "runs a declared local command; requires the exec capability",
        ));
    }
    adapters
}

/// Resolve a job's declared inputs against the current pointer heads.
///
/// The result is a snapshot: it records the pointer sequence numbers it read,
/// so a run can be replayed against exactly the same inputs later (J3).
pub fn resolve_inputs(control: &Control, job_id: &JobId) -> Result<InputManifest> {
    let head = control
        .job_log
        .get_job(job_id)?
        .ok_or_else(|| JobError::JobNotFound(job_id.to_string()))?;

    let mut pointer_heads = Vec::new();
    for pointer_id in &head.spec.inputs.pointer_inputs {
        let ptr = control
            .pointer_log
            .get_head(pointer_id)
            .map_err(ControlError::from)
            .ctx(|| format!("resolving pointer input {:?}", pointer_id))?;
        pointer_heads.push(ResolvedPointer {
            pointer_id: pointer_id.clone(),
            head_cid: ptr.current_cid,
            log_seq: ptr.seq,
        });
    }

    Ok(InputManifest {
        static_inputs: head.spec.inputs.static_inputs.clone(),
        pointer_heads,
        resolved_at_unix: now_unix(),
    })
}

/// Outcome of a completed run.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Identifier assigned to this run.
    pub run_id: RunId,
    /// Output CIDs, keyed by the job's declared output names.
    pub outputs: Vec<(String, Cid)>,
    /// Whether the adapter ran here, the effect cache answered, or a signed
    /// claim was adopted. Recorded on the run too, so it survives the call.
    pub origin: RunOrigin,
    /// Immutable job event used for this execution.
    pub revision: JobRevision,
}

/// The word `dag job run-once` and the run record use for an origin.
pub fn effect_origin_label(origin: &RunOrigin) -> &'static str {
    match origin {
        RunOrigin::Executed => "executed",
        RunOrigin::CacheHit => "cache-hit",
        RunOrigin::Adopted => "adopted",
    }
}

/// Execute one run of `job_id` with no extra capabilities.
///
/// This is the safe default and what the HTTP API uses: a job whose `code_ref`
/// is `exec` fails here as an unknown adapter, which is the intended
/// behaviour on an unauthenticated surface. Callers that should be able to run
/// commands — the CLI — use [`execute_once_with`].
pub async fn execute_once(control: &Control, job_id: &JobId) -> Result<RunOutcome> {
    execute_once_with(control, job_id, Capabilities::none()).await
}

/// Execute one run of `job_id`: trigger, resolve inputs, run the adapter, and
/// record the result in the job log.
///
/// A failure is recorded as a failed run *and* returned, so callers never have
/// to reconcile "the log says failed" against "the call returned Ok".
pub async fn execute_once_with(
    control: &Control,
    job_id: &JobId,
    caps: Capabilities,
) -> Result<RunOutcome> {
    execute_once_hooked(control, job_id, caps, crate::runner::EffectHooks::none()).await
}

/// [`execute_once_with`] plus attested-effect participation (ADR-003).
///
/// `hooks.adopt` lets a keyring-trusted claim satisfy a cache miss without
/// executing; `hooks.attest` publishes a signed claim for the resolved
/// outputs. Both default to absent everywhere: the HTTP API and the plain
/// CLI path can never adopt or attest by accident.
pub async fn execute_once_hooked(
    control: &Control,
    job_id: &JobId,
    caps: Capabilities,
    hooks: crate::runner::EffectHooks<'_>,
) -> Result<RunOutcome> {
    Execution::new(control)
        .capabilities(caps)
        .hooks(hooks)
        .run(job_id)
        .await
}

/// A configurable single-run execution — the embedder's entry point when the
/// built-in adapters are not enough.
///
/// Everything [`execute_once`] does (trigger, resolve, record, effect cache,
/// output pinning) with the one thing it could not offer: adapters the
/// *caller* brings. Before this existed an embedder chose between the
/// provenance lifecycle and their own adapters — building a `JobRunner` by
/// hand skipped the run record entirely, which is the half the system is for.
///
/// ```no_run
/// # use dag_jobs::{Execution, JobAdapter};
/// # use std::sync::Arc;
/// # async fn demo(control: &dag_control::Control, my_adapter: Arc<dyn JobAdapter>) -> dag_jobs::Result<()> {
/// let outcome = Execution::new(control)
///     .adapter(my_adapter) // resolves whatever `code_ref` it names
///     .run(&"my-job".to_string().into())
///     .await?;
/// # Ok(()) }
/// ```
///
/// The capability gate is unmoved: a caller-supplied adapter runs *their*
/// code, in *their* process, which they could run anyway — but the built-in
/// names stay authoritative. Registering an adapter under a built-in name
/// (including a withheld `exec`) is refused, so no embedder discovers that
/// shadowing `hash` silently changed what every spec in the directory means.
pub struct Execution<'c> {
    control: &'c Control,
    caps: Capabilities,
    hooks: crate::runner::EffectHooks<'c>,
    extra: Vec<Arc<dyn crate::adapters::JobAdapter>>,
}

impl<'c> Execution<'c> {
    /// Start configuring a run against `control`. Grants nothing.
    pub fn new(control: &'c Control) -> Self {
        Self {
            control,
            caps: Capabilities::none(),
            hooks: crate::runner::EffectHooks::none(),
            extra: Vec::new(),
        }
    }

    /// Grant capabilities beyond pure computation (see [`Capabilities`]).
    pub fn capabilities(mut self, caps: Capabilities) -> Self {
        self.caps = caps;
        self
    }

    /// Participate in attested effect claims (ADR-003).
    pub fn hooks(mut self, hooks: crate::runner::EffectHooks<'c>) -> Self {
        self.hooks = hooks;
        self
    }

    /// Register a caller-supplied adapter for this run. Repeatable.
    ///
    /// The adapter's `name()` is the `code_ref` it answers to.
    pub fn adapter(mut self, adapter: Arc<dyn crate::adapters::JobAdapter>) -> Self {
        self.extra.push(adapter);
        self
    }

    /// Run one execution of `job_id` through the full lifecycle.
    pub async fn run(self, job_id: &JobId) -> Result<RunOutcome> {
        let (control, runner, hooks) = self.prepare_runner()?;
        execute_via(control, runner, job_id, hooks, None).await
    }

    /// Execute a Pending run already claimed by a durable background worker.
    /// Unlike [`Self::run`], this does not create another run record.
    pub async fn run_claimed(self, claim: &RunClaim) -> Result<RunOutcome> {
        let job_id = claim.job_id.clone();
        let (control, runner, hooks) = self.prepare_runner()?;
        execute_via(control, runner, &job_id, hooks, Some(claim)).await
    }

    fn prepare_runner(
        self,
    ) -> Result<(
        &'c Control,
        crate::runner::JobRunner,
        crate::runner::EffectHooks<'c>,
    )> {
        let Self {
            control,
            caps,
            hooks,
            extra,
        } = self;
        let mut runner = runner_with_capabilities(control, caps);
        for adapter in extra {
            let name = adapter.name();
            if runner.has_adapter(name) || runner.is_withheld(name) {
                return Err(crate::RunError::Invalid(format!(
                    "adapter name {name:?} is built in and cannot be shadowed; \
                     pick another code_ref for the custom adapter"
                )));
            }
            runner.register_adapter(adapter);
        }
        Ok((control, runner, hooks))
    }
}

/// The trigger → resolve → execute → record lifecycle over a ready runner.
async fn execute_via(
    control: &Control,
    runner: crate::runner::JobRunner,
    job_id: &JobId,
    hooks: crate::runner::EffectHooks<'_>,
    claim: Option<&RunClaim>,
) -> Result<RunOutcome> {
    // Manual runs enqueue and claim the exact new row; background workers
    // arrive with a claim. From here onward the paths are identical.
    let (claim, spec, manifest, revision) = offload(|| {
        let claim = match claim {
            Some(claim) => claim.clone(),
            None => {
                let run_id = control.enqueue_job_run(job_id, "manual")?;
                control
                    .job_log
                    .claim_pending_run(job_id, &run_id, "manual-local", 60)?
            }
        };
        let prepared = match (|| {
            let prepared = control.job_log.claimed_run(&claim)?;
            control
                .job_log
                .record_claimed_run_started(&claim, &prepared.manifest)?;
            Ok::<_, crate::RunError>(prepared)
        })() {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = control.job_log.record_claimed_run_completed(
                    &claim,
                    Vec::new(),
                    RunStatus::Failed {
                        message: error.to_string(),
                    },
                    None,
                );
                return Err(error);
            }
        };
        Ok::<_, crate::RunError>((claim, prepared.spec, prepared.manifest, prepared.revision))
    })?;
    let run_id = claim.run_id;

    tracing::info!(
        job_id = %job_id,
        run_id = %run_id,
        static_inputs = manifest.static_inputs.len(),
        pointer_inputs = manifest.pointer_heads.len(),
        "job run started"
    );

    let execution = runner.execute_with_policy(
        &spec,
        &manifest,
        &*control.job_log as &dyn EffectCache,
        Some(&*control.pin_log as &dyn PinCreator),
        hooks,
    );
    // A claim renewal failure cancels manual work as well as worker work.
    tokio::pin!(execution);
    let mut heartbeat = tokio::time::interval(claim.heartbeat_interval());
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let result = loop {
        tokio::select! {
            outcome = &mut execution => break outcome,
            _ = heartbeat.tick() => {
                if let Err(error) = offload(|| control.job_log.renew_run_claim(&claim)) {
                    break Err(crate::RunError::from(error));
                }
            }
        }
    };

    match result {
        Ok(effect) => {
            let outputs = effect.outputs;
            let origin = effect.origin;
            offload(|| {
                control.job_log.record_claimed_run_completed(
                    &claim,
                    outputs.clone(),
                    RunStatus::Succeeded,
                    Some(origin.clone()),
                )
            })?;
            tracing::info!(
                job_id = %job_id,
                run_id = %run_id,
                outputs = outputs.len(),
                origin = ?effect_origin_label(&origin),
                "job run succeeded"
            );
            Ok(RunOutcome {
                run_id,
                outputs,
                origin,
                revision,
            })
        }
        Err(e) => {
            offload(|| {
                let status = RunStatus::Failed {
                    message: e.to_string(),
                };
                control
                    .job_log
                    .record_claimed_run_completed(&claim, Vec::new(), status, None)
            })?;
            tracing::error!(job_id = %job_id, run_id = %run_id, error = %e, "job run failed");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every listed adapter must be registered, and vice versa: a name in the
    /// listing that no runner answers to sends an operator writing a spec
    /// against an adapter that does not exist.
    #[test]
    fn the_listing_matches_what_the_default_runner_registers() {
        let temp = tempfile::tempdir().unwrap();
        let control = Control::open(temp.path()).unwrap();
        let runner = default_runner(&control);

        for info in builtin_adapters() {
            // `exec` is listed when compiled in, but the default runner
            // withholds it — that withholding is itself the documented state.
            if info.name == "exec" {
                continue;
            }
            assert!(
                runner.has_adapter(info.name),
                "`{}` is advertised but not registered",
                info.name
            );
        }
    }

    /// The one adapter that fabricates its output must say so, and nothing
    /// else may claim to. Without this, adding a second double silently gets
    /// it listed as if it did real work.
    #[test]
    fn fake_fetch_is_the_only_adapter_marked_simulated() {
        let simulated: Vec<_> = builtin_adapters()
            .into_iter()
            .filter(|a| a.simulated)
            .map(|a| a.name)
            .collect();
        assert_eq!(simulated, vec!["fake_fetch"]);
    }

    /// The bytes an operator actually receives have to carry the warning: the
    /// listing is one `dag job adapters` away, and nobody runs it after the
    /// job already succeeded.
    #[test]
    fn the_simulated_payload_announces_itself() {
        let text = std::str::from_utf8(SIMULATED_FETCH_PAYLOAD).unwrap();
        assert!(text.contains("SIMULATED"), "payload must self-identify");
        assert!(
            text.contains("no network request"),
            "payload must say no fetch happened"
        );
    }
}
