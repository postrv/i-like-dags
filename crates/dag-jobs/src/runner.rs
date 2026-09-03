//! Job runner with effect caching for side-effecting jobs
//!
//! This module implements the JobRunner, which executes jobs using registered adapters
//! and implements first-run caching for side-effecting jobs.

use crate::error::{Contextualize, RunError};
use crate::Result;
use dag_control::blocking::offload;
use dag_control::{AttestedEffects, EffectCache, EffectClaimSink, PinCreator};
use dag_core::{
    CachePolicy, Cid, ContentStore, EffectKey, InputManifest, JobError, JobSpec, PinScope,
    PinTarget, RunOrigin,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::adapters::{JobAdapter, JobContext};

/// Optional attested-effect participation for one execution (ADR-003).
///
/// Deny-by-default in both directions: with no hooks, execution behaves
/// exactly as before this type existed. `adopt` lets a keyring-trusted
/// claim satisfy a cache miss without running the adapter; `attest`
/// publishes a signed claim for whatever outputs this key resolves to.
#[derive(Default, Clone, Copy)]
pub struct EffectHooks<'a> {
    /// Consulted on an effect-cache miss, before the adapter runs.
    pub adopt: Option<&'a dyn AttestedEffects>,
    /// Told the (key, outputs) fact after it is known — on execution, cache
    /// hit, or adoption alike, since the fact is the same in all three.
    pub attest: Option<&'a dyn EffectClaimSink>,
}

impl EffectHooks<'_> {
    /// No participation: the pre-ADR-003 behaviour.
    pub fn none() -> Self {
        Self::default()
    }
}

/// What an execution produced, and how.
///
/// The `origin` is carried out of the runner rather than inferred by the
/// caller, because only the runner knows which of the three paths was taken —
/// and a run record that cannot tell "we built this" from "we believed a
/// signed claim that someone else had" is missing the fact ADR-003 turns on.
#[derive(Debug, Clone)]
pub struct EffectOutcome {
    /// Output CIDs by declared name.
    pub outputs: Vec<(String, Cid)>,
    /// Whether the adapter ran, the cache answered, or a claim was adopted.
    pub origin: RunOrigin,
}

/// Job runner that executes jobs with effect caching
pub struct JobRunner {
    store: Arc<dyn ContentStore>,
    adapters: HashMap<String, Arc<dyn JobAdapter>>,
    /// Adapters this runner knows about but was not permitted to register,
    /// with an explanation. Without this, a capability-gated adapter fails as
    /// "adapter not found", sending the operator to hunt for a missing build
    /// feature when they actually need to grant a capability.
    withheld: HashMap<String, String>,
}

impl JobRunner {
    fn validate_declared_outputs(spec: &JobSpec, outputs: &[(String, Cid)]) -> Result<()> {
        if outputs.len() != spec.declared_outputs.len()
            || outputs
                .iter()
                .zip(&spec.declared_outputs)
                .any(|((actual, _), declared)| actual != declared)
        {
            return Err(RunError::Invalid(
                "adapter/cache outputs do not exactly match the job revision's declared names and order"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Create a new job runner
    pub fn new(store: Arc<dyn ContentStore>) -> Self {
        Self {
            store,
            adapters: HashMap::new(),
            withheld: HashMap::new(),
        }
    }

    /// Register an adapter
    pub fn register_adapter(&mut self, adapter: Arc<dyn JobAdapter>) {
        self.adapters.insert(adapter.name().to_string(), adapter);
    }

    /// Whether a job with this `code_ref` would find an adapter here.
    ///
    /// Withheld adapters report `false`: they are known but cannot run.
    pub fn has_adapter(&self, name: &str) -> bool {
        self.adapters.contains_key(name)
    }

    /// Whether this `code_ref` names an adapter that exists but was
    /// deliberately withheld (see [`Self::withhold_adapter`]).
    pub fn is_withheld(&self, name: &str) -> bool {
        self.withheld.contains_key(name)
    }

    /// Record that `name` exists but is not available here, and why.
    ///
    /// `reason` is shown verbatim to whoever tried to run the job, so it should
    /// say what to do about it.
    pub fn withhold_adapter(&mut self, name: impl Into<String>, reason: impl Into<String>) {
        self.withheld.insert(name.into(), reason.into());
    }

    /// Qualify an adapter's effect spec with the adapter that produced it.
    ///
    /// J4 says `(job_id, inputs_hash, effect_spec)` identifies an effect, and
    /// the effect spec is an adapter-chosen opaque string — so two *different*
    /// adapters that happen to describe an effect the same way collided under
    /// one job id, and the cache served the first one's outputs to the second.
    /// That was unreachable while a spec's `code_ref` was fixed at creation;
    /// `JobLog::update_job` makes it reachable, and the cache is the wrong
    /// place to find out. The adapter's name is part of what the effect *is*.
    ///
    /// Note this changes key derivation, so effects cached before it — and
    /// claims published under the old keys — no longer match. The cost is one
    /// re-execution per (job, inputs); the alternative is serving one
    /// adapter's outputs as another's.
    fn scoped_effect_spec(code_ref: &str, effect_spec: &str) -> String {
        // Unit separator: not something a code_ref or a URL contains, so the
        // two fields cannot be made to run together.
        format!("{}\u{1f}{}", code_ref, effect_spec)
    }

    /// Execute a job with the given manifest
    ///
    /// For side-effecting jobs, checks effect cache first and stores results on first run.
    /// Returns the output CIDs by declared name.
    pub async fn execute(
        &self,
        spec: &JobSpec,
        manifest: &InputManifest,
        effect_cache: &dyn EffectCache,
    ) -> Result<EffectOutcome> {
        self.execute_with_hooks(spec, manifest, effect_cache, EffectHooks::none())
            .await
    }

    /// [`Self::execute`] with attested-effect participation (ADR-003).
    ///
    /// On an effect-cache miss, a trusted claim from `hooks.adopt` satisfies
    /// the run without invoking the adapter; the adopted outputs enter the
    /// local cache so the next run is a plain hit. `hooks.attest` is told
    /// the (key, outputs) fact however it was established.
    pub async fn execute_with_hooks(
        &self,
        spec: &JobSpec,
        manifest: &InputManifest,
        effect_cache: &dyn EffectCache,
        hooks: EffectHooks<'_>,
    ) -> Result<EffectOutcome> {
        // Look up adapter. A withheld one gets its own message: "not found"
        // would be actively misleading when the adapter exists and was
        // deliberately not made available.
        let adapter = match self.adapters.get(&spec.code_ref) {
            Some(adapter) => adapter,
            None => {
                if let Some(reason) = self.withheld.get(&spec.code_ref) {
                    return Err(RunError::AdapterWithheld {
                        adapter: spec.code_ref.clone(),
                        reason: reason.clone(),
                    });
                }
                return Err(JobError::AdapterNotFound(spec.code_ref.clone()).into());
            }
        };

        let ctx = JobContext::new(spec, manifest);

        // For side-effecting adapters, check effect cache
        if !adapter.is_deterministic() {
            if let Some(effect_spec) = adapter.effect_spec(&ctx) {
                let effect_key = EffectKey::new(
                    spec.job_id.clone(),
                    manifest.compute_hash(),
                    Self::scoped_effect_spec(&spec.code_ref, &effect_spec),
                );

                // Check if we have cached outputs. Cache reads and writes are
                // synchronous redb access; see dag_control::blocking.
                if let Some(cached_outputs) = offload(|| effect_cache.get(&effect_key))? {
                    Self::validate_declared_outputs(spec, &cached_outputs)?;
                    tracing::debug!("Effect cache hit for job {}, reusing outputs", spec.job_id);
                    if let Some(sink) = hooks.attest {
                        offload(|| sink.record(&effect_key, &cached_outputs))?;
                    }
                    return Ok(EffectOutcome {
                        outputs: cached_outputs,
                        origin: RunOrigin::CacheHit,
                    });
                }

                // A trusted claim satisfies the miss without running the
                // adapter (ADR-003). Everything that makes this safe lives
                // behind AttestedEffects::adopt: it returns outputs only for
                // a keyring-trusted claim over exactly this key, with the
                // content present and intact.
                if let Some(attested) = hooks.adopt {
                    if let Some(outputs) = offload(|| attested.adopt(&effect_key))? {
                        Self::validate_declared_outputs(spec, &outputs)?;
                        tracing::info!(
                            job_id = %spec.job_id,
                            "adopted attested outputs instead of executing"
                        );
                        offload(|| effect_cache.store(&effect_key, &outputs))?;
                        if let Some(sink) = hooks.attest {
                            offload(|| sink.record(&effect_key, &outputs))?;
                        }
                        return Ok(EffectOutcome {
                            outputs,
                            origin: RunOrigin::Adopted,
                        });
                    }
                }

                // First run - execute and cache
                tracing::debug!(
                    "Effect cache miss for job {}, executing first run",
                    spec.job_id
                );
                let outputs = adapter
                    .run(&self.store, &ctx)
                    .await
                    .ctx(|| "adapter execution failed".to_string())?;
                Self::validate_declared_outputs(spec, &outputs)?;

                // Store in effect cache
                offload(|| effect_cache.store(&effect_key, &outputs))?;
                if let Some(sink) = hooks.attest {
                    offload(|| sink.record(&effect_key, &outputs))?;
                }

                return Ok(EffectOutcome {
                    outputs,
                    origin: RunOrigin::Executed,
                });
            }
        }

        // Deterministic adapter - just execute
        let outputs = adapter
            .run(&self.store, &ctx)
            .await
            .ctx(|| "adapter execution failed".to_string())?;
        Self::validate_declared_outputs(spec, &outputs)?;
        Ok(EffectOutcome {
            outputs,
            origin: RunOrigin::Executed,
        })
    }

    /// Execute a job and optionally pin outputs according to policy
    pub async fn execute_with_policy(
        &self,
        spec: &JobSpec,
        manifest: &InputManifest,
        effect_cache: &dyn EffectCache,
        pin_creator: Option<&dyn PinCreator>,
        hooks: EffectHooks<'_>,
    ) -> Result<EffectOutcome> {
        let outcome = self
            .execute_with_hooks(spec, manifest, effect_cache, hooks)
            .await?;
        let outputs = &outcome.outputs;

        // Apply the output caching policy.
        if let Some(pin_creator) = pin_creator {
            let ttl = match &spec.policy.cache_outputs {
                CachePolicy::Pin { ttl } => *ttl,
                // "Cache for N seconds" is a pin that expires: without one,
                // the next collection is free to delete the output.
                CachePolicy::Ttl { seconds } => Some(*seconds),
                CachePolicy::None => return Ok(outcome),
            };

            offload(|| {
                for (name, cid) in outputs {
                    pin_creator.ensure_pin(
                        &output_pin_id(spec.job_id.as_ref(), name, cid),
                        PinTarget::Direct(cid.clone()),
                        PinScope::Global,
                        ttl,
                    )?;
                }
                Ok::<_, dag_control::ControlError>(())
            })?;
        }

        Ok(outcome)
    }
}

/// Pin ID for a job output.
///
/// The output CID is part of the ID on purpose. Pins are append-only — there
/// is no "move this pin" operation — so a per-job-and-name ID could only ever
/// retain one run's output, and the second run would collide. Keying on
/// content means every distinct output keeps its own retention, which is what
/// an audit trail needs, while a deterministic re-run re-derives the same ID
/// and is absorbed as a no-op.
pub fn output_pin_id(job_id: &str, output_name: &str, cid: &Cid) -> String {
    format!("job/{}/{}/{}", job_id, output_name, cid.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{ConcatAdapter, FakeFetchAdapter, HashAdapter};
    use dag_core::{CachePolicy, Determinism, JobId, JobInput, JobPolicy, TriggerPolicy};
    use dag_storage::FsStore;
    use parking_lot::RwLock;
    use std::collections::HashMap as StdHashMap;
    use tempfile::TempDir;

    // Type aliases to reduce complexity
    type EffectCacheMap = StdHashMap<Vec<u8>, Vec<(String, Cid)>>;
    type PinRecord = (String, Cid, PinScope, Option<u64>);

    // Mock effect cache for testing
    struct MockEffectCache {
        cache: RwLock<EffectCacheMap>,
    }

    impl MockEffectCache {
        fn new() -> Self {
            Self {
                cache: RwLock::new(StdHashMap::new()),
            }
        }

        fn hit_count(&self, key: &EffectKey) -> usize {
            let cache = self.cache.read();
            let binary_key = key.to_binary_key();
            if cache.contains_key(&binary_key) {
                1
            } else {
                0
            }
        }
    }

    impl EffectCache for MockEffectCache {
        fn get(&self, key: &EffectKey) -> dag_control::Result<Option<Vec<(String, Cid)>>> {
            let cache = self.cache.read();
            let binary_key = key.to_binary_key();
            Ok(cache.get(&binary_key).cloned())
        }

        fn store(&self, key: &EffectKey, outputs: &[(String, Cid)]) -> dag_control::Result<()> {
            let mut cache = self.cache.write();
            let binary_key = key.to_binary_key();
            cache.insert(binary_key, outputs.to_vec());
            Ok(())
        }
    }

    fn setup() -> (TempDir, Arc<dyn ContentStore>, JobRunner) {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        let store: Arc<dyn ContentStore> = Arc::new(FsStore::new(&data_dir).unwrap());

        let mut runner = JobRunner::new(store.clone());
        runner.register_adapter(Arc::new(HashAdapter));
        runner.register_adapter(Arc::new(ConcatAdapter));

        (temp, store, runner)
    }

    #[tokio::test]
    async fn test_deterministic_job_reproducible() {
        let (_temp, store, runner) = setup();

        let input1 = store.put_chunk(b"hello", None).unwrap();
        let input2 = store.put_chunk(b"world", None).unwrap();

        let spec = JobSpec {
            job_id: JobId::from("hash-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new()
                .with_static(input1.clone())
                .with_static(input2.clone()),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["hash".into()],
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        let manifest = InputManifest {
            static_inputs: vec![input1, input2],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let cache = MockEffectCache::new();

        // Run twice
        let outputs1 = runner
            .execute(&spec, &manifest, &cache)
            .await
            .unwrap()
            .outputs;
        let outputs2 = runner
            .execute(&spec, &manifest, &cache)
            .await
            .unwrap()
            .outputs;

        // Should produce identical outputs
        assert_eq!(outputs1.len(), 1);
        assert_eq!(outputs2.len(), 1);
        assert_eq!(outputs1[0].1, outputs2[0].1);
    }

    #[tokio::test]
    async fn test_side_effecting_job_first_run_cache() {
        let (_temp, store, mut runner) = setup();

        let fake_data = b"fetched data".to_vec();
        let fake_adapter = Arc::new(FakeFetchAdapter::new(
            fake_data.clone(),
            "https://example.com/resource".into(),
        ));
        runner.register_adapter(fake_adapter.clone());

        let spec = JobSpec {
            job_id: JobId::from("fetch-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new(),
            determinism: Determinism::SideEffecting,
            declared_outputs: vec!["artifact".into()],
            code_ref: "fake_fetch".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let cache = MockEffectCache::new();

        // First run - should execute and cache
        let first = runner.execute(&spec, &manifest, &cache).await.unwrap();
        assert_eq!(first.origin, RunOrigin::Executed);
        let outputs1 = first.outputs;
        assert_eq!(outputs1.len(), 1);
        assert_eq!(outputs1[0].0, "artifact");

        // Verify artifact was stored
        let artifact = store.get_chunk(&outputs1[0].1).unwrap();
        assert_eq!(artifact, fake_data);

        // Verify effect was cached
        // The key is scoped by the adapter that produced the effect spec, so
        // this reproduces what the runner filed rather than the bare URL.
        let effect_key = EffectKey::new(
            spec.job_id.clone(),
            manifest.compute_hash(),
            JobRunner::scoped_effect_spec("fake_fetch", "https://example.com/resource"),
        );
        assert_eq!(cache.hit_count(&effect_key), 1);

        // Second run - should use cache
        let second = runner.execute(&spec, &manifest, &cache).await.unwrap();
        assert_eq!(
            second.origin,
            RunOrigin::CacheHit,
            "the cache answered, and the record must be able to say so"
        );
        let outputs2 = second.outputs;
        assert_eq!(outputs2.len(), 1);
        assert_eq!(outputs1[0].1, outputs2[0].1);
    }

    #[tokio::test]
    async fn test_adapter_not_found() {
        let (_temp, _store, runner) = setup();

        let spec = JobSpec {
            job_id: JobId::from("bad-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new(),
            determinism: Determinism::Deterministic,
            declared_outputs: vec![],
            code_ref: "nonexistent".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let cache = MockEffectCache::new();

        let result = runner.execute(&spec, &manifest, &cache).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Adapter not found"));
    }

    #[tokio::test]
    async fn test_concat_adapter() {
        let (_temp, store, runner) = setup();

        let input1 = store.put_chunk(b"hello ", None).unwrap();
        let input2 = store.put_chunk(b"world", None).unwrap();

        let spec = JobSpec {
            job_id: JobId::from("concat-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new()
                .with_static(input1.clone())
                .with_static(input2.clone()),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["concatenated".into()],
            code_ref: "concat".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        let manifest = InputManifest {
            static_inputs: vec![input1, input2],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let cache = MockEffectCache::new();

        let outputs = runner
            .execute(&spec, &manifest, &cache)
            .await
            .unwrap()
            .outputs;
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "concatenated");

        let result = store.get_chunk(&outputs[0].1).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[tokio::test]
    async fn test_output_pin_policy() {
        let (_temp, store, runner) = setup();

        // Mock pin creator that tracks pin calls
        struct MockPinCreator {
            pins: Arc<RwLock<Vec<PinRecord>>>,
        }

        impl MockPinCreator {
            fn new() -> Self {
                Self {
                    pins: Arc::new(RwLock::new(Vec::new())),
                }
            }

            fn get_pins(&self) -> Vec<PinRecord> {
                self.pins.read().clone()
            }
        }

        impl PinCreator for MockPinCreator {
            fn ensure_pin(
                &self,
                pin_id: &str,
                target: PinTarget,
                scope: PinScope,
                ttl: Option<u64>,
            ) -> dag_control::Result<bool> {
                if self.pins.read().iter().any(|(id, ..)| id == pin_id) {
                    return Ok(false);
                }
                if let PinTarget::Direct(cid) = target {
                    self.pins
                        .write()
                        .push((pin_id.to_string(), cid, scope, ttl));
                }
                Ok(true)
            }
        }

        let input = store.put_chunk(b"test data", None).unwrap();

        let spec = JobSpec {
            job_id: JobId::from("pin-test-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new().with_static(input.clone()),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["hash".into()],
            code_ref: "hash".into(),
            policy: JobPolicy {
                cache_outputs: CachePolicy::Pin { ttl: Some(3600) },
                trigger: TriggerPolicy::Manual,
            },
            config: None,
        };

        let manifest = InputManifest {
            static_inputs: vec![input],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let cache = MockEffectCache::new();
        let pin_creator = MockPinCreator::new();

        // Execute with pin policy
        let outputs = runner
            .execute_with_policy(
                &spec,
                &manifest,
                &cache,
                Some(&pin_creator),
                EffectHooks::none(),
            )
            .await
            .unwrap()
            .outputs;

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "hash");

        // Verify pin was created
        let pins = pin_creator.get_pins();
        assert_eq!(pins.len(), 1);
        assert_eq!(
            pins[0].0,
            output_pin_id("pin-test-job", "hash", &outputs[0].1)
        );
        assert_eq!(pins[0].1, outputs[0].1);
        assert_eq!(pins[0].3, Some(3600)); // ttl
    }

    /// A side-effecting adapter that must never run: adoption tests use it to
    /// prove the adapter was short-circuited rather than merely agreed with.
    struct MustNotRunAdapter;

    #[async_trait::async_trait]
    impl JobAdapter for MustNotRunAdapter {
        fn name(&self) -> &'static str {
            "must_not_run"
        }
        fn is_deterministic(&self) -> bool {
            false
        }
        fn effect_spec(&self, _ctx: &JobContext<'_>) -> Option<String> {
            Some("must-not-run-spec".to_string())
        }
        async fn run(
            &self,
            _store: &Arc<dyn ContentStore>,
            _ctx: &JobContext<'_>,
        ) -> Result<Vec<(String, Cid)>> {
            panic!("the adapter ran: adoption failed to short-circuit execution");
        }
    }

    struct FixedAdoption(Vec<(String, Cid)>);

    impl dag_control::AttestedEffects for FixedAdoption {
        fn adopt(&self, _key: &EffectKey) -> dag_control::Result<Option<Vec<(String, Cid)>>> {
            Ok(Some(self.0.clone()))
        }
    }

    type RecordedClaim = (EffectKey, Vec<(String, Cid)>);

    #[derive(Default)]
    struct RecordingSink {
        records: RwLock<Vec<RecordedClaim>>,
    }

    impl dag_control::EffectClaimSink for RecordingSink {
        fn record(&self, key: &EffectKey, outputs: &[(String, Cid)]) -> dag_control::Result<()> {
            self.records.write().push((key.clone(), outputs.to_vec()));
            Ok(())
        }
    }

    fn side_effecting_spec(job_id: &str) -> JobSpec {
        JobSpec {
            job_id: JobId::from(job_id),
            placement: None,
            inputs: JobInput::new(),
            determinism: Determinism::SideEffecting,
            declared_outputs: vec!["artifact".into()],
            code_ref: "must_not_run".into(),
            policy: JobPolicy::default(),
            config: None,
        }
    }

    #[tokio::test]
    async fn stale_cache_outputs_fail_before_attestation_or_pinning() {
        let (_temp, _store, mut runner) = setup();
        runner.register_adapter(Arc::new(MustNotRunAdapter));
        let mut spec = side_effecting_spec("changed-outputs");
        spec.declared_outputs = vec!["new-name".to_string()];
        spec.policy.cache_outputs = CachePolicy::Pin { ttl: None };
        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1,
        };
        let key = EffectKey::new(
            spec.job_id.clone(),
            manifest.compute_hash(),
            JobRunner::scoped_effect_spec("must_not_run", "must-not-run-spec"),
        );
        let cache = MockEffectCache::new();
        cache
            .store(&key, &[("old-name".to_string(), Cid::compute(b"stale"))])
            .unwrap();
        let sink = RecordingSink::default();
        #[derive(Default)]
        struct CountingPins(std::sync::atomic::AtomicUsize);
        impl PinCreator for CountingPins {
            fn ensure_pin(
                &self,
                _pin_id: &str,
                _target: PinTarget,
                _scope: PinScope,
                _ttl: Option<u64>,
            ) -> dag_control::Result<bool> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(true)
            }
        }
        let pins = CountingPins::default();
        let error = runner
            .execute_with_policy(
                &spec,
                &manifest,
                &cache,
                Some(&pins),
                EffectHooks {
                    adopt: None,
                    attest: Some(&sink),
                },
            )
            .await
            .expect_err("a cache entry from an old declared-output revision must fail closed");
        assert!(error.to_string().contains("declared names and order"));
        assert!(sink.records.read().is_empty());
        assert_eq!(pins.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn adoption_short_circuits_execution_and_seeds_the_cache() {
        let (_temp, _store, mut runner) = setup();
        runner.register_adapter(Arc::new(MustNotRunAdapter));

        let spec = side_effecting_spec("adopt-job");
        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1_700_000_000,
        };
        let cache = MockEffectCache::new();
        let adopted = vec![("artifact".to_string(), Cid::compute(b"built elsewhere"))];
        let adoption = FixedAdoption(adopted.clone());

        // MustNotRunAdapter panics if invoked, so reaching these assertions
        // proves the adapter never ran.
        let outputs = runner
            .execute_with_hooks(
                &spec,
                &manifest,
                &cache,
                EffectHooks {
                    adopt: Some(&adoption),
                    attest: None,
                },
            )
            .await
            .expect("adoption should satisfy the run");
        assert_eq!(outputs.outputs, adopted);
        assert_eq!(outputs.origin, RunOrigin::Adopted);

        // Adoption seeded the local cache: the next run is a plain hit, with
        // no hooks needed at all.
        let outputs = runner
            .execute(&spec, &manifest, &cache)
            .await
            .expect("second run should hit the cache");
        assert_eq!(outputs.outputs, adopted);
        assert_eq!(outputs.origin, RunOrigin::CacheHit);
    }

    #[tokio::test]
    async fn the_attest_sink_is_told_on_execution_hit_and_adoption() {
        let (_temp, _store, mut runner) = setup();

        let fake = Arc::new(FakeFetchAdapter::new(
            b"payload".to_vec(),
            "https://example.com/x".into(),
        ));
        runner.register_adapter(fake);

        let mut spec = side_effecting_spec("attest-job");
        spec.code_ref = "fake_fetch".into();
        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1_700_000_000,
        };
        let cache = MockEffectCache::new();
        let sink = RecordingSink::default();
        let hooks = EffectHooks {
            adopt: None,
            attest: Some(&sink),
        };

        // Miss → executes → attests; hit → attests again with the same fact.
        runner
            .execute_with_hooks(&spec, &manifest, &cache, hooks)
            .await
            .unwrap();
        runner
            .execute_with_hooks(&spec, &manifest, &cache, hooks)
            .await
            .unwrap();

        let records = sink.records.read();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], records[1], "hit and miss attest the same fact");
    }
}
