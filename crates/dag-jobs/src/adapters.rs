//! Job adapters (deterministic + side-effecting).
//! Intent: tiny, testable units. No logging/DB here; just pure(ish) transforms.

use std::sync::Arc;

use crate::error::RunError;
use crate::Result;
use async_trait::async_trait;
use dag_core::{Cid, ContentStore, Entry, InputManifest, JobSpec, MAX_CHUNK_SIZE};
use sha2::{Digest, Sha256};

/// Maximum input bytes one built-in adapter invocation will read.
///
/// A chunk is individually bounded, but a manifest can name many chunks. A
/// per-run aggregate limit prevents a valid job spec from turning `hash` (or
/// a future adapter using the same helper) into an unbounded disk/CPU job.
pub const MAX_ADAPTER_INPUT_BYTES: usize = 64 * 1024 * 1024;

fn account_input_bytes(total: &mut usize, next: usize, limit: usize, adapter: &str) -> Result<()> {
    let updated = total
        .checked_add(next)
        .ok_or_else(|| RunError::Invalid(format!("{adapter} input byte count overflowed")))?;
    if updated > limit {
        return Err(RunError::Invalid(format!(
            "{adapter} inputs total {updated} bytes; the limit is {limit}"
        )));
    }
    *total = updated;
    Ok(())
}

/// Determinism classification
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Determinism {
    Deterministic,
    SideEffecting,
}

/// Everything an adapter is told about the run it is performing.
///
/// Adapters receive the whole spec, not just the manifest, because an
/// adapter's behaviour can be parameterised per job — which command to run,
/// which URL to fetch — and that configuration belongs in the spec where the
/// job log records it. Passing the spec also means an adapter's effect key can
/// cover its configuration, so changing the command invalidates the cache.
pub struct JobContext<'a> {
    /// The job being run, including [`JobSpec::config`].
    pub spec: &'a JobSpec,
    /// The inputs resolved for this run.
    pub manifest: &'a InputManifest,
}

impl<'a> JobContext<'a> {
    pub fn new(spec: &'a JobSpec, manifest: &'a InputManifest) -> Self {
        Self { spec, manifest }
    }

    /// This job's adapter configuration, or `null` when unset.
    pub fn config(&self) -> &serde_json::Value {
        const NULL: &serde_json::Value = &serde_json::Value::Null;
        self.spec.config.as_ref().unwrap_or(NULL)
    }

    /// Deserialize the adapter configuration, naming the adapter on failure.
    pub fn parse_config<T: serde::de::DeserializeOwned>(&self, adapter: &str) -> Result<T> {
        let config = self
            .spec
            .config
            .clone()
            .ok_or_else(|| RunError::ConfigMissing {
                job: self.spec.job_id.to_string(),
                adapter: adapter.to_string(),
            })?;
        serde_json::from_value(config).map_err(|e| RunError::ConfigInvalid {
            adapter: adapter.to_string(),
            job: self.spec.job_id.to_string(),
            message: e.to_string(),
        })
    }
}

#[async_trait]
pub trait JobAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_deterministic(&self) -> bool;

    /// Side-effecting adapters should return a stable, deterministic spec string
    /// (e.g., canonical JSON of `{command, args, env}`) that becomes part of the
    /// EffectKey. Anything that changes the effect must appear here, or a
    /// changed job will serve a stale cached result.
    fn effect_spec(&self, _ctx: &JobContext<'_>) -> Option<String> {
        None
    }

    /// Execute adapter against a context.
    /// - Deterministic adapters MUST return identical outputs for identical contexts.
    /// - Side-effecting adapters SHOULD read effect_spec() and behave deterministically
    ///   given the same spec + manifest; first-run caching is handled by the runner.
    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>>;
}

// -------------------- Built-in deterministic adapters --------------------

pub struct HashAdapter;

#[async_trait]
impl JobAdapter for HashAdapter {
    fn name(&self) -> &'static str {
        "hash"
    }

    fn is_deterministic(&self) -> bool {
        true
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>> {
        let manifest = ctx.manifest;
        // Feed the digest incrementally. The previous implementation first
        // concatenated every input into one Vec, doubling peak memory for an
        // operation whose output is only 32 bytes.
        let mut hasher = Sha256::new();
        let mut total = 0usize;
        for input_cid in manifest.flattened() {
            let chunk = store.get_chunk(&input_cid)?;
            account_input_bytes(
                &mut total,
                chunk.len(),
                MAX_ADAPTER_INPUT_BYTES,
                self.name(),
            )?;
            hasher.update(&chunk);
        }

        // Compute hash of combined inputs
        let digest: [u8; 32] = hasher.finalize().into();
        let hash_cid = Cid::from_bytes(&digest)
            .map_err(|error| RunError::Invalid(format!("hash digest was not a CID: {error}")))?;

        // Create an entry containing the hash and metadata
        let hash_hex = hash_cid.to_hex();
        let entry = Entry::with_payload(hash_hex.as_bytes().to_vec());

        // Store the entry
        let output_cid = store.put_entry(&entry)?;

        Ok(vec![("hash".to_string(), output_cid)])
    }
}

pub struct ConcatAdapter;

#[async_trait]
impl JobAdapter for ConcatAdapter {
    fn name(&self) -> &'static str {
        "concat"
    }

    fn is_deterministic(&self) -> bool {
        true
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>> {
        let manifest = ctx.manifest;
        // `concat` produces one plain chunk, so refuse before allocation as
        // soon as the result would exceed the storage invariant.
        let mut combined = Vec::new();
        let mut total = 0usize;
        for input_cid in manifest.flattened() {
            let chunk = store.get_chunk(&input_cid)?;
            account_input_bytes(&mut total, chunk.len(), MAX_CHUNK_SIZE, self.name())?;
            combined.try_reserve(chunk.len()).map_err(|_| {
                RunError::Invalid("concat could not reserve its bounded output buffer".into())
            })?;
            combined.extend_from_slice(&chunk);
        }

        // Store concatenated result
        let output_cid = store.put_chunk(&combined, None)?;

        Ok(vec![("concatenated".to_string(), output_cid)])
    }
}

pub struct EchoAdapter {
    pub message: String,
}

impl EchoAdapter {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

#[async_trait]
impl JobAdapter for EchoAdapter {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn is_deterministic(&self) -> bool {
        true
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        _ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>> {
        let output_cid = store.put_chunk(self.message.as_bytes(), None)?;
        Ok(vec![("message".to_string(), output_cid)])
    }
}

/// Builds a provenance attestation: a JSON payload describing exactly which
/// inputs were resolved, published as an [`Entry`] that *links* every one of
/// them.
///
/// The links are the point. The payload is human-readable metadata, but the
/// link set is what makes the attestation traversable — and what a subtree pin
/// grabs hold of, so pinning the attestation transitively retains every input
/// it vouches for.
///
/// Deterministic: the same manifest always yields byte-identical output, and
/// therefore the same CID.
pub struct AttestAdapter;

#[async_trait]
impl JobAdapter for AttestAdapter {
    fn name(&self) -> &'static str {
        "attest"
    }

    fn is_deterministic(&self) -> bool {
        true
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>> {
        let manifest = ctx.manifest;
        use dag_core::{Link, MetaHint};

        let mut links = Vec::new();
        let mut static_inputs = Vec::new();
        for (i, cid) in manifest.static_inputs.iter().enumerate() {
            links.push(Link::named(cid.clone(), format!("input/{}", i)));
            static_inputs.push(cid.to_hex());
        }

        let mut pointer_inputs = Vec::new();
        for resolved in &manifest.pointer_heads {
            links.push(Link::named(
                resolved.head_cid.clone(),
                resolved.pointer_id.clone(),
            ));
            pointer_inputs.push(serde_json::json!({
                "pointer_id": resolved.pointer_id,
                "seq": resolved.log_seq,
                "cid": resolved.head_cid.to_hex(),
            }));
        }

        // Deliberately no timestamp. An attestation records *what* was read,
        // not when — the when is already in the run record and the event
        // journal. Leaving time out makes the attestation a pure function of
        // its inputs, so re-attesting unchanged inputs yields the same CID
        // instead of a fresh near-duplicate every run.
        //
        // Field order is fixed by the literal and serde_json preserves
        // insertion order, so the encoding is stable across runs.
        let payload = serde_json::json!({
            "kind": "attestation/v1",
            "inputs_digest": inputs_digest(manifest).to_hex(),
            "static_inputs": static_inputs,
            "pointer_inputs": pointer_inputs,
        });

        let entry = Entry::new(
            serde_json::to_vec(&payload)?,
            links,
            Some(MetaHint {
                content_type: Some("application/json".to_string()),
                encoding: None,
            }),
        );

        Ok(vec![("attestation".to_string(), store.put_entry(&entry)?)])
    }
}

/// Digest over what a manifest resolved, excluding when it resolved.
///
/// [`InputManifest::compute_hash`] now has the same time-free semantics, but
/// this digest's byte encoding is part of the `attestation/v1` payload
/// format, so it stays independent: re-attesting the same inputs must keep
/// producing the same CID across releases.
fn inputs_digest(manifest: &InputManifest) -> Cid {
    let mut buf = Vec::new();
    for cid in &manifest.static_inputs {
        buf.extend_from_slice(cid.as_bytes());
    }
    for resolved in &manifest.pointer_heads {
        buf.extend_from_slice(resolved.pointer_id.as_bytes());
        buf.extend_from_slice(&resolved.log_seq.to_be_bytes());
        buf.extend_from_slice(resolved.head_cid.as_bytes());
    }
    Cid::compute(&buf)
}

// -------------------- Side-effecting test double --------------------

/// The bytes [`crate::default_runner`]'s `fake_fetch` registration emits.
///
/// Self-describing on purpose. The previous payload was `b"fake data"`, which
/// told an operator following the shipped example nothing about *why* their
/// artifact was not the web page they asked for.
pub const SIMULATED_FETCH_PAYLOAD: &[u8] =
    b"SIMULATED OUTPUT. The `fake_fetch` adapter is a test double: it performs \
      no network request and returns these fixed bytes. This system ships no \
      HTTP fetcher; to fetch a URL, run one via the `exec` adapter.\n";

/// The effect-key discriminator [`crate::default_runner`]'s `fake_fetch`
/// registration uses. Reserved by RFC 2606 precisely so it resolves to
/// nothing anyone owns — and nothing here resolves it in any case.
pub const SIMULATED_FETCH_URL: &str = "https://example.com/data";

/// **A test double, not a fetcher.** Returns fixed bytes and performs no I/O
/// of any kind — the `url` is only an effect-key discriminator.
///
/// It exists so the side-effecting half of the runner (first-run effect
/// caching, J2/J8) can be exercised hermetically: a real network adapter would
/// make those tests non-deterministic and require a network in CI. It is
/// registered in [`crate::default_runner`] so those paths are reachable from
/// the CLI and the API without a build flag, and both `dag job adapters` and
/// `GET /api/adapters` report it as `simulated` so it is never mistaken for
/// the real thing.
///
/// There is deliberately no HTTP adapter in this workspace. Fetching a URL is
/// a job for `exec`, where the capability gate applies.
pub struct FakeFetchAdapter {
    /// The fixed bytes this instance returns. No request is made to obtain them.
    pub data: Vec<u8>,
    /// Effect-key discriminator only. Never dereferenced.
    pub url: String,
}

impl FakeFetchAdapter {
    /// A double returning `data`, keyed by `url`. `url` is never dereferenced.
    pub fn new(data: Vec<u8>, url: String) -> Self {
        Self { data, url }
    }
}

#[async_trait]
impl JobAdapter for FakeFetchAdapter {
    fn name(&self) -> &'static str {
        "fake_fetch"
    }

    fn is_deterministic(&self) -> bool {
        false
    }

    fn effect_spec(&self, _ctx: &JobContext<'_>) -> Option<String> {
        // Discriminates one double from another in the effect cache. Nothing
        // resolves it.
        Some(self.url.clone())
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        _ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>> {
        // No request happens here, by design: store the fixed bytes.
        let artifact_cid = store.put_chunk(&self.data, None)?;
        Ok(vec![("artifact".to_string(), artifact_cid)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_storage::FsStore;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Arc<dyn ContentStore>) {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        let store: Arc<dyn ContentStore> = Arc::new(FsStore::new(&data_dir).unwrap());
        (temp, store)
    }

    /// A minimal spec for adapters that ignore everything but the manifest.
    pub(crate) fn bare_spec(code_ref: &str) -> JobSpec {
        JobSpec {
            job_id: dag_core::JobId::from("test-job"),
            placement: None,
            inputs: dag_core::JobInput::new(),
            determinism: dag_core::Determinism::Deterministic,
            declared_outputs: vec![],
            code_ref: code_ref.to_string(),
            policy: dag_core::JobPolicy::default(),
            config: None,
        }
    }

    #[tokio::test]
    async fn test_hash_adapter_deterministic() {
        let (_temp, store) = setup();

        let input1 = b"hello world";
        let input2 = b"foo bar";

        let cid1 = store.put_chunk(input1, None).unwrap();
        let cid2 = store.put_chunk(input2, None).unwrap();

        let manifest = InputManifest {
            static_inputs: vec![cid1, cid2],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let adapter = HashAdapter;
        let spec = bare_spec("hash");

        // Run twice
        let outputs1 = adapter
            .run(&store, &JobContext::new(&spec, &manifest))
            .await
            .unwrap();
        let outputs2 = adapter
            .run(&store, &JobContext::new(&spec, &manifest))
            .await
            .unwrap();

        // Should produce identical outputs
        assert_eq!(outputs1.len(), 1);
        assert_eq!(outputs2.len(), 1);
        assert_eq!(outputs1[0].0, "hash");
        assert_eq!(outputs1[0].1, outputs2[0].1);
    }

    #[tokio::test]
    async fn test_concat_adapter() {
        let (_temp, store) = setup();

        let input1 = b"hello ";
        let input2 = b"world";

        let cid1 = store.put_chunk(input1, None).unwrap();
        let cid2 = store.put_chunk(input2, None).unwrap();

        let manifest = InputManifest {
            static_inputs: vec![cid1, cid2],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let adapter = ConcatAdapter;
        let spec = bare_spec("concat");
        let outputs = adapter
            .run(&store, &JobContext::new(&spec, &manifest))
            .await
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "concatenated");

        // Verify concatenated content
        let result = store.get_chunk(&outputs[0].1).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn aggregate_input_accounting_is_checked_and_hard_bounded() {
        let mut total = MAX_ADAPTER_INPUT_BYTES - 1;
        account_input_bytes(&mut total, 1, MAX_ADAPTER_INPUT_BYTES, "hash").unwrap();
        assert_eq!(total, MAX_ADAPTER_INPUT_BYTES);

        let error =
            account_input_bytes(&mut total, 1, MAX_ADAPTER_INPUT_BYTES, "hash").unwrap_err();
        assert!(error.to_string().contains("the limit is"));
        assert_eq!(
            total, MAX_ADAPTER_INPUT_BYTES,
            "refusal must not mutate the total"
        );

        let mut total = usize::MAX;
        let error = account_input_bytes(&mut total, 1, usize::MAX, "hash").unwrap_err();
        assert!(error.to_string().contains("overflowed"));
    }

    #[tokio::test]
    async fn concat_refuses_an_output_larger_than_one_chunk() {
        let (_temp, store) = setup();
        let first = store
            .put_chunk(&vec![b'a'; MAX_CHUNK_SIZE / 2 + 1], None)
            .unwrap();
        let second = store
            .put_chunk(&vec![b'b'; MAX_CHUNK_SIZE / 2], None)
            .unwrap();
        let manifest = InputManifest {
            static_inputs: vec![first, second],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };
        let adapter = ConcatAdapter;
        let spec = bare_spec("concat");

        let error = adapter
            .run(&store, &JobContext::new(&spec, &manifest))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("the limit is"));
    }

    #[tokio::test]
    async fn test_fake_fetch_adapter() {
        let (_temp, store) = setup();

        let fake_data = b"downloaded content".to_vec();
        let adapter = FakeFetchAdapter::new(fake_data.clone(), "https://example.com/data".into());
        let spec = bare_spec("fake_fetch");

        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let outputs = adapter
            .run(&store, &JobContext::new(&spec, &manifest))
            .await
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "artifact");

        // Verify artifact content
        let artifact = store.get_chunk(&outputs[0].1).unwrap();
        assert_eq!(artifact, fake_data);

        // Verify effect spec
        let effect_spec = adapter.effect_spec(&JobContext::new(&spec, &manifest));
        assert_eq!(effect_spec, Some("https://example.com/data".to_string()));
    }

    #[tokio::test]
    async fn attest_adapter_ignores_resolution_time() {
        let (_temp, store) = setup();

        let input = store.put_chunk(b"dataset", None).unwrap();
        let head = store.put_chunk(b"config", None).unwrap();

        let make = |resolved_at_unix| InputManifest {
            static_inputs: vec![input.clone()],
            pointer_heads: vec![dag_core::ResolvedPointer {
                pointer_id: "configs/x".into(),
                head_cid: head.clone(),
                log_seq: 3,
            }],
            resolved_at_unix,
        };

        let adapter = AttestAdapter;
        let spec = bare_spec("attest");
        let first = adapter
            .run(&store, &JobContext::new(&spec, &make(1_000)))
            .await
            .unwrap();
        let second = adapter
            .run(&store, &JobContext::new(&spec, &make(2_000)))
            .await
            .unwrap();

        // Same inputs, different clocks: the attestation must be identical.
        assert_eq!(first[0].1, second[0].1);

        // And it must link every input, so a subtree pin on the attestation
        // transitively retains everything it vouches for.
        let entry = store.get_entry(&first[0].1).unwrap();
        let targets: Vec<_> = entry.links.iter().map(|l| l.target.clone()).collect();
        assert!(targets.contains(&input));
        assert!(targets.contains(&head));
    }

    #[tokio::test]
    async fn attest_adapter_reflects_changed_inputs() {
        let (_temp, store) = setup();

        let a = store.put_chunk(b"a", None).unwrap();
        let b = store.put_chunk(b"b", None).unwrap();

        let manifest = |cid| InputManifest {
            static_inputs: vec![cid],
            pointer_heads: vec![],
            resolved_at_unix: 1_000,
        };

        let adapter = AttestAdapter;
        let spec = bare_spec("attest");
        let first = adapter
            .run(&store, &JobContext::new(&spec, &manifest(a)))
            .await
            .unwrap();
        let second = adapter
            .run(&store, &JobContext::new(&spec, &manifest(b)))
            .await
            .unwrap();
        assert_ne!(first[0].1, second[0].1);
    }

    #[tokio::test]
    async fn test_echo_adapter() {
        let (_temp, store) = setup();

        let adapter = EchoAdapter::new("Hello, jobs!".into());
        let spec = bare_spec("echo");

        let manifest = InputManifest {
            static_inputs: vec![],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let outputs = adapter
            .run(&store, &JobContext::new(&spec, &manifest))
            .await
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "message");

        let message = store.get_chunk(&outputs[0].1).unwrap();
        assert_eq!(message, b"Hello, jobs!");
    }
}
