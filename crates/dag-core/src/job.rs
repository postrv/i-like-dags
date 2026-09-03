//! Job types for deterministic and side-effecting job execution
//!
//! This module defines the core data structures for the job system (M5),
//! which enables reproducible computation over content-addressed data.

use crate::Cid;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Hard limits for one immutable job definition.
///
/// Job specs are persisted in the control log and later drive filesystem and
/// adapter work.  Keeping these limits in `dag-core` gives every ingress path
/// (CLI, HTTP, recovery and embedders) one contract instead of a collection of
/// handler-specific guesses.
pub const MAX_JOB_STATIC_INPUTS: usize = 256;
pub const MAX_JOB_POINTER_INPUTS: usize = 256;
pub const MAX_JOB_DECLARED_OUTPUTS: usize = 256;
pub const MAX_JOB_PLACEMENT_BYTES: usize = 256;
pub const MAX_JOB_CODE_REF_BYTES: usize = 128;
pub const MAX_JOB_NAME_BYTES: usize = 256;
pub const MAX_JOB_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_JOB_CONFIG_DEPTH: usize = 32;
pub const MAX_JOB_CONFIG_NODES: usize = 8_192;

/// Unique identifier for a job
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for JobId {
    fn from(s: String) -> Self {
        JobId(s)
    }
}

impl From<&str> for JobId {
    fn from(s: &str) -> Self {
        JobId(s.to_string())
    }
}

impl AsRef<str> for JobId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Unique identifier for a job run (u64 for efficient sequential allocation)
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub u64);

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for RunId {
    fn from(n: u64) -> Self {
        RunId(n)
    }
}

/// Determinism classification for jobs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Determinism {
    /// Pure function of inputs - always produces same outputs for same inputs
    Deterministic,
    /// May perform side effects (network, etc) - first-run caching required
    SideEffecting,
}

/// Input specification for a job
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobInput {
    /// Static CID inputs (resolved at job creation time)
    pub static_inputs: Vec<Cid>,
    /// Pointer inputs (resolved at job trigger time)
    pub pointer_inputs: Vec<String>,
}

impl JobInput {
    pub fn new() -> Self {
        Self {
            static_inputs: Vec::new(),
            pointer_inputs: Vec::new(),
        }
    }

    pub fn with_static(mut self, cid: Cid) -> Self {
        self.static_inputs.push(cid);
        self
    }

    pub fn with_pointer(mut self, pointer_id: impl Into<String>) -> Self {
        self.pointer_inputs.push(pointer_id.into());
        self
    }
}

impl Default for JobInput {
    fn default() -> Self {
        Self::new()
    }
}

/// Output caching policy
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CachePolicy {
    /// Don't cache outputs
    #[default]
    None,
    /// Retain outputs until the TTL (in seconds) expires.
    Ttl { seconds: u64 },
    /// Pin outputs, permanently when `ttl` is `None` or until the TTL expires.
    Pin { ttl: Option<u64> },
}

/// Job trigger condition
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerPolicy {
    /// Trigger immediately on job creation
    OnCreate,
    /// Trigger when subscribed pointers update
    OnPointerUpdate,
    /// Manual trigger only
    Manual,
}

/// Job policy configuration
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobPolicy {
    /// Output caching strategy
    pub cache_outputs: CachePolicy,
    /// Trigger condition
    pub trigger: TriggerPolicy,
}

impl Default for JobPolicy {
    fn default() -> Self {
        Self {
            cache_outputs: CachePolicy::None,
            trigger: TriggerPolicy::Manual,
        }
    }
}

/// Complete job specification
///
/// `Eq` is deliberately not derived: [`Self::config`] is arbitrary JSON, and
/// JSON numbers are floats. Nothing keys on a spec, so `PartialEq` suffices.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobSpec {
    /// Unique job identifier
    pub job_id: JobId,
    /// Placement hint (opaque for M5)
    pub placement: Option<String>,
    /// Input specification
    pub inputs: JobInput,
    /// Determinism classification
    pub determinism: Determinism,
    /// Expected output names
    pub declared_outputs: Vec<String>,
    /// Code adapter reference (e.g., "hash", "concat", "fetch")
    pub code_ref: String,
    /// Job policy
    pub policy: JobPolicy,
    /// Adapter-specific configuration, opaque to the core.
    ///
    /// Adapters that need parameters — which command to run, which URL to
    /// fetch — read them from here. It lives in the spec rather than in the
    /// adapter so that a job's behaviour is fully described by its spec:
    /// recorded in the job log, visible in `dag job list`, and part of what a
    /// side-effecting adapter's effect key covers.
    ///
    /// `#[serde(default)]` keeps job specs written before this field existed
    /// readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

/// Resolved pointer with sequence tracking for replay fidelity (I6)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPointer {
    pub pointer_id: String,
    pub head_cid: Cid,
    pub log_seq: u64,
}

/// Snapshot of resolved inputs at trigger time
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputManifest {
    /// Static CID inputs (order preserved from JobInput)
    pub static_inputs: Vec<Cid>,
    /// Resolved pointer heads (order matches pointer_inputs)
    pub pointer_heads: Vec<ResolvedPointer>,
    /// Unix timestamp when resolved
    pub resolved_at_unix: i64,
}

impl InputManifest {
    /// Flatten to ordered CID list: [static_inputs..., pointer_heads[].head_cid...]
    pub fn flattened(&self) -> Vec<Cid> {
        let mut result = self.static_inputs.clone();
        for resolved in &self.pointer_heads {
            result.push(resolved.head_cid.clone());
        }
        result
    }

    /// Compute deterministic hash of this manifest for effect caching:
    /// SHA-256 of canonical CBOR over the static CIDs and the pointer
    /// (id, head CID) pairs.
    ///
    /// `resolved_at_unix` and `log_seq` are deliberately excluded. This hash
    /// keys the effect cache, and an effect is identified by what was
    /// resolved — which bytes, under which names — not by the coordinates of
    /// the resolution. A key covering the instant would miss on any
    /// re-trigger in a later second; one covering the sequence number would
    /// miss when a pointer reverts to bytes that were built before, turning
    /// a revert into a rebuild J2 says is reusable. Both still travel with
    /// the manifest in every run record, where replay (J3) needs them.
    pub fn compute_hash(&self) -> Cid {
        let heads: Vec<(&str, &Cid)> = self
            .pointer_heads
            .iter()
            .map(|r| (r.pointer_id.as_str(), &r.head_cid))
            .collect();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&(&self.static_inputs, &heads), &mut buf)
            .expect("manifest serialization should not fail");
        Cid::compute(&buf)
    }
}

/// Status of a job run
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    /// Run is queued
    Pending,
    /// Run is executing
    Running,
    /// Run completed successfully
    Succeeded,
    /// Run failed with error
    Failed { message: String },
}

/// Record of a job run execution
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRun {
    /// Unique run identifier
    pub run_id: RunId,
    /// Job this run belongs to
    pub job_id: JobId,
    /// Input manifest snapshot
    pub manifest: InputManifest,
    /// Output CIDs by declared name (order preserved)
    pub outputs: Vec<(String, Cid)>,
    /// Run status
    pub status: RunStatus,
    /// Node that executed this run
    pub node_id: Option<String>,
    /// Start timestamp (unix seconds)
    pub started_at_unix: i64,
    /// Completion timestamp (unix seconds)
    pub finished_at_unix: Option<i64>,
    /// How this run's outputs came to be.
    ///
    /// `#[serde(default)]`, so runs recorded before this field existed decode
    /// as [`RunOrigin::Executed`] — which is what they were, since nothing
    /// else was possible then.
    #[serde(default)]
    pub origin: RunOrigin,
    /// Immutable job definition selected when this run was enqueued.
    ///
    /// Runs written before schema 5 decode with `None`, but are never eligible
    /// for execution: there is no safe way to infer which historical spec they
    /// meant after the job head has moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<JobRevision>,
}

/// Event-addressed job definition bound to a run at enqueue time.
///
/// `code_ref` is deliberately denormalised. It drives the durable runnable
/// index, while execution verifies it against the spec carried by
/// `event_cid`; corrupting either side therefore refuses the run rather than
/// dispatching it to the wrong adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRevision {
    /// CID of the filed `Created`/`Updated` job event.
    pub event_cid: Cid,
    /// Sequence at which that CID was filed for this job.
    pub event_seq: u64,
    /// Adapter name copied from the event's immutable spec.
    pub code_ref: String,
}

/// How a run's outputs were established.
///
/// A run record that cannot distinguish these is a provenance record missing
/// the one fact ADR-003 turns on. Adoption is a *trust decision* — this node
/// accepted another node's word, checked against its keyring — and a run that
/// adopted looks otherwise identical to one that did the work: same outputs,
/// same status, same manifest. An auditor asking "did this machine build
/// this, or believe someone who said they had" had nowhere to look.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunOrigin {
    /// The adapter ran here.
    #[default]
    Executed,
    /// The local effect cache already held outputs for this effect key (J2).
    CacheHit,
    /// Outputs came from a signed claim by a key trusted for adoption (J7).
    Adopted,
}

/// Key for effect caching (side-effecting jobs only)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectKey {
    /// Job identifier
    pub job_id: JobId,
    /// SHA-256 hash of canonical CBOR of InputManifest
    pub manifest_hash: [u8; 32],
    /// SHA-256 hash of canonical CBOR of adapter-specific effect spec
    pub effect_spec_hash: [u8; 32],
}

impl EffectKey {
    /// Create a new effect key from job_id, manifest CID, and effect spec string
    pub fn new(job_id: JobId, manifest_hash: Cid, effect_spec: String) -> Self {
        let mut manifest_hash_bytes = [0u8; 32];
        manifest_hash_bytes.copy_from_slice(manifest_hash.as_bytes());

        let effect_spec_cid = Cid::compute(effect_spec.as_bytes());
        let mut effect_spec_hash_bytes = [0u8; 32];
        effect_spec_hash_bytes.copy_from_slice(effect_spec_cid.as_bytes());

        Self {
            job_id,
            manifest_hash: manifest_hash_bytes,
            effect_spec_hash: effect_spec_hash_bytes,
        }
    }

    /// Serialize to a binary storage key:
    ///
    /// ```text
    /// [u32:job_id_len_be][job_id_bytes][manifest_hash][effect_spec_hash]
    /// ```
    ///
    /// Length-prefixed rather than delimited, so a job ID may contain any
    /// bytes at all without colliding with the key encoding (invariant J5).
    pub fn to_binary_key(&self) -> Vec<u8> {
        let job_id_bytes = self.job_id.0.as_bytes();
        let mut key = Vec::new();
        key.extend_from_slice(&(job_id_bytes.len() as u32).to_be_bytes());
        key.extend_from_slice(job_id_bytes);
        key.extend_from_slice(&self.manifest_hash);
        key.extend_from_slice(&self.effect_spec_hash);
        key
    }

    /// Deserialize from binary key
    pub fn from_binary_key(key: &[u8]) -> Result<Self, JobError> {
        if key.len() < 4 {
            return Err(JobError::InvalidKey("key too short".into()));
        }

        let mut pos = 0;

        // Read job_id length and bytes
        let job_id_len =
            u32::from_be_bytes([key[pos], key[pos + 1], key[pos + 2], key[pos + 3]]) as usize;
        pos += 4;

        if pos + job_id_len > key.len() {
            return Err(JobError::InvalidKey("job_id overflow".into()));
        }

        let job_id = JobId(
            String::from_utf8(key[pos..pos + job_id_len].to_vec())
                .map_err(|e| JobError::InvalidKey(format!("invalid job_id utf8: {}", e)))?,
        );
        pos += job_id_len;

        // Read manifest_hash (32 bytes)
        if pos + 32 > key.len() {
            return Err(JobError::InvalidKey("manifest_hash overflow".into()));
        }
        let mut manifest_hash = [0u8; 32];
        manifest_hash.copy_from_slice(&key[pos..pos + 32]);
        pos += 32;

        // Read effect_spec_hash (32 bytes)
        if pos + 32 != key.len() {
            return Err(JobError::InvalidKey(
                "effect_spec_hash size mismatch".into(),
            ));
        }
        let mut effect_spec_hash = [0u8; 32];
        effect_spec_hash.copy_from_slice(&key[pos..pos + 32]);

        Ok(Self {
            job_id,
            manifest_hash,
            effect_spec_hash,
        })
    }
}

/// Job-related errors
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("Invalid job ID: {0}")]
    InvalidJobId(String),

    #[error("Invalid run ID: {0}")]
    InvalidRunId(String),

    #[error("Invalid effect key: {0}")]
    InvalidKey(String),

    #[error("Job not found: {0}")]
    JobNotFound(String),

    #[error("Run not found: {0}")]
    RunNotFound(String),

    #[error("Job already exists: {0}")]
    JobAlreadyExists(String),

    #[error("Invalid job specification: {0}")]
    InvalidSpec(String),

    #[error("Adapter not found: {0}")]
    AdapterNotFound(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

/// Validate job ID (similar to pointer/pin validation)
pub fn validate_job_id(id: &str) -> Result<(), JobError> {
    if id.is_empty() {
        return Err(JobError::InvalidJobId("job ID cannot be empty".into()));
    }
    if id.len() > 256 {
        return Err(JobError::InvalidJobId(
            "job ID too long (max 256 bytes)".into(),
        ));
    }
    if let Err(reason) = crate::validate_identifier_text(id) {
        return Err(JobError::InvalidJobId(reason.into()));
    }
    if id.contains('\0') {
        return Err(JobError::InvalidJobId(
            "job ID cannot contain NUL bytes".into(),
        ));
    }
    Ok(())
}

/// Validate the complete resource and naming contract for a job definition.
///
/// This intentionally does not decide which adapters are installed: a spec
/// may be replicated to a node that does not execute it. It only rejects data
/// that cannot be stored or evaluated with bounded resources and unambiguous
/// names.
pub fn validate_job_spec(spec: &JobSpec) -> Result<(), JobError> {
    validate_job_id(spec.job_id.as_ref())?;

    if let Some(placement) = &spec.placement {
        validate_bounded_text("placement", placement, MAX_JOB_PLACEMENT_BYTES)?;
    }
    validate_bounded_text("code_ref", &spec.code_ref, MAX_JOB_CODE_REF_BYTES)?;

    if spec.inputs.static_inputs.len() > MAX_JOB_STATIC_INPUTS {
        return Err(JobError::InvalidSpec(format!(
            "static input count {} exceeds the limit of {MAX_JOB_STATIC_INPUTS}",
            spec.inputs.static_inputs.len()
        )));
    }
    if spec.inputs.pointer_inputs.len() > MAX_JOB_POINTER_INPUTS {
        return Err(JobError::InvalidSpec(format!(
            "pointer input count {} exceeds the limit of {MAX_JOB_POINTER_INPUTS}",
            spec.inputs.pointer_inputs.len()
        )));
    }
    if spec.declared_outputs.len() > MAX_JOB_DECLARED_OUTPUTS {
        return Err(JobError::InvalidSpec(format!(
            "declared output count {} exceeds the limit of {MAX_JOB_DECLARED_OUTPUTS}",
            spec.declared_outputs.len()
        )));
    }

    let mut pointer_names = HashSet::with_capacity(spec.inputs.pointer_inputs.len());
    for pointer in &spec.inputs.pointer_inputs {
        validate_bounded_text("pointer input", pointer, MAX_JOB_NAME_BYTES)?;
        if !pointer_names.insert(pointer.as_str()) {
            return Err(JobError::InvalidSpec(format!(
                "pointer input {pointer:?} is declared more than once"
            )));
        }
    }

    let mut output_names = HashSet::with_capacity(spec.declared_outputs.len());
    for output in &spec.declared_outputs {
        validate_bounded_text("output name", output, MAX_JOB_NAME_BYTES)?;
        if !output_names.insert(output.as_str()) {
            return Err(JobError::InvalidSpec(format!(
                "output name {output:?} is declared more than once"
            )));
        }
    }

    if let Some(config) = &spec.config {
        validate_job_config(config)?;
    }
    Ok(())
}

fn validate_bounded_text(field: &str, value: &str, max_bytes: usize) -> Result<(), JobError> {
    if value.is_empty() {
        return Err(JobError::InvalidSpec(format!("{field} cannot be empty")));
    }
    if value.len() > max_bytes {
        return Err(JobError::InvalidSpec(format!(
            "{field} exceeds the limit of {max_bytes} bytes"
        )));
    }
    if let Err(reason) = crate::validate_identifier_text(value) {
        return Err(JobError::InvalidSpec(format!(
            "{field} is unsafe: {reason}"
        )));
    }
    Ok(())
}

fn validate_job_config(config: &serde_json::Value) -> Result<(), JobError> {
    // Traverse iteratively so an embedder-provided Value cannot consume the
    // process stack. Check fan-out before extending the work vector, keeping
    // the validator's own memory bounded by MAX_JOB_CONFIG_NODES.
    let mut pending = vec![(config, 1usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_JOB_CONFIG_NODES {
            return Err(JobError::InvalidSpec(format!(
                "config exceeds the limit of {MAX_JOB_CONFIG_NODES} JSON values"
            )));
        }
        if depth > MAX_JOB_CONFIG_DEPTH {
            return Err(JobError::InvalidSpec(format!(
                "config exceeds the maximum nesting depth of {MAX_JOB_CONFIG_DEPTH}"
            )));
        }

        let child_count = match value {
            serde_json::Value::Array(values) => values.len(),
            serde_json::Value::Object(values) => values.len(),
            _ => 0,
        };
        if nodes
            .saturating_add(pending.len())
            .saturating_add(child_count)
            > MAX_JOB_CONFIG_NODES
        {
            return Err(JobError::InvalidSpec(format!(
                "config exceeds the limit of {MAX_JOB_CONFIG_NODES} JSON values"
            )));
        }
        match value {
            serde_json::Value::Array(values) => {
                pending.extend(values.iter().map(|child| (child, depth + 1)));
            }
            serde_json::Value::Object(values) => {
                pending.extend(values.values().map(|child| (child, depth + 1)));
            }
            _ => {}
        }
    }

    let bytes = serde_json::to_vec(config)
        .map_err(|error| JobError::InvalidSpec(format!("config is not encodable: {error}")))?;
    if bytes.len() > MAX_JOB_CONFIG_BYTES {
        return Err(JobError::InvalidSpec(format!(
            "encoded config is {} bytes; the limit is {MAX_JOB_CONFIG_BYTES}",
            bytes.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_id_creation() {
        let id1 = JobId::from("test-job");
        let id2 = JobId::from("test-job".to_string());
        assert_eq!(id1, id2);
        assert_eq!(id1.as_ref(), "test-job");
    }

    #[test]
    fn test_job_input_builder() {
        let cid1 = Cid::compute(b"input1");
        let cid2 = Cid::compute(b"input2");

        let input = JobInput::new()
            .with_static(cid1.clone())
            .with_static(cid2.clone())
            .with_pointer("ptr1")
            .with_pointer("ptr2");

        assert_eq!(input.static_inputs.len(), 2);
        assert_eq!(input.pointer_inputs.len(), 2);
        assert_eq!(input.static_inputs[0], cid1);
        assert_eq!(input.pointer_inputs[0], "ptr1");
    }

    #[test]
    fn test_manifest_flattened() {
        let cid1 = Cid::compute(b"static1");
        let cid2 = Cid::compute(b"static2");
        let cid3 = Cid::compute(b"pointer1");
        let cid4 = Cid::compute(b"pointer2");

        let manifest = InputManifest {
            static_inputs: vec![cid1.clone(), cid2.clone()],
            pointer_heads: vec![
                ResolvedPointer {
                    pointer_id: "ptr1".into(),
                    head_cid: cid3.clone(),
                    log_seq: 5,
                },
                ResolvedPointer {
                    pointer_id: "ptr2".into(),
                    head_cid: cid4.clone(),
                    log_seq: 10,
                },
            ],
            resolved_at_unix: 1234567890,
        };

        let flat = manifest.flattened();
        assert_eq!(flat.len(), 4);
        assert_eq!(flat[0], cid1);
        assert_eq!(flat[1], cid2);
        assert_eq!(flat[2], cid3);
        assert_eq!(flat[3], cid4);
    }

    #[test]
    fn test_manifest_hash_is_stable() {
        let cid1 = Cid::compute(b"data1");
        let cid2 = Cid::compute(b"pointer_data");

        let manifest1 = InputManifest {
            static_inputs: vec![cid1.clone()],
            pointer_heads: vec![ResolvedPointer {
                pointer_id: "ptr".into(),
                head_cid: cid2.clone(),
                log_seq: 42,
            }],
            resolved_at_unix: 1234567890,
        };

        let manifest2 = InputManifest {
            static_inputs: vec![cid1.clone()],
            pointer_heads: vec![ResolvedPointer {
                pointer_id: "ptr".into(),
                head_cid: cid2.clone(),
                log_seq: 42,
            }],
            resolved_at_unix: 1234567890,
        };

        let hash1 = manifest1.compute_hash();
        let hash2 = manifest2.compute_hash();

        assert_eq!(
            hash1, hash2,
            "Identical manifests must produce identical hashes"
        );
    }

    #[test]
    fn test_manifest_hash_ignores_resolution_time() {
        let cid1 = Cid::compute(b"data1");
        let cid2 = Cid::compute(b"pointer_data");

        let resolved = |at: i64| InputManifest {
            static_inputs: vec![cid1.clone()],
            pointer_heads: vec![ResolvedPointer {
                pointer_id: "ptr".into(),
                head_cid: cid2.clone(),
                log_seq: 42,
            }],
            resolved_at_unix: at,
        };

        assert_eq!(
            resolved(1234567890).compute_hash(),
            resolved(1234567891).compute_hash(),
            "The same inputs resolved at different times must produce the same \
             hash: this hash keys the effect cache (J2, J4), and an effect is \
             identified by what was resolved, not when"
        );
    }

    #[test]
    fn test_manifest_hash_ignores_pointer_seq() {
        let cid1 = Cid::compute(b"data1");
        let cid2 = Cid::compute(b"pointer_data");

        let at_seq = |seq: u64| InputManifest {
            static_inputs: vec![cid1.clone()],
            pointer_heads: vec![ResolvedPointer {
                pointer_id: "ptr".into(),
                head_cid: cid2.clone(),
                log_seq: seq,
            }],
            resolved_at_unix: 1234567890,
        };

        assert_eq!(
            at_seq(1).compute_hash(),
            at_seq(3).compute_hash(),
            "A pointer resolving to the same CID at a later sequence number \
             must produce the same hash: reverting a pointer to bytes that \
             were built before is a cache hit, not a rebuild (J2). The seq \
             stays in the run record, where replay (J3) needs it"
        );
    }

    #[test]
    fn test_manifest_hash_differs_when_content_differs() {
        let cid1 = Cid::compute(b"data1");
        let cid2 = Cid::compute(b"data2");

        let manifest1 = InputManifest {
            static_inputs: vec![cid1.clone()],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let manifest2 = InputManifest {
            static_inputs: vec![cid2.clone()],
            pointer_heads: vec![],
            resolved_at_unix: 1234567890,
        };

        let hash1 = manifest1.compute_hash();
        let hash2 = manifest2.compute_hash();

        assert_ne!(
            hash1, hash2,
            "Different manifests must produce different hashes"
        );
    }

    #[test]
    fn test_effect_key_binary_round_trip() {
        let job_id = JobId::from("test-job");
        let manifest_cid = Cid::compute(b"manifest");
        let effect_spec = "https://example.com/resource".to_string();

        let key = EffectKey::new(job_id.clone(), manifest_cid, effect_spec);
        let binary = key.to_binary_key();
        let decoded = EffectKey::from_binary_key(&binary).expect("decode failed");

        assert_eq!(decoded.job_id, job_id);
        assert_eq!(decoded.manifest_hash, key.manifest_hash);
        assert_eq!(decoded.effect_spec_hash, key.effect_spec_hash);
    }

    #[test]
    fn test_effect_key_with_special_chars() {
        let job_id = JobId::from("job:with:colons");
        let manifest_cid = Cid::compute(b"manifest");
        let effect_spec = "url:with:colons:and:slashes".to_string();

        let key = EffectKey::new(job_id, manifest_cid, effect_spec);
        let binary = key.to_binary_key();
        let decoded = EffectKey::from_binary_key(&binary).expect("decode failed");

        assert_eq!(decoded.job_id.0, "job:with:colons");
    }

    #[test]
    fn test_job_spec_serde_round_trip() {
        let spec = JobSpec {
            job_id: JobId::from("test-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new().with_static(Cid::compute(b"data")),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["output".into()],
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&spec, &mut cbor).unwrap();
        let decoded: JobSpec = ciborium::de::from_reader(&cbor[..]).unwrap();

        assert_eq!(decoded.job_id, spec.job_id);
        assert_eq!(decoded.code_ref, spec.code_ref);
    }

    #[test]
    fn test_run_status_variants() {
        let pending = RunStatus::Pending;
        let running = RunStatus::Running;
        let succeeded = RunStatus::Succeeded;
        let failed = RunStatus::Failed {
            message: "error".into(),
        };

        assert!(matches!(pending, RunStatus::Pending));
        assert!(matches!(running, RunStatus::Running));
        assert!(matches!(succeeded, RunStatus::Succeeded));
        assert!(matches!(failed, RunStatus::Failed { .. }));
    }

    #[test]
    fn test_validate_job_id() {
        assert!(validate_job_id("valid-job").is_ok());
        assert!(validate_job_id("job/with/slashes").is_ok());
        assert!(validate_job_id("模型/é/مرحبا").is_ok());
        assert!(validate_job_id("").is_err());
        assert!(validate_job_id("job\0hidden").is_err());
        assert!(validate_job_id("job\nforged").is_err());
        assert!(validate_job_id("job\u{001b}[2J").is_err());
        assert!(validate_job_id("job\u{202e}txt").is_err());
        assert!(validate_job_id(&"x".repeat(300)).is_err());
    }

    fn bounded_spec() -> JobSpec {
        JobSpec {
            job_id: JobId::from("bounded"),
            placement: Some("node-a".into()),
            inputs: JobInput::new(),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["result".into()],
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: Some(serde_json::json!({"format": "hex"})),
        }
    }

    #[test]
    fn job_spec_resource_contract_rejects_oversized_or_ambiguous_fields() {
        assert!(validate_job_spec(&bounded_spec()).is_ok());

        let mut unicode = bounded_spec();
        unicode.placement = Some("nœud-東京".into());
        unicode.code_ref = "哈希".into();
        unicode.inputs.pointer_inputs = vec!["输入".into()];
        unicode.declared_outputs = vec!["résultat".into()];
        assert!(validate_job_spec(&unicode).is_ok());

        for unsafe_text in [
            "bad\nline",
            "bad\u{001b}[2J",
            "bad\u{202e}txt",
            "bad\u{2028}line",
        ] {
            let mut spec = bounded_spec();
            spec.placement = Some(unsafe_text.into());
            assert!(validate_job_spec(&spec).is_err());
            let mut spec = bounded_spec();
            spec.code_ref = unsafe_text.into();
            assert!(validate_job_spec(&spec).is_err());
            let mut spec = bounded_spec();
            spec.inputs.pointer_inputs = vec![unsafe_text.into()];
            assert!(validate_job_spec(&spec).is_err());
            let mut spec = bounded_spec();
            spec.declared_outputs = vec![unsafe_text.into()];
            assert!(validate_job_spec(&spec).is_err());
        }

        let mut spec = bounded_spec();
        spec.inputs.pointer_inputs = vec!["source".into(), "source".into()];
        assert!(validate_job_spec(&spec)
            .unwrap_err()
            .to_string()
            .contains("more than once"));

        let mut spec = bounded_spec();
        spec.declared_outputs = vec!["result".into(), "result".into()];
        assert!(validate_job_spec(&spec)
            .unwrap_err()
            .to_string()
            .contains("more than once"));

        let mut spec = bounded_spec();
        spec.inputs.static_inputs = (0..=MAX_JOB_STATIC_INPUTS)
            .map(|index| Cid::compute(&index.to_be_bytes()))
            .collect();
        assert!(validate_job_spec(&spec)
            .unwrap_err()
            .to_string()
            .contains("static input"));

        let mut spec = bounded_spec();
        spec.config = Some(serde_json::Value::String("x".repeat(MAX_JOB_CONFIG_BYTES)));
        assert!(validate_job_spec(&spec)
            .unwrap_err()
            .to_string()
            .contains("encoded config"));
    }

    #[test]
    fn job_config_depth_and_node_count_are_bounded() {
        let mut nested = serde_json::Value::Null;
        for _ in 0..=MAX_JOB_CONFIG_DEPTH {
            nested = serde_json::Value::Array(vec![nested]);
        }
        let mut spec = bounded_spec();
        spec.config = Some(nested);
        assert!(validate_job_spec(&spec)
            .unwrap_err()
            .to_string()
            .contains("nesting depth"));

        let mut spec = bounded_spec();
        spec.config = Some(serde_json::Value::Array(
            (0..=MAX_JOB_CONFIG_NODES)
                .map(|_| serde_json::Value::Null)
                .collect(),
        ));
        assert!(validate_job_spec(&spec)
            .unwrap_err()
            .to_string()
            .contains("JSON values"));
    }
}
