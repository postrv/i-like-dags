//! Job log implementation with event sourcing
//!
//! This module implements the JobLog, which tracks job specifications, run history,
//! and effect caching using an append-only event log stored in redb.
//!
//! ## Concurrency
//!
//! As with the pointer and pin logs: redb serialises writers, and a per-log
//! mutex covers each read-modify-write window between transactions.

use crate::error::{ControlError, Result};
use crate::pointer::{PointerError, PointerTriggerAuthority};
use dag_core::{
    validate_job_id, validate_job_spec, Cid, ContentStore, EffectKey, Entry, InputManifest,
    JobError, JobId, JobRevision, JobRun, JobSpec, ResolvedPointer, RunId, RunStatus,
    TriggerPolicy,
};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
use std::sync::{Arc, Mutex, RwLock};

const JOB_EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_events");
const JOB_HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_heads");
const JOB_RUNS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_runs");
/// Job ID → highest run sequence ever allocated. Run-history compaction may
/// remove every old row, but it must never make a future run reuse an ID.
const JOB_RUN_WATERMARKS: TableDefinition<&[u8], u64> = TableDefinition::new("job_run_watermarks");
/// Pending-run key → global enqueue order. Keeping the runnable index separate
/// from immutable run history makes selection O(pending), and the monotonic
/// value makes "oldest" independent of lexicographic job IDs.
const PENDING_RUNS: TableDefinition<&[u8], u64> = TableDefinition::new("job_pending_runs");
/// `[adapter length][adapter][enqueue order]` -> run key. This is the
/// authoritative runnable selection index in schema 5, so a worker scans only
/// adapters it can actually execute.
const PENDING_BY_ADAPTER: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("job_pending_by_adapter");
/// Enqueue order -> run key, for capability-unfiltered workers and exact
/// oldest selection without scanning job-key order.
const PENDING_BY_ORDER: TableDefinition<u64, &[u8]> = TableDefinition::new("job_pending_by_order");
/// Running-run key → marker. This makes health/metrics O(active) metadata
/// rather than decoding an unbounded terminal history on every scrape.
const RUNNING_RUNS: TableDefinition<&[u8], u8> = TableDefinition::new("job_running_runs");
const RUN_QUEUE_META: TableDefinition<&[u8], u64> = TableDefinition::new("job_run_queue_meta");
const NEXT_PENDING_ORDER_KEY: &[u8] = b"next_pending_order";
const EFFECT_CACHE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("effect_cache");
/// Effect-key binary → CBOR `Vec<Cid>` of claim entries (ADR-003). Derived
/// from the claim entries themselves; rebuildable by store scan.
const EFFECT_CLAIMS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("effect_claims");
pub(crate) const POINTER_SUBSCRIPTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("pointer_subscriptions");
/// Pointer updates enqueue deterministic trigger intents here in the same
/// transaction that advances the pointer. A worker turns each intent into a
/// pending run through `TRIGGER_RECEIPTS`, so replay after a crash cannot
/// duplicate a run.
const TRIGGER_QUEUE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_trigger_queue");
const TRIGGER_RECEIPTS: TableDefinition<&[u8], u64> = TableDefinition::new("job_trigger_receipts");
const TRIGGER_DEAD_LETTERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("job_trigger_dead_letters");
/// A lease exists while a background worker owns a pending/running run. It is
/// deliberately separate from `JobRun`, preserving the on-disk run encoding
/// and backwards compatibility.
const RUN_LEASES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_run_leases");
/// Invalid active rows removed from scheduling during migration/startup.
const RUN_QUARANTINE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_run_quarantine");

const MIN_LEASE_SECONDS: u64 = 5;
const MAX_LEASE_SECONDS: u64 = 24 * 60 * 60;
const MAX_TRIGGER_QUEUE: u64 = 100_000;
const MAX_TRIGGER_DEAD_LETTERS: u64 = 100_000;
const MAX_SUBSCRIPTIONS_PER_POINTER: usize = 4_096;
const MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES: usize = 2 * 1024 * 1024;
const MAX_TRIGGER_ROW_BYTES: usize = 512 * 1024;
const MAX_TRIGGER_DEAD_LETTER_ROW_BYTES: usize = MAX_TRIGGER_ROW_BYTES + 16 * 1024;
const MAX_TRIGGER_KEY_BYTES: usize = 1_024;
const MAX_RUN_LEASE_ROW_BYTES: usize = 4 * 1024;
const MAX_TRIGGER_SNAPSHOT_INPUT_REFS_PER_UPDATE: usize = 65_536;
const MAX_TRIGGER_SNAPSHOT_BYTES_PER_UPDATE: usize = 64 * 1024 * 1024;
const MAX_ACTIVE_WORK_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
/// Maximum number of runnable rows. Admission is checked in the transaction
/// that inserts every kind of trigger.
pub const MAX_PENDING_RUNS: u64 = 100_000;
const MAX_RUN_QUARANTINE: u64 = 100_000;
/// Run-history reads must always name a finite page.
pub const MAX_RUN_HISTORY_PAGE: usize = 1_000;
/// Maximum UTF-8 bytes retained from an execution failure.
pub const MAX_RUN_FAILURE_MESSAGE_BYTES: usize = 16 * 1024;
/// A run row is bounded before CBOR decoding. The largest valid row contains
/// 256 named pointer inputs, 256 named outputs and a bounded failure message;
/// 512 KiB leaves substantial encoding headroom without allowing a corrupt
/// database value to drive an unbounded allocation on startup or read paths.
const MAX_JOB_RUN_ROW_BYTES: usize = 512 * 1024;
/// Job definitions are bounded by `validate_job_spec`; enforce a generous
/// encoded ceiling before decoding cached heads as well.
const MAX_JOB_HEAD_ROW_BYTES: usize = 512 * 1024;
/// Maximum encoded job-event payload accepted from immutable storage.
///
/// `validate_job_spec` already bounds every variable-length collection and
/// string a current writer emits. This pre-decode ceiling also protects
/// recovery and table rebuilds from indefinite/oversized CBOR planted in an
/// otherwise valid Entry.
pub(crate) const MAX_JOB_EVENT_PAYLOAD_BYTES: usize = 512 * 1024;
/// Effect-cache rows contain at most 256 `(name, CID)` pairs. Check the
/// encoded form too, before deserializing an attacker-planted indefinite
/// array or oversized name.
const MAX_EFFECT_CACHE_ROW_BYTES: usize = 256 * 1024;
/// Maximum independently attested claims indexed under one effect key.
///
/// A claim row is a derived accelerator, not an append-only log. Keeping the
/// vector finite bounds every adoption lookup and prevents many valid claim
/// objects sharing a key from becoming one unbounded database value.
pub const MAX_EFFECT_CLAIMS_PER_KEY: usize = 4_096;
const MAX_EFFECT_CLAIM_INDEX_ROW_BYTES: usize = 256 * 1024;

#[cfg(test)]
static CLAIM_INDEX_ROWS_SCANNED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RUN_PAGE_ROWS_DECODED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct QueuedTrigger {
    job_id: JobId,
    reason: String,
    queued_at_unix: i64,
    /// Exact job event selected by the pointer-publication transaction.
    ///
    /// Legacy rows decode as `None` and are dead-lettered: inferring the
    /// current job head at drain time would let later spec/config changes
    /// rewrite already-authorized work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<JobRevision>,
    /// Exact pointer/static inputs selected by the pointer-publication
    /// transaction. Legacy rows are never resolved from mutable heads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<InputManifest>,
}

fn decode_pointer_subscriptions(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() > MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "pointer subscription row exceeds {MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES} bytes"
        )));
    }
    let job_ids: Vec<String> = cbor_decode(bytes)?;
    if job_ids.len() > MAX_SUBSCRIPTIONS_PER_POINTER {
        return Err(ControlError::Database(format!(
            "pointer subscription row exceeds {MAX_SUBSCRIPTIONS_PER_POINTER} jobs"
        )));
    }
    for job_id in &job_ids {
        validate_job_id(job_id).map_err(|error| {
            ControlError::Database(format!(
                "pointer subscription row contains an invalid job ID: {error}"
            ))
        })?;
    }
    Ok(job_ids)
}

fn decode_queued_trigger(bytes: &[u8]) -> Result<QueuedTrigger> {
    if bytes.len() > MAX_TRIGGER_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "queued trigger row exceeds {MAX_TRIGGER_ROW_BYTES} bytes"
        )));
    }
    let trigger: QueuedTrigger = cbor_decode(bytes)?;
    validate_job_id(trigger.job_id.as_ref()).map_err(|error| {
        ControlError::Database(format!(
            "queued trigger contains an invalid job ID: {error}"
        ))
    })?;
    Ok(trigger)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct DeadTrigger {
    trigger: QueuedTrigger,
    error: String,
    failed_at_unix: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct StoredLease {
    token: [u8; 32],
    worker_id: String,
    claimed_at_unix: i64,
    expires_at_unix: i64,
}

fn decode_dead_trigger(bytes: &[u8]) -> Result<DeadTrigger> {
    if bytes.len() > MAX_TRIGGER_DEAD_LETTER_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "trigger dead-letter row exceeds {MAX_TRIGGER_DEAD_LETTER_ROW_BYTES} bytes"
        )));
    }
    cbor_decode(bytes)
}

fn decode_stored_lease(bytes: &[u8]) -> Result<StoredLease> {
    if bytes.len() > MAX_RUN_LEASE_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "job run lease row exceeds {MAX_RUN_LEASE_ROW_BYTES} bytes"
        )));
    }
    let lease: StoredLease = cbor_decode(bytes)?;
    if lease.worker_id.trim().is_empty() || lease.worker_id.len() > 256 {
        return Err(ControlError::Database(
            "job run lease contains an invalid worker ID".into(),
        ));
    }
    Ok(lease)
}

/// An unforgeable claim on one queued run. Callers can inspect which run was
/// claimed but cannot construct or alter the token; lifecycle mutations take
/// this value and validate it against the durable lease table.
#[derive(Clone, Debug)]
pub struct RunClaim {
    pub job_id: JobId,
    pub run_id: RunId,
    pub worker_id: String,
    token: [u8; 32],
    lease_seconds: u64,
}

/// Immutable execution material recovered for a durably claimed run.
#[derive(Clone, Debug)]
pub struct ClaimedRun {
    pub spec: JobSpec,
    pub manifest: InputManifest,
    pub revision: JobRevision,
}

impl RunClaim {
    /// How often an executor should renew this lease while adapter work is in
    /// flight. One third leaves room for a delayed heartbeat before expiry.
    pub fn heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs((self.lease_seconds / 3).max(1))
    }
}

/// Result of draining durable pointer-trigger intents.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct TriggerDrainReport {
    pub examined: u32,
    pub enqueued: u32,
    pub already_enqueued: u32,
    pub dead_lettered: u32,
}

/// Outcome of an explicit terminal run-history compaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RunCompactionReport {
    pub examined: u64,
    pub terminal_rows: u64,
    pub active_retained: u64,
    pub eligible: u64,
    pub deleted: u64,
    pub remaining_eligible: u64,
    pub dry_run: bool,
}

/// One transaction cannot be allowed to retain an arbitrarily large delete
/// set. Operators repeat compaction until `remaining_eligible` reaches zero.
pub const MAX_RUN_COMPACTION_DELETE: usize = 10_000;

/// Operator-facing view of one permanently refused pointer trigger.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TriggerDeadLetter {
    pub key: String,
    pub job_id: String,
    pub reason: String,
    pub queued_at_unix: i64,
    pub error: String,
    pub failed_at_unix: i64,
}

/// Result of a bounded dead-letter purge.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct DeadLetterCompactionReport {
    pub total: u64,
    pub selected: u64,
    pub deleted: u64,
    pub remaining: u64,
    pub dry_run: bool,
}

pub const MAX_DEAD_LETTER_DELETE: usize = 10_000;
pub const MAX_DEAD_LETTER_LIST: usize = 1_000;

/// Binary key encoding/decoding for job events
mod keys {
    use dag_core::JobError;

    /// Encode job event key: [u32:job_id_len_be][job_id_bytes][u64:seq_be]
    pub fn encode_event_key(job_id: &str, seq: u64) -> Vec<u8> {
        let job_id_bytes = job_id.as_bytes();
        let mut key = Vec::new();
        key.extend_from_slice(&(job_id_bytes.len() as u32).to_be_bytes());
        key.extend_from_slice(job_id_bytes);
        key.extend_from_slice(&seq.to_be_bytes());
        key
    }

    /// Decode job event key back to (job_id, seq).
    pub fn decode_event_key(key: &[u8]) -> Result<(String, u64), JobError> {
        if key.len() < 4 {
            return Err(JobError::InvalidKey("key too short".into()));
        }

        let job_id_len = u32::from_be_bytes([key[0], key[1], key[2], key[3]]) as usize;
        if key.len() != 4 + job_id_len + 8 {
            return Err(JobError::InvalidKey(
                "key length does not exactly match its job ID and sequence".into(),
            ));
        }

        let job_id = String::from_utf8(key[4..4 + job_id_len].to_vec())
            .map_err(|e| JobError::InvalidKey(format!("invalid job_id utf8: {}", e)))?;

        let seq = u64::from_be_bytes([
            key[4 + job_id_len],
            key[4 + job_id_len + 1],
            key[4 + job_id_len + 2],
            key[4 + job_id_len + 3],
            key[4 + job_id_len + 4],
            key[4 + job_id_len + 5],
            key[4 + job_id_len + 6],
            key[4 + job_id_len + 7],
        ]);

        Ok((job_id, seq))
    }

    /// Encode prefix for all events of a job
    pub fn encode_job_prefix(job_id: &str) -> Vec<u8> {
        let job_id_bytes = job_id.as_bytes();
        let mut key = Vec::new();
        key.extend_from_slice(&(job_id_bytes.len() as u32).to_be_bytes());
        key.extend_from_slice(job_id_bytes);
        key
    }

    /// Encode run key: [u32:job_id_len_be][job_id_bytes][u64:run_seq_be]
    pub fn encode_run_key(job_id: &str, run_seq: u64) -> Vec<u8> {
        encode_event_key(job_id, run_seq)
    }

    /// `[u32:adapter_len_be][adapter][u64:enqueue_order_be]`.
    pub fn encode_adapter_order_key(adapter: &str, order: u64) -> Vec<u8> {
        let adapter = adapter.as_bytes();
        let mut key = Vec::with_capacity(4 + adapter.len() + 8);
        key.extend_from_slice(&(adapter.len() as u32).to_be_bytes());
        key.extend_from_slice(adapter);
        key.extend_from_slice(&order.to_be_bytes());
        key
    }

    pub fn encode_adapter_prefix(adapter: &str) -> Vec<u8> {
        let adapter = adapter.as_bytes();
        let mut key = Vec::with_capacity(4 + adapter.len());
        key.extend_from_slice(&(adapter.len() as u32).to_be_bytes());
        key.extend_from_slice(adapter);
        key
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_basic_encoding() {
            let key = encode_event_key("test-job", 42);
            let (job_id, seq) = decode_event_key(&key).unwrap();
            assert_eq!(job_id, "test-job");
            assert_eq!(seq, 42);
        }

        #[test]
        fn test_empty_job_id() {
            let key = encode_event_key("", 1);
            let (job_id, seq) = decode_event_key(&key).unwrap();
            assert_eq!(job_id, "");
            assert_eq!(seq, 1);
        }

        #[test]
        fn test_special_characters() {
            let key = encode_event_key("job/with:special@chars", 999);
            let (job_id, seq) = decode_event_key(&key).unwrap();
            assert_eq!(job_id, "job/with:special@chars");
            assert_eq!(seq, 999);
        }

        #[test]
        fn test_lexicographic_ordering() {
            let k1 = encode_event_key("job-a", 1);
            let k2 = encode_event_key("job-a", 2);
            let k3 = encode_event_key("job-b", 1);

            assert!(k1 < k2);
            assert!(k2 < k3);
        }

        #[test]
        fn test_prefix_encoding() {
            let prefix = encode_job_prefix("test-job");
            let k1 = encode_event_key("test-job", 1);
            let k2 = encode_event_key("test-job", 2);
            let k3 = encode_event_key("other-job", 1);

            assert!(k1.starts_with(&prefix));
            assert!(k2.starts_with(&prefix));
            assert!(!k3.starts_with(&prefix));
        }

        #[test]
        fn test_invalid_keys() {
            assert!(decode_event_key(&[]).is_err());
            assert!(decode_event_key(&[0, 0, 0, 1]).is_err());
            assert!(decode_event_key(&[0, 0, 0, 10, b't', b'e', b's', b't']).is_err());
            let mut trailing = encode_event_key("job", 1);
            trailing.push(0);
            assert!(decode_event_key(&trailing).is_err());
            let invalid_utf8 = [0, 0, 0, 1, 0xff, 0, 0, 0, 0, 0, 0, 0, 1];
            assert!(decode_event_key(&invalid_utf8).is_err());
        }
    }
}

fn active_pointer_trigger_jobs<S, H>(
    subscriptions: &S,
    heads: &H,
    pointer_id: &str,
) -> Result<Vec<JobHead>>
where
    S: ReadableTable<&'static [u8], &'static [u8]>,
    H: ReadableTable<&'static [u8], &'static [u8]>,
{
    let subscribed: Vec<String> = subscriptions
        .get(pointer_id.as_bytes())
        .map_err(db_err)?
        .map(|value| decode_pointer_subscriptions(value.value()))
        .transpose()?
        .unwrap_or_default();
    let mut active = Vec::new();
    for job in subscribed {
        let Some(bytes) = heads.get(job.as_bytes()).map_err(db_err)? else {
            // A stale subscription is inert. `drain_trigger_queue` keeps
            // failures visible, but a pointer update must not be bricked
            // forever merely because an old job was removed manually.
            continue;
        };
        let head = decode_job_head(bytes.value(), Some(&job))?;
        if matches!(head.spec.policy.trigger, TriggerPolicy::OnPointerUpdate) {
            active.push(head);
        }
    }
    Ok(active)
}

/// Advisory read used to reject steady-state unauthorized mutations before
/// they create an immutable-but-unfiled pointer-event object.
///
/// The pointer publication path repeats this lookup in its write transaction;
/// this read is an allocation/abuse guard, never the authorization decision.
pub(crate) fn has_active_pointer_triggers(db: &Database, pointer_id: &str) -> Result<bool> {
    let txn = db.begin_read().map_err(db_err)?;
    let subscriptions = txn.open_table(POINTER_SUBSCRIPTIONS).map_err(db_err)?;
    let heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
    Ok(!active_pointer_trigger_jobs(&subscriptions, &heads, pointer_id)?.is_empty())
}

/// Definitive active-subscription lookup for callers that already own the
/// publication transaction. Keeping this in the same redb writer as the
/// pointer-head replacement closes the subscription/publication race.
pub(crate) fn has_active_pointer_triggers_in_transaction(
    txn: &WriteTransaction,
    pointer_id: &str,
) -> Result<bool> {
    let subscriptions = txn.open_table(POINTER_SUBSCRIPTIONS).map_err(db_err)?;
    let heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
    Ok(!active_pointer_trigger_jobs(&subscriptions, &heads, pointer_id)?.is_empty())
}

fn snapshot_trigger_manifest<H>(
    heads: &H,
    spec: &JobSpec,
    resolved_at_unix: i64,
) -> Result<InputManifest>
where
    H: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut pointer_heads = Vec::with_capacity(spec.inputs.pointer_inputs.len());
    for pointer_id in &spec.inputs.pointer_inputs {
        let bytes = heads
            .get(pointer_id.as_bytes())
            .map_err(db_err)?
            .ok_or_else(|| {
                JobError::InvalidSpec(format!(
                    "job {} cannot snapshot absent pointer input {pointer_id}",
                    spec.job_id
                ))
            })?;
        let head = crate::pointer::decode_pointer_head(bytes.value())?;
        pointer_heads.push(ResolvedPointer {
            pointer_id: pointer_id.clone(),
            head_cid: head.current_cid,
            log_seq: head.seq,
        });
    }
    let manifest = InputManifest {
        static_inputs: spec.inputs.static_inputs.clone(),
        pointer_heads,
        resolved_at_unix,
    };
    validate_manifest_for_spec(spec, &manifest)?;
    Ok(manifest)
}

/// Queue every active OnPointerUpdate subscription as part of the pointer's
/// own write transaction. The key is deterministic for
/// `(pointer, sequence, job)`, so retrying a transaction or replaying an
/// offered pointer event overwrites the same intent rather than multiplying
/// work.
pub(crate) fn enqueue_pointer_triggers(
    txn: &WriteTransaction,
    pointer_id: &str,
    pointer_seq: u64,
    queued_at_unix: i64,
    trigger_authority: PointerTriggerAuthority,
) -> Result<u32> {
    let subscriptions = txn.open_table(POINTER_SUBSCRIPTIONS).map_err(db_err)?;
    let heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
    let active = active_pointer_trigger_jobs(&subscriptions, &heads, pointer_id)?;
    drop(heads);
    drop(subscriptions);
    if active.is_empty() {
        return Ok(0);
    }

    // Authorize before resolving or encoding any job material. This decision
    // observes the same transaction that will publish the pointer and queue
    // rows, so neither a subscription nor a job revision can race it.
    if !trigger_authority.permits_triggers() {
        return Err(PointerError::TriggerPermissionRequired {
            pointer_id: pointer_id.to_string(),
        }
        .into());
    }

    let mut intents = Vec::new();
    let events = txn.open_table(JOB_EVENTS).map_err(db_err)?;
    let pointer_heads = txn
        .open_table(crate::pointer::POINTER_HEADS)
        .map_err(db_err)?;
    let mut total_input_refs = 0usize;
    let mut total_snapshot_bytes = 0usize;
    for head in active {
        total_input_refs = total_input_refs
            .checked_add(head.spec.inputs.static_inputs.len())
            .and_then(|count| count.checked_add(head.spec.inputs.pointer_inputs.len()))
            .ok_or_else(|| {
                ControlError::Capacity("trigger snapshot input count overflow".into())
            })?;
        if total_input_refs > MAX_TRIGGER_SNAPSHOT_INPUT_REFS_PER_UPDATE {
            return Err(ControlError::Capacity(format!(
                "pointer update would snapshot {total_input_refs} job inputs, above the {MAX_TRIGGER_SNAPSHOT_INPUT_REFS_PER_UPDATE}-input aggregate limit"
            )));
        }
        let job_id = head.job_id.clone();
        let event_key = keys::encode_event_key(job_id.as_ref(), head.seq);
        let event_cid_bytes = events
            .get(event_key.as_slice())
            .map_err(db_err)?
            .ok_or_else(|| {
                JobError::ExecutionFailed(format!(
                    "job {job_id} head seq {} has no filed event",
                    head.seq
                ))
            })?;
        let event_cid = Cid::from_bytes(event_cid_bytes.value()).map_err(db_err)?;
        let revision = JobRevision {
            event_cid,
            event_seq: head.seq,
            code_ref: head.spec.code_ref.clone(),
        };
        let manifest = snapshot_trigger_manifest(&pointer_heads, &head.spec, queued_at_unix)?;
        let key = pointer_trigger_key(pointer_id, pointer_seq, job_id.as_ref());
        let value = cbor_encode(&QueuedTrigger {
            job_id: job_id.clone(),
            reason: format!("pointer_update:{pointer_id}:{pointer_seq}"),
            queued_at_unix,
            revision: Some(revision),
            manifest: Some(manifest),
        })?;
        if value.len() > MAX_TRIGGER_ROW_BYTES {
            return Err(ControlError::Capacity(format!(
                "queued trigger snapshot for job {job_id} is {} bytes, above the {MAX_TRIGGER_ROW_BYTES}-byte row limit",
                value.len()
            )));
        }
        total_snapshot_bytes = total_snapshot_bytes
            .checked_add(value.len())
            .ok_or_else(|| ControlError::Capacity("trigger snapshot byte count overflow".into()))?;
        if total_snapshot_bytes > MAX_TRIGGER_SNAPSHOT_BYTES_PER_UPDATE {
            return Err(ControlError::Capacity(format!(
                "pointer update would write {total_snapshot_bytes} bytes of trigger snapshots, above the {MAX_TRIGGER_SNAPSHOT_BYTES_PER_UPDATE}-byte aggregate limit"
            )));
        }
        intents.push((key, value));
    }
    drop(pointer_heads);
    drop(events);

    let mut queue = txn.open_table(TRIGGER_QUEUE).map_err(db_err)?;
    let mut new_rows = 0u64;
    for (key, _) in &intents {
        if queue.get(key.as_slice()).map_err(db_err)?.is_none() {
            new_rows = new_rows.saturating_add(1);
        }
    }
    if queue.len().map_err(db_err)?.saturating_add(new_rows) > MAX_TRIGGER_QUEUE {
        return Err(ControlError::Capacity(format!(
            "pointer trigger queue is full ({MAX_TRIGGER_QUEUE} intents); drain the worker queue before updating this pointer"
        )));
    }
    for (key, value) in &intents {
        queue
            .insert(key.as_slice(), value.as_slice())
            .map_err(db_err)?;
    }
    Ok(intents.len() as u32)
}

fn pointer_trigger_key(pointer_id: &str, pointer_seq: u64, job_id: &str) -> Vec<u8> {
    let pointer = pointer_id.as_bytes();
    let job = job_id.as_bytes();
    let mut key = Vec::with_capacity(1 + 4 + pointer.len() + 8 + 4 + job.len());
    key.push(b'p');
    key.extend_from_slice(&(pointer.len() as u32).to_be_bytes());
    key.extend_from_slice(pointer);
    key.extend_from_slice(&pointer_seq.to_be_bytes());
    key.extend_from_slice(&(job.len() as u32).to_be_bytes());
    key.extend_from_slice(job);
    key
}

/// Job event types
///
/// `Created` and `Updated` carry `prev` for the same reason
/// [`dag_core::PinEvent::prev`] does, and it matters more here: a job spec
/// names a `code_ref` and carries adapter `config`, so a spec an attacker
/// chose is the closest thing in this system to arbitrary instruction. Job
/// events live in the content store as ordinary entries, and
/// [`JobLog::rebuild_from_store`] recovers specs by *decoding chunks* — so
/// without a chain, anything that can write a chunk (an unauthenticated
/// `POST /api/chunks`, a `Sync.PutChunk`, a hostile sync source) could plant
/// an `Updated` with a far-future `ts`, and the next operator recovery would
/// sort it last and adopt its spec. `prev` makes the order the chain's rather
/// than the timestamp's, and a graft has to name a real event.
///
/// Skipped on the wire when absent, so every `Created` written before this
/// field existed encodes to exactly the bytes it always did, and keeps the CID
/// it was stored and protected under (I1). There is a golden test below.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum JobEvent {
    /// Job created. Always the root of a chain, so `prev` is `None`.
    Created {
        spec: JobSpec,
        ts: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev: Option<Cid>,
    },
    /// Job triggered.
    ///
    /// Nothing writes these: [`JobLog::trigger_job`] records a run instead,
    /// and the runs table is the authority on how many triggers happened. The
    /// variant is kept because it decodes historical data, and because a
    /// recovered one is *reported* rather than silently dropped — it names no
    /// job, so it cannot be filed.
    Triggered { reason: String, ts: i64 },
    /// Job spec replaced. `prev` names the event it supersedes.
    Updated {
        spec: JobSpec,
        ts: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev: Option<Cid>,
    },
}

impl JobEvent {
    /// The event this one supersedes, or `None` for a chain root.
    fn prev(&self) -> Option<&Cid> {
        match self {
            JobEvent::Created { prev, .. } | JobEvent::Updated { prev, .. } => prev.as_ref(),
            JobEvent::Triggered { .. } => None,
        }
    }

    /// When this event was written (POSIX seconds).
    fn ts(&self) -> i64 {
        match self {
            JobEvent::Created { ts, .. }
            | JobEvent::Updated { ts, .. }
            | JobEvent::Triggered { ts, .. } => *ts,
        }
    }

    /// The spec this event carries, if it carries one.
    pub(crate) fn spec(&self) -> Option<&JobSpec> {
        match self {
            JobEvent::Created { spec, .. } | JobEvent::Updated { spec, .. } => Some(spec),
            JobEvent::Triggered { .. } => None,
        }
    }
}

/// Decode one immutable job event through the common allocation ceiling.
pub(crate) fn decode_job_event(bytes: &[u8]) -> Result<JobEvent> {
    if bytes.len() > MAX_JOB_EVENT_PAYLOAD_BYTES {
        return Err(ControlError::Invalid(format!(
            "job event payload is {} bytes, above the {}-byte limit",
            bytes.len(),
            MAX_JOB_EVENT_PAYLOAD_BYTES
        )));
    }
    cbor_decode(bytes)
}

/// Job head (cached current state)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JobHead {
    pub job_id: JobId,
    pub spec: JobSpec,
    pub seq: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub trigger_count: u64,
}

/// One job's recovered events, as `(timestamp, event entry CID, event)`.
///
/// Job events carry no sequence number of their own — positions are the
/// events table's, assigned from the recovered order. That order comes from
/// [`order_chain`], which follows `prev` links; the timestamp is carried for
/// the head's `created_at`/`updated_at` and is never allowed to decide order,
/// because whoever wrote the chunk chose it.
type JobChain = Vec<(i64, Cid, JobEvent)>;

/// Put one job's store-recovered events into chain order, or explain why they
/// are not a chain.
///
/// This is the gate that makes [`JobLog::rebuild_from_store`] safe to run
/// against a store anyone can write to. It used to sort by `ts`, which meant a
/// single planted `Updated { ts: i64::MAX }` chunk sorted last, became the
/// recovered spec, and rewrote the job's `code_ref` and `config` the next time
/// an operator recovered a directory. Following `prev` instead means a graft
/// has to name the CID of a real event, and anything that does not hang off
/// the `Created` root is refused rather than ranked.
///
/// Refusal is whole-job on purpose: a fork or a stray event means the log no
/// longer says one thing, and picking a branch is exactly the judgement that
/// let the forgery in. The reason is reported so an operator can look.
fn order_chain(job_id: &str, events: JobChain) -> Result<JobChain, String> {
    use std::collections::{HashMap, HashSet};

    // The same entry offered twice is one event, not a fork.
    let mut events = events;
    let mut seen_cids = HashSet::new();
    events.retain(|(_, cid, _)| seen_cids.insert(cid.clone()));

    let mut roots: Vec<usize> = Vec::new();
    let mut successors: HashMap<Cid, Vec<usize>> = HashMap::new();
    for (i, (_, _, event)) in events.iter().enumerate() {
        match event.prev() {
            None => roots.push(i),
            Some(prev) => successors.entry(prev.clone()).or_default().push(i),
        }
    }

    let hexes = |idx: &[usize]| -> String {
        idx.iter()
            .map(|i| events[*i].1.to_hex())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let root = match roots.as_slice() {
        [only] => *only,
        [] => return Err(format!("{}: no Created event to start the chain", job_id)),
        many => {
            return Err(format!(
                "{}: {} events claim to start the chain ({}); refusing to guess which is the job",
                job_id,
                many.len(),
                hexes(many)
            ))
        }
    };
    if !matches!(events[root].2, JobEvent::Created { .. }) {
        return Err(format!(
            "{}: the chain starts at {}, which is not a Created event",
            job_id, events[root].1
        ));
    }

    let mut order = vec![root];
    let mut visited = HashSet::from([root]);
    loop {
        let tail = &events[*order.last().expect("order is never empty")].1;
        let next = match successors.get(tail).map(Vec::as_slice) {
            None | Some([]) => break,
            Some([only]) => *only,
            Some(many) => {
                return Err(format!(
                    "{}: {} events chain to {}, so the history forks ({}); refusing to adopt \
                     either branch",
                    job_id,
                    many.len(),
                    tail,
                    hexes(many)
                ))
            }
        };
        // Unreachable while CIDs are content hashes (a cycle would need one),
        // but a scan must not be made to spin by whatever it is handed.
        if !visited.insert(next) {
            return Err(format!(
                "{}: the event chain loops back to {}",
                job_id, events[next].1
            ));
        }
        order.push(next);
    }

    if order.len() != events.len() {
        let stray: Vec<String> = (0..events.len())
            .filter(|i| !visited.contains(i))
            .map(|i| events[i].1.to_hex())
            .collect();
        return Err(format!(
            "{}: {} event(s) do not chain to the Created event ({}); this log never wrote an \
             unchained event, so refusing the whole job",
            job_id,
            stray.len(),
            stray.join(", ")
        ));
    }

    let mut slots: Vec<Option<(i64, Cid, JobEvent)>> = events.into_iter().map(Some).collect();
    Ok(order
        .into_iter()
        .map(|i| slots[i].take().expect("each index is visited once"))
        .collect())
}

/// Check that events already filed in the events table form a chain.
///
/// The store scan is where forgeries enter, but the table is only as
/// trustworthy as whatever filed it — including an older build's scan, which
/// accepted anything that decoded. `events` must already be sorted by
/// sequence and contiguous from 1.
fn validate_filed_chain(
    job_id: &str,
    events: &[(u64, Cid, JobEvent)],
    legacy_prev_cutoff: Option<u64>,
) -> Result<(), String> {
    for (i, (seq, _, event)) in events.iter().enumerate() {
        if let Some(spec) = event.spec() {
            validate_job_spec(spec)
                .map_err(|e| format!("seq {seq} contains an invalid job spec: {e}"))?;
            if spec.job_id.as_ref() != job_id {
                return Err(format!(
                    "seq {seq} is filed under job {job_id:?} but its spec names {:?}",
                    spec.job_id.as_ref()
                ));
            }
        }
        if i == 0 {
            if !matches!(event, JobEvent::Created { .. }) {
                return Err("seq 1 is not a Created event".to_string());
            }
            if let Some(prev) = event.prev() {
                return Err(format!("seq 1 must have no `prev`, but names {}", prev));
            }
            continue;
        }
        let expected = &events[i - 1].1;
        match event.prev() {
            Some(claimed) if claimed == expected => {}
            Some(claimed) => {
                return Err(format!(
                    "seq {} chains to {}, but seq {} is {}",
                    seq,
                    claimed,
                    seq - 1,
                    expected
                ))
            }
            None => {
                if matches!(event, JobEvent::Updated { .. })
                    && legacy_prev_cutoff.is_some_and(|cutoff| *seq <= cutoff)
                {
                    continue;
                }
                return Err(format!(
                    "seq {} has no `prev`; nothing in this log ever wrote an unchained event \
                     past the first",
                    seq
                ));
            }
        }
    }
    Ok(())
}

/// Report from a rebuild driven by a content-store scan.
///
/// The counts exist because the scan *identifies* events by decoding them,
/// which is a guess however strict: anything it declines has to be visible,
/// or a recovery that quietly restored half a deployment would look identical
/// to one that restored all of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct JobStoreRebuildReport {
    /// Chunks examined in the content store.
    pub chunks_scanned: usize,
    /// Chunks whose payload decoded as a spec-carrying [`JobEvent`].
    pub events_found: usize,
    /// Events belonging to a job that failed validation and was not filed.
    pub events_skipped: usize,
    /// Events the store held that the events table did *not* already have, and
    /// which this scan filed. When a reconcile runs after a table rebuild, a
    /// non-zero count is the signal that the table was behind the store — the
    /// truncated-table case (seam 1) the plain rebuild reported success over.
    pub events_added: usize,
    /// Why each rejected job was rejected, one line per job.
    pub skipped: Vec<String>,
    /// Job heads written.
    pub heads_rebuilt: u32,
}

/// A table rebuild reconciled against the content store.
///
/// The job counterpart of [`crate::PointerReconcileReport`]. Only specs come
/// back through a store scan — runs, the effect cache and pointer
/// subscriptions live only in the database — so this heals a job spec the
/// truncated table forgot, nothing more.
#[derive(Debug, Clone, serde::Serialize)]
pub struct JobReconcileReport {
    /// The events-table rebuild.
    pub table: JobRebuildReport,
    /// The store scan that reconciled anything the table lacked.
    pub store: JobStoreRebuildReport,
}

/// Report from a job log rebuild.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct JobRebuildReport {
    /// Jobs found in the event log.
    pub jobs_processed: u32,
    /// Heads rewritten from events and runs.
    pub heads_rebuilt: u32,
    /// Jobs whose event chain failed validation.
    pub validation_errors: u32,
}

fn db_err(e: impl std::fmt::Display) -> ControlError {
    ControlError::db("job log", e)
}

fn next_pending_order(txn: &WriteTransaction) -> Result<u64> {
    let mut meta = txn.open_table(RUN_QUEUE_META).map_err(db_err)?;
    let current = {
        let value = meta.get(NEXT_PENDING_ORDER_KEY).map_err(db_err)?;
        value.map(|value| value.value()).unwrap_or(0)
    };
    let next = current
        .checked_add(1)
        .ok_or_else(|| JobError::InvalidSpec("pending-run order exhausted".to_string()))?;
    meta.insert(NEXT_PENDING_ORDER_KEY, next).map_err(db_err)?;
    Ok(next)
}

fn ensure_pending_capacity(txn: &WriteTransaction) -> Result<()> {
    ensure_pending_capacity_at(txn, MAX_PENDING_RUNS)
}

fn ensure_pending_capacity_at(txn: &WriteTransaction, limit: u64) -> Result<()> {
    let pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
    if pending.len().map_err(db_err)? >= limit {
        return Err(ControlError::Capacity(format!(
            "pending job queue is full ({limit} runs); execute or cancel queued work before triggering more"
        )));
    }
    Ok(())
}

fn validate_manifest_for_spec(spec: &JobSpec, manifest: &InputManifest) -> Result<()> {
    if manifest.static_inputs != spec.inputs.static_inputs {
        return Err(JobError::InvalidSpec(
            "resolved manifest static inputs do not match the queued job revision".to_string(),
        )
        .into());
    }
    if manifest.pointer_heads.len() != spec.inputs.pointer_inputs.len()
        || manifest
            .pointer_heads
            .iter()
            .zip(&spec.inputs.pointer_inputs)
            .any(|(resolved, declared)| resolved.pointer_id != *declared)
    {
        return Err(JobError::InvalidSpec(
            "resolved manifest pointer inputs do not match the queued job revision".to_string(),
        )
        .into());
    }
    Ok(())
}

fn validate_output_shape(outputs: &[(String, Cid)]) -> Result<()> {
    if outputs.len() > dag_core::MAX_JOB_DECLARED_OUTPUTS {
        return Err(JobError::InvalidSpec(format!(
            "output count {} exceeds {}",
            outputs.len(),
            dag_core::MAX_JOB_DECLARED_OUTPUTS
        ))
        .into());
    }
    let mut names = std::collections::HashSet::with_capacity(outputs.len());
    for (name, _) in outputs {
        if name.is_empty()
            || name.len() > dag_core::MAX_JOB_NAME_BYTES
            || name.chars().any(char::is_control)
            || !names.insert(name)
        {
            return Err(JobError::InvalidSpec(format!(
                "invalid or duplicate output name {name:?}"
            ))
            .into());
        }
    }
    Ok(())
}

fn validate_outputs_for_spec(spec: &JobSpec, outputs: &[(String, Cid)]) -> Result<()> {
    validate_output_shape(outputs)?;
    if outputs.len() != spec.declared_outputs.len()
        || outputs
            .iter()
            .zip(&spec.declared_outputs)
            .any(|((actual, _), declared)| actual != declared)
    {
        return Err(JobError::ExecutionFailed(
            "successful run outputs must exactly match the declared names and order".to_string(),
        )
        .into());
    }
    Ok(())
}

fn bounded_failure_message(mut message: String) -> String {
    if message.len() <= MAX_RUN_FAILURE_MESSAGE_BYTES {
        return message;
    }
    let mut end = MAX_RUN_FAILURE_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message
}

fn bounded_terminal_status(status: RunStatus) -> RunStatus {
    match status {
        RunStatus::Failed { message } => RunStatus::Failed {
            message: bounded_failure_message(message),
        },
        other => other,
    }
}

fn static_manifest(spec: &JobSpec) -> Result<InputManifest> {
    if !spec.inputs.pointer_inputs.is_empty() {
        return Err(JobError::InvalidSpec(
            "this enqueue path cannot resolve pointer inputs; use Control or Scheduler so the manifest is bound before queue admission".to_string(),
        )
        .into());
    }
    Ok(InputManifest {
        static_inputs: spec.inputs.static_inputs.clone(),
        pointer_heads: Vec::new(),
        resolved_at_unix: current_timestamp(),
    })
}

enum TriggerBinding<'a> {
    Resolve(&'a dyn Fn(&JobSpec) -> Result<InputManifest>),
    Frozen {
        revision: &'a JobRevision,
        manifest: &'a InputManifest,
    },
}

fn validate_revision_material(
    db: &Database,
    store: &dyn ContentStore,
    job_id: &JobId,
    revision: &JobRevision,
    manifest: &InputManifest,
) -> Result<JobSpec> {
    if revision.event_seq == 0 {
        return Err(JobError::ExecutionFailed("job revision sequence is zero".into()).into());
    }
    let event_key = keys::encode_event_key(job_id.as_ref(), revision.event_seq);
    let txn = db.begin_read().map_err(db_err)?;
    let events = txn.open_table(JOB_EVENTS).map_err(db_err)?;
    let filed = events
        .get(event_key.as_slice())
        .map_err(db_err)?
        .ok_or_else(|| {
            JobError::ExecutionFailed(format!(
                "job revision {} is no longer filed",
                revision.event_seq
            ))
        })?;
    if filed.value() != revision.event_cid.as_bytes() {
        return Err(JobError::ExecutionFailed(
            "job revision CID does not match the filed event".to_string(),
        )
        .into());
    }
    drop(filed);
    drop(events);
    drop(txn);

    let entry = store.get_entry(&revision.event_cid)?;
    let event = decode_job_event(&entry.payload)?;
    let spec = event.spec().ok_or_else(|| {
        JobError::ExecutionFailed("job revision event carries no job specification".to_string())
    })?;
    validate_job_spec(spec)?;
    if spec.job_id != *job_id {
        return Err(JobError::ExecutionFailed(
            "job revision event names a different job".to_string(),
        )
        .into());
    }
    if spec.code_ref != revision.code_ref {
        return Err(JobError::ExecutionFailed(
            "queued adapter does not match the immutable job revision".to_string(),
        )
        .into());
    }
    validate_manifest_for_spec(spec, manifest)?;
    Ok(spec.clone())
}

fn validate_run_revision(db: &Database, store: &dyn ContentStore, run: &JobRun) -> Result<JobSpec> {
    let revision = run.revision.as_ref().ok_or_else(|| {
        JobError::ExecutionFailed(
            "queued run has no immutable job revision; refusing to infer one".to_string(),
        )
    })?;
    validate_revision_material(db, store, &run.job_id, revision, &run.manifest)
}

fn remove_pending_indexes(txn: &WriteTransaction, run_key: &[u8], run: &JobRun) -> Result<()> {
    let order = {
        let mut pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
        let order = pending
            .get(run_key)
            .map_err(db_err)?
            .map(|value| value.value());
        pending.remove(run_key).map_err(db_err)?;
        order
    };
    if let Some(order) = order {
        txn.open_table(PENDING_BY_ORDER)
            .map_err(db_err)?
            .remove(order)
            .map_err(db_err)?;
        if let Some(revision) = &run.revision {
            let adapter_key = keys::encode_adapter_order_key(&revision.code_ref, order);
            txn.open_table(PENDING_BY_ADAPTER)
                .map_err(db_err)?
                .remove(adapter_key.as_slice())
                .map_err(db_err)?;
        }
    }
    Ok(())
}

fn quarantine_row(txn: &WriteTransaction, key: &[u8], reason: &str) -> Result<()> {
    let mut quarantine = txn.open_table(RUN_QUARANTINE).map_err(db_err)?;
    if quarantine.get(key).map_err(db_err)?.is_none()
        && quarantine.len().map_err(db_err)? >= MAX_RUN_QUARANTINE
    {
        return Err(ControlError::Capacity(format!(
            "job run quarantine is full ({MAX_RUN_QUARANTINE} rows); repair it before opening this directory"
        )));
    }
    quarantine.insert(key, reason.as_bytes()).map_err(db_err)?;
    Ok(())
}

/// One-time schema-5 migration. It may scan terminal history, but does so in
/// fixed-size batches and never lets a corrupt terminal row prevent startup.
/// Any pre-v5 active row is failed: it has no authoritative revision and
/// choosing the current head could execute a different program.
fn migrate_pre_v5_job_state(db: &Database) -> Result<()> {
    if !crate::schema::job_v5_migration_pending(db)? {
        return Ok(());
    }

    use std::ops::Bound::{Excluded, Unbounded};
    let mut after: Option<Vec<u8>> = None;
    loop {
        let batch = {
            let txn = db.begin_read().map_err(db_err)?;
            let runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            let pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
            let running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
            let range = (after.as_deref().map_or(Unbounded, Excluded), Unbounded);
            let mut out = Vec::with_capacity(512);
            for row in runs.range::<&[u8]>(range).map_err(db_err)?.take(512) {
                let (key, value) = row.map_err(db_err)?;
                let key = key.value().to_vec();
                let indexed_active = pending.get(key.as_slice()).map_err(db_err)?.is_some()
                    || running.get(key.as_slice()).map_err(db_err)?.is_some();
                let decoded = decode_job_run(value.value());
                out.push((key, indexed_active, decoded));
            }
            out
        };
        if batch.is_empty() {
            break;
        }
        after = batch.last().map(|(key, _, _)| key.clone());

        let now = current_timestamp();
        let txn = db.begin_write().map_err(db_err)?;
        {
            let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            let mut watermarks = txn.open_table(JOB_RUN_WATERMARKS).map_err(db_err)?;
            for (key, indexed_active, decoded) in batch {
                let decoded_key = keys::decode_event_key(&key);
                if let Ok((job_id, seq)) = &decoded_key {
                    let previous = watermarks
                        .get(job_id.as_bytes())
                        .map_err(db_err)?
                        .map(|value| value.value())
                        .unwrap_or(0);
                    if *seq > previous {
                        watermarks.insert(job_id.as_bytes(), *seq).map_err(db_err)?;
                    }
                }
                if let Err(error) = &decoded_key {
                    quarantine_row(&txn, &key, &format!("invalid run key: {error}"))?;
                }
                match decoded {
                    Ok(mut run)
                        if matches!(run.status, RunStatus::Pending | RunStatus::Running) =>
                    {
                        run.status = bounded_terminal_status(RunStatus::Failed {
                            message: "run was active during the schema-5 upgrade and has no immutable job revision; execution was refused".to_string(),
                        });
                        run.finished_at_unix = Some(now);
                        let bytes = cbor_encode(&run)?;
                        runs.insert(key.as_slice(), bytes.as_slice())
                            .map_err(db_err)?;
                    }
                    Ok(_) => {}
                    Err(error) if indexed_active => {
                        quarantine_row(&txn, &key, &format!("invalid pre-v5 active row: {error}"))?;
                    }
                    Err(_) => {
                        // A corrupt terminal history row remains inspectable
                        // for repair but does not block normal startup.
                    }
                }
            }
        }
        txn.commit().map_err(db_err)?;
    }

    let txn = db.begin_write().map_err(db_err)?;
    {
        txn.open_table(PENDING_RUNS)
            .map_err(db_err)?
            .retain(|_, _| false)
            .map_err(db_err)?;
        txn.open_table(PENDING_BY_ADAPTER)
            .map_err(db_err)?
            .retain(|_, _| false)
            .map_err(db_err)?;
        txn.open_table(PENDING_BY_ORDER)
            .map_err(db_err)?
            .retain(|_, _| false)
            .map_err(db_err)?;
        txn.open_table(RUNNING_RUNS)
            .map_err(db_err)?
            .retain(|_, _| false)
            .map_err(db_err)?;
        txn.open_table(RUN_LEASES)
            .map_err(db_err)?
            .retain(|_, _| false)
            .map_err(db_err)?;
        crate::schema::finish_job_v5_migration(&txn)?;
    }
    txn.commit().map_err(db_err)
}

/// Validate only the bounded active indexes on a current schema. Because redb
/// grants one process exclusive ownership, every row left Running belongs to
/// a dead prior owner and is failed immediately even if its wall-clock lease
/// had not yet expired.
fn reconcile_current_active_indexes(db: &Database, store: &dyn ContentStore) -> Result<()> {
    let (pending_rows, running_rows) = {
        let txn = db.begin_read().map_err(db_err)?;
        let pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
        let running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
        if pending.len().map_err(db_err)? > MAX_PENDING_RUNS {
            return Err(ControlError::Capacity(format!(
                "pending job queue exceeds the schema-5 limit of {MAX_PENDING_RUNS}"
            )));
        }
        if running.len().map_err(db_err)? > MAX_PENDING_RUNS {
            return Err(ControlError::Capacity(format!(
                "running job index exceeds the safety limit of {MAX_PENDING_RUNS}"
            )));
        }
        let pending_rows = pending
            .range::<&[u8]>(..)
            .map_err(db_err)?
            .map(|row| {
                row.map(|(key, order)| (key.value().to_vec(), order.value()))
                    .map_err(db_err)
            })
            .collect::<Result<Vec<_>>>()?;
        let running_rows = running
            .range::<&[u8]>(..)
            .map_err(db_err)?
            .map(|row| row.map(|(key, _)| key.value().to_vec()).map_err(db_err))
            .collect::<Result<Vec<_>>>()?;
        (pending_rows, running_rows)
    };

    let mut valid_pending = Vec::with_capacity(pending_rows.len());
    let mut invalid_pending = Vec::new();
    let mut seen_orders = std::collections::HashSet::new();
    for (key, order) in pending_rows {
        if !seen_orders.insert(order) {
            invalid_pending.push((key, format!("duplicate pending enqueue order {order}")));
            continue;
        }
        let validation = (|| -> Result<(JobRun, Vec<u8>)> {
            let txn = db.begin_read().map_err(db_err)?;
            let runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            let bytes = runs.get(key.as_slice()).map_err(db_err)?.ok_or_else(|| {
                ControlError::Database("pending index names a missing run".into())
            })?;
            let run = decode_job_run(bytes.value())?;
            let (key_job, key_run) = keys::decode_event_key(&key)?;
            if run.job_id.as_ref() != key_job || run.run_id.0 != key_run {
                return Err(ControlError::Database(
                    "pending run's embedded IDs do not match its key".into(),
                ));
            }
            if !matches!(run.status, RunStatus::Pending) {
                return Err(ControlError::Database(
                    "pending index names a non-pending run".into(),
                ));
            }
            validate_run_revision(db, store, &run)?;
            let code_ref = run
                .revision
                .as_ref()
                .expect("validated above")
                .code_ref
                .clone();
            Ok((run, keys::encode_adapter_order_key(&code_ref, order)))
        })();
        match validation {
            Ok((run, adapter_key)) => valid_pending.push((key, order, run, adapter_key)),
            Err(error) => invalid_pending.push((key, error.to_string())),
        }
    }

    let now = current_timestamp();
    let txn = db.begin_write().map_err(db_err)?;
    {
        let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
        let mut pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
        let mut running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
        let mut by_adapter = txn.open_table(PENDING_BY_ADAPTER).map_err(db_err)?;
        let mut by_order = txn.open_table(PENDING_BY_ORDER).map_err(db_err)?;
        let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
        by_adapter.retain(|_, _| false).map_err(db_err)?;
        by_order.retain(|_, _| false).map_err(db_err)?;

        for (key, reason) in invalid_pending {
            quarantine_row(&txn, &key, &reason)?;
            pending.remove(key.as_slice()).map_err(db_err)?;
            leases.remove(key.as_slice()).map_err(db_err)?;
            let existing = runs
                .get(key.as_slice())
                .map_err(db_err)?
                .map(|value| decode_job_run(value.value()));
            if let Some(Ok(mut run)) = existing {
                run.status = bounded_terminal_status(RunStatus::Failed {
                    message: format!("invalid queued run refused during startup: {reason}"),
                });
                run.finished_at_unix = Some(now);
                let bytes = cbor_encode(&run)?;
                runs.insert(key.as_slice(), bytes.as_slice())
                    .map_err(db_err)?;
            }
        }
        let mut max_order = 0u64;
        for (key, order, _run, adapter_key) in valid_pending {
            max_order = max_order.max(order);
            by_adapter
                .insert(adapter_key.as_slice(), key.as_slice())
                .map_err(db_err)?;
            by_order.insert(order, key.as_slice()).map_err(db_err)?;
        }
        let mut meta = txn.open_table(RUN_QUEUE_META).map_err(db_err)?;
        let existing_next = meta
            .get(NEXT_PENDING_ORDER_KEY)
            .map_err(db_err)?
            .map(|value| value.value())
            .unwrap_or(0);
        meta.insert(NEXT_PENDING_ORDER_KEY, existing_next.max(max_order))
            .map_err(db_err)?;
        for key in running_rows {
            let existing = runs
                .get(key.as_slice())
                .map_err(db_err)?
                .map(|value| decode_job_run(value.value()));
            if let Some(decoded) = existing {
                match decoded {
                    Ok(mut run)
                        if keys::decode_event_key(&key).is_ok_and(|(job, seq)| {
                            run.job_id.as_ref() == job && run.run_id.0 == seq
                        }) && matches!(run.status, RunStatus::Running) =>
                    {
                        run.status = bounded_terminal_status(RunStatus::Failed {
                            message: "the process owning this running job exited; automatic retry is disabled to avoid duplicating side effects".to_string(),
                        });
                        run.finished_at_unix = Some(now);
                        let bytes = cbor_encode(&run)?;
                        runs.insert(key.as_slice(), bytes.as_slice())
                            .map_err(db_err)?;
                    }
                    Ok(_) => quarantine_row(
                        &txn,
                        &key,
                        "running index row has mismatched IDs or status",
                    )?,
                    Err(error) => quarantine_row(
                        &txn,
                        &key,
                        &format!("invalid running row at startup: {error}"),
                    )?,
                }
            } else {
                quarantine_row(&txn, &key, "running index names a missing run")?;
            }
            running.remove(key.as_slice()).map_err(db_err)?;
            leases.remove(key.as_slice()).map_err(db_err)?;
        }
        // Pending claims belong to the prior process too. No adapter had
        // started, so releasing them permits a fresh exact claim.
        leases.retain(|_, _| false).map_err(db_err)?;
    }
    txn.commit().map_err(db_err)
}

/// Job log managing all job state
pub struct JobLog {
    /// Shared control-plane database
    db: Arc<Database>,
    store: Arc<dyn ContentStore>,
    /// Serialises read-modify-write between transactions.
    write_lock: Mutex<()>,
    /// Cross-log recovery barrier for the derived effect-claim lookup.
    mutation_gate: crate::MutationGate,
    event_bus: Option<crate::events::EventBus>,
}

/// Encoded replacement rows for the derived effect-claim lookup.
pub(crate) struct ClaimRebuildPlan {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    count: u32,
}

/// Encoded effect-claim updates for only the keys implicated by one sync.
/// Applying this plan preserves every unrelated lookup row.
pub(crate) struct ClaimMergePlan {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    added: u32,
}

impl ClaimRebuildPlan {
    pub(crate) fn count(&self) -> u32 {
        self.count
    }
}

impl ClaimMergePlan {
    pub(crate) fn added(&self) -> u32 {
        self.added
    }
}

impl JobLog {
    /// Rows a full recovery scans or replaces in job/claim state.
    pub(crate) fn recovery_row_count(&self) -> Result<u64> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let counts = [
            txn.open_table(JOB_EVENTS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
            txn.open_table(JOB_HEADS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
            txn.open_table(JOB_RUNS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
            txn.open_table(JOB_RUN_WATERMARKS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
            txn.open_table(TRIGGER_QUEUE)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
            txn.open_table(PENDING_RUNS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
            txn.open_table(RUNNING_RUNS)
                .map_err(db_err)?
                .len()
                .map_err(db_err)?,
        ];
        let mut total = counts.into_iter().try_fold(0u64, |total, count| {
            total
                .checked_add(count)
                .ok_or_else(|| ControlError::Capacity("job recovery row count overflow".into()))
        })?;
        // Count the claim CIDs represented by each derived row, not merely
        // the number of effect keys. One key may otherwise hide thousands of
        // decoded/indexed entries behind a single apparent control row.
        let claims = txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
        for row in claims.range::<&[u8]>(..).map_err(db_err)? {
            let (_, value) = row.map_err(db_err)?;
            // This is derived state that recovery replaces. A legacy or
            // damaged oversized row must make GC fail closed, but it must not
            // make recovery itself impossible. Count it conservatively as one
            // over the supported per-key maximum without allocating it.
            let represented = decode_claim_index_row(value.value())
                .map(|claims| claims.len())
                .unwrap_or(MAX_EFFECT_CLAIMS_PER_KEY + 1);
            let count = u64::try_from(represented)
                .map_err(|_| ControlError::Capacity("claim index count overflow".into()))?;
            total = total
                .checked_add(count)
                .ok_or_else(|| ControlError::Capacity("job recovery row count overflow".into()))?;
        }
        Ok(total)
    }

    /// Full-DAG roots required by work that has been authorized but has not
    /// reached a terminal run state.
    ///
    /// Trigger intents carry enqueue-time snapshots; pending/running records
    /// carry admission-time snapshots. GC must retain both even after pointer
    /// heads advance. Every row is bounded before decoding and every snapshot
    /// is checked against its immutable filed job event. Missing, legacy, or
    /// corrupt active material refuses collection instead of silently
    /// shrinking the protected set.
    pub(crate) fn active_work_retention_roots(
        &self,
        max_root_references: usize,
    ) -> Result<Vec<Cid>> {
        self.active_work_retention_roots_with_limits(
            MAX_ACTIVE_WORK_SNAPSHOT_BYTES,
            max_root_references,
        )
    }

    fn active_work_retention_roots_with_limits(
        &self,
        max_snapshot_bytes: usize,
        max_root_references: usize,
    ) -> Result<Vec<Cid>> {
        fn charge(total: &mut usize, row_bytes: usize, limit: usize) -> Result<()> {
            *total = total.checked_add(row_bytes).ok_or_else(|| {
                ControlError::Capacity("active-work snapshot byte count overflow".into())
            })?;
            if *total > limit {
                return Err(ControlError::Capacity(format!(
                    "active work needs to decode {total} bytes of trigger/run snapshots, above the {limit}-byte GC retention limit"
                )));
            }
            Ok(())
        }

        let txn = self.db.begin_read().map_err(db_err)?;
        let queue = txn.open_table(TRIGGER_QUEUE).map_err(db_err)?;
        let pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
        let running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
        let queue_len = queue.len().map_err(db_err)?;
        let pending_len = pending.len().map_err(db_err)?;
        let running_len = running.len().map_err(db_err)?;
        let active_rows = queue_len
            .checked_add(pending_len)
            .and_then(|rows| rows.checked_add(running_len))
            .ok_or_else(|| ControlError::Capacity("active-work row count overflow".into()))?;
        let active_limit = MAX_TRIGGER_QUEUE.saturating_add(MAX_PENDING_RUNS.saturating_mul(2));
        if active_rows > active_limit {
            return Err(ControlError::Capacity(format!(
                "active work has {active_rows} trigger/pending/running rows, above the {active_limit}-row GC retention limit"
            )));
        }

        let mut snapshot_bytes = 0usize;
        let mut roots = Vec::new();
        for row in queue.range::<&[u8]>(..).map_err(db_err)? {
            let (_, value) = row.map_err(db_err)?;
            charge(&mut snapshot_bytes, value.value().len(), max_snapshot_bytes)?;
            let trigger = decode_queued_trigger(value.value())?;
            drop(value);
            let revision = trigger.revision.ok_or_else(|| {
                ControlError::Invalid(
                    "garbage collection refused: an active legacy trigger intent has no immutable job revision"
                        .into(),
                )
            })?;
            let manifest = trigger.manifest.ok_or_else(|| {
                ControlError::Invalid(
                    "garbage collection refused: an active legacy trigger intent has no immutable input manifest"
                        .into(),
                )
            })?;
            self.append_active_snapshot_roots(
                &mut roots,
                max_root_references,
                &trigger.job_id,
                &revision,
                manifest,
            )?;
        }

        drop(queue);
        let runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
        for row in pending.range::<&[u8]>(..).map_err(db_err)? {
            let (key, _) = row.map_err(db_err)?;
            if running.get(key.value()).map_err(db_err)?.is_some() {
                return Err(ControlError::Database(
                    "one job run is indexed as both pending and running".into(),
                ));
            }
            self.append_indexed_run_roots(
                &runs,
                key.value(),
                false,
                (&mut snapshot_bytes, max_snapshot_bytes),
                (&mut roots, max_root_references),
            )?;
        }
        drop(pending);
        for row in running.range::<&[u8]>(..).map_err(db_err)? {
            let (key, _) = row.map_err(db_err)?;
            self.append_indexed_run_roots(
                &runs,
                key.value(),
                true,
                (&mut snapshot_bytes, max_snapshot_bytes),
                (&mut roots, max_root_references),
            )?;
        }
        Ok(roots)
    }

    fn append_indexed_run_roots<T>(
        &self,
        runs: &T,
        key: &[u8],
        expected_running: bool,
        snapshot_budget: (&mut usize, usize),
        root_budget: (&mut Vec<Cid>, usize),
    ) -> Result<()>
    where
        T: ReadableTable<&'static [u8], &'static [u8]>,
    {
        let (snapshot_bytes, max_snapshot_bytes) = snapshot_budget;
        let (roots, max_root_references) = root_budget;
        let (key_job, key_seq) = keys::decode_event_key(key)?;
        let bytes = runs
            .get(key)
            .map_err(db_err)?
            .ok_or_else(|| ControlError::Database("active job index names a missing run".into()))?;
        *snapshot_bytes = snapshot_bytes
            .checked_add(bytes.value().len())
            .ok_or_else(|| {
                ControlError::Capacity("active-work snapshot byte count overflow".into())
            })?;
        if *snapshot_bytes > max_snapshot_bytes {
            return Err(ControlError::Capacity(format!(
                "active work needs to decode {snapshot_bytes} bytes of trigger/run snapshots, above the {max_snapshot_bytes}-byte GC retention limit"
            )));
        }
        let run = decode_job_run(bytes.value())?;
        drop(bytes);
        if run.job_id.as_ref() != key_job || run.run_id.0 != key_seq {
            return Err(ControlError::Database(
                "active job index key disagrees with its run record".into(),
            ));
        }
        if matches!(run.status, RunStatus::Running) != expected_running
            || !matches!(run.status, RunStatus::Pending | RunStatus::Running)
        {
            return Err(ControlError::Database(
                "active job index disagrees with its run status".into(),
            ));
        }
        let revision = run.revision.ok_or_else(|| {
            ControlError::Invalid(
                "garbage collection refused: an active run has no immutable job revision".into(),
            )
        })?;
        self.append_active_snapshot_roots(
            roots,
            max_root_references,
            &run.job_id,
            &revision,
            run.manifest,
        )
    }

    fn append_active_snapshot_roots(
        &self,
        roots: &mut Vec<Cid>,
        max_root_references: usize,
        job_id: &JobId,
        revision: &JobRevision,
        manifest: InputManifest,
    ) -> Result<()> {
        let additional = 1usize
            .checked_add(manifest.static_inputs.len())
            .and_then(|count| count.checked_add(manifest.pointer_heads.len()))
            .ok_or_else(|| {
                ControlError::Capacity("active-work root reference count overflow".into())
            })?;
        let required = roots.len().checked_add(additional).ok_or_else(|| {
            ControlError::Capacity("active-work root reference count overflow".into())
        })?;
        if required > max_root_references {
            return Err(ControlError::Capacity(format!(
                "active work names {required} immutable job/input roots, above the {max_root_references}-root GC retention limit"
            )));
        }
        roots.try_reserve(additional).map_err(|_| {
            ControlError::Capacity(format!(
                "unable to reserve memory for {required} active-work GC roots"
            ))
        })?;
        validate_revision_material(&self.db, self.store.as_ref(), job_id, revision, &manifest)?;
        roots.push(revision.event_cid.clone());
        roots.extend(manifest.static_inputs);
        roots.extend(
            manifest
                .pointer_heads
                .into_iter()
                .map(|pointer| pointer.head_cid),
        );
        Ok(())
    }

    /// Create a new JobLog over the shared control-plane database.
    pub fn new(db: Arc<Database>, store: Arc<dyn ContentStore>) -> Result<Self> {
        // `Control` stamps before constructing subsystems, but embedders and
        // focused tests may construct a JobLog directly. The constructor must
        // still establish schema-5 migration invariants before opening work.
        crate::schema::check_and_stamp(&db)?;
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(JOB_EVENTS).map_err(db_err)?;
        txn.open_table(JOB_HEADS).map_err(db_err)?;
        txn.open_table(JOB_RUNS).map_err(db_err)?;
        txn.open_table(JOB_RUN_WATERMARKS).map_err(db_err)?;
        txn.open_table(PENDING_RUNS).map_err(db_err)?;
        txn.open_table(PENDING_BY_ADAPTER).map_err(db_err)?;
        txn.open_table(PENDING_BY_ORDER).map_err(db_err)?;
        txn.open_table(RUNNING_RUNS).map_err(db_err)?;
        txn.open_table(RUN_QUEUE_META).map_err(db_err)?;
        txn.open_table(EFFECT_CACHE).map_err(db_err)?;
        txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
        txn.open_table(POINTER_SUBSCRIPTIONS).map_err(db_err)?;
        txn.open_table(TRIGGER_QUEUE).map_err(db_err)?;
        txn.open_table(TRIGGER_RECEIPTS).map_err(db_err)?;
        txn.open_table(TRIGGER_DEAD_LETTERS).map_err(db_err)?;
        txn.open_table(RUN_LEASES).map_err(db_err)?;
        txn.open_table(RUN_QUARANTINE).map_err(db_err)?;
        txn.open_table(crate::schema::JOB_LEGACY_PREV_CUTOFFS)
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        migrate_pre_v5_job_state(&db)?;
        reconcile_current_active_indexes(&db, store.as_ref())?;

        Ok(Self {
            db,
            store,
            write_lock: Mutex::new(()),
            mutation_gate: Arc::new(RwLock::new(())),
            event_bus: None,
        })
    }

    /// Use the control plane's cross-log recovery barrier.
    pub(crate) fn with_mutation_gate(mut self, gate: crate::MutationGate) -> Self {
        self.mutation_gate = gate;
        self
    }

    /// Attach an event bus to emit job run events
    pub fn with_event_bus(mut self, bus: crate::events::EventBus) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Emit a JobRun event
    fn emit_run(&self, job: &JobId, run: &RunId, status: RunStatus) {
        if let Some(ref bus) = self.event_bus {
            bus.emit(crate::events::Event::JobRun {
                job: job.to_string(),
                run: run.0.to_string(),
                status,
                ts: current_timestamp(),
            });
        }
    }

    /// Read one value from one table under a read transaction.
    fn read_one(
        &self,
        table_def: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        max_bytes: usize,
        row_name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(table_def).map_err(db_err)?;
        let Some(value) = table.get(key).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > max_bytes {
            return Err(ControlError::Database(format!(
                "{row_name} exceeds {max_bytes} bytes"
            )));
        }
        Ok(Some(value.value().to_vec()))
    }

    /// Read a run without first copying an arbitrarily large corrupt value.
    fn read_run_row(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_RUNS).map_err(db_err)?;
        let Some(value) = table.get(key).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > MAX_JOB_RUN_ROW_BYTES {
            return Err(ControlError::Database(format!(
                "job run row exceeds {MAX_JOB_RUN_ROW_BYTES} bytes"
            )));
        }
        Ok(Some(value.value().to_vec()))
    }

    fn read_job_head_row(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_HEADS).map_err(db_err)?;
        let Some(value) = table.get(key).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > MAX_JOB_HEAD_ROW_BYTES {
            return Err(ControlError::Database(format!(
                "job head row exceeds {MAX_JOB_HEAD_ROW_BYTES} bytes"
            )));
        }
        Ok(Some(value.value().to_vec()))
    }

    /// Read an effect-cache value with its encoded-size contract enforced
    /// before allocation.
    fn read_effect_cache_row(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EFFECT_CACHE).map_err(db_err)?;
        let Some(value) = table.get(key).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > MAX_EFFECT_CACHE_ROW_BYTES {
            return Err(ControlError::Database(format!(
                "effect-cache row exceeds {MAX_EFFECT_CACHE_ROW_BYTES} bytes"
            )));
        }
        Ok(Some(value.value().to_vec()))
    }

    fn legacy_prev_cutoff(&self, job_id: &str) -> Result<Option<u64>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn
            .open_table(crate::schema::JOB_LEGACY_PREV_CUTOFFS)
            .map_err(db_err)?;
        Ok(table
            .get(job_id.as_bytes())
            .map_err(db_err)?
            .map(|value| value.value()))
    }

    /// Create a new job
    pub fn create_job(&self, spec: JobSpec) -> Result<()> {
        let initial_manifest = if matches!(spec.policy.trigger, TriggerPolicy::OnCreate) {
            Some(static_manifest(&spec)?)
        } else {
            None
        };
        self.create_job_with_manifest(spec, initial_manifest)
    }

    /// Create a job while binding an OnCreate run to an already-resolved
    /// input snapshot. Control/Scheduler resolve pointer names before calling
    /// this method; no active run is ever stored with an empty placeholder.
    pub fn create_job_with_manifest(
        &self,
        spec: JobSpec,
        initial_manifest: Option<InputManifest>,
    ) -> Result<()> {
        validate_job_spec(&spec)?;

        let job_id = spec.job_id.as_ref().to_string();

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Writers are serialised, so one existence check is definitive.
        if self
            .read_one(
                JOB_HEADS,
                job_id.as_bytes(),
                MAX_JOB_HEAD_ROW_BYTES,
                "job head row",
            )?
            .is_some()
        {
            return Err(JobError::JobAlreadyExists(job_id).into());
        }

        let ts = current_timestamp();
        let event = JobEvent::Created {
            spec: spec.clone(),
            ts,
            prev: None,
        };

        // Store event in the ContentStore before opening the write
        // transaction — put_entry commits its own index transaction on the
        // same database, and write transactions must never nest.
        let event_entry = Entry::with_payload(cbor_encode(&event)?);
        let event_cid = self.store.put_entry(&event_entry)?;

        let on_create = matches!(spec.policy.trigger, TriggerPolicy::OnCreate);
        let head = JobHead {
            job_id: spec.job_id.clone(),
            spec: spec.clone(),
            seq: 1,
            created_at: ts,
            updated_at: ts,
            trigger_count: u64::from(on_create),
        };
        let head_bytes = cbor_encode(&head)?;
        let event_key = keys::encode_event_key(&job_id, 1);
        let initial_run = if on_create {
            let manifest = initial_manifest.ok_or_else(|| {
                JobError::InvalidSpec("OnCreate job requires a resolved input manifest".into())
            })?;
            validate_manifest_for_spec(&spec, &manifest)?;
            Some(pending_run(
                &spec.job_id,
                RunId(1),
                JobRevision {
                    event_cid: event_cid.clone(),
                    event_seq: 1,
                    code_ref: spec.code_ref.clone(),
                },
                manifest,
            ))
        } else {
            None
        };
        let initial_run_bytes = initial_run.as_ref().map(cbor_encode).transpose()?;
        let initial_run_key = keys::encode_run_key(&job_id, 1);

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
            heads
                .insert(job_id.as_bytes(), head_bytes.as_slice())
                .map_err(db_err)?;
            let mut events = txn.open_table(JOB_EVENTS).map_err(db_err)?;
            events
                .insert(event_key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;

            if let Some(run_bytes) = &initial_run_bytes {
                ensure_pending_capacity(&txn)?;
                let order = next_pending_order(&txn)?;
                let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
                runs.insert(initial_run_key.as_slice(), run_bytes.as_slice())
                    .map_err(db_err)?;
                let mut pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
                pending
                    .insert(initial_run_key.as_slice(), order)
                    .map_err(db_err)?;
                let mut by_adapter = txn.open_table(PENDING_BY_ADAPTER).map_err(db_err)?;
                let adapter_key = keys::encode_adapter_order_key(&spec.code_ref, order);
                by_adapter
                    .insert(adapter_key.as_slice(), initial_run_key.as_slice())
                    .map_err(db_err)?;
                let mut by_order = txn.open_table(PENDING_BY_ORDER).map_err(db_err)?;
                by_order
                    .insert(order, initial_run_key.as_slice())
                    .map_err(db_err)?;
            }
            let mut watermarks = txn.open_table(JOB_RUN_WATERMARKS).map_err(db_err)?;
            watermarks
                .insert(job_id.as_bytes(), head.trigger_count)
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        if on_create {
            self.emit_run(&spec.job_id, &RunId(1), RunStatus::Pending);
        }

        Ok(())
    }

    /// Replace a job's spec, appending an `Updated` event chained to the
    /// current head.
    ///
    /// The job id in `spec` selects the job and cannot itself be changed —
    /// that would be a different job. Runs, the effect cache and pointer
    /// existing explicit subscriptions remain keyed by job id. They are
    /// deliberately separate from input declarations: a pointer may be only
    /// a trigger, and an input may be read without being a trigger. A
    /// subscription is inert while another policy is active because pointer
    /// writes gate on the current spec. Note that
    /// changing `code_ref` or `config` changes the effect key, so cached
    /// effects from the old spec simply stop matching rather than being
    /// served for the new one (J4).
    pub fn update_job(&self, spec: JobSpec) -> Result<()> {
        validate_job_spec(&spec)?;
        let job_id = spec.job_id.as_ref().to_string();

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        let head_bytes = self
            .read_job_head_row(job_id.as_bytes())?
            .ok_or_else(|| JobError::JobNotFound(job_id.clone()))?;
        let mut head = decode_job_head(&head_bytes, Some(&job_id))?;

        // Chain to the event the head was built from. Without a filed event at
        // that position there is nothing to chain to, and writing a `prev`-less
        // `Updated` would be indistinguishable from a planted one — so refuse
        // and let the operator reconcile first.
        let prev_key = keys::encode_event_key(&job_id, head.seq);
        let prev_cid = match self.read_one(
            JOB_EVENTS,
            &prev_key,
            dag_core::CID_LEN,
            "job event CID row",
        )? {
            Some(bytes) => Cid::from_bytes(&bytes).map_err(db_err)?,
            None => {
                return Err(JobError::InvalidSpec(format!(
                    "{}: no event filed at seq {}, so there is nothing to chain an update to; \
                     run `dag job rebuild --from-store` first",
                    job_id, head.seq
                ))
                .into())
            }
        };

        let ts = current_timestamp();
        let event = JobEvent::Updated {
            spec: spec.clone(),
            ts,
            prev: Some(prev_cid),
        };

        // Content-store I/O before the write transaction: `put_entry` commits
        // its own index transaction on the same database.
        let event_entry = Entry::with_payload(cbor_encode(&event)?);
        let event_cid = self.store.put_entry(&event_entry)?;

        let new_seq = head.seq + 1;
        head.spec = spec;
        head.seq = new_seq;
        head.updated_at = ts;

        let head_bytes = cbor_encode(&head)?;
        let event_key = keys::encode_event_key(&job_id, new_seq);

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
            heads
                .insert(job_id.as_bytes(), head_bytes.as_slice())
                .map_err(db_err)?;
            let mut events = txn.open_table(JOB_EVENTS).map_err(db_err)?;
            events
                .insert(event_key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        Ok(())
    }

    /// Get job specification
    pub fn get_job(&self, job_id: &JobId) -> Result<Option<JobHead>> {
        validate_job_id(job_id.as_ref())?;
        match self.read_job_head_row(job_id.as_ref().as_bytes())? {
            Some(bytes) => Ok(Some(decode_job_head(&bytes, Some(job_id.as_ref()))?)),
            None => Ok(None),
        }
    }

    /// Every `(job_id, seq, event_cid)` in the log, ordered by key.
    ///
    /// The job-log counterpart of [`crate::PointerLog::event_cids`] and
    /// [`crate::PinLog::event_cids`]: it yields the event *addresses* without
    /// reading the content store.
    ///
    /// Garbage collection unions these CIDs into its protected set. Job events
    /// are stored as ordinary entries in the content store (see
    /// [`Self::create_job`]), and [`Self::rebuild_from_store`] recovers job specs
    /// from exactly those entries after a lost `control.redb`; without this a
    /// default `dag gc run` would collect them as unpinned chunks and leave
    /// that recovery with nothing to read.
    pub fn event_cids(&self) -> Result<Vec<(String, u64, Cid)>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_EVENTS).map_err(db_err)?;

        let mut out = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key_guard, cid_guard) = item.map_err(db_err)?;
            let (job_id, seq) = keys::decode_event_key(key_guard.value())?;
            let cid = Cid::from_bytes(cid_guard.value()).map_err(db_err)?;
            out.push((job_id, seq, cid));
        }
        Ok(out)
    }

    /// Trigger a static-input job, freezing its manifest before queue admission.
    ///
    /// Under sled the run insert and the head update were separate writes; a
    /// crash between them could lose the head update. Here they commit in one
    /// transaction.
    pub fn trigger_job(&self, job_id: &JobId, _reason: &str) -> Result<RunId> {
        self.trigger_job_resolved(job_id, _reason, static_manifest)
    }

    /// Trigger a run and bind its inputs while the selected job head is held
    /// stable by the job writer lock.
    pub fn trigger_job_resolved<F>(
        &self,
        job_id: &JobId,
        _reason: &str,
        resolve: F,
    ) -> Result<RunId>
    where
        F: Fn(&JobSpec) -> Result<InputManifest>,
    {
        self.trigger_job_inner(job_id, None, TriggerBinding::Resolve(&resolve))
            .map(|(run_id, _)| run_id)
    }

    /// Enqueue one run, optionally idempotent under a durable trigger key.
    /// The receipt and run commit together: if a worker dies before deleting
    /// the queue row, replay observes the receipt and returns the original run
    /// rather than creating a second one.
    fn trigger_job_inner(
        &self,
        job_id: &JobId,
        receipt_key: Option<&[u8]>,
        binding: TriggerBinding<'_>,
    ) -> Result<(RunId, bool)> {
        let key = job_id.as_ref().to_string();

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        // Snapshot validation may read immutable event content, so it occurs
        // before the job writer lock in the global mutation -> content -> log
        // lock order. The shared mutation guard keeps recovery from replacing
        // the filed event mapping before admission commits.
        if let TriggerBinding::Frozen { revision, manifest } = &binding {
            validate_revision_material(&self.db, self.store.as_ref(), job_id, revision, manifest)?;
        }
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(receipt_key) = receipt_key {
            let txn = self.db.begin_read().map_err(db_err)?;
            let receipts = txn.open_table(TRIGGER_RECEIPTS).map_err(db_err)?;
            if let Some(existing) = receipts.get(receipt_key).map_err(db_err)? {
                return Ok((RunId(existing.value()), false));
            }
        }

        let head_bytes = self
            .read_job_head_row(key.as_bytes())?
            .ok_or_else(|| JobError::JobNotFound(key.clone()))?;
        let mut head = decode_job_head(&head_bytes, Some(&key))?;

        let (revision, manifest) = match binding {
            TriggerBinding::Resolve(resolve) => {
                let event_key = keys::encode_event_key(&key, head.seq);
                let event_cid = self
                    .read_one(
                        JOB_EVENTS,
                        &event_key,
                        dag_core::CID_LEN,
                        "job event CID row",
                    )?
                    .ok_or_else(|| {
                        JobError::ExecutionFailed(format!(
                            "job {} head seq {} has no filed event",
                            key, head.seq
                        ))
                    })
                    .map_err(ControlError::from)
                    .and_then(|bytes| Cid::from_bytes(&bytes).map_err(db_err))?;
                let manifest = resolve(&head.spec)?;
                validate_manifest_for_spec(&head.spec, &manifest)?;
                (
                    JobRevision {
                        event_cid,
                        event_seq: head.seq,
                        code_ref: head.spec.code_ref.clone(),
                    },
                    manifest,
                )
            }
            TriggerBinding::Frozen { revision, manifest } => (revision.clone(), manifest.clone()),
        };

        // Generate run ID (u64 sequence number)
        let run_seq = head
            .trigger_count
            .checked_add(1)
            .ok_or_else(|| JobError::InvalidSpec(format!("job {key} exhausted its run IDs")))?;
        let run_id = RunId(run_seq);

        let run = pending_run(job_id, run_id, revision.clone(), manifest);

        head.trigger_count = run_seq;
        head.updated_at = current_timestamp();

        let run_key = keys::encode_run_key(&key, run_seq);
        let run_bytes = cbor_encode(&run)?;
        let head_bytes = cbor_encode(&head)?;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            ensure_pending_capacity(&txn)?;
            let order = next_pending_order(&txn)?;
            let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            runs.insert(run_key.as_slice(), run_bytes.as_slice())
                .map_err(db_err)?;
            let mut pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
            pending.insert(run_key.as_slice(), order).map_err(db_err)?;
            let mut by_adapter = txn.open_table(PENDING_BY_ADAPTER).map_err(db_err)?;
            let adapter_key = keys::encode_adapter_order_key(&revision.code_ref, order);
            by_adapter
                .insert(adapter_key.as_slice(), run_key.as_slice())
                .map_err(db_err)?;
            let mut by_order = txn.open_table(PENDING_BY_ORDER).map_err(db_err)?;
            by_order.insert(order, run_key.as_slice()).map_err(db_err)?;
            let mut watermarks = txn.open_table(JOB_RUN_WATERMARKS).map_err(db_err)?;
            watermarks.insert(key.as_bytes(), run_seq).map_err(db_err)?;
            let mut heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
            heads
                .insert(key.as_bytes(), head_bytes.as_slice())
                .map_err(db_err)?;
            if let Some(receipt_key) = receipt_key {
                let mut receipts = txn.open_table(TRIGGER_RECEIPTS).map_err(db_err)?;
                receipts.insert(receipt_key, run_id.0).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        self.emit_run(job_id, &run_id, RunStatus::Pending);

        Ok((run_id, true))
    }

    /// Convert durable pointer-update intents into pending job runs.
    ///
    /// Each queue key also keys a receipt written atomically with the run.
    /// Therefore the queue row may safely be deleted in a later transaction:
    /// a crash in between replays to the same run ID. Permanent references to
    /// a missing job move to a dead-letter table; storage failures leave the
    /// intent in place and are returned for retry.
    pub fn drain_trigger_queue(&self, limit: usize) -> Result<TriggerDrainReport> {
        self.drain_trigger_queue_resolved(limit, static_manifest)
    }

    /// Drain trigger intents using the immutable job revision and input
    /// manifest captured by the pointer-publication transaction.
    ///
    /// The resolver remains in the signature for source compatibility with
    /// callers of the pre-snapshot API, but is deliberately never consulted.
    /// Legacy intents without snapshots are dead-lettered rather than bound
    /// to mutable current state.
    pub fn drain_trigger_queue_resolved<F>(
        &self,
        limit: usize,
        _resolve: F,
    ) -> Result<TriggerDrainReport>
    where
        F: Fn(&JobSpec) -> Result<InputManifest>,
    {
        let limit = limit.clamp(1, 4096);
        let pending: Vec<(Vec<u8>, QueuedTrigger)> = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let queue = txn.open_table(TRIGGER_QUEUE).map_err(db_err)?;
            let mut out = Vec::new();
            for row in queue.range::<&[u8]>(..).map_err(db_err)?.take(limit) {
                let (key, value) = row.map_err(db_err)?;
                if key.value().len() > MAX_TRIGGER_KEY_BYTES {
                    return Err(ControlError::Database(format!(
                        "queued trigger key exceeds {MAX_TRIGGER_KEY_BYTES} bytes"
                    )));
                }
                out.push((key.value().to_vec(), decode_queued_trigger(value.value())?));
            }
            out
        };

        let mut report = TriggerDrainReport::default();
        for (key, trigger) in pending {
            report.examined += 1;
            let (revision, manifest) = match (
                trigger.revision.as_ref().cloned(),
                trigger.manifest.as_ref().cloned(),
            ) {
                (Some(revision), Some(manifest)) => (revision, manifest),
                _ => {
                    let dead = DeadTrigger {
                        trigger,
                        error: "legacy trigger intent has no immutable job revision and input manifest; mutable-state inference was refused".to_string(),
                        failed_at_unix: current_timestamp(),
                    };
                    self.remove_trigger_intent(&key, Some(&dead))?;
                    report.dead_lettered += 1;
                    continue;
                }
            };
            match self.trigger_job_inner(
                &trigger.job_id,
                Some(&key),
                TriggerBinding::Frozen {
                    revision: &revision,
                    manifest: &manifest,
                },
            ) {
                Ok((_run_id, created)) => {
                    if created {
                        report.enqueued += 1;
                    } else {
                        report.already_enqueued += 1;
                    }
                    self.remove_trigger_intent(&key, None)?;
                }
                Err(ControlError::Job(
                    JobError::JobNotFound(_)
                    | JobError::InvalidSpec(_)
                    | JobError::ExecutionFailed(_),
                )) => {
                    let dead = DeadTrigger {
                        trigger,
                        error: "queued trigger's immutable job revision or manifest is no longer admissible"
                            .to_string(),
                        failed_at_unix: current_timestamp(),
                    };
                    self.remove_trigger_intent(&key, Some(&dead))?;
                    report.dead_lettered += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(report)
    }

    fn remove_trigger_intent(&self, key: &[u8], dead: Option<&DeadTrigger>) -> Result<()> {
        let dead_bytes = dead.map(cbor_encode).transpose()?;
        if dead_bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_TRIGGER_DEAD_LETTER_ROW_BYTES)
        {
            return Err(ControlError::Capacity(format!(
                "trigger dead-letter row exceeds {MAX_TRIGGER_DEAD_LETTER_ROW_BYTES} bytes"
            )));
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut queue = txn.open_table(TRIGGER_QUEUE).map_err(db_err)?;
            queue.remove(key).map_err(db_err)?;
            // The receipt is only needed while the intent may be replayed:
            // its run and receipt committed together, and this transaction
            // removes the last durable copy of that intent. Deleting both in
            // one commit preserves crash idempotence without accumulating one
            // receipt forever for every pointer update.
            let mut receipts = txn.open_table(TRIGGER_RECEIPTS).map_err(db_err)?;
            receipts.remove(key).map_err(db_err)?;
            if let Some(bytes) = &dead_bytes {
                let mut dead_letters = txn.open_table(TRIGGER_DEAD_LETTERS).map_err(db_err)?;
                let is_new = dead_letters.get(key).map_err(db_err)?.is_none();
                if is_new && dead_letters.len().map_err(db_err)? >= MAX_TRIGGER_DEAD_LETTERS {
                    return Err(ControlError::Capacity(format!(
                        "trigger dead-letter queue is full ({MAX_TRIGGER_DEAD_LETTERS} entries); inspect and compact it before draining more triggers"
                    )));
                }
                dead_letters.insert(key, bytes.as_slice()).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)
    }

    /// Number of unprocessed trigger intents and permanent dead letters.
    pub fn trigger_queue_depths(&self) -> Result<(u64, u64)> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let queue = txn.open_table(TRIGGER_QUEUE).map_err(db_err)?;
        let dead = txn.open_table(TRIGGER_DEAD_LETTERS).map_err(db_err)?;
        Ok((queue.len().map_err(db_err)?, dead.len().map_err(db_err)?))
    }

    /// Inspect a bounded number of permanent trigger failures.
    pub fn list_trigger_dead_letters(&self, limit: usize) -> Result<Vec<TriggerDeadLetter>> {
        if limit == 0 || limit > MAX_DEAD_LETTER_LIST {
            return Err(JobError::InvalidSpec(format!(
                "dead-letter list limit must be between 1 and {MAX_DEAD_LETTER_LIST}"
            ))
            .into());
        }
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(TRIGGER_DEAD_LETTERS).map_err(db_err)?;
        let mut out = Vec::new();
        for row in table.range::<&[u8]>(..).map_err(db_err)?.take(limit) {
            let (key, value) = row.map_err(db_err)?;
            if key.value().len() > MAX_TRIGGER_KEY_BYTES {
                return Err(ControlError::Database(format!(
                    "trigger dead-letter key exceeds {MAX_TRIGGER_KEY_BYTES} bytes"
                )));
            }
            let dead = decode_dead_trigger(value.value())?;
            out.push(TriggerDeadLetter {
                key: hex::encode(key.value()),
                job_id: dead.trigger.job_id.to_string(),
                reason: dead.trigger.reason,
                queued_at_unix: dead.trigger.queued_at_unix,
                error: dead.error,
                failed_at_unix: dead.failed_at_unix,
            });
        }
        Ok(out)
    }

    /// Purge a bounded batch of trigger dead letters after operator review.
    pub fn compact_trigger_dead_letters(
        &self,
        max_delete: usize,
        dry_run: bool,
    ) -> Result<DeadLetterCompactionReport> {
        if max_delete == 0 || max_delete > MAX_DEAD_LETTER_DELETE {
            return Err(JobError::InvalidSpec(format!(
                "dead-letter max-delete must be between 1 and {MAX_DEAD_LETTER_DELETE}"
            ))
            .into());
        }
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let (total, keys) = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(TRIGGER_DEAD_LETTERS).map_err(db_err)?;
            let total = table.len().map_err(db_err)?;
            let mut keys = Vec::new();
            for row in table.range::<&[u8]>(..).map_err(db_err)?.take(max_delete) {
                let (key, _) = row.map_err(db_err)?;
                if key.value().len() > MAX_TRIGGER_KEY_BYTES {
                    return Err(ControlError::Database(format!(
                        "trigger dead-letter key exceeds {MAX_TRIGGER_KEY_BYTES} bytes"
                    )));
                }
                keys.push(key.value().to_vec());
            }
            (total, keys)
        };
        if !dry_run && !keys.is_empty() {
            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(TRIGGER_DEAD_LETTERS).map_err(db_err)?;
                for key in &keys {
                    table.remove(key.as_slice()).map_err(db_err)?;
                }
            }
            txn.commit().map_err(db_err)?;
        }
        drop(guard);
        let selected = keys.len() as u64;
        Ok(DeadLetterCompactionReport {
            total,
            selected,
            deleted: if dry_run { 0 } else { selected },
            remaining: total.saturating_sub(if dry_run { 0 } else { selected }),
            dry_run,
        })
    }

    /// Pending and Running run counts for health dashboards. Terminal history
    /// is intentionally not counted here; it can be large and does not
    /// represent work requiring an operator or worker.
    pub fn active_run_counts(&self) -> Result<(u64, u64)> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
        let running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
        Ok((
            pending.len().map_err(db_err)?,
            running.len().map_err(db_err)?,
        ))
    }

    /// Claim the oldest visible pending run for a background worker.
    ///
    /// A pending lease may be reclaimed after expiry because the adapter has
    /// not started yet. Once [`Self::record_claimed_run_started`] changes the
    /// run to Running, expiry fails that run closed; it never launches an
    /// automatic second execution of an uncertain side effect.
    pub fn claim_next_pending(
        &self,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<Option<RunClaim>> {
        self.claim_next_pending_inner(worker_id, lease_seconds, None, None)
    }

    /// Claim the oldest Pending run whose immutable queued revision names one
    /// of `code_refs`.
    ///
    /// A background worker must never claim work it cannot execute: doing so
    /// would turn a capability denial (for example, an `exec` job seen by the
    /// network-safe worker) into a permanent failed run. Unknown or withheld
    /// adapters remain Pending for an explicitly capable worker or operator.
    pub fn claim_next_pending_for_code_refs(
        &self,
        worker_id: &str,
        lease_seconds: u64,
        code_refs: &[&str],
    ) -> Result<Option<RunClaim>> {
        self.claim_next_pending_inner(worker_id, lease_seconds, Some(code_refs), None)
    }

    /// Claim one exact queued run. Manual CLI/HTTP execution uses this after
    /// enqueueing, so it cannot accidentally execute an older backlog row.
    pub fn claim_pending_run(
        &self,
        job_id: &JobId,
        run_id: &RunId,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<RunClaim> {
        let key = keys::encode_run_key(job_id.as_ref(), run_id.0);
        self.claim_next_pending_inner(worker_id, lease_seconds, None, Some(&key))?
            .ok_or_else(|| {
                JobError::ExecutionFailed(format!(
                    "run {} is not pending or is already leased",
                    run_id
                ))
                .into()
            })
    }

    fn claim_next_pending_inner(
        &self,
        worker_id: &str,
        lease_seconds: u64,
        code_refs: Option<&[&str]>,
        exact_key: Option<&[u8]>,
    ) -> Result<Option<RunClaim>> {
        if worker_id.trim().is_empty() || worker_id.len() > 256 {
            return Err(
                JobError::InvalidSpec("worker ID must contain 1..=256 bytes".to_string()).into(),
            );
        }
        if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
            return Err(JobError::InvalidSpec(format!(
                "job lease must be between {MIN_LEASE_SECONDS} and {MAX_LEASE_SECONDS} seconds"
            ))
            .into());
        }

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let now = current_timestamp();
        if code_refs.is_some_and(|refs| refs.len() > 256) {
            return Err(JobError::InvalidSpec(
                "a worker may advertise at most 256 adapter names".to_string(),
            )
            .into());
        }
        if code_refs.is_some_and(|refs| {
            refs.iter().any(|code_ref| {
                code_ref.is_empty()
                    || code_ref.len() > dag_core::MAX_JOB_CODE_REF_BYTES
                    || code_ref.chars().any(char::is_control)
            })
        }) {
            return Err(JobError::InvalidSpec(
                "worker adapter names must follow the bounded job code_ref contract".to_string(),
            )
            .into());
        }
        let candidate_key = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let pending = txn.open_table(PENDING_RUNS).map_err(db_err)?;
            let leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            let visible = |key: &[u8]| -> Result<bool> {
                let leased = leases
                    .get(key)
                    .map_err(db_err)?
                    .map(|bytes| decode_stored_lease(bytes.value()))
                    .transpose()?;
                Ok(leased.is_none_or(|lease| lease.expires_at_unix <= now))
            };

            if let Some(key) = exact_key {
                if pending.get(key).map_err(db_err)?.is_some() && visible(key)? {
                    Some(key.to_vec())
                } else {
                    None
                }
            } else if let Some(allowed) = code_refs {
                let by_adapter = txn.open_table(PENDING_BY_ADAPTER).map_err(db_err)?;
                let mut oldest: Option<(u64, Vec<u8>)> = None;
                for adapter in allowed {
                    let prefix = keys::encode_adapter_prefix(adapter);
                    for row in by_adapter.range(prefix.as_slice()..).map_err(db_err)? {
                        #[cfg(test)]
                        CLAIM_INDEX_ROWS_SCANNED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let (index_key, run_key) = row.map_err(db_err)?;
                        if !index_key.value().starts_with(&prefix) {
                            break;
                        }
                        let order = u64::from_be_bytes(
                            index_key.value()[index_key.value().len() - 8..]
                                .try_into()
                                .expect("adapter order key has an eight-byte suffix"),
                        );
                        if visible(run_key.value())?
                            && oldest.as_ref().is_none_or(|(seen, _)| order < *seen)
                        {
                            oldest = Some((order, run_key.value().to_vec()));
                            break;
                        }
                    }
                }
                oldest.map(|(_, key)| key)
            } else {
                let by_order = txn.open_table(PENDING_BY_ORDER).map_err(db_err)?;
                let mut selected = None;
                for row in by_order.range::<u64>(..).map_err(db_err)? {
                    let (_, run_key) = row.map_err(db_err)?;
                    if visible(run_key.value())? {
                        selected = Some(run_key.value().to_vec());
                        break;
                    }
                }
                selected
            }
        };

        let Some(run_key) = candidate_key else {
            return Ok(None);
        };
        let run_bytes = self
            .read_run_row(&run_key)?
            .ok_or_else(|| ControlError::Database("pending index names a missing run".into()))?;
        let run = decode_job_run(&run_bytes)?;
        if !matches!(run.status, RunStatus::Pending) {
            return Err(ControlError::Database(
                "pending index names a non-pending run".into(),
            ));
        }
        validate_run_revision(&self.db, self.store.as_ref(), &run)?;
        let mut token = [0u8; 32];
        getrandom::fill(&mut token)
            .map_err(|error| ControlError::db("job lease randomness", error))?;
        let lease = StoredLease {
            token,
            worker_id: worker_id.to_string(),
            claimed_at_unix: now,
            expires_at_unix: now.saturating_add(lease_seconds as i64),
        };
        let lease_bytes = cbor_encode(&lease)?;
        if lease_bytes.len() > MAX_RUN_LEASE_ROW_BYTES {
            return Err(ControlError::Capacity(format!(
                "job run lease exceeds {MAX_RUN_LEASE_ROW_BYTES} bytes"
            )));
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            leases
                .insert(run_key.as_slice(), lease_bytes.as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        Ok(Some(RunClaim {
            job_id: run.job_id,
            run_id: run.run_id,
            worker_id: worker_id.to_string(),
            token,
            lease_seconds,
        }))
    }

    /// Persist resolved inputs and move a leased Pending run to Running.
    pub fn record_claimed_run_started(
        &self,
        claim: &RunClaim,
        manifest: &InputManifest,
    ) -> Result<()> {
        let run_key = keys::encode_run_key(claim.job_id.as_ref(), claim.run_id.0);
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut lease = self.require_claim(&run_key, claim)?;
        let run_bytes = self
            .read_run_row(&run_key)?
            .ok_or_else(|| JobError::RunNotFound(claim.run_id.to_string()))?;
        let mut run = decode_job_run(&run_bytes)?;
        if !matches!(run.status, RunStatus::Pending) {
            return Err(invalid_transition(&run.status, "Running").into());
        }
        let now = current_timestamp();
        if run.manifest != *manifest {
            return Err(JobError::ExecutionFailed(
                "executor attempted to replace the manifest bound at enqueue time".to_string(),
            )
            .into());
        }
        validate_run_revision(&self.db, self.store.as_ref(), &run)?;
        run.status = RunStatus::Running;
        run.node_id = Some(claim.worker_id.clone());
        run.started_at_unix = now;
        lease.expires_at_unix = now.saturating_add(claim.lease_seconds as i64);

        let run_bytes = cbor_encode(&run)?;
        let lease_bytes = cbor_encode(&lease)?;
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            runs.insert(run_key.as_slice(), run_bytes.as_slice())
                .map_err(db_err)?;
            remove_pending_indexes(&txn, &run_key, &run)?;
            let mut running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
            running.insert(run_key.as_slice(), 1).map_err(db_err)?;
            let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            leases
                .insert(run_key.as_slice(), lease_bytes.as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);
        self.emit_run(&claim.job_id, &claim.run_id, RunStatus::Running);
        Ok(())
    }

    /// Load the exact filed spec and input snapshot selected at enqueue time.
    pub fn claimed_run(&self, claim: &RunClaim) -> Result<ClaimedRun> {
        let run_key = keys::encode_run_key(claim.job_id.as_ref(), claim.run_id.0);
        self.require_claim(&run_key, claim)?;
        let bytes = self
            .read_run_row(&run_key)?
            .ok_or_else(|| JobError::RunNotFound(claim.run_id.to_string()))?;
        let run = decode_job_run(&bytes)?;
        if !matches!(run.status, RunStatus::Pending | RunStatus::Running) {
            return Err(invalid_transition(&run.status, "execute").into());
        }
        let spec = validate_run_revision(&self.db, self.store.as_ref(), &run)?;
        Ok(ClaimedRun {
            spec,
            manifest: run.manifest,
            revision: run.revision.expect("revision validation succeeded"),
        })
    }

    /// Extend an active claim. Workers heartbeat while an adapter future is
    /// running; failure to renew causes them to cancel and leave the run for
    /// fail-closed expiry handling.
    pub fn renew_run_claim(&self, claim: &RunClaim) -> Result<()> {
        let run_key = keys::encode_run_key(claim.job_id.as_ref(), claim.run_id.0);
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut lease = self.require_claim(&run_key, claim)?;
        lease.expires_at_unix = current_timestamp().saturating_add(claim.lease_seconds as i64);
        let bytes = cbor_encode(&lease)?;
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            leases
                .insert(run_key.as_slice(), bytes.as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);
        Ok(())
    }

    /// Complete a claimed run, recording its provenance and releasing the
    /// durable lease in the same commit.
    pub fn record_claimed_run_completed(
        &self,
        claim: &RunClaim,
        outputs: Vec<(String, Cid)>,
        status: RunStatus,
        origin: Option<dag_core::RunOrigin>,
    ) -> Result<()> {
        let run_key = keys::encode_run_key(claim.job_id.as_ref(), claim.run_id.0);
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.require_claim(&run_key, claim)?;
        let run_bytes = self
            .read_run_row(&run_key)?
            .ok_or_else(|| JobError::RunNotFound(claim.run_id.to_string()))?;
        let mut run = decode_job_run(&run_bytes)?;
        let status = bounded_terminal_status(status);
        let allowed = matches!(run.status, RunStatus::Running)
            || (matches!(run.status, RunStatus::Pending)
                && matches!(status, RunStatus::Failed { .. }));
        if !allowed || !is_terminal(&status) {
            return Err(invalid_transition(&run.status, status_label(&status)).into());
        }
        match &status {
            RunStatus::Succeeded => {
                let spec = validate_run_revision(&self.db, self.store.as_ref(), &run)?;
                validate_outputs_for_spec(&spec, &outputs)?;
            }
            RunStatus::Failed { .. } if !outputs.is_empty() => {
                return Err(JobError::ExecutionFailed(
                    "failed runs cannot record successful outputs".to_string(),
                )
                .into())
            }
            RunStatus::Failed { .. } => {}
            RunStatus::Pending | RunStatus::Running => unreachable!("terminal checked above"),
        }
        run.outputs = outputs;
        run.status = status.clone();
        run.finished_at_unix = Some(current_timestamp());
        if let Some(origin) = origin {
            run.origin = origin;
        }
        let bytes = cbor_encode(&run)?;
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            runs.insert(run_key.as_slice(), bytes.as_slice())
                .map_err(db_err)?;
            remove_pending_indexes(&txn, &run_key, &run)?;
            let mut running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
            running.remove(run_key.as_slice()).map_err(db_err)?;
            let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            leases.remove(run_key.as_slice()).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);
        self.emit_run(&claim.job_id, &claim.run_id, status);
        Ok(())
    }

    /// Fail Running runs whose owning worker stopped heartbeating. Pending
    /// leases are simply released for reclaim because no adapter started.
    /// Running work is never retried automatically: after a crash, an
    /// external side effect may have happened even when no output was saved.
    pub fn expire_run_claims(&self) -> Result<u32> {
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let now = current_timestamp();
        let expired: Vec<(Vec<u8>, StoredLease)> = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            let mut out = Vec::new();
            for row in leases.range::<&[u8]>(..).map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                let lease = decode_stored_lease(value.value())?;
                if lease.expires_at_unix <= now {
                    out.push((key.value().to_vec(), lease));
                }
            }
            out
        };
        if expired.is_empty() {
            return Ok(0);
        }

        let mut failed = Vec::new();
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
            let mut running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
            for (key, lease) in expired {
                let decoded_run = runs
                    .get(key.as_slice())
                    .map_err(db_err)?
                    .map(|bytes| decode_job_run(bytes.value()))
                    .transpose()?;
                if let Some(mut run) = decoded_run {
                    if matches!(run.status, RunStatus::Running) {
                        run.status = bounded_terminal_status(RunStatus::Failed {
                            message: format!(
                                "worker {} stopped renewing its execution lease; automatic retry is disabled to avoid duplicating side effects",
                                lease.worker_id
                            ),
                        });
                        run.finished_at_unix = Some(now);
                        let encoded = cbor_encode(&run)?;
                        runs.insert(key.as_slice(), encoded.as_slice())
                            .map_err(db_err)?;
                        failed.push((run.job_id, run.run_id, run.status));
                    }
                }
                running.remove(key.as_slice()).map_err(db_err)?;
                leases.remove(key.as_slice()).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;
        drop(guard);
        for (job_id, run_id, status) in &failed {
            self.emit_run(job_id, run_id, status.clone());
        }
        Ok(failed.len() as u32)
    }

    fn require_claim(&self, run_key: &[u8], claim: &RunClaim) -> Result<StoredLease> {
        let bytes = self
            .read_one(
                RUN_LEASES,
                run_key,
                MAX_RUN_LEASE_ROW_BYTES,
                "job run lease row",
            )?
            .ok_or_else(|| JobError::ExecutionFailed("run lease is missing or expired".into()))?;
        let lease = decode_stored_lease(&bytes)?;
        let different = lease
            .token
            .iter()
            .zip(claim.token.iter())
            .fold(0u8, |diff, (left, right)| diff | (left ^ right));
        if different != 0 || lease.worker_id != claim.worker_id {
            return Err(JobError::ExecutionFailed(
                "run lease belongs to another worker".to_string(),
            )
            .into());
        }
        // A token proves which worker owned the lease, but it does not make
        // an expired lease current again. Rejecting at the mutation boundary
        // prevents a paused worker from renewing or completing after its
        // deadline but before the scheduler's cleanup pass has run.
        if lease.expires_at_unix <= current_timestamp() {
            return Err(
                JobError::ExecutionFailed("run lease is missing or expired".to_string()).into(),
            );
        }
        Ok(lease)
    }

    /// Legacy unleased lifecycle entry point. Execution without a durable
    /// token is intentionally refused; callers must use
    /// [`Self::claim_pending_run`] and [`Self::record_claimed_run_started`].
    #[deprecated(note = "claim the run and use record_claimed_run_started")]
    pub fn record_run_started(
        &self,
        _job_id: &JobId,
        _run_id: &RunId,
        _node_id: &str,
        _manifest: &InputManifest,
    ) -> Result<()> {
        Err(JobError::ExecutionFailed(
            "unleased run start is disabled; claim the pending run first".to_string(),
        )
        .into())
    }

    /// Record that a run has completed, leaving its origin as recorded.
    #[deprecated(note = "complete through record_claimed_run_completed")]
    pub fn record_run_completed(
        &self,
        _job_id: &JobId,
        _run_id: &RunId,
        _outputs: Vec<(String, Cid)>,
        _status: RunStatus,
    ) -> Result<()> {
        Err(JobError::ExecutionFailed(
            "unleased run completion is disabled; complete with the claim token".to_string(),
        )
        .into())
    }

    /// [`Self::record_run_completed`], also recording how the outputs came to
    /// be (executed here, served from the cache, or adopted from a signed
    /// claim). `None` leaves whatever the run already carries.
    #[deprecated(note = "complete through record_claimed_run_completed")]
    pub fn record_run_completed_with_origin(
        &self,
        _job_id: &JobId,
        _run_id: &RunId,
        _outputs: Vec<(String, Cid)>,
        _status: RunStatus,
        _origin: dag_core::RunOrigin,
    ) -> Result<()> {
        Err(JobError::ExecutionFailed(
            "unleased run completion is disabled; complete with the claim token".to_string(),
        )
        .into())
    }

    /// Get job run history, newest first.
    pub fn get_job_runs(&self, job_id: &JobId, limit: Option<usize>) -> Result<Vec<JobRun>> {
        if limit == Some(0) {
            return Ok(Vec::new());
        }
        let limit = limit.unwrap_or(MAX_RUN_HISTORY_PAGE);
        if limit > MAX_RUN_HISTORY_PAGE {
            return Err(JobError::InvalidSpec(format!(
                "run history page limit {limit} exceeds {MAX_RUN_HISTORY_PAGE}"
            ))
            .into());
        }
        self.get_job_runs_page(job_id, None, limit)
    }

    /// Newest-first run page with an exclusive run-sequence cursor.
    pub fn get_job_runs_page(
        &self,
        job_id: &JobId,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<JobRun>> {
        validate_job_id(job_id.as_ref())?;
        if limit == 0 || limit > MAX_RUN_HISTORY_PAGE.saturating_add(1) {
            return Err(JobError::InvalidSpec(format!(
                "run history page limit must be between 1 and {}",
                MAX_RUN_HISTORY_PAGE + 1
            ))
            .into());
        }
        if before == Some(0) {
            return Err(JobError::InvalidRunId(
                "run history cursor must be greater than zero".to_string(),
            )
            .into());
        }

        use std::ops::Bound::{Excluded, Included};
        let prefix = keys::encode_job_prefix(job_id.as_ref());
        let upper = keys::encode_run_key(job_id.as_ref(), before.unwrap_or(u64::MAX));
        let upper_bound = if before.is_some() {
            Excluded(upper.as_slice())
        } else {
            Included(upper.as_slice())
        };
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_RUNS).map_err(db_err)?;
        let mut runs = Vec::with_capacity(limit);
        for row in table
            .range::<&[u8]>((Included(prefix.as_slice()), upper_bound))
            .map_err(db_err)?
            .rev()
            .take(limit)
        {
            let (_, value) = row.map_err(db_err)?;
            #[cfg(test)]
            RUN_PAGE_ROWS_DECODED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            runs.push(decode_job_run(value.value())?);
        }
        Ok(runs)
    }

    /// Delete the oldest terminal runs while retaining active work and the
    /// newest `keep_terminal` terminal records.
    ///
    /// Run IDs are never reused: `JOB_RUN_WATERMARKS` is authoritative for
    /// allocation and is deliberately untouched. Deletion is explicit and
    /// bounded because run records are provenance; callers should dry-run and
    /// back up before choosing a retention policy.
    pub fn compact_terminal_runs(
        &self,
        job_id: &JobId,
        keep_terminal: usize,
        max_delete: usize,
        dry_run: bool,
    ) -> Result<RunCompactionReport> {
        validate_job_id(job_id.as_ref())?;
        if max_delete == 0 || max_delete > MAX_RUN_COMPACTION_DELETE {
            return Err(JobError::InvalidSpec(format!(
                "run compaction max-delete must be between 1 and {MAX_RUN_COMPACTION_DELETE}"
            ))
            .into());
        }
        if self.get_job(job_id)?.is_none() {
            return Err(JobError::JobNotFound(job_id.to_string()).into());
        }

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let prefix = keys::encode_job_prefix(job_id.as_ref());
        let (examined, active_retained, terminal_rows) = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            let mut examined = 0u64;
            let mut active = 0u64;
            let mut terminal = 0u64;
            for row in runs.range(prefix.as_slice()..).map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                if !key.value().starts_with(&prefix) {
                    break;
                }
                examined = examined.saturating_add(1);
                let run = decode_job_run(value.value())?;
                if is_terminal(&run.status) {
                    terminal = terminal.saturating_add(1);
                } else {
                    active = active.saturating_add(1);
                }
            }
            (examined, active, terminal)
        };

        let eligible = terminal_rows.saturating_sub(keep_terminal as u64);
        let selected = eligible.min(max_delete as u64) as usize;
        let terminal_keys = if selected == 0 {
            Vec::new()
        } else {
            let txn = self.db.begin_read().map_err(db_err)?;
            let runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
            let mut keys = Vec::with_capacity(selected);
            for row in runs.range(prefix.as_slice()..).map_err(db_err)? {
                let (key, value) = row.map_err(db_err)?;
                if !key.value().starts_with(&prefix) || keys.len() >= selected {
                    break;
                }
                let run = decode_job_run(value.value())?;
                if is_terminal(&run.status) {
                    keys.push(key.value().to_vec());
                }
            }
            keys
        };
        if !dry_run && selected > 0 {
            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut runs = txn.open_table(JOB_RUNS).map_err(db_err)?;
                let mut running = txn.open_table(RUNNING_RUNS).map_err(db_err)?;
                let mut leases = txn.open_table(RUN_LEASES).map_err(db_err)?;
                for key in &terminal_keys {
                    if let Some(value) = runs.get(key.as_slice()).map_err(db_err)? {
                        let run = decode_job_run(value.value())?;
                        drop(value);
                        remove_pending_indexes(&txn, key, &run)?;
                    }
                    runs.remove(key.as_slice()).map_err(db_err)?;
                    running.remove(key.as_slice()).map_err(db_err)?;
                    leases.remove(key.as_slice()).map_err(db_err)?;
                }
            }
            txn.commit().map_err(db_err)?;
        }
        drop(guard);

        Ok(RunCompactionReport {
            examined,
            terminal_rows,
            active_retained,
            eligible,
            deleted: if dry_run { 0 } else { selected as u64 },
            remaining_eligible: eligible.saturating_sub(if dry_run { 0 } else { selected as u64 }),
            dry_run,
        })
    }

    /// Subscribe a pointer to trigger a job
    pub fn subscribe_pointer(&self, pointer_id: &str, job_id: &JobId) -> Result<()> {
        crate::pointer::validate_pointer_id(pointer_id)?;
        let head = self
            .get_job(job_id)?
            .ok_or_else(|| JobError::JobNotFound(job_id.to_string()))?;
        if !matches!(head.spec.policy.trigger, TriggerPolicy::OnPointerUpdate) {
            return Err(JobError::InvalidSpec(format!(
                "job {} has {:?} trigger policy; set OnPointerUpdate before subscribing it",
                job_id, head.spec.policy.trigger
            ))
            .into());
        }
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Key: pointer_id -> List of job_ids (CBOR encoded Vec<String>)
        let mut job_ids: Vec<String> = match self.read_one(
            POINTER_SUBSCRIPTIONS,
            pointer_id.as_bytes(),
            MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES,
            "pointer subscription row",
        )? {
            Some(bytes) => decode_pointer_subscriptions(&bytes)?,
            None => Vec::new(),
        };

        let job_id_str = job_id.as_ref().to_string();
        if !job_ids.contains(&job_id_str) {
            if job_ids.len() >= MAX_SUBSCRIPTIONS_PER_POINTER {
                return Err(ControlError::Capacity(format!(
                    "pointer {pointer_id} already has the maximum {MAX_SUBSCRIPTIONS_PER_POINTER} job subscriptions"
                )));
            }
            job_ids.push(job_id_str);
            let bytes = cbor_encode(&job_ids)?;
            if bytes.len() > MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES {
                return Err(ControlError::Capacity(format!(
                    "pointer {pointer_id} subscriptions need {} bytes, above the {MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES}-byte row limit",
                    bytes.len()
                )));
            }

            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(POINTER_SUBSCRIPTIONS).map_err(db_err)?;
                table
                    .insert(pointer_id.as_bytes(), bytes.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
        }
        drop(guard);

        Ok(())
    }

    /// Remove one explicit pointer subscription.
    ///
    /// Returns `true` when a subscription existed. Removing the final job also
    /// removes the table row, so abandoned pointer names do not accumulate.
    pub fn unsubscribe_pointer(&self, pointer_id: &str, job_id: &JobId) -> Result<bool> {
        crate::pointer::validate_pointer_id(pointer_id)?;
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(bytes) = self.read_one(
            POINTER_SUBSCRIPTIONS,
            pointer_id.as_bytes(),
            MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES,
            "pointer subscription row",
        )?
        else {
            return Ok(false);
        };
        let mut job_ids = decode_pointer_subscriptions(&bytes)?;
        let before = job_ids.len();
        job_ids.retain(|existing| existing != job_id.as_ref());
        if job_ids.len() == before {
            return Ok(false);
        }

        let encoded = (!job_ids.is_empty())
            .then(|| cbor_encode(&job_ids))
            .transpose()?;
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(POINTER_SUBSCRIPTIONS).map_err(db_err)?;
            if let Some(encoded) = &encoded {
                table
                    .insert(pointer_id.as_bytes(), encoded.as_slice())
                    .map_err(db_err)?;
            } else {
                table.remove(pointer_id.as_bytes()).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;
        drop(guard);
        Ok(true)
    }

    /// Get jobs subscribed to a pointer
    pub fn get_pointer_subscriptions(&self, pointer_id: &str) -> Result<Vec<JobId>> {
        match self.read_one(
            POINTER_SUBSCRIPTIONS,
            pointer_id.as_bytes(),
            MAX_POINTER_SUBSCRIPTIONS_ROW_BYTES,
            "pointer subscription row",
        )? {
            Some(bytes) => {
                let job_ids = decode_pointer_subscriptions(&bytes)?;
                Ok(job_ids.into_iter().map(JobId::from).collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// List all jobs
    pub fn list_jobs(&self) -> Result<Vec<JobHead>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_HEADS).map_err(db_err)?;

        let mut jobs = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key, value) = item.map_err(db_err)?;
            let id = std::str::from_utf8(key.value()).map_err(|error| {
                ControlError::Database(format!("job head key is not UTF-8: {error}"))
            })?;
            let head = decode_job_head(value.value(), Some(id))?;
            jobs.push(head);
        }
        Ok(jobs)
    }

    /// Number of registered jobs without allocating or decoding their specs.
    pub fn job_count(&self) -> Result<u64> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_HEADS).map_err(db_err)?;
        table.len().map_err(db_err)
    }

    /// List a bounded lexicographic page of job IDs strictly after `after`.
    ///
    /// Returning keys rather than decoded heads lets HTTP and other remote
    /// callers enforce an encoded-byte budget while loading one potentially
    /// large job specification at a time.
    pub fn list_job_ids_page(&self, after: Option<&str>, limit: usize) -> Result<Vec<String>> {
        use std::ops::Bound::{Excluded, Unbounded};

        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(JOB_HEADS).map_err(db_err)?;
        let range = (
            after.map_or(Unbounded, |id| Excluded(id.as_bytes())),
            Unbounded,
        );
        let mut ids = Vec::with_capacity(limit);
        for row in table.range::<&[u8]>(range).map_err(db_err)?.take(limit) {
            let (key, _) = row.map_err(db_err)?;
            let id = std::str::from_utf8(key.value()).map_err(|e| {
                ControlError::Database(format!("job log: job ID is not UTF-8: {e}"))
            })?;
            ids.push(id.to_string());
        }
        Ok(ids)
    }

    /// Store effect cache entry
    pub fn store_effect_cache(
        &self,
        effect_key: &EffectKey,
        outputs: &[(String, Cid)],
    ) -> Result<()> {
        validate_output_shape(outputs)?;
        let key = effect_key.to_binary_key();
        let value = cbor_encode(outputs)?;
        if value.len() > MAX_EFFECT_CACHE_ROW_BYTES {
            return Err(ControlError::Capacity(format!(
                "encoded effect-cache row exceeds {MAX_EFFECT_CACHE_ROW_BYTES} bytes"
            )));
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(EFFECT_CACHE).map_err(db_err)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Get effect cache entry
    pub fn get_effect_cache(&self, effect_key: &EffectKey) -> Result<Option<Vec<(String, Cid)>>> {
        let key = effect_key.to_binary_key();
        match self.read_effect_cache_row(&key)? {
            Some(bytes) => {
                let outputs: Vec<(String, Cid)> = cbor_decode(&bytes)?;
                validate_output_shape(&outputs)?;
                Ok(Some(outputs))
            }
            None => Ok(None),
        }
    }

    /// Rebuild job heads from the event log and run records.
    ///
    /// Validates each job's event chain (sequence contiguity from 1) and
    /// reconstructs its head: the spec comes from the latest Created/Updated
    /// event, and `trigger_count` from the durable run-ID watermark. The
    /// watermark survives explicit run-history compaction, so rebuilding can
    /// never reuse a previously allocated run ID.
    ///
    /// This is the job log's table-oriented repair phase. `dag migrate` runs it
    /// after copying a pre-redb directory, and it is usable whenever the heads
    /// are suspect; only the complete offline recovery protocol certifies GC
    /// readiness.
    pub fn rebuild(&self) -> Result<JobRebuildReport> {
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Collect events per job. Content-store reads stay outside any write
        // transaction.
        let mut job_events: std::collections::HashMap<String, Vec<(u64, Cid, JobEvent)>> =
            std::collections::HashMap::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(JOB_EVENTS).map_err(db_err)?;
            for item in table.range::<&[u8]>(..).map_err(db_err)? {
                let (key_guard, cid_guard) = item.map_err(db_err)?;
                let (job_id, seq) = keys::decode_event_key(key_guard.value())?;
                let event_cid = Cid::from_bytes(cid_guard.value()).map_err(db_err)?;
                let entry = self.store.get_entry(&event_cid)?;
                let event = decode_job_event(&entry.payload)?;
                job_events
                    .entry(job_id)
                    .or_default()
                    .push((seq, event_cid, event));
            }
        }

        // Highest allocated run sequence per job. The run scan is retained as
        // a defensive migration fallback for a database that predates the
        // watermark table.
        let mut max_run_seq: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let watermarks = txn.open_table(JOB_RUN_WATERMARKS).map_err(db_err)?;
            for item in watermarks.range::<&[u8]>(..).map_err(db_err)? {
                let (job_id, seq) = item.map_err(db_err)?;
                let job_id = std::str::from_utf8(job_id.value()).map_err(|error| {
                    ControlError::Database(format!("job run watermark key is not UTF-8: {error}"))
                })?;
                validate_job_id(job_id).map_err(|error| {
                    ControlError::Database(format!(
                        "job run watermark key contains an invalid job ID: {error}"
                    ))
                })?;
                max_run_seq.insert(job_id.to_string(), seq.value());
            }
            let table = txn.open_table(JOB_RUNS).map_err(db_err)?;
            for item in table.range::<&[u8]>(..).map_err(db_err)? {
                let (key_guard, _) = item.map_err(db_err)?;
                let (job_id, seq) = keys::decode_event_key(key_guard.value())?;
                let entry = max_run_seq.entry(job_id).or_insert(0);
                *entry = (*entry).max(seq);
            }
        }

        let jobs_processed = job_events.len() as u32;
        let mut validation_errors = 0;
        let mut rebuilt: Vec<(String, Vec<u8>)> = Vec::new();

        for (job_id, mut events) in job_events {
            events.sort_by_key(|(seq, _, _)| *seq);

            // Sequence contiguity from 1.
            let contiguous = events
                .iter()
                .enumerate()
                .all(|(i, (seq, _, _))| *seq == i as u64 + 1);
            if !contiguous {
                validation_errors += 1;
                tracing::warn!(job = %job_id, "job event chain has sequence gaps; skipping");
                continue;
            }

            // Chain integrity, against the same rule the store scan applies.
            // The table's positions are only as trustworthy as whatever filed
            // them, and a forged event that reached the table through an older
            // build's store scan is still sitting there.
            let legacy_cutoff = self.legacy_prev_cutoff(&job_id)?;
            if let Err(reason) = validate_filed_chain(&job_id, &events, legacy_cutoff) {
                validation_errors += 1;
                tracing::warn!(job = %job_id, reason = %reason, "job event chain is broken; skipping");
                continue;
            }

            // Spec: latest Created or Updated event. Timestamps: first/last.
            let mut spec: Option<JobSpec> = None;
            let mut created_at = 0i64;
            let mut updated_at = 0i64;
            for (i, (_seq, _cid, event)) in events.iter().enumerate() {
                if let Some(s) = event.spec() {
                    spec = Some(s.clone());
                }
                let ts = event.ts();
                if i == 0 {
                    created_at = ts;
                }
                updated_at = updated_at.max(ts);
            }

            let Some(spec) = spec else {
                validation_errors += 1;
                tracing::warn!(job = %job_id, "job has no Created event; skipping");
                continue;
            };

            let head = JobHead {
                job_id: spec.job_id.clone(),
                spec,
                seq: events.len() as u64,
                created_at,
                updated_at,
                trigger_count: max_run_seq.get(&job_id).copied().unwrap_or(0),
            };
            rebuilt.push((job_id, cbor_encode(&head)?));
        }

        let heads_rebuilt = rebuilt.len() as u32;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut heads = txn.open_table(JOB_HEADS).map_err(db_err)?;
            heads.retain(|_, _| false).map_err(db_err)?;
            for (job_id, head_bytes) in &rebuilt {
                heads
                    .insert(job_id.as_bytes(), head_bytes.as_slice())
                    .map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;

        Ok(JobRebuildReport {
            jobs_processed,
            heads_rebuilt,
            validation_errors,
        })
    }
}

impl JobLog {
    /// Rebuild job events and heads by scanning the content store, for when
    /// `control.redb` itself is gone.
    ///
    /// [`Self::rebuild`] reads the `job_events` table to learn which CIDs the
    /// events are, so it recovers nothing from a directory whose database was
    /// lost. Job events are ordinary CBOR entries in `data/` and survive.
    ///
    /// Unlike the pointer and pin logs, this takes the CID list rather than
    /// enumerating it: `JobLog` holds an `Arc<dyn ContentStore>`, and
    /// enumeration lives on `GcCapableStore`, which a trait object of the
    /// former cannot reach. [`crate::Control::rebuild_jobs_from_store`]
    /// supplies it.
    ///
    /// **What does not come back**: runs, the effect cache and pointer
    /// subscriptions exist only in the database. `trigger_count` is therefore
    /// recovered from whatever the runs table still holds — zero, if it was
    /// lost with the rest. Recording zero is the honest answer; inventing a
    /// count would desynchronise the next run's ID from the runs table.
    ///
    /// Only `Created` and `Updated` events can be attributed to a job at all,
    /// because a `Triggered` event carries no job id — nothing writes those
    /// today (triggering records a run), and one found in the store is counted
    /// as skipped rather than guessed at.
    pub fn rebuild_from_store(&self, cids: &[Cid]) -> Result<JobStoreRebuildReport> {
        use std::collections::HashMap;

        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        let mut report = JobStoreRebuildReport {
            chunks_scanned: cids.len(),
            ..Default::default()
        };

        // (ts, cid, event) per job, unordered here: order comes from the
        // `prev` chain below, never from `ts`, which whoever wrote the chunk
        // chose.
        let mut jobs: HashMap<String, JobChain> = HashMap::new();
        for cid in cids {
            // An unreadable object may be the only copy of a job event. It is
            // protected as control-plane evidence, so recovery cannot safely
            // classify a read failure as irrelevant content.
            let bytes = self.store.get_chunk(cid)?;
            let Ok(entry) = Entry::from_bytes_cbor(&bytes) else {
                continue;
            };
            let Ok(event) = decode_job_event(&entry.payload) else {
                continue;
            };

            let Some(spec) = event.spec() else {
                report.events_skipped += 1;
                report
                    .skipped
                    .push("a Triggered event names no job and cannot be filed".to_string());
                continue;
            };
            let job_id = spec.job_id.as_ref().to_string();
            if let Err(error) = validate_job_spec(spec) {
                report.events_skipped += 1;
                report.skipped.push(format!(
                    "{}: event contains a job spec this log cannot accept: {}",
                    job_id, error
                ));
                continue;
            }

            report.events_found += 1;
            let ts = event.ts();
            jobs.entry(job_id)
                .or_default()
                .push((ts, cid.clone(), event));
        }

        // Highest allocated run sequence per job, including the watermark
        // retained when old terminal rows were compacted.
        let mut max_run_seq: HashMap<String, u64> = HashMap::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let watermarks = txn.open_table(JOB_RUN_WATERMARKS).map_err(db_err)?;
            for item in watermarks.range::<&[u8]>(..).map_err(db_err)? {
                let (job_id, seq) = item.map_err(db_err)?;
                let job_id = std::str::from_utf8(job_id.value()).map_err(|error| {
                    ControlError::Database(format!("job run watermark key is not UTF-8: {error}"))
                })?;
                validate_job_id(job_id).map_err(|error| {
                    ControlError::Database(format!(
                        "job run watermark key contains an invalid job ID: {error}"
                    ))
                })?;
                max_run_seq.insert(job_id.to_string(), seq.value());
            }
            let table = txn.open_table(JOB_RUNS).map_err(db_err)?;
            for item in table.range::<&[u8]>(..).map_err(db_err)? {
                let (key_guard, _) = item.map_err(db_err)?;
                let (job_id, seq) = keys::decode_event_key(key_guard.value())?;
                let entry = max_run_seq.entry(job_id).or_insert(0);
                *entry = (*entry).max(seq);
            }
        }

        // Positions already filed, so recovery merges into a partly populated
        // database rather than rewriting it.
        let mut existing: HashMap<(String, u64), Cid> = HashMap::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(JOB_EVENTS).map_err(db_err)?;
            for item in table.range::<&[u8]>(..).map_err(db_err)? {
                let (key_guard, cid_guard) = item.map_err(db_err)?;
                let (job_id, seq) = keys::decode_event_key(key_guard.value())?;
                existing.insert(
                    (job_id, seq),
                    Cid::from_bytes(cid_guard.value()).map_err(db_err)?,
                );
            }
        }

        let mut accepted: Vec<(String, JobChain)> = Vec::new();
        for (job_id, events) in jobs {
            let count = events.len();
            let events = match order_chain(&job_id, events) {
                Ok(ordered) => ordered,
                Err(reason) => {
                    report.events_skipped += count;
                    report.skipped.push(reason);
                    continue;
                }
            };

            // Sequence numbers are reassigned from the recovered order, so a
            // mapping already filed at a position must agree with it.
            let conflict = events.iter().enumerate().find_map(|(i, (_, cid, _))| {
                existing
                    .get(&(job_id.clone(), i as u64 + 1))
                    .filter(|filed| *filed != cid)
                    .map(|filed| (i as u64 + 1, filed.clone(), cid.clone()))
            });
            if let Some((seq, filed, offered)) = conflict {
                report.events_skipped += events.len();
                report.skipped.push(format!(
                    "{}: seq {} is already filed as {}, refusing to replace it with {}",
                    job_id, seq, filed, offered
                ));
                continue;
            }

            accepted.push((job_id, events));
        }
        accepted.sort_by(|a, b| a.0.cmp(&b.0));

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut events_table = txn.open_table(JOB_EVENTS).map_err(db_err)?;
            let mut heads = txn.open_table(JOB_HEADS).map_err(db_err)?;

            for (job_id, events) in &accepted {
                let mut spec: Option<JobSpec> = None;
                let created_at = events[0].0;
                let mut updated_at = created_at;

                for (i, (ts, cid, event)) in events.iter().enumerate() {
                    let key = keys::encode_event_key(job_id, i as u64 + 1);
                    // Count only what the table did not already hold — the
                    // signal that a reconcile healed a truncated table.
                    if events_table.get(key.as_slice()).map_err(db_err)?.is_none() {
                        report.events_added += 1;
                    }
                    events_table
                        .insert(key.as_slice(), cid.as_bytes())
                        .map_err(db_err)?;
                    if let JobEvent::Created { spec: s, .. } | JobEvent::Updated { spec: s, .. } =
                        event
                    {
                        spec = Some(s.clone());
                    }
                    updated_at = updated_at.max(*ts);
                }

                let spec = spec.expect("a Created event was required above");
                let new_seq = events.len() as u64;
                let head = JobHead {
                    job_id: spec.job_id.clone(),
                    spec,
                    seq: new_seq,
                    created_at,
                    updated_at,
                    trigger_count: max_run_seq.get(job_id).copied().unwrap_or(0),
                };
                // Advance-only: a store chain shorter than the table's head is
                // less evidence, not divergence, and must not regress a good
                // head (the job head's `seq` is its recovered event count).
                let current_seq = match heads.get(job_id.as_bytes()).map_err(db_err)? {
                    Some(g) => Some(cbor_decode::<JobHead>(g.value())?.seq),
                    None => None,
                };
                if current_seq.is_none_or(|c| new_seq >= c) {
                    heads
                        .insert(job_id.as_bytes(), cbor_encode(&head)?.as_slice())
                        .map_err(db_err)?;
                }
                report.heads_rebuilt += 1;
            }
        }
        txn.commit().map_err(db_err)?;

        Ok(report)
    }

    /// Add `claim` to the list of claim entries filed under an effect key
    /// (idempotent). Returns whether the index changed.
    ///
    /// The index is a lookup accelerator, never an authority: adoption
    /// re-validates the claim entry itself against the requested key, so a
    /// wrong or stale row can cause a miss, not a wrong adoption.
    pub fn index_claim(&self, key_bytes: &[u8], claim: &Cid) -> Result<bool> {
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        let mut claims = self.read_claim_index(key_bytes)?;
        if claims.contains(claim) {
            drop(guard);
            return Ok(false);
        }
        if claims.len() >= MAX_EFFECT_CLAIMS_PER_KEY {
            return Err(ControlError::Capacity(format!(
                "effect key already has the maximum {MAX_EFFECT_CLAIMS_PER_KEY} indexed claims"
            )));
        }
        claims.push(claim.clone());
        let buf = cbor_encode(&claims)?;
        if buf.len() > MAX_EFFECT_CLAIM_INDEX_ROW_BYTES {
            return Err(ControlError::Capacity(format!(
                "effect-claim index row exceeds {MAX_EFFECT_CLAIM_INDEX_ROW_BYTES} bytes"
            )));
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
            table.insert(key_bytes, buf.as_slice()).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);
        Ok(true)
    }

    /// Claim entry CIDs filed under `key`.
    pub fn claims_for_key(&self, key: &EffectKey) -> Result<Vec<Cid>> {
        self.read_claim_index(&key.to_binary_key())
    }

    /// Replace the whole claim index with `by_key`, for rebuild-by-scan.
    /// Returns the number of claims indexed.
    pub fn replace_claims(
        &self,
        by_key: std::collections::HashMap<Vec<u8>, Vec<Cid>>,
    ) -> Result<u32> {
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let plan = Self::prepare_claim_rebuild(by_key)?;
        let count = plan.count();

        let txn = self.db.begin_write().map_err(db_err)?;
        self.apply_claim_rebuild(&txn, &plan)?;
        txn.commit().map_err(db_err)?;
        Ok(count)
    }

    /// Encode a deterministic replacement for the claim lookup.
    pub(crate) fn prepare_claim_rebuild(
        by_key: std::collections::HashMap<Vec<u8>, Vec<Cid>>,
    ) -> Result<ClaimRebuildPlan> {
        let mut count = 0u32;
        let mut rows = Vec::with_capacity(by_key.len());
        for (key_bytes, mut claims) in by_key {
            claims.sort_by_key(|c| c.to_hex());
            claims.dedup();
            if claims.len() > MAX_EFFECT_CLAIMS_PER_KEY {
                claims.truncate(MAX_EFFECT_CLAIMS_PER_KEY);
            }
            let encoded = cbor_encode(&claims)?;
            if encoded.len() > MAX_EFFECT_CLAIM_INDEX_ROW_BYTES {
                return Err(ControlError::Capacity(format!(
                    "effect-claim rebuild row exceeds {MAX_EFFECT_CLAIM_INDEX_ROW_BYTES} bytes"
                )));
            }
            let added = u32::try_from(claims.len())
                .map_err(|_| ControlError::Capacity("claim rebuild count overflow".into()))?;
            count = count
                .checked_add(added)
                .ok_or_else(|| ControlError::Capacity("claim rebuild count overflow".into()))?;
            rows.push((key_bytes, encoded));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(ClaimRebuildPlan { rows, count })
    }

    /// Prepare idempotent claim-index updates for a bounded, strictly decoded
    /// sync candidate set. A full row is refused rather than allowing remote
    /// input to evict a previously indexed claim; adoption can still fall
    /// back to execution after an operator resolves the saturated key.
    pub(crate) fn prepare_claim_merge(
        &self,
        by_key: std::collections::HashMap<Vec<u8>, Vec<Cid>>,
    ) -> Result<ClaimMergePlan> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
        let mut keys: Vec<_> = by_key.into_iter().collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));

        let mut rows = Vec::with_capacity(keys.len());
        let mut added = 0u32;
        for (key, mut offered) in keys {
            offered.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            offered.dedup();
            let mut merged = match table.get(key.as_slice()).map_err(db_err)? {
                Some(value) => decode_claim_index_row(value.value())?,
                None => Vec::new(),
            };
            let mut seen: std::collections::HashSet<Cid> = merged.iter().cloned().collect();
            let before = merged.len();
            for cid in offered {
                if seen.insert(cid.clone()) {
                    merged.push(cid);
                }
            }
            if merged.len() > MAX_EFFECT_CLAIMS_PER_KEY {
                return Err(ControlError::Capacity(format!(
                    "sync would give one effect key {} indexed claims, above the {MAX_EFFECT_CLAIMS_PER_KEY}-claim limit",
                    merged.len()
                )));
            }
            let newly_added = merged.len() - before;
            if newly_added == 0 {
                continue;
            }
            added = added
                .checked_add(u32::try_from(newly_added).map_err(|_| {
                    ControlError::Capacity("effect-claim sync-merge count overflow".into())
                })?)
                .ok_or_else(|| {
                    ControlError::Capacity("effect-claim sync-merge count overflow".into())
                })?;
            let encoded = cbor_encode(&merged)?;
            if encoded.len() > MAX_EFFECT_CLAIM_INDEX_ROW_BYTES {
                return Err(ControlError::Capacity(format!(
                    "effect-claim sync-merge row exceeds {MAX_EFFECT_CLAIM_INDEX_ROW_BYTES} bytes"
                )));
            }
            rows.push((key, encoded));
        }
        Ok(ClaimMergePlan { rows, added })
    }

    /// Replace the claim lookup in a caller-owned transaction.
    pub(crate) fn apply_claim_rebuild(
        &self,
        txn: &WriteTransaction,
        plan: &ClaimRebuildPlan,
    ) -> Result<()> {
        let mut table = txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
        table.retain(|_, _| false).map_err(db_err)?;
        for (key, claims) in &plan.rows {
            table
                .insert(key.as_slice(), claims.as_slice())
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// Apply an incremental claim plan in a caller-owned atomic publication.
    pub(crate) fn apply_claim_merge(
        &self,
        txn: &WriteTransaction,
        plan: &ClaimMergePlan,
    ) -> Result<()> {
        let mut table = txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
        for (key, claims) in &plan.rows {
            table
                .insert(key.as_slice(), claims.as_slice())
                .map_err(db_err)?;
        }
        Ok(())
    }

    fn read_claim_index(&self, key: &[u8]) -> Result<Vec<Cid>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EFFECT_CLAIMS).map_err(db_err)?;
        match table.get(key).map_err(db_err)? {
            Some(value) => decode_claim_index_row(value.value()),
            None => Ok(Vec::new()),
        }
    }
}

/// EffectCache trait implementation for JobLog
impl crate::integration::EffectCache for JobLog {
    fn get(&self, key: &EffectKey) -> Result<Option<Vec<(String, Cid)>>> {
        self.get_effect_cache(key)
    }

    fn store(&self, key: &EffectKey, outputs: &[(String, Cid)]) -> Result<()> {
        self.store_effect_cache(key, outputs)
    }
}

fn pending_run(
    job_id: &JobId,
    run_id: RunId,
    revision: JobRevision,
    manifest: InputManifest,
) -> JobRun {
    JobRun {
        run_id,
        job_id: job_id.clone(),
        // Inputs are resolved and frozen before queue admission.
        manifest,
        outputs: Vec::new(),
        status: RunStatus::Pending,
        node_id: None,
        started_at_unix: 0,
        finished_at_unix: None,
        origin: dag_core::RunOrigin::Executed,
        revision: Some(revision),
    }
}

fn status_label(status: &RunStatus) -> &'static str {
    match status {
        RunStatus::Pending => "Pending",
        RunStatus::Running => "Running",
        RunStatus::Succeeded => "Succeeded",
        RunStatus::Failed { .. } => "Failed",
    }
}

fn is_terminal(status: &RunStatus) -> bool {
    matches!(status, RunStatus::Succeeded | RunStatus::Failed { .. })
}

fn invalid_transition(from: &RunStatus, to: &str) -> JobError {
    JobError::ExecutionFailed(format!(
        "invalid run transition from {} to {to}",
        status_label(from)
    ))
}

/// Helper: encode to CBOR
fn cbor_encode<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Helper: decode from CBOR
fn cbor_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    dag_core::decode_cbor_exact(bytes).map_err(|error| ControlError::Codec(error.to_string()))
}

fn decode_claim_index_row(bytes: &[u8]) -> Result<Vec<Cid>> {
    if bytes.len() > MAX_EFFECT_CLAIM_INDEX_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "effect-claim index row exceeds {MAX_EFFECT_CLAIM_INDEX_ROW_BYTES} bytes"
        )));
    }
    let claims: Vec<Cid> = cbor_decode(bytes)?;
    if claims.len() > MAX_EFFECT_CLAIMS_PER_KEY {
        return Err(ControlError::Database(format!(
            "effect-claim index row contains {} claims, above the {MAX_EFFECT_CLAIMS_PER_KEY} limit",
            claims.len()
        )));
    }
    let mut unique = std::collections::HashSet::with_capacity(claims.len());
    if claims.iter().any(|cid| !unique.insert(cid.clone())) {
        return Err(ControlError::Database(
            "effect-claim index row contains duplicate CIDs".into(),
        ));
    }
    Ok(claims)
}

fn decode_job_head(bytes: &[u8], expected_id: Option<&str>) -> Result<JobHead> {
    if bytes.len() > MAX_JOB_HEAD_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "job head row exceeds {MAX_JOB_HEAD_ROW_BYTES} bytes"
        )));
    }
    let head: JobHead = cbor_decode(bytes)?;
    validate_job_spec(&head.spec).map_err(|error| {
        ControlError::Database(format!(
            "job head contains an invalid specification: {error}"
        ))
    })?;
    if head.seq == 0 || head.job_id != head.spec.job_id {
        return Err(ControlError::Database(
            "job head contains mismatched IDs or sequence zero".to_string(),
        ));
    }
    if expected_id.is_some_and(|expected| head.job_id.as_ref() != expected) {
        return Err(ControlError::Database(
            "job head's embedded ID does not match its table key".to_string(),
        ));
    }
    Ok(head)
}

/// Decode a persisted run only after bounding its encoded size, then validate
/// every generic field whose contract does not require loading the immutable
/// job revision. Active-run reconciliation additionally validates the exact
/// filed spec and manifest before a row can remain runnable.
fn decode_job_run(bytes: &[u8]) -> Result<JobRun> {
    if bytes.len() > MAX_JOB_RUN_ROW_BYTES {
        return Err(ControlError::Database(format!(
            "job run row exceeds {MAX_JOB_RUN_ROW_BYTES} bytes"
        )));
    }
    let run: JobRun = cbor_decode(bytes)?;
    validate_job_id(run.job_id.as_ref()).map_err(|error| {
        ControlError::Database(format!("job run contains an invalid job ID: {error}"))
    })?;
    if run.run_id.0 == 0 {
        return Err(ControlError::Database(
            "job run contains sequence zero".to_string(),
        ));
    }
    if run.manifest.static_inputs.len() > dag_core::MAX_JOB_STATIC_INPUTS
        || run.manifest.pointer_heads.len() > dag_core::MAX_JOB_POINTER_INPUTS
    {
        return Err(ControlError::Database(
            "job run manifest exceeds the input-count limits".to_string(),
        ));
    }
    for pointer in &run.manifest.pointer_heads {
        crate::pointer::validate_pointer_id(&pointer.pointer_id).map_err(|error| {
            ControlError::Database(format!(
                "job run manifest contains an invalid pointer ID: {error}"
            ))
        })?;
    }
    validate_output_shape(&run.outputs).map_err(|error| {
        ControlError::Database(format!("job run contains invalid outputs: {error}"))
    })?;
    if let RunStatus::Failed { message } = &run.status {
        if message.len() > MAX_RUN_FAILURE_MESSAGE_BYTES {
            return Err(ControlError::Database(format!(
                "job run failure message exceeds {MAX_RUN_FAILURE_MESSAGE_BYTES} bytes"
            )));
        }
    }
    if run
        .node_id
        .as_ref()
        .is_some_and(|node| node.is_empty() || node.len() > 256)
    {
        return Err(ControlError::Database(
            "job run contains an invalid node ID".to_string(),
        ));
    }
    if let Some(revision) = &run.revision {
        if revision.event_seq == 0
            || revision.code_ref.is_empty()
            || revision.code_ref.len() > dag_core::MAX_JOB_CODE_REF_BYTES
            || revision.code_ref.chars().any(char::is_control)
        {
            return Err(ControlError::Database(
                "job run contains an invalid immutable revision".to_string(),
            ));
        }
    }
    Ok(run)
}

/// Get current Unix timestamp
fn current_timestamp() -> i64 {
    crate::now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::{Determinism, JobInput, JobPolicy, TriggerPolicy};
    use dag_storage::FsStore;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Arc<FsStore>, JobLog) {
        let temp = TempDir::new().unwrap();

        let store = Arc::new(FsStore::new(temp.path().join("data")).unwrap());
        let db = Arc::new(Database::create(temp.path().join("control.redb")).unwrap());

        // Keep unit tests independent from the event system
        let job_log = JobLog::new(db, store.clone()).unwrap();

        (temp, store, job_log)
    }

    fn spec(id: &str, code_ref: &str) -> JobSpec {
        JobSpec {
            job_id: JobId::from(id),
            placement: Some("node1".into()),
            inputs: JobInput::new(),
            determinism: Determinism::Deterministic,
            declared_outputs: vec![],
            code_ref: code_ref.into(),
            policy: JobPolicy::default(),
            config: None,
        }
    }

    #[test]
    fn immutable_job_event_decoder_rejects_trailing_cbor() {
        let event = JobEvent::Created {
            spec: spec("strict", "hash"),
            ts: 1,
            prev: None,
        };
        let mut payload = cbor_encode(&event).unwrap();
        assert!(matches!(
            decode_job_event(&payload).unwrap(),
            JobEvent::Created { .. }
        ));

        payload.push(0xf6); // a second, valid CBOR value
        assert!(matches!(
            decode_job_event(&payload),
            Err(ControlError::Codec(_))
        ));
    }

    #[test]
    fn oversized_dead_letter_and_lease_rows_are_refused_before_decode() {
        let (_temp, _store, job_log) = setup();
        let txn = job_log.db.begin_write().unwrap();
        {
            let mut dead = txn.open_table(TRIGGER_DEAD_LETTERS).unwrap();
            dead.insert(
                b"oversized".as_slice(),
                vec![0u8; MAX_TRIGGER_DEAD_LETTER_ROW_BYTES + 1].as_slice(),
            )
            .unwrap();
        }
        txn.commit().unwrap();
        assert!(matches!(
            job_log.list_trigger_dead_letters(1),
            Err(ControlError::Database(_))
        ));

        let job = spec("bounded-lease", "hash");
        job_log.create_job(job.clone()).unwrap();
        job_log.trigger_job(&job.job_id, "test").unwrap();
        let claim = job_log
            .claim_next_pending("worker", MIN_LEASE_SECONDS)
            .unwrap()
            .unwrap();
        let run_key = keys::encode_run_key(job.job_id.as_ref(), claim.run_id.0);
        let txn = job_log.db.begin_write().unwrap();
        {
            let mut leases = txn.open_table(RUN_LEASES).unwrap();
            leases
                .insert(
                    run_key.as_slice(),
                    vec![0u8; MAX_RUN_LEASE_ROW_BYTES + 1].as_slice(),
                )
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(matches!(
            job_log.require_claim(&run_key, &claim),
            Err(ControlError::Database(_))
        ));
        assert!(matches!(
            job_log.expire_run_claims(),
            Err(ControlError::Database(_))
        ));
    }

    #[test]
    fn event_cids_names_each_stored_job_event() {
        let (_temp, store, job_log) = setup();
        job_log.create_job(spec("digest", "hash")).unwrap();
        job_log.create_job(spec("join", "concat")).unwrap();

        let mut events = job_log.event_cids().unwrap();
        assert_eq!(events.len(), 2, "each created job records one event");
        events.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!((events[0].0.as_str(), events[0].1), ("digest", 1));
        assert_eq!((events[1].0.as_str(), events[1].1), ("join", 1));

        // Each named CID resolves to a decodable JobEvent entry in the store,
        // which is what recovery reads.
        for (_, _, cid) in &events {
            let entry = store.get_entry(cid).unwrap();
            let _ev: JobEvent = cbor_decode(&entry.payload).unwrap();
        }
    }

    #[test]
    fn a_job_event_encodes_as_an_externally_tagged_map_carrying_ts() {
        // The GC backstop in dag-storage (`gc::looks_like_job_event`) cannot
        // import `JobEvent` — dag-storage sits below this crate — so it
        // recognises the CBOR shape by hand. This pins that shape so the
        // backstop cannot silently drift out of agreement with it: a
        // single-entry map keyed by the variant name, whose value is a map
        // carrying `ts`.
        let ev = JobEvent::Created {
            spec: spec("digest", "hash"),
            ts: 42,
            prev: None,
        };
        let bytes = cbor_encode(&ev).unwrap();
        let value: ciborium::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();

        let map = match value {
            ciborium::Value::Map(m) => m,
            other => panic!("expected a map, got {other:?}"),
        };
        assert_eq!(map.len(), 1, "an externally-tagged enum is one entry");
        let (key, val) = &map[0];
        assert!(
            matches!(key, ciborium::Value::Text(s) if s == "Created"),
            "keyed by the variant name"
        );
        let fields = match val {
            ciborium::Value::Map(f) => f,
            other => panic!("the variant value is a map, got {other:?}"),
        };
        assert!(
            fields
                .iter()
                .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "ts")),
            "every JobEvent variant carries ts"
        );
    }

    #[test]
    fn test_create_and_get_job() {
        let (_temp, _store, job_log) = setup();

        let spec = JobSpec {
            job_id: JobId::from("test-job"),
            placement: Some("node1".into()),
            inputs: JobInput::new().with_static(Cid::compute(b"input1")),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["output".into()],
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        job_log.create_job(spec.clone()).unwrap();

        let head = job_log.get_job(&spec.job_id).unwrap().unwrap();
        assert_eq!(head.job_id, spec.job_id);
        assert_eq!(head.spec.code_ref, "hash");
        assert_eq!(head.seq, 1);
        assert_eq!(head.trigger_count, 0);
    }

    #[test]
    fn test_duplicate_job_fails() {
        let (_temp, _store, job_log) = setup();

        let spec = spec("duplicate-job", "hash");
        job_log.create_job(spec.clone()).unwrap();
        let result = job_log.create_job(spec);
        assert!(result.is_err());
    }

    #[test]
    fn test_trigger_job() {
        let (_temp, _store, job_log) = setup();

        let spec = JobSpec {
            job_id: JobId::from("trigger-test"),
            placement: Some("node1".into()),
            inputs: JobInput::new()
                .with_static(Cid::compute(b"input1"))
                .with_static(Cid::compute(b"input2")),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["output".into()],
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        job_log.create_job(spec.clone()).unwrap();

        let run_id = job_log.trigger_job(&spec.job_id, "manual trigger").unwrap();
        assert_eq!(run_id.0, 1);

        // Check head updated
        let head = job_log.get_job(&spec.job_id).unwrap().unwrap();
        assert_eq!(head.trigger_count, 1);

        // Check run created
        let runs = job_log.get_job_runs(&spec.job_id, None).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert!(matches!(runs[0].status, RunStatus::Pending));
    }

    #[test]
    fn test_record_run_lifecycle() {
        let (_temp, _store, job_log) = setup();

        let spec = JobSpec {
            job_id: JobId::from("lifecycle-test"),
            placement: Some("node1".into()),
            inputs: JobInput::new().with_static(Cid::compute(b"input")),
            determinism: Determinism::Deterministic,
            declared_outputs: vec!["result".into()],
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: None,
        };

        job_log.create_job(spec.clone()).unwrap();
        let run_id = job_log.trigger_job(&spec.job_id, "test").unwrap();
        let claim = job_log
            .claim_pending_run(&spec.job_id, &run_id, "worker-1", 60)
            .unwrap();
        let prepared = job_log.claimed_run(&claim).unwrap();

        // Start run
        job_log
            .record_claimed_run_started(&claim, &prepared.manifest)
            .unwrap();
        let runs = job_log.get_job_runs(&spec.job_id, None).unwrap();
        assert!(matches!(runs[0].status, RunStatus::Running));
        assert_eq!(runs[0].node_id, Some("worker-1".to_string()));
        assert!(runs[0].started_at_unix > 0);

        // Complete run
        let output_cid = Cid::compute(b"result data");
        job_log
            .record_claimed_run_completed(
                &claim,
                vec![("result".into(), output_cid.clone())],
                RunStatus::Succeeded,
                None,
            )
            .unwrap();

        let runs = job_log.get_job_runs(&spec.job_id, None).unwrap();
        assert!(matches!(runs[0].status, RunStatus::Succeeded));
        assert_eq!(runs[0].outputs.len(), 1);
        assert_eq!(runs[0].outputs[0].0, "result");
        assert_eq!(runs[0].outputs[0].1, output_cid);
        assert!(runs[0].finished_at_unix.is_some());
    }

    #[test]
    fn terminal_run_compaction_preserves_the_run_id_watermark() {
        let (_temp, _store, job_log) = setup();
        let job = spec("compact-runs", "hash");
        job_log.create_job(job.clone()).unwrap();
        for _ in 0..5 {
            let run = job_log.trigger_job(&job.job_id, "test").unwrap();
            let claim = job_log
                .claim_pending_run(&job.job_id, &run, "test-worker", 60)
                .unwrap();
            job_log
                .record_claimed_run_completed(
                    &claim,
                    Vec::new(),
                    RunStatus::Failed {
                        message: "expected test failure".to_string(),
                    },
                    None,
                )
                .unwrap();
        }

        let dry = job_log
            .compact_terminal_runs(&job.job_id, 2, 10, true)
            .unwrap();
        assert_eq!(dry.eligible, 3);
        assert_eq!(dry.deleted, 0);
        assert_eq!(job_log.get_job_runs(&job.job_id, None).unwrap().len(), 5);

        let applied = job_log
            .compact_terminal_runs(&job.job_id, 2, 10, false)
            .unwrap();
        assert_eq!(applied.deleted, 3);
        let retained = job_log.get_job_runs(&job.job_id, None).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].run_id, RunId(5));
        assert_eq!(retained[1].run_id, RunId(4));

        job_log.rebuild().unwrap();
        assert_eq!(
            job_log.get_job(&job.job_id).unwrap().unwrap().trigger_count,
            5
        );
        assert_eq!(
            job_log
                .trigger_job(&job.job_id, "after compaction")
                .unwrap(),
            RunId(6)
        );
    }

    #[test]
    fn leased_run_is_fenced_and_cannot_be_completed_twice() {
        let (_temp, _store, job_log) = setup();
        let job = spec("leased", "hash");
        job_log.create_job(job.clone()).unwrap();
        let run_id = job_log.trigger_job(&job.job_id, "test").unwrap();
        assert_eq!(job_log.active_run_counts().unwrap(), (1, 0));

        let claim = job_log
            .claim_next_pending("worker-a", 60)
            .unwrap()
            .expect("pending run should be claimable");
        assert_eq!(job_log.active_run_counts().unwrap(), (1, 0));
        assert_eq!(claim.run_id, run_id);
        assert!(job_log
            .claim_next_pending("worker-b", 60)
            .unwrap()
            .is_none());

        let manifest = InputManifest {
            static_inputs: Vec::new(),
            pointer_heads: Vec::new(),
            resolved_at_unix: current_timestamp(),
        };
        job_log
            .record_claimed_run_started(&claim, &manifest)
            .unwrap();
        assert_eq!(job_log.active_run_counts().unwrap(), (0, 1));
        job_log.renew_run_claim(&claim).unwrap();
        job_log
            .record_claimed_run_completed(&claim, Vec::new(), RunStatus::Succeeded, None)
            .unwrap();
        assert_eq!(job_log.active_run_counts().unwrap(), (0, 0));

        assert!(job_log
            .record_claimed_run_completed(&claim, Vec::new(), RunStatus::Succeeded, None,)
            .is_err());
        assert!(job_log.renew_run_claim(&claim).is_err());
        assert!(matches!(
            job_log.get_job_runs(&job.job_id, None).unwrap()[0].status,
            RunStatus::Succeeded
        ));
    }

    #[test]
    fn claimed_completion_validates_outputs_and_bounds_failure_text() {
        let (_temp, _store, job_log) = setup();
        let mut job = spec("bounded-completion", "hash");
        job.declared_outputs = vec!["expected".to_string()];
        job_log.create_job(job.clone()).unwrap();
        let run_id = job_log.trigger_job(&job.job_id, "test").unwrap();
        let claim = job_log
            .claim_pending_run(&job.job_id, &run_id, "worker", 60)
            .unwrap();
        let prepared = job_log.claimed_run(&claim).unwrap();
        job_log
            .record_claimed_run_started(&claim, &prepared.manifest)
            .unwrap();
        assert!(job_log
            .record_claimed_run_completed(
                &claim,
                vec![("wrong".to_string(), Cid::compute(b"out"))],
                RunStatus::Succeeded,
                None,
            )
            .is_err());
        assert!(job_log
            .record_claimed_run_completed(
                &claim,
                vec![("expected".to_string(), Cid::compute(b"out"))],
                RunStatus::Failed {
                    message: "failed".to_string(),
                },
                None,
            )
            .is_err());
        job_log
            .record_claimed_run_completed(
                &claim,
                Vec::new(),
                RunStatus::Failed {
                    message: "x".repeat(MAX_RUN_FAILURE_MESSAGE_BYTES + 1_000),
                },
                None,
            )
            .unwrap();
        let run = &job_log.get_job_runs(&job.job_id, Some(1)).unwrap()[0];
        let RunStatus::Failed { message } = &run.status else {
            panic!("run should be failed");
        };
        assert_eq!(message.len(), MAX_RUN_FAILURE_MESSAGE_BYTES);
    }

    #[test]
    fn effect_cache_rejects_ambiguous_output_shapes() {
        let (_temp, _store, job_log) = setup();
        let key = EffectKey::new(JobId::from("cache-shape"), Cid::compute(b"m"), "x".into());
        assert!(job_log
            .store_effect_cache(
                &key,
                &[
                    ("same".to_string(), Cid::compute(b"a")),
                    ("same".to_string(), Cid::compute(b"b")),
                ],
            )
            .is_err());

        let binary_key = key.to_binary_key();
        let oversized = vec![0u8; MAX_EFFECT_CACHE_ROW_BYTES + 1];
        let txn = job_log.db.begin_write().unwrap();
        txn.open_table(EFFECT_CACHE)
            .unwrap()
            .insert(binary_key.as_slice(), oversized.as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(matches!(
            job_log.get_effect_cache(&key),
            Err(ControlError::Database(_))
        ));

        let invalid = vec![(
            "n".repeat(dag_core::MAX_JOB_NAME_BYTES + 1),
            Cid::compute(b"invalid-name"),
        )];
        let encoded = cbor_encode(&invalid).unwrap();
        let txn = job_log.db.begin_write().unwrap();
        txn.open_table(EFFECT_CACHE)
            .unwrap()
            .insert(binary_key.as_slice(), encoded.as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(job_log.get_effect_cache(&key).is_err());
    }

    #[test]
    fn claims_follow_global_enqueue_order_across_job_ids() {
        let (_temp, _store, job_log) = setup();
        let older = spec("z-older", "hash");
        let newer = spec("a-newer", "hash");
        job_log.create_job(older.clone()).unwrap();
        job_log.create_job(newer.clone()).unwrap();
        job_log.trigger_job(&older.job_id, "older").unwrap();
        job_log.trigger_job(&newer.job_id, "newer").unwrap();

        let claim = job_log
            .claim_next_pending("worker", 60)
            .unwrap()
            .expect("one run should be claimable");

        assert_eq!(claim.job_id, older.job_id);
    }

    #[test]
    fn an_ineligible_older_run_does_not_block_capable_work() {
        let (_temp, _store, job_log) = setup();
        let unavailable = spec("a-exec", "exec");
        let runnable = spec("z-hash", "hash");
        job_log.create_job(unavailable.clone()).unwrap();
        job_log.create_job(runnable.clone()).unwrap();
        job_log.trigger_job(&unavailable.job_id, "older").unwrap();
        job_log.trigger_job(&runnable.job_id, "newer").unwrap();

        let claim = job_log
            .claim_next_pending_for_code_refs("safe-worker", 60, &["hash"])
            .unwrap()
            .expect("the later supported run should be claimable");

        assert_eq!(claim.job_id, runnable.job_id);
        assert!(matches!(
            job_log.get_job_runs(&unavailable.job_id, None).unwrap()[0].status,
            RunStatus::Pending
        ));
    }

    #[test]
    fn allowed_adapter_claim_does_not_scan_an_unsupported_backlog() {
        let (_temp, _store, job_log) = setup();
        let unavailable = spec("unsupported-backlog", "exec");
        let runnable = spec("supported-tail", "hash");
        job_log.create_job(unavailable.clone()).unwrap();
        job_log.create_job(runnable.clone()).unwrap();
        for _ in 0..2_000 {
            job_log
                .trigger_job(&unavailable.job_id, "unsupported")
                .unwrap();
        }
        job_log.trigger_job(&runnable.job_id, "supported").unwrap();

        let before = CLAIM_INDEX_ROWS_SCANNED.load(std::sync::atomic::Ordering::Relaxed);
        let claim = job_log
            .claim_next_pending_for_code_refs("safe-worker", 60, &["hash"])
            .unwrap()
            .unwrap();
        let inspected = CLAIM_INDEX_ROWS_SCANNED
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(before);
        assert_eq!(claim.job_id, runnable.job_id);
        assert!(
            inspected < 50,
            "claim inspected {inspected} rows despite 2,000 unsupported rows"
        );
    }

    #[test]
    fn pending_capacity_is_checked_in_the_insertion_transaction() {
        let (_temp, _store, job_log) = setup();
        let txn = job_log.db.begin_write().unwrap();
        {
            let mut pending = txn.open_table(PENDING_RUNS).unwrap();
            for index in 0..3u64 {
                pending
                    .insert(index.to_be_bytes().as_slice(), index)
                    .unwrap();
            }
        }
        assert!(matches!(
            ensure_pending_capacity_at(&txn, 3),
            Err(ControlError::Capacity(_))
        ));
        txn.abort().unwrap();
    }

    #[test]
    fn schema_five_terminalises_legacy_active_rows_without_a_revision() {
        let temp = TempDir::new().unwrap();
        let store = Arc::new(FsStore::new(temp.path().join("data")).unwrap());
        let db = Arc::new(Database::create(temp.path().join("control.redb")).unwrap());
        let run_key = keys::encode_run_key("legacy-active", 1);
        let legacy = JobRun {
            run_id: RunId(1),
            job_id: JobId::from("legacy-active"),
            manifest: InputManifest {
                static_inputs: Vec::new(),
                pointer_heads: Vec::new(),
                resolved_at_unix: 0,
            },
            outputs: Vec::new(),
            status: RunStatus::Pending,
            node_id: None,
            started_at_unix: 0,
            finished_at_unix: None,
            origin: dag_core::RunOrigin::Executed,
            revision: None,
        };
        let txn = db.begin_write().unwrap();
        {
            const SCHEMA_TABLE: TableDefinition<&str, u32> = TableDefinition::new("schema");
            txn.open_table(SCHEMA_TABLE)
                .unwrap()
                .insert("version", 4)
                .unwrap();
            txn.open_table(JOB_RUNS)
                .unwrap()
                .insert(run_key.as_slice(), cbor_encode(&legacy).unwrap().as_slice())
                .unwrap();
            txn.open_table(PENDING_RUNS)
                .unwrap()
                .insert(run_key.as_slice(), 1)
                .unwrap();
        }
        txn.commit().unwrap();

        let log = JobLog::new(db, store).unwrap();
        let run = &log
            .get_job_runs(&JobId::from("legacy-active"), Some(1))
            .unwrap()[0];
        assert!(matches!(run.status, RunStatus::Failed { .. }));
        assert_eq!(log.active_run_counts().unwrap(), (0, 0));
    }

    #[test]
    fn corrupt_terminal_history_does_not_block_current_schema_startup() {
        let (_temp, store, log) = setup();
        let key = keys::encode_run_key("corrupt-terminal", 1);
        let txn = log.db.begin_write().unwrap();
        txn.open_table(JOB_RUNS)
            .unwrap()
            .insert(key.as_slice(), b"not cbor".as_slice())
            .unwrap();
        txn.commit().unwrap();

        JobLog::new(log.db.clone(), store).expect(
            "current-schema startup reads bounded active indexes, not corrupt terminal history",
        );
    }

    #[test]
    fn rebuild_refuses_malformed_authoritative_event_keys() {
        let (_temp, _store, log) = setup();
        let mut key = keys::encode_event_key("malformed", 1);
        key.push(0);
        let txn = log.db.begin_write().unwrap();
        txn.open_table(JOB_EVENTS)
            .unwrap()
            .insert(key.as_slice(), Cid::compute(b"event").as_bytes())
            .unwrap();
        txn.commit().unwrap();
        assert!(log.rebuild().is_err());
        assert!(log.event_cids().is_err());
    }

    #[test]
    fn run_pages_do_not_scan_lexicographically_later_jobs() {
        let (_temp, _store, job_log) = setup();
        let target = spec("a-target", "hash");
        let later = spec("z-large-history", "hash");
        job_log.create_job(target.clone()).unwrap();
        job_log.create_job(later.clone()).unwrap();
        for _ in 0..3 {
            job_log.trigger_job(&target.job_id, "target").unwrap();
        }
        for _ in 0..2_000 {
            job_log.trigger_job(&later.job_id, "later").unwrap();
        }

        let before = RUN_PAGE_ROWS_DECODED.load(std::sync::atomic::Ordering::Relaxed);
        let first = job_log.get_job_runs_page(&target.job_id, None, 2).unwrap();
        let second = job_log
            .get_job_runs_page(&target.job_id, Some(2), 2)
            .unwrap();
        let decoded = RUN_PAGE_ROWS_DECODED
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(before);
        assert_eq!(
            first.iter().map(|run| run.run_id.0).collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(
            second.iter().map(|run| run.run_id.0).collect::<Vec<_>>(),
            vec![1]
        );
        assert!(decoded < 50, "decoded {decoded} rows for a three-row job");
    }

    #[test]
    fn trigger_dead_letters_are_inspectable_and_boundedly_purgeable() {
        let (_temp, _store, job_log) = setup();
        for index in 0..3 {
            let dead = DeadTrigger {
                trigger: QueuedTrigger {
                    job_id: JobId::from(format!("missing-{index}")),
                    reason: format!("test-{index}"),
                    queued_at_unix: 100 + index,
                    revision: None,
                    manifest: None,
                },
                error: "job was removed".to_string(),
                failed_at_unix: 200 + index,
            };
            job_log
                .remove_trigger_intent(format!("key-{index}").as_bytes(), Some(&dead))
                .unwrap();
        }

        let listed = job_log.list_trigger_dead_letters(2).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed
            .iter()
            .all(|letter| letter.error == "job was removed"));

        let dry = job_log.compact_trigger_dead_letters(2, true).unwrap();
        assert_eq!(dry.total, 3);
        assert_eq!(dry.selected, 2);
        assert_eq!(dry.deleted, 0);
        let applied = job_log.compact_trigger_dead_letters(2, false).unwrap();
        assert_eq!(applied.deleted, 2);
        assert_eq!(applied.remaining, 1);
        assert_eq!(job_log.trigger_queue_depths().unwrap(), (0, 1));
    }

    #[test]
    fn active_work_gc_snapshot_has_an_aggregate_encoded_byte_limit() {
        let directory = TempDir::new().unwrap();
        let control = crate::Control::open(directory.path()).unwrap();
        let retained = control.store.put_chunk(b"retained input", None).unwrap();
        let trigger_v1 = control.store.put_chunk(b"trigger one", None).unwrap();
        control
            .pointer_log
            .create("bounded-input", retained.clone())
            .unwrap();
        control
            .pointer_log
            .create("bounded-trigger", trigger_v1)
            .unwrap();
        let mut job = spec("bounded-active-work", "hash");
        job.inputs = JobInput::new().with_pointer("bounded-input");
        job.policy.trigger = TriggerPolicy::OnPointerUpdate;
        control.create_job(job.clone()).unwrap();
        control
            .subscribe_pointer("bounded-trigger", job.job_id)
            .unwrap();
        for value in [b"trigger two".as_slice(), b"trigger three".as_slice()] {
            let cid = control.store.put_chunk(value, None).unwrap();
            control.pointer_log.update("bounded-trigger", cid).unwrap();
        }

        let encoded_bytes = {
            let txn = control.job_log.db.begin_read().unwrap();
            let queue = txn.open_table(TRIGGER_QUEUE).unwrap();
            queue
                .range::<&[u8]>(..)
                .unwrap()
                .map(|row| row.unwrap().1.value().len())
                .sum::<usize>()
        };
        assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (2, 0));
        let error = control
            .job_log
            .active_work_retention_roots_with_limits(encoded_bytes - 1, usize::MAX)
            .unwrap_err();
        assert!(matches!(error, ControlError::Capacity(_)));
        assert!(control.store.has_chunk(&retained).unwrap());

        let error = control
            .job_log
            .active_work_retention_roots_with_limits(encoded_bytes, 3)
            .unwrap_err();
        assert!(matches!(error, ControlError::Capacity(_)));
        assert!(control.store.has_chunk(&retained).unwrap());
    }

    #[test]
    fn expired_running_lease_fails_closed_without_retrying() {
        let (_temp, _store, job_log) = setup();
        let job = spec("expired", "hash");
        job_log.create_job(job.clone()).unwrap();
        job_log.trigger_job(&job.job_id, "test").unwrap();
        let claim = job_log
            .claim_next_pending("gone-worker", MIN_LEASE_SECONDS)
            .unwrap()
            .unwrap();
        let manifest = InputManifest {
            static_inputs: Vec::new(),
            pointer_heads: Vec::new(),
            resolved_at_unix: current_timestamp(),
        };
        job_log
            .record_claimed_run_started(&claim, &manifest)
            .unwrap();

        // Age the internal lease without sleeping. This is a unit test in the
        // module that owns the lease encoding, so production APIs never gain
        // a clock-forging escape hatch merely to make the case reachable.
        let key = keys::encode_run_key(job.job_id.as_ref(), claim.run_id.0);
        let mut lease = job_log.require_claim(&key, &claim).unwrap();
        lease.expires_at_unix = current_timestamp() - 1;
        let bytes = cbor_encode(&lease).unwrap();
        let txn = job_log.db.begin_write().unwrap();
        {
            let mut leases = txn.open_table(RUN_LEASES).unwrap();
            leases.insert(key.as_slice(), bytes.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        assert!(job_log.renew_run_claim(&claim).is_err());
        assert_eq!(job_log.expire_run_claims().unwrap(), 1);
        let runs = job_log.get_job_runs(&job.job_id, None).unwrap();
        assert_eq!(runs.len(), 1);
        match &runs[0].status {
            RunStatus::Failed { message } => {
                assert!(message.contains("automatic retry is disabled"));
            }
            other => panic!("expected fail-closed run, got {other:?}"),
        }
        assert!(job_log
            .claim_next_pending("worker-b", 60)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_pointer_subscriptions() {
        let (_temp, _store, job_log) = setup();

        let mut spec1 = spec("job1", "hash");
        spec1.policy.trigger = TriggerPolicy::OnPointerUpdate;
        let mut spec2 = spec("job2", "hash");
        spec2.policy.trigger = TriggerPolicy::OnPointerUpdate;

        job_log.create_job(spec1.clone()).unwrap();
        job_log.create_job(spec2.clone()).unwrap();

        // Subscribe both jobs to same pointer
        job_log.subscribe_pointer("ptr1", &spec1.job_id).unwrap();
        job_log.subscribe_pointer("ptr1", &spec2.job_id).unwrap();

        let subscribed = job_log.get_pointer_subscriptions("ptr1").unwrap();
        assert_eq!(subscribed.len(), 2);
        assert!(subscribed.contains(&spec1.job_id));
        assert!(subscribed.contains(&spec2.job_id));

        // No duplicate subscriptions
        job_log.subscribe_pointer("ptr1", &spec1.job_id).unwrap();
        let subscribed = job_log.get_pointer_subscriptions("ptr1").unwrap();
        assert_eq!(subscribed.len(), 2);
    }

    #[test]
    fn test_effect_cache() {
        let (_temp, _store, job_log) = setup();

        let effect_key = EffectKey::new(
            JobId::from("fetch-job"),
            Cid::compute(b"manifest"),
            "https://example.com/data".to_string(),
        );

        let outputs = vec![
            ("artifact1".into(), Cid::compute(b"data1")),
            ("artifact2".into(), Cid::compute(b"data2")),
        ];

        // Store in cache
        job_log.store_effect_cache(&effect_key, &outputs).unwrap();

        // Retrieve from cache
        let cached = job_log.get_effect_cache(&effect_key).unwrap().unwrap();
        assert_eq!(cached.len(), 2);
        assert_eq!(cached[0].0, "artifact1");
        assert_eq!(cached[1].0, "artifact2");

        // Non-existent key
        let other_key = EffectKey::new(
            JobId::from("other-job"),
            Cid::compute(b"other"),
            "other".to_string(),
        );
        assert!(job_log.get_effect_cache(&other_key).unwrap().is_none());
    }

    #[test]
    fn test_list_jobs() {
        let (_temp, _store, job_log) = setup();

        job_log.create_job(spec("job-a", "hash")).unwrap();
        job_log.create_job(spec("job-b", "concat")).unwrap();

        let jobs = job_log.list_jobs().unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[test]
    fn job_id_pages_are_bounded_and_do_not_repeat_the_cursor() {
        let (_temp, _store, job_log) = setup();
        for id in ["job-a", "job-b", "job-c"] {
            job_log.create_job(spec(id, "hash")).unwrap();
        }

        assert_eq!(
            job_log.list_job_ids_page(None, 2).unwrap(),
            vec!["job-a", "job-b"]
        );
        assert_eq!(
            job_log.list_job_ids_page(Some("job-b"), 2).unwrap(),
            vec!["job-c"]
        );
        assert!(job_log.list_job_ids_page(None, 0).unwrap().is_empty());
    }

    /// The heads table is a cache over job_events + job_runs; wiping and
    /// rebuilding it must reproduce exactly what incremental updates built.
    #[test]
    fn test_rebuild_reconstructs_heads() {
        let (_temp, _store, job_log) = setup();

        let spec1 = spec("rebuild-a", "hash");
        let spec2 = spec("rebuild-b", "concat");
        job_log.create_job(spec1.clone()).unwrap();
        job_log.create_job(spec2.clone()).unwrap();

        // Trigger job-a twice so trigger_count differs between jobs.
        job_log.trigger_job(&spec1.job_id, "t1").unwrap();
        job_log.trigger_job(&spec1.job_id, "t2").unwrap();

        let before_a = job_log.get_job(&spec1.job_id).unwrap().unwrap();
        let before_b = job_log.get_job(&spec2.job_id).unwrap().unwrap();
        assert_eq!(before_a.trigger_count, 2);
        assert_eq!(before_b.trigger_count, 0);

        let report = job_log.rebuild().unwrap();
        assert_eq!(report.jobs_processed, 2);
        assert_eq!(report.heads_rebuilt, 2);
        assert_eq!(report.validation_errors, 0);

        let after_a = job_log.get_job(&spec1.job_id).unwrap().unwrap();
        let after_b = job_log.get_job(&spec2.job_id).unwrap().unwrap();
        assert_eq!(after_a.spec.code_ref, "hash");
        assert_eq!(after_b.spec.code_ref, "concat");
        assert_eq!(
            after_a.trigger_count, 2,
            "trigger_count must be recovered from the runs table"
        );
        assert_eq!(after_b.trigger_count, 0);
        assert_eq!(after_a.created_at, before_a.created_at);
    }

    /// A `Created` event as it was encoded before `prev` existed.
    fn legacy_shaped_created() -> JobEvent {
        JobEvent::Created {
            spec: spec("golden", "hash"),
            ts: 1_700_000_000,
            prev: None,
        }
    }

    /// Adding `prev` must not rename a single already-stored job event.
    ///
    /// Job event CIDs are what `job_events` files, what
    /// [`crate::Control::collect`] protects, and what recovery reads. A field
    /// that changed the encoding of an existing event would orphan every one
    /// of them — a `dag gc run` would then collect the specs. `prev: None` is
    /// skipped on the wire and these bytes are frozen. Captured from the
    /// encoder before the field was added.
    #[test]
    fn adding_prev_does_not_change_an_existing_events_cid() {
        const GOLDEN_PAYLOAD: &str = "a16743726561746564a26473706563a7666a6f625f696466676f6c64656e69706c6163656d656e74656e6f6465316669\
6e70757473a26d7374617469635f696e70757473806e706f696e7465725f696e70757473806b64657465726d696e6973\
6d6d44657465726d696e6973746963706465636c617265645f6f7574707574738068636f64655f726566646861736866\
706f6c696379a26d63616368655f6f757470757473644e6f6e656774726967676572664d616e75616c6274731a6553f1\
00";
        const GOLDEN_CID: &str = "fca9df4d93d09bdad3d441da4c994a477c53512f45bfef5a6ae02d9149c059fb";

        let mut payload = Vec::new();
        ciborium::ser::into_writer(&legacy_shaped_created(), &mut payload).unwrap();
        assert_eq!(
            hex::encode(&payload),
            GOLDEN_PAYLOAD.replace(['\n', ' '], ""),
            "a `prev: None` job event no longer encodes to its historical bytes"
        );

        let entry = Entry::with_payload(payload);
        let cid = Cid::compute(&entry.to_bytes_cbor().unwrap());
        assert_eq!(
            cid.to_hex(),
            GOLDEN_CID,
            "an existing job event was renamed"
        );
    }

    /// The other half: bytes written before the field existed still decode.
    #[test]
    fn a_job_event_encoded_without_prev_decodes_with_prev_none() {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&legacy_shaped_created(), &mut payload).unwrap();

        let round_tripped: JobEvent = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(round_tripped.prev(), None);
        assert!(matches!(round_tripped, JobEvent::Created { .. }));
    }

    #[test]
    fn legacy_prev_exception_is_narrow_and_cannot_authorise_a_future_forgery() {
        let created = JobEvent::Created {
            spec: spec("legacy-chain", "hash"),
            ts: 1,
            prev: None,
        };
        // Encode through the genuine schema-1 type shape, which had no `prev`
        // field at all, rather than asking today's serializer to omit None.
        #[derive(serde::Serialize)]
        enum SchemaOneJobEvent<'a> {
            Updated { spec: &'a JobSpec, ts: i64 },
        }
        let legacy_spec = spec("legacy-chain", "concat");
        let mut old_shape = Vec::new();
        ciborium::ser::into_writer(
            &SchemaOneJobEvent::Updated {
                spec: &legacy_spec,
                ts: 2,
            },
            &mut old_shape,
        )
        .unwrap();
        let updated: JobEvent = ciborium::de::from_reader(old_shape.as_slice()).unwrap();
        assert_eq!(updated.prev(), None);
        let events = vec![
            (1, Cid::compute(b"created"), created),
            (2, Cid::compute(b"legacy-update"), updated.clone()),
        ];
        assert!(validate_filed_chain("legacy-chain", &events, Some(2)).is_ok());
        assert!(validate_filed_chain("legacy-chain", &events, None).is_err());

        let mut forged = events;
        forged.push((3, Cid::compute(b"future-forgery"), updated));
        assert!(validate_filed_chain("legacy-chain", &forged, Some(2)).is_err());
    }

    /// Build a `(ts, cid, event)` triple the way a store scan would.
    fn recovered(event: JobEvent) -> (i64, Cid, JobEvent) {
        let payload = cbor_encode(&event).unwrap();
        let entry = Entry::with_payload(payload);
        let cid = Cid::compute(&entry.to_bytes_cbor().unwrap());
        (event.ts(), cid, event)
    }

    fn created(id: &str, code_ref: &str, ts: i64) -> (i64, Cid, JobEvent) {
        recovered(JobEvent::Created {
            spec: spec(id, code_ref),
            ts,
            prev: None,
        })
    }

    fn updated(id: &str, code_ref: &str, ts: i64, prev: Option<Cid>) -> (i64, Cid, JobEvent) {
        recovered(JobEvent::Updated {
            spec: spec(id, code_ref),
            ts,
            prev,
        })
    }

    #[test]
    fn order_chain_follows_prev_not_timestamps() {
        let root = created("j", "hash", 1_000);
        // Deliberately backdated: a chained event still comes second.
        let next = updated("j", "concat", 1, Some(root.1.clone()));

        let ordered = order_chain("j", vec![next.clone(), root.clone()]).unwrap();
        assert_eq!(ordered[0].1, root.1);
        assert_eq!(ordered[1].1, next.1);
    }

    /// The finding: a planted `Updated` with a far-future timestamp used to
    /// sort last and become the recovered spec.
    #[test]
    fn order_chain_refuses_an_unchained_event() {
        let root = created("j", "hash", 1_000);
        let forged = updated("j", "exec", i64::MAX, None);

        let err = order_chain("j", vec![root, forged]).unwrap_err();
        assert!(
            err.contains("claim to start the chain"),
            "unexpected reason: {err}"
        );
    }

    #[test]
    fn order_chain_refuses_a_fork() {
        let root = created("j", "hash", 1_000);
        let honest = updated("j", "concat", 2_000, Some(root.1.clone()));
        let forged = updated("j", "exec", 3_000, Some(root.1.clone()));

        let err = order_chain("j", vec![root, honest, forged]).unwrap_err();
        assert!(err.contains("forks"), "unexpected reason: {err}");
    }

    /// An event chained to something that is not in the recovered set is not
    /// a shorter chain, it is an event of unknown provenance.
    #[test]
    fn order_chain_refuses_a_stray() {
        let root = created("j", "hash", 1_000);
        let orphan = updated("j", "exec", 2_000, Some(Cid::compute(b"not in this set")));

        let err = order_chain("j", vec![root, orphan]).unwrap_err();
        assert!(
            err.contains("do not chain to the Created event"),
            "unexpected reason: {err}"
        );
    }

    /// The same entry offered twice is one event; enumeration is allowed to
    /// repeat itself without that reading as divergent history.
    #[test]
    fn order_chain_tolerates_a_duplicate_offer() {
        let root = created("j", "hash", 1_000);
        let ordered = order_chain("j", vec![root.clone(), root.clone()]).unwrap();
        assert_eq!(ordered.len(), 1);
    }

    #[test]
    fn update_job_appends_a_chained_event() {
        let (_temp, _store, job_log) = setup();
        let id = JobId::from("evolving");
        job_log.create_job(spec("evolving", "hash")).unwrap();
        job_log.update_job(spec("evolving", "concat")).unwrap();

        let head = job_log.get_job(&id).unwrap().unwrap();
        assert_eq!(head.spec.code_ref, "concat");
        assert_eq!(head.seq, 2);

        // The rebuild path validates the chain, so a clean rebuild is the
        // assertion that `update_job` wrote a well-formed one.
        let report = job_log.rebuild().unwrap();
        assert_eq!(report.validation_errors, 0);
        assert_eq!(
            job_log.get_job(&id).unwrap().unwrap().spec.code_ref,
            "concat"
        );
    }

    #[test]
    fn update_job_refuses_an_unknown_job() {
        let (_temp, _store, job_log) = setup();
        assert!(job_log.update_job(spec("never-created", "hash")).is_err());
    }

    #[test]
    fn invalid_specs_are_rejected_by_writers_and_store_recovery() {
        let (_temp, store, job_log) = setup();
        let mut invalid = spec("oversized", "hash");
        invalid.code_ref = "x".repeat(dag_core::MAX_JOB_CODE_REF_BYTES + 1);

        assert!(job_log.create_job(invalid.clone()).is_err());
        assert!(
            job_log.get_job(&invalid.job_id).unwrap().is_none(),
            "an invalid create must publish no head"
        );

        // Recovery scans attacker-writable immutable chunks. A decodable
        // JobEvent is not enough: it must pass the same complete spec bounds
        // as a normal create before it can become executable state.
        let event = JobEvent::Created {
            spec: invalid.clone(),
            ts: 1,
            prev: None,
        };
        let cid = store
            .put_entry(&Entry::with_payload(cbor_encode(&event).unwrap()))
            .unwrap();
        let report = job_log.rebuild_from_store(&[cid]).unwrap();
        assert_eq!(report.events_skipped, 1);
        assert_eq!(report.events_added, 0);
        assert_eq!(report.heads_rebuilt, 0);
        assert!(report.skipped[0].contains("cannot accept"));
        assert!(job_log.get_job(&invalid.job_id).unwrap().is_none());
    }

    #[test]
    fn job_head_reads_validate_existing_specs_and_embedded_ids() {
        let (_temp, _store, job_log) = setup();
        let job = spec("head-integrity", "hash");
        job_log.create_job(job.clone()).unwrap();
        let mut head = job_log.get_job(&job.job_id).unwrap().unwrap();
        head.job_id = JobId::from("different-embedded-id");
        let txn = job_log.db.begin_write().unwrap();
        txn.open_table(JOB_HEADS)
            .unwrap()
            .insert(
                job.job_id.as_ref().as_bytes(),
                cbor_encode(&head).unwrap().as_slice(),
            )
            .unwrap();
        txn.commit().unwrap();

        assert!(job_log.get_job(&job.job_id).is_err());
        assert!(job_log.list_jobs().is_err());
        let mut replacement = job;
        replacement.code_ref = "concat".to_string();
        assert!(
            job_log.update_job(replacement).is_err(),
            "an update must validate the old cached head before appending a new event"
        );
    }

    #[test]
    fn effect_claim_rebuild_deterministically_bounds_a_per_key_row() {
        let claims = (0..=MAX_EFFECT_CLAIMS_PER_KEY)
            .map(|index| Cid::compute(index.to_string().as_bytes()))
            .collect();
        let by_key = std::collections::HashMap::from([(b"effect-key".to_vec(), claims)]);
        let plan = JobLog::prepare_claim_rebuild(by_key).unwrap();
        assert_eq!(plan.count(), MAX_EFFECT_CLAIMS_PER_KEY as u32);
    }
}
