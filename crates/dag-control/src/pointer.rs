//! # Pointer Management
//!
//! This module implements mutable named pointers with append-only history, satisfying
//! Acceptance Criterion C from the DAG system design. Pointers provide mutable references
//! to immutable content in the DAG system.
//!
//! ## Core Concepts
//!
//! - **Pointer**: A named reference that resolves to a CID, can be updated over time
//! - **PointerEvent**: An immutable event recording a pointer state change
//! - **PointerLog**: The append-only log managing all pointer operations
//! - **PointerHead**: Current state cache for fast resolution
//!
//! ## Key Invariants
//!
//! The pointer system maintains several critical invariants:
//!
//! ### I1: Sequence Monotonicity
//! For any pointer P, sequence numbers are strictly increasing: seq(n) = seq(n-1) + 1
//! This ensures total ordering of events within each pointer's history.
//!
//! ### I2: Event Chain Integrity
//! For any pointer P with events E\[1\]..E\[n\]:
//! - E\[1\].prev = None (create event)
//! - E\[i\].prev = E\[i-1\].new for i > 1 (update events)
//!
//! This maintains a verifiable chain of custody for pointer updates.
//!
//! ### I3: Head Consistency
//! The cached head always matches the latest event:
//! head.seq = max(seq) AND head.current_cid = E\[max(seq)\].new
//!
//! ### I4: Event Immutability
//! Once written to the content store, PointerEvents are immutable and tamper-evident
//! through CID-based addressing.
//!
//! ### I5: Append-Only History
//! The event log only grows; historical events are never modified or deleted.
//! Recovery operations rebuild heads from the authoritative event log.
//!
//! ## Storage Architecture
//!
//! ```text
//! PointerLog
//! ├── ContentStore (via Arc<S>)          # PointerEvents as CBOR-encoded Entries
//! └── redb Database (shared)
//!     ├── "pointer_heads" table          # pointer_id -> PointerHead (fast resolution)
//!     └── "pointer_events" table         # binary_key([len][pid][seq]) -> event_cid
//! ```
//!
//! Event keys use binary encoding to avoid delimiter issues:
//!
//! ```text
//! [u32:pid_len_be] [pid_bytes] [u64:seq_be]
//! ```
//!
//! Length-prefixed rather than delimited: no delimiter collisions, efficient
//! range scans, and a pointer ID may contain any characters at all (P5).
//!
//! ## Concurrency
//!
//! redb admits one writer at a time, so a write is never racing another write
//! *inside* a transaction. What still needs serialising is the read-modify-write
//! *between* transactions: an update reads the head, stores its event in the
//! content store, and only then opens the write transaction. A per-log mutex
//! covers that window. This replaces the optimistic-retry loops the sled
//! implementation needed — writers queue briefly instead of colliding and
//! retrying, and readers are never blocked (MVCC).
//!
//! ## Usage Examples
//!
//! ```rust,no_run
//! use dag_control::PointerLog;
//! use dag_core::ContentStore;
//! use dag_storage::FsStore;
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize with content store and a shared database
//! let store = Arc::new(FsStore::new("./data")?);
//! let db = Arc::new(redb::Database::create("./control.redb")?);
//! let pointer_log = PointerLog::new(store.clone(), db)?;
//!
//! // Create a new pointer
//! let initial_cid = store.put_chunk(b"initial content", None)?;
//! pointer_log.create("my-pointer", initial_cid)?;
//!
//! // Update the pointer
//! let new_cid = store.put_chunk(b"updated content", None)?;
//! let (seq, old_cid) = pointer_log.update("my-pointer", new_cid)?;
//!
//! // Resolve current value
//! let current = pointer_log.resolve("my-pointer")?;
//!
//! // Get history in sequence range
//! let history = pointer_log.history("my-pointer", 1..10)?;
//! # Ok(())
//! # }
//! ```

use crate::error::Result;
use dag_core::{Cid, ContentStore, CoreError, Entry, PointerEvent};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tracing::{debug, info};

#[cfg(any(test, feature = "test-utils"))]
static EVENT_PAGE_ROWS_VISITED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

mod keys;
use keys::{decode_event_key, encode_event_key};

pub(crate) const POINTER_HEADS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("pointer_heads");
const POINTER_EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pointer_events");

/// Maximum encoded [`PointerEvent`] payload accepted from storage or a peer.
///
/// A valid event contains one bounded identifier, two fixed-size CIDs and
/// scalar metadata, so 4 KiB is deliberately generous. Checking before CBOR
/// decoding prevents a schema-shaped content chunk from turning a bounded
/// recovery inventory into an unbounded allocation.
pub(crate) const MAX_POINTER_EVENT_PAYLOAD_BYTES: usize = 4 * 1024;

/// Maximum number of pointer positions one incremental publication may plan.
///
/// Transport sessions already page control events, but the storage boundary
/// enforces its own ceiling so an in-process caller cannot accidentally turn
/// an exact-key operation into unbounded CPU, I/O or plan memory.
pub(crate) const MAX_INCREMENTAL_POINTER_EVENTS: usize = 65_536;

/// Aggregate event bytes read while checking one incremental pointer offer.
///
/// Pointer events are individually capped at 4 KiB. This separate aggregate
/// limit also covers the current head and its predecessor for each affected
/// pointer, keeping adversarial batches deterministic even when every event
/// is at the individual maximum.
const MAX_INCREMENTAL_POINTER_EVENT_BYTES: usize = crate::sync::MAX_SYNC_POINTER_EVENT_READ_BYTES;

/// A pointer head contains one sequence and one fixed-size CID. A generous
/// pre-decode bound prevents a corrupt derived row from allocating freely.
const MAX_POINTER_HEAD_BYTES: usize = 1_024;

/// Validate a pointer ID for safety and consistency.
///
/// Current validation rules:
/// - Maximum length of 256 bytes (reasonable limit)
/// - No null bytes (for safety)
///
/// Note: With binary key encoding, most special characters are now safe,
/// including empty strings and colons.
pub fn validate_pointer_id(id: &str) -> Result<(), PointerError> {
    if id.len() > 256 {
        return Err(PointerError::Serialization(
            "Pointer ID too long (max 256 bytes)".to_string(),
        ));
    }
    if id.bytes().any(|b| b == 0) {
        return Err(PointerError::Serialization(
            "Pointer ID cannot contain null bytes".to_string(),
        ));
    }
    if let Err(reason) = dag_core::validate_identifier_text(id) {
        return Err(PointerError::Serialization(reason.into()));
    }
    Ok(())
}

/// Decode an event using the same bounds and identifier rules on every path.
pub(crate) fn decode_pointer_event(bytes: &[u8]) -> Result<PointerEvent, PointerError> {
    if bytes.len() > MAX_POINTER_EVENT_PAYLOAD_BYTES {
        return Err(PointerError::Serialization(format!(
            "pointer event payload is {} bytes, above the {}-byte limit",
            bytes.len(),
            MAX_POINTER_EVENT_PAYLOAD_BYTES
        )));
    }
    let event: PointerEvent = dag_core::decode_cbor_exact(bytes).map_err(|error| {
        PointerError::Serialization(format!("Failed to deserialize event: {error}"))
    })?;
    validate_pointer_id(&event.pointer_id)?;
    if event.seq == 0 {
        return Err(PointerError::Serialization(
            "pointer event sequence must be at least 1".into(),
        ));
    }
    Ok(event)
}

/// Decode one derived pointer-head row without copying or allocating from an
/// attacker-sized corrupt value first.
pub(crate) fn decode_pointer_head(bytes: &[u8]) -> Result<PointerHead, PointerError> {
    if bytes.len() > MAX_POINTER_HEAD_BYTES {
        return Err(PointerError::Serialization(format!(
            "pointer head exceeds the {MAX_POINTER_HEAD_BYTES}-byte limit"
        )));
    }
    dag_core::decode_cbor_exact(bytes).map_err(|error| {
        PointerError::Serialization(format!("Failed to deserialize head: {error}"))
    })
}

/// Errors that can occur during pointer operations.
///
/// These errors maintain the system's integrity by failing fast on invalid operations
/// rather than allowing inconsistent state.
#[derive(thiserror::Error, Debug)]
pub enum PointerError {
    #[error("Pointer {0} not found")]
    NotFound(String),
    #[error("Pointer {0} already exists")]
    AlreadyExists(String),
    #[error("Storage error: {0}")]
    Storage(#[from] CoreError),
    #[error("Database error: {0}")]
    Database(String),
    /// A bounded scheduler resource could not admit the pointer update.
    ///
    /// Pointer-trigger intents are committed in the same transaction as the
    /// pointer head. Keeping capacity distinct from a database fault lets
    /// callers retry after the queue is drained, and confirms that no head
    /// was published when admission failed.
    #[error("Capacity limit reached: {0}")]
    Capacity(String),
    /// The pointer mutation would enqueue locally configured work, but its
    /// caller did not carry authority to cross that separate boundary.
    ///
    /// This is checked from the same redb write transaction that would publish
    /// the event mapping, head, generation and trigger intents. A refusal
    /// therefore leaves all of those rows unchanged.
    #[error("pointer {pointer_id} has active update-triggered jobs; trigger scope is required")]
    TriggerPermissionRequired { pointer_id: String },
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid sequence range: {start}..{end}")]
    InvalidRange { start: u64, end: u64 },
    /// A compare-and-set update whose expectation was stale (ADR-005).
    ///
    /// Names the actual head so the caller can re-read and retry without
    /// another round trip. Not an error in the system — it is the mechanism
    /// working: one of two concurrent writers is being told it lost.
    #[error(
        "pointer {pointer_id} is at seq {actual} (cid {actual_cid}), \
         not {expected}; re-read and retry"
    )]
    CasConflict {
        pointer_id: String,
        expected: u64,
        actual: u64,
        actual_cid: String,
    },
}

fn db_err(e: impl std::fmt::Display) -> PointerError {
    PointerError::Database(e.to_string())
}

fn trigger_enqueue_err(e: crate::ControlError) -> PointerError {
    match e {
        crate::ControlError::Capacity(detail) => PointerError::Capacity(detail),
        crate::ControlError::Pointer(error) => error,
        other => PointerError::Database(other.to_string()),
    }
}

/// Authority to enqueue jobs as a consequence of a pointer mutation.
///
/// Local operator paths use [`Self::Granted`]. Network paths must derive this
/// value from authenticated request scopes and pass it explicitly; possessing
/// pointer CAS authority alone is not job-trigger authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerTriggerAuthority {
    Granted,
    Withheld,
}

impl PointerTriggerAuthority {
    pub(crate) const fn permits_triggers(self) -> bool {
        matches!(self, Self::Granted)
    }
}

fn pointer_offer_err(e: dag_core::OfferError) -> PointerError {
    match e {
        dag_core::OfferError::ZeroSeq => PointerError::InvalidRange { start: 0, end: 1 },
        dag_core::OfferError::Divergent {
            id,
            seq,
            existing,
            offered,
        } => PointerError::AlreadyExists(format!(
            "{id} seq {seq} already names {existing}, refusing to replace it with {offered}"
        )),
        other => PointerError::Serialization(other.to_string()),
    }
}

/// One pointer's recovered events, as `(seq, event entry CID, event)`.
type PointerChain = Vec<(u64, Cid, PointerEvent)>;

/// Report from a rebuild driven by a content-store scan.
///
/// The counts exist because the scan *identifies* events by decoding them,
/// which is a guess however strict: anything it declines has to be visible,
/// or a recovery that quietly restored half a deployment would look identical
/// to one that restored all of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PointerStoreRebuildReport {
    /// Chunks examined in the content store.
    pub chunks_scanned: usize,
    /// Chunks whose payload decoded as a [`PointerEvent`].
    pub events_found: usize,
    /// Events belonging to a chain that failed validation and was not filed.
    pub events_skipped: usize,
    /// Events the store held that the events table did *not* already have, and
    /// which this scan filed. When a reconcile runs after a table rebuild, a
    /// non-zero count is the signal that the table was behind the store — the
    /// truncated-table case (seam 1) the plain rebuild reported success over.
    pub events_added: usize,
    /// Why each rejected chain was rejected, one line per pointer.
    pub skipped: Vec<String>,
    /// Pointer heads written.
    pub heads_rebuilt: u32,
}

/// A table rebuild reconciled against the content store.
///
/// The plain [`PointerLog::rebuild_from_events`] trusts the events table. When
/// that table has been *truncated* — `control.redb` restored from an older
/// backup over a newer `data/` — it recovers a head that is behind the store
/// and reports success, stranding every later event in `data/`. Reconciling
/// runs the table rebuild and then merges anything the store holds beyond it
/// (`rebuild_from_store`, add-only and advance-only), so a stranded event is
/// adopted rather than lost. `store.events_added` is the count that was
/// missing before; `store.skipped` names any chain the two disagreed on, which
/// is refused rather than merged.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PointerReconcileReport {
    /// Pointer heads the events-table rebuild produced.
    pub from_table: u32,
    /// The store scan that reconciled anything the table lacked.
    pub store: PointerStoreRebuildReport,
}

/// Cached metadata about a pointer's current state for fast resolution.
///
/// This is derived data that can be rebuilt from the authoritative event log.
/// Maintains invariant I3 (Head Consistency).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PointerHead {
    /// Current sequence number (highest in the event log)
    pub seq: u64,
    /// CID that this pointer currently resolves to
    pub current_cid: Cid,
}

/// Append-only log managing mutable pointers with complete history.
///
/// Provides the core pointer abstraction for the DAG system, maintaining all
/// critical invariants through careful event sourcing and caching.
pub struct PointerLog<S: ContentStore> {
    /// Content store for immutable PointerEvent storage
    store: Arc<S>,
    /// Shared control-plane database
    db: Arc<Database>,
    /// Serialises the read-modify-write window between transactions; see the
    /// module docs on concurrency.
    write_lock: Mutex<()>,
    /// Cross-log recovery barrier. See [`crate::MutationGate`].
    mutation_gate: crate::MutationGate,
    /// Hard ceiling for validating the complete closure of a new head.
    max_reference_expansion: AtomicUsize,
    /// One-shot deterministic pause after closure validation. Test-only.
    #[cfg(test)]
    publication_test_pause:
        parking_lot::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    /// Optional event bus for observability
    event_bus: Option<crate::events::EventBus>,
}

/// Fully validated replacement for the derived pointer-head table.
///
/// The plan contains encoded database rows plus the immutable CIDs those rows
/// would publish as roots. Applying it cannot touch the content store; callers
/// validate `roots` under the mutation gate before committing the rows.
pub(crate) struct PointerRebuildPlan {
    heads: Vec<(Vec<u8>, Vec<u8>)>,
    roots: Vec<Cid>,
}

/// One exact-key row replacement guarded by the bytes observed during plan
/// preparation. The caller holds the pointer writer lock across preparation
/// and apply; retaining the expectation also fails closed if another log
/// instance was constructed over the same database with a different lock.
#[derive(Debug)]
struct PointerRowUpdate {
    key: Vec<u8>,
    expected: Option<Vec<u8>>,
    value: Vec<u8>,
}

/// Bounded, read-only plan for publishing an incremental pointer-event batch.
///
/// Unlike [`PointerRebuildPlan`], this plan never inventories history and
/// never clears the head table. It contains only new event mappings and heads
/// that advance because of those mappings. `new_roots` are exactly the roots
/// that become visible when the affected heads advance.
#[derive(Debug)]
pub(crate) struct PointerIncrementalSyncPlan {
    event_inserts: Vec<(Vec<u8>, Vec<u8>)>,
    head_updates: Vec<PointerRowUpdate>,
    new_roots: Vec<Cid>,
}

impl PointerIncrementalSyncPlan {
    /// New append-only event mappings in this plan. Idempotent offered rows
    /// already on file are excluded.
    pub(crate) fn events_inserted(&self) -> usize {
        self.event_inserts.len()
    }

    /// Pointer heads that advance in this plan.
    pub(crate) fn heads_updated(&self) -> u32 {
        self.head_updates.len() as u32
    }

    /// Roots newly exposed by the advancing heads.
    pub(crate) fn roots(&self) -> &[Cid] {
        &self.new_roots
    }
}

/// A rejected incremental pointer offer with the exact offered position being
/// validated when the failure occurred. Corrupt current-head state is
/// attributed to the first offered position for that affected pointer.
#[derive(Debug, thiserror::Error)]
#[error("pointer {id} seq {seq} ({cid}): {source}")]
pub(crate) struct PointerIncrementalSyncError {
    id: String,
    seq: u64,
    cid: Cid,
    #[source]
    source: PointerError,
}

impl PointerIncrementalSyncError {
    fn new(id: String, seq: u64, cid: Cid, source: PointerError) -> Self {
        Self {
            id,
            seq,
            cid,
            source,
        }
    }

    pub(crate) fn into_parts(self) -> (String, u64, Cid, PointerError) {
        (self.id, self.seq, self.cid, self.source)
    }
}

impl PointerRebuildPlan {
    pub(crate) fn count(&self) -> u32 {
        self.heads.len() as u32
    }

    pub(crate) fn roots(&self) -> &[Cid] {
        &self.roots
    }
}

impl<S: ContentStore + 'static> PointerLog<S> {
    /// Hold the pointer-log read/validate/write window while replication
    /// validates a complete cross-log event offer.
    pub(crate) fn import_batch_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Shared control database used by the atomic replication coordinator.
    pub(crate) fn import_database(&self) -> Arc<Database> {
        Arc::clone(&self.db)
    }

    /// Rows a full recovery scans or replaces in the pointer subsystem.
    pub(crate) fn recovery_row_count(&self) -> Result<u64, PointerError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let events = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
        let heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
        events
            .len()
            .map_err(db_err)?
            .checked_add(heads.len().map_err(db_err)?)
            .ok_or_else(|| {
                PointerError::Serialization("pointer recovery row count overflow".into())
            })
    }

    fn load_incremental_event(
        &self,
        cid: &Cid,
        bytes_read: &mut usize,
    ) -> Result<PointerEvent, PointerError> {
        // Charge the complete stored Entry before decoding it. Charging only
        // its small PointerEvent payload would let a peer hide megabytes of
        // links/meta in every entry and bypass the aggregate budget.
        let raw = self.store.get_chunk(cid)?;
        *bytes_read = bytes_read.checked_add(raw.len()).ok_or_else(|| {
            PointerError::Capacity("incremental pointer event-byte accounting overflow".into())
        })?;
        if *bytes_read > MAX_INCREMENTAL_POINTER_EVENT_BYTES {
            return Err(PointerError::Capacity(format!(
                "incremental pointer validation exceeds the {MAX_INCREMENTAL_POINTER_EVENT_BYTES}-byte event-read budget"
            )));
        }
        let entry = Entry::from_bytes_cbor(&raw)?;
        if !entry.links.is_empty() || entry.meta.is_some() {
            return Err(PointerError::Serialization(format!(
                "pointer event entry {cid} is non-canonical: links and metadata are not permitted"
            )));
        }
        self.deserialize_event(&entry.payload)
    }

    /// Recover direct content targets named by a bounded page of pointer
    /// event refs for sync offer/classification.
    ///
    /// These are advisory, wanted-only hints: current-head closure remains
    /// the authority for publication. An unreadable, absent, malformed, or
    /// mismatched event is omitted here and is still transferred (or reported
    /// as a required event failure) through its authoritative mapping CID.
    /// Raw stored Entry bytes are charged before decoding through the same
    /// aggregate budget used by incremental publication.
    #[doc(hidden)]
    pub fn sync_target_hints(
        &self,
        events: &[(String, u64, Cid)],
        bytes_read: &mut usize,
    ) -> Result<Vec<Cid>, PointerError> {
        let mut targets = Vec::with_capacity(events.len());
        for (id, seq, event_cid) in events {
            let event = match self.load_incremental_event(event_cid, bytes_read) {
                Ok(event) => event,
                Err(PointerError::Capacity(error)) => {
                    return Err(PointerError::Capacity(error));
                }
                Err(_) => continue,
            };
            let valid_shape = if *seq == 1 {
                event.prev.is_none()
            } else {
                event.prev.is_some()
            };
            if event.pointer_id == *id && event.seq == *seq && valid_shape {
                targets.push(event.new);
            }
        }
        Ok(targets)
    }

    /// Prepare an incremental pointer publication using exact-key lookups.
    ///
    /// The caller must hold the shared mutation/durability barriers and
    /// [`Self::import_batch_lock`] until the returned plan is either applied
    /// or discarded. Those locks make the read snapshot stable; byte
    /// expectations retained in the plan add a final stale-plan check inside
    /// the caller-owned write transaction.
    ///
    /// Existing history is trusted only through a locally consistent cached
    /// head: its filed event and immediate predecessor are checked, and a
    /// filed successor is refused as evidence that the cache is stale. New
    /// positions must then form one contiguous suffix. No table or per-ID
    /// history range is scanned.
    pub(crate) fn prepare_incremental_sync_plan(
        &self,
        offered: &[(String, u64, Cid)],
    ) -> Result<PointerIncrementalSyncPlan, PointerIncrementalSyncError> {
        if offered.is_empty() {
            return Ok(PointerIncrementalSyncPlan {
                event_inserts: Vec::new(),
                head_updates: Vec::new(),
                new_roots: Vec::new(),
            });
        }
        let (id, seq, cid) = &offered[0];
        let mut failure_context = Some((id.clone(), *seq, cid.clone()));
        self.prepare_incremental_sync_plan_inner(offered, &mut failure_context)
            .map_err(|source| {
                let (id, seq, cid) =
                    failure_context.expect("a non-empty offer always has rejection context");
                PointerIncrementalSyncError::new(id, seq, cid, source)
            })
    }

    fn prepare_incremental_sync_plan_inner(
        &self,
        offered: &[(String, u64, Cid)],
        failure_context: &mut Option<(String, u64, Cid)>,
    ) -> Result<PointerIncrementalSyncPlan, PointerError> {
        use std::collections::BTreeMap;

        if offered.len() > MAX_INCREMENTAL_POINTER_EVENTS {
            return Err(PointerError::Capacity(format!(
                "incremental pointer offer contains {} events; limit is {MAX_INCREMENTAL_POINTER_EVENTS}",
                offered.len()
            )));
        }

        // Canonical grouping makes validation and the encoded plan independent
        // of peer ordering. A repeated identical position is idempotent; two
        // CIDs for one position are a divergent offer before any database I/O.
        let mut by_id: BTreeMap<String, BTreeMap<u64, Cid>> = BTreeMap::new();
        for (pointer_id, seq, cid) in offered {
            *failure_context = Some((pointer_id.clone(), *seq, cid.clone()));
            validate_pointer_id(pointer_id)?;
            if *seq == 0 {
                return Err(pointer_offer_err(dag_core::OfferError::ZeroSeq));
            }
            match by_id.entry(pointer_id.clone()).or_default().entry(*seq) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(cid.clone());
                }
                std::collections::btree_map::Entry::Occupied(slot) if slot.get() == cid => {}
                std::collections::btree_map::Entry::Occupied(slot) => {
                    return Err(pointer_offer_err(dag_core::OfferError::Divergent {
                        id: pointer_id.clone(),
                        seq: *seq,
                        existing: slot.get().clone(),
                        offered: cid.clone(),
                    }));
                }
            }
        }

        let (first_id, first_seq, first_cid) = &offered[0];
        *failure_context = Some((first_id.clone(), *first_seq, first_cid.clone()));
        let read = self.db.begin_read().map_err(db_err)?;
        let event_table = read.open_table(POINTER_EVENTS).map_err(db_err)?;
        let head_table = read.open_table(POINTER_HEADS).map_err(db_err)?;
        let mut bytes_read = 0usize;
        let mut event_inserts = Vec::with_capacity(offered.len());
        let mut head_updates = Vec::with_capacity(by_id.len());
        let mut new_roots = Vec::with_capacity(by_id.len());

        for (pointer_id, positions) in by_id {
            let (first_seq, first_cid) = positions
                .first_key_value()
                .expect("a grouped pointer offer is non-empty");
            *failure_context = Some((pointer_id.clone(), *first_seq, first_cid.clone()));
            let current_head_bytes = match head_table.get(pointer_id.as_bytes()).map_err(db_err)? {
                None => None,
                Some(value) => {
                    let bytes = value.value();
                    if bytes.len() > MAX_POINTER_HEAD_BYTES {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id} head exceeds the {MAX_POINTER_HEAD_BYTES}-byte limit"
                        )));
                    }
                    Some(bytes.to_vec())
                }
            };

            let mut tail: Option<(u64, PointerEvent)> = match current_head_bytes.as_ref() {
                None => None,
                Some(bytes) => {
                    let head = self.deserialize_head(bytes)?;
                    if head.seq == 0 {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id} has an invalid seq-0 head"
                        )));
                    }
                    let head_key = encode_event_key(&pointer_id, head.seq);
                    let head_event_cid = event_table
                        .get(head_key.as_slice())
                        .map_err(db_err)?
                        .map(|value| Cid::from_bytes(value.value()))
                        .transpose()
                        .map_err(|error| PointerError::Serialization(error.to_string()))?
                        .ok_or_else(|| {
                            PointerError::Serialization(format!(
                                "pointer {pointer_id} head seq {} has no filed event",
                                head.seq
                            ))
                        })?;
                    let head_event =
                        self.load_incremental_event(&head_event_cid, &mut bytes_read)?;

                    let predecessor = if head.seq > 1 {
                        let predecessor_key = encode_event_key(&pointer_id, head.seq - 1);
                        let predecessor_cid = event_table
                            .get(predecessor_key.as_slice())
                            .map_err(db_err)?
                            .map(|value| Cid::from_bytes(value.value()))
                            .transpose()
                            .map_err(|error| PointerError::Serialization(error.to_string()))?
                            .ok_or_else(|| {
                                PointerError::Serialization(format!(
                                    "pointer {pointer_id} head seq {} has no filed predecessor",
                                    head.seq
                                ))
                            })?;
                        let event =
                            self.load_incremental_event(&predecessor_cid, &mut bytes_read)?;
                        if event.pointer_id != pointer_id || event.seq != head.seq - 1 {
                            return Err(PointerError::Serialization(format!(
                                "pointer {pointer_id} predecessor at seq {} describes ({}, seq {})",
                                head.seq - 1,
                                event.pointer_id,
                                event.seq
                            )));
                        }
                        Some(event)
                    } else {
                        None
                    };

                    dag_core::offer_pointer_event(
                        &pointer_id,
                        head.seq,
                        &head_event_cid,
                        &head_event,
                        None,
                        predecessor.as_ref(),
                    )
                    .map_err(pointer_offer_err)?;
                    if head.current_cid != head_event.new {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id} head seq {} resolves to {}, but its filed event resolves to {}",
                            head.seq, head.current_cid, head_event.new
                        )));
                    }
                    if let Some(successor_seq) = head.seq.checked_add(1) {
                        let successor_key = encode_event_key(&pointer_id, successor_seq);
                        if event_table
                            .get(successor_key.as_slice())
                            .map_err(db_err)?
                            .is_some()
                        {
                            return Err(PointerError::Serialization(format!(
                                "pointer {pointer_id} head is stale: seq {successor_seq} is already filed"
                            )));
                        }
                    }
                    Some((head.seq, head_event))
                }
            };

            let mut advanced = false;
            for (seq, event_cid) in positions {
                *failure_context = Some((pointer_id.clone(), seq, event_cid.clone()));
                let event = self.load_incremental_event(&event_cid, &mut bytes_read)?;
                let key = encode_event_key(&pointer_id, seq);
                let existing = event_table
                    .get(key.as_slice())
                    .map_err(db_err)?
                    .map(|value| Cid::from_bytes(value.value()))
                    .transpose()
                    .map_err(|error| PointerError::Serialization(error.to_string()))?;

                if existing.is_some() {
                    dag_core::offer_pointer_event(
                        &pointer_id,
                        seq,
                        &event_cid,
                        &event,
                        existing.as_ref(),
                        None,
                    )
                    .map_err(pointer_offer_err)?;
                    let tail_seq = tail.as_ref().map(|(tail_seq, _)| *tail_seq).unwrap_or(0);
                    if seq > tail_seq {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id} has filed seq {seq} beyond cached head {tail_seq}; run recovery before incremental sync"
                        )));
                    }
                    continue;
                }

                let expected_seq = match tail.as_ref() {
                    Some((tail_seq, _)) => tail_seq.checked_add(1).ok_or_else(|| {
                        PointerError::Serialization(format!(
                            "pointer {pointer_id} sequence is exhausted"
                        ))
                    })?,
                    None => 1,
                };
                if seq != expected_seq {
                    return Err(PointerError::Serialization(format!(
                        "pointer {pointer_id}: incremental suffix expected seq {expected_seq}, found {seq}"
                    )));
                }
                dag_core::offer_pointer_event(
                    &pointer_id,
                    seq,
                    &event_cid,
                    &event,
                    None,
                    tail.as_ref().map(|(_, event)| event),
                )
                .map_err(pointer_offer_err)?;
                event_inserts.push((key, event_cid.as_bytes().to_vec()));
                tail = Some((seq, event));
                advanced = true;
            }

            if advanced {
                let (seq, event) = tail.expect("an advanced chain has a tail");
                if let Some(successor_seq) = seq.checked_add(1) {
                    let successor_key = encode_event_key(&pointer_id, successor_seq);
                    if event_table
                        .get(successor_key.as_slice())
                        .map_err(db_err)?
                        .is_some()
                    {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id} would leave already-filed seq {successor_seq} beyond its new head"
                        )));
                    }
                }
                let head = PointerHead {
                    seq,
                    current_cid: event.new.clone(),
                };
                head_updates.push(PointerRowUpdate {
                    key: pointer_id.as_bytes().to_vec(),
                    expected: current_head_bytes,
                    value: self.serialize_head(&head)?,
                });
                new_roots.push(event.new);
            }
        }

        Ok(PointerIncrementalSyncPlan {
            event_inserts,
            head_updates,
            new_roots,
        })
    }

    /// Validate exactly the roots newly published by an incremental plan.
    /// The caller must retain the mutation and durability barriers through
    /// [`Self::apply_incremental_sync_plan`] and transaction commit.
    #[cfg(test)]
    fn validate_incremental_sync_plan(
        &self,
        plan: &PointerIncrementalSyncPlan,
    ) -> Result<(), PointerError> {
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            plan.roots()
                .iter()
                .cloned()
                .map(|cid| (cid, crate::reference::ReferenceDepth::Unlimited)),
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map(|_| ())
        .map_err(|error| {
            PointerError::Storage(CoreError::PreconditionFailed(format!(
                "refusing to publish incremental pointer heads: {error}"
            )))
        })
    }

    /// Apply a validated incremental plan inside a caller-owned transaction.
    ///
    /// No table is scanned or cleared. Every planned replacement first checks
    /// the exact bytes observed during preparation. On error the caller must
    /// abort the transaction (the atomic Control path does so with `?`). The
    /// cross-log coordinator is responsible for bumping sync generation once
    /// when either pointer or pin inserts are non-empty.
    pub(crate) fn apply_incremental_sync_plan(
        &self,
        txn: &WriteTransaction,
        plan: &PointerIncrementalSyncPlan,
    ) -> Result<(), PointerError> {
        {
            let events = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
            for (key, _) in &plan.event_inserts {
                if events.get(key.as_slice()).map_err(db_err)?.is_some() {
                    return Err(PointerError::Database(
                        "pointer incremental plan became stale before event publication".into(),
                    ));
                }
            }
        }
        {
            let heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
            for update in &plan.head_updates {
                let current = heads.get(update.key.as_slice()).map_err(db_err)?;
                if current.as_ref().map(|value| value.value()) != update.expected.as_deref() {
                    return Err(PointerError::Database(
                        "pointer incremental plan became stale before head publication".into(),
                    ));
                }
            }
        }
        {
            let mut events = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
            for (key, cid) in &plan.event_inserts {
                events
                    .insert(key.as_slice(), cid.as_slice())
                    .map_err(db_err)?;
            }
        }
        {
            let mut heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
            for update in &plan.head_updates {
                heads
                    .insert(update.key.as_slice(), update.value.as_slice())
                    .map_err(db_err)?;
            }
        }
        Ok(())
    }

    /// Authorize a native-sync plan that advances subscribed pointer heads.
    ///
    /// Replication does not itself enqueue destination jobs. It nevertheless
    /// crosses the trigger authority boundary when it advances a pointer with
    /// an active `OnPointerUpdate` subscription, so the decision is made in
    /// the exact write transaction that will replace those heads. Existing
    /// queued intents carry immutable revision/input snapshots and therefore
    /// cannot be steered by unrelated pointer or job changes after enqueue.
    pub(crate) fn authorize_incremental_sync_triggers(
        &self,
        txn: &WriteTransaction,
        plan: &PointerIncrementalSyncPlan,
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<(), PointerError> {
        if trigger_authority.permits_triggers() {
            return Ok(());
        }
        for update in &plan.head_updates {
            let pointer_id = std::str::from_utf8(&update.key).map_err(|_| {
                PointerError::Serialization(
                    "incremental pointer plan contains a non-UTF-8 head key".into(),
                )
            })?;
            if crate::job::has_active_pointer_triggers_in_transaction(txn, pointer_id)
                .map_err(trigger_enqueue_err)?
            {
                return Err(PointerError::TriggerPermissionRequired {
                    pointer_id: pointer_id.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Create a new PointerLog over the shared control-plane database.
    ///
    /// The log's tables are created if they don't exist.
    pub fn new(store: Arc<S>, db: Arc<Database>) -> Result<Self, PointerError> {
        // Create tables up front so read paths never see a missing table.
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(POINTER_HEADS).map_err(db_err)?;
        txn.open_table(POINTER_EVENTS).map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        crate::sync_generation::initialize(&db).map_err(db_err)?;

        Ok(Self {
            store,
            db,
            write_lock: Mutex::new(()),
            mutation_gate: Arc::new(RwLock::new(())),
            max_reference_expansion: AtomicUsize::new(crate::DEFAULT_MAX_SUBTREE_EXPANSION),
            #[cfg(test)]
            publication_test_pause: parking_lot::Mutex::new(None),
            event_bus: None,
        })
    }

    /// Use the control plane's cross-log recovery barrier.
    pub(crate) fn with_mutation_gate(mut self, gate: crate::MutationGate) -> Self {
        self.mutation_gate = gate;
        self
    }

    /// Change the ceiling used to validate a new pointer head's full DAG.
    pub(crate) fn set_max_reference_expansion(&self, max_expansion: usize) {
        self.max_reference_expansion
            .store(max_expansion, Ordering::Relaxed);
    }

    /// Prove that a proposed pointer head is a complete, readable DAG before
    /// the append-only event makes it visible. The caller owns the shared
    /// mutation gate, so GC cannot delete between this walk and the commit.
    fn validate_new_head(&self, cid: &Cid) -> Result<(), PointerError> {
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            [(cid.clone(), crate::reference::ReferenceDepth::Unlimited)],
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map(|_| ())
        .map_err(|error| {
            PointerError::Storage(CoreError::PreconditionFailed(format!(
                "refusing to publish pointer head {cid}: {error}"
            )))
        })?;

        #[cfg(test)]
        let pause = { self.publication_test_pause.lock().take() };
        #[cfg(test)]
        if let Some((validated, resume)) = pause {
            validated.wait();
            resume.wait();
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pause_next_publication_for_test(
        &self,
        validated: Arc<std::sync::Barrier>,
        resume: Arc<std::sync::Barrier>,
    ) {
        *self.publication_test_pause.lock() = Some((validated, resume));
    }

    /// Set the event bus for this log (for observability)
    pub fn with_event_bus(mut self, bus: crate::events::EventBus) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Read a pointer's head bytes, if it exists.
    fn head_bytes(&self, pointer_id: &str) -> Result<Option<Vec<u8>>, PointerError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_HEADS).map_err(db_err)?;
        let Some(value) = table.get(pointer_id.as_bytes()).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > MAX_POINTER_HEAD_BYTES {
            return Err(PointerError::Serialization(format!(
                "pointer {pointer_id} head exceeds the {MAX_POINTER_HEAD_BYTES}-byte limit"
            )));
        }
        Ok(Some(value.value().to_vec()))
    }

    /// Refuse a steady-state unauthorized trigger before constructing and
    /// storing an immutable pointer-event object.
    ///
    /// This is advisory only. The trigger lookup is repeated in the eventual
    /// redb write transaction, which is the authorization decision. If a
    /// subscription commits in the narrow window after this read, that
    /// transaction refuses every mutable row but the already durable event
    /// object remains as one unfiled, GC-eligible chunk. Avoiding even that
    /// bounded race would require holding a database writer across content I/O
    /// and violate the global durability/lock order.
    fn preflight_trigger_authority(
        &self,
        pointer_id: &str,
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<(), PointerError> {
        if !trigger_authority.permits_triggers()
            && crate::job::has_active_pointer_triggers(&self.db, pointer_id)
                .map_err(trigger_enqueue_err)?
        {
            return Err(PointerError::TriggerPermissionRequired {
                pointer_id: pointer_id.to_string(),
            });
        }
        Ok(())
    }

    /// Create a new pointer with an initial CID.
    ///
    /// This creates the first event in the pointer's history (seq=1) and initializes
    /// the cached head. The operation is atomic - either the entire pointer is created
    /// or the operation fails.
    ///
    /// # Invariants Maintained
    /// - I1: Creates seq=1 (sequence monotonicity starts)
    /// - I2: First event has prev=None (chain integrity starts)
    /// - I3: Head matches the created event
    /// - I4: Event stored immutably in content store
    ///
    /// # Errors
    /// Returns `PointerError::AlreadyExists` if the pointer ID is already in use.
    pub fn create(&self, pointer_id: &str, initial_cid: Cid) -> Result<(), PointerError> {
        self.create_inner(pointer_id, initial_cid, PointerTriggerAuthority::Granted)
    }

    /// Create a pointer while explicitly carrying authority for any subscribed
    /// jobs the transaction would enqueue.
    fn create_inner(
        &self,
        pointer_id: &str,
        initial_cid: Cid,
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<(), PointerError> {
        validate_pointer_id(pointer_id)?;

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());

        // Fast-path the established API error before an expensive DAG walk.
        // The writer-locked check below remains definitive against races.
        if self.head_bytes(pointer_id)?.is_some() {
            return Err(PointerError::AlreadyExists(pointer_id.to_string()));
        }
        self.preflight_trigger_authority(pointer_id, trigger_authority)?;

        // Validate and register the *whole* reachable closure, not just the
        // root. If GC won the exclusive gate first, any descendant it removed
        // makes this fail closed. If this shared guard won first, GC's later
        // root snapshot observes the committed pointer.
        self.validate_new_head(&initial_cid)?;

        let timestamp = chrono::Utc::now().timestamp();
        let event = PointerEvent::create_event(pointer_id, initial_cid.clone(), timestamp);

        // Store the event before taking the log mutex. This preserves the
        // global order mutation -> FsStore durability -> log mutex -> redb.
        let entry = Entry::with_payload(self.serialize_event(&event)?);
        let event_cid = self.store.put_entry(&entry)?;

        // Acquire the log mutex only after content I/O, preserving the global
        // mutation -> durability -> log -> redb order.
        let guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        if self.head_bytes(pointer_id)?.is_some() {
            return Err(PointerError::AlreadyExists(pointer_id.to_string()));
        }

        let head = PointerHead {
            seq: 1,
            current_cid: initial_cid.clone(),
        };
        let head_bytes = self.serialize_head(&head)?;
        let event_key = encode_event_key(pointer_id, event.seq);

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut events = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
            let existing = events
                .get(event_key.as_slice())
                .map_err(db_err)?
                .map(|value| value.value().to_vec());
            if existing
                .as_deref()
                .is_some_and(|cid| cid != event_cid.as_bytes())
            {
                return Err(PointerError::AlreadyExists(format!(
                    "{pointer_id} seq {} was filed concurrently with a different event",
                    event.seq
                )));
            }
            events
                .insert(event_key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;
            let mut heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
            heads
                .insert(pointer_id.as_bytes(), head_bytes.as_slice())
                .map_err(db_err)?;
            drop(heads);
            crate::job::enqueue_pointer_triggers(
                &txn,
                pointer_id,
                event.seq,
                timestamp,
                trigger_authority,
            )
            .map_err(trigger_enqueue_err)?;
            crate::sync_generation::bump(&txn).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        info!(
            "Created pointer '{}' at seq {} pointing to {}",
            pointer_id, event.seq, initial_cid
        );

        if let Some(ref bus) = self.event_bus {
            bus.emit(crate::events::Event::PointerUpdate {
                id: pointer_id.to_string(),
                new: initial_cid,
                ts: timestamp,
            });
        }

        Ok(())
    }

    /// Update a pointer to point to a new CID.
    ///
    /// Creates a new event with seq=current_seq+1 and prev=current_cid, maintaining
    /// the event chain integrity. Updates the cached head atomically.
    ///
    /// # Invariants Maintained
    /// - I1: Increments sequence number monotonically
    /// - I2: Sets prev to current head's CID (chain integrity)
    /// - I3: Updates head to match new event
    /// - I4: New event stored immutably
    ///
    /// # Returns
    /// Returns `(new_sequence_number, previous_cid)` on success.
    ///
    /// # Errors
    /// Returns `PointerError::NotFound` if the pointer doesn't exist.
    pub fn update(&self, pointer_id: &str, new_cid: Cid) -> Result<(u64, Cid), PointerError> {
        self.update_inner(pointer_id, new_cid, None, PointerTriggerAuthority::Granted)
    }

    /// Compare-and-set update: apply only if the head is exactly `expect_seq`.
    ///
    /// `expect_seq == 0` means create — the pointer must not exist yet. A
    /// stale expectation is refused with [`PointerError::CasConflict`] naming
    /// the actual head, so the caller re-reads and retries; two concurrent
    /// writers cannot lose an update silently (ADR-005 decision 3). This is
    /// the primitive behind the remote `Pointers.Update` RPC; local
    /// [`Self::update`] keeps its unconditional append semantics.
    ///
    /// Returns the new head sequence.
    pub fn update_cas(
        &self,
        pointer_id: &str,
        new_cid: Cid,
        expect_seq: u64,
    ) -> Result<u64, PointerError> {
        self.update_cas_with_trigger_authority(
            pointer_id,
            new_cid,
            expect_seq,
            PointerTriggerAuthority::Granted,
        )
    }

    /// Compare-and-set update with an explicit pointer-trigger authority.
    ///
    /// A caller with [`PointerTriggerAuthority::Withheld`] may still create or
    /// update a pointer when no active `OnPointerUpdate` subscription would be
    /// enqueued. The definitive subscription check and any enqueue happen in
    /// the pointer publication transaction, so a concurrent subscription
    /// cannot race past this decision.
    pub fn update_cas_with_trigger_authority(
        &self,
        pointer_id: &str,
        new_cid: Cid,
        expect_seq: u64,
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<u64, PointerError> {
        if expect_seq == 0 {
            return match self.create_inner(pointer_id, new_cid, trigger_authority) {
                Ok(()) => Ok(1),
                // Someone created it concurrently (or it already existed):
                // that is a conflict with the caller's "does not exist yet"
                // expectation, reported with the head they did not know about.
                Err(PointerError::AlreadyExists(_)) => {
                    let head = self.get_head(pointer_id)?;
                    Err(PointerError::CasConflict {
                        pointer_id: pointer_id.to_string(),
                        expected: 0,
                        actual: head.seq,
                        actual_cid: head.current_cid.to_hex(),
                    })
                }
                Err(other) => Err(other),
            };
        }
        self.update_inner(pointer_id, new_cid, Some(expect_seq), trigger_authority)
            .map(|(seq, _)| seq)
    }

    /// The shared body of [`Self::update`] and [`Self::update_cas`].
    ///
    /// An unconditional writer whose optimistic read loses a race retries
    /// from the new head. CAS writers instead report the definitive head.
    /// No log mutex is held while content I/O acquires FsStore's durability
    /// gate; the final check and redb commit are serialized by `write_lock`.
    fn update_inner(
        &self,
        pointer_id: &str,
        new_cid: Cid,
        expect_seq: Option<u64>,
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<(u64, Cid), PointerError> {
        validate_pointer_id(pointer_id)?;

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());

        // Preserve NotFound/CAS semantics without holding the log mutex across
        // content I/O. The state is checked again under that mutex below.
        let mut observed_head: PointerHead = self.deserialize_head(
            &self
                .head_bytes(pointer_id)?
                .ok_or_else(|| PointerError::NotFound(pointer_id.to_string()))?,
        )?;
        if let Some(expected) = expect_seq {
            if observed_head.seq != expected {
                return Err(PointerError::CasConflict {
                    pointer_id: pointer_id.to_string(),
                    expected,
                    actual: observed_head.seq,
                    actual_cid: observed_head.current_cid.to_hex(),
                });
            }
        }
        self.preflight_trigger_authority(pointer_id, trigger_authority)?;

        // A revert can name an old DAG whose descendants have ancient mtimes.
        // Validate/register its complete closure under the shared mutation
        // gate before committing the new root; see `create`.
        self.validate_new_head(&new_cid)?;

        loop {
            let timestamp = chrono::Utc::now().timestamp();
            let new_seq = observed_head.seq.checked_add(1).ok_or_else(|| {
                PointerError::Serialization(format!(
                    "pointer {pointer_id} sequence is already u64::MAX"
                ))
            })?;
            let event = PointerEvent::update_event(
                pointer_id,
                new_seq,
                observed_head.current_cid.clone(),
                new_cid.clone(),
                timestamp,
            );

            // Content is written before the log mutex, maintaining the global
            // mutation -> durability -> log -> database lock order.
            let entry = Entry::with_payload(self.serialize_event(&event)?);
            let event_cid = self.store.put_entry(&entry)?;

            // Exclude imported mappings for the final validation and commit.
            let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
            let current_head: PointerHead = self.deserialize_head(
                &self
                    .head_bytes(pointer_id)?
                    .ok_or_else(|| PointerError::NotFound(pointer_id.to_string()))?,
            )?;

            if current_head != observed_head {
                if let Some(expected) = expect_seq {
                    return Err(PointerError::CasConflict {
                        pointer_id: pointer_id.to_string(),
                        expected,
                        actual: current_head.seq,
                        actual_cid: current_head.current_cid.to_hex(),
                    });
                }
                drop(guard);
                observed_head = current_head;
                continue;
            }

            let new_head = PointerHead {
                seq: new_seq,
                current_cid: new_cid.clone(),
            };
            let new_head_bytes = self.serialize_head(&new_head)?;
            let event_key = encode_event_key(pointer_id, event.seq);

            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut events = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
                let existing = events
                    .get(event_key.as_slice())
                    .map_err(db_err)?
                    .map(|value| value.value().to_vec());
                if existing
                    .as_deref()
                    .is_some_and(|cid| cid != event_cid.as_bytes())
                {
                    return Err(PointerError::AlreadyExists(format!(
                        "{pointer_id} seq {} was filed concurrently with a different event",
                        event.seq
                    )));
                }
                events
                    .insert(event_key.as_slice(), event_cid.as_bytes())
                    .map_err(db_err)?;
                let mut heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
                heads
                    .insert(pointer_id.as_bytes(), new_head_bytes.as_slice())
                    .map_err(db_err)?;
                drop(heads);
                crate::job::enqueue_pointer_triggers(
                    &txn,
                    pointer_id,
                    event.seq,
                    timestamp,
                    trigger_authority,
                )
                .map_err(trigger_enqueue_err)?;
                crate::sync_generation::bump(&txn).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
            drop(guard);

            info!(
                "Updated pointer '{}' from {} to {} at seq {}",
                pointer_id, current_head.current_cid, new_cid, new_seq
            );

            if let Some(ref bus) = self.event_bus {
                bus.emit(crate::events::Event::PointerUpdate {
                    id: pointer_id.to_string(),
                    new: new_cid,
                    ts: timestamp,
                });
            }

            return Ok((new_seq, current_head.current_cid));
        }
    }

    /// Resolve a pointer to its current CID.
    ///
    /// This is a fast O(1) operation that reads from the cached head rather than
    /// scanning the event log.
    ///
    /// # Errors
    /// Returns `PointerError::NotFound` if the pointer doesn't exist.
    pub fn resolve(&self, pointer_id: &str) -> Result<Cid, PointerError> {
        let head = self.get_head(pointer_id)?;

        debug!(
            "Resolved pointer '{}' to {} at seq {}",
            pointer_id, head.current_cid, head.seq
        );

        Ok(head.current_cid)
    }

    /// Get the history of a pointer within a sequence range.
    ///
    /// Returns events in chronological order (ascending sequence numbers).
    /// The range is half-open: [start, end). Events are retrieved from the
    /// content store and deserialized.
    ///
    /// # Errors
    /// Returns `PointerError::InvalidRange` if start >= end.
    pub fn history(
        &self,
        pointer_id: &str,
        range: Range<u64>,
    ) -> Result<Vec<PointerEvent>, PointerError> {
        if range.start >= range.end {
            return Err(PointerError::InvalidRange {
                start: range.start,
                end: range.end,
            });
        }

        let start_key = encode_event_key(pointer_id, range.start);
        let end_key = encode_event_key(pointer_id, range.end);

        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;

        let mut events = Vec::new();
        for item in table
            .range(start_key.as_slice()..end_key.as_slice())
            .map_err(db_err)?
        {
            let (key_guard, cid_guard) = item.map_err(db_err)?;

            // Decode the key to verify it's for our pointer
            if let Some((decoded_id, _seq)) = decode_event_key(key_guard.value()) {
                if decoded_id != pointer_id {
                    break; // We've moved past this pointer's events
                }

                let event_cid = Cid::from_bytes(cid_guard.value())
                    .map_err(|e| PointerError::Serialization(e.to_string()))?;

                // Retrieve and decode the event from the content store
                let entry = self.store.get_entry(&event_cid)?;
                let event: PointerEvent = self.deserialize_event(&entry.payload)?;

                events.push(event);
            }
        }

        debug!(
            "Retrieved {} history events for pointer '{}' in range {}..{}",
            events.len(),
            pointer_id,
            range.start,
            range.end
        );

        Ok(events)
    }

    /// Get the current head information for a pointer
    pub fn get_head(&self, pointer_id: &str) -> Result<PointerHead, PointerError> {
        let head_bytes = self
            .head_bytes(pointer_id)?
            .ok_or_else(|| PointerError::NotFound(pointer_id.to_string()))?;
        self.deserialize_head(&head_bytes)
    }

    /// List all pointer IDs currently in the system
    pub fn list_pointers(&self) -> Result<Vec<String>, PointerError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_HEADS).map_err(db_err)?;

        let mut pointers = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key, _) = item.map_err(db_err)?;
            let pointer_id = std::str::from_utf8(key.value()).map_err(|error| {
                PointerError::Serialization(format!("pointer-head key is not valid UTF-8: {error}"))
            })?;
            pointers.push(pointer_id.to_string());
        }

        pointers.sort();
        Ok(pointers)
    }

    /// Count pointer heads without allocating one string per namespace row.
    pub fn head_count(&self) -> Result<usize, PointerError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_HEADS).map_err(db_err)?;
        usize::try_from(table.len().map_err(db_err)?)
            .map_err(|_| PointerError::Database("pointer head count does not fit usize".into()))
    }

    /// List a bounded lexicographic page of pointer IDs strictly after
    /// `after`. This is the node protocol's pagination primitive: unlike
    /// [`Self::list_pointers`], it never materializes the whole namespace.
    pub fn list_pointers_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, PointerError> {
        use std::ops::Bound::{Excluded, Unbounded};

        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_HEADS).map_err(db_err)?;
        let mut pointers = Vec::with_capacity(limit);
        let range = (
            after.map_or(Unbounded, |id| Excluded(id.as_bytes())),
            Unbounded,
        );
        for item in table.range::<&[u8]>(range).map_err(db_err)?.take(limit) {
            let (key, _) = item.map_err(db_err)?;
            let id = std::str::from_utf8(key.value()).map_err(|error| {
                PointerError::Serialization(format!("pointer-head key is not valid UTF-8: {error}"))
            })?;
            pointers.push(id.to_string());
        }
        Ok(pointers)
    }

    /// Every `(pointer_id, seq, event_cid)` in the log, ordered by key.
    ///
    /// Unlike [`Self::history`], this yields the event *addresses* rather than
    /// the decoded events, and reads nothing from the content store. It exists
    /// for replication: what a replica needs is the CIDs, because the events
    /// themselves are ordinary chunks it can copy byte-for-byte.
    pub fn event_cids(&self) -> Result<Vec<(String, u64, Cid)>, PointerError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;

        let mut out = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key_guard, cid_guard) = item.map_err(db_err)?;
            if let Some((pointer_id, seq)) = decode_event_key(key_guard.value()) {
                let cid = Cid::from_bytes(cid_guard.value())
                    .map_err(|e| PointerError::Serialization(e.to_string()))?;
                out.push((pointer_id.into_owned(), seq, cid));
            }
        }
        Ok(out)
    }

    /// Read at most `limit` event mappings after an opaque `(id, seq)` cursor.
    ///
    /// Ordering is the table's encoded-key order (ID byte length, ID bytes,
    /// then sequence), which is stable and lets replication resume without
    /// rescanning or retaining the complete history.
    pub fn event_cids_page(
        &self,
        after: Option<(&str, u64)>,
        limit: usize,
    ) -> Result<Vec<(String, u64, Cid)>, PointerError> {
        use std::ops::Bound::{Excluded, Unbounded};

        let after_key = after.map(|(id, seq)| encode_event_key(id, seq));
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
        let range = match after_key.as_deref() {
            Some(key) => table.range::<&[u8]>((Excluded(key), Unbounded)),
            None => table.range::<&[u8]>(..),
        }
        .map_err(db_err)?;
        let mut out = Vec::with_capacity(limit.min(4096));
        for item in range.take(limit) {
            #[cfg(any(test, feature = "test-utils"))]
            EVENT_PAGE_ROWS_VISITED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (key, value) = item.map_err(db_err)?;
            let (id, seq) = decode_event_key(key.value()).ok_or_else(|| {
                PointerError::Serialization("invalid pointer event key".to_string())
            })?;
            let cid = Cid::from_bytes(value.value())
                .map_err(|error| PointerError::Serialization(error.to_string()))?;
            out.push((id.into_owned(), seq, cid));
        }
        Ok(out)
    }

    /// Test instrumentation for proving cursor pages do not rescan prefixes.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn reset_event_page_rows_visited() {
        EVENT_PAGE_ROWS_VISITED.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Rows visited by [`Self::event_cids_page`] since the last reset.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn event_page_rows_visited() -> usize {
        EVENT_PAGE_ROWS_VISITED.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Return the event CID currently filed at `(pointer_id, seq)`.
    ///
    /// This is the read-only half of replication's offer protocol. A dry run
    /// uses it to report divergent history without calling [`Self::import_event`]
    /// and therefore without mutating the destination.
    pub fn event_cid(&self, pointer_id: &str, seq: u64) -> Result<Option<Cid>, PointerError> {
        validate_pointer_id(pointer_id)?;
        let key = encode_event_key(pointer_id, seq);
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
        table
            .get(key.as_slice())
            .map_err(db_err)?
            .map(|guard| {
                Cid::from_bytes(guard.value())
                    .map_err(|e| PointerError::Serialization(e.to_string()))
            })
            .transpose()
    }

    /// File an event that already exists in the content store under
    /// `(pointer_id, seq)`.
    ///
    /// This is how replication moves history without rewriting it.
    /// [`Self::create`] and [`Self::update`] mint a *new* event, stamping the
    /// local clock into it, so replaying a remote log through them would give
    /// every event a different CID — and a provenance log whose entries are
    /// not the ones that were signed is not the same log. See ADR-002.
    ///
    /// Everything is checked before anything is written:
    ///
    /// - the entry must already be in the local store and decode as a
    ///   [`PointerEvent`];
    /// - the event's own `pointer_id` and `seq` must match the key it is being
    ///   filed under, so a caller cannot graft one pointer's event onto
    ///   another;
    /// - `seq == 1` must be a create with no `prev`, and any later event's
    ///   `prev` must match the `new` of `seq - 1` (P1, P2);
    /// - if a mapping already exists at this position it must name the same
    ///   CID. Divergent history is refused, never overwritten.
    ///
    /// Returns `true` if a new mapping was written, `false` if this exact
    /// event was already filed — so a repeated sync is a no-op rather than an
    /// error.
    ///
    /// Heads are not updated; run [`Self::rebuild_from_events`] afterwards,
    /// which derives them from whatever actually arrived.
    pub fn import_event(
        &self,
        pointer_id: &str,
        seq: u64,
        event_cid: &Cid,
    ) -> Result<bool, PointerError> {
        validate_pointer_id(pointer_id)?;

        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        // The event has to be readable here before it can be filed. This is
        // what stops a failed chunk transfer from producing a log entry that
        // points at nothing.
        let entry = self.store.get_entry(event_cid)?;
        let event: PointerEvent = self.deserialize_event(&entry.payload)?;

        let key = encode_event_key(pointer_id, seq);

        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Chain validation reads the neighbouring positions first, outside the
        // write transaction. The judgement itself is `offer_pointer_event` —
        // the same function the Edge replica uses (ADR-007).
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;

            let existing = table
                .get(key.as_slice())
                .map_err(db_err)?
                .map(|g| Cid::from_bytes(g.value()))
                .transpose()
                .map_err(|e| PointerError::Serialization(e.to_string()))?;

            let predecessor = if seq > 1 && existing.is_none() {
                let prev_key = encode_event_key(pointer_id, seq - 1);
                match table
                    .get(prev_key.as_slice())
                    .map_err(db_err)?
                    .map(|g| Cid::from_bytes(g.value()))
                    .transpose()
                    .map_err(|e| PointerError::Serialization(e.to_string()))?
                {
                    Some(prev_cid) => {
                        let prev_entry = self.store.get_entry(&prev_cid)?;
                        Some(self.deserialize_event(&prev_entry.payload)?)
                    }
                    None => None,
                }
            } else {
                None
            };

            match dag_core::offer_pointer_event(
                pointer_id,
                seq,
                event_cid,
                &event,
                existing.as_ref(),
                predecessor.as_ref(),
            ) {
                Ok(dag_core::OfferOutcome::AlreadyFiled) => return Ok(false),
                Ok(dag_core::OfferOutcome::Accept) => {}
                Err(e) => return Err(pointer_offer_err(e)),
            }
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
            table
                .insert(key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;
            crate::sync_generation::bump(&txn).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;

        debug!("imported pointer event {} seq {}", pointer_id, seq);
        Ok(true)
    }

    /// Rebuild heads from the authoritative event log with full validation.
    ///
    /// This is a recovery operation that reconstructs the cached heads by scanning
    /// all events in the system. Validates chain integrity and sequence contiguity.
    ///
    /// # Returns
    /// Number of pointer heads that were rebuilt.
    pub fn rebuild_from_events(&self) -> Result<u32, PointerError> {
        info!("Starting pointer index rebuild from events...");

        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let plan = self.prepare_rebuild_plan()?;
        self.validate_rebuild_plan(&plan)?;
        let rebuilt_count = plan.count();

        let txn = self.db.begin_write().map_err(db_err)?;
        self.apply_rebuild_plan(&txn, &plan)?;
        txn.commit().map_err(db_err)?;

        info!("Rebuilt {} pointer heads from events", rebuilt_count);
        Ok(rebuilt_count)
    }

    /// Validate the complete filed history and prepare an all-or-nothing head
    /// replacement. The caller owns both the cross-log mutation barrier and
    /// this log's writer lock.
    pub(crate) fn prepare_rebuild_plan(&self) -> Result<PointerRebuildPlan, PointerError> {
        let mut positions = Vec::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
            for item in table.range::<&[u8]>(..).map_err(db_err)? {
                let (key_guard, cid_guard) = item.map_err(db_err)?;
                let (pointer_id, seq) = decode_event_key(key_guard.value()).ok_or_else(|| {
                    PointerError::Serialization("malformed key in pointer_events".into())
                })?;
                validate_pointer_id(pointer_id.as_ref())?;
                let event_cid = Cid::from_bytes(cid_guard.value())
                    .map_err(|e| PointerError::Serialization(e.to_string()))?;
                positions.push((pointer_id.into_owned(), seq, event_cid));
            }
        }
        self.prepare_rebuild_plan_from_positions(&positions)
    }

    /// Prepare heads from the complete prospective event mapping. Atomic sync
    /// publication uses this before any offered mapping is visible.
    pub(crate) fn prepare_rebuild_plan_from_positions(
        &self,
        positions: &[(String, u64, Cid)],
    ) -> Result<PointerRebuildPlan, PointerError> {
        use std::collections::HashMap;

        let mut pointer_events: HashMap<String, PointerChain> = HashMap::new();
        for (pointer_id, seq, event_cid) in positions {
            validate_pointer_id(pointer_id)?;
            let entry = self.store.get_entry(event_cid)?;
            let event: PointerEvent = self.deserialize_event(&entry.payload)?;
            if event.pointer_id != *pointer_id || event.seq != *seq {
                return Err(PointerError::Serialization(format!(
                    "pointer event {event_cid} is filed as ({pointer_id}, seq {seq}) but describes ({}, seq {})",
                    event.pointer_id, event.seq
                )));
            }
            pointer_events.entry(pointer_id.clone()).or_default().push((
                *seq,
                event_cid.clone(),
                event,
            ));
        }

        let mut rebuilt: Vec<(String, Vec<u8>, Cid)> = Vec::new();
        for (pointer_id, mut events) in pointer_events {
            events.sort_by_key(|(seq, _, _)| *seq);
            let mut previous_target: Option<&Cid> = None;
            for (expected_seq, (seq, _event_cid, event)) in (1u64..).zip(events.iter()) {
                if *seq != expected_seq {
                    return Err(PointerError::Serialization(format!(
                        "pointer {pointer_id}: expected seq {expected_seq}, found {seq}"
                    )));
                }
                if expected_seq == 1 {
                    if !event.is_create() || event.prev.is_some() {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id}: seq 1 is not a create without prev"
                        )));
                    }
                } else {
                    if !event.is_update() {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id}: seq {seq} is not an update"
                        )));
                    }
                    if event.prev.as_ref() != previous_target {
                        return Err(PointerError::Serialization(format!(
                            "pointer {pointer_id}: seq {seq} does not name the prior target"
                        )));
                    }
                }
                previous_target = Some(&event.new);
            }

            let (last_seq, _, last_event) = events.last().expect("grouped chain is non-empty");
            let head = PointerHead {
                seq: *last_seq,
                current_cid: last_event.new.clone(),
            };
            rebuilt.push((pointer_id, self.serialize_head(&head)?, head.current_cid));
        }
        rebuilt.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(PointerRebuildPlan {
            heads: rebuilt
                .iter()
                .map(|(id, head, _)| (id.as_bytes().to_vec(), head.clone()))
                .collect(),
            roots: rebuilt.into_iter().map(|(_, _, root)| root).collect(),
        })
    }

    /// Validate every root this plan would make visible. The caller holds the
    /// mutation gate exclusively from plan preparation through commit.
    pub(crate) fn validate_rebuild_plan(
        &self,
        plan: &PointerRebuildPlan,
    ) -> Result<(), PointerError> {
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            plan.roots()
                .iter()
                .cloned()
                .map(|cid| (cid, crate::reference::ReferenceDepth::Unlimited)),
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map(|_| ())
        .map_err(|error| {
            PointerError::Storage(CoreError::PreconditionFailed(format!(
                "refusing to rebuild pointer heads: {error}"
            )))
        })
    }

    /// Replace pointer heads inside a caller-owned cross-table transaction.
    pub(crate) fn apply_rebuild_plan(
        &self,
        txn: &WriteTransaction,
        plan: &PointerRebuildPlan,
    ) -> Result<(), PointerError> {
        let mut heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
        heads.retain(|_, _| false).map_err(db_err)?;
        for (pointer_id, head_bytes) in &plan.heads {
            heads
                .insert(pointer_id.as_slice(), head_bytes.as_slice())
                .map_err(db_err)?;
        }
        Ok(())
    }

    // Helper methods for serialization
    fn serialize_event(&self, event: &PointerEvent) -> Result<Vec<u8>, PointerError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(event, &mut buf).map_err(|e| {
            PointerError::Serialization(format!("Failed to serialize event: {}", e))
        })?;
        Ok(buf)
    }

    fn deserialize_event(&self, bytes: &[u8]) -> Result<PointerEvent, PointerError> {
        decode_pointer_event(bytes)
    }

    fn serialize_head(&self, head: &PointerHead) -> Result<Vec<u8>, PointerError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(head, &mut buf)
            .map_err(|e| PointerError::Serialization(format!("Failed to serialize head: {}", e)))?;
        Ok(buf)
    }

    fn deserialize_head(&self, bytes: &[u8]) -> Result<PointerHead, PointerError> {
        decode_pointer_head(bytes)
    }

    #[cfg(test)]
    pub(crate) fn overwrite_head_for_test(
        &self,
        pointer_id: &str,
        bytes: &[u8],
    ) -> Result<(), PointerError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;
            heads.insert(pointer_id.as_bytes(), bytes).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)
    }
}

/// Recovery that does not depend on the control database existing.
///
/// [`PointerLog::rebuild_from_events`] reads the `pointer_events` table to
/// learn which CIDs the events are, so it recovers nothing from a directory
/// whose `control.redb` was lost — and reports a cheerful zero while doing it.
/// The events themselves are ordinary CBOR entries in `data/` and survive;
/// this is the path back to them. It needs store enumeration, which only
/// GC-capable stores provide, hence the separate impl block (as with
/// `SignatureLog`).
impl<S: ContentStore + dag_storage::GcCapableStore + 'static> PointerLog<S> {
    /// Rebuild the event mappings and heads by scanning the content store for
    /// pointer events.
    ///
    /// Events are identified by a strict CBOR decode into [`PointerEvent`],
    /// which is far stronger than the field-name sniffing the collector uses
    /// but is still a guess — so nothing is trusted on the strength of the
    /// decode alone. Each candidate chain must then pass the same validation
    /// [`Self::rebuild_from_events`] applies: contiguous from seq 1, a create
    /// with no `prev`, and every later event's `prev` naming the previous
    /// event's `new` (P1, P2).
    ///
    /// Merges rather than replaces: an event mapping that is already filed is
    /// never overwritten, and a recovered chain that disagrees with one is
    /// divergence — refused and reported, the same rule [`Self::import_event`]
    /// follows. A head is rewritten only for a pointer whose chain was
    /// recovered, so a pointer the scan found nothing for keeps whatever the
    /// table said.
    ///
    /// Note what a store scan rests on: anyone able to write into the data
    /// directory can plant an entry. Never overwriting what is already filed
    /// is what keeps that to filling gaps rather than rewriting history.
    pub fn rebuild_from_store(&self) -> Result<PointerStoreRebuildReport, PointerError> {
        let cids = self.store.list_all_cids()?;
        self.rebuild_from_cids(&cids)
    }

    /// Rebuild from a caller-owned inventory snapshot.
    ///
    /// Full recovery uses this form so its finite preflight is the only store
    /// enumeration retained in memory; explicit lower-level recovery keeps the
    /// unbounded wrapper above for operator compatibility.
    pub(crate) fn rebuild_from_cids(
        &self,
        cids: &[Cid],
    ) -> Result<PointerStoreRebuildReport, PointerError> {
        use std::collections::HashMap;

        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        let mut report = PointerStoreRebuildReport {
            chunks_scanned: cids.len(),
            ..Default::default()
        };

        let mut chains: HashMap<String, PointerChain> = HashMap::new();
        for cid in cids {
            // An unreadable object may be the only copy of a pointer event.
            // Treating it as irrelevant would let recovery close the GC gate
            // over an incomplete retention view.
            let bytes = self.store.get_chunk(cid)?;
            let Ok(entry) = Entry::from_bytes_cbor(&bytes) else {
                continue;
            };
            let Ok(event) = decode_pointer_event(&entry.payload) else {
                continue;
            };
            report.events_found += 1;

            chains.entry(event.pointer_id.clone()).or_default().push((
                event.seq,
                cid.clone(),
                event,
            ));
        }

        // Positions already filed, so recovery can be merged into a partly
        // populated database without rewriting anything.
        let mut existing: HashMap<(String, u64), Cid> = HashMap::new();
        for (pointer_id, seq, cid) in self.event_cids()? {
            existing.insert((pointer_id, seq), cid);
        }

        let mut accepted: Vec<(String, PointerChain)> = Vec::new();
        for (pointer_id, mut events) in chains {
            events.sort_by_key(|(seq, _, _)| *seq);
            match validate_chain(&pointer_id, &events, &existing) {
                Ok(()) => accepted.push((pointer_id, events)),
                Err(reason) => {
                    report.events_skipped += events.len();
                    report.skipped.push(reason);
                }
            }
        }
        accepted.sort_by(|a, b| a.0.cmp(&b.0));

        // This recovery scan can advance pointer heads just like a normal
        // update. Determine exactly which accepted chains would win the
        // advance-only rule, then validate their complete closures before any
        // event mapping or head is committed. The exclusive mutation gate is
        // held across this walk and the transaction.
        let roots_to_publish = {
            let read = self.db.begin_read().map_err(db_err)?;
            let heads = read.open_table(POINTER_HEADS).map_err(db_err)?;
            let mut roots = Vec::new();
            for (pointer_id, events) in &accepted {
                let (seq, _, event) = events.last().expect("chain is non-empty");
                let current_seq = match heads.get(pointer_id.as_bytes()).map_err(db_err)? {
                    Some(value) => Some(self.deserialize_head(value.value())?.seq),
                    None => None,
                };
                if current_seq.is_none_or(|current| *seq >= current) {
                    roots.push((
                        event.new.clone(),
                        crate::reference::ReferenceDepth::Unlimited,
                    ));
                }
            }
            roots
        };
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            roots_to_publish,
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map_err(|error| {
            PointerError::Storage(CoreError::PreconditionFailed(format!(
                "refusing to recover pointer heads from the store: {error}"
            )))
        })?;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut events_table = txn.open_table(POINTER_EVENTS).map_err(db_err)?;
            let mut heads = txn.open_table(POINTER_HEADS).map_err(db_err)?;

            for (pointer_id, events) in &accepted {
                for (seq, cid, _) in events {
                    let key = encode_event_key(pointer_id, *seq);
                    // Count only what the table did not already hold. That is
                    // the difference between a reconcile that merely confirmed
                    // an intact table and one that healed a truncated one.
                    if events_table.get(key.as_slice()).map_err(db_err)?.is_none() {
                        report.events_added += 1;
                    }
                    events_table
                        .insert(key.as_slice(), cid.as_bytes())
                        .map_err(db_err)?;
                }

                let (seq, _, event) = events.last().expect("chain is non-empty");

                // Advance-only. When this runs as a reconcile after a table
                // rebuild, the store chain can be *shorter* than the table's —
                // a suffix of event bytes went missing — and a shorter chain
                // that agrees on the overlap is not divergence (that is refused
                // above), it is simply less evidence. Overwriting the head with
                // it would regress a good pointer to a stale CID. So a head is
                // only ever moved forward.
                let current_seq = match heads.get(pointer_id.as_bytes()).map_err(db_err)? {
                    Some(g) => Some(self.deserialize_head(g.value())?.seq),
                    None => None,
                };
                if current_seq.is_none_or(|c| *seq >= c) {
                    let head = PointerHead {
                        seq: *seq,
                        current_cid: event.new.clone(),
                    };
                    heads
                        .insert(
                            pointer_id.as_bytes(),
                            self.serialize_head(&head)?.as_slice(),
                        )
                        .map_err(db_err)?;
                }
                report.heads_rebuilt += 1;
            }
            if report.events_added > 0 {
                crate::sync_generation::bump(&txn).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;

        info!(
            "Rebuilt {} pointer heads from {} store chunks",
            report.heads_rebuilt, report.chunks_scanned
        );
        Ok(report)
    }
}

/// Validate one recovered chain, or say why it cannot be filed.
///
/// The rules are [`PointerLog::rebuild_from_events`]'s: contiguous from 1, a
/// create at seq 1 with no `prev`, and every later event's `prev` naming its
/// predecessor's `new`. Plus one that only applies here — a chain must not
/// contradict a mapping already in the table.
fn validate_chain(
    pointer_id: &str,
    events: &[(u64, Cid, PointerEvent)],
    existing: &std::collections::HashMap<(String, u64), Cid>,
) -> Result<(), String> {
    for (i, (seq, cid, event)) in events.iter().enumerate() {
        let expected = i as u64 + 1;
        if *seq != expected {
            return Err(if i > 0 && *seq == events[i - 1].0 {
                format!("{}: two different events claim seq {}", pointer_id, seq)
            } else {
                format!(
                    "{}: sequence {} is missing (found {} at that position)",
                    pointer_id, expected, seq
                )
            });
        }
        if i == 0 {
            if !event.is_create() {
                return Err(format!(
                    "{}: seq 1 is not a create (it carries a `prev`)",
                    pointer_id
                ));
            }
        } else {
            let previous = &events[i - 1].2;
            if event.prev.as_ref() != Some(&previous.new) {
                return Err(format!(
                    "{}: seq {} breaks the chain: `prev` is {:?}, but seq {} ended at {}",
                    pointer_id,
                    seq,
                    event.prev,
                    seq - 1,
                    previous.new
                ));
            }
        }
        if let Some(filed) = existing.get(&(pointer_id.to_string(), *seq)) {
            if filed != cid {
                return Err(format!(
                    "{}: seq {} is already filed as {}, refusing to replace it with {}",
                    pointer_id, seq, filed, cid
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::{Determinism, JobId, JobInput, JobPolicy, JobSpec, TriggerPolicy};
    use dag_storage::FsStore;
    use std::sync::{mpsc, Barrier};
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_setup() -> (Arc<FsStore>, TempDir, PointerLog<FsStore>) {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("store");
        let index_path = temp_dir.path().join("index.redb");
        let db_path = temp_dir.path().join("control.redb");

        let store = Arc::new(FsStore::with_index(&store_path, &index_path).unwrap());
        let db = Arc::new(Database::create(&db_path).unwrap());
        let pointer_log = PointerLog::new(store.clone(), db).unwrap();

        (store, temp_dir, pointer_log)
    }

    fn put_event(pointer_log: &PointerLog<FsStore>, event: &PointerEvent) -> Cid {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(event, &mut payload).unwrap();
        pointer_log
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap()
    }

    fn put_target(pointer_log: &PointerLog<FsStore>, bytes: &[u8]) -> Cid {
        pointer_log.store.put_chunk(bytes, None).unwrap()
    }

    fn file_event(pointer_log: &PointerLog<FsStore>, id: &str, seq: u64, cid: &Cid) {
        let txn = pointer_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(POINTER_EVENTS).unwrap();
            let key = encode_event_key(id, seq);
            events.insert(key.as_slice(), cid.as_bytes()).unwrap();
        }
        txn.commit().unwrap();
    }

    fn apply_incremental(pointer_log: &PointerLog<FsStore>, plan: &PointerIncrementalSyncPlan) {
        let txn = pointer_log.db.begin_write().unwrap();
        pointer_log.apply_incremental_sync_plan(&txn, plan).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn immutable_pointer_event_decoder_rejects_trailing_cbor() {
        let event = PointerEvent::create_event("strict", Cid::compute(b"target"), 1);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        assert_eq!(decode_pointer_event(&payload).unwrap(), event);

        payload.push(0xf6); // a second, valid CBOR value
        assert!(matches!(
            decode_pointer_event(&payload),
            Err(PointerError::Serialization(_))
        ));
    }

    #[test]
    fn oversized_pointer_head_is_refused_before_decode() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        pointer_log
            .overwrite_head_for_test("oversized", &vec![0u8; MAX_POINTER_HEAD_BYTES + 1])
            .unwrap();
        assert!(matches!(
            pointer_log.get_head("oversized"),
            Err(PointerError::Serialization(_))
        ));
    }

    #[test]
    fn subscription_committed_during_validation_cannot_race_past_trigger_authority() {
        let directory = TempDir::new().unwrap();
        let control = Arc::new(crate::Control::open(directory.path()).unwrap());
        let initial = control.store.put_chunk(b"initial", None).unwrap();
        let updated = control.store.put_chunk(b"updated", None).unwrap();
        control
            .pointer_log
            .create("release", initial.clone())
            .unwrap();
        let job = JobSpec {
            job_id: JobId::from("release-hook"),
            placement: None,
            inputs: JobInput::new().with_pointer("release"),
            determinism: Determinism::SideEffecting,
            declared_outputs: vec!["hash".into()],
            code_ref: "hash".into(),
            policy: JobPolicy {
                trigger: TriggerPolicy::OnPointerUpdate,
                ..JobPolicy::default()
            },
            config: None,
        };
        control.create_job(job.clone()).unwrap();

        let generation_before = control.sync_event_generation().unwrap();
        let events_before = control.pointer_log.event_cids().unwrap();
        let validated = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        control
            .pointer_log
            .pause_next_publication_for_test(validated.clone(), resume.clone());

        let updating = control.clone();
        let (result_tx, result_rx) = mpsc::channel();
        let updater = std::thread::spawn(move || {
            result_tx
                .send(updating.pointer_log.update_cas_with_trigger_authority(
                    "release",
                    updated,
                    1,
                    PointerTriggerAuthority::Withheld,
                ))
                .unwrap();
        });
        validated.wait();

        // This subscription commits after the update's closure validation but
        // before its pointer publication transaction. The definitive in-txn
        // lookup must see it and refuse the whole publication.
        control
            .subscribe_pointer("release", job.job_id.clone())
            .unwrap();
        resume.wait();

        let error = result_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        updater.join().unwrap();
        assert!(matches!(
            error,
            PointerError::TriggerPermissionRequired { ref pointer_id }
                if pointer_id == "release"
        ));
        assert_eq!(control.pointer_log.resolve("release").unwrap(), initial);
        assert_eq!(control.pointer_log.get_head("release").unwrap().seq, 1);
        assert_eq!(control.pointer_log.event_cids().unwrap(), events_before);
        assert_eq!(control.sync_event_generation().unwrap(), generation_before);
        assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (0, 0));
    }

    #[test]
    fn incremental_sync_advances_only_affected_pointer_rows_and_is_idempotent() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let unrelated_target = put_target(&pointer_log, b"unrelated");
        pointer_log
            .create("unrelated", unrelated_target.clone())
            .unwrap();
        let initial = put_target(&pointer_log, b"initial");
        pointer_log.create("affected", initial.clone()).unwrap();

        let unrelated_head_before = pointer_log.head_bytes("unrelated").unwrap().unwrap();
        // A malformed, unrelated event key proves preparation is not a table
        // inventory in disguise.
        let txn = pointer_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(POINTER_EVENTS).unwrap();
            events
                .insert(
                    b"malformed-unrelated".as_slice(),
                    unrelated_target.as_bytes(),
                )
                .unwrap();
        }
        txn.commit().unwrap();

        let updated = put_target(&pointer_log, b"updated");
        let event = PointerEvent::update_event("affected", 2, initial, updated.clone(), 2);
        let event_cid = put_event(&pointer_log, &event);
        let offer = vec![("affected".to_string(), 2, event_cid.clone())];
        let plan = pointer_log.prepare_incremental_sync_plan(&offer).unwrap();
        assert_eq!(plan.events_inserted(), 1);
        assert_eq!(plan.heads_updated(), 1);
        assert_eq!(plan.roots(), std::slice::from_ref(&updated));
        pointer_log.validate_incremental_sync_plan(&plan).unwrap();
        apply_incremental(&pointer_log, &plan);

        assert_eq!(pointer_log.get_head("affected").unwrap().seq, 2);
        assert_eq!(pointer_log.resolve("affected").unwrap(), updated);
        assert_eq!(
            pointer_log.head_bytes("unrelated").unwrap().unwrap(),
            unrelated_head_before,
            "an unrelated derived row must remain byte-identical"
        );
        let read = pointer_log.db.begin_read().unwrap();
        let events = read.open_table(POINTER_EVENTS).unwrap();
        assert_eq!(
            events
                .get(b"malformed-unrelated".as_slice())
                .unwrap()
                .unwrap()
                .value(),
            unrelated_target.as_bytes()
        );
        drop(events);
        drop(read);

        let repeated = pointer_log.prepare_incremental_sync_plan(&offer).unwrap();
        assert_eq!(repeated.events_inserted(), 0);
        assert_eq!(repeated.heads_updated(), 0);
        assert!(repeated.roots().is_empty());
        apply_incremental(&pointer_log, &repeated);
        assert_eq!(
            pointer_log.head_bytes("unrelated").unwrap().unwrap(),
            unrelated_head_before
        );
    }

    #[test]
    fn incremental_pointer_refusals_leave_history_and_head_unchanged() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let initial = put_target(&pointer_log, b"initial");
        pointer_log.create("guarded", initial.clone()).unwrap();
        let head_before = pointer_log.get_head("guarded").unwrap();

        let next = put_target(&pointer_log, b"next");
        let broken = PointerEvent::update_event(
            "guarded",
            2,
            Cid::compute(b"wrong predecessor"),
            next.clone(),
            2,
        );
        let broken_cid = put_event(&pointer_log, &broken);
        let create_cid = pointer_log.event_cid("guarded", 1).unwrap().unwrap();
        let error = pointer_log
            .prepare_incremental_sync_plan(&[
                ("guarded".into(), 1, create_cid),
                ("guarded".into(), 2, broken_cid.clone()),
            ])
            .unwrap_err();
        let (id, seq, cid, _) = error.into_parts();
        assert_eq!((id.as_str(), seq, cid), ("guarded", 2, broken_cid));

        let gap = PointerEvent::update_event("guarded", 3, initial, next, 3);
        let gap_cid = put_event(&pointer_log, &gap);
        assert!(pointer_log
            .prepare_incremental_sync_plan(&[("guarded".into(), 3, gap_cid)])
            .is_err());

        let divergent =
            PointerEvent::create_event("guarded", put_target(&pointer_log, b"divergent"), 1);
        let divergent_cid = put_event(&pointer_log, &divergent);
        let error = pointer_log
            .prepare_incremental_sync_plan(&[("guarded".into(), 1, divergent_cid)])
            .unwrap_err();
        let (id, seq, _, source) = error.into_parts();
        assert_eq!((id.as_str(), seq), ("guarded", 1));
        assert!(matches!(source, PointerError::AlreadyExists(_)));

        assert_eq!(pointer_log.get_head("guarded").unwrap(), head_before);
        assert!(pointer_log.event_cid("guarded", 2).unwrap().is_none());
        assert!(pointer_log.event_cid("guarded", 3).unwrap().is_none());
    }

    #[test]
    fn incremental_pointer_batch_limit_accepts_cap_and_rejects_cap_plus_one() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let target = put_target(&pointer_log, b"bounded");
        let event = PointerEvent::create_event("bounded", target, 1);
        let event_cid = put_event(&pointer_log, &event);
        let tuple = ("bounded".to_string(), 1, event_cid);
        let at_cap = vec![tuple.clone(); MAX_INCREMENTAL_POINTER_EVENTS];
        let plan = pointer_log.prepare_incremental_sync_plan(&at_cap).unwrap();
        assert_eq!(plan.events_inserted(), 1);

        let over_cap = vec![tuple; MAX_INCREMENTAL_POINTER_EVENTS + 1];
        assert!(matches!(
            pointer_log
                .prepare_incremental_sync_plan(&over_cap)
                .unwrap_err()
                .into_parts()
                .3,
            PointerError::Capacity(_)
        ));
    }

    #[test]
    fn incremental_pointer_does_not_adopt_a_stranded_event_beyond_a_gap() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let first_target = put_target(&pointer_log, b"first");
        let stranded_target = put_target(&pointer_log, b"stranded");
        let stranded = PointerEvent::update_event(
            "incomplete",
            3,
            Cid::compute(b"missing seq2 target"),
            stranded_target,
            3,
        );
        let stranded_cid = put_event(&pointer_log, &stranded);
        file_event(&pointer_log, "incomplete", 3, &stranded_cid);

        let create = PointerEvent::create_event("incomplete", first_target.clone(), 1);
        let create_cid = put_event(&pointer_log, &create);
        let plan = pointer_log
            .prepare_incremental_sync_plan(&[("incomplete".into(), 1, create_cid)])
            .unwrap();
        pointer_log.validate_incremental_sync_plan(&plan).unwrap();
        apply_incremental(&pointer_log, &plan);

        assert_eq!(pointer_log.resolve("incomplete").unwrap(), first_target);
        assert_eq!(pointer_log.get_head("incomplete").unwrap().seq, 1);
        assert_eq!(
            pointer_log.event_cid("incomplete", 3).unwrap(),
            Some(stranded_cid),
            "the unvalidated row remains filed but never becomes the head"
        );
        assert!(pointer_log.rebuild_from_events().is_err());
        assert_eq!(pointer_log.get_head("incomplete").unwrap().seq, 1);
    }

    #[test]
    fn incremental_pointer_rejects_noncanonical_padded_event_entries() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let target = put_target(&pointer_log, b"target");
        let event = PointerEvent::create_event("padded", target, 1);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let padding_target = put_target(&pointer_log, b"padding target");
        let padded = Entry::new(
            payload,
            vec![dag_core::Link::named(
                padding_target,
                "x".repeat(256 * 1024),
            )],
            None,
        );
        let padded_cid = pointer_log.store.put_entry(&padded).unwrap();

        assert!(matches!(
            pointer_log
                .prepare_incremental_sync_plan(&[("padded".into(), 1, padded_cid)])
                .unwrap_err()
                .into_parts()
                .3,
            PointerError::Serialization(_)
        ));
        assert!(matches!(
            pointer_log.get_head("padded"),
            Err(PointerError::NotFound(_))
        ));
    }

    #[test]
    fn event_pages_seek_to_the_cursor_without_rescanning_the_prefix() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let txn = pointer_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(POINTER_EVENTS).unwrap();
            for seq in 1..=1_000u64 {
                let key = encode_event_key("history", seq);
                let cid = Cid::compute(&seq.to_be_bytes());
                events.insert(key.as_slice(), cid.as_bytes()).unwrap();
            }
        }
        txn.commit().unwrap();

        PointerLog::<FsStore>::reset_event_page_rows_visited();
        let first = pointer_log.event_cids_page(None, 17).unwrap();
        assert_eq!(first.len(), 17);
        let cursor = first.last().unwrap();
        let second = pointer_log
            .event_cids_page(Some((&cursor.0, cursor.1)), 17)
            .unwrap();
        assert_eq!(second.len(), 17);
        assert_eq!(
            PointerLog::<FsStore>::event_page_rows_visited(),
            34,
            "the second page must seek to its encoded cursor, not scan 17 prior rows"
        );
    }

    #[test]
    fn test_create_and_resolve_pointer() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let target_cid = put_target(&pointer_log, b"test content");

        pointer_log
            .create("test-pointer", target_cid.clone())
            .unwrap();

        let resolved = pointer_log.resolve("test-pointer").unwrap();
        assert_eq!(resolved, target_cid);

        let head = pointer_log.get_head("test-pointer").unwrap();
        assert_eq!(head.seq, 1);
        assert_eq!(head.current_cid, target_cid);
    }

    #[test]
    fn test_update_pointer() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let initial_cid = put_target(&pointer_log, b"initial content");
        let updated_cid = put_target(&pointer_log, b"updated content");

        pointer_log
            .create("update-test", initial_cid.clone())
            .unwrap();

        let (new_seq, old_cid) = pointer_log
            .update("update-test", updated_cid.clone())
            .unwrap();
        assert_eq!(new_seq, 2);
        assert_eq!(old_cid, initial_cid);

        let resolved = pointer_log.resolve("update-test").unwrap();
        assert_eq!(resolved, updated_cid);

        let head = pointer_log.get_head("update-test").unwrap();
        assert_eq!(head.seq, 2);
        assert_eq!(head.current_cid, updated_cid);
    }

    #[test]
    fn test_pointer_history() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid1 = put_target(&pointer_log, b"content 1");
        let cid2 = put_target(&pointer_log, b"content 2");
        let cid3 = put_target(&pointer_log, b"content 3");

        pointer_log.create("history-test", cid1.clone()).unwrap();
        pointer_log.update("history-test", cid2.clone()).unwrap();
        pointer_log.update("history-test", cid3.clone()).unwrap();

        let history = pointer_log.history("history-test", 1..4).unwrap();
        assert_eq!(history.len(), 3);

        assert!(history[0].is_create());
        assert_eq!(history[0].seq, 1);
        assert_eq!(history[0].new, cid1);
        assert_eq!(history[0].prev, None);

        assert!(history[1].is_update());
        assert_eq!(history[1].seq, 2);
        assert_eq!(history[1].new, cid2);
        assert_eq!(history[1].prev, Some(cid1.clone()));

        assert!(history[2].is_update());
        assert_eq!(history[2].seq, 3);
        assert_eq!(history[2].new, cid3);
        assert_eq!(history[2].prev, Some(cid2));
    }

    #[test]
    fn test_list_pointers() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid = put_target(&pointer_log, b"test content");

        let pointers = pointer_log.list_pointers().unwrap();
        assert!(pointers.is_empty());

        pointer_log.create("alpha", cid.clone()).unwrap();
        pointer_log.create("beta", cid.clone()).unwrap();
        pointer_log.create("gamma", cid).unwrap();

        let pointers = pointer_log.list_pointers().unwrap();
        assert_eq!(pointers, vec!["alpha", "beta", "gamma"]);
        assert_eq!(pointer_log.head_count().unwrap(), 3);
    }

    #[test]
    fn list_pointers_refuses_non_utf8_head_keys() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let target = put_target(&pointer_log, b"valid target");
        pointer_log.create("valid", target).unwrap();

        let txn = pointer_log.db.begin_write().unwrap();
        {
            let mut heads = txn.open_table(POINTER_HEADS).unwrap();
            heads
                .insert([0xff].as_slice(), b"irrelevant".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        assert!(matches!(
            pointer_log.list_pointers(),
            Err(PointerError::Serialization(_))
        ));
        assert_eq!(pointer_log.head_count().unwrap(), 2);
    }

    #[test]
    fn test_pointer_not_found() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let result = pointer_log.resolve("nonexistent");
        assert!(matches!(result, Err(PointerError::NotFound(_))));

        let result = pointer_log.get_head("nonexistent");
        assert!(matches!(result, Err(PointerError::NotFound(_))));

        let result = pointer_log.update("nonexistent", Cid::compute(b"test"));
        assert!(matches!(result, Err(PointerError::NotFound(_))));
    }

    #[test]
    fn test_pointer_already_exists() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid = put_target(&pointer_log, b"test content");

        pointer_log.create("duplicate-test", cid.clone()).unwrap();

        let result = pointer_log.create("duplicate-test", cid);
        assert!(matches!(result, Err(PointerError::AlreadyExists(_))));
    }

    #[test]
    fn trigger_capacity_remains_a_typed_pointer_error() {
        let error = trigger_enqueue_err(crate::ControlError::Capacity("trigger queue".into()));
        assert!(matches!(error, PointerError::Capacity(ref detail) if detail == "trigger queue"));
    }

    #[test]
    fn test_history_range_validation() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid = put_target(&pointer_log, b"test content");
        pointer_log.create("range-test", cid).unwrap();

        // Invalid range: start >= end
        let result = pointer_log.history("range-test", 5..5);
        assert!(matches!(
            result,
            Err(PointerError::InvalidRange { start: 5, end: 5 })
        ));

        // Built from bindings rather than written as `10..5`: the reversal is
        // the point of the test, but as a literal it reads as a typo and trips
        // `clippy::reversed_empty_ranges`.
        let (start, end) = (10u64, 5u64);
        let result = pointer_log.history("range-test", start..end);
        assert!(matches!(
            result,
            Err(PointerError::InvalidRange { start: 10, end: 5 })
        ));

        // Valid range but beyond available data
        let result = pointer_log.history("range-test", 5..10);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        // Partial overlap
        let result = pointer_log.history("range-test", 1..10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_rebuild_from_events() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid1 = put_target(&pointer_log, b"content 1");
        let cid2 = put_target(&pointer_log, b"content 2");
        let cid3 = put_target(&pointer_log, b"content 3");

        pointer_log.create("rebuild-test1", cid1.clone()).unwrap();
        pointer_log.create("rebuild-test2", cid2.clone()).unwrap();
        pointer_log.update("rebuild-test1", cid3.clone()).unwrap();

        let head1 = pointer_log.get_head("rebuild-test1").unwrap();
        let head2 = pointer_log.get_head("rebuild-test2").unwrap();
        assert_eq!(head1.seq, 2);
        assert_eq!(head1.current_cid, cid3);
        assert_eq!(head2.seq, 1);
        assert_eq!(head2.current_cid, cid2);

        let rebuilt_count = pointer_log.rebuild_from_events().unwrap();
        assert_eq!(rebuilt_count, 2);

        let head1_after = pointer_log.get_head("rebuild-test1").unwrap();
        let head2_after = pointer_log.get_head("rebuild-test2").unwrap();
        assert_eq!(head1_after.seq, 2);
        assert_eq!(head1_after.current_cid, cid3);
        assert_eq!(head2_after.seq, 1);
        assert_eq!(head2_after.current_cid, cid2);

        assert_eq!(pointer_log.resolve("rebuild-test1").unwrap(), cid3);
        assert_eq!(pointer_log.resolve("rebuild-test2").unwrap(), cid2);
    }

    #[test]
    fn test_pointer_sequence_ordering() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid1 = put_target(&pointer_log, b"seq 1");
        let cid2 = put_target(&pointer_log, b"seq 2");
        let cid3 = put_target(&pointer_log, b"seq 3");
        let cid4 = put_target(&pointer_log, b"seq 4");
        let cid5 = put_target(&pointer_log, b"seq 5");

        pointer_log.create("sequence-test", cid1.clone()).unwrap();
        let (seq2, _) = pointer_log.update("sequence-test", cid2.clone()).unwrap();
        let (seq3, _) = pointer_log.update("sequence-test", cid3.clone()).unwrap();
        let (seq4, _) = pointer_log.update("sequence-test", cid4.clone()).unwrap();
        let (seq5, _) = pointer_log.update("sequence-test", cid5.clone()).unwrap();

        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
        assert_eq!(seq4, 4);
        assert_eq!(seq5, 5);

        let history = pointer_log.history("sequence-test", 1..6).unwrap();
        assert_eq!(history.len(), 5);

        for (i, event) in history.iter().enumerate() {
            assert_eq!(event.seq, (i + 1) as u64);
        }

        assert_eq!(history[0].prev, None);
        assert_eq!(history[0].new, cid1);

        assert_eq!(history[1].prev, Some(cid1));
        assert_eq!(history[1].new, cid2);

        assert_eq!(history[2].prev, Some(cid2));
        assert_eq!(history[2].new, cid3);

        assert_eq!(history[3].prev, Some(cid3));
        assert_eq!(history[3].new, cid4);

        assert_eq!(history[4].prev, Some(cid4));
        assert_eq!(history[4].new, cid5);
    }

    #[test]
    fn test_pointer_id_validation() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let cid = put_target(&pointer_log, b"test");

        // Empty string is a valid pointer ID
        assert!(pointer_log.create("", cid.clone()).is_ok());

        // Binary keys make special characters safe, including the old
        // delimiter characters and non-ASCII text.
        let special_ids = vec![
            "test-pointer",
            "test_pointer",
            "test.pointer",
            "test/pointer",
            "test pointer",
            "test:pointer",
            "UPPERCASE",
            "123numeric",
            "\u{3b1}\u{3b2}\u{3b3}", // Greek alpha-beta-gamma
        ];

        for id in special_ids {
            pointer_log
                .create(id, cid.clone())
                .unwrap_or_else(|e| panic!("failed to create pointer {:?}: {}", id, e));
            assert_eq!(pointer_log.resolve(id).unwrap(), cid);
        }

        for unsafe_id in [
            "pointer\nforged",
            "pointer\u{001b}[2J",
            "pointer\u{202e}txt",
            "pointer\u{2067}txt\u{2069}",
        ] {
            assert!(matches!(
                pointer_log.create(unsafe_id, cid.clone()),
                Err(PointerError::Serialization(_))
            ));
        }
    }

    #[test]
    fn test_rapid_sequential_updates() {
        // This test validates that rapid sequential updates maintain data integrity
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let initial_cid = put_target(&pointer_log, b"initial");
        pointer_log.create("rapid-test", initial_cid).unwrap();

        let num_updates = 20;
        let mut expected_cids = vec![];

        for i in 0..num_updates {
            let content = format!("rapid update {}", i);
            let cid = put_target(&pointer_log, content.as_bytes());
            expected_cids.push(cid.clone());

            let (seq, _) = pointer_log.update("rapid-test", cid).unwrap();
            assert_eq!(seq, (i + 2) as u64); // +2 because initial was seq 1
        }

        let final_head = pointer_log.get_head("rapid-test").unwrap();
        assert_eq!(final_head.seq, (num_updates + 1) as u64);
        assert_eq!(
            final_head.current_cid,
            expected_cids.last().unwrap().clone()
        );

        let history = pointer_log
            .history("rapid-test", 1..(num_updates + 2) as u64)
            .unwrap();
        assert_eq!(history.len(), (num_updates + 1) as usize);

        for i in 1..history.len() {
            assert_eq!(history[i].prev.as_ref().unwrap(), &history[i - 1].new);
            assert_eq!(history[i].seq, (i + 1) as u64);
        }

        for (i, expected_cid) in expected_cids.iter().enumerate() {
            assert_eq!(history[i + 1].new, *expected_cid); // +1 because first event is create
        }
    }

    /// Under sled this asserted a >=75% success rate, because optimistic
    /// transactions could exhaust their retries under contention. The redb
    /// port serialises writers behind a mutex, so there is no failure mode
    /// left: every update must succeed, exactly once each.
    #[test]
    fn test_atomic_concurrent_updates() {
        use std::sync::Arc;
        use std::thread;

        let (_store, _temp_dir, pointer_log) = create_test_setup();
        let pointer_log = Arc::new(pointer_log);

        let initial_cid = put_target(&pointer_log, b"initial");
        pointer_log.create("atomic-test", initial_cid).unwrap();

        let num_threads = 16;
        let mut handles = vec![];

        for i in 0..num_threads {
            let pointer_log = pointer_log.clone();
            let handle = thread::spawn(move || {
                let content = format!("atomic update {}", i);
                let cid = put_target(&pointer_log, content.as_bytes());
                pointer_log.update("atomic-test", cid)
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Writers queue; none may fail.
        for (i, result) in results.iter().enumerate() {
            assert!(result.is_ok(), "update {} failed: {:?}", i, result);
        }

        // Final sequence is exactly initial + one per thread.
        let final_head = pointer_log.get_head("atomic-test").unwrap();
        assert_eq!(final_head.seq, 1 + num_threads as u64);

        // Sequence numbers are unique and consecutive.
        let mut seq_numbers: Vec<u64> = results.iter().map(|r| r.as_ref().unwrap().0).collect();
        seq_numbers.sort();
        for (i, &seq) in seq_numbers.iter().enumerate() {
            assert_eq!(
                seq,
                (i + 2) as u64,
                "Sequence numbers should be consecutive"
            );
        }

        // History and chain integrity survive the contention.
        let history = pointer_log
            .history("atomic-test", 1..(final_head.seq + 1))
            .unwrap();
        assert_eq!(history.len(), final_head.seq as usize);

        for i in 1..history.len() {
            assert_eq!(
                history[i].prev.as_ref().unwrap(),
                &history[i - 1].new,
                "Chain integrity should be maintained"
            );
            assert_eq!(history[i].seq, (i + 1) as u64);
        }
    }

    #[test]
    fn test_rebuild_validation() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid1 = put_target(&pointer_log, b"content 1");
        let cid2 = put_target(&pointer_log, b"content 2");
        let cid3 = put_target(&pointer_log, b"content 3");

        pointer_log
            .create("validation-test1", cid1.clone())
            .unwrap();
        pointer_log
            .create("validation-test2", cid2.clone())
            .unwrap();
        pointer_log
            .update("validation-test1", cid3.clone())
            .unwrap();

        let orig_head1 = pointer_log.get_head("validation-test1").unwrap();
        let orig_head2 = pointer_log.get_head("validation-test2").unwrap();
        assert_eq!(orig_head1.seq, 2);
        assert_eq!(orig_head1.current_cid, cid3);
        assert_eq!(orig_head2.seq, 1);
        assert_eq!(orig_head2.current_cid, cid2);

        let history1 = pointer_log.history("validation-test1", 1..3).unwrap();
        let history2 = pointer_log.history("validation-test2", 1..2).unwrap();

        assert_eq!(history1.len(), 2);
        assert_eq!(history2.len(), 1);

        assert!(history1[0].is_create());
        assert_eq!(history1[0].prev, None);
        assert_eq!(history1[0].new, cid1);

        assert!(history1[1].is_update());
        assert_eq!(history1[1].prev, Some(cid1.clone()));
        assert_eq!(history1[1].new, cid3);

        assert!(history2[0].is_create());
        assert_eq!(history2[0].prev, None);
        assert_eq!(history2[0].new, cid2);

        let rebuilt_count = pointer_log.rebuild_from_events().unwrap();
        assert_eq!(rebuilt_count, 2, "Should rebuild both valid pointers");

        let rebuilt_head1 = pointer_log.get_head("validation-test1").unwrap();
        let rebuilt_head2 = pointer_log.get_head("validation-test2").unwrap();

        assert_eq!(rebuilt_head1.seq, orig_head1.seq);
        assert_eq!(rebuilt_head1.current_cid, orig_head1.current_cid);
        assert_eq!(rebuilt_head2.seq, orig_head2.seq);
        assert_eq!(rebuilt_head2.current_cid, orig_head2.current_cid);

        assert_eq!(pointer_log.resolve("validation-test1").unwrap(), cid3);
        assert_eq!(pointer_log.resolve("validation-test2").unwrap(), cid2);

        let rebuilt_history1 = pointer_log.history("validation-test1", 1..3).unwrap();
        let rebuilt_history2 = pointer_log.history("validation-test2", 1..2).unwrap();

        assert_eq!(rebuilt_history1.len(), 2);
        assert_eq!(rebuilt_history2.len(), 1);

        assert_eq!(rebuilt_history1[0].new, history1[0].new);
        assert_eq!(rebuilt_history1[1].new, history1[1].new);
        assert_eq!(rebuilt_history1[1].prev, history1[1].prev);
    }

    #[test]
    fn test_large_sequence_numbers() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid1 = put_target(&pointer_log, b"content 1");
        let cid2 = put_target(&pointer_log, b"content 2");

        pointer_log.create("large-seq-test", cid1).unwrap();
        pointer_log.update("large-seq-test", cid2.clone()).unwrap();

        let head = pointer_log.get_head("large-seq-test").unwrap();
        assert_eq!(head.seq, 2);

        // Test that we can handle reasonably large sequences
        for i in 3..=1000 {
            let content = format!("content {}", i);
            let cid = put_target(&pointer_log, content.as_bytes());
            let (seq, _) = pointer_log.update("large-seq-test", cid).unwrap();
            assert_eq!(seq, i as u64);
        }

        let final_head = pointer_log.get_head("large-seq-test").unwrap();
        assert_eq!(final_head.seq, 1000);
    }

    #[test]
    fn test_serialization_edge_cases() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let test_cases = vec![
            ("zero-cid", vec![0u8; 32]),
            ("max-cid", vec![255u8; 32]),
            ("pattern-cid", (0..32).map(|i| i as u8).collect()),
        ];

        for (name, cid_bytes) in test_cases {
            let cid = Cid::from_bytes(&cid_bytes).unwrap();
            let pointer_id = format!("serde-test-{}", name);
            let event = PointerEvent::create_event(&pointer_id, cid.clone(), 42);
            let bytes = pointer_log.serialize_event(&event).unwrap();
            assert_eq!(pointer_log.deserialize_event(&bytes).unwrap(), event);

            let head = PointerHead {
                seq: 1,
                current_cid: cid,
            };
            let bytes = pointer_log.serialize_head(&head).unwrap();
            assert_eq!(pointer_log.deserialize_head(&bytes).unwrap(), head);
        }
    }

    #[test]
    fn test_pointer_event_invariants() {
        let (_store, _temp_dir, pointer_log) = create_test_setup();

        let cid1 = put_target(&pointer_log, b"invariant test 1");
        let cid2 = put_target(&pointer_log, b"invariant test 2");
        let cid3 = put_target(&pointer_log, b"invariant test 3");

        pointer_log.create("invariant-test", cid1.clone()).unwrap();
        pointer_log.update("invariant-test", cid2.clone()).unwrap();
        pointer_log.update("invariant-test", cid3.clone()).unwrap();

        let history = pointer_log.history("invariant-test", 1..4).unwrap();

        for (i, event) in history.iter().enumerate() {
            // I1: Sequence numbers are monotonic and consecutive
            assert_eq!(event.seq, (i + 1) as u64);

            // I2: Pointer IDs match
            assert_eq!(event.pointer_id, "invariant-test");

            // I3: Timestamps are monotonic (approximately)
            if i > 0 {
                assert!(event.ts >= history[i - 1].ts);
            }

            // I4: First event has no prev, others have correct prev chain
            if i == 0 {
                assert!(event.prev.is_none());
                assert!(event.is_create());
            } else {
                assert!(event.prev.is_some());
                assert!(event.is_update());
                assert_eq!(event.prev.as_ref().unwrap(), &history[i - 1].new);
            }
        }

        // I5: Current head matches last event's 'new' CID
        let head = pointer_log.get_head("invariant-test").unwrap();
        assert_eq!(head.current_cid, history.last().unwrap().new);
        assert_eq!(head.seq, history.last().unwrap().seq);
    }

    #[test]
    fn malformed_filed_pointer_history_leaves_all_heads_unchanged() {
        for case in ["identity", "gap", "prev", "missing"] {
            let (_store, _temp, pointer_log) = create_test_setup();
            let target = put_target(&pointer_log, b"good target");
            pointer_log.create("good", target.clone()).unwrap();
            let before = pointer_log.get_head("good").unwrap();

            let first_target = Cid::compute(b"bad first target");
            if matches!(case, "gap" | "prev") {
                let create = PointerEvent::create_event("bad", first_target.clone(), 1);
                let create_cid = put_event(&pointer_log, &create);
                file_event(&pointer_log, "bad", 1, &create_cid);
            }

            let seq = if case == "gap" { 3 } else { 2 };
            let event = PointerEvent::update_event(
                if case == "identity" { "other" } else { "bad" },
                if case == "identity" { 7 } else { seq },
                if case == "prev" {
                    Cid::compute(b"wrong predecessor")
                } else {
                    first_target
                },
                Cid::compute(b"new target"),
                2,
            );
            let cid = if case == "missing" {
                Cid::compute(b"not stored")
            } else {
                put_event(&pointer_log, &event)
            };
            file_event(&pointer_log, "bad", seq, &cid);

            assert!(
                pointer_log.rebuild_from_events().is_err(),
                "case {case} was accepted"
            );
            assert_eq!(pointer_log.get_head("good").unwrap(), before);
            assert_eq!(pointer_log.list_pointers().unwrap(), vec!["good"]);
        }
    }

    #[test]
    fn successful_pointer_rebuild_clears_stale_heads() {
        let (_store, _temp, pointer_log) = create_test_setup();
        let live = put_target(&pointer_log, b"live");
        pointer_log.create("live", live.clone()).unwrap();
        let stale = put_target(&pointer_log, b"stale");
        pointer_log.create("stale", stale).unwrap();

        let txn = pointer_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(POINTER_EVENTS).unwrap();
            let key = encode_event_key("stale", 1);
            events.remove(key.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        assert_eq!(pointer_log.rebuild_from_events().unwrap(), 1);
        assert_eq!(pointer_log.resolve("live").unwrap(), live);
        assert!(matches!(
            pointer_log.get_head("stale"),
            Err(PointerError::NotFound(_))
        ));
    }

    #[test]
    fn rebuild_snapshot_and_swap_are_one_writer_exclusion_window() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (_store, _temp, pointer_log) = create_test_setup();
        let pointer_log = Arc::new(pointer_log);
        let first = put_target(&pointer_log, b"first");
        let second = put_target(&pointer_log, b"second");
        pointer_log.create("release", first.clone()).unwrap();

        // Pause a writer inside the shared mutation window. The pre-fix
        // rebuild took its snapshot before acquiring the writer lock, so it
        // would later overwrite this writer's seq-2 head with its stale seq-1
        // plan. The exclusive rebuild gate must wait until publication ends.
        let mutation_guard = pointer_log
            .mutation_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let writer_guard = pointer_log
            .write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (done_tx, done_rx) = mpsc::channel();
        let rebuilding = pointer_log.clone();
        let handle = std::thread::spawn(move || {
            done_tx.send(rebuilding.rebuild_from_events()).unwrap();
        });
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        let event = PointerEvent::update_event("release", 2, first, second.clone(), 2);
        let event_cid = put_event(&pointer_log, &event);
        let txn = pointer_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(POINTER_EVENTS).unwrap();
            let key = encode_event_key("release", 2);
            events.insert(key.as_slice(), event_cid.as_bytes()).unwrap();
            let mut heads = txn.open_table(POINTER_HEADS).unwrap();
            let head = PointerHead {
                seq: 2,
                current_cid: second.clone(),
            };
            let bytes = pointer_log.serialize_head(&head).unwrap();
            heads
                .insert(b"release".as_slice(), bytes.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        drop(writer_guard);
        drop(mutation_guard);

        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            1
        );
        handle.join().unwrap();
        assert_eq!(pointer_log.get_head("release").unwrap().seq, 2);
        assert_eq!(pointer_log.resolve("release").unwrap(), second);
    }
}
