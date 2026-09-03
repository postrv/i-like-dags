//! # Pin Management
//!
//! This module implements the pin system for retention policies, satisfying
//! Acceptance Criterion D from the DAG system design. Pins prevent garbage
//! collection by marking content as important with optional TTL.
//!
//! ## Core Concepts
//!
//! - **Pin**: A retention policy targeting specific content
//! - **PinEvent**: An immutable event recording pin state changes
//! - **PinLog**: The append-only log managing all pin operations
//! - **PinHead**: Current state cache for fast lookup
//!
//! ## Key Invariants
//!
//! The pin system maintains several critical invariants:
//!
//! ### P1: Sequence Monotonicity
//! For any pin P, sequence numbers are strictly increasing: seq(n) = seq(n-1) + 1
//! This ensures total ordering of events within each pin's history.
//!
//! ### P2: Event Immutability
//! Once written to the content store, PinEvents are immutable and tamper-evident
//! through CID-based addressing.
//!
//! ### P3: Append-Only History
//! The event log only grows; historical events are never modified or deleted.
//! Deactivation is modeled as a new event on the same pin_id.
//!
//! ### P4: Head Consistency
//! The cached head always matches the latest event:
//! head.event.seq = max(seq) for the pin
//!
//! ### P5: TTL Semantics
//! expires_at is stored as absolute POSIX timestamp to avoid clock skew issues.
//! TTL is converted to absolute time at creation, not evaluation.
//!
//! ## Storage Architecture
//!
//! ```text
//! PinLog
//! ├── ContentStore (via Arc<S>)          # PinEvents as CBOR-encoded Entries
//! └── redb Database (shared)
//!     ├── "pin_heads" table              # pin_id -> PinHead (fast lookup)
//!     ├── "pin_events" table             # binary_key([len][pid][seq]) -> event_cid
//!     └── "pin_by_target" table          # target_cid -> Vec<pin_id> (reverse lookup)
//! ```
//!
//! Event keys use binary encoding to avoid delimiter issues:
//! `[u32:pin_id_len_be] [pin_id_bytes] [u64:seq_be]`
//!
//! ## Concurrency
//!
//! As with `PointerLog`: redb serialises writers, and a per-log mutex covers
//! the read-modify-write window between transactions, replacing the sled-era
//! optimistic retry loops.

mod keys;

use dag_core::{
    validate_pin_id, Cid, ContentStore, Entry, PinError, PinEvent, PinHead, PinScope, PinState,
    PinTarget,
};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use keys::{decode_event_key, encode_event_key};

const PIN_HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pin_heads");
const PIN_EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pin_events");
const PIN_BY_TARGET: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pin_by_target");

/// Maximum encoded legacy [`PinEvent`] payload accepted before CBOR decoding.
///
/// Older schemas bounded only the enclosing content chunk, so historical
/// author/node strings can legitimately exceed today's ingress limits. Keep
/// that compatibility boundary while aggregate recovery byte limits bound a
/// scan; newly serialized events use the tighter field checks below.
pub(crate) const MAX_PIN_EVENT_PAYLOAD_BYTES: usize = dag_core::MAX_CHUNK_SIZE;
const MAX_PIN_NODE_ID_BYTES: usize = 256;
const MAX_PIN_AUTHOR_BYTES: usize = 1_024;

/// Per-log ceiling matching the native atomic sync session limit.
pub(crate) const MAX_INCREMENTAL_PIN_EVENTS: usize = 65_536;

/// Aggregate immutable-event bytes decoded by one incremental pin plan.
const MAX_INCREMENTAL_PIN_EVENT_BYTES: usize = 64 * 1024 * 1024;

/// Pin heads embed one event and its CID. Keep legacy event compatibility but
/// bound corrupt derived rows before CBOR allocation.
const MAX_PIN_HEAD_BYTES: usize = MAX_PIN_EVENT_PAYLOAD_BYTES + 4 * 1024;

/// The legacy reverse index stores all IDs for a target in one CBOR row. Until
/// that schema is migrated to composite keys, every path uses these limits so
/// local writes, recovery and sync cannot disagree about a valid row.
pub(crate) const MAX_PIN_IDS_PER_TARGET: usize = 65_536;
pub(crate) const MAX_PIN_BY_TARGET_ROW_BYTES: usize = 32 * 1024 * 1024;

/// One batch can touch many target rows; cap their aggregate decoded bytes as
/// well as each row individually.
const MAX_INCREMENTAL_PIN_REVERSE_BYTES: usize = 64 * 1024 * 1024;

fn db_err(e: impl std::fmt::Display) -> PinError {
    PinError::Storage(e.to_string())
}

fn pin_offer_err(e: dag_core::OfferError) -> PinError {
    match e {
        dag_core::OfferError::ZeroSeq => PinError::InvalidSequence {
            expected: 1,
            actual: 0,
        },
        dag_core::OfferError::Divergent {
            id,
            seq,
            existing,
            offered,
        } => PinError::PinAlreadyExists(format!(
            "{id} seq {seq} already names {existing}, refusing to replace it with {offered}"
        )),
        other => PinError::Storage(other.to_string()),
    }
}

/// Validate fields that are not covered by [`validate_pin_id`].
///
/// Scope and author strings are persisted in heads, reports and indexes. Keep
/// them finite and single-line/control-free everywhere they can enter, rather
/// than trusting only the CLI's argument parser.
pub(crate) fn validate_pin_event_fields(event: &PinEvent) -> Result<(), PinError> {
    validate_pin_event_identity(event)?;
    if let PinScope::Local { node_id } = &event.scope {
        if node_id.is_empty() {
            return Err(PinError::Serialization(
                "local pin node ID cannot be empty".into(),
            ));
        }
        if node_id.len() > MAX_PIN_NODE_ID_BYTES {
            return Err(PinError::Serialization(format!(
                "local pin node ID exceeds {MAX_PIN_NODE_ID_BYTES} bytes"
            )));
        }
        if let Err(reason) = dag_core::validate_identifier_text(node_id) {
            return Err(PinError::Serialization(format!(
                "local pin node ID is unsafe: {reason}"
            )));
        }
    }
    if let Some(author) = &event.author {
        if author.len() > MAX_PIN_AUTHOR_BYTES {
            return Err(PinError::Serialization(format!(
                "pin author exceeds {MAX_PIN_AUTHOR_BYTES} bytes"
            )));
        }
        if let Err(reason) = dag_core::validate_identifier_text(author) {
            return Err(PinError::Serialization(format!(
                "pin author is unsafe: {reason}"
            )));
        }
    }
    Ok(())
}

fn validate_pin_event_identity(event: &PinEvent) -> Result<(), PinError> {
    validate_pin_id(&event.pin_id)?;
    if event.seq == 0 {
        return Err(PinError::InvalidSequence {
            expected: 1,
            actual: 0,
        });
    }
    Ok(())
}

/// Decode a pin event through the common pre-allocation and field bounds.
pub(crate) fn decode_pin_event(bytes: &[u8]) -> Result<PinEvent, PinError> {
    if bytes.len() > MAX_PIN_EVENT_PAYLOAD_BYTES {
        return Err(PinError::Serialization(format!(
            "pin event payload is {} bytes, above the {}-byte limit",
            bytes.len(),
            MAX_PIN_EVENT_PAYLOAD_BYTES
        )));
    }
    let event: PinEvent = dag_core::decode_cbor_exact(bytes).map_err(|error| {
        PinError::Serialization(format!("Failed to deserialize event: {error}"))
    })?;
    // Do not apply current ingress-only author/node limits to historical
    // immutable events: doing so would orphan CIDs accepted by older schemas.
    validate_pin_event_identity(&event)?;
    Ok(event)
}

/// CBOR decoder that grows the legacy reverse row one element at a time.
/// Ignoring the sequence size hint is important: an attacker-controlled CBOR
/// array length must not become a preallocation before the cardinality limit
/// is checked.
struct BoundedPinIds(Vec<String>);

impl<'de> serde::Deserialize<'de> for BoundedPinIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BoundedPinIds;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a bounded sequence of pin IDs")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut ids = Vec::new();
                while let Some(id) = sequence.next_element::<String>()? {
                    if ids.len() == MAX_PIN_IDS_PER_TARGET {
                        return Err(serde::de::Error::custom(format!(
                            "pin target has more than {MAX_PIN_IDS_PER_TARGET} IDs"
                        )));
                    }
                    validate_pin_id(&id).map_err(serde::de::Error::custom)?;
                    ids.push(id);
                }
                Ok(BoundedPinIds(ids))
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

/// Append-only pin log with atomic operations and fast lookups
pub struct PinLog<S: ContentStore> {
    /// Content store for immutable PinEvent storage
    store: Arc<S>,
    /// Shared control-plane database
    db: Arc<Database>,
    /// Serialises read-modify-write between transactions; see module docs.
    write_lock: Mutex<()>,
    /// Cross-log recovery barrier. See [`crate::MutationGate`].
    mutation_gate: crate::MutationGate,
    /// Hard ceiling for validating the closure promised by a new pin.
    max_reference_expansion: AtomicUsize,
    /// One-shot deterministic pause after closure validation. Test-only.
    #[cfg(test)]
    publication_test_pause:
        parking_lot::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    /// Optional event bus for observability
    event_bus: Option<crate::events::EventBus>,
}

/// Fully validated replacements for every pin-derived lookup table.
pub(crate) struct PinRebuildPlan {
    heads: Vec<(Vec<u8>, Vec<u8>)>,
    by_target: Vec<(Vec<u8>, Vec<u8>)>,
    retention_roots: Vec<PinRetentionRoot>,
    pins_processed: u32,
    events_processed: u32,
}

#[derive(Debug)]
struct PinRowUpdate {
    key: Vec<u8>,
    expected: Option<Vec<u8>>,
    value: Vec<u8>,
}

/// Bounded exact-key plan for one incremental pin-event publication.
///
/// Only newly filed events, advancing heads and reverse rows gaining a pin ID
/// are written. A deactivation never removes reverse membership: the index is
/// provenance lookup, not merely the set of currently retaining pins.
#[derive(Debug)]
pub(crate) struct PinIncrementalSyncPlan {
    event_inserts: Vec<(Vec<u8>, Vec<u8>)>,
    head_updates: Vec<PinRowUpdate>,
    reverse_updates: Vec<PinRowUpdate>,
    retention_roots: Vec<PinRetentionRoot>,
}

impl PinIncrementalSyncPlan {
    pub(crate) fn events_inserted(&self) -> usize {
        self.event_inserts.len()
    }

    pub(crate) fn heads_updated(&self) -> u32 {
        self.head_updates.len() as u32
    }

    pub(crate) fn retention_roots(&self) -> &[PinRetentionRoot] {
        &self.retention_roots
    }
}

/// A rejected incremental pin offer with the exact position being validated.
/// Failures in an affected cached head or reverse row use that pin's first
/// offered position as their diagnostic context.
#[derive(Debug, thiserror::Error)]
#[error("pin {id} seq {seq} ({cid}): {source}")]
pub(crate) struct PinIncrementalSyncError {
    id: String,
    seq: u64,
    cid: Cid,
    #[source]
    source: PinError,
}

impl PinIncrementalSyncError {
    fn new(id: String, seq: u64, cid: Cid, source: PinError) -> Self {
        Self {
            id,
            seq,
            cid,
            source,
        }
    }

    pub(crate) fn into_parts(self) -> (String, u64, Cid, PinError) {
        (self.id, self.seq, self.cid, self.source)
    }
}

/// An active pin head that may be a live root for a particular node.
#[derive(Debug, Clone)]
pub(crate) struct PinRetentionRoot {
    pub(crate) target: PinTarget,
    pub(crate) scope: PinScope,
    pub(crate) expires_at: Option<i64>,
}

impl PinRetentionRoot {
    pub(crate) fn is_unexpired(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }

    pub(crate) fn applies_to(&self, node_id: &str) -> bool {
        match &self.scope {
            PinScope::Global => true,
            PinScope::Local { node_id: pin_node } => pin_node == node_id,
        }
    }
}

impl PinRebuildPlan {
    pub(crate) fn report(&self, applied: bool) -> PinRebuildReport {
        PinRebuildReport {
            pins_processed: self.pins_processed,
            events_processed: self.events_processed,
            validation_errors: 0,
            heads_rebuilt: if applied { self.pins_processed } else { 0 },
        }
    }

    pub(crate) fn retention_roots(&self) -> &[PinRetentionRoot] {
        &self.retention_roots
    }
}

/// One pin's recovered events, as `(seq, event entry CID, event)`.
type PinChain = Vec<(u64, Cid, PinEvent)>;

/// Report from a rebuild driven by a content-store scan.
///
/// The counts exist because the scan *identifies* events by decoding them,
/// which is a guess however strict: anything it declines has to be visible,
/// or a recovery that quietly restored half a deployment would look identical
/// to one that restored all of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PinStoreRebuildReport {
    /// Chunks examined in the content store.
    pub chunks_scanned: usize,
    /// Chunks whose payload decoded as a [`PinEvent`].
    pub events_found: usize,
    /// Events belonging to a chain that failed validation and was not filed.
    pub events_skipped: usize,
    /// Events the store held that the events table did *not* already have, and
    /// which this scan filed. When a reconcile runs after a table rebuild, a
    /// non-zero count is the signal that the table was behind the store — the
    /// truncated-table case (seam 1) the plain rebuild reported success over.
    pub events_added: usize,
    /// Why each rejected chain was rejected, one line per pin.
    pub skipped: Vec<String>,
    /// Pin heads written.
    pub heads_rebuilt: u32,
}

/// A table rebuild reconciled against the content store.
///
/// The pin counterpart of [`crate::PointerReconcileReport`]: [`PinLog::rebuild`]
/// trusts the events table, so a table truncated by restoring an old
/// `control.redb` over a newer `data/` comes back behind the store — a pin
/// deactivated since the backup would return *active* and re-protect released
/// content. Reconciling merges anything the store holds beyond the table.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PinReconcileReport {
    /// The events-table rebuild.
    pub table: PinRebuildReport,
    /// The store scan that reconciled anything the table lacked.
    pub store: PinStoreRebuildReport,
}

/// Report from pin log rebuild operation
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PinRebuildReport {
    /// Number of pins processed
    pub pins_processed: u32,
    /// Number of events processed
    pub events_processed: u32,
    /// Number of validation errors found
    pub validation_errors: u32,
    /// Number of heads rebuilt
    pub heads_rebuilt: u32,
}

impl<S: ContentStore + 'static> PinLog<S> {
    /// Rows a full recovery scans or replaces in the pin subsystem.
    pub(crate) fn recovery_row_count(&self) -> Result<u64, PinError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let events = txn.open_table(PIN_EVENTS).map_err(db_err)?;
        let heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
        let by_target = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;
        let events = events.len().map_err(db_err)?;
        let heads = heads.len().map_err(db_err)?;
        let by_target = by_target.len().map_err(db_err)?;
        events
            .checked_add(heads)
            .and_then(|rows| rows.checked_add(by_target))
            .ok_or_else(|| PinError::Storage("pin recovery row count overflow".into()))
    }

    /// Hold the pin-log read/validate/write window for an atomic replication
    /// offer. The cross-log coordinator always takes the pointer lock first.
    pub(crate) fn import_batch_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn load_incremental_event(
        &self,
        cid: &Cid,
        bytes_read: &mut usize,
    ) -> Result<PinEvent, PinError> {
        // Account for the complete stored Entry before CBOR decoding. Event
        // payload bounds alone do not cover an entry padded with link/meta
        // structures.
        let raw = self
            .store
            .get_chunk(cid)
            .map_err(|error| PinError::Storage(error.to_string()))?;
        *bytes_read = bytes_read
            .checked_add(raw.len())
            .ok_or_else(|| PinError::Storage("pin event-byte accounting overflow".into()))?;
        if *bytes_read > MAX_INCREMENTAL_PIN_EVENT_BYTES {
            return Err(PinError::Storage(format!(
                "incremental pin validation exceeds the {MAX_INCREMENTAL_PIN_EVENT_BYTES}-byte event-read budget"
            )));
        }
        let entry =
            Entry::from_bytes_cbor(&raw).map_err(|error| PinError::Storage(error.to_string()))?;
        if !entry.links.is_empty() || entry.meta.is_some() {
            return Err(PinError::Serialization(format!(
                "pin event entry {cid} is non-canonical: links and metadata are not permitted"
            )));
        }
        self.deserialize_event(&entry.payload)
    }

    fn validate_incremental_transition(
        pin_id: &str,
        event_cid: &Cid,
        event: &PinEvent,
        previous: Option<(&Cid, &PinEvent)>,
    ) -> Result<(), PinError> {
        match previous {
            None => {
                if event.seq != 1 || event.prev.is_some() || event.state != PinState::Active {
                    return Err(PinError::Storage(format!(
                        "pin {pin_id}: seq 1 must be an active create without prev"
                    )));
                }
            }
            Some((previous_cid, previous_event)) => {
                if previous_event.pin_id != pin_id
                    || previous_event.seq.checked_add(1) != Some(event.seq)
                {
                    return Err(PinError::Storage(format!(
                        "pin {pin_id}: event {event_cid} does not immediately follow its decoded predecessor"
                    )));
                }
                if event.prev.as_ref() != Some(previous_cid) {
                    return Err(PinError::Storage(format!(
                        "pin {pin_id}: seq {} does not name filed predecessor {previous_cid}",
                        event.seq
                    )));
                }
                if event.target != previous_event.target
                    || event.scope != previous_event.scope
                    || event.expires_at != previous_event.expires_at
                {
                    return Err(PinError::Storage(format!(
                        "pin {pin_id}: seq {} changes immutable retention policy",
                        event.seq
                    )));
                }
                if previous_event.state != PinState::Active || event.state != PinState::Deactivated
                {
                    return Err(PinError::Storage(format!(
                        "pin {pin_id}: seq {} is not an active-to-deactivated transition",
                        event.seq
                    )));
                }
            }
        }
        Ok(())
    }

    /// Prepare a bounded incremental pin publication without scanning either
    /// the event history or a derived table.
    ///
    /// The caller retains the mutation/durability barriers and
    /// [`Self::import_batch_lock`] through validation and apply. Current heads
    /// are checked against their exact filed event and predecessor; every new
    /// event must be a contiguous suffix. Reverse target rows are exact-key
    /// reads and are updated only when they do not already contain every
    /// affected pin ID.
    pub(crate) fn prepare_incremental_sync_plan(
        &self,
        offered: &[(String, u64, Cid)],
    ) -> Result<PinIncrementalSyncPlan, PinIncrementalSyncError> {
        if offered.is_empty() {
            return Ok(PinIncrementalSyncPlan {
                event_inserts: Vec::new(),
                head_updates: Vec::new(),
                reverse_updates: Vec::new(),
                retention_roots: Vec::new(),
            });
        }
        let (id, seq, cid) = &offered[0];
        let mut failure_context = Some((id.clone(), *seq, cid.clone()));
        self.prepare_incremental_sync_plan_inner(offered, &mut failure_context)
            .map_err(|source| {
                let (id, seq, cid) =
                    failure_context.expect("a non-empty offer always has rejection context");
                PinIncrementalSyncError::new(id, seq, cid, source)
            })
    }

    fn prepare_incremental_sync_plan_inner(
        &self,
        offered: &[(String, u64, Cid)],
        failure_context: &mut Option<(String, u64, Cid)>,
    ) -> Result<PinIncrementalSyncPlan, PinError> {
        use std::collections::{BTreeMap, BTreeSet};

        if offered.len() > MAX_INCREMENTAL_PIN_EVENTS {
            return Err(PinError::Storage(format!(
                "incremental pin offer contains {} events; limit is {MAX_INCREMENTAL_PIN_EVENTS}",
                offered.len()
            )));
        }

        let mut by_id: BTreeMap<String, BTreeMap<u64, Cid>> = BTreeMap::new();
        for (pin_id, seq, cid) in offered {
            *failure_context = Some((pin_id.clone(), *seq, cid.clone()));
            validate_pin_id(pin_id)?;
            if *seq == 0 {
                return Err(pin_offer_err(dag_core::OfferError::ZeroSeq));
            }
            match by_id.entry(pin_id.clone()).or_default().entry(*seq) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(cid.clone());
                }
                std::collections::btree_map::Entry::Occupied(slot) if slot.get() == cid => {}
                std::collections::btree_map::Entry::Occupied(slot) => {
                    return Err(pin_offer_err(dag_core::OfferError::Divergent {
                        id: pin_id.clone(),
                        seq: *seq,
                        existing: slot.get().clone(),
                        offered: cid.clone(),
                    }));
                }
            }
        }

        let first_context_by_id: BTreeMap<String, (u64, Cid)> = by_id
            .iter()
            .map(|(pin_id, positions)| {
                let (seq, cid) = positions
                    .first_key_value()
                    .expect("a grouped pin offer is non-empty");
                (pin_id.clone(), (*seq, cid.clone()))
            })
            .collect();

        let (first_id, first_seq, first_cid) = &offered[0];
        *failure_context = Some((first_id.clone(), *first_seq, first_cid.clone()));
        let read = self.db.begin_read().map_err(db_err)?;
        let event_table = read.open_table(PIN_EVENTS).map_err(db_err)?;
        let head_table = read.open_table(PIN_HEADS).map_err(db_err)?;
        let reverse_table = read.open_table(PIN_BY_TARGET).map_err(db_err)?;
        let mut event_bytes_read = 0usize;
        let mut event_inserts = Vec::with_capacity(offered.len());
        let mut head_updates = Vec::with_capacity(by_id.len());
        let mut reverse_additions: BTreeMap<Vec<u8>, BTreeSet<String>> = BTreeMap::new();
        let mut retention_roots = Vec::with_capacity(by_id.len());

        for (pin_id, positions) in by_id {
            let (first_seq, first_cid) = first_context_by_id
                .get(&pin_id)
                .expect("every grouped pin has a first offer");
            *failure_context = Some((pin_id.clone(), *first_seq, first_cid.clone()));
            let current_head_bytes = match head_table.get(pin_id.as_bytes()).map_err(db_err)? {
                None => None,
                Some(value) => {
                    let bytes = value.value();
                    if bytes.len() > MAX_PIN_HEAD_BYTES {
                        return Err(PinError::Serialization(format!(
                            "pin {pin_id} head exceeds the {MAX_PIN_HEAD_BYTES}-byte limit"
                        )));
                    }
                    Some(bytes.to_vec())
                }
            };

            let mut tail: Option<(u64, Cid, PinEvent)> = match current_head_bytes.as_ref() {
                None => None,
                Some(bytes) => {
                    let head = self.deserialize_head(bytes)?;
                    validate_pin_event_identity(&head.event)?;
                    if head.event.pin_id != pin_id {
                        return Err(PinError::Storage(format!(
                            "pin head key {pin_id:?} contains a head for {:?}",
                            head.event.pin_id
                        )));
                    }
                    let head_key = encode_event_key(&pin_id, head.event.seq);
                    let filed_cid = event_table
                        .get(head_key.as_slice())
                        .map_err(db_err)?
                        .map(|value| Cid::from_bytes(value.value()))
                        .transpose()
                        .map_err(|error| PinError::Storage(error.to_string()))?
                        .ok_or_else(|| {
                            PinError::Storage(format!(
                                "pin {pin_id} head seq {} has no filed event",
                                head.event.seq
                            ))
                        })?;
                    if filed_cid != head.event_cid {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id} head names event {}, but seq {} is filed as {filed_cid}",
                            head.event_cid, head.event.seq
                        )));
                    }
                    let filed_event =
                        self.load_incremental_event(&head.event_cid, &mut event_bytes_read)?;
                    if filed_event != head.event {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id} cached head does not match its filed event {}",
                            head.event_cid
                        )));
                    }

                    let predecessor = if head.event.seq > 1 {
                        let predecessor_key = encode_event_key(&pin_id, head.event.seq - 1);
                        let predecessor_cid = event_table
                            .get(predecessor_key.as_slice())
                            .map_err(db_err)?
                            .map(|value| Cid::from_bytes(value.value()))
                            .transpose()
                            .map_err(|error| PinError::Storage(error.to_string()))?
                            .ok_or_else(|| {
                                PinError::Storage(format!(
                                    "pin {pin_id} head seq {} has no filed predecessor",
                                    head.event.seq
                                ))
                            })?;
                        let event =
                            self.load_incremental_event(&predecessor_cid, &mut event_bytes_read)?;
                        if event.pin_id != pin_id || event.seq != head.event.seq - 1 {
                            return Err(PinError::Storage(format!(
                                "pin {pin_id} predecessor at seq {} describes ({}, seq {})",
                                head.event.seq - 1,
                                event.pin_id,
                                event.seq
                            )));
                        }
                        Some((predecessor_cid, event))
                    } else {
                        None
                    };

                    dag_core::offer_pin_event(
                        &pin_id,
                        head.event.seq,
                        &head.event_cid,
                        &head.event,
                        None,
                        predecessor.as_ref().map(|(cid, _)| cid),
                    )
                    .map_err(pin_offer_err)?;
                    Self::validate_incremental_transition(
                        &pin_id,
                        &head.event_cid,
                        &head.event,
                        predecessor.as_ref().map(|(cid, event)| (cid, event)),
                    )?;
                    if let Some(successor_seq) = head.event.seq.checked_add(1) {
                        let successor_key = encode_event_key(&pin_id, successor_seq);
                        if event_table
                            .get(successor_key.as_slice())
                            .map_err(db_err)?
                            .is_some()
                        {
                            return Err(PinError::Storage(format!(
                                "pin {pin_id} head is stale: seq {successor_seq} is already filed"
                            )));
                        }
                    }
                    Some((head.event.seq, head.event_cid, head.event))
                }
            };

            let mut advanced = false;
            for (seq, event_cid) in positions {
                *failure_context = Some((pin_id.clone(), seq, event_cid.clone()));
                let event = self.load_incremental_event(&event_cid, &mut event_bytes_read)?;
                let key = encode_event_key(&pin_id, seq);
                let existing = event_table
                    .get(key.as_slice())
                    .map_err(db_err)?
                    .map(|value| Cid::from_bytes(value.value()))
                    .transpose()
                    .map_err(|error| PinError::Storage(error.to_string()))?;
                if existing.is_some() {
                    dag_core::offer_pin_event(
                        &pin_id,
                        seq,
                        &event_cid,
                        &event,
                        existing.as_ref(),
                        None,
                    )
                    .map_err(pin_offer_err)?;
                    let tail_seq = tail.as_ref().map(|(seq, _, _)| *seq).unwrap_or(0);
                    if seq > tail_seq {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id} has filed seq {seq} beyond cached head {tail_seq}; run recovery before incremental sync"
                        )));
                    }
                    continue;
                }

                // Historical rows keep identity-only decoding compatibility,
                // but a peer cannot use that exception to introduce a new
                // multi-megabyte author or local-node field into a derived
                // head.
                validate_pin_event_fields(&event)?;

                let expected_seq = match tail.as_ref() {
                    Some((tail_seq, _, _)) => tail_seq.checked_add(1).ok_or_else(|| {
                        PinError::Storage(format!("pin {pin_id} sequence is exhausted"))
                    })?,
                    None => 1,
                };
                if seq != expected_seq {
                    return Err(PinError::InvalidSequence {
                        expected: expected_seq,
                        actual: seq,
                    });
                }
                dag_core::offer_pin_event(
                    &pin_id,
                    seq,
                    &event_cid,
                    &event,
                    None,
                    tail.as_ref().map(|(_, cid, _)| cid),
                )
                .map_err(pin_offer_err)?;
                Self::validate_incremental_transition(
                    &pin_id,
                    &event_cid,
                    &event,
                    tail.as_ref().map(|(_, cid, event)| (cid, event)),
                )?;
                event_inserts.push((key, event_cid.as_bytes().to_vec()));
                tail = Some((seq, event_cid, event));
                advanced = true;
            }

            if advanced {
                let (seq, event_cid, event) = tail.expect("an advanced chain has a tail");
                if let Some(successor_seq) = seq.checked_add(1) {
                    let successor_key = encode_event_key(&pin_id, successor_seq);
                    if event_table
                        .get(successor_key.as_slice())
                        .map_err(db_err)?
                        .is_some()
                    {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id} would leave already-filed seq {successor_seq} beyond its new head"
                        )));
                    }
                }
                let head = PinHead {
                    event: event.clone(),
                    event_cid,
                };
                head_updates.push(PinRowUpdate {
                    key: pin_id.as_bytes().to_vec(),
                    expected: current_head_bytes,
                    value: self.serialize_head(&head)?,
                });
                reverse_additions
                    .entry(target_to_key(&event.target))
                    .or_default()
                    .insert(pin_id.clone());
                if event.state == PinState::Active {
                    retention_roots.push(PinRetentionRoot {
                        target: event.target,
                        scope: event.scope,
                        expires_at: event.expires_at,
                    });
                }
            } else if let Some((_, _, event)) = tail.as_ref() {
                // Reverse lookup is derived data, so an idempotent offer is a
                // bounded opportunity to repair its one affected membership.
                // This is especially important for deactivated pins: they are
                // historical lookup results even though they are not roots.
                reverse_additions
                    .entry(target_to_key(&event.target))
                    .or_default()
                    .insert(pin_id);
            }
        }

        let mut reverse_bytes_read = 0usize;
        let mut reverse_updates = Vec::with_capacity(reverse_additions.len());
        for (target_key, additions) in reverse_additions {
            let pin_id = additions
                .first()
                .expect("a reverse-index addition set is non-empty");
            let (seq, cid) = first_context_by_id
                .get(pin_id)
                .expect("every affected reverse row belongs to an offered pin");
            *failure_context = Some((pin_id.clone(), *seq, cid.clone()));
            let current = match reverse_table.get(target_key.as_slice()).map_err(db_err)? {
                None => None,
                Some(value) => {
                    let bytes = value.value();
                    if bytes.len() > MAX_PIN_BY_TARGET_ROW_BYTES {
                        return Err(PinError::Serialization(format!(
                            "pin reverse row is {} bytes, above the {MAX_PIN_BY_TARGET_ROW_BYTES}-byte limit",
                            bytes.len()
                        )));
                    }
                    reverse_bytes_read =
                        reverse_bytes_read.checked_add(bytes.len()).ok_or_else(|| {
                            PinError::Storage("pin reverse-byte accounting overflow".into())
                        })?;
                    if reverse_bytes_read > MAX_INCREMENTAL_PIN_REVERSE_BYTES {
                        return Err(PinError::Storage(format!(
                            "incremental pin validation exceeds the {MAX_INCREMENTAL_PIN_REVERSE_BYTES}-byte reverse-index read budget"
                        )));
                    }
                    Some(bytes.to_vec())
                }
            };
            let existing = current
                .as_ref()
                .map(|bytes| self.deserialize_pin_ids(bytes))
                .transpose()?
                .unwrap_or_default();
            let mut ids: BTreeSet<String> = existing.into_iter().collect();
            if additions.is_subset(&ids) {
                continue;
            }
            ids.extend(additions);
            let ids: Vec<String> = ids.into_iter().collect();
            reverse_updates.push(PinRowUpdate {
                key: target_key,
                expected: current,
                value: self.serialize_pin_ids(&ids)?,
            });
        }
        retention_roots.sort_by_key(|root| target_to_key(&root.target));

        Ok(PinIncrementalSyncPlan {
            event_inserts,
            head_updates,
            reverse_updates,
            retention_roots,
        })
    }

    /// Validate only active, unexpired roots newly exposed by this plan.
    #[cfg(test)]
    fn validate_incremental_sync_plan(
        &self,
        plan: &PinIncrementalSyncPlan,
    ) -> Result<(), PinError> {
        let now = crate::now_unix();
        let roots = plan
            .retention_roots()
            .iter()
            .filter(|root| root.is_unexpired(now))
            .map(|root| match &root.target {
                PinTarget::Direct(cid) => (cid.clone(), crate::reference::ReferenceDepth::Named),
                PinTarget::Subtree { root, max_depth } => (
                    root.clone(),
                    max_depth.map_or(
                        crate::reference::ReferenceDepth::Unlimited,
                        crate::reference::ReferenceDepth::Descendants,
                    ),
                ),
            });
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            roots,
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map(|_| ())
        .map_err(|error| {
            PinError::Storage(format!(
                "refusing to publish incremental pin heads: {error}"
            ))
        })
    }

    /// Apply an incremental plan in a caller-owned cross-log transaction.
    /// The caller must abort that transaction on any error and bump sync
    /// generation once if either log inserted at least one event.
    pub(crate) fn apply_incremental_sync_plan(
        &self,
        txn: &WriteTransaction,
        plan: &PinIncrementalSyncPlan,
    ) -> Result<(), PinError> {
        {
            let events = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            for (key, _) in &plan.event_inserts {
                if events.get(key.as_slice()).map_err(db_err)?.is_some() {
                    return Err(PinError::Storage(
                        "pin incremental plan became stale before event publication".into(),
                    ));
                }
            }
        }
        {
            let heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
            for update in &plan.head_updates {
                let current = heads.get(update.key.as_slice()).map_err(db_err)?;
                if current.as_ref().map(|value| value.value()) != update.expected.as_deref() {
                    return Err(PinError::Storage(
                        "pin incremental plan became stale before head publication".into(),
                    ));
                }
            }
        }
        {
            let reverse = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;
            for update in &plan.reverse_updates {
                let current = reverse.get(update.key.as_slice()).map_err(db_err)?;
                if current.as_ref().map(|value| value.value()) != update.expected.as_deref() {
                    return Err(PinError::Storage(
                        "pin incremental plan became stale before reverse-index publication".into(),
                    ));
                }
            }
        }
        {
            let mut events = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            for (key, cid) in &plan.event_inserts {
                events
                    .insert(key.as_slice(), cid.as_slice())
                    .map_err(db_err)?;
            }
        }
        {
            let mut heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
            for update in &plan.head_updates {
                heads
                    .insert(update.key.as_slice(), update.value.as_slice())
                    .map_err(db_err)?;
            }
        }
        {
            let mut reverse = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;
            for update in &plan.reverse_updates {
                reverse
                    .insert(update.key.as_slice(), update.value.as_slice())
                    .map_err(db_err)?;
            }
        }
        Ok(())
    }

    /// Create a new PinLog over the shared control-plane database.
    pub fn new(store: Arc<S>, db: Arc<Database>) -> Result<Self, PinError> {
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(PIN_HEADS).map_err(db_err)?;
        txn.open_table(PIN_EVENTS).map_err(db_err)?;
        txn.open_table(PIN_BY_TARGET).map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        crate::sync_generation::initialize(&db).map_err(db_err)?;

        Ok(PinLog {
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

    /// Change the ceiling used to validate a new pin's promised closure.
    pub(crate) fn set_max_reference_expansion(&self, max_expansion: usize) {
        self.max_reference_expansion
            .store(max_expansion, Ordering::Relaxed);
    }

    /// Validate exactly what `target` promises before its event is published.
    /// Direct non-file pins name one CID; subtree pins include descendants to
    /// their configured depth. The caller owns the shared mutation gate.
    fn validate_new_target(&self, target: &PinTarget) -> Result<(), PinError> {
        let (root, depth) = match target {
            PinTarget::Direct(cid) => (cid.clone(), crate::reference::ReferenceDepth::Named),
            PinTarget::Subtree { root, max_depth } => (
                root.clone(),
                max_depth.map_or(
                    crate::reference::ReferenceDepth::Unlimited,
                    crate::reference::ReferenceDepth::Descendants,
                ),
            ),
        };
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            [(root.clone(), depth)],
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map(|_| ())
        .map_err(|error| {
            PinError::Storage(format!("refusing to publish pin target {root}: {error}"))
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

    fn head_bytes(&self, pin_id: &str) -> Result<Option<Vec<u8>>, PinError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_HEADS).map_err(db_err)?;
        let Some(value) = table.get(pin_id.as_bytes()).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > MAX_PIN_HEAD_BYTES {
            return Err(PinError::Serialization(format!(
                "pin {pin_id} head exceeds the {MAX_PIN_HEAD_BYTES}-byte limit"
            )));
        }
        Ok(Some(value.value().to_vec()))
    }

    /// Whether `cid` names a `file/v1` manifest — content whose CID is the
    /// name of a *file* rather than of the bytes it addresses.
    ///
    /// Absent or unreadable answers `false`, so the pin stays direct and
    /// protects exactly what it names. Erring the other way would let one bad
    /// read silently widen a pin into a walk of whatever the bytes decoded as.
    fn names_a_file(&self, cid: &Cid) -> bool {
        self.store
            .get_chunk(cid)
            .ok()
            .and_then(|bytes| dag_core::file::info_from_bytes(&bytes))
            .is_some()
    }

    fn canonical_target(&self, target: PinTarget) -> PinTarget {
        match target {
            PinTarget::Direct(cid) if self.names_a_file(&cid) => PinTarget::Subtree {
                root: cid,
                max_depth: None,
            },
            other => other,
        }
    }

    fn verify_ensured_pin(
        &self,
        pin_id: &str,
        head: &PinHead,
        target: &PinTarget,
        scope: &PinScope,
        required_expiry: Option<i64>,
        now: i64,
    ) -> crate::error::Result<()> {
        if head.event.target != *target || head.event.scope != *scope {
            return Err(crate::ControlError::Invalid(format!(
                "pin {pin_id} already exists with a different target or scope"
            )));
        }
        if !head.is_providing_retention(now) {
            return Err(crate::ControlError::Invalid(format!(
                "pin {pin_id} already exists but is deactivated or expired"
            )));
        }
        let sufficient_expiry = match (required_expiry, head.event.expires_at) {
            (None, None) | (Some(_), None) => true,
            (Some(required), Some(actual)) => actual >= required,
            (None, Some(_)) => false,
        };
        if !sufficient_expiry {
            return Err(crate::ControlError::Invalid(format!(
                "pin {pin_id} already exists but expires before the requested retention period"
            )));
        }
        Ok(())
    }

    /// Create a new pin with the given parameters.
    ///
    /// The TTL is converted to an absolute expiry timestamp at creation time.
    pub fn create(
        &self,
        pin_id: &str,
        target: PinTarget,
        scope: PinScope,
        expires_at: Option<i64>,
        author: Option<String>,
    ) -> Result<(), PinError> {
        validate_pin_id(pin_id)?;
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());

        // Avoid a potentially large closure walk when the stable API answer is
        // already `PinAlreadyExists`; the writer-locked check remains the
        // definitive race gate below.
        if self.head_bytes(pin_id)?.is_some() {
            return Err(PinError::PinAlreadyExists(pin_id.to_string()));
        }

        // A direct pin on a `file/v1` manifest is recorded as a subtree pin,
        // because that is what the operator asked for.
        //
        // `dag put` chunks anything over 4 MiB and hands back the manifest
        // CID without saying so — that CID *is* the file's only name. Pinning
        // it directly retained the list of parts while collection took the
        // parts, so `dag pin list` showed a retained artefact that was gone.
        // Job output pins are direct too, and `store_auto` chunks a large
        // output, so this was reachable without anyone typing a pin command.
        //
        // Decided here rather than during retention expansion: the snapshot is
        // rebuilt on a timer and would otherwise re-read every directly-pinned
        // chunk each time. Deciding once, at creation, also means the stored
        // event says `Subtree` — `pin info` shows what the pin actually does.
        //
        // A missing or unreadable target falls through as Direct here, then
        // the validation immediately below refuses it. No root is published
        // on the strength of this format probe alone.
        let target = self.canonical_target(target);

        // Validate and register everything this pin promises. A collection
        // that won the exclusive mutation gate first may have removed an old
        // descendant; that must make pin creation fail, never create a dangling
        // retention root.
        self.validate_new_target(&target)?;

        let now = crate::now_unix();

        let event = PinEvent {
            seq: 1,
            pin_id: pin_id.to_string(),
            target: target.clone(),
            scope,
            expires_at,
            state: PinState::Active,
            ts: now,
            author,
            // Nothing precedes a create. `prev: None` is skipped on the wire,
            // so this event encodes exactly as it did before the field existed.
            prev: None,
        };

        // Store the event in the content store before opening the write
        // transaction: put_entry commits its own index transaction on the
        // same database, and write transactions must never nest.
        let entry = Entry::with_payload(self.serialize_event(&event)?);
        let event_cid = self
            .store
            .put_entry(&entry)
            .map_err(|e| PinError::Storage(format!("Failed to store pin event: {}", e)))?;

        // Content is complete before the log mutex is acquired, preserving
        // mutation -> durability -> log -> redb. The recheck below is the
        // definitive race gate against another creator.
        let guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.head_bytes(pin_id)?.is_some() {
            return Err(PinError::PinAlreadyExists(pin_id.to_string()));
        }

        let pin_head = PinHead {
            event: event.clone(),
            event_cid: event_cid.clone(),
        };
        let head_bytes = self.serialize_head(&pin_head)?;
        let event_key = encode_event_key(pin_id, 1);
        let target_key = target_to_key(&target);

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut events = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            let existing = events
                .get(event_key.as_slice())
                .map_err(db_err)?
                .map(|value| value.value().to_vec());
            if existing
                .as_deref()
                .is_some_and(|cid| cid != event_cid.as_bytes())
            {
                return Err(PinError::PinAlreadyExists(format!(
                    "{pin_id} seq 1 was filed concurrently with a different event"
                )));
            }
            events
                .insert(event_key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;

            let mut heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
            heads
                .insert(pin_id.as_bytes(), head_bytes.as_slice())
                .map_err(db_err)?;

            // Update the reverse lookup by target.
            let mut by_target = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;
            let mut pin_ids: Vec<String> =
                match by_target.get(target_key.as_slice()).map_err(db_err)? {
                    Some(bytes) => self.deserialize_pin_ids(bytes.value())?,
                    None => Vec::new(),
                };
            if !pin_ids.iter().any(|existing| existing == pin_id) {
                pin_ids.push(pin_id.to_string());
            }
            let pin_ids_bytes = self.serialize_pin_ids(&pin_ids)?;
            by_target
                .insert(target_key.as_slice(), pin_ids_bytes.as_slice())
                .map_err(db_err)?;
            crate::sync_generation::bump(&txn).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        if let Some(ref bus) = self.event_bus {
            bus.emit(crate::events::Event::PinEvent {
                id: pin_id.to_string(),
                action: "created".to_string(),
                ts: now,
            });
        }

        Ok(())
    }

    /// Deactivate a pin, preventing it from providing retention.
    ///
    /// Deactivation is modeled as a new event on the same pin_id. Deactivating
    /// an already-deactivated pin is a no-op.
    pub fn deactivate(&self, pin_id: &str, author: Option<String>) -> Result<(), PinError> {
        validate_pin_id(pin_id)?;
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());

        let current_head: PinHead = self.deserialize_head(
            &self
                .head_bytes(pin_id)?
                .ok_or_else(|| PinError::PinNotFound(pin_id.to_string()))?,
        )?;

        if matches!(current_head.event.state, PinState::Deactivated) {
            return Ok(()); // Already deactivated, no-op
        }

        let now = crate::now_unix();

        let next_seq = current_head.event.seq.checked_add(1).ok_or_else(|| {
            PinError::Storage(format!("pin {pin_id} sequence is already u64::MAX"))
        })?;

        let event = PinEvent {
            seq: next_seq,
            pin_id: pin_id.to_string(),
            target: current_head.event.target.clone(),
            scope: current_head.event.scope.clone(),
            expires_at: current_head.event.expires_at,
            state: PinState::Deactivated,
            ts: now,
            author,
            // Names the event this one follows, so a replica can tell an
            // honest continuation of *this* chain from a graft onto it.
            prev: Some(current_head.event_cid.clone()),
        };

        // Content-store write first; see create().
        let entry = Entry::with_payload(self.serialize_event(&event)?);
        let event_cid = self
            .store
            .put_entry(&entry)
            .map_err(|e| PinError::Storage(format!("Failed to store pin event: {}", e)))?;

        let guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let committed_head: PinHead = self.deserialize_head(
            &self
                .head_bytes(pin_id)?
                .ok_or_else(|| PinError::PinNotFound(pin_id.to_string()))?,
        )?;
        if committed_head != current_head {
            if matches!(committed_head.event.state, PinState::Deactivated) {
                return Ok(());
            }
            return Err(PinError::Storage(format!(
                "pin {pin_id} changed while deactivation was being prepared"
            )));
        }

        let new_head = PinHead {
            event,
            event_cid: event_cid.clone(),
        };
        let head_bytes = self.serialize_head(&new_head)?;
        let event_key = encode_event_key(pin_id, next_seq);

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut events = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            let existing = events
                .get(event_key.as_slice())
                .map_err(db_err)?
                .map(|value| value.value().to_vec());
            if existing
                .as_deref()
                .is_some_and(|cid| cid != event_cid.as_bytes())
            {
                return Err(PinError::PinAlreadyExists(format!(
                    "{pin_id} seq {next_seq} was filed concurrently with a different event"
                )));
            }
            events
                .insert(event_key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;
            let mut heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
            heads
                .insert(pin_id.as_bytes(), head_bytes.as_slice())
                .map_err(db_err)?;
            crate::sync_generation::bump(&txn).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        if let Some(ref bus) = self.event_bus {
            bus.emit(crate::events::Event::PinEvent {
                id: pin_id.to_string(),
                action: "deactivated".to_string(),
                ts: now,
            });
        }

        Ok(())
    }

    /// Get the current head (latest state) of a pin.
    pub fn head(&self, pin_id: &str) -> Result<PinHead, PinError> {
        let head_bytes = self
            .head_bytes(pin_id)?
            .ok_or_else(|| PinError::PinNotFound(pin_id.to_string()))?;
        self.deserialize_head(&head_bytes)
    }

    /// Get the history of a pin within the given sequence range.
    pub fn history(&self, pin_id: &str, range: Range<u64>) -> Result<Vec<PinEvent>, PinError> {
        if range.start >= range.end {
            return Err(PinError::InvalidSequence {
                expected: range.end,
                actual: range.start,
            });
        }

        let start_key = encode_event_key(pin_id, range.start);
        let end_key = encode_event_key(pin_id, range.end);
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_EVENTS).map_err(db_err)?;

        let mut events = Vec::new();
        for item in table
            .range(start_key.as_slice()..end_key.as_slice())
            .map_err(db_err)?
        {
            let (key_guard, cid_guard) = item.map_err(db_err)?;

            if let Some((decoded_pin_id, _seq)) = decode_event_key(key_guard.value()) {
                if decoded_pin_id != pin_id {
                    break;
                }

                let cid = Cid::from_bytes(cid_guard.value())
                    .map_err(|e| PinError::Storage(e.to_string()))?;
                let entry = self
                    .store
                    .get_entry(&cid)
                    .map_err(|e| PinError::Storage(format!("Failed to get pin event: {}", e)))?;

                let event: PinEvent = self.deserialize_event(&entry.payload)?;
                events.push(event);
            }
        }

        Ok(events)
    }

    /// List all pin IDs.
    pub fn list(&self) -> Result<Vec<String>, PinError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_HEADS).map_err(db_err)?;

        let mut pins = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key, _) = item.map_err(db_err)?;
            let pin_id = std::str::from_utf8(key.value())
                .map_err(|e| PinError::Storage(format!("Invalid UTF-8 in pin ID: {}", e)))?;
            pins.push(pin_id.to_string());
        }

        pins.sort();
        Ok(pins)
    }

    /// Count all heads and currently-retaining heads without materializing the
    /// pin namespace. Every row is decoded; corrupt derived state is an error,
    /// never silently counted as inactive.
    pub fn head_counts(&self, now: i64) -> Result<(usize, usize), PinError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_HEADS).map_err(db_err)?;
        let mut total = 0usize;
        let mut active = 0usize;
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key, value) = item.map_err(db_err)?;
            let pin_id = std::str::from_utf8(key.value())
                .map_err(|error| PinError::Storage(format!("invalid pin head key: {error}")))?;
            validate_pin_id(pin_id)?;
            let head = self.deserialize_head(value.value())?;
            if head.event.pin_id != pin_id {
                return Err(PinError::Storage(format!(
                    "pin head key {pin_id:?} contains a head for {:?}",
                    head.event.pin_id
                )));
            }
            total = total
                .checked_add(1)
                .ok_or_else(|| PinError::Storage("pin head count overflow".into()))?;
            if head.is_providing_retention(now) {
                active = active
                    .checked_add(1)
                    .ok_or_else(|| PinError::Storage("active pin count overflow".into()))?;
            }
        }
        Ok((total, active))
    }

    /// List a bounded lexicographic page of pin IDs strictly after `after`.
    pub fn list_page(&self, after: Option<&str>, limit: usize) -> Result<Vec<String>, PinError> {
        use std::ops::Bound::{Excluded, Unbounded};

        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_HEADS).map_err(db_err)?;
        let range = (
            after.map_or(Unbounded, |id| Excluded(id.as_bytes())),
            Unbounded,
        );
        let mut pins = Vec::with_capacity(limit);
        for item in table.range::<&[u8]>(range).map_err(db_err)?.take(limit) {
            let (key, _) = item.map_err(db_err)?;
            let pin_id = std::str::from_utf8(key.value())
                .map_err(|e| PinError::Storage(format!("Invalid UTF-8 in pin ID: {}", e)))?;
            pins.push(pin_id.to_string());
        }
        Ok(pins)
    }

    /// Every `(pin_id, seq, event_cid)` in the log, ordered by key.
    ///
    /// The replication counterpart of [`Self::history`]: it yields event
    /// addresses without reading the content store, because a replica copies
    /// the event chunks themselves rather than re-creating them. See ADR-002.
    pub fn event_cids(&self) -> Result<Vec<(String, u64, Cid)>, PinError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_EVENTS).map_err(db_err)?;

        let mut out = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key_guard, cid_guard) = item.map_err(db_err)?;
            if let Some((pin_id, seq)) = decode_event_key(key_guard.value()) {
                out.push((
                    pin_id.into_owned(),
                    seq,
                    Cid::from_bytes(cid_guard.value())
                        .map_err(|e| PinError::Storage(e.to_string()))?,
                ));
            }
        }
        Ok(out)
    }

    /// Bounded event-history page in the table's stable encoded-key order.
    pub fn event_cids_page(
        &self,
        after: Option<(&str, u64)>,
        limit: usize,
    ) -> Result<Vec<(String, u64, Cid)>, PinError> {
        use std::ops::Bound::{Excluded, Unbounded};

        let after_key = after.map(|(id, seq)| encode_event_key(id, seq));
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_EVENTS).map_err(db_err)?;
        let range = match after_key.as_deref() {
            Some(key) => table.range::<&[u8]>((Excluded(key), Unbounded)),
            None => table.range::<&[u8]>(..),
        }
        .map_err(db_err)?;
        let mut out = Vec::with_capacity(limit.min(4096));
        for item in range.take(limit) {
            let (key, value) = item.map_err(db_err)?;
            let (id, seq) = decode_event_key(key.value())
                .ok_or_else(|| PinError::Storage("invalid pin event key".to_string()))?;
            let cid = Cid::from_bytes(value.value())
                .map_err(|error| PinError::Storage(error.to_string()))?;
            out.push((id.into_owned(), seq, cid));
        }
        Ok(out)
    }

    /// Return the event CID currently filed at `(pin_id, seq)`.
    ///
    /// Replication dry-runs use this read-only lookup to identify divergent
    /// history without importing the offered event or rebuilding pin heads.
    pub fn event_cid(&self, pin_id: &str, seq: u64) -> Result<Option<Cid>, PinError> {
        dag_core::validate_pin_id(pin_id)?;
        let key = encode_event_key(pin_id, seq);
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_EVENTS).map_err(db_err)?;
        table
            .get(key.as_slice())
            .map_err(db_err)?
            .map(|guard| {
                Cid::from_bytes(guard.value()).map_err(|e| PinError::Storage(e.to_string()))
            })
            .transpose()
    }

    /// File a pin event that already exists in the content store under
    /// `(pin_id, seq)`.
    ///
    /// The pin counterpart of [`crate::PointerLog::import_event`], and the
    /// same reasoning applies: [`Self::create`] and [`Self::deactivate`] stamp
    /// the local clock, so replaying through them would change every event's
    /// CID.
    ///
    /// Everything is checked before anything is written:
    ///
    /// - the entry must already be in the local store and decode as a
    ///   [`PinEvent`];
    /// - the event's own `pin_id` and `seq` must match the key it is being
    ///   filed under, so a caller cannot graft one pin's event onto another;
    /// - `seq == 1` must carry no `prev`, and **seq N is refused unless seq
    ///   N-1 is already filed locally**. Refusing to file at an arbitrary
    ///   sequence is what stops a remote injecting into a chain it has never
    ///   seen;
    /// - **seq > 1 must carry a `prev`, naming the event already filed at
    ///   `seq - 1`.** Divergence is refused, never overwritten;
    /// - an existing mapping at this position must already name the same CID.
    ///
    /// Before these gates existed, a hostile remote could offer a seq-2
    /// deactivation for a pin name the destination was using, and sync would
    /// file it, switch the local pin off and unprotect its content —
    /// reporting zero failures.
    ///
    /// The `prev` requirement is unconditional rather than "checked when
    /// present", which is the rule [`crate::PointerLog::import_event`] has
    /// always applied. Contiguity alone does not close the hole: a chain that
    /// is *longer* than the local one can still be grafted onto its end, and
    /// an event that simply omits `prev` would sail through. The cost is that
    /// a deactivation written before [`dag_core::PinEvent::prev`] existed
    /// cannot replicate; it is refused by name and by sequence, in the sync
    /// report, and the destination keeps the pin at seq 1 — over-retention,
    /// which is the safe direction (R6).
    ///
    /// What this does *not* provide is authentication. An attacker who has
    /// already replicated from us knows our head event's CID and can build an
    /// event that satisfies every rule here. The gates raise the bar to
    /// "must have seen this history", not "is authorised to extend it"; pin
    /// logs are unsigned, exactly as ADR-002 leaves pointer logs.
    ///
    /// Returns `true` if a new mapping was written, `false` if this exact
    /// event was already filed.
    pub fn import_event(&self, pin_id: &str, seq: u64, event_cid: &Cid) -> Result<bool, PinError> {
        dag_core::validate_pin_id(pin_id)?;
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());

        let entry = self
            .store
            .get_entry(event_cid)
            .map_err(|e| PinError::Storage(e.to_string()))?;
        let event: PinEvent = self.deserialize_event(&entry.payload)?;

        let key = encode_event_key(pin_id, seq);

        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Chain validation reads the neighbouring positions first, outside the
        // write transaction. The judgement is `offer_pin_event` — the same
        // function the Edge replica uses (ADR-007).
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            let existing = table
                .get(key.as_slice())
                .map_err(db_err)?
                .map(|g| Cid::from_bytes(g.value()))
                .transpose()
                .map_err(|e| PinError::Storage(e.to_string()))?;

            let predecessor_cid = if seq > 1 && existing.is_none() {
                let prev_key = encode_event_key(pin_id, seq - 1);
                table
                    .get(prev_key.as_slice())
                    .map_err(db_err)?
                    .map(|g| Cid::from_bytes(g.value()))
                    .transpose()
                    .map_err(|e| PinError::Storage(e.to_string()))?
            } else {
                None
            };

            match dag_core::offer_pin_event(
                pin_id,
                seq,
                event_cid,
                &event,
                existing.as_ref(),
                predecessor_cid.as_ref(),
            ) {
                Ok(dag_core::OfferOutcome::AlreadyFiled) => return Ok(false),
                Ok(dag_core::OfferOutcome::Accept) => {}
                Err(e) => return Err(pin_offer_err(e)),
            }
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            table
                .insert(key.as_slice(), event_cid.as_bytes())
                .map_err(db_err)?;
            crate::sync_generation::bump(&txn).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        Ok(true)
    }

    /// List pins targeting a specific CID.
    pub fn list_by_target(&self, target: &PinTarget) -> Result<Vec<String>, PinError> {
        let target_key = target_to_key(target);
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;

        let pin_ids = table
            .get(target_key.as_slice())
            .map_err(db_err)?
            .map(|g| self.deserialize_pin_ids(g.value()))
            .transpose()?
            .unwrap_or_default();

        Ok(pin_ids)
    }

    /// Rebuild the pin heads from the event log.
    ///
    /// This operation validates the entire event log and rebuilds the heads
    /// from scratch. It's used for recovery and integrity verification.
    pub fn rebuild(&self, dry_run: bool) -> Result<PinRebuildReport, PinError> {
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let plan = self.prepare_rebuild_plan()?;
        self.validate_rebuild_plan(&plan)?;
        if dry_run {
            return Ok(plan.report(false));
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        self.apply_rebuild_plan(&txn, &plan)?;
        txn.commit().map_err(db_err)?;
        Ok(plan.report(true))
    }

    /// Validate all filed pin events and prepare encoded replacement rows.
    ///
    /// This is intentionally read-only. In particular, it preserves the CID
    /// filed in `pin_events`; reserializing a schema-1 payload under the current
    /// schema would silently give the same logical event a different address.
    pub(crate) fn prepare_rebuild_plan(&self) -> Result<PinRebuildPlan, PinError> {
        let mut positions = Vec::new();
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            for item in table.range::<&[u8]>(..).map_err(db_err)? {
                let (key_guard, cid_guard) = item.map_err(db_err)?;
                let (pin_id, seq) = decode_event_key(key_guard.value())
                    .ok_or_else(|| PinError::Storage("malformed key in pin_events".into()))?;
                validate_pin_id(pin_id.as_ref())?;
                let cid = Cid::from_bytes(cid_guard.value())
                    .map_err(|e| PinError::Storage(e.to_string()))?;
                positions.push((pin_id.into_owned(), seq, cid));
            }
        }
        self.prepare_rebuild_plan_from_positions(&positions)
    }

    /// Prepare pin-derived tables from the complete prospective event mapping.
    pub(crate) fn prepare_rebuild_plan_from_positions(
        &self,
        positions: &[(String, u64, Cid)],
    ) -> Result<PinRebuildPlan, PinError> {
        use std::collections::HashMap;

        let mut pin_chains: HashMap<String, PinChain> = HashMap::new();
        for (pin_id, seq, cid) in positions {
            validate_pin_id(pin_id)?;
            let entry = self
                .store
                .get_entry(cid)
                .map_err(|e| PinError::Storage(format!("Failed to get pin event {cid}: {e}")))?;
            let event: PinEvent = self.deserialize_event(&entry.payload)?;
            if event.pin_id != *pin_id || event.seq != *seq {
                return Err(PinError::Storage(format!(
                    "pin event {cid} is filed as ({pin_id}, seq {seq}) but describes ({}, seq {})",
                    event.pin_id, event.seq
                )));
            }
            pin_chains
                .entry(pin_id.clone())
                .or_default()
                .push((*seq, cid.clone(), event));
        }

        let pins_processed = pin_chains.len() as u32;
        let mut heads = Vec::with_capacity(pin_chains.len());
        let mut targets: HashMap<Vec<u8>, Vec<String>> = HashMap::new();
        let mut retention_roots = Vec::new();
        for (pin_id, mut events) in pin_chains {
            events.sort_by_key(|(seq, _, _)| *seq);
            let mut previous: Option<(&Cid, &PinEvent)> = None;
            for (expected_seq, (seq, event_cid, event)) in (1u64..).zip(events.iter()) {
                if *seq != expected_seq {
                    return Err(PinError::InvalidSequence {
                        expected: expected_seq,
                        actual: *seq,
                    });
                }
                if expected_seq == 1 {
                    if event.prev.is_some() || event.state != PinState::Active {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id}: seq 1 must be an active create without prev"
                        )));
                    }
                } else {
                    let (previous_cid, previous_event) =
                        previous.expect("seq greater than one has a predecessor");
                    if event.prev.as_ref() != Some(previous_cid) {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id}: seq {seq} does not name filed predecessor {previous_cid}"
                        )));
                    }
                    if event.target != previous_event.target
                        || event.scope != previous_event.scope
                        || event.expires_at != previous_event.expires_at
                    {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id}: seq {seq} changes immutable retention policy"
                        )));
                    }
                    if previous_event.state != PinState::Active
                        || event.state != PinState::Deactivated
                    {
                        return Err(PinError::Storage(format!(
                            "pin {pin_id}: seq {seq} is not an active-to-deactivated transition"
                        )));
                    }
                }
                previous = Some((event_cid, event));
            }

            let (_, event_cid, event) = events.last().expect("grouped chain is non-empty");
            let head = PinHead {
                event: event.clone(),
                event_cid: event_cid.clone(),
            };
            heads.push((pin_id.as_bytes().to_vec(), self.serialize_head(&head)?));
            if event.state == PinState::Active {
                retention_roots.push(PinRetentionRoot {
                    target: event.target.clone(),
                    scope: event.scope.clone(),
                    expires_at: event.expires_at,
                });
            }
            targets
                .entry(target_to_key(&event.target))
                .or_default()
                .push(pin_id);
        }

        heads.sort_by(|a, b| a.0.cmp(&b.0));
        let mut by_target = Vec::with_capacity(targets.len());
        for (target, mut ids) in targets {
            ids.sort();
            ids.dedup();
            by_target.push((target, self.serialize_pin_ids(&ids)?));
        }
        by_target.sort_by(|a, b| a.0.cmp(&b.0));
        retention_roots.sort_by_key(|root| target_to_key(&root.target));

        Ok(PinRebuildPlan {
            heads,
            by_target,
            retention_roots,
            pins_processed,
            events_processed: positions.len() as u32,
        })
    }

    /// Validate every active retention target this plan would make visible.
    /// The caller holds the mutation gate exclusively through publication.
    pub(crate) fn validate_rebuild_plan(&self, plan: &PinRebuildPlan) -> Result<(), PinError> {
        let now = crate::now_unix();
        let roots = plan
            .retention_roots()
            .iter()
            .filter(|root| root.is_unexpired(now))
            .map(|root| match &root.target {
                PinTarget::Direct(cid) => (cid.clone(), crate::reference::ReferenceDepth::Named),
                PinTarget::Subtree { root, max_depth } => (
                    root.clone(),
                    max_depth.map_or(
                        crate::reference::ReferenceDepth::Unlimited,
                        crate::reference::ReferenceDepth::Descendants,
                    ),
                ),
            });
        crate::reference::validate_and_note_references(
            self.store.as_ref(),
            roots,
            self.max_reference_expansion.load(Ordering::Relaxed),
        )
        .map(|_| ())
        .map_err(|error| PinError::Storage(format!("refusing to rebuild pin heads: {error}")))
    }

    /// Replace pin heads and the reverse target index inside a caller-owned
    /// transaction. The clear removes stale rows absent from authoritative
    /// history.
    pub(crate) fn apply_rebuild_plan(
        &self,
        txn: &WriteTransaction,
        plan: &PinRebuildPlan,
    ) -> Result<(), PinError> {
        {
            let mut heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
            heads.retain(|_, _| false).map_err(db_err)?;
            for (pin_id, bytes) in &plan.heads {
                heads
                    .insert(pin_id.as_slice(), bytes.as_slice())
                    .map_err(db_err)?;
            }
        }
        {
            let mut by_target = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;
            by_target.retain(|_, _| false).map_err(db_err)?;
            for (target, bytes) in &plan.by_target {
                by_target
                    .insert(target.as_slice(), bytes.as_slice())
                    .map_err(db_err)?;
            }
        }
        Ok(())
    }

    /// Serialize a pin event to bytes using CBOR
    fn serialize_event(&self, event: &PinEvent) -> Result<Vec<u8>, PinError> {
        validate_pin_event_fields(event)?;
        let mut buf = Vec::new();
        ciborium::ser::into_writer(event, &mut buf)
            .map_err(|e| PinError::Serialization(format!("Failed to serialize event: {}", e)))?;
        Ok(buf)
    }

    /// Deserialize a pin event from CBOR bytes
    fn deserialize_event(&self, bytes: &[u8]) -> Result<PinEvent, PinError> {
        decode_pin_event(bytes)
    }

    /// Serialize a pin head to bytes using CBOR
    fn serialize_head(&self, head: &PinHead) -> Result<Vec<u8>, PinError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(head, &mut buf)
            .map_err(|e| PinError::Serialization(format!("Failed to serialize head: {}", e)))?;
        Ok(buf)
    }

    /// Deserialize a pin head from CBOR bytes
    fn deserialize_head(&self, bytes: &[u8]) -> Result<PinHead, PinError> {
        if bytes.len() > MAX_PIN_HEAD_BYTES {
            return Err(PinError::Serialization(format!(
                "pin head exceeds the {MAX_PIN_HEAD_BYTES}-byte limit"
            )));
        }
        dag_core::decode_cbor_exact(bytes)
            .map_err(|e| PinError::Serialization(format!("Failed to deserialize head: {}", e)))
    }

    /// Serialize pin IDs list to bytes using CBOR
    fn serialize_pin_ids(&self, pin_ids: &[String]) -> Result<Vec<u8>, PinError> {
        if pin_ids.len() > MAX_PIN_IDS_PER_TARGET {
            return Err(PinError::Serialization(format!(
                "pin target has {} IDs, above the {MAX_PIN_IDS_PER_TARGET}-ID limit",
                pin_ids.len()
            )));
        }
        for pin_id in pin_ids {
            validate_pin_id(pin_id)?;
        }
        let mut buf = Vec::new();
        ciborium::ser::into_writer(pin_ids, &mut buf)
            .map_err(|e| PinError::Serialization(format!("Failed to serialize pin IDs: {}", e)))?;
        if buf.len() > MAX_PIN_BY_TARGET_ROW_BYTES {
            return Err(PinError::Serialization(format!(
                "pin reverse row is {} bytes, above the {MAX_PIN_BY_TARGET_ROW_BYTES}-byte limit",
                buf.len()
            )));
        }
        Ok(buf)
    }

    /// Deserialize pin IDs list from CBOR bytes
    fn deserialize_pin_ids(&self, bytes: &[u8]) -> Result<Vec<String>, PinError> {
        if bytes.len() > MAX_PIN_BY_TARGET_ROW_BYTES {
            return Err(PinError::Serialization(format!(
                "pin reverse row is {} bytes, above the {MAX_PIN_BY_TARGET_ROW_BYTES}-byte limit",
                bytes.len()
            )));
        }
        let BoundedPinIds(ids) = dag_core::decode_cbor_exact(bytes)
            .map_err(|e| PinError::Serialization(format!("Failed to deserialize pin IDs: {e}")))?;
        Ok(ids)
    }
}

/// Recovery that does not depend on the control database existing.
///
/// [`PinLog::rebuild`] reads the `pin_events` table to learn which CIDs the
/// events are, so it recovers nothing from a directory whose `control.redb`
/// was lost — and reports a cheerful zero while doing it. The events
/// themselves are ordinary CBOR entries in `data/` and survive; this is the
/// path back to them. It needs store enumeration, which only GC-capable
/// stores provide, hence the separate impl block (as with `SignatureLog`).
impl<S: ContentStore + dag_storage::GcCapableStore + 'static> PinLog<S> {
    /// Rebuild the event mappings, heads and target index by scanning the
    /// content store for pin events.
    ///
    /// Events are identified by a strict CBOR decode into [`PinEvent`], which
    /// is far stronger than the field-name sniffing the collector uses but is
    /// still a guess — so nothing is trusted on the strength of the decode
    /// alone. Each candidate chain must then validate exactly as
    /// [`Self::import_event`] requires: contiguous from seq 1, no `prev` on
    /// the create, and every later `prev` naming the event before it.
    ///
    /// Merges rather than replaces: an event mapping that is already filed is
    /// never overwritten, and a recovered chain that disagrees with one is
    /// divergence — refused and reported, the same rule replication follows.
    /// A head is rewritten only for a pin whose chain was recovered, so a pin
    /// the scan found nothing for keeps whatever the table said.
    pub fn rebuild_from_store(&self) -> Result<PinStoreRebuildReport, PinError> {
        let cids = self
            .store
            .list_all_cids()
            .map_err(|e| PinError::Storage(format!("listing store: {e}")))?;
        self.rebuild_from_cids(&cids)
    }

    /// Rebuild from a caller-owned inventory snapshot.
    pub(crate) fn rebuild_from_cids(
        &self,
        cids: &[Cid],
    ) -> Result<PinStoreRebuildReport, PinError> {
        use std::collections::HashMap;

        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        let mut report = PinStoreRebuildReport {
            chunks_scanned: cids.len(),
            ..Default::default()
        };

        let mut chains: HashMap<String, PinChain> = HashMap::new();
        for cid in cids {
            // An unreadable object may be the only copy of a pin event. Full
            // recovery must fail closed rather than silently omit it.
            let bytes = self.store.get_chunk(cid).map_err(|error| {
                PinError::Storage(format!("reading enumerated object {cid}: {error}"))
            })?;
            let Ok(entry) = Entry::from_bytes_cbor(&bytes) else {
                continue;
            };
            let Ok(event) = decode_pin_event(&entry.payload) else {
                continue;
            };
            report.events_found += 1;

            chains
                .entry(event.pin_id.clone())
                .or_default()
                .push((event.seq, cid.clone(), event));
        }

        // Positions already filed, so recovery can be merged into a partly
        // populated database without rewriting anything.
        let existing = self.existing_event_cids()?;

        let mut accepted: Vec<(String, PinChain)> = Vec::new();
        for (pin_id, mut events) in chains {
            events.sort_by_key(|(seq, _, _)| *seq);
            match validate_chain(&pin_id, &events, &existing) {
                Ok(()) => accepted.push((pin_id, events)),
                Err(reason) => {
                    report.events_skipped += events.len();
                    report.skipped.push(reason);
                }
            }
        }
        accepted.sort_by(|a, b| a.0.cmp(&b.0));

        // A recovered active head is a newly visible retention root. Apply
        // the same depth-aware validation as normal pin creation before any
        // recovered event or derived row is committed. Inactive heads do not
        // promise retention and therefore need no target walk.
        let roots_to_publish = {
            let read = self.db.begin_read().map_err(db_err)?;
            let heads = read.open_table(PIN_HEADS).map_err(db_err)?;
            let mut roots = Vec::new();
            for (pin_id, events) in &accepted {
                let (_, _, event) = events.last().expect("chain is non-empty");
                let current_seq = match heads.get(pin_id.as_bytes()).map_err(db_err)? {
                    Some(value) => Some(self.deserialize_head(value.value())?.event.seq),
                    None => None,
                };
                if current_seq.is_none_or(|current| event.seq >= current)
                    && event.state == PinState::Active
                {
                    let root = match &event.target {
                        PinTarget::Direct(cid) => {
                            (cid.clone(), crate::reference::ReferenceDepth::Named)
                        }
                        PinTarget::Subtree { root, max_depth } => (
                            root.clone(),
                            max_depth.map_or(
                                crate::reference::ReferenceDepth::Unlimited,
                                crate::reference::ReferenceDepth::Descendants,
                            ),
                        ),
                    };
                    roots.push(root);
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
            PinError::Storage(format!(
                "refusing to recover pin heads from the store: {error}"
            ))
        })?;

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut events_table = txn.open_table(PIN_EVENTS).map_err(db_err)?;
            let mut heads = txn.open_table(PIN_HEADS).map_err(db_err)?;
            let mut by_target = txn.open_table(PIN_BY_TARGET).map_err(db_err)?;

            for (pin_id, events) in &accepted {
                for (seq, cid, _) in events {
                    let key = encode_event_key(pin_id, *seq);
                    // Count only what the table did not already hold — the
                    // signal that a reconcile healed a truncated table rather
                    // than confirming an intact one.
                    if events_table.get(key.as_slice()).map_err(db_err)?.is_none() {
                        report.events_added += 1;
                    }
                    events_table
                        .insert(key.as_slice(), cid.as_bytes())
                        .map_err(db_err)?;
                }

                let (_, head_cid, head_event) = events.last().expect("chain is non-empty");

                // Advance-only: never lower a head. A store chain shorter than
                // the table's (a missing suffix of event bytes) is less
                // evidence, not divergence — regressing to it would resurrect a
                // superseded pin state.
                let current_seq = match heads.get(pin_id.as_bytes()).map_err(db_err)? {
                    Some(g) => Some(self.deserialize_head(g.value())?.event.seq),
                    None => None,
                };
                if current_seq.is_none_or(|c| head_event.seq >= c) {
                    let head = PinHead {
                        event: head_event.clone(),
                        event_cid: head_cid.clone(),
                    };
                    heads
                        .insert(pin_id.as_bytes(), self.serialize_head(&head)?.as_slice())
                        .map_err(db_err)?;
                }

                // The reverse index is derived too, and `rebuild` never
                // touched it — a recovered deployment would answer
                // `list_by_target` with nothing.
                let target_key = target_to_key(&head_event.target);
                let mut pin_ids: Vec<String> = by_target
                    .get(target_key.as_slice())
                    .map_err(db_err)?
                    .map(|g| self.deserialize_pin_ids(g.value()))
                    .transpose()?
                    .unwrap_or_default();
                if !pin_ids.contains(pin_id) {
                    pin_ids.push(pin_id.clone());
                }
                by_target
                    .insert(
                        target_key.as_slice(),
                        self.serialize_pin_ids(&pin_ids)?.as_slice(),
                    )
                    .map_err(db_err)?;

                report.heads_rebuilt += 1;
            }
            if report.events_added > 0 {
                crate::sync_generation::bump(&txn).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;

        Ok(report)
    }

    /// Every `(pin_id, seq) -> event_cid` mapping currently filed.
    fn existing_event_cids(
        &self,
    ) -> Result<std::collections::HashMap<(String, u64), Cid>, PinError> {
        let mut out = std::collections::HashMap::new();
        for (pin_id, seq, cid) in self.event_cids()? {
            out.insert((pin_id, seq), cid);
        }
        Ok(out)
    }
}

/// Validate one recovered chain, or say why it cannot be filed.
///
/// Contiguous from 1, no `prev` on the create, and every later `prev` naming
/// its predecessor — [`PinLog::import_event`]'s rules applied to a whole chain
/// at once, with one carefully bounded relaxation for a later event with
/// **no** `prev`.
///
/// A `prev`-less event at seq > 1 is legacy history — written before
/// [`dag_core::PinEvent::prev`] existed — *only* when the whole chain is being
/// recovered from scratch (its predecessor is not yet filed). Then tolerating
/// it is right: refusing would bring a deactivated legacy pin back as active,
/// a state change wearing the clothes of a recovery.
///
/// But when a `prev`-less event *extends* a chain the database already commits
/// to — the predecessor is filed and this event is not — it is
/// indistinguishable from a deactivation someone planted in `data/` to switch
/// off a live pin. That is the very attack [`PinLog::import_event`] closed by
/// requiring `prev` unconditionally, and a store scan is no safer: it trusts
/// whoever can write a chunk. So this case is refused, not merged.
///
/// Note what a store scan therefore rests on: anyone able to write into
/// `data/` can plant an event entry. That is why an existing mapping is never
/// overwritten — recovery can fill gaps, never rewrite what the log already
/// says — and why a `prev`-less extension of a filed chain is turned away.
fn validate_chain(
    pin_id: &str,
    events: &[(u64, Cid, PinEvent)],
    existing: &std::collections::HashMap<(String, u64), Cid>,
) -> Result<(), String> {
    for (i, (seq, cid, event)) in events.iter().enumerate() {
        let expected = i as u64 + 1;
        if *seq != expected {
            return Err(if i > 0 && *seq == events[i - 1].0 {
                format!("{}: two different events claim seq {}", pin_id, seq)
            } else {
                format!(
                    "{}: sequence {} is missing (found {} at that position)",
                    pin_id, expected, seq
                )
            });
        }
        if i == 0 {
            if event.prev.is_some() {
                return Err(format!("{}: seq 1 must have no `prev`", pin_id));
            }
        } else {
            let actual = &events[i - 1].1;
            match &event.prev {
                Some(claimed) if claimed != actual => {
                    return Err(format!(
                        "{}: seq {} breaks the chain: `prev` is {}, but seq {} is {}",
                        pin_id,
                        seq,
                        claimed,
                        seq - 1,
                        actual
                    ));
                }
                Some(_) => {}
                None => {
                    // A `prev`-less event at seq > 1 is legacy history — written
                    // before `PinEvent::prev` existed — only when the whole
                    // chain is being recovered from scratch. When it instead
                    // *extends* a chain the database already commits to (the
                    // predecessor is filed, this event is not), it is
                    // indistinguishable from a deactivation planted in `data/`
                    // to switch off a live pin. `PinLog::import_event` refuses
                    // exactly this by requiring `prev` unconditionally; refuse
                    // it here too, because a store scan trusts whoever can write
                    // a chunk. Over-retention is the safe direction (R6): the
                    // pin keeps the last state a chain proves.
                    let predecessor_filed = existing.contains_key(&(pin_id.to_string(), seq - 1));
                    let this_filed = existing.contains_key(&(pin_id.to_string(), *seq));
                    if predecessor_filed && !this_filed {
                        return Err(format!(
                            "{}: seq {} has no `prev` and would extend the already-filed seq {} \
                             with an unchained event; refusing to adopt it \
                             (over-retaining is the safe direction)",
                            pin_id,
                            seq,
                            seq - 1
                        ));
                    }
                }
            }
        }
        if let Some(filed) = existing.get(&(pin_id.to_string(), *seq)) {
            if filed != cid {
                return Err(format!(
                    "{}: seq {} is already filed as {}, refusing to replace it with {}",
                    pin_id, seq, filed, cid
                ));
            }
        }
    }
    Ok(())
}

/// PinCreator trait implementation for PinLog
impl<S: ContentStore + 'static> crate::integration::PinCreator for PinLog<S> {
    fn ensure_pin(
        &self,
        pin_id: &str,
        target: PinTarget,
        scope: PinScope,
        ttl: Option<u64>,
    ) -> crate::error::Result<bool> {
        // TTL is relative here but absolute on disk (R5).
        let now = crate::now_unix();
        let expires_at = ttl
            .map(|ttl_secs| {
                let ttl_secs = i64::try_from(ttl_secs).map_err(|_| {
                    crate::ControlError::Invalid("pin TTL exceeds the supported range".into())
                })?;
                now.checked_add(ttl_secs).ok_or_else(|| {
                    crate::ControlError::Invalid("pin expiry exceeds the supported range".into())
                })
            })
            .transpose()?;
        let target = self.canonical_target(target);

        // Only an absent head authorises creation. A corrupt head, an I/O
        // failure, or any other read error is not evidence that the pin is
        // absent. Existing rows must also satisfy the requested postcondition;
        // a reused ID with a different target/scope (or too-short lifetime)
        // must not be reported as success.
        match self.head(pin_id) {
            Ok(head) => {
                self.verify_ensured_pin(pin_id, &head, &target, &scope, expires_at, now)?;
                return Ok(false);
            }
            Err(PinError::PinNotFound(_)) => {}
            Err(error) => return Err(error.into()),
        }

        match self.create(pin_id, target.clone(), scope.clone(), expires_at, None) {
            Ok(()) => Ok(true),
            // Lost a race with a concurrent creator. Re-read and prove that
            // its row establishes *this* request's postcondition before
            // reporting idempotent success.
            Err(PinError::PinAlreadyExists(_)) => {
                let head = self.head(pin_id)?;
                self.verify_ensured_pin(pin_id, &head, &target, &scope, expires_at, now)?;
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Convert a PinTarget to a storage key for reverse lookups
fn target_to_key(target: &PinTarget) -> Vec<u8> {
    match target {
        PinTarget::Direct(cid) => {
            let mut key = Vec::with_capacity(1 + 32);
            key.push(0); // Type discriminant for Direct
            key.extend_from_slice(cid.as_bytes());
            key
        }
        PinTarget::Subtree { root, max_depth } => {
            let mut key = Vec::with_capacity(1 + 32 + 4);
            key.push(1); // Type discriminant for Subtree
            key.extend_from_slice(root.as_bytes());
            if let Some(depth) = max_depth {
                key.extend_from_slice(&depth.to_be_bytes());
            }
            key
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::{Cid, ContentStore};
    use dag_storage::FsStore;
    use tempfile::TempDir;

    fn setup_test() -> (PinLog<FsStore>, TempDir) {
        let temp = TempDir::new().unwrap();

        let store = Arc::new(FsStore::new(temp.path().join("data")).unwrap());
        let db = Arc::new(Database::create(temp.path().join("control.redb")).unwrap());
        let pin_log = PinLog::new(store, db).unwrap();

        (pin_log, temp)
    }

    fn put_event(pin_log: &PinLog<FsStore>, event: &PinEvent) -> Cid {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(event, &mut payload).unwrap();
        pin_log
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap()
    }

    fn put_target(pin_log: &PinLog<FsStore>, bytes: &[u8]) -> Cid {
        pin_log.store.put_chunk(bytes, None).unwrap()
    }

    fn file_event(pin_log: &PinLog<FsStore>, id: &str, seq: u64, cid: &Cid) {
        let txn = pin_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(PIN_EVENTS).unwrap();
            let key = encode_event_key(id, seq);
            events.insert(key.as_slice(), cid.as_bytes()).unwrap();
        }
        txn.commit().unwrap();
    }

    fn overwrite_head(pin_log: &PinLog<FsStore>, id: &str, bytes: &[u8]) {
        let txn = pin_log.db.begin_write().unwrap();
        {
            let mut heads = txn.open_table(PIN_HEADS).unwrap();
            heads.insert(id.as_bytes(), bytes).unwrap();
        }
        txn.commit().unwrap();
    }

    fn overwrite_reverse(pin_log: &PinLog<FsStore>, target: &PinTarget, bytes: &[u8]) {
        let key = target_to_key(target);
        let txn = pin_log.db.begin_write().unwrap();
        {
            let mut reverse = txn.open_table(PIN_BY_TARGET).unwrap();
            reverse.insert(key.as_slice(), bytes).unwrap();
        }
        txn.commit().unwrap();
    }

    #[test]
    fn immutable_pin_event_decoder_rejects_trailing_cbor() {
        let event = PinEvent {
            seq: 1,
            pin_id: "strict".into(),
            target: PinTarget::Direct(Cid::compute(b"target")),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        assert_eq!(decode_pin_event(&payload).unwrap(), event);

        payload.push(0xf6); // a second, valid CBOR value
        assert!(matches!(
            decode_pin_event(&payload),
            Err(PinError::Serialization(_))
        ));
    }

    #[test]
    fn oversized_pin_head_is_refused_before_decode() {
        let (pin_log, _temp) = setup_test();
        overwrite_head(&pin_log, "oversized", &vec![0u8; MAX_PIN_HEAD_BYTES + 1]);
        assert!(matches!(
            pin_log.head("oversized"),
            Err(PinError::Serialization(_))
        ));
    }

    fn reverse_bytes(pin_log: &PinLog<FsStore>, target: &PinTarget) -> Option<Vec<u8>> {
        let key = target_to_key(target);
        let read = pin_log.db.begin_read().unwrap();
        let reverse = read.open_table(PIN_BY_TARGET).unwrap();
        reverse
            .get(key.as_slice())
            .unwrap()
            .map(|value| value.value().to_vec())
    }

    fn apply_incremental(pin_log: &PinLog<FsStore>, plan: &PinIncrementalSyncPlan) {
        let txn = pin_log.db.begin_write().unwrap();
        pin_log.apply_incremental_sync_plan(&txn, plan).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn incremental_pin_sync_preserves_unrelated_rows_and_deactivated_reverse_membership() {
        let (pin_log, _temp) = setup_test();
        let unrelated_target = PinTarget::Direct(put_target(&pin_log, b"unrelated"));
        pin_log
            .create(
                "unrelated",
                unrelated_target.clone(),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        let unrelated_head_before = pin_log.head_bytes("unrelated").unwrap().unwrap();
        let unrelated_reverse_before = reverse_bytes(&pin_log, &unrelated_target).unwrap();

        // A malformed event-table row would break a whole-table rebuild but
        // is not visited by an exact-key incremental plan for other IDs.
        let txn = pin_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(PIN_EVENTS).unwrap();
            events
                .insert(
                    b"malformed-unrelated".as_slice(),
                    Cid::compute(b"irrelevant").as_bytes(),
                )
                .unwrap();
        }
        txn.commit().unwrap();

        let target = PinTarget::Direct(put_target(&pin_log, b"shared target"));
        let first_create = PinEvent {
            seq: 1,
            pin_id: "first".into(),
            target: target.clone(),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let first_create_cid = put_event(&pin_log, &first_create);
        let first_deactivate = PinEvent {
            seq: 2,
            pin_id: "first".into(),
            target: target.clone(),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: Some(first_create_cid.clone()),
        };
        let first_deactivate_cid = put_event(&pin_log, &first_deactivate);
        let second_create = PinEvent {
            seq: 1,
            pin_id: "second".into(),
            target: target.clone(),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let second_create_cid = put_event(&pin_log, &second_create);
        let offer = vec![
            ("second".into(), 1, second_create_cid),
            ("first".into(), 2, first_deactivate_cid),
            ("first".into(), 1, first_create_cid),
        ];
        let plan = pin_log.prepare_incremental_sync_plan(&offer).unwrap();
        assert_eq!(plan.events_inserted(), 3);
        assert_eq!(plan.heads_updated(), 2);
        assert_eq!(plan.retention_roots().len(), 1);
        pin_log.validate_incremental_sync_plan(&plan).unwrap();
        apply_incremental(&pin_log, &plan);

        assert_eq!(
            pin_log.list_by_target(&target).unwrap(),
            vec!["first".to_string(), "second".to_string()]
        );
        assert_eq!(
            pin_log.head("first").unwrap().event.state,
            PinState::Deactivated
        );
        assert_eq!(
            pin_log.head("second").unwrap().event.state,
            PinState::Active
        );
        assert_eq!(
            pin_log.head_bytes("unrelated").unwrap().unwrap(),
            unrelated_head_before
        );
        assert_eq!(
            reverse_bytes(&pin_log, &unrelated_target).unwrap(),
            unrelated_reverse_before,
            "an unrelated reverse row must remain byte-identical"
        );

        // Simulate loss of this one derived reverse row. Re-offering already
        // filed history must repair both the active and deactivated pin IDs
        // without rebuilding or touching unrelated targets.
        let target_key = target_to_key(&target);
        let txn = pin_log.db.begin_write().unwrap();
        {
            let mut reverse = txn.open_table(PIN_BY_TARGET).unwrap();
            reverse.remove(target_key.as_slice()).unwrap();
        }
        txn.commit().unwrap();
        assert!(pin_log.list_by_target(&target).unwrap().is_empty());

        let repeated = pin_log.prepare_incremental_sync_plan(&offer).unwrap();
        assert_eq!(repeated.events_inserted(), 0);
        assert_eq!(repeated.heads_updated(), 0);
        assert!(repeated.retention_roots().is_empty());
        apply_incremental(&pin_log, &repeated);
        assert_eq!(
            pin_log.list_by_target(&target).unwrap(),
            vec!["first".to_string(), "second".to_string()]
        );
    }

    #[test]
    fn incremental_pin_refusals_leave_history_head_and_reverse_unchanged() {
        let (pin_log, _temp) = setup_test();
        let target = PinTarget::Direct(put_target(&pin_log, b"guarded"));
        pin_log
            .create("guarded", target.clone(), PinScope::Global, None, None)
            .unwrap();
        let head_before = pin_log.head("guarded").unwrap();
        let reverse_before = reverse_bytes(&pin_log, &target).unwrap();

        let bad_prev = PinEvent {
            seq: 2,
            pin_id: "guarded".into(),
            target: target.clone(),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: Some(Cid::compute(b"wrong predecessor")),
        };
        let bad_prev_cid = put_event(&pin_log, &bad_prev);
        let error = pin_log
            .prepare_incremental_sync_plan(&[
                ("guarded".into(), 1, head_before.event_cid.clone()),
                ("guarded".into(), 2, bad_prev_cid.clone()),
            ])
            .unwrap_err();
        let (id, seq, cid, _) = error.into_parts();
        assert_eq!((id.as_str(), seq, cid), ("guarded", 2, bad_prev_cid));

        let changed_policy = PinEvent {
            seq: 2,
            pin_id: "guarded".into(),
            target: PinTarget::Direct(put_target(&pin_log, b"changed")),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: Some(head_before.event_cid.clone()),
        };
        let changed_policy_cid = put_event(&pin_log, &changed_policy);
        assert!(pin_log
            .prepare_incremental_sync_plan(&[("guarded".into(), 2, changed_policy_cid)])
            .is_err());

        let gap = PinEvent {
            seq: 3,
            pin_id: "guarded".into(),
            target: target.clone(),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 3,
            author: None,
            prev: Some(head_before.event_cid.clone()),
        };
        let gap_cid = put_event(&pin_log, &gap);
        assert!(pin_log
            .prepare_incremental_sync_plan(&[("guarded".into(), 3, gap_cid)])
            .is_err());

        let divergent = PinEvent {
            ts: 99,
            ..head_before.event.clone()
        };
        let divergent_cid = put_event(&pin_log, &divergent);
        let error = pin_log
            .prepare_incremental_sync_plan(&[("guarded".into(), 1, divergent_cid)])
            .unwrap_err();
        let (id, seq, _, source) = error.into_parts();
        assert_eq!((id.as_str(), seq), ("guarded", 1));
        assert!(matches!(source, PinError::PinAlreadyExists(_)));

        assert_eq!(pin_log.head("guarded").unwrap(), head_before);
        assert!(pin_log.event_cid("guarded", 2).unwrap().is_none());
        assert!(pin_log.event_cid("guarded", 3).unwrap().is_none());
        assert_eq!(reverse_bytes(&pin_log, &target).unwrap(), reverse_before);
    }

    #[test]
    fn incremental_pin_batch_and_reverse_cardinality_limits_are_exact() {
        let (pin_log, _temp) = setup_test();
        let target = PinTarget::Direct(put_target(&pin_log, b"bounded"));
        let event = PinEvent {
            seq: 1,
            pin_id: "bounded".into(),
            target,
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let event_cid = put_event(&pin_log, &event);
        let tuple = ("bounded".to_string(), 1, event_cid);
        let at_cap = vec![tuple.clone(); MAX_INCREMENTAL_PIN_EVENTS];
        assert_eq!(
            pin_log
                .prepare_incremental_sync_plan(&at_cap)
                .unwrap()
                .events_inserted(),
            1
        );
        let over_cap = vec![tuple; MAX_INCREMENTAL_PIN_EVENTS + 1];
        assert!(pin_log.prepare_incremental_sync_plan(&over_cap).is_err());

        let ids: Vec<String> = (0..MAX_PIN_IDS_PER_TARGET)
            .map(|index| format!("pin-{index:05}"))
            .collect();
        let encoded = pin_log.serialize_pin_ids(&ids).unwrap();
        assert_eq!(pin_log.deserialize_pin_ids(&encoded).unwrap(), ids);
        let mut too_many = ids;
        too_many.push("one-too-many".into());
        assert!(pin_log.serialize_pin_ids(&too_many).is_err());

        // Bypass the encoder to prove the streaming decoder stops at the same
        // exact cardinality rather than honoring a hostile array size hint.
        let repeated = vec!["valid".to_string(); MAX_PIN_IDS_PER_TARGET + 1];
        let mut raw = Vec::new();
        ciborium::ser::into_writer(&repeated, &mut raw).unwrap();
        assert!(pin_log.deserialize_pin_ids(&raw).is_err());
    }

    #[test]
    fn incremental_pin_rejects_noncanonical_padded_event_entries() {
        let (pin_log, _temp) = setup_test();
        let target = PinTarget::Direct(put_target(&pin_log, b"target"));
        let event = PinEvent {
            seq: 1,
            pin_id: "padded".into(),
            target,
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let padding_target = put_target(&pin_log, b"padding target");
        let padded = Entry::new(
            payload,
            vec![dag_core::Link::named(
                padding_target,
                "x".repeat(256 * 1024),
            )],
            None,
        );
        let padded_cid = pin_log.store.put_entry(&padded).unwrap();

        assert!(matches!(
            pin_log
                .prepare_incremental_sync_plan(&[("padded".into(), 1, padded_cid)])
                .unwrap_err()
                .into_parts()
                .3,
            PinError::Serialization(_)
        ));
        assert!(matches!(
            pin_log.head("padded"),
            Err(PinError::PinNotFound(_))
        ));
    }

    #[test]
    fn test_create_and_get_pin() {
        let (pin_log, _temp) = setup_test();
        let test_cid = put_target(&pin_log, b"test-content");

        pin_log
            .create(
                "test-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                Some("test-author".to_string()),
            )
            .unwrap();

        let head = pin_log.head("test-pin").unwrap();
        assert_eq!(head.event.pin_id, "test-pin");
        assert_eq!(head.event.seq, 1);
        assert_eq!(head.event.target, PinTarget::Direct(test_cid.clone()));
        assert!(matches!(head.event.state, PinState::Active));
        assert_eq!(head.event.author, Some("test-author".to_string()));
    }

    #[test]
    fn pin_node_and_author_fields_reject_terminal_and_bidi_formatting() {
        let (pin_log, _temp) = setup_test();
        let target = put_target(&pin_log, b"safe target");
        for (index, unsafe_text) in [
            "bad\nline",
            "bad\u{001b}[2J",
            "bad\u{202e}txt",
            "bad\u{2029}line",
        ]
        .into_iter()
        .enumerate()
        {
            assert!(pin_log
                .create(
                    &format!("unsafe-node-{index}"),
                    PinTarget::Direct(target.clone()),
                    PinScope::Local {
                        node_id: unsafe_text.into(),
                    },
                    None,
                    None,
                )
                .is_err());
            assert!(pin_log
                .create(
                    &format!("unsafe-author-{index}"),
                    PinTarget::Direct(target.clone()),
                    PinScope::Global,
                    None,
                    Some(unsafe_text.into()),
                )
                .is_err());
        }
        pin_log
            .create(
                "unicode-fields",
                PinTarget::Direct(target),
                PinScope::Local {
                    node_id: "nœud-東京".into(),
                },
                None,
                Some("作者-é".into()),
            )
            .unwrap();
    }

    #[test]
    fn test_deactivate_pin() {
        let (pin_log, _temp) = setup_test();
        let test_cid = put_target(&pin_log, b"test-content");

        pin_log
            .create(
                "test-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        pin_log
            .deactivate("test-pin", Some("deactivation-author".to_string()))
            .unwrap();

        let head = pin_log.head("test-pin").unwrap();
        assert_eq!(head.event.seq, 2);
        assert!(matches!(head.event.state, PinState::Deactivated));
        assert_eq!(head.event.author, Some("deactivation-author".to_string()));

        // Deactivating again is a no-op, not an error.
        pin_log.deactivate("test-pin", None).unwrap();
        assert_eq!(pin_log.head("test-pin").unwrap().event.seq, 2);
    }

    #[test]
    fn test_pin_history() {
        let (pin_log, _temp) = setup_test();
        let test_cid = put_target(&pin_log, b"test-content");

        pin_log
            .create(
                "test-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        pin_log.deactivate("test-pin", None).unwrap();

        let history = pin_log.history("test-pin", 1..3).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].seq, 1);
        assert!(matches!(history[0].state, PinState::Active));
        assert_eq!(history[1].seq, 2);
        assert!(matches!(history[1].state, PinState::Deactivated));
    }

    #[test]
    fn test_list_pins() {
        let (pin_log, _temp) = setup_test();
        let cid1 = put_target(&pin_log, b"content1");
        let cid2 = put_target(&pin_log, b"content2");

        pin_log
            .create(
                "pin-a",
                PinTarget::Direct(cid1),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        pin_log
            .create(
                "pin-b",
                PinTarget::Direct(cid2),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let pins = pin_log.list().unwrap();
        assert_eq!(pins.len(), 2);
        assert!(pins.contains(&"pin-a".to_string()));
        assert!(pins.contains(&"pin-b".to_string()));

        assert_eq!(pin_log.list_page(None, 1).unwrap(), vec!["pin-a"]);
        assert_eq!(pin_log.list_page(Some("pin-a"), 1).unwrap(), vec!["pin-b"]);
        assert!(pin_log.list_page(Some("pin-b"), 1).unwrap().is_empty());
    }

    #[test]
    fn test_pin_validation() {
        let (pin_log, _temp) = setup_test();
        let test_cid = put_target(&pin_log, b"test-content");

        // Test invalid pin IDs
        assert!(pin_log
            .create(
                "",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None
            )
            .is_err());
        assert!(pin_log
            .create(
                "pin\0with\0nul",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None
            )
            .is_err());

        // Test duplicate pin creation
        pin_log
            .create(
                "test-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        assert!(pin_log
            .create(
                "test-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None
            )
            .is_err());
    }

    #[test]
    fn test_pin_expiry() {
        let (pin_log, _temp) = setup_test();
        let test_cid = put_target(&pin_log, b"test-content");

        let now = crate::now_unix();
        let future_expiry = now + 3600; // 1 hour from now
        let past_expiry = now - 1; // 1 second ago

        pin_log
            .create(
                "future-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                Some(future_expiry),
                None,
            )
            .unwrap();

        let head = pin_log.head("future-pin").unwrap();
        assert!(!head.event.is_expired(now));
        assert!(head.event.is_providing_retention(now));
        assert!(head.event.is_expired(future_expiry + 1));
        assert!(!head.event.is_providing_retention(future_expiry + 1));

        pin_log
            .create(
                "past-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                Some(past_expiry),
                None,
            )
            .unwrap();

        let head = pin_log.head("past-pin").unwrap();
        assert!(head.event.is_expired(now));
        assert!(!head.event.is_providing_retention(now));
    }

    #[test]
    fn relative_pin_ttl_overflow_is_refused_before_publication() {
        let (pin_log, _temp) = setup_test();
        let target = Cid::compute(b"ttl-overflow");

        let error = crate::integration::PinCreator::ensure_pin(
            &pin_log,
            "ttl-overflow",
            PinTarget::Direct(target),
            PinScope::Global,
            Some(u64::MAX),
        )
        .unwrap_err();

        assert!(matches!(error, crate::ControlError::Invalid(_)));
        assert!(matches!(
            pin_log.head("ttl-overflow"),
            Err(PinError::PinNotFound(_))
        ));
    }

    #[test]
    fn ensure_pin_propagates_corrupt_heads_and_checks_the_postcondition() {
        let (pin_log, _temp) = setup_test();
        let first = put_target(&pin_log, b"first target");
        let second = put_target(&pin_log, b"second target");

        overwrite_head(&pin_log, "corrupt", b"not a pin head");
        let error = crate::integration::PinCreator::ensure_pin(
            &pin_log,
            "corrupt",
            PinTarget::Direct(first.clone()),
            PinScope::Global,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            crate::ControlError::Pin(PinError::Serialization(_))
        ));

        pin_log
            .create(
                "existing",
                PinTarget::Direct(first.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        assert!(!crate::integration::PinCreator::ensure_pin(
            &pin_log,
            "existing",
            PinTarget::Direct(first),
            PinScope::Global,
            Some(60),
        )
        .unwrap());

        let error = crate::integration::PinCreator::ensure_pin(
            &pin_log,
            "existing",
            PinTarget::Direct(second),
            PinScope::Global,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, crate::ControlError::Invalid(_)));
    }

    #[test]
    fn ensure_pin_rechecks_the_winner_of_a_concurrent_create() {
        let (pin_log, _temp) = setup_test();
        let pin_log = Arc::new(pin_log);
        let requested = put_target(&pin_log, b"requested target");
        let competing = put_target(&pin_log, b"competing target");
        let validated = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        pin_log.pause_next_publication_for_test(validated.clone(), resume.clone());

        let ensuring = pin_log.clone();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            result_tx
                .send(crate::integration::PinCreator::ensure_pin(
                    ensuring.as_ref(),
                    "raced",
                    PinTarget::Direct(requested),
                    PinScope::Global,
                    None,
                ))
                .unwrap();
        });
        validated.wait();

        pin_log
            .create(
                "raced",
                PinTarget::Direct(competing.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        resume.wait();

        let error = result_rx.recv().unwrap().unwrap_err();
        worker.join().unwrap();
        assert!(matches!(error, crate::ControlError::Invalid(_)));
        assert_eq!(
            pin_log.head("raced").unwrap().event.target,
            PinTarget::Direct(competing)
        );
    }

    #[test]
    fn corrupt_reverse_rows_are_never_treated_as_empty_or_overwritten() {
        let (pin_log, _temp) = setup_test();
        let target = PinTarget::Direct(put_target(&pin_log, b"reverse target"));
        pin_log
            .create("first", target.clone(), PinScope::Global, None, None)
            .unwrap();
        overwrite_reverse(&pin_log, &target, b"not a pin-id list");

        assert!(matches!(
            pin_log.list_by_target(&target),
            Err(PinError::Serialization(_))
        ));
        assert!(matches!(
            pin_log.create("second", target.clone(), PinScope::Global, None, None),
            Err(PinError::Serialization(_))
        ));
        assert!(matches!(
            pin_log.head("second"),
            Err(PinError::PinNotFound(_))
        ));
        assert!(matches!(
            pin_log.list_by_target(&target),
            Err(PinError::Serialization(_))
        ));
    }

    #[test]
    fn pin_head_counts_decode_every_row_and_propagate_corruption() {
        let (pin_log, _temp) = setup_test();
        let first = put_target(&pin_log, b"count one");
        let second = put_target(&pin_log, b"count two");
        pin_log
            .create(
                "one",
                PinTarget::Direct(first),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        pin_log
            .create(
                "two",
                PinTarget::Direct(second),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        pin_log.deactivate("two", None).unwrap();
        assert_eq!(pin_log.head_counts(crate::now_unix()).unwrap(), (2, 1));

        overwrite_head(&pin_log, "two", b"not a pin head");
        assert!(matches!(
            pin_log.head_counts(crate::now_unix()),
            Err(PinError::Serialization(_))
        ));
    }

    #[test]
    fn rebuild_preserves_the_filed_schema_one_event_cid() {
        const SCHEMA_1_PAYLOAD: &str = "a963736571016670696e5f696466676f6c64656e66746172676574a1664469726563749820\
07183f18a918ad189b15186f18e718731853181a184a18a4185118c90b186118bb188918ca18dd18b4182318ee18f6186118d7188f\
187a18f8188218516573636f706566476c6f62616c6a696d706f7274616e636518646a657870697265735f6174f6657374617465664\
163746976656274731a6553f10066617574686f7266746573746572";

        let (pin_log, _temp) = setup_test();
        let payload = hex::decode(SCHEMA_1_PAYLOAD.replace(['\n', ' '], "")).unwrap();
        let event: PinEvent = ciborium::de::from_reader(payload.as_slice()).unwrap();
        let golden_target = put_target(&pin_log, b"golden target");
        assert_eq!(event.target, PinTarget::Direct(golden_target));
        let filed = pin_log
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();
        file_event(&pin_log, "golden", 1, &filed);

        let current_encoding = put_event(&pin_log, &event);
        assert_ne!(
            filed, current_encoding,
            "fixture no longer distinguishes schemas"
        );

        pin_log.rebuild(false).unwrap();
        assert_eq!(pin_log.head("golden").unwrap().event_cid, filed);

        pin_log.deactivate("golden", None).unwrap();
        let (_, _, second_cid) = pin_log
            .event_cids()
            .unwrap()
            .into_iter()
            .find(|(_, seq, _)| *seq == 2)
            .unwrap();
        let second_entry = pin_log.store.get_entry(&second_cid).unwrap();
        let second: PinEvent = ciborium::de::from_reader(second_entry.payload.as_slice()).unwrap();
        assert_eq!(second.prev.as_ref(), Some(&filed));
        assert_eq!(
            dag_core::offer_pin_event("golden", 2, &second_cid, &second, None, Some(&filed))
                .unwrap(),
            dag_core::OfferOutcome::Accept
        );
    }

    #[test]
    fn malformed_filed_pin_history_leaves_all_heads_unchanged() {
        let cases = ["identity", "gap", "prev", "missing"];
        for case in cases {
            let (pin_log, _temp) = setup_test();
            let target = put_target(&pin_log, b"retained");
            pin_log
                .create(
                    "good",
                    PinTarget::Direct(target.clone()),
                    PinScope::Global,
                    None,
                    None,
                )
                .unwrap();
            let before = pin_log.head("good").unwrap();

            if matches!(case, "gap" | "prev") {
                let create = PinEvent {
                    seq: 1,
                    pin_id: "bad".into(),
                    target: PinTarget::Direct(target.clone()),
                    scope: PinScope::Global,
                    expires_at: None,
                    state: PinState::Active,
                    ts: 1,
                    author: None,
                    prev: None,
                };
                let create_cid = put_event(&pin_log, &create);
                file_event(&pin_log, "bad", 1, &create_cid);
            }

            let seq = if case == "gap" { 3 } else { 2 };
            let event = PinEvent {
                seq: if case == "identity" { 7 } else { seq },
                pin_id: if case == "identity" {
                    "other".into()
                } else {
                    "bad".into()
                },
                target: PinTarget::Direct(target),
                scope: PinScope::Global,
                expires_at: None,
                state: PinState::Deactivated,
                ts: 2,
                author: None,
                prev: Some(Cid::compute(b"wrong predecessor")),
            };
            let cid = if case == "missing" {
                Cid::compute(b"not actually stored")
            } else {
                put_event(&pin_log, &event)
            };
            file_event(&pin_log, "bad", seq, &cid);

            assert!(pin_log.rebuild(false).is_err(), "case {case} was accepted");
            assert_eq!(pin_log.head("good").unwrap(), before, "case {case}");
            assert_eq!(pin_log.list().unwrap(), vec!["good"], "case {case}");
        }
    }

    #[test]
    fn successful_pin_rebuild_clears_stale_heads_and_reverse_rows() {
        let (pin_log, _temp) = setup_test();
        let live_target = put_target(&pin_log, b"live");
        let stale_target = put_target(&pin_log, b"stale");
        pin_log
            .create(
                "live",
                PinTarget::Direct(live_target.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        pin_log
            .create(
                "stale",
                PinTarget::Direct(stale_target.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let txn = pin_log.db.begin_write().unwrap();
        {
            let mut events = txn.open_table(PIN_EVENTS).unwrap();
            let key = encode_event_key("stale", 1);
            events.remove(key.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let report = pin_log.rebuild(false).unwrap();
        assert_eq!(report.heads_rebuilt, 1);
        assert!(matches!(
            pin_log.head("stale"),
            Err(PinError::PinNotFound(_))
        ));
        assert!(pin_log
            .list_by_target(&PinTarget::Direct(stale_target))
            .unwrap()
            .is_empty());
        assert_eq!(
            pin_log
                .list_by_target(&PinTarget::Direct(live_target))
                .unwrap(),
            vec!["live"]
        );
    }
}
