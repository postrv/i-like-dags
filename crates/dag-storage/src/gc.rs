//! # Garbage Collection
//!
//! This module implements garbage collection for the storage layer, using
//! retention policies from the control layer to determine what can be deleted.
//!
//! ## Core Concepts
//!
//! - **GarbageCollector**: Main coordinator for collection operations
//! - **GcReport**: Detailed report of collection results
//! - **SystemDataPolicy**: Protection rules for control-plane data
//! - **Collection Epoch**: Snapshot timestamp for consistent retention evaluation
//!
//! ## Key Invariants
//!
//! ### GC1: Retention Snapshot Consistency
//! All collection decisions use a single retention snapshot to ensure
//! consistent behavior even if pins change during collection.
//!
//! ### GC2: System Data Protection
//! Control-plane data (PointerEvents, PinEvents, JobEvents, NodeLinks) is never deleted
//! regardless of pin status, with configurable retention periods.
//!
//! ### GC3: Conservative Collection
//! When in doubt, don't delete. False negatives (keeping data) are safer
//! than false positives (deleting needed data).
//!
//! ### GC4: Atomic Operations
//! Individual chunk deletions are atomic. Collection can be interrupted
//! without corrupting the storage state.

use dag_core::{Cid, ContentStore};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Chunks per batched deletion — one index transaction, one fsync, per this
/// many chunks. Large enough to amortise the commit, small enough that the
/// gap between a chunk's last in-flight check and its removal stays tens of
/// milliseconds.
const GC_DELETE_BATCH: usize = 512;

/// Default per-pass deletion/report ceiling.
///
/// Every deletion is itemised for defensible disposition. An unlimited
/// default therefore also means an unlimited in-memory report. Operators may
/// explicitly select `0` for an uncapped offline pass, but normal callers get
/// a repeatable bounded unit of work.
pub const DEFAULT_GC_MAX_DELETIONS: usize = 10_000;

/// Default number of store CIDs inventoried in one ordinary pass.
///
/// The collector requests one extra CID to prove truncation, then discards it.
/// This bounds filesystem-walk memory and work even when most objects are
/// protected and the deletion ceiling is never reached. `0` remains an
/// explicit offline opt-out for scale experiments and operator-controlled full
/// passes.
pub const DEFAULT_GC_MAX_EXAMINED: usize = 100_000;

/// Aggregate bytes admitted by an ordinary collection inventory (1 GiB).
///
/// Object count alone is not a byte/work bound: every valid chunk may be up
/// to 4 MiB. The explicit offline `0` escape hatch remains available after an
/// operator sizes the deployment.
pub const DEFAULT_GC_MAX_BYTES_EXAMINED: u64 = 1024 * 1024 * 1024;

/// Maximum individual error strings retained in one report.
const MAX_GC_ERROR_DETAILS: usize = 1_000;

// Re-export the unified GcReport from dag-core
pub use dag_core::GcReport;

/// Policy for protecting system data from garbage collection
///
/// # Why there is no minimum age here any more
///
/// This used to carry a `control_logs_min_age`, and protection expired once a
/// control-plane entry was older than it. That made the append-only pointer
/// and pin logs collectable after a day — after which `pointer history`,
/// `pointer rebuild` and `pin rebuild` all failed permanently and the M6
/// recovery gate could never close again. An audit log with an expiry is not
/// an audit log, so protection is now unconditional whenever it is `enabled`.
///
/// The detection below is also only a backstop. The authoritative list of
/// control-plane CIDs comes from the control plane, which knows them exactly;
/// see `Control::run_gc`. This heuristic exists to catch an event entry that
/// the tables have somehow lost, which is the case where guessing beats
/// deleting (GC3).
#[derive(Debug, Clone)]
pub struct SystemDataPolicy {
    /// Whether to protect NodeLink entries indefinitely
    pub protect_node_links: bool,
    /// Whether to enable system data protection at all
    pub enabled: bool,
}

impl Default for SystemDataPolicy {
    fn default() -> Self {
        SystemDataPolicy {
            protect_node_links: true,
            enabled: true,
        }
    }
}

/// Configuration for garbage collection behavior
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// Optional node identifier for multi-node deployments
    pub node_id: Option<String>,
    /// System data protection policy
    pub system_policy: SystemDataPolicy,
    /// Maximum number of chunks to delete in one run (0 = unlimited)
    pub max_deletions: usize,
    /// Maximum number of store CIDs to examine in one run (0 = unlimited)
    pub max_examined: usize,
    /// Maximum aggregate bytes in the complete inventory (0 = unlimited)
    pub max_bytes_examined: u64,
    /// Whether this is a dry run (report only, no deletions)
    pub dry_run: bool,
    /// Minimum age for chunks to be eligible for deletion
    pub min_chunk_age: Duration,
    /// Retain an itemised disposition row for every deletion.
    ///
    /// Counters remain exact when this is false. Keeping details is opt-in
    /// because callers such as the HTTP summary endpoint otherwise allocate a
    /// second O(deletions) structure they immediately discard.
    pub collect_details: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        GcConfig {
            node_id: None,
            system_policy: SystemDataPolicy::default(),
            max_deletions: DEFAULT_GC_MAX_DELETIONS,
            max_examined: DEFAULT_GC_MAX_EXAMINED,
            max_bytes_examined: DEFAULT_GC_MAX_BYTES_EXAMINED,
            dry_run: false,
            min_chunk_age: Duration::from_secs(60), // 1 minute
            collect_details: false,
        }
    }
}

/// Garbage collector that respects retention policies and protects system data
pub struct GarbageCollector<S: GcCapableStore> {
    /// Content store to collect from
    store: Arc<S>,
}

/// A complete, ceiling-checked store inventory prepared before the control
/// plane starts materialising retention roots.
///
/// Its CID vector is private so callers cannot manufacture a partial snapshot
/// and pass it to the destructive phase.
pub struct PreparedGcInventory {
    cids: Vec<Cid>,
    bytes: u64,
}

impl PreparedGcInventory {
    /// Number of filesystem objects in the proven-complete inventory.
    pub fn len(&self) -> usize {
        self.cids.len()
    }

    /// Whether the inventory contains no objects.
    pub fn is_empty(&self) -> bool {
        self.cids.is_empty()
    }

    /// CIDs in the complete snapshot. Exposed read-only so a control plane can
    /// prove its event/index tables account for every plausible system entry
    /// before it derives retention roots.
    pub fn cids(&self) -> &[Cid] {
        &self.cids
    }

    /// Aggregate file bytes proven during inventory preparation.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl<S: GcCapableStore + 'static> GarbageCollector<S> {
    /// Create a new garbage collector
    pub fn new(store: Arc<S>) -> Self {
        GarbageCollector { store }
    }

    /// Perform garbage collection with the given configuration
    pub fn collect(
        &self,
        protected_cids: &HashSet<Cid>,
        config: &GcConfig,
    ) -> Result<GcReport, dag_core::CoreError> {
        let inventory = self.prepare_inventory(config.max_examined, config.max_bytes_examined)?;
        self.collect_prepared(protected_cids, config, inventory)
    }

    /// Enumerate a complete finite inventory and prove that it agrees exactly
    /// with any derived index the store maintains.
    pub fn prepare_inventory(
        &self,
        max_examined: usize,
        max_bytes_examined: u64,
    ) -> Result<PreparedGcInventory, dag_core::CoreError> {
        // Request one extra row so a finite inventory can say conclusively
        // that it was truncated without ever materialising the whole store.
        let cids = self.store.prepare_gc_inventory(max_examined)?;
        let mut bytes = 0u64;
        for cid in &cids {
            let size = u64::try_from(self.store.get_inventory_chunk_size(cid)?).map_err(|_| {
                dag_core::CoreError::PreconditionFailed(
                    "chunk length does not fit the inventory byte counter".into(),
                )
            })?;
            bytes = bytes.checked_add(size).ok_or_else(|| {
                dag_core::CoreError::PreconditionFailed(
                    "garbage-collection inventory byte count overflowed".into(),
                )
            })?;
            if max_bytes_examined > 0 && bytes > max_bytes_examined {
                return Err(dag_core::CoreError::GcInventoryBytesLimit {
                    limit: max_bytes_examined,
                    required: bytes,
                });
            }
        }
        Ok(PreparedGcInventory { cids, bytes })
    }

    /// Collect against an inventory produced by [`Self::prepare_inventory`].
    ///
    /// Control-plane callers use this split form so the store and database
    /// bounds are proven before any retention graph is expanded.
    pub fn collect_prepared(
        &self,
        protected_cids: &HashSet<Cid>,
        config: &GcConfig,
        inventory: PreparedGcInventory,
    ) -> Result<GcReport, dag_core::CoreError> {
        let collection_start = SystemTime::now();
        let collection_epoch = collection_start
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if config.max_examined > 0 && inventory.cids.len() > config.max_examined {
            return Err(dag_core::CoreError::GcInventoryLimit {
                limit: config.max_examined,
            });
        }
        if config.max_bytes_examined > 0 && inventory.bytes > config.max_bytes_examined {
            return Err(dag_core::CoreError::GcInventoryBytesLimit {
                limit: config.max_bytes_examined,
                required: inventory.bytes,
            });
        }
        // Recheck immediately before classification/deletion. Content added
        // after the prepared snapshot is outside this pass and therefore safe
        // to ignore; every CID that was prepared must still have a valid index
        // witness. A removal/reindex that loses one is a conservative refusal,
        // never a stale destructive snapshot.
        self.store.validate_gc_snapshot(&inventory.cids)?;
        let all_cids = inventory.cids;

        // Verify and classify the complete finite inventory before the first
        // deletion. An unreadable object cannot be classified as ordinary
        // content: it may be the only unfiled pointer/pin/job event and thus
        // hide retention roots. Classifying lazily during the sweep could
        // delete such a target earlier in inventory order before discovering
        // the damaged event. Fail the whole pass with zero deletions instead.
        let system_protected =
            self.verify_and_classify_inventory(&all_cids, &config.system_policy)?;

        let mut report = GcReport {
            node_id: config.node_id.clone(),
            collection_epoch,
            total_chunks_examined: 0,
            chunks_deleted: 0,
            bytes_freed: 0,
            errors: Vec::new(),
            errors_truncated: false,
            protected_by_pins: 0,
            protected_by_system: 0,
            skipped_too_young: 0,
            dry_run: config.dry_run,
            collected: Vec::new(),
            truncated_by_max_deletions: false,
        };

        let mut chunks_deleted = 0;

        // Chunks that passed every gate, awaiting one batched deletion.
        // Batching exists because the index write dominates deletion cost:
        // one committed transaction per chunk is one fsync per chunk —
        // measured at ~5.6 ms each, ninety minutes for a million chunks.
        let mut doomed: Vec<(Cid, usize, Option<Duration>)> = Vec::new();

        let flush = |doomed: &mut Vec<(Cid, usize, Option<Duration>)>, report: &mut GcReport| {
            if doomed.is_empty() {
                return 0usize;
            }
            let cids: Vec<Cid> = doomed.iter().map(|(cid, _, _)| cid.clone()).collect();
            let outcome = self.store.delete_chunks(&cids, config.min_chunk_age);
            let deleted: HashSet<&Cid> = outcome.deleted.iter().collect();
            let skipped: HashSet<&Cid> = outcome.skipped_in_flight.iter().collect();

            let mut deleted_now = 0usize;
            for (cid, size, age) in doomed.drain(..) {
                if deleted.contains(&cid) {
                    deleted_now += 1;
                    report.chunks_deleted += 1;
                    report.bytes_freed += size;
                    if config.collect_details {
                        report.collected.push(dag_core::CollectedChunk {
                            cid,
                            bytes: size,
                            age_secs: age.map(|d| d.as_secs()),
                        });
                    }
                } else if skipped.contains(&cid) {
                    report.skipped_too_young += 1;
                }
                // Failures are reported below from the outcome itself.
            }
            append_errors(report, outcome.errors);
            deleted_now
        };

        for cid in all_cids {
            // Check deletion limits
            if config.max_deletions > 0 && chunks_deleted + doomed.len() >= config.max_deletions {
                // The counters below describe a prefix of the store, not the
                // whole of it. Say so rather than presenting them as totals.
                report.truncated_by_max_deletions = true;
                break;
            }
            report.total_chunks_examined += 1;

            // Check if protected by retention policies
            if protected_cids.contains(&cid) {
                report.protected_by_pins += 1;
                continue;
            }

            // Check if protected by system data policy
            if system_protected.contains(&cid) {
                report.protected_by_system += 1;
                continue;
            }

            // Check minimum age requirement
            let age = self.get_chunk_age(&cid)?;
            if let Some(chunk_age) = age {
                if chunk_age < config.min_chunk_age {
                    report.skipped_too_young += 1;
                    continue;
                }
            }

            // Last gate, deliberately here rather than in the protected set:
            // this is re-read per chunk, so a write that landed after the
            // snapshot was taken is still seen.
            if self.store.is_in_flight(&cid, config.min_chunk_age) {
                report.skipped_too_young += 1;
                continue;
            }

            // This chunk can go. A dry run just prices it; a real run queues
            // it for the next batched deletion.
            if config.dry_run {
                match self.store.get_chunk_size(&cid) {
                    Ok(size) => {
                        chunks_deleted += 1;
                        report.chunks_deleted += 1;
                        report.bytes_freed += size;
                        if config.collect_details {
                            report.collected.push(dag_core::CollectedChunk {
                                cid: cid.clone(),
                                bytes: size,
                                age_secs: age.map(|d| d.as_secs()),
                            });
                        }
                    }
                    Err(e) => {
                        append_errors(&mut report, [format!("Failed to delete {}: {}", cid, e)])
                    }
                }
                continue;
            }

            match self.store.get_chunk_size(&cid) {
                Ok(size) => doomed.push((cid, size, age)),
                Err(e) => append_errors(&mut report, [format!("Failed to delete {}: {}", cid, e)]),
            }
            if doomed.len() >= GC_DELETE_BATCH {
                chunks_deleted += flush(&mut doomed, &mut report);
            }
        }

        chunks_deleted += flush(&mut doomed, &mut report);
        let _ = chunks_deleted;

        Ok(report)
    }

    /// Check if a CID is protected by system data policy
    #[cfg(test)]
    fn is_system_protected(
        &self,
        cid: &Cid,
        policy: &SystemDataPolicy,
    ) -> Result<bool, dag_core::CoreError> {
        let bytes = self.store.get_chunk(cid)?;
        Ok(self.is_system_protected_bytes(&bytes, policy))
    }

    /// Verify every enumerated object and retain the system-data subset.
    fn verify_and_classify_inventory(
        &self,
        cids: &[Cid],
        policy: &SystemDataPolicy,
    ) -> Result<HashSet<Cid>, dag_core::CoreError> {
        let mut protected = HashSet::new();
        for cid in cids {
            let bytes = self.store.get_chunk(cid)?;
            if policy.enabled && self.is_system_protected_bytes(&bytes, policy) {
                protected.insert(cid.clone());
            }
        }
        Ok(protected)
    }

    /// Classify already verified bytes. Ordinary leaf bytes are not entries;
    /// a schema decode miss is therefore a normal negative, unlike a storage
    /// read/hash failure.
    fn is_system_protected_bytes(&self, bytes: &[u8], policy: &SystemDataPolicy) -> bool {
        let Ok(entry) = dag_core::Entry::from_bytes_cbor(bytes) else {
            return false;
        };

        // Protect NodeLinks indefinitely if configured
        if policy.protect_node_links && !entry.links.is_empty() && entry.payload.is_empty() {
            return true;
        }

        // Control-plane data is protected for as long as it exists. This
        // deliberately has no age gate: see SystemDataPolicy's docs.
        if self.is_control_plane_data(&entry.payload) {
            return true;
        }

        false
    }

    /// Check if payload looks like control-plane data
    fn is_control_plane_data(&self, payload: &[u8]) -> bool {
        // Try to deserialize as known control-plane types
        if self.looks_like_pin_event(payload) {
            return true;
        }
        if self.looks_like_pointer_event(payload) {
            return true;
        }
        if self.looks_like_job_event(payload) {
            return true;
        }
        false
    }

    /// Heuristic to detect PinEvent payloads
    fn looks_like_pin_event(&self, payload: &[u8]) -> bool {
        // Simple heuristic: try CBOR deserialization
        use std::io::Cursor;
        let cursor = Cursor::new(payload);

        // Try to parse as CBOR and look for pin-specific fields
        if let Ok(ciborium::Value::Map(map)) =
            ciborium::de::from_reader::<ciborium::Value, _>(cursor)
        {
            // Look for fields that indicate this is a PinEvent
            let has_pin_id = map.iter().any(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    s == "pin_id"
                } else {
                    false
                }
            });
            let has_target = map.iter().any(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    s == "target"
                } else {
                    false
                }
            });
            // Was `importance` until schema 2 removed it. `scope` is the
            // replacement marker: every pin event has one, no other event
            // type here carries all three of these keys, and unlike
            // `importance` it is load-bearing rather than decorative — so a
            // future removal would break loudly elsewhere first. Getting this
            // wrong stops pin events being recognised as system data, and the
            // collector eats the retention log.
            let has_scope = map.iter().any(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    s == "scope"
                } else {
                    false
                }
            });
            return has_pin_id && has_target && has_scope;
        }
        false
    }

    /// Heuristic to detect PointerEvent payloads
    fn looks_like_pointer_event(&self, payload: &[u8]) -> bool {
        // Simple heuristic: try CBOR deserialization
        use std::io::Cursor;
        let cursor = Cursor::new(payload);

        if let Ok(ciborium::Value::Map(map)) =
            ciborium::de::from_reader::<ciborium::Value, _>(cursor)
        {
            // Look for fields that indicate this is a PointerEvent
            let has_pointer_id = map.iter().any(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    s == "pointer_id"
                } else {
                    false
                }
            });
            let has_seq = map.iter().any(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    s == "seq"
                } else {
                    false
                }
            });
            let has_new_cid = map.iter().any(|(k, _)| {
                if let ciborium::Value::Text(s) = k {
                    s == "new" || s == "new_cid"
                } else {
                    false
                }
            });
            return has_pointer_id && has_seq && has_new_cid;
        }
        false
    }

    /// Heuristic to detect JobEvent payloads.
    ///
    /// `JobLog` stores each job event as a CBOR entry in the content store, and
    /// `JobLog::rebuild_from_store` recovers job specs from exactly those
    /// entries — so they are control-plane history and must survive collection,
    /// like pin and pointer events. A `JobEvent` is an externally-tagged serde
    /// enum, so it encodes as a single-entry map whose key is the variant name
    /// (`Created`/`Triggered`/`Updated`) and whose value is a map carrying the
    /// event's `ts`. That shape is what this recognises. As with the two
    /// heuristics above it is only a backstop; the authoritative list comes
    /// from `Control::run_gc`, which asks `JobLog::event_cids` directly.
    fn looks_like_job_event(&self, payload: &[u8]) -> bool {
        use std::io::Cursor;
        let cursor = Cursor::new(payload);

        if let Ok(ciborium::Value::Map(map)) =
            ciborium::de::from_reader::<ciborium::Value, _>(cursor)
        {
            // Externally-tagged enum: exactly one entry, keyed by variant name.
            if map.len() != 1 {
                return false;
            }
            let (key, value) = &map[0];
            let is_variant = matches!(
                key,
                ciborium::Value::Text(s) if s == "Created" || s == "Triggered" || s == "Updated"
            );
            if !is_variant {
                return false;
            }
            // Every variant carries a `ts`; requiring it keeps an arbitrary
            // single-key user map from matching.
            if let ciborium::Value::Map(fields) = value {
                return fields
                    .iter()
                    .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "ts"));
            }
        }
        false
    }

    /// Get the age of a chunk (time since creation)
    fn get_chunk_age(&self, cid: &Cid) -> Result<Option<Duration>, dag_core::CoreError> {
        // This would need to be implemented based on storage backend
        // For filesystem storage, check file modification time
        // For now, we'll call a hypothetical method on the store
        self.store.get_chunk_age(cid)
    }
}

fn append_errors(report: &mut GcReport, errors: impl IntoIterator<Item = String>) {
    for error in errors {
        if report.errors.len() < MAX_GC_ERROR_DETAILS {
            report.errors.push(error);
        } else {
            report.errors_truncated = true;
        }
    }
}

/// Extend ContentStore trait with GC-specific methods
pub trait GcCapableStore: ContentStore {
    /// List at most `limit` CIDs from the store (`None` = all).
    ///
    /// Implementations must apply a finite limit during enumeration rather
    /// than collecting the complete inventory and truncating afterward.
    fn list_cids(&self, limit: Option<usize>) -> Result<Vec<Cid>, dag_core::CoreError>;

    /// Explicit unbounded inventory for offline diagnostics and tests.
    fn list_all_cids(&self) -> Result<Vec<Cid>, dag_core::CoreError> {
        self.list_cids(None)
    }

    /// Capture the initial complete inventory used by a destructive pass.
    ///
    /// The default composes [`Self::list_cids`] and
    /// [`Self::validate_gc_inventory`]. Stores whose bytes and catalogue are
    /// published in separate steps must override this and exclude writers
    /// across both operations; otherwise a legitimate put can look exactly
    /// like a restored stale index in the rename-to-index window.
    fn prepare_gc_inventory(&self, max_examined: usize) -> Result<Vec<Cid>, dag_core::CoreError> {
        // Request one extra row so a finite inventory can say conclusively
        // that it was truncated without materialising the complete store.
        let inventory_limit = max_examined.checked_add(1).filter(|_| max_examined > 0);
        let cids = self.list_cids(inventory_limit)?;
        if max_examined > 0 && cids.len() > max_examined {
            return Err(dag_core::CoreError::GcInventoryLimit {
                limit: max_examined,
            });
        }
        self.validate_gc_inventory(&cids)?;
        Ok(cids)
    }

    /// Prove that `filesystem_cids` is also the exact inventory of any
    /// derived catalogue used by this store. Indexless stores have no second
    /// authority to compare and therefore accept the filesystem snapshot.
    fn validate_gc_inventory(&self, _filesystem_cids: &[Cid]) -> Result<(), dag_core::CoreError> {
        Ok(())
    }

    /// Revalidate the prepared inventory immediately before deletion.
    ///
    /// Extra rows created after the snapshot are safe: they are not candidates
    /// in this pass. The default remains exact for backends without a distinct
    /// snapshot protocol; concurrent stores should override it with a
    /// writer-excluded subset check for every prepared CID.
    fn validate_gc_snapshot(&self, prepared_cids: &[Cid]) -> Result<(), dag_core::CoreError> {
        self.validate_gc_inventory(prepared_cids)
    }

    /// Get the age of a chunk (time since creation)
    fn get_chunk_age(&self, cid: &Cid) -> Result<Option<Duration>, dag_core::CoreError>;

    /// Get the size of a chunk in bytes
    fn get_chunk_size(&self, cid: &Cid) -> Result<usize, dag_core::CoreError>;

    /// Get a no-content-read size for bounded inventory preflight.
    ///
    /// The default may open the chunk. Filesystem stores override this with a
    /// no-follow metadata lookup so permissions failures still reach the
    /// retention walker and receive an actionable root diagnostic. The later
    /// mandatory whole-inventory read/hash pass remains the deletion gate.
    fn get_inventory_chunk_size(&self, cid: &Cid) -> Result<usize, dag_core::CoreError> {
        self.get_chunk_size(cid)
    }

    /// Delete a chunk from storage
    fn delete_chunk(&self, cid: &Cid) -> Result<(), dag_core::CoreError>;

    /// Whether this process wrote `cid` recently enough that something may be
    /// about to reference it.
    ///
    /// Consulted immediately before deletion rather than folded into the
    /// caller's protected set, and that timing is the whole point: the
    /// protected set is a snapshot, so a chunk written *after* it was taken
    /// but before the sweep reaches it would otherwise be unprotected. A
    /// large ingest writes every chunk before the manifest names any of them,
    /// which makes that window as long as the ingest.
    ///
    /// `within` is the caller's minimum chunk age, so an operator who passes
    /// `--min-age-secs 0` — "collect everything, I know what I am doing" — is
    /// taken at their word rather than quietly overruled. The default of 60
    /// seconds is what protects an ordinary ingest.
    ///
    /// Defaults to `false` for stores that do not track it.
    fn is_in_flight(&self, _cid: &Cid, _within: Duration) -> bool {
        false
    }

    /// Delete many chunks, with the in-flight gate applied per chunk
    /// *inside* the call — immediately before anything is removed.
    ///
    /// Exists because deletion cost is dominated by the index write: one
    /// committed transaction per chunk is one fsync per chunk, measured at
    /// ~5.6 ms each — ninety minutes for a million-chunk collection. A
    /// batched implementation amortises that to one commit per batch.
    ///
    /// The default implementation is the un-batched loop, so stores without
    /// a batchable index keep their existing behaviour.
    fn delete_chunks(&self, cids: &[Cid], in_flight_within: Duration) -> BatchDelete {
        let mut outcome = BatchDelete::default();
        for cid in cids {
            if self.is_in_flight(cid, in_flight_within) {
                outcome.skipped_in_flight.push(cid.clone());
                continue;
            }
            match self.delete_chunk(cid) {
                Ok(()) => outcome.deleted.push(cid.clone()),
                Err(e) => outcome
                    .errors
                    .push(format!("Failed to delete {}: {}", cid, e)),
            }
        }
        outcome
    }
}

/// What one [`GcCapableStore::delete_chunks`] call did, per chunk.
///
/// Deletion failures are entries here rather than an `Err` return: one
/// unremovable file must not abort the rest of a batch, the same per-item
/// isolation the sync report keeps.
#[derive(Debug, Default)]
pub struct BatchDelete {
    /// Chunks actually removed.
    pub deleted: Vec<Cid>,
    /// Chunks skipped because a live ingest touched them within the window —
    /// the final gate holding, not an error.
    pub skipped_in_flight: Vec<Cid>,
    /// Per-chunk failures, already formatted for the report.
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock storage for testing
    #[derive(Default)]
    struct MockStore {
        chunks: Mutex<HashMap<Cid, (Vec<u8>, SystemTime)>>,
        unreadable: Mutex<HashSet<Cid>>,
    }

    impl MockStore {
        fn add_chunk(&self, cid: Cid, data: Vec<u8>) {
            let mut chunks = self.chunks.lock().unwrap();
            chunks.insert(cid, (data, SystemTime::now()));
        }

        fn add_chunk_with_age(&self, cid: Cid, data: Vec<u8>, age: Duration) {
            let mut chunks = self.chunks.lock().unwrap();
            let timestamp = SystemTime::now() - age;
            chunks.insert(cid, (data, timestamp));
        }

        fn make_unreadable(&self, cid: Cid) {
            self.unreadable.lock().unwrap().insert(cid);
        }
    }

    impl ContentStore for MockStore {
        fn put_chunk(
            &self,
            data: &[u8],
            _meta: Option<dag_core::MetaHint>,
        ) -> Result<Cid, dag_core::CoreError> {
            let cid = Cid::compute(data);
            self.add_chunk(cid.clone(), data.to_vec());
            Ok(cid)
        }

        fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, dag_core::CoreError> {
            if self.unreadable.lock().unwrap().contains(cid) {
                return Err(dag_core::CoreError::Backend(format!(
                    "injected read failure for {cid}"
                )));
            }
            let chunks = self.chunks.lock().unwrap();
            match chunks.get(cid) {
                Some((data, _)) => Ok(data.clone()),
                None => Err(dag_core::CoreError::ChunkNotFound(format!(
                    "Chunk not found: {}",
                    cid
                ))),
            }
        }

        fn has_chunk(&self, cid: &Cid) -> Result<bool, dag_core::CoreError> {
            let chunks = self.chunks.lock().unwrap();
            Ok(chunks.contains_key(cid))
        }

        fn put_entry(&self, entry: &Entry) -> Result<Cid, dag_core::CoreError> {
            let data = entry.to_bytes_cbor()?;
            self.put_chunk(&data, None)
        }

        fn get_entry(&self, cid: &Cid) -> Result<Entry, dag_core::CoreError> {
            let data = self.get_chunk(cid)?;
            Entry::from_bytes_cbor(&data)
        }
    }

    impl GcCapableStore for MockStore {
        fn list_cids(&self, limit: Option<usize>) -> Result<Vec<Cid>, dag_core::CoreError> {
            let chunks = self.chunks.lock().unwrap();
            Ok(chunks
                .keys()
                .take(limit.unwrap_or(usize::MAX))
                .cloned()
                .collect())
        }

        fn get_chunk_age(&self, cid: &Cid) -> Result<Option<Duration>, dag_core::CoreError> {
            let chunks = self.chunks.lock().unwrap();
            match chunks.get(cid) {
                Some((_, timestamp)) => {
                    let age = SystemTime::now()
                        .duration_since(*timestamp)
                        .unwrap_or(Duration::ZERO);
                    Ok(Some(age))
                }
                None => Ok(None),
            }
        }

        fn get_chunk_size(&self, cid: &Cid) -> Result<usize, dag_core::CoreError> {
            let chunks = self.chunks.lock().unwrap();
            match chunks.get(cid) {
                Some((data, _)) => Ok(data.len()),
                None => Err(dag_core::CoreError::ChunkNotFound(format!(
                    "Chunk not found: {}",
                    cid
                ))),
            }
        }

        fn delete_chunk(&self, cid: &Cid) -> Result<(), dag_core::CoreError> {
            let mut chunks = self.chunks.lock().unwrap();
            match chunks.remove(cid) {
                Some(_) => Ok(()),
                None => Err(dag_core::CoreError::ChunkNotFound(format!(
                    "Chunk not found: {}",
                    cid
                ))),
            }
        }
    }

    // Wrapper to avoid orphan rule issues with Arc<MockStore>
    #[derive(Clone)]
    struct MockStoreWrapper(Arc<MockStore>);

    impl MockStoreWrapper {
        fn new() -> Self {
            MockStoreWrapper(Arc::new(MockStore::default()))
        }
    }

    impl ContentStore for MockStoreWrapper {
        fn put_chunk(
            &self,
            data: &[u8],
            meta: Option<dag_core::MetaHint>,
        ) -> Result<Cid, dag_core::CoreError> {
            self.0.put_chunk(data, meta)
        }

        fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, dag_core::CoreError> {
            self.0.get_chunk(cid)
        }

        fn has_chunk(&self, cid: &Cid) -> Result<bool, dag_core::CoreError> {
            self.0.has_chunk(cid)
        }
    }

    impl GcCapableStore for MockStoreWrapper {
        fn list_cids(&self, limit: Option<usize>) -> Result<Vec<Cid>, dag_core::CoreError> {
            self.0.list_cids(limit)
        }

        fn get_chunk_age(&self, cid: &Cid) -> Result<Option<Duration>, dag_core::CoreError> {
            self.0.get_chunk_age(cid)
        }

        fn get_chunk_size(&self, cid: &Cid) -> Result<usize, dag_core::CoreError> {
            self.0.get_chunk_size(cid)
        }

        fn delete_chunk(&self, cid: &Cid) -> Result<(), dag_core::CoreError> {
            self.0.delete_chunk(cid)
        }
    }

    #[test]
    fn test_basic_gc() {
        let store = MockStoreWrapper::new();
        let store_clone = store.clone();
        let gc = GarbageCollector::new(Arc::new(store));

        // Add some chunks
        let cid1 = gc.store.put_chunk(b"data1", None).unwrap();
        let cid2 = gc.store.put_chunk(b"data2", None).unwrap();

        // Protect only cid1
        let mut protected = HashSet::new();
        protected.insert(cid1.clone());

        let config = GcConfig {
            min_chunk_age: Duration::ZERO, // Delete immediately for testing
            ..Default::default()
        };

        let report = gc.collect(&protected, &config).unwrap();

        // Should delete cid2 but not cid1
        assert_eq!(report.chunks_deleted, 1);
        assert_eq!(report.protected_by_pins, 1);
        assert!(store_clone.has_chunk(&cid1).unwrap());
        assert!(!store_clone.has_chunk(&cid2).unwrap());
    }

    #[test]
    fn an_unreadable_inventory_refuses_before_any_deletion() {
        let store = Arc::new(MockStore::default());
        let readable = Cid::compute(b"readable garbage");
        let unreadable = Cid::compute(b"possibly a lost control event");
        store.add_chunk_with_age(
            readable.clone(),
            b"readable garbage".to_vec(),
            Duration::from_secs(3_600),
        );
        store.add_chunk_with_age(
            unreadable.clone(),
            b"possibly a lost control event".to_vec(),
            Duration::from_secs(3_600),
        );
        store.make_unreadable(unreadable.clone());

        let gc = GarbageCollector::new(Arc::clone(&store));
        let error = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap_err();

        assert!(error.to_string().contains("injected read failure"));
        assert!(store.has_chunk(&readable).unwrap());
        assert!(store.has_chunk(&unreadable).unwrap());
    }

    #[test]
    fn a_job_event_entry_is_system_protected() {
        use ciborium::Value;

        // CBOR matching serde's externally-tagged encoding of a JobEvent.
        // `JobEvent` lives in dag-control, which sits *above* this crate, so
        // the shape is reconstructed by hand rather than imported. A
        // dag-control unit test (`job::tests`) pins that this is the real
        // encoding.
        fn job_event_cbor(variant: &str) -> Vec<u8> {
            let inner = Value::Map(vec![
                (
                    Value::Text("spec".into()),
                    Value::Map(vec![(
                        Value::Text("job_id".into()),
                        Value::Text("digest".into()),
                    )]),
                ),
                (Value::Text("ts".into()), Value::Integer(42i64.into())),
            ]);
            let outer = Value::Map(vec![(Value::Text(variant.into()), inner)]);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&outer, &mut buf).unwrap();
            buf
        }

        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());
        let policy = SystemDataPolicy::default();
        assert!(policy.enabled);

        for variant in ["Created", "Triggered", "Updated"] {
            let entry = Entry {
                payload: job_event_cbor(variant),
                links: vec![],
                meta: None,
            };
            let cid = store.put_entry(&entry).unwrap();
            assert!(
                gc.is_system_protected(&cid, &policy).unwrap(),
                "a {variant} job event is control-plane history and must be protected"
            );
        }

        // The heuristic must not swallow ordinary content.
        let plain = store.put_chunk(b"ordinary user content", None).unwrap();
        assert!(
            !gc.is_system_protected(&plain, &policy).unwrap(),
            "a plain chunk is not control-plane data"
        );
    }

    #[test]
    fn test_dry_run() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());

        let cid = store.put_chunk(b"test data", None).unwrap();

        let config = GcConfig {
            dry_run: true,
            min_chunk_age: Duration::ZERO,
            ..Default::default()
        };

        let report = gc.collect(&HashSet::new(), &config).unwrap();

        // Should report deletion but not actually delete
        assert_eq!(report.chunks_deleted, 1);
        assert!(report.dry_run);
        assert!(store.has_chunk(&cid).unwrap()); // Still exists
    }

    #[test]
    fn test_min_age_protection() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());

        // Add fresh chunk
        let fresh_cid = store.put_chunk(b"fresh data", None).unwrap();

        // Add old chunk
        let old_cid = Cid::compute(b"old data");
        store.add_chunk_with_age(
            old_cid.clone(),
            b"old data".to_vec(),
            Duration::from_secs(3600),
        );

        let config = GcConfig {
            min_chunk_age: Duration::from_secs(300), // 5 minutes
            ..Default::default()
        };

        let report = gc.collect(&HashSet::new(), &config).unwrap();

        // Should delete old chunk but not fresh one
        assert_eq!(report.chunks_deleted, 1);
        assert_eq!(report.skipped_too_young, 1);
        assert!(store.has_chunk(&fresh_cid).unwrap());
        assert!(!store.has_chunk(&old_cid).unwrap());
    }

    #[test]
    fn test_max_deletions_limit() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());

        // Add 5 chunks
        let mut cids = Vec::new();
        for i in 0..5 {
            let data = format!("data{}", i);
            let cid = store.put_chunk(data.as_bytes(), None).unwrap();
            cids.push(cid);
        }

        let config = GcConfig {
            max_deletions: 3, // Limit to 3 deletions
            min_chunk_age: Duration::ZERO,
            ..Default::default()
        };

        let report = gc.collect(&HashSet::new(), &config).unwrap();

        // Should delete only 3 chunks
        assert_eq!(report.chunks_deleted, 3);

        // Count remaining chunks
        let remaining = cids
            .iter()
            .filter(|cid| store.has_chunk(cid).unwrap())
            .count();
        assert_eq!(remaining, 2);
    }

    /// Build a store of 5 protected and 5 collectable chunks.
    fn mixed_store() -> (Arc<MockStore>, HashSet<Cid>, Vec<Cid>) {
        let store = Arc::new(MockStore::default());
        let mut protected = HashSet::new();
        let mut collectable = Vec::new();

        for i in 0..10 {
            let cid = store
                .put_chunk(format!("chunk-{}", i).as_bytes(), None)
                .unwrap();
            if i % 2 == 0 {
                protected.insert(cid);
            } else {
                collectable.push(cid);
            }
        }
        (store, protected, collectable)
    }

    /// I6/R6 under a deletion cap. The budget must be spent on collectable
    /// chunks only — were protected CIDs to count against it, a pass would stop
    /// early and leave collectable garbage behind while appearing to have hit
    /// its limit.
    ///
    /// Note what is *not* asserted: `protected_by_pins`. `collect` stops
    /// scanning the moment the cap is reached, so how many protected chunks it
    /// noticed first depends on store iteration order. The counter is a partial
    /// tally of a truncated scan, not a total.
    #[test]
    fn a_deletion_cap_is_spent_only_on_collectable_chunks() {
        let (store, protected, collectable) = mixed_store();
        let gc = GarbageCollector::new(store.clone());

        let report = gc
            .collect(
                &protected,
                &GcConfig {
                    max_deletions: 3,
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(
            report.chunks_deleted, 3,
            "the cap should be reached exactly"
        );

        for cid in &protected {
            assert!(
                store.has_chunk(cid).unwrap(),
                "a pinned chunk was collected under a deletion cap: {}",
                cid
            );
        }
        let survivors = collectable
            .iter()
            .filter(|c| store.has_chunk(c).unwrap())
            .count();
        assert_eq!(survivors, 2, "5 collectable chunks minus a cap of 3");
    }

    /// The same mix with no cap, so the scan runs to completion and every
    /// counter in the report is a true total.
    #[test]
    fn an_uncapped_pass_collects_everything_unprotected_and_nothing_else() {
        let (store, protected, collectable) = mixed_store();
        let gc = GarbageCollector::new(store.clone());

        let report = gc
            .collect(
                &protected,
                &GcConfig {
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(report.total_chunks_examined, 10);
        assert_eq!(report.chunks_deleted, 5);
        assert_eq!(
            report.protected_by_pins, 5,
            "a complete scan should account for every protected chunk"
        );

        for cid in &protected {
            assert!(store.has_chunk(cid).unwrap(), "pinned chunk collected");
        }
        for cid in &collectable {
            assert!(!store.has_chunk(cid).unwrap(), "unpinned chunk survived");
        }
    }

    /// A dry run is the thing operators use to decide whether to run for real,
    /// so its byte figure has to be true even though nothing is unlinked.
    #[test]
    fn a_dry_run_reports_real_byte_counts_without_deleting() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());

        let payloads: [&[u8]; 3] = [b"a", b"bbbb", b"cccccccc"];
        let expected: usize = payloads.iter().map(|p| p.len()).sum();
        for p in payloads {
            store.put_chunk(p, None).unwrap();
        }

        let dry = GcConfig {
            dry_run: true,
            min_chunk_age: Duration::ZERO,
            ..Default::default()
        };
        let report = gc.collect(&HashSet::new(), &dry).unwrap();

        assert_eq!(report.chunks_deleted, 3);
        assert_eq!(
            report.bytes_freed, expected,
            "a dry run must report the bytes a real run would reclaim"
        );

        // Now do it for real and confirm the estimate was honest.
        let wet = GcConfig {
            min_chunk_age: Duration::ZERO,
            ..Default::default()
        };
        let real = gc.collect(&HashSet::new(), &wet).unwrap();
        assert_eq!(real.bytes_freed, report.bytes_freed);
        assert_eq!(store.list_all_cids().unwrap().len(), 0);
    }

    /// Nothing protected and nothing stored is a legitimate state, not an edge
    /// case to trip over — a fresh node runs GC before it has any content.
    #[test]
    fn collecting_an_empty_store_is_a_clean_no_op() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());

        let report = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(report.total_chunks_examined, 0);
        assert_eq!(report.chunks_deleted, 0);
        assert_eq!(report.bytes_freed, 0);
        assert!(report.errors.is_empty());
    }

    /// An explicit `max_deletions: 0` means unlimited, not "delete nothing".
    #[test]
    fn a_zero_deletion_cap_means_unlimited() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());

        for i in 0..7 {
            store
                .put_chunk(format!("chunk-{}", i).as_bytes(), None)
                .unwrap();
        }

        let report = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    max_deletions: 0,
                    max_examined: 0,
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(report.chunks_deleted, 7);
        assert_eq!(store.list_all_cids().unwrap().len(), 0);
    }

    #[test]
    fn defaults_bound_work_and_do_not_retain_itemised_rows() {
        let config = GcConfig::default();
        assert_eq!(config.max_deletions, DEFAULT_GC_MAX_DELETIONS);
        assert!(config.max_deletions > 0);
        assert_eq!(config.max_examined, DEFAULT_GC_MAX_EXAMINED);
        assert!(config.max_examined > config.max_deletions);
        assert!(!config.collect_details);

        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());
        store.put_chunk(b"summary-only", None).unwrap();
        let report = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    min_chunk_age: Duration::ZERO,
                    ..config
                },
            )
            .unwrap();
        assert_eq!(report.chunks_deleted, 1);
        assert!(report.collected.is_empty());
    }

    #[test]
    fn finite_inventory_refuses_before_deleting_a_prefix() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());
        let cids = (0..3)
            .map(|i| {
                store
                    .put_chunk(format!("inventory-{i}").as_bytes(), None)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let error = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    max_deletions: 0,
                    max_examined: 2,
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            dag_core::CoreError::GcInventoryLimit { limit: 2 }
        ));
        assert!(
            cids.iter().all(|cid| store.has_chunk(cid).unwrap()),
            "an incomplete inventory must not delete even its known prefix"
        );
    }

    #[test]
    fn finite_inventory_byte_ceiling_refuses_before_deleting_anything() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());
        let first = store.put_chunk(b"four", None).unwrap();
        let second = store.put_chunk(b"also-four", None).unwrap();

        let error = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    max_bytes_examined: 5,
                    min_chunk_age: Duration::ZERO,
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            dag_core::CoreError::GcInventoryBytesLimit {
                limit: 5,
                required: 6..
            }
        ));
        assert!(store.has_chunk(&first).unwrap());
        assert!(store.has_chunk(&second).unwrap());
    }

    #[test]
    fn itemised_rows_are_an_explicit_bounded_choice() {
        let store = Arc::new(MockStore::default());
        let gc = GarbageCollector::new(store.clone());
        store.put_chunk(b"disposition", None).unwrap();
        let report = gc
            .collect(
                &HashSet::new(),
                &GcConfig {
                    max_deletions: 1,
                    min_chunk_age: Duration::ZERO,
                    collect_details: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(report.collected.len(), 1);
    }
}
