//! # Retention Management
//!
//! This module implements the retention index system for tracking which content
//! should be protected from garbage collection based on pin policies.
//!
//! ## Core Concepts
//!
//! - **RetentionIndex**: Main coordinator for retention queries and caching
//! - **RetentionCache**: In-memory snapshot of effective retention policies
//! - **EffectiveRetention**: Computed retention status for a specific CID
//! - **RetentionEpoch**: Timestamp-based cache invalidation mechanism
//!
//! ## Key Invariants
//!
//! ### R1: Epoch Consistency
//! All retention queries within the same epoch use the same pin snapshot.
//! This ensures GC sees consistent state even if pins change during collection.
//!
//! ### R2: Cache Invalidation
//! The cache is refreshed when:
//! - Explicit refresh is requested
//! - Cache TTL expires
//! - Pin log sequence advances significantly
//!
//! ### R3: Effective Retention Computation
//! For any CID, effective retention is the union of:
//! - All active, non-expired pins targeting it directly
//! - All active, non-expired subtree pins containing it
//! - System data protection (control logs, NodeLinks)
//!
//! ### R4: Subtree Expansion Limits
//! Subtree pin expansion is bounded by max_expansion to prevent runaway traversal
//! of large DAGs or cycles (though cycles can't form in content-addressed DAGs).

use super::pin::PinLog;
use dag_core::{Cid, ContentStore, PinEvent, PinScope, PinTarget};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Type alias for cache snapshot data structure
type CacheSnapshot = (
    HashMap<Cid, EffectiveRetention>,
    HashMap<String, HashMap<Cid, EffectiveRetention>>,
    Vec<IncompleteExpansion>,
);

/// Index for tracking effective retention policies across all pins
pub struct RetentionIndex<S: ContentStore> {
    /// Pin log for querying current pin states
    pin_log: Arc<PinLog<S>>,
    /// Content store for subtree expansion
    store: Arc<S>,
    /// Cached retention information
    cache: RwLock<RetentionCache>,
    /// Maximum number of CIDs to expand in subtree pins
    max_expansion: AtomicUsize,
}

/// Cached retention information with epoch-based invalidation
#[derive(Debug, Clone)]
struct RetentionCache {
    /// Global retention policies (scope: Global)
    global: HashMap<Cid, EffectiveRetention>,
    /// Local retention policies by node (scope: Local)
    local: HashMap<String, HashMap<Cid, EffectiveRetention>>,
    /// Cache creation epoch (POSIX seconds)
    epoch: i64,
    /// Cache TTL in seconds
    ttl_seconds: i64,
    /// Pins whose expansion hit the ceiling, so this snapshot names less than
    /// they actually cover.
    ///
    /// The snapshot is the *whole* input to a collection decision, so a
    /// partial one is not a smaller answer — it is a wrong one. Callers that
    /// delete must consult this; see `Control::run_gc`.
    incomplete: Vec<IncompleteExpansion>,
}

/// A pin whose subtree could not be enumerated within the configured ceiling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IncompleteExpansion {
    /// The pin whose coverage is understated.
    pub pin_id: String,
    /// How many CIDs were enumerated before the walk stopped.
    pub expanded: usize,
    /// The ceiling, when that is what stopped it.
    pub max_expansion: usize,
    /// Entries the walk could not read, when *that* is what stopped it.
    ///
    /// Empty for a ceiling stop. Non-empty means an entry inside the pinned
    /// subtree is absent or unreadable, so everything below it is unknown
    /// rather than absent — a permissions error or a bad sector must not
    /// quietly shrink the protected set.
    #[serde(default)]
    pub unreadable: Vec<String>,
}

/// Effective retention computed for a specific CID
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EffectiveRetention {
    /// Earliest expiry among contributing pins (None = never expires)
    pub earliest_expiry: Option<i64>,
    /// Pin IDs contributing to this retention (for debugging)
    pub sources: Vec<String>,
    /// Whether this is system-protected data
    pub is_system_protected: bool,
}

/// Status of retention for a specific CID
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum RetentionStatus {
    /// CID is not protected by any pins
    Unprotected,
    /// CID is protected by active pins
    Protected(EffectiveRetention),
}

/// Report from subtree expansion operation
#[derive(Debug, Clone)]
pub struct SubtreeExpansionReport {
    /// Number of CIDs expanded
    pub cids_expanded: usize,
    /// Maximum depth reached
    pub max_depth_reached: u32,
    /// Whether expansion was limited by max_expansion
    pub limited_by_max_expansion: bool,
    /// Entries the walk could not read, so it could not enumerate below them.
    ///
    /// Distinct from a leaf. Most content is not an entry and *correctly*
    /// ends a branch — a decode failure means "no children". An entry that
    /// is absent or unreadable means "children unknown", and treating the
    /// two alike is how a permissions error or a bad sector silently drops
    /// an entire pinned subtree out of the protected set.
    pub unreadable: Vec<Cid>,
}

impl<S: ContentStore + 'static> RetentionIndex<S> {
    /// Create a new RetentionIndex
    pub fn new(pin_log: Arc<PinLog<S>>, store: Arc<S>, max_expansion: usize) -> Self {
        let cache = RetentionCache {
            global: HashMap::new(),
            local: HashMap::new(),
            epoch: 0,
            ttl_seconds: 300, // 5 minutes default TTL
            incomplete: Vec::new(),
        };

        RetentionIndex {
            pin_log,
            store,
            cache: RwLock::new(cache),
            max_expansion: AtomicUsize::new(max_expansion),
        }
    }

    /// Set cache TTL in seconds
    pub fn set_cache_ttl(&self, ttl_seconds: i64) {
        let mut cache = self.cache.write();
        cache.ttl_seconds = ttl_seconds;
    }

    /// Ceiling on how many CIDs one pin's subtree may enumerate.
    pub fn max_expansion(&self) -> usize {
        self.max_expansion.load(Ordering::Relaxed)
    }

    /// Change the expansion ceiling. Takes effect at the next refresh.
    pub fn set_max_expansion(&self, max_expansion: usize) {
        self.max_expansion.store(max_expansion, Ordering::Relaxed);
    }

    /// Pins whose coverage the current snapshot understates.
    ///
    /// Empty means the snapshot is exact and safe to delete against.
    pub fn incomplete_expansions(&self) -> Vec<IncompleteExpansion> {
        self.cache.read().incomplete.clone()
    }

    /// Enumerate everything reachable from `root`, bounded by the same ceiling
    /// pins use.
    ///
    /// Exposed because a pointer head is a retention root too, and the caller
    /// that knows about pointers lives a layer up.
    pub fn expand_root(
        &self,
        root: &Cid,
    ) -> Result<(HashSet<Cid>, SubtreeExpansionReport), dag_core::PinError> {
        Self::expand_subtree_static(&*self.store, root, u32::MAX, self.max_expansion())
    }

    /// Enumerate everything reachable from *all* of `roots`, sharing one
    /// visited set and one ceiling across the whole walk.
    ///
    /// This is [`Self::expand_root`] for many roots at once. The sharing is not
    /// just an optimisation: N pointer heads resolving into one DAG are walked
    /// once between them rather than N times — the pointer-head closure was
    /// O(pointers x graph) before — and the ceiling bounds the *total*
    /// enumeration rather than each root independently.
    ///
    /// Exposed for the pointer-head closure, whose caller lives a layer up.
    pub fn expand_roots(
        &self,
        roots: &[Cid],
    ) -> Result<(HashSet<Cid>, SubtreeExpansionReport), dag_core::PinError> {
        Self::bfs_expand(
            &*self.store,
            roots.iter().cloned(),
            u32::MAX,
            self.max_expansion(),
        )
    }

    /// Get retention status for a specific CID
    pub fn status(&self, cid: &Cid) -> Result<RetentionStatus, dag_core::PinError> {
        // Ensure cache is fresh BEFORE taking any locks
        self.ensure_cache_fresh()?;

        // Take short-lived read lock just to copy relevant result
        let global_retention = {
            let cache = self.cache.read();
            cache.global.get(cid).cloned()
        };

        if let Some(retention) = global_retention {
            return Ok(RetentionStatus::Protected(retention));
        }

        // System data is always protected regardless of pins (no locks held during I/O)
        if self.is_system_protected(cid)? {
            let retention = EffectiveRetention {
                earliest_expiry: None, // Never expires
                sources: vec!["system-protection".to_string()],
                is_system_protected: true,
            };
            return Ok(RetentionStatus::Protected(retention));
        }

        Ok(RetentionStatus::Unprotected)
    }

    /// Get retention status for a specific node's local scope
    pub fn status_for_node(
        &self,
        cid: &Cid,
        node_id: &str,
    ) -> Result<RetentionStatus, dag_core::PinError> {
        // Ensure cache is fresh BEFORE taking any locks
        self.ensure_cache_fresh()?;

        // Take short-lived read lock just to copy relevant results
        let (global_retention, local_retention) = {
            let cache = self.cache.read();
            let global = cache.global.get(cid).cloned();
            let local = cache
                .local
                .get(node_id)
                .and_then(|node_map| node_map.get(cid))
                .cloned();
            (global, local)
        };

        // Check global retention first
        if let Some(retention) = global_retention {
            return Ok(RetentionStatus::Protected(retention));
        }

        // Then check local retention for this node
        if let Some(retention) = local_retention {
            return Ok(RetentionStatus::Protected(retention));
        }

        // Check system protection (no locks held during I/O)
        if self.is_system_protected(cid)? {
            let retention = EffectiveRetention {
                earliest_expiry: None,
                sources: vec!["system-protection".to_string()],
                is_system_protected: true,
            };
            return Ok(RetentionStatus::Protected(retention));
        }

        Ok(RetentionStatus::Unprotected)
    }

    /// Get the set of all CIDs protected for a specific node
    /// This is the main interface used by GC
    pub fn protected_set(&self, node_id: &str) -> Result<HashSet<Cid>, dag_core::PinError> {
        self.ensure_cache_fresh()?;
        let cache = self.cache.read();

        let mut protected = HashSet::new();

        // Add all globally protected CIDs
        protected.extend(cache.global.keys().cloned());

        // Add all locally protected CIDs for this node
        if let Some(node_retention) = cache.local.get(node_id) {
            protected.extend(node_retention.keys().cloned());
        }

        // Add system-protected CIDs
        // Note: This is a simplified approach. In production, you might want to
        // enumerate system CIDs more efficiently or track them separately.
        let system_protected = self.get_system_protected_cids()?;
        protected.extend(system_protected);

        Ok(protected)
    }

    /// Force refresh the retention cache
    pub fn refresh_cache(&self) -> Result<i64, dag_core::PinError> {
        let now = self.current_timestamp();

        // Build new cache snapshot off-lock to avoid deadlocks
        let new_cache_data = self.build_cache_snapshot(now)?;

        // Get TTL from current cache
        let ttl_seconds = { self.cache.read().ttl_seconds };

        // Create new cache with computed data
        let new_cache = RetentionCache {
            global: new_cache_data.0,
            local: new_cache_data.1,
            epoch: now,
            ttl_seconds,
            incomplete: new_cache_data.2,
        };

        // Quick atomic swap under write lock
        {
            *self.cache.write() = new_cache;
        }

        Ok(now)
    }

    /// Build cache snapshot without holding any locks
    fn build_cache_snapshot(&self, now: i64) -> Result<CacheSnapshot, dag_core::PinError> {
        // Get all active pins
        let pin_ids = self.pin_log.list()?;
        let mut global_retention = HashMap::new();
        let mut local_retention: HashMap<String, HashMap<Cid, EffectiveRetention>> = HashMap::new();
        let mut incomplete = Vec::new();
        let max_expansion = self.max_expansion();

        for pin_id in pin_ids {
            let head = self.pin_log.head(&pin_id)?;

            // Skip inactive or expired pins
            if !head.is_providing_retention(now) {
                continue;
            }

            let event = &head.event;

            // Expand the target to get all protected CIDs (off-lock)
            let (protected_cids, expansion) =
                Self::expand_target_static(&*self.store, &event.target, max_expansion)?;

            if expansion.limited_by_max_expansion {
                incomplete.push(IncompleteExpansion {
                    pin_id: pin_id.clone(),
                    expanded: expansion.cids_expanded,
                    max_expansion,
                    unreadable: Vec::new(),
                });
            }
            if !expansion.unreadable.is_empty() {
                // The same refusal, for the same reason: this snapshot names
                // less than the pin covers, and collection against it would
                // treat the remainder as unprotected.
                incomplete.push(IncompleteExpansion {
                    pin_id: pin_id.clone(),
                    expanded: expansion.cids_expanded,
                    max_expansion,
                    unreadable: expansion
                        .unreadable
                        .iter()
                        .map(|cid| cid.to_hex())
                        .collect(),
                });
            }

            // Create effective retention for this pin
            let retention = EffectiveRetention {
                earliest_expiry: event.expires_at,
                sources: vec![pin_id.clone()],
                is_system_protected: false,
            };

            // Add to appropriate scope
            match &event.scope {
                PinScope::Global => {
                    for cid in protected_cids {
                        Self::merge_retention_static(&mut global_retention, cid, &retention);
                    }
                }
                PinScope::Local { node_id } => {
                    let node_map = local_retention.entry(node_id.clone()).or_default();
                    for cid in protected_cids {
                        Self::merge_retention_static(node_map, cid, &retention);
                    }
                }
            }
        }

        Ok((global_retention, local_retention, incomplete))
    }

    /// Get current cache epoch
    pub fn cache_epoch(&self) -> i64 {
        self.cache.read().epoch
    }

    /// Check if cache is fresh
    pub fn is_cache_fresh(&self) -> bool {
        let cache = self.cache.read();
        let now = self.current_timestamp();
        now - cache.epoch < cache.ttl_seconds
    }

    /// Static version of expand_target for off-lock operations
    fn expand_target_static(
        store: &impl ContentStore,
        target: &PinTarget,
        max_expansion: usize,
    ) -> Result<(HashSet<Cid>, SubtreeExpansionReport), dag_core::PinError> {
        match target {
            PinTarget::Direct(cid) => {
                // A direct pin names one CID and walks nothing. Content whose
                // CID is a `file/v1` manifest is recorded as a subtree pin at
                // creation time instead (see `PinLog::create`) — deciding it
                // here would mean reading every directly-pinned chunk on every
                // retention refresh, and job output pins are direct.
                let mut result = HashSet::new();
                result.insert(cid.clone());
                Ok((
                    result,
                    SubtreeExpansionReport {
                        cids_expanded: 1,
                        max_depth_reached: 0,
                        limited_by_max_expansion: false,
                        // Walks nothing, so there is nothing it could fail to
                        // read.
                        unreadable: Vec::new(),
                    },
                ))
            }
            PinTarget::Subtree { root, max_depth } => Self::expand_subtree_static(
                store,
                root,
                max_depth.unwrap_or(u32::MAX),
                max_expansion,
            ),
        }
    }

    /// Breadth-first expansion of a single subtree, bounded by depth and by a
    /// hard ceiling on the number of CIDs. A one-root wrapper over
    /// [`Self::bfs_expand`].
    fn expand_subtree_static(
        store: &impl ContentStore,
        root: &Cid,
        max_depth: u32,
        hard_cap: usize,
    ) -> Result<(HashSet<Cid>, SubtreeExpansionReport), dag_core::PinError> {
        Self::bfs_expand(store, [root.clone()], max_depth, hard_cap)
    }

    /// Breadth-first walk from one or more roots that share a single visited
    /// set and a single ceiling — the core of both
    /// [`Self::expand_subtree_static`] and [`Self::expand_roots`].
    ///
    /// Returns what it found **and whether the ceiling stopped it**. The second
    /// half is not optional detail: this used to `break` at the ceiling and
    /// return the partial set indistinguishably from a complete one, so a pin
    /// (or pointer closure) over a graph larger than the ceiling silently
    /// protected a prefix and collection deleted the rest.
    ///
    /// The visited set is shared across all roots, which is what makes the
    /// many-root form cheap: N pointer heads over one DAG are walked once
    /// between them, not once each. It also means the ceiling bounds the
    /// *total* enumeration — a per-root ceiling would let N roots each expand
    /// `hard_cap` objects and still call the snapshot complete.
    fn bfs_expand(
        store: &impl ContentStore,
        roots: impl IntoIterator<Item = Cid>,
        max_depth: u32,
        hard_cap: usize,
    ) -> Result<(HashSet<Cid>, SubtreeExpansionReport), dag_core::PinError> {
        use std::collections::{HashSet, VecDeque};

        let mut out = HashSet::new();
        let mut seen = HashSet::new();
        let mut queue: VecDeque<(Cid, u32)> = roots.into_iter().map(|c| (c, 0u32)).collect();
        let mut max_depth_reached = 0u32;
        let mut limited = false;
        let mut unreadable: Vec<Cid> = Vec::new();

        while let Some((cid, depth)) = queue.pop_front() {
            // Skip if already seen
            if !seen.insert(cid.clone()) {
                continue;
            }

            // Hard cap to prevent runaway. Checked here, on a node we have
            // dequeued but not yet counted, so reaching it means there was
            // demonstrably more to enumerate — which is the fact the caller
            // needs. Checking after the insert instead would miss a linear
            // chain, where the queue is momentarily empty at the ceiling.
            if out.len() >= hard_cap {
                limited = true;
                break;
            }

            // Add to output set
            out.insert(cid.clone());
            max_depth_reached = max_depth_reached.max(depth);

            // Depth limit check
            if depth >= max_depth {
                continue;
            }

            // No locks held during I/O. Three outcomes, and conflating them
            // is a retention defect rather than an inefficiency:
            match store.get_links(&cid) {
                Ok(links) => {
                    for link in links {
                        if !seen.contains(&link.target) {
                            queue.push_back((link.target, depth + 1));
                        }
                    }
                }
                // Not an entry: a genuine leaf. This is the common case —
                // every chunk of file content lands here.
                Err(dag_core::CoreError::Deserialization(_)) => {}
                // Absent or unreadable: the children are *unknown*, not
                // absent. Record it so the caller can refuse to collect
                // against a snapshot that understates what the pin covers,
                // exactly as the expansion ceiling does.
                Err(_) => unreadable.push(cid.clone()),
            }
        }

        let report = SubtreeExpansionReport {
            cids_expanded: out.len(),
            max_depth_reached,
            limited_by_max_expansion: limited,
            unreadable,
        };
        Ok((out, report))
    }

    /// Static version of merge_retention for use in off-lock operations
    fn merge_retention_static(
        map: &mut HashMap<Cid, EffectiveRetention>,
        cid: Cid,
        new_retention: &EffectiveRetention,
    ) {
        match map.get_mut(&cid) {
            Some(existing) => {
                // Merge with existing retention
                existing.earliest_expiry =
                    match (existing.earliest_expiry, new_retention.earliest_expiry) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (None, _) | (_, None) => None, // If any pin never expires, result never expires
                    };
                existing.sources.extend_from_slice(&new_retention.sources);
                existing.is_system_protected =
                    existing.is_system_protected || new_retention.is_system_protected;
            }
            None => {
                map.insert(cid, new_retention.clone());
            }
        }
    }

    /// Ensure cache is fresh, refreshing if needed
    fn ensure_cache_fresh(&self) -> Result<(), dag_core::PinError> {
        if !self.is_cache_fresh() {
            self.refresh_cache()?;
        }
        Ok(())
    }

    /// Check if a CID represents system-protected data
    fn is_system_protected(&self, cid: &Cid) -> Result<bool, dag_core::PinError> {
        // System protection heuristic: check if this looks like a control-plane entry
        match self.store.get_entry(cid) {
            Ok(entry) => {
                // Check if the entry payload looks like serialized PinEvent or PointerEvent
                // This is a simple heuristic - in production you might want more sophisticated detection
                if self.looks_like_pin_event(&entry.payload)
                    || self.looks_like_pointer_event(&entry.payload)
                {
                    return Ok(true);
                }

                // Protect NodeLink entries (DAG structure)
                if !entry.links.is_empty() && entry.payload.is_empty() {
                    return Ok(true);
                }

                Ok(false)
            }
            Err(_) => {
                // If we can't read the entry, assume it's not system data
                Ok(false)
            }
        }
    }

    /// Get all system-protected CIDs
    ///
    /// Note: This is intentionally simplified for M4. In production, this would
    /// efficiently track control-plane CIDs (PinEvents, PointerEvents, NodeLinks)
    /// based on SystemDataPolicy configuration.
    fn get_system_protected_cids(&self) -> Result<HashSet<Cid>, dag_core::PinError> {
        // Return empty set for now - system protection is handled via policy in GC
        // Tests disable system protection anyway via SystemDataPolicy { enabled: false }
        Ok(HashSet::new())
    }

    /// Heuristic to detect if payload looks like a CBOR-encoded PinEvent
    fn looks_like_pin_event(&self, payload: &[u8]) -> bool {
        // Simple heuristic: try to deserialize as PinEvent
        dag_core::decode_cbor_exact::<PinEvent>(payload).is_ok()
    }

    /// Heuristic to detect if payload looks like a CBOR-encoded PointerEvent
    fn looks_like_pointer_event(&self, payload: &[u8]) -> bool {
        // Simple heuristic: try to deserialize as PointerEvent
        dag_core::decode_cbor_exact::<dag_core::PointerEvent>(payload).is_ok()
    }

    /// Get current timestamp
    fn current_timestamp(&self) -> i64 {
        crate::now_unix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_storage::FsStore;
    use tempfile::TempDir;

    fn setup_test() -> (
        RetentionIndex<FsStore>,
        Arc<PinLog<FsStore>>,
        TempDir,
        TempDir,
    ) {
        let storage_dir = TempDir::new().unwrap();
        let db_dir = TempDir::new().unwrap();

        let store = Arc::new(FsStore::new(storage_dir.path()).unwrap());
        let db = Arc::new(redb::Database::create(db_dir.path().join("control.redb")).unwrap());
        let pin_log = Arc::new(PinLog::new(store.clone(), db).unwrap());
        let retention_index = RetentionIndex::new(pin_log.clone(), store, 1000);

        (retention_index, pin_log, storage_dir, db_dir)
    }

    #[test]
    fn test_direct_pin_protection() {
        let (retention_index, pin_log, _storage_dir, _db_dir) = setup_test();
        let test_cid = retention_index
            .store
            .put_chunk(b"test-content", None)
            .unwrap();

        // Create a direct pin
        pin_log
            .create(
                "test-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        // Check retention status
        let status = retention_index.status(&test_cid).unwrap();
        match status {
            RetentionStatus::Protected(retention) => {
                assert!(retention.earliest_expiry.is_none());
                assert!(retention.sources.contains(&"test-pin".to_string()));
                assert!(!retention.is_system_protected);
            }
            RetentionStatus::Unprotected => panic!("Expected protection"),
        }
    }

    #[test]
    fn test_unprotected_cid() {
        let (retention_index, _pin_log, _storage_dir, _db_dir) = setup_test();
        let test_cid = Cid::compute(b"unprotected-content");

        // Check retention status for unpinned CID
        let status = retention_index.status(&test_cid).unwrap();
        assert!(matches!(status, RetentionStatus::Unprotected));
    }

    #[test]
    fn test_pin_expiry() {
        let (retention_index, pin_log, _storage_dir, _db_dir) = setup_test();
        let test_cid = retention_index
            .store
            .put_chunk(b"expiring-content", None)
            .unwrap();

        let now = crate::now_unix();
        let past_expiry = now - 1; // 1 second ago

        // Create an expired pin
        pin_log
            .create(
                "expired-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                Some(past_expiry),
                None,
            )
            .unwrap();

        // Should not be protected due to expiry
        let status = retention_index.status(&test_cid).unwrap();
        assert!(matches!(status, RetentionStatus::Unprotected));
    }

    #[test]
    fn test_cache_refresh() {
        let (retention_index, pin_log, _storage_dir, _db_dir) = setup_test();
        let test_cid = retention_index
            .store
            .put_chunk(b"cached-content", None)
            .unwrap();

        // Initial state - no pins
        let status1 = retention_index.status(&test_cid).unwrap();
        assert!(matches!(status1, RetentionStatus::Unprotected));

        // Create a pin
        pin_log
            .create(
                "cache-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        // Force cache refresh
        retention_index.refresh_cache().unwrap();

        // Should now be protected
        let status2 = retention_index.status(&test_cid).unwrap();
        assert!(matches!(status2, RetentionStatus::Protected(_)));
    }

    #[test]
    fn test_local_scope() {
        let (retention_index, pin_log, _storage_dir, _db_dir) = setup_test();
        let test_cid = retention_index
            .store
            .put_chunk(b"local-content", None)
            .unwrap();

        // Create a local pin
        pin_log
            .create(
                "local-pin",
                PinTarget::Direct(test_cid.clone()),
                PinScope::Local {
                    node_id: "node-A".to_string(),
                },
                None,
                None,
            )
            .unwrap();

        // Should be protected for node-A
        let status_a = retention_index
            .status_for_node(&test_cid, "node-A")
            .unwrap();
        assert!(matches!(status_a, RetentionStatus::Protected(_)));

        // Should not be protected for node-B
        let status_b = retention_index
            .status_for_node(&test_cid, "node-B")
            .unwrap();
        assert!(matches!(status_b, RetentionStatus::Unprotected));

        // Should not be protected globally
        let status_global = retention_index.status(&test_cid).unwrap();
        assert!(matches!(status_global, RetentionStatus::Unprotected));
    }

    #[test]
    fn test_protected_set() {
        let (retention_index, pin_log, _storage_dir, _db_dir) = setup_test();
        let cid1 = retention_index.store.put_chunk(b"content1", None).unwrap();
        let cid2 = retention_index.store.put_chunk(b"content2", None).unwrap();

        // Create pins
        pin_log
            .create(
                "global-pin",
                PinTarget::Direct(cid1.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        pin_log
            .create(
                "local-pin",
                PinTarget::Direct(cid2.clone()),
                PinScope::Local {
                    node_id: "node-A".to_string(),
                },
                None,
                None,
            )
            .unwrap();

        let protected = retention_index.protected_set("node-A").unwrap();

        assert!(protected.contains(&cid1)); // Global pin protects for all nodes
        assert!(protected.contains(&cid2)); // Local pin protects for node-A
        assert_eq!(protected.len(), 2);

        let protected_b = retention_index.protected_set("node-B").unwrap();
        assert!(protected_b.contains(&cid1)); // Global pin protects for all nodes
        assert!(!protected_b.contains(&cid2)); // Local pin doesn't protect for node-B
        assert_eq!(protected_b.len(), 1);
    }
}
