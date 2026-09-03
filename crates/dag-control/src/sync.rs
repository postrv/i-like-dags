//! Replication between two data directories.
//!
//! Content addressing makes this unusually cheap: the destination already
//! knows the name of every byte it holds, so "what is missing" is a set
//! difference over CIDs and needs no journal, no resume token and no
//! agreement about time. Re-running an interrupted sync *is* the resume.
//!
//! See `docs/decisions/adr-002-sync.md` for what moves, what deliberately does
//! not (trusted keys, jobs, the event journal), and why history is transferred
//! rather than replayed.
//!
//! ```no_run
//! use dag_control::{sync, Control};
//! use std::path::Path;
//!
//! let local = Control::open(Path::new(".dag"))?;
//! let backup = Control::open(Path::new("/Volumes/backup/dag"))?;
//!
//! let report = sync::push(&local, &backup, &sync::SyncOptions::default())?;
//! println!("{} chunks sent, {} already present", report.chunks_sent, report.chunks_skipped);
//! # Ok::<(), dag_control::ControlError>(())
//! ```

use std::collections::{HashMap, HashSet, VecDeque};

use dag_core::{Cid, ContentStore, PinScope, PinTarget};
#[cfg(test)]
use dag_core::{PinEvent, PointerEvent};
use serde::{Deserialize, Serialize};

use crate::error::{ControlError, Result};
use crate::pointer::PointerTriggerAuthority;
use crate::Control;

/// How a transfer should behave.
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// Report what would be transferred without writing anything.
    pub dry_run: bool,
    /// Cap on scheduled content-walk work. Zero selects the safe default;
    /// network-facing/local sync enumeration is never unbounded.
    ///
    /// A malformed or hostile graph could otherwise walk indefinitely. Exact
    /// duplicate coverage is pruned before I/O, while a CID reached later at a
    /// deeper policy depth is a new bounded work item.
    pub max_walk: usize,
    /// Identity whose local-scoped pins apply at the source.
    ///
    /// Global pins always apply. `Local { node_id }` pins root content only
    /// when their node ID equals this value. Pin event history still moves in
    /// either case: replication preserves provenance, but does not silently
    /// promote another node's local retention policy into a content root.
    pub source_node_id: String,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_walk: 1_000_000,
            source_node_id: "local".to_string(),
        }
    }
}

/// Why a source enumeration is only a prefix of the graph it intended to
/// offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncTruncation {
    /// Unique CIDs visited before stopping.
    pub visited: usize,
    /// Configured ceiling that stopped the walk.
    pub limit: usize,
    /// Frontier items known to remain when the ceiling was reached.
    ///
    /// This is diagnostic, not a count of all omitted descendants: those
    /// descendants were deliberately never read.
    pub remaining_frontier: usize,
}

/// What a transfer did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncReport {
    /// Chunks copied to the destination.
    pub chunks_sent: usize,
    /// Bytes copied.
    pub bytes_sent: u64,
    /// Chunks the destination already had.
    pub chunks_skipped: usize,
    /// Pointer event mappings newly filed.
    pub pointer_events: usize,
    /// Pin event mappings newly filed.
    pub pin_events: usize,
    /// Pointer heads rebuilt at the destination.
    pub pointers_rebuilt: u32,
    /// Pin heads rebuilt at the destination.
    pub pins_rebuilt: u32,
    /// Signature entries indexed at the destination.
    pub signatures_indexed: u32,
    /// Effect-claim entries indexed at the destination (ADR-003).
    #[serde(default)]
    pub claims_indexed: u32,
    /// Chunks that failed to transfer, with the reason.
    ///
    /// A failure here is isolated to that chunk during copying: one unreadable
    /// chunk on a failing source disk does not stop the rest reaching safety.
    /// It does block event/head publication for this run. Re-running retries
    /// exactly these, because they are still missing.
    pub failures: Vec<SyncFailure>,
    /// Event mappings the destination already filed under a *different* CID.
    ///
    /// Not a missing chunk and not retryable: two independent seeds of the
    /// same pointer name produce different event CIDs (`ts` is on the event),
    /// and the replica will not overwrite the chain it already has. Content
    /// may still match. Counted apart from [`Self::failures`] so "re-run to
    /// retry" is not the advice.
    #[serde(default)]
    pub divergent: Vec<SyncFailure>,
    /// Chunks the source's own history names but no longer holds.
    ///
    /// Not failures, by design: pointer history is permanent while
    /// superseded bytes are collectable, so a source that has ever collected
    /// old revisions will name chunks it cannot produce — for ever. The
    /// provenance log still transfers whole; these are the bytes behind it
    /// that are gone *at the source*, reported so the replica knows exactly
    /// what it does not have. (Before this category existed they were
    /// counted as failures, and one routine collection made every later
    /// sync exit non-zero permanently.)
    #[serde(default)]
    pub missing_at_source: Vec<String>,
    /// Present when the source's graph walk hit its safety ceiling.
    ///
    /// A truncated transfer may still copy useful chunks, but it is never
    /// complete and never imports events or publishes rebuilt heads.
    #[serde(default)]
    pub truncation: Option<SyncTruncation>,
    /// Whether publication of event-derived heads/indexes was deliberately
    /// withheld because the offered snapshot was incomplete or refused.
    #[serde(default)]
    pub publication_blocked: bool,
    /// Whether anything was actually written.
    pub dry_run: bool,
}

/// One chunk that did not make it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFailure {
    /// The chunk that failed.
    pub cid: String,
    /// Why.
    pub reason: String,
}

impl SyncReport {
    /// True only for a complete, non-divergent, publishable enumeration.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
            && self.divergent.is_empty()
            && self.truncation.is_none()
            && !self.publication_blocked
    }
}

/// Copy everything `local` has that `remote` lacks.
pub fn push(local: &Control, remote: &Control, opts: &SyncOptions) -> Result<SyncReport> {
    transfer(local, remote, opts)
}

/// Copy everything `remote` has that `local` lacks.
///
/// Identical to [`push`] with the arguments swapped — replication is
/// one-directional per invocation, and which side is "ours" is the caller's
/// business.
pub fn pull(local: &Control, remote: &Control, opts: &SyncOptions) -> Result<SyncReport> {
    transfer(remote, local, opts)
}

/// The engine behind [`push`] and [`pull`], for two open directories.
///
/// A thin wrapper over [`replicate`], which is generic over where each side
/// lives; `Control` implements both sides. The destination is wrapped in a
/// [`BulkDestination`] so chunk writes defer their fsyncs to one flush at the
/// durability barrier — durable-per-chunk writes cost ~16 ms of fsync per
/// chunk (measured), which made a small-chunk sync sixty chunks a second, and
/// a transfer is exactly the replayable workload deferral is safe for.
pub fn transfer(from: &Control, to: &Control, opts: &SyncOptions) -> Result<SyncReport> {
    replicate(from, &BulkDestination::new(to)?, opts)
}

/// A sync destination writing through a deferred staging store.
///
/// Chunk writes skip their per-write fsyncs; [`SyncDestination::flush`]
/// settles all of them — files, directories and index entries — before the
/// engine files a single event. Validation is untouched: imports and
/// finalize delegate to the underlying [`Control`], and each one flushes
/// first if anything is still pending, so even a caller that skips the
/// barrier cannot file an event over unflushed bytes.
pub struct BulkDestination<'a> {
    control: &'a Control,
    staging: dag_storage::FsStore,
}

impl<'a> BulkDestination<'a> {
    /// Wrap `control` for one transfer.
    pub fn new(control: &'a Control) -> Result<Self> {
        Ok(Self {
            control,
            staging: control.staging_store()?,
        })
    }
}

impl SyncDestination for BulkDestination<'_> {
    fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>> {
        SyncDestination::missing(self.control, cids)
    }

    fn store_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<()> {
        let written = self.staging.put_chunk(bytes, None)?;
        if &written != cid {
            return Err(ControlError::Invalid(format!(
                "chunk {} arrived as {}: content does not match its address",
                cid, written
            )));
        }
        self.control.metrics.sync_chunks_received_total.inc();
        self.control
            .metrics
            .sync_bytes_received_total
            .add(bytes.len() as u64);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.staging.sync()?;
        Ok(())
    }

    fn probe_pointer_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        SyncDestination::probe_pointer_events(self.control, events)
    }

    fn probe_pin_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        SyncDestination::probe_pin_events(self.control, events)
    }

    fn import_pointer_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "native event publication requires a complete atomic batch".into(),
        ))
    }

    fn import_pin_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "native event publication requires a complete atomic batch".into(),
        ))
    }

    fn import_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<EventBatchOutcome> {
        // `Control` owns the lock order: mutation barrier first, then the
        // shared durability coordinator. Wrapping this call in a durability
        // barrier here would invert that order against a normal pointer/pin
        // writer (mutation read -> content write) and can deadlock.
        self.control
            .publish_durable_sync_snapshot(pointer_events, pin_events)
            .map(|(outcome, _counts)| outcome)
    }

    fn publish_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        index_candidates: &[Cid],
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        self.control.publish_durable_sync_snapshot_with_candidates(
            pointer_events,
            pin_events,
            index_candidates,
        )
    }

    fn finalize(&self) -> Result<RebuildCounts> {
        self.control.finalize_durable_sync()
    }
}

/// Upper bound on how many CIDs one [`SyncDestination::missing`] call carries.
///
/// A truthful destination answer requires reading and hashing the held bytes,
/// not trusting a path or index entry. At the 4 MiB chunk ceiling, 16 CIDs
/// bound one local or gRPC check to 64 MiB of integrity work.
pub const MISSING_BATCH: usize = 16;

/// Event probes touch only bounded control-plane metadata, so they retain the
/// larger wire batch that missing checks used before those became verified.
pub const PROBE_BATCH: usize = 4096;
/// Complete pointer+pin history refs accepted by one atomic publication.
pub const MAX_SYNC_EVENT_REFS: usize = 65_536;
/// Aggregate retained bytes for the bounded event-ref snapshot.
pub const MAX_SYNC_EVENT_REF_BYTES: usize = 64 * 1024 * 1024;
/// Aggregate raw pointer-event entry bytes that one sync enumeration may
/// inspect while recovering direct historical target hints.
///
/// This matches incremental publication's event-read ceiling. The bytes are
/// charged before Entry/CBOR decoding, so an event with oversized auxiliary
/// structure cannot hide work behind a small pointer payload.
pub const MAX_SYNC_POINTER_EVENT_READ_BYTES: usize = 64 * 1024 * 1024;

/// Maximum strict signature/effect records one sync publication may ask the
/// destination to classify and merge. The source normally supplies only the
/// handful discovered by its bounded graph walk, but a remote hint is never
/// trusted to remain small.
pub const MAX_SYNC_INDEX_CANDIDATES: usize = 65_536;
/// Aggregate immutable bytes decoded while preparing one sync's auxiliary
/// index rows. Publication holds exclusive mutation/durability barriers, so
/// this is also a hard latency/availability contract for hostile candidates.
pub const MAX_SYNC_INDEX_CANDIDATE_BYTES: usize = 256 * 1024 * 1024;

/// Everything a source offers a destination: event mappings, event entries,
/// current-root closure, direct historical pointer targets, and supporting
/// signatures (duplicates allowed; the engine deduplicates).
#[derive(Debug, Clone, Default)]
pub struct SyncEnumeration {
    /// `(pointer_id, seq, event_cid)` for every pointer event.
    pub pointer_events: Vec<(String, u64, Cid)>,
    /// `(pin_id, seq, event_cid)` for every pin event.
    pub pin_events: Vec<(String, u64, Cid)>,
    /// Every chunk the transfer should offer, in offer order.
    ///
    /// This includes direct targets recovered from readable superseded
    /// pointer events. Those historical hints are not recursively walked and
    /// are not required-live: if the source has collected one, replication
    /// reports it through [`SyncReport::missing_at_source`] and may still
    /// publish the intact current state.
    pub wanted: Vec<Cid>,
    /// CIDs required to publish the offered live state safely.
    ///
    /// This is the complete closure of current pointer heads and applicable
    /// active pins, plus event entries and signatures needed to preserve that
    /// state. Direct superseded-history targets are deliberately excluded:
    /// source-side collection of one is expected and harmless
    /// ([`SyncReport::missing_at_source`]). An absent CID in this set blocks
    /// event import and head publication.
    ///
    /// The field keeps its historical name for source/API compatibility.
    pub live_roots: Vec<Cid>,
    /// Strict signature/effect-claim entries whose derived lookup rows must
    /// be merged in the same publication as this transfer's event mappings.
    /// This is deliberately narrower than `wanted`: bulk content does not
    /// need classification work at the destination.
    pub index_candidates: Vec<Cid>,
    /// Set when the graph walk stopped at [`SyncOptions::max_walk`].
    pub truncation: Option<SyncTruncation>,
}

/// One destination event position that already names a different CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventConflict {
    /// Event-log identifier.
    pub id: String,
    /// Event sequence number.
    pub seq: u64,
    /// CID the source offered.
    pub offered: Cid,
    /// CID already filed by the destination.
    pub existing: Cid,
}

/// What [`SyncDestination::finalize`] rebuilt from the events that arrived.
#[derive(Debug, Clone, Copy, Default)]
pub struct RebuildCounts {
    /// Pointer heads rebuilt.
    pub pointers_rebuilt: u32,
    /// Pin heads rebuilt.
    pub pins_rebuilt: u32,
    /// Signature entries indexed.
    pub signatures_indexed: u32,
    /// Effect-claim entries indexed (ADR-003).
    pub claims_indexed: u32,
}

/// Result of crossing the event-log publication barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBatchOutcome {
    /// Every new mapping was committed in one transaction. Counts exclude
    /// mappings that were already filed under the same CID.
    Applied {
        pointer_events: usize,
        pin_events: usize,
    },
    /// Validation refused one member; no member of the offered batch was
    /// published by an atomic destination.
    Rejected(EventBatchRejection),
}

struct SyncAuxiliaryCandidates {
    signature_targets: HashMap<Cid, Vec<Cid>>,
    claim_keys: HashMap<Vec<u8>, Vec<Cid>>,
    classified_cids: Vec<Cid>,
}

/// Structured validation refusal from an atomic event offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBatchRejection {
    pub kind: String,
    pub id: String,
    pub seq: u64,
    pub cid: Cid,
    pub reason: String,
    pub divergent: bool,
}

/// The reading side of a replication: where content and history come from.
///
/// `Control` implements this for a local directory; a network client
/// implements it against a remote node (ADR-005). Everything [`replicate`]
/// needs from a source is here, so the engine cannot care where the bytes
/// live.
pub trait SyncSource {
    /// Enumerate what this source offers. Immutable pointer event history and
    /// its direct target hints are included, not just heads; recursive content
    /// traversal is reserved for current live roots.
    fn enumerate(&self, opts: &SyncOptions) -> Result<SyncEnumeration>;

    /// Size of one chunk without transferring it — what a dry run reports.
    fn chunk_len(&self, cid: &Cid) -> Result<usize>;

    /// The chunk's bytes.
    fn fetch_chunk(&self, cid: &Cid) -> Result<Vec<u8>>;
}

/// The writing side of a replication.
///
/// **This trait carries the ADR-002 trust boundary.** The import methods run
/// in the destination's own process with the full `import_event` validation —
/// chain integrity, right-id-right-seq, divergence refused. A remote peer
/// implementing [`SyncSource`] can therefore never file history the
/// destination itself would refuse; the gRPC server (ADR-005) implements this
/// trait by running exactly the validation `Control` runs locally.
pub trait SyncDestination {
    /// The subset of `cids` this destination lacks. Called in batches of at
    /// most [`MISSING_BATCH`].
    fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>>;

    /// Store one chunk, verifying the bytes hash to `cid`. A mismatch is an
    /// error naming both CIDs, and fails that chunk alone.
    fn store_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<()>;

    /// Make every stored chunk durable before any event names one.
    ///
    /// The engine calls this once, between the chunk phase and the event
    /// phase. A destination that writes durably per chunk needs nothing here
    /// (the default); one that defers durability for throughput flushes now,
    /// so the ordering invariant — the log never names bytes that are not on
    /// disk — holds across the whole transfer, not per write.
    fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Read-only conflict check for a bounded batch of pointer events.
    ///
    /// `None` means this destination cannot probe without writing; dry-run
    /// remains non-mutating but cannot promise conflict discovery there.
    fn probe_pointer_events(
        &self,
        _events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        Ok(None)
    }

    /// Read-only conflict check for a bounded batch of pin events.
    fn probe_pin_events(
        &self,
        _events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        Ok(None)
    }

    /// Stage one pointer event inside a destination-owned transaction.
    ///
    /// This compatibility hook exists for the Edge session protocol. A
    /// canonical destination must leave the fail-closed default in place and
    /// implement [`Self::import_event_batch`] atomically instead.
    fn import_pointer_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "event publication requires a complete atomic batch".into(),
        ))
    }

    /// Pin counterpart of [`Self::import_pointer_event`].
    fn import_pin_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "event publication requires a complete atomic batch".into(),
        ))
    }

    /// Validate and stage or commit the complete pointer+pin offer as one
    /// publication unit. Native and gRPC destinations override this with a
    /// single database transaction. The default preserves the Edge session
    /// protocol, whose imports remain invisible until its atomic finalize.
    fn import_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<EventBatchOutcome> {
        let mut pointer_imported = 0;
        let mut pin_imported = 0;
        for (id, seq, cid) in pointer_events {
            match self.import_pointer_event(id, *seq, cid) {
                Ok(true) => pointer_imported += 1,
                Ok(false) => {}
                Err(error) => {
                    return Ok(EventBatchOutcome::Rejected(batch_rejection(
                        "pointer", id, *seq, cid, error,
                    )))
                }
            }
        }
        for (id, seq, cid) in pin_events {
            match self.import_pin_event(id, *seq, cid) {
                Ok(true) => pin_imported += 1,
                Ok(false) => {}
                Err(error) => {
                    return Ok(EventBatchOutcome::Rejected(batch_rejection(
                        "pin", id, *seq, cid, error,
                    )))
                }
            }
        }
        Ok(EventBatchOutcome::Applied {
            pointer_events: pointer_imported,
            pin_events: pin_imported,
        })
    }

    /// Publish one complete event offer together with the bounded immutable
    /// records that need signature/effect lookup rows. Canonical native and
    /// gRPC destinations override this with one database transaction. The
    /// default preserves the sessionful Edge protocol by staging events and
    /// then invoking its atomic finalize endpoint.
    fn publish_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        _index_candidates: &[Cid],
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        let outcome = self.import_event_batch(pointer_events, pin_events)?;
        if matches!(outcome, EventBatchOutcome::Rejected(_)) {
            return Ok((outcome, RebuildCounts::default()));
        }
        let counts = self.finalize()?;
        Ok((outcome, counts))
    }

    /// Rebuild derived state (heads and indexes) from whatever arrived.
    fn finalize(&self) -> Result<RebuildCounts>;
}

/// The replication engine, generic over where each side lives.
///
/// Order matters. Content moves before the event mappings that name it, so a
/// mapping is never filed for an event whose chunk did not arrive — that is
/// enforced again inside `import_event`. A partial or truncated content phase
/// is flushed as resumable progress but crosses no event/publication barrier.
/// Derived state is rebuilt last, only after every offered chunk and event was
/// accepted.
pub fn replicate<S, D>(from: &S, to: &D, opts: &SyncOptions) -> Result<SyncReport>
where
    S: SyncSource + ?Sized,
    D: SyncDestination + ?Sized,
{
    let started = std::time::Instant::now();
    let mut report = SyncReport {
        dry_run: opts.dry_run,
        ..Default::default()
    };

    // 1. What the source offers: events, reachable content, signatures.
    let SyncEnumeration {
        pointer_events,
        pin_events,
        wanted,
        live_roots,
        index_candidates,
        truncation,
    } = from.enumerate(opts)?;
    report.truncation = truncation;

    // A CID a live root names is not "collected history" however absent it
    // is; see `SyncEnumeration::live_roots`.
    let live: HashSet<String> = live_roots.iter().map(|cid| cid.to_hex()).collect();

    // 2. Deduplicate preserving offer order.
    let mut seen = HashSet::new();
    let wanted: Vec<Cid> = wanted
        .into_iter()
        .filter(|cid| seen.insert(cid.to_hex()))
        .collect();
    let wanted_set: HashSet<Cid> = wanted.iter().cloned().collect();
    let mut candidate_seen = HashSet::new();
    let index_candidates: Vec<Cid> = index_candidates
        .into_iter()
        .filter(|cid| candidate_seen.insert(cid.clone()))
        .collect();
    if index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
        return Err(ControlError::Capacity(format!(
            "sync offered {} signature/effect index candidates, above the {MAX_SYNC_INDEX_CANDIDATES}-record publication limit",
            index_candidates.len()
        )));
    }
    if index_candidates
        .iter()
        .any(|candidate| !wanted_set.contains(candidate))
    {
        return Err(ControlError::Invalid(
            "sync enumeration named an index candidate outside its content offer".into(),
        ));
    }

    // 3. One set difference, in bounded batches — the destination answers
    //    "which of these do you lack", which over a network is the batch
    //    endpoint whose absence ADR-002 objected to.
    let mut missing: HashSet<String> = HashSet::new();
    for batch in wanted.chunks(MISSING_BATCH) {
        for cid in to.missing(batch)? {
            missing.insert(cid.to_hex());
        }
    }

    // 4. Move (or, dry, measure) exactly the missing chunks. A failure is
    //    per-chunk, never fatal: one unreadable chunk on a failing source
    //    disk must not stop the rest reaching safety.
    for cid in &wanted {
        if !missing.contains(&cid.to_hex()) {
            report.chunks_skipped += 1;
            continue;
        }
        let outcome = if opts.dry_run {
            from.chunk_len(cid)
        } else {
            from.fetch_chunk(cid).and_then(|bytes| {
                to.store_chunk(cid, &bytes)?;
                Ok(bytes.len())
            })
        };
        match outcome {
            Ok(size) => {
                report.chunks_sent += 1;
                report.bytes_sent += size as u64;
            }
            // The source itself no longer holds it. Collected history is
            // expected and not a failure — but a CID a *live* root names is
            // a dangling head at the replica, which is.
            Err(ControlError::Core(dag_core::CoreError::ChunkNotFound(_)))
                if !live.contains(&cid.to_hex()) =>
            {
                report.missing_at_source.push(cid.to_hex());
            }
            Err(e) => report.failures.push(SyncFailure {
                cid: cid.to_hex(),
                reason: e.to_string(),
            }),
        }
    }

    if opts.dry_run {
        probe_dry_run(to, &pointer_events, &pin_events, &mut report)?;
        log_replication(&report, started);
        return Ok(report);
    }

    // 5. Durability barrier: every chunk that moved becomes durable before a
    //    single event mapping can name one. A failure here is fatal to the
    //    transfer rather than per-chunk — filing events over unflushed bytes
    //    is the one state this engine must never produce.
    to.flush()?;

    // A prefix is useful resumable progress, not a publishable snapshot. The
    // same is true after any attempted chunk failed: importing even the event
    // chunks that did arrive could make a later finalize expose a head before
    // its required closure or evidence is present. Keep the bytes, withhold
    // every mapping and derived head, and let a subsequent complete run cross
    // the publication barrier.
    if report.truncation.is_some() || !report.failures.is_empty() {
        report.publication_blocked = true;
        log_replication(&report, started);
        return Ok(report);
    }

    // 6. Validate and publish the complete event offer atomically. Sorting by
    //    sequence lets validation consume predecessor mappings from this same
    //    prospective transaction. A later invalid event cannot leave a
    //    canonical prefix for an unrelated finalize to expose.
    let mut pointer_events = pointer_events;
    pointer_events.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    let mut pin_events = pin_events;
    pin_events.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    let (publication, counts) =
        to.publish_event_batch(&pointer_events, &pin_events, &index_candidates)?;
    match publication {
        EventBatchOutcome::Applied {
            pointer_events,
            pin_events,
        } => {
            report.pointer_events = pointer_events;
            report.pin_events = pin_events;
        }
        EventBatchOutcome::Rejected(rejection) => {
            push_batch_rejection(&mut report, rejection);
        }
    }

    // Imports are add-only, but they can still be refused because the
    // destination owns a divergent history or because an offered chain is
    // malformed. Do not rebuild any head from a partially accepted batch.
    if !report.failures.is_empty() || !report.divergent.is_empty() {
        report.publication_blocked = true;
        log_replication(&report, started);
        return Ok(report);
    }

    // 7. The atomic publication above derived affected heads and merged the
    //    offered evidence indexes. No second, sessionless whole-store
    //    finalize is needed (or permitted by canonical native transports).
    report.pointers_rebuilt = counts.pointers_rebuilt;
    report.pins_rebuilt = counts.pins_rebuilt;
    report.signatures_indexed = counts.signatures_indexed;
    report.claims_indexed = counts.claims_indexed;

    log_replication(&report, started);
    Ok(report)
}

/// `OfferError::Divergent` / `PointerError::AlreadyExists` as the HTTP
/// stand-in and the laptop `import_event` both phrase it.
fn is_divergent_history(err: &ControlError) -> bool {
    let s = err.to_string();
    s.contains("already names") && s.contains("refusing to replace")
}

fn batch_rejection(
    kind: &str,
    id: &str,
    seq: u64,
    cid: &Cid,
    error: ControlError,
) -> EventBatchRejection {
    EventBatchRejection {
        kind: kind.to_string(),
        id: id.to_string(),
        seq,
        cid: cid.clone(),
        reason: error.to_string(),
        divergent: is_divergent_history(&error),
    }
}

fn validate_sync_publication_shape(
    pointer_events: &[(String, u64, Cid)],
    pin_events: &[(String, u64, Cid)],
    index_candidates: &[Cid],
) -> Result<()> {
    let event_refs = pointer_events
        .len()
        .checked_add(pin_events.len())
        .ok_or_else(|| ControlError::Capacity("sync event-ref count overflow".into()))?;
    if event_refs > MAX_SYNC_EVENT_REFS {
        return Err(ControlError::Capacity(format!(
            "sync publication contains {event_refs} pointer/pin refs; limit is {MAX_SYNC_EVENT_REFS}"
        )));
    }
    let event_bytes =
        pointer_events
            .iter()
            .chain(pin_events)
            .try_fold(0usize, |total, (id, _, _)| {
                total
                    .checked_add(id.len())
                    .and_then(|total| total.checked_add(std::mem::size_of::<u64>() + 32))
                    .ok_or_else(|| {
                        ControlError::Capacity("sync event-ref byte count overflow".into())
                    })
            })?;
    if event_bytes > MAX_SYNC_EVENT_REF_BYTES {
        return Err(ControlError::Capacity(format!(
            "sync publication contains {event_bytes} event-ref bytes; limit is {MAX_SYNC_EVENT_REF_BYTES}"
        )));
    }
    if index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
        return Err(ControlError::Capacity(format!(
            "sync publication has {} index candidates, above the {MAX_SYNC_INDEX_CANDIDATES}-record limit",
            index_candidates.len()
        )));
    }
    Ok(())
}

fn push_batch_rejection(report: &mut SyncReport, rejection: EventBatchRejection) {
    let item = SyncFailure {
        cid: rejection.cid.to_hex(),
        reason: format!(
            "{} {} seq {}: {}",
            rejection.kind, rejection.id, rejection.seq, rejection.reason
        ),
    };
    if rejection.divergent {
        report.divergent.push(item);
    } else {
        report.failures.push(item);
    }
}

/// Ask a destination what a dry run can learn without importing anything.
///
/// Probes are bounded like missing-set queries. A destination may return
/// `None` for an unsupported event kind; that is deliberately not a failure,
/// because HTTP Edge replicas predating the probe endpoint can still provide
/// a truthful byte-transfer plan. Local and gRPC destinations implement it.
fn probe_dry_run<D: SyncDestination + ?Sized>(
    to: &D,
    pointer_events: &[(String, u64, Cid)],
    pin_events: &[(String, u64, Cid)],
    report: &mut SyncReport,
) -> Result<()> {
    for batch in pointer_events.chunks(PROBE_BATCH) {
        let Some(conflicts) = to.probe_pointer_events(batch)? else {
            break;
        };
        for conflict in conflicts {
            report.divergent.push(conflict_failure("pointer", conflict));
        }
    }
    for batch in pin_events.chunks(PROBE_BATCH) {
        let Some(conflicts) = to.probe_pin_events(batch)? else {
            break;
        };
        for conflict in conflicts {
            report.divergent.push(conflict_failure("pin", conflict));
        }
    }
    Ok(())
}

fn conflict_failure(kind: &str, conflict: EventConflict) -> SyncFailure {
    SyncFailure {
        cid: conflict.offered.to_hex(),
        reason: format!(
            "{kind} {} seq {} already names {}, refusing to replace it with {}",
            conflict.id, conflict.seq, conflict.existing, conflict.offered
        ),
    }
}

/// One structured line per transfer — the fields a log pipeline indexes.
fn log_replication(report: &SyncReport, started: std::time::Instant) {
    tracing::info!(
        target: "dag::sync",
        chunks_sent = report.chunks_sent,
        bytes_sent = report.bytes_sent,
        chunks_skipped = report.chunks_skipped,
        pointer_events = report.pointer_events,
        pin_events = report.pin_events,
        failures = report.failures.len(),
        divergent = report.divergent.len(),
        truncated = report.truncation.is_some(),
        publication_blocked = report.publication_blocked,
        dry_run = report.dry_run,
        duration_ms = started.elapsed().as_millis() as u64,
        "replication complete"
    );
}

/// One walk root and how far its retention policy permits traversal.
/// `None` is unbounded; `Some(0)` is the CID itself only.
#[derive(Debug, Clone)]
struct WalkRoot {
    cid: Cid,
    max_depth: Option<u32>,
}

#[derive(Debug)]
struct WalkResult {
    cids: Vec<Cid>,
    index_candidates: Vec<Cid>,
    truncation: Option<SyncTruncation>,
}

/// Pointer history and effective pin roots, split into all offered history and
/// the subset required by the currently published state.
#[cfg(test)]
fn collect_roots(
    from: &Control,
    source_node_id: &str,
    now: i64,
) -> Result<(Vec<WalkRoot>, Vec<WalkRoot>)> {
    let mut roots = Vec::new();
    let mut live = Vec::new();

    for id in from.pointer_log.list_pointers()? {
        let head = from.pointer_log.get_head(&id)?;
        for event in from.pointer_log.history(&id, 1..head.seq + 1)? {
            roots.push(WalkRoot {
                cid: event.new,
                max_depth: None,
            });
        }
        live.push(WalkRoot {
            cid: head.current_cid,
            max_depth: None,
        });
    }

    for id in from.pin_log.list()? {
        let head = from.pin_log.head(&id)?;
        let scope_applies = match &head.event.scope {
            PinScope::Global => true,
            PinScope::Local { node_id } => node_id == source_node_id,
        };
        if !scope_applies || !head.is_providing_retention(now) {
            continue;
        }

        let root = match &head.event.target {
            PinTarget::Direct(cid) => WalkRoot {
                cid: cid.clone(),
                max_depth: Some(0),
            },
            PinTarget::Subtree { root, max_depth } => WalkRoot {
                cid: root.clone(),
                max_depth: *max_depth,
            },
        };
        roots.push(root.clone());
        live.push(root);
    }

    Ok((roots, live))
}

/// Current published roots for protocol-v3 content enumeration. Event
/// history travels independently in bounded pages; this function therefore
/// never loads or decodes historical events.
fn collect_current_roots(
    from: &Control,
    source_node_id: &str,
    now: i64,
    max_roots: usize,
) -> Result<(Vec<WalkRoot>, bool)> {
    const ID_PAGE: usize = 1_024;
    let mut roots = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let ids = from
            .pointer_log
            .list_pointers_page(after.as_deref(), ID_PAGE)?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            roots.push(WalkRoot {
                cid: from.pointer_log.get_head(id)?.current_cid,
                max_depth: None,
            });
            if max_roots != 0 && roots.len() > max_roots {
                return Ok((roots, true));
            }
        }
        if ids.len() < ID_PAGE {
            break;
        }
        after = ids.last().cloned();
    }

    let mut after: Option<String> = None;
    loop {
        let ids = from.pin_log.list_page(after.as_deref(), ID_PAGE)?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            let head = from.pin_log.head(id)?;
            let scope_applies = match &head.event.scope {
                PinScope::Global => true,
                PinScope::Local { node_id } => node_id == source_node_id,
            };
            if !scope_applies || !head.is_providing_retention(now) {
                continue;
            }
            roots.push(match &head.event.target {
                PinTarget::Direct(cid) => WalkRoot {
                    cid: cid.clone(),
                    max_depth: Some(0),
                },
                PinTarget::Subtree { root, max_depth } => WalkRoot {
                    cid: root.clone(),
                    max_depth: *max_depth,
                },
            });
            if max_roots != 0 && roots.len() > max_roots {
                return Ok((roots, true));
            }
        }
        if ids.len() < ID_PAGE {
            break;
        }
        after = ids.last().cloned();
    }
    Ok((roots, false))
}

/// Whether a previously expanded depth covers a newly encountered one.
fn depth_covers(existing: Option<u32>, candidate: Option<u32>) -> bool {
    match (existing, candidate) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => a >= b,
    }
}

fn next_depth(depth: Option<u32>) -> Option<Option<u32>> {
    match depth {
        None => Some(None),
        Some(0) => None,
        Some(n) => Some(Some(n - 1)),
    }
}

/// Breadth-first walk over entry links with per-root depth policies.
///
/// A chunk that does not decode as an entry is a leaf — most content is —
/// which is not an error, so decode failures end that branch rather than the
/// walk. CIDs are emitted once, while a CID first seen through a shallow pin
/// may be expanded again if a deeper or unbounded root later reaches it.
/// Scheduling deduplicates equal or shallower coverage before either queue
/// growth or chunk I/O. Every accepted depth upgrade is charged as work, so
/// adversarial fan-in cannot hide repeated reads behind the unique-CID count.
/// Reaching `max_walk` while work remains is explicit truncation, never a
/// successful partial result.
fn walk(from: &Control, roots: &[WalkRoot], max_walk: usize) -> Result<WalkResult> {
    let mut discovered: HashSet<Cid> = HashSet::new();
    let mut expanded: HashMap<Cid, Option<u32>> = HashMap::new();
    let mut scheduled: HashMap<Cid, Option<u32>> = HashMap::new();
    let mut root_order = Vec::new();
    let mut scheduled_work = 0usize;
    let mut deferred_frontier = 0usize;

    // Coalesce repeated roots before queueing them. A later, deeper policy
    // replaces the shallower state without creating an avoidable stale item.
    for root in roots {
        if scheduled
            .get(&root.cid)
            .is_some_and(|depth| depth_covers(*depth, root.max_depth))
        {
            continue;
        }
        if !scheduled.contains_key(&root.cid) {
            if max_walk != 0 && scheduled_work >= max_walk {
                deferred_frontier = 1;
                break;
            }
            scheduled_work += 1;
            root_order.push(root.cid.clone());
        }
        scheduled.insert(root.cid.clone(), root.max_depth);
    }

    let mut queue = VecDeque::with_capacity(root_order.len());
    for cid in root_order {
        queue.push_back((cid.clone(), scheduled[&cid]));
    }
    let mut out = Vec::new();
    let mut index_candidates = Vec::new();

    while let Some((cid, depth)) = queue.pop_front() {
        // A deeper occurrence may have superseded this queued state, or an
        // earlier path may already cover it. Both checks precede the verified
        // read and decode: duplicate edges therefore consume neither I/O nor
        // an unbounded frontier.
        if scheduled.get(&cid).is_some_and(|scheduled_depth| {
            depth_covers(*scheduled_depth, depth) && *scheduled_depth != depth
        }) || expanded
            .get(&cid)
            .is_some_and(|previous| depth_covers(*previous, depth))
        {
            continue;
        }

        let is_new = discovered.insert(cid.clone());
        if is_new {
            out.push(cid.clone());
        }

        // Classification happens even for a depth-zero direct pin. Effect
        // claims are pinned directly and nothing links *to* them, so waiting
        // until child expansion would omit exactly the records sync must
        // index. The strict destination parser repeats this judgement before
        // publication; this source-side list is only a work hint.
        let entry = from.store.get_chunk(&cid).ok().and_then(|bytes| {
            if is_new
                && (crate::effects::claim_from_bytes(&bytes).is_some()
                    || dag_core::signing::record_from_bytes(&bytes).is_some())
            {
                index_candidates.push(cid.clone());
                if index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
                    return None;
                }
            }
            dag_core::Entry::from_bytes_cbor(&bytes).ok()
        });

        if index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
            return Err(ControlError::Capacity(format!(
                "sync graph exceeds the {MAX_SYNC_INDEX_CANDIDATES}-record index-candidate limit"
            )));
        }

        expanded.insert(cid.clone(), depth);

        let Some(child_depth) = next_depth(depth) else {
            continue;
        };

        // Missing content is reported by the chunk copy, not here: a root or
        // descendant that is absent should be one named failure, not a walk
        // error that hides the other transferable branches.
        if let Some(entry) = entry {
            for link in entry.links {
                if expanded
                    .get(&link.target)
                    .is_some_and(|previous| depth_covers(*previous, child_depth))
                    || scheduled
                        .get(&link.target)
                        .is_some_and(|scheduled_depth| depth_covers(*scheduled_depth, child_depth))
                {
                    continue;
                }
                if max_walk != 0 && scheduled_work >= max_walk {
                    return Ok(WalkResult {
                        cids: out,
                        index_candidates,
                        truncation: Some(SyncTruncation {
                            visited: discovered.len(),
                            limit: max_walk,
                            remaining_frontier: queue.len() + deferred_frontier + 1,
                        }),
                    });
                }
                scheduled_work += 1;
                scheduled.insert(link.target.clone(), child_depth);
                queue.push_back((link.target, child_depth));
            }
        }
    }

    Ok(WalkResult {
        cids: out,
        index_candidates,
        truncation: (deferred_frontier != 0).then_some(SyncTruncation {
            visited: discovered.len(),
            limit: max_walk,
            remaining_frontier: deferred_frontier,
        }),
    })
}

impl SyncSource for Control {
    fn enumerate(&self, opts: &SyncOptions) -> Result<SyncEnumeration> {
        // Local and network sync use the same bounded shape: current roots
        // come from paged head tables, and immutable history travels through
        // stable exact-key pages. The generation check refuses a mixed
        // snapshot if a normal writer changes either log between pages.
        let before_generation = self.sync_event_generation()?;
        let mut enumeration = self.enumerate_content(opts)?;
        let mut retained_event_bytes = 0usize;
        let mut pointer_event_bytes_read = 0usize;
        let mut event_refs = 0usize;

        let mut pointer_after: Option<(String, u64)> = None;
        loop {
            let remaining = MAX_SYNC_EVENT_REFS.saturating_sub(event_refs);
            let page_limit = PROBE_BATCH.min(remaining.saturating_add(1));
            let page = self.pointer_log.event_cids_page(
                pointer_after.as_ref().map(|(id, seq)| (id.as_str(), *seq)),
                page_limit,
            )?;
            if page.len() > remaining {
                return Err(ControlError::Capacity(format!(
                    "pointer/pin history exceeds the {MAX_SYNC_EVENT_REFS}-ref atomic sync limit"
                )));
            }
            if page.is_empty() {
                break;
            }
            let complete = page.len() < page_limit;
            for (id, _, _) in &page {
                retained_event_bytes = retained_event_bytes
                    .checked_add(id.len() + 8 + 32)
                    .ok_or_else(|| {
                        ControlError::Capacity("sync event-ref byte count overflow".into())
                    })?;
            }
            if retained_event_bytes > MAX_SYNC_EVENT_REF_BYTES {
                return Err(ControlError::Capacity(format!(
                    "sync event history exceeds the {MAX_SYNC_EVENT_REF_BYTES}-byte snapshot limit"
                )));
            }
            event_refs += page.len();
            pointer_after = page.last().map(|(id, seq, _)| (id.clone(), *seq));
            enumeration.wanted.extend(
                self.pointer_log
                    .sync_target_hints(&page, &mut pointer_event_bytes_read)?,
            );
            enumeration.pointer_events.extend(page);
            if complete {
                break;
            }
        }

        let mut pin_after: Option<(String, u64)> = None;
        loop {
            let remaining = MAX_SYNC_EVENT_REFS.saturating_sub(event_refs);
            let page_limit = PROBE_BATCH.min(remaining.saturating_add(1));
            let page = self.pin_log.event_cids_page(
                pin_after.as_ref().map(|(id, seq)| (id.as_str(), *seq)),
                page_limit,
            )?;
            if page.len() > remaining {
                return Err(ControlError::Capacity(format!(
                    "pointer/pin history exceeds the {MAX_SYNC_EVENT_REFS}-ref atomic sync limit"
                )));
            }
            if page.is_empty() {
                break;
            }
            let complete = page.len() < page_limit;
            for (id, _, _) in &page {
                retained_event_bytes = retained_event_bytes
                    .checked_add(id.len() + 8 + 32)
                    .ok_or_else(|| {
                        ControlError::Capacity("sync event-ref byte count overflow".into())
                    })?;
            }
            if retained_event_bytes > MAX_SYNC_EVENT_REF_BYTES {
                return Err(ControlError::Capacity(format!(
                    "sync event history exceeds the {MAX_SYNC_EVENT_REF_BYTES}-byte snapshot limit"
                )));
            }
            event_refs += page.len();
            pin_after = page.last().map(|(id, seq, _)| (id.clone(), *seq));
            enumeration.pin_events.extend(page);
            if complete {
                break;
            }
        }

        let event_cids: HashSet<Cid> = enumeration
            .pointer_events
            .iter()
            .chain(&enumeration.pin_events)
            .map(|(_, _, cid)| cid.clone())
            .collect();
        let event_signatures = self
            .signature_log
            .covering_bounded(&event_cids, MAX_SYNC_INDEX_CANDIDATES)?;
        enumeration.wanted.extend(event_cids.iter().cloned());
        enumeration.live_roots.extend(event_cids);
        enumeration.wanted.extend(event_signatures.iter().cloned());
        enumeration
            .live_roots
            .extend(event_signatures.iter().cloned());
        enumeration.index_candidates.extend(event_signatures);
        enumeration.index_candidates.sort_by_key(Cid::to_hex);
        enumeration.index_candidates.dedup();

        if enumeration.index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
            return Err(ControlError::Capacity(format!(
                "sync snapshot exceeds the {MAX_SYNC_INDEX_CANDIDATES}-record index-candidate limit"
            )));
        }
        let after_generation = self.sync_event_generation()?;
        if after_generation != before_generation {
            return Err(ControlError::Invalid(
                "source event generation changed during local sync enumeration; retry the snapshot"
                    .into(),
            ));
        }
        Ok(enumeration)
    }

    fn chunk_len(&self, cid: &Cid) -> Result<usize> {
        // A full read, not a stat: the read verifies the bytes on the way
        // past, so a dry run reports the failure a real run would hit.
        Ok(self.store.get_chunk(cid)?.len())
    }

    fn fetch_chunk(&self, cid: &Cid) -> Result<Vec<u8>> {
        Ok(self.store.get_chunk(cid)?)
    }
}

impl Control {
    /// Hash-verify and strictly classify immutable auxiliary records before
    /// taking either global publication barrier. Content addressing makes the
    /// result stable; only the exact-key derived-row merge must remain under
    /// the mutation gate.
    fn classify_sync_auxiliary_candidates(
        &self,
        candidates: &[Cid],
    ) -> Result<SyncAuxiliaryCandidates> {
        if candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
            return Err(ControlError::Capacity(format!(
                "sync publication has {} index candidates, above the {MAX_SYNC_INDEX_CANDIDATES}-record limit",
                candidates.len()
            )));
        }

        let mut seen = HashSet::with_capacity(candidates.len());
        let mut signature_targets: HashMap<Cid, Vec<Cid>> = HashMap::new();
        let mut claim_keys: HashMap<Vec<u8>, Vec<Cid>> = HashMap::new();
        let mut classified_cids = Vec::new();
        let mut bytes_examined = 0usize;
        for cid in candidates {
            if !seen.insert(cid.clone()) {
                continue;
            }
            let bytes = self.store.get_chunk(cid)?;
            bytes_examined = bytes_examined.checked_add(bytes.len()).ok_or_else(|| {
                ControlError::Capacity("sync index-candidate byte count overflow".into())
            })?;
            if bytes_examined > MAX_SYNC_INDEX_CANDIDATE_BYTES {
                return Err(ControlError::Capacity(format!(
                    "sync index candidates exceed the {MAX_SYNC_INDEX_CANDIDATE_BYTES}-byte publication limit"
                )));
            }

            if let Some((_record, entry)) = dag_core::signing::record_from_bytes(&bytes) {
                // The strict parser requires exactly one named `signs` link.
                signature_targets
                    .entry(entry.links[0].target.clone())
                    .or_default()
                    .push(cid.clone());
                classified_cids.push(cid.clone());
                continue;
            }
            if let Some((claim, _entry)) = crate::effects::claim_from_bytes(&bytes) {
                let key = hex::decode(&claim.effect_key).map_err(|error| {
                    ControlError::Invalid(format!(
                        "effect claim {cid} has an invalid effect key: {error}"
                    ))
                })?;
                claim_keys.entry(key).or_default().push(cid.clone());
                classified_cids.push(cid.clone());
            }
        }

        Ok(SyncAuxiliaryCandidates {
            signature_targets,
            claim_keys,
            classified_cids,
        })
    }

    fn prepare_sync_auxiliary_merges(
        &self,
        candidates: SyncAuxiliaryCandidates,
    ) -> Result<(
        crate::signatures::SignatureMergePlan,
        crate::job::ClaimMergePlan,
    )> {
        // Classification deliberately happens before the exclusive gates so
        // hostile bytes cannot monopolize global publication. GC may win the
        // gap, however, so recheck the recognized immutable objects now that
        // the mutation and content gates exclude deletion. The earlier read
        // already hash-verified them; application writers cannot replace one
        // CID with different bytes.
        for cid in &candidates.classified_cids {
            if !self.store.has_chunk(cid)? {
                return Err(ControlError::Invalid(format!(
                    "sync index candidate {cid} disappeared before atomic publication"
                )));
            }
        }
        Ok((
            self.signature_log
                .prepare_merge_plan(candidates.signature_targets)?,
            self.job_log.prepare_claim_merge(candidates.claim_keys)?,
        ))
    }

    /// Protocol-v3 content enumeration without materializing event history.
    /// Event refs and their chunks are added by the paged transport adapter.
    pub fn enumerate_content(&self, opts: &SyncOptions) -> Result<SyncEnumeration> {
        let max_walk = if opts.max_walk == 0 {
            SyncOptions::default().max_walk
        } else {
            opts.max_walk
        };
        let (mut roots, root_overflow) =
            collect_current_roots(self, &opts.source_node_id, crate::now_unix(), max_walk)?;
        if root_overflow {
            roots.truncate(max_walk);
        }
        let reachable = walk(self, &roots, max_walk)?;
        let mut index_candidates: HashSet<Cid> =
            reachable.index_candidates.iter().cloned().collect();
        if index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
            return Err(ControlError::Capacity(format!(
                "sync snapshot exceeds the {MAX_SYNC_INDEX_CANDIDATES}-record index-candidate limit"
            )));
        }
        let mut truncation = reachable.truncation;
        if root_overflow && truncation.is_none() {
            truncation = Some(SyncTruncation {
                visited: reachable.cids.len(),
                limit: max_walk,
                remaining_frontier: 1,
            });
        }

        let targets: HashSet<Cid> = reachable.cids.iter().cloned().collect();
        let mut signatures: Vec<Cid> = self
            .signature_log
            .covering_bounded(&targets, MAX_SYNC_INDEX_CANDIDATES)?
            .into_iter()
            .collect();
        signatures.sort_by_key(Cid::to_hex);
        index_candidates.extend(signatures.iter().cloned());
        if index_candidates.len() > MAX_SYNC_INDEX_CANDIDATES {
            return Err(ControlError::Capacity(format!(
                "sync snapshot exceeds the {MAX_SYNC_INDEX_CANDIDATES}-record index-candidate limit"
            )));
        }

        let mut required: Vec<Cid> = targets.into_iter().collect();
        required.extend(signatures.iter().cloned());
        required.sort_by_key(Cid::to_hex);
        required.dedup();

        let mut wanted = reachable.cids;
        wanted.extend(signatures);
        let mut index_candidates: Vec<Cid> = index_candidates.into_iter().collect();
        index_candidates.sort_by_key(Cid::to_hex);
        Ok(SyncEnumeration {
            pointer_events: Vec::new(),
            pin_events: Vec::new(),
            wanted,
            live_roots: required,
            index_candidates,
            truncation,
        })
    }

    /// O(1) stable token for source event-history pagination.
    ///
    /// Every authoritative pointer/pin mutation increments this value in the
    /// same redb transaction as the mapping. Holding the shared mutation gate
    /// pairs the token with any bounded page read without rescanning history.
    pub fn sync_event_generation(&self) -> Result<String> {
        let _mutation_guard = self
            .mutation_gate
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let generation = crate::sync_generation::read(&self.pointer_log.import_database())
            .map_err(|error| ControlError::db("reading sync event generation", error))?;
        Ok(format!("{generation:016x}"))
    }

    /// Atomically file a complete sync event snapshot and publish every
    /// safety-relevant derived lookup. Protocol implementations should keep
    /// references session-private until this call; a reader then sees either
    /// the old event logs and indexes or the complete new generation.
    pub fn publish_sync_snapshot(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        self.publish_durable_sync_snapshot_with_candidates(pointer_events, pin_events, &[])
    }

    /// Durably publish a complete sync snapshot using the sole safe lock
    /// order: cross-log mutation barrier, content durability barrier, log
    /// writer locks, then the database transaction.
    ///
    /// Every staging view created by this [`Control`] shares the store's
    /// durability coordinator, so publishing through the primary store also
    /// flushes and excludes writes through those views. Callers must not wrap
    /// this method in [`dag_storage::FsStore::with_durable_publication`].
    pub fn publish_durable_sync_snapshot(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        self.publish_durable_sync_snapshot_with_candidates(pointer_events, pin_events, &[])
    }

    /// Candidate-aware atomic publication used by the replication engine.
    /// An entirely empty offer is a cheap idempotent receipt and deliberately
    /// does not acquire either exclusive global barrier.
    pub fn publish_durable_sync_snapshot_with_candidates(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        index_candidates: &[Cid],
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        self.publish_durable_sync_snapshot_with_candidates_and_trigger_authority(
            pointer_events,
            pin_events,
            index_candidates,
            PointerTriggerAuthority::Granted,
        )
    }

    /// Candidate-aware atomic publication with explicit authority for plans
    /// that advance actively subscribed pointer heads. Native transports must
    /// derive this value from the authenticated Commit request; in-process
    /// replication retains its historical trusted-operator behavior.
    pub fn publish_durable_sync_snapshot_with_candidates_and_trigger_authority(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        index_candidates: &[Cid],
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        validate_sync_publication_shape(pointer_events, pin_events, index_candidates)?;
        if pointer_events.is_empty() && pin_events.is_empty() && index_candidates.is_empty() {
            return Ok((
                EventBatchOutcome::Applied {
                    pointer_events: 0,
                    pin_events: 0,
                },
                RebuildCounts::default(),
            ));
        }
        let auxiliary = self.classify_sync_auxiliary_candidates(index_candidates)?;
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        self.store.with_durable_publication(|| {
            self.publish_sync_snapshot_under_mutation(
                pointer_events,
                pin_events,
                auxiliary,
                trigger_authority,
            )
        })
    }

    /// Publish a snapshot while the caller owns both the mutation and content
    /// durability barriers, in that order.
    fn publish_sync_snapshot_under_mutation(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        auxiliary: SyncAuxiliaryCandidates,
        trigger_authority: PointerTriggerAuthority,
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        let _pointer_guard = self.pointer_log.import_batch_lock();
        let _pin_guard = self.pin_log.import_batch_lock();

        let pointer_plan = match self
            .pointer_log
            .prepare_incremental_sync_plan(pointer_events)
        {
            Ok(plan) => plan,
            Err(error) => {
                let (id, seq, cid, source) = error.into_parts();
                let rejection = batch_rejection("pointer", &id, seq, &cid, source.into());
                self.metrics.sync_events_refused_total.inc();
                return Ok((
                    EventBatchOutcome::Rejected(rejection),
                    RebuildCounts::default(),
                ));
            }
        };
        let pin_plan = match self.pin_log.prepare_incremental_sync_plan(pin_events) {
            Ok(plan) => plan,
            Err(error) => {
                let (id, seq, cid, source) = error.into_parts();
                let rejection = batch_rejection("pin", &id, seq, &cid, source.into());
                self.metrics.sync_events_refused_total.inc();
                return Ok((
                    EventBatchOutcome::Rejected(rejection),
                    RebuildCounts::default(),
                ));
            }
        };
        self.validate_incremental_sync_roots(&pointer_plan, &pin_plan)?;
        let (signature_plan, claim_plan) = self.prepare_sync_auxiliary_merges(auxiliary)?;
        // Sync rebuilds the state it was offered, but it does not inventory
        // and reconcile every object already present in this store. It may
        // preserve an already-complete recovery verdict; it must never create
        // one for an unrecovered or truncated deployment.
        let recovery_generation = self.chunk_index_rebuild_generation()?;
        let may_mark_recovered = self.recovery_state.is_recovered(recovery_generation)?;

        let db = self.pointer_log.import_database();
        let txn = db
            .begin_write()
            .map_err(|e| ControlError::db("begin atomic sync publication", e))?;
        // Replication deliberately does not enqueue destination jobs, but an
        // actively subscribed pointer is still a trigger-authority boundary.
        // Decide against the exact subscription/head state in this writer
        // transaction, before any mapping, head, generation, or index row is
        // changed. Trigger intents already on file carry immutable job/input
        // snapshots, so later unrelated sync updates cannot rewrite them.
        self.pointer_log.authorize_incremental_sync_triggers(
            &txn,
            &pointer_plan,
            trigger_authority,
        )?;
        self.pointer_log
            .apply_incremental_sync_plan(&txn, &pointer_plan)?;
        self.pin_log.apply_incremental_sync_plan(&txn, &pin_plan)?;
        if pointer_plan.events_inserted() != 0 || pin_plan.events_inserted() != 0 {
            crate::sync_generation::bump(&txn)
                .map_err(|error| ControlError::db("bumping sync event generation", error))?;
        }
        self.signature_log.apply_merge_plan(&txn, &signature_plan)?;
        self.job_log.apply_claim_merge(&txn, &claim_plan)?;
        if may_mark_recovered {
            self.recovery_state
                .apply_complete(&txn, recovery_generation)?;
        }
        txn.commit()
            .map_err(|e| ControlError::db("commit atomic sync publication", e))?;

        let pointer_count = pointer_plan.events_inserted();
        let pin_count = pin_plan.events_inserted();
        self.metrics
            .sync_events_imported_total
            .add((pointer_count + pin_count) as u64);
        Ok((
            EventBatchOutcome::Applied {
                pointer_events: pointer_count,
                pin_events: pin_count,
            },
            RebuildCounts {
                pointers_rebuilt: pointer_plan.heads_updated(),
                pins_rebuilt: pin_plan.heads_updated(),
                signatures_indexed: signature_plan.added(),
                claims_indexed: claim_plan.added(),
            },
        ))
    }

    /// Rebuild every safety-relevant derived lookup and publish the recovery
    /// flags in one redb commit. Preparation is read-only; any validation or
    /// decoding failure leaves all previously visible derived state intact.
    #[cfg(test)]
    fn finalize_sync_state(&self, fail_after_stage: Option<u8>) -> Result<RebuildCounts> {
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        self.store
            .with_durable_publication(|| self.finalize_sync_state_under_mutation(fail_after_stage))
    }

    /// Durably finalize all sync-derived state. The method owns the complete
    /// lock order so transport implementations cannot accidentally acquire the
    /// storage barrier before the mutation barrier.
    pub fn finalize_durable_sync(&self) -> Result<RebuildCounts> {
        Err(ControlError::Invalid(
            "sessionless sync finalization is disabled; publish a complete event batch and its bounded index candidates atomically"
                .into(),
        ))
    }

    /// Finalize while the mutation and durability barriers are already held.
    #[cfg(test)]
    fn finalize_sync_state_under_mutation(
        &self,
        fail_after_stage: Option<u8>,
    ) -> Result<RebuildCounts> {
        // Stable order shared with atomic event import. The exclusive mutation
        // guard keeps every participating normal writer outside this window;
        // the per-log locks also cover direct logs constructed without Control.
        let _pointer_guard = self.pointer_log.import_batch_lock();
        let _pin_guard = self.pin_log.import_batch_lock();

        let pointer_plan = self.pointer_log.prepare_rebuild_plan()?;
        let pin_plan = self.pin_log.prepare_rebuild_plan()?;
        self.validate_sync_rebuild_roots(&pointer_plan, &pin_plan)?;
        let signature_plan = self.signature_log.prepare_rebuild_plan()?;
        let claim_plan = self.prepare_effect_claim_rebuild()?;
        // Finalization is table-oriented and cannot prove there are no newer
        // events stranded only in the content store. Preserve a prior full
        // recovery verdict, but never use sync to mint one.
        let recovery_generation = self.chunk_index_rebuild_generation()?;
        let may_mark_recovered = self.recovery_state.is_recovered(recovery_generation)?;

        let db = self.pointer_log.import_database();
        let txn = db
            .begin_write()
            .map_err(|e| ControlError::db("begin atomic sync finalize", e))?;

        self.pointer_log.apply_rebuild_plan(&txn, &pointer_plan)?;
        Self::fail_finalize_after(fail_after_stage, 1)?;
        self.pin_log.apply_rebuild_plan(&txn, &pin_plan)?;
        Self::fail_finalize_after(fail_after_stage, 2)?;
        self.signature_log
            .apply_rebuild_plan(&txn, &signature_plan)?;
        Self::fail_finalize_after(fail_after_stage, 3)?;
        self.job_log.apply_claim_rebuild(&txn, &claim_plan)?;
        Self::fail_finalize_after(fail_after_stage, 4)?;
        if may_mark_recovered {
            self.recovery_state
                .apply_complete(&txn, recovery_generation)?;
        }
        Self::fail_finalize_after(fail_after_stage, 5)?;

        txn.commit()
            .map_err(|e| ControlError::db("commit atomic sync finalize", e))?;

        Ok(RebuildCounts {
            pointers_rebuilt: pointer_plan.count(),
            pins_rebuilt: pin_plan.report(true).heads_rebuilt,
            signatures_indexed: signature_plan.count(),
            claims_indexed: claim_plan.count(),
        })
    }

    #[cfg(test)]
    fn fail_finalize_after(requested: Option<u8>, stage: u8) -> Result<()> {
        if requested == Some(stage) {
            return Err(ControlError::Invalid(format!(
                "injected finalize failure after stage {stage}"
            )));
        }
        Ok(())
    }
}

impl SyncDestination for Control {
    fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>> {
        if cids.len() > MISSING_BATCH {
            return Err(ControlError::Invalid(format!(
                "at most {MISSING_BATCH} CIDs per verified missing check, got {}",
                cids.len()
            )));
        }

        // "Held" means indexed and hash-verified, and it has to be both.
        //
        // File presence alone is not enough. A destination writing with
        // deferred durability renames a chunk into its canonical path before
        // the bytes are fsynced, so a crash mid-transfer can leave a file
        // that is present and torn. Answering "not missing" for it would
        // skip it on every future run — the bytes would never be re-offered,
        // `store_chunk`'s repair path would never see them, and the index
        // scan that `verify` drives would never look. Permanently corrupt,
        // and every sync reporting success.
        //
        // An index entry alone is not enough either: an entry naming a file
        // that is gone would make the transfer skip a chunk the destination
        // does not have. `get_chunk` reads and hashes, so an indexed file
        // whose bytes changed is re-offered too. The small call bound keeps
        // that integrity work finite.
        let index = self.store.get_index();
        let mut out = Vec::new();
        for cid in cids {
            let indexed = match &index {
                // No index (a bare store): presence is the only authority.
                None => true,
                Some(index) => matches!(index.get(cid), Ok(Some(_))),
            };
            let verified = self.store.get_chunk(cid).is_ok();
            if !(indexed && verified) {
                out.push(cid.clone());
            }
        }
        Ok(out)
    }

    fn store_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<()> {
        // The receipt check is the destination's own: `put_chunk` hashes what
        // it is handed, so comparing that against the CID the source claimed
        // detects corruption in transit or at rest on the source.
        let written = self.store.put_chunk(bytes, None)?;
        if &written != cid {
            return Err(ControlError::Invalid(format!(
                "chunk {} arrived as {}: content does not match its address",
                cid, written
            )));
        }
        self.metrics.sync_chunks_received_total.inc();
        self.metrics
            .sync_bytes_received_total
            .add(bytes.len() as u64);
        Ok(())
    }

    fn probe_pointer_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        let mut conflicts = Vec::new();
        for (id, seq, offered) in events {
            if let Some(existing) = self.pointer_log.event_cid(id, *seq)? {
                if existing != *offered {
                    conflicts.push(EventConflict {
                        id: id.clone(),
                        seq: *seq,
                        offered: offered.clone(),
                        existing,
                    });
                }
            }
        }
        Ok(Some(conflicts))
    }

    fn probe_pin_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        let mut conflicts = Vec::new();
        for (id, seq, offered) in events {
            if let Some(existing) = self.pin_log.event_cid(id, *seq)? {
                if existing != *offered {
                    conflicts.push(EventConflict {
                        id: id.clone(),
                        seq: *seq,
                        offered: offered.clone(),
                        existing,
                    });
                }
            }
        }
        Ok(Some(conflicts))
    }

    fn import_pointer_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "native event publication requires a complete atomic batch".into(),
        ))
    }

    fn import_pin_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "native event publication requires a complete atomic batch".into(),
        ))
    }

    fn import_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<EventBatchOutcome> {
        // Event mappings and every derived lookup are one publication marker.
        // This also owns the only safe mutation -> durability -> log-lock
        // ordering, so callers must not add an outer durability barrier.
        self.publish_durable_sync_snapshot(pointer_events, pin_events)
            .map(|(outcome, _counts)| outcome)
    }

    fn publish_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        index_candidates: &[Cid],
    ) -> Result<(EventBatchOutcome, RebuildCounts)> {
        self.publish_durable_sync_snapshot_with_candidates(
            pointer_events,
            pin_events,
            index_candidates,
        )
    }

    fn finalize(&self) -> Result<RebuildCounts> {
        self.finalize_durable_sync()
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use crate::test_utils::TestControl;
    use dag_core::{EffectKey, Entry, JobId, Link, PinScope, PinState};

    fn put(tc: &TestControl, bytes: &[u8]) -> Cid {
        tc.control.store.put_chunk(bytes, None).unwrap()
    }

    // ---- The engine's contract, pinned against mocks ----------------------
    //
    // These are the properties a *remote* implementation depends on (ADR-005):
    // bounded batch sizes, a dry run that moves nothing, and per-chunk failure
    // isolation. The Control-to-Control tests below cannot see any of them.

    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    struct MockSource {
        enumeration: SyncEnumeration,
        chunks: HashMap<String, Vec<u8>>,
        fetches: Cell<usize>,
    }

    impl MockSource {
        fn with_chunks(bodies: &[&[u8]]) -> Self {
            let mut chunks = HashMap::new();
            let mut wanted = Vec::new();
            for body in bodies {
                let cid = Cid::compute(body);
                chunks.insert(cid.to_hex(), body.to_vec());
                wanted.push(cid);
            }
            Self {
                enumeration: SyncEnumeration {
                    wanted,
                    ..Default::default()
                },
                chunks,
                fetches: Cell::new(0),
            }
        }
    }

    impl SyncSource for MockSource {
        fn enumerate(&self, _opts: &SyncOptions) -> Result<SyncEnumeration> {
            Ok(self.enumeration.clone())
        }

        fn chunk_len(&self, cid: &Cid) -> Result<usize> {
            self.chunks
                .get(&cid.to_hex())
                .map(Vec::len)
                .ok_or_else(|| ControlError::Invalid(format!("no such chunk {}", cid)))
        }

        fn fetch_chunk(&self, cid: &Cid) -> Result<Vec<u8>> {
            self.fetches.set(self.fetches.get() + 1);
            self.chunks
                .get(&cid.to_hex())
                .cloned()
                .ok_or_else(|| ControlError::Invalid(format!("no such chunk {}", cid)))
        }
    }

    #[derive(Default)]
    struct RecordingDestination {
        missing_batch_sizes: RefCell<Vec<usize>>,
        stored: RefCell<Vec<String>>,
        imported_pointer_events: RefCell<Vec<(String, u64)>>,
        finalized: Cell<bool>,
    }

    impl SyncDestination for RecordingDestination {
        fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>> {
            self.missing_batch_sizes.borrow_mut().push(cids.len());
            Ok(cids.to_vec()) // holds nothing
        }

        fn store_chunk(&self, cid: &Cid, _bytes: &[u8]) -> Result<()> {
            self.stored.borrow_mut().push(cid.to_hex());
            Ok(())
        }

        fn import_pointer_event(&self, id: &str, seq: u64, _cid: &Cid) -> Result<bool> {
            self.imported_pointer_events
                .borrow_mut()
                .push((id.to_string(), seq));
            Ok(true)
        }

        fn import_pin_event(&self, _id: &str, _seq: u64, _cid: &Cid) -> Result<bool> {
            Ok(true)
        }

        fn finalize(&self) -> Result<RebuildCounts> {
            self.finalized.set(true);
            Ok(RebuildCounts::default())
        }
    }

    #[test]
    fn the_engine_asks_for_missing_chunks_in_bounded_batches() {
        // Over a network each batch is one request, so an unbounded batch
        // would put the whole store's key set into a single message.
        let n = MISSING_BATCH * 2 + 7;
        let bodies: Vec<Vec<u8>> = (0..n).map(|i| (i as u64).to_le_bytes().to_vec()).collect();
        let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        let source = MockSource::with_chunks(&refs);
        let dest = RecordingDestination::default();

        let report = replicate(&source, &dest, &SyncOptions::default()).unwrap();

        assert!(report.is_complete(), "{:?}", report.failures);
        assert_eq!(report.chunks_sent, n);
        let sizes = dest.missing_batch_sizes.borrow();
        assert_eq!(sizes.iter().sum::<usize>(), n);
        assert!(
            sizes.iter().all(|s| *s <= MISSING_BATCH),
            "a batch exceeded MISSING_BATCH: {:?}",
            sizes
        );
        assert_eq!(sizes.len(), 3, "{:?}", sizes);
        assert!(dest.finalized.get());
    }

    #[test]
    fn a_dry_run_through_the_engine_moves_nothing_and_finalizes_nothing() {
        let mut source = MockSource::with_chunks(&[b"event entry", b"content"]);
        source.enumeration.pointer_events =
            vec![("p".to_string(), 1, source.enumeration.wanted[0].clone())];
        let dest = RecordingDestination::default();

        let opts = SyncOptions {
            dry_run: true,
            ..Default::default()
        };
        let report = replicate(&source, &dest, &opts).unwrap();

        assert!(report.dry_run);
        assert_eq!(report.chunks_sent, 2);
        assert!(report.bytes_sent > 0);
        assert_eq!(source.fetches.get(), 0, "a dry run fetched chunk bytes");
        assert!(dest.stored.borrow().is_empty());
        assert!(
            dest.imported_pointer_events.borrow().is_empty(),
            "a dry run filed event mappings"
        );
        assert!(!dest.finalized.get(), "a dry run rebuilt derived state");
    }

    #[test]
    fn one_failing_chunk_arrives_partially_but_blocks_publication() {
        let mut source = MockSource::with_chunks(&[b"first", b"second", b"third"]);
        // The middle chunk is enumerated but unreadable — a failing source
        // disk in miniature.
        let ghost = Cid::compute(b"unreadable");
        source.enumeration.wanted.insert(1, ghost.clone());
        let dest = RecordingDestination::default();

        let report = replicate(&source, &dest, &SyncOptions::default()).unwrap();

        assert_eq!(report.chunks_sent, 3);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].cid, ghost.to_hex());
        assert_eq!(dest.stored.borrow().len(), 3);
        assert!(report.publication_blocked);
        assert!(
            !dest.finalized.get(),
            "a partial snapshot was published as derived state"
        );
    }

    #[test]
    fn truncation_is_incomplete_and_never_imports_or_finalizes() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let child = put(&src, b"child");
        let root = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![Link {
                    name: None,
                    target: child.clone(),
                }],
                meta: None,
            })
            .unwrap();
        src.control.pointer_log.create("release", root).unwrap();

        let report = push(
            &src.control,
            &dst.control,
            &SyncOptions {
                max_walk: 1,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(!report.is_complete());
        assert_eq!(
            report.truncation,
            Some(SyncTruncation {
                visited: 1,
                limit: 1,
                remaining_frontier: 1,
            })
        );
        assert!(report.publication_blocked);
        assert!(dst.control.pointer_log.event_cids().unwrap().is_empty());
        assert!(dst.control.pointer_log.list_pointers().unwrap().is_empty());
        assert!(!dst.control.store.has_chunk(&child).unwrap());
    }

    #[test]
    fn reaching_the_limit_exactly_is_not_truncation() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        let leaf = put(&src, b"only node");
        src.control.pointer_log.create("release", leaf).unwrap();

        let report = push(
            &src.control,
            &dst.control,
            &SyncOptions {
                max_walk: 1,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(report.is_complete(), "{report:?}");
        assert!(report.truncation.is_none());
    }

    #[test]
    fn a_replica_resolves_the_same_pointer_to_the_same_cid() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let v1 = put(&src, b"version one");
        let v2 = put(&src, b"version two");
        src.control.pointer_log.create("model", v1).unwrap();
        src.control.pointer_log.update("model", v2.clone()).unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{:?}", report.failures);

        assert_eq!(dst.control.pointer_log.resolve("model").unwrap(), v2);
        assert_eq!(dst.control.store.get_chunk(&v2).unwrap(), b"version two");
    }

    #[test]
    fn history_arrives_with_its_original_cids_not_re_minted_ones() {
        // The reason import_event exists. Replaying through create/update would
        // stamp the local clock into each event, so the replica's provenance
        // log would have different CIDs from the one that was signed.
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let v1 = put(&src, b"one");
        let v2 = put(&src, b"two");
        src.control.pointer_log.create("p", v1).unwrap();
        src.control.pointer_log.update("p", v2).unwrap();

        push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        let source_events = src.control.pointer_log.event_cids().unwrap();
        let replica_events = dst.control.pointer_log.event_cids().unwrap();
        assert_eq!(source_events, replica_events);
        assert_eq!(source_events.len(), 2);
    }

    #[test]
    fn linked_entries_are_followed_so_the_whole_graph_arrives() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let leaf = put(&src, b"the artifact");
        let mid = src
            .control
            .store
            .put_entry(&Entry {
                payload: b"a record".to_vec(),
                links: vec![Link {
                    name: Some("artifact".into()),
                    target: leaf.clone(),
                }],
                meta: None,
            })
            .unwrap();
        src.control.pointer_log.create("release", mid).unwrap();

        push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        // The leaf is two hops from the pointer and was never named directly.
        assert_eq!(dst.control.store.get_chunk(&leaf).unwrap(), b"the artifact");
    }

    #[test]
    fn duplicate_edges_are_pruned_before_chunk_reads_and_frontier_growth() {
        let src = TestControl::new().unwrap();
        let child = put(&src, b"one shared child");
        let duplicate = Link {
            name: None,
            target: child.clone(),
        };
        let root = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![duplicate; 10_000],
                meta: None,
            })
            .unwrap();
        let reads_before = src.control.metrics.store_get_total.get();

        let result = walk(
            &src.control,
            &[WalkRoot {
                cid: root,
                max_depth: None,
            }],
            2,
        )
        .unwrap();

        assert!(result.truncation.is_none(), "{result:?}");
        assert_eq!(result.cids.len(), 2);
        assert_eq!(
            src.control.metrics.store_get_total.get() - reads_before,
            2,
            "the root and shared child must each be verified exactly once"
        );
    }

    #[test]
    fn deeper_reexpansion_is_charged_to_the_walk_budget() {
        let src = TestControl::new().unwrap();
        let shared = put(&src, b"shared");
        let parent = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![Link {
                    name: None,
                    target: shared.clone(),
                }],
                meta: None,
            })
            .unwrap();
        let reads_before = src.control.metrics.store_get_total.get();

        let result = walk(
            &src.control,
            &[
                WalkRoot {
                    cid: shared,
                    max_depth: Some(0),
                },
                WalkRoot {
                    cid: parent,
                    max_depth: None,
                },
            ],
            2,
        )
        .unwrap();

        assert_eq!(
            result.truncation,
            Some(SyncTruncation {
                visited: 2,
                limit: 2,
                remaining_frontier: 1,
            })
        );
        assert_eq!(
            src.control.metrics.store_get_total.get() - reads_before,
            2,
            "the rejected depth upgrade must stop before a third read"
        );
    }

    #[test]
    fn pins_and_their_targets_transfer() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let target = put(&src, b"keep me");
        src.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{:?}", report.failures);

        assert!(dst.control.store.has_chunk(&target).unwrap());
        // The pin arrived and its head is readable at the destination.
        dst.control.pin_log.head("keep").unwrap();
    }

    #[test]
    fn inactive_and_expired_pins_preserve_history_without_rooting_content() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let released = put(&src, b"released");
        src.control
            .pin_log
            .create(
                "released",
                PinTarget::Direct(released.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        src.control.pin_log.deactivate("released", None).unwrap();

        let expired = put(&src, b"expired");
        src.control
            .pin_log
            .create(
                "expired",
                PinTarget::Direct(expired.clone()),
                PinScope::Global,
                Some(crate::now_unix() - 1),
                None,
            )
            .unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert!(!dst.control.store.has_chunk(&released).unwrap());
        assert!(!dst.control.store.has_chunk(&expired).unwrap());
        assert_eq!(
            src.control.pin_log.event_cids().unwrap(),
            dst.control.pin_log.event_cids().unwrap(),
            "pin provenance must move even when its retention is ineffective"
        );
    }

    #[test]
    fn local_pin_roots_apply_only_to_the_selected_source_node() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let matching = put(&src, b"node-a only");
        let other = put(&src, b"node-b only");
        src.control
            .pin_log
            .create(
                "matching",
                PinTarget::Direct(matching.clone()),
                PinScope::Local {
                    node_id: "node-a".to_string(),
                },
                None,
                None,
            )
            .unwrap();
        src.control
            .pin_log
            .create(
                "other",
                PinTarget::Direct(other.clone()),
                PinScope::Local {
                    node_id: "node-b".to_string(),
                },
                None,
                None,
            )
            .unwrap();

        let report = push(
            &src.control,
            &dst.control,
            &SyncOptions {
                source_node_id: "node-a".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert!(dst.control.store.has_chunk(&matching).unwrap());
        assert!(!dst.control.store.has_chunk(&other).unwrap());
        assert_eq!(dst.control.pin_log.event_cids().unwrap().len(), 2);
    }

    #[test]
    fn direct_and_depth_limited_subtree_pins_keep_their_exact_shape() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let direct_child = put(&src, b"not covered by a direct pin");
        let direct_root = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![Link {
                    name: None,
                    target: direct_child.clone(),
                }],
                meta: None,
            })
            .unwrap();
        src.control
            .pin_log
            .create(
                "direct",
                PinTarget::Direct(direct_root.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let grandchild = put(&src, b"depth two");
        let child = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![Link {
                    name: None,
                    target: grandchild.clone(),
                }],
                meta: None,
            })
            .unwrap();
        let subtree_root = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![Link {
                    name: None,
                    target: child.clone(),
                }],
                meta: None,
            })
            .unwrap();
        src.control
            .pin_log
            .create(
                "bounded",
                PinTarget::Subtree {
                    root: subtree_root.clone(),
                    max_depth: Some(1),
                },
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{report:?}");
        assert!(dst.control.store.has_chunk(&direct_root).unwrap());
        assert!(!dst.control.store.has_chunk(&direct_child).unwrap());
        assert!(dst.control.store.has_chunk(&subtree_root).unwrap());
        assert!(dst.control.store.has_chunk(&child).unwrap());
        assert!(!dst.control.store.has_chunk(&grandchild).unwrap());
    }

    #[test]
    fn a_second_sync_sends_nothing() {
        // Resumability, stated as a property: what is missing is always
        // recomputable, so there is no journal to keep and re-running is free.
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let cid = put(&src, b"payload");
        src.control.pointer_log.create("p", cid).unwrap();

        let first = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(first.chunks_sent > 0);

        let second = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert_eq!(second.chunks_sent, 0, "a repeat sync re-sent content");
        assert_eq!(second.pointer_events, 0, "a repeat sync re-filed events");
        assert_eq!(second.chunks_skipped, first.chunks_sent);
        assert!(second.is_complete());
    }

    #[test]
    fn an_interrupted_sync_is_completed_by_running_it_again() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        for i in 0..8 {
            let cid = put(&src, format!("chunk {}", i).as_bytes());
            let id = format!("p{}", i);
            src.control.pointer_log.create(&id, cid).unwrap();
        }

        // Stand in for an interruption: copy only some of the content, so the
        // destination starts the real sync partially populated.
        let (roots, _) = collect_roots(&src.control, "local", crate::now_unix()).unwrap();
        let partial = walk(&src.control, &roots, 0).unwrap();
        for cid in partial.cids.iter().take(3) {
            let bytes = src.control.store.get_chunk(cid).unwrap();
            dst.control.store.put_chunk(&bytes, None).unwrap();
        }

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{:?}", report.failures);
        assert_eq!(report.chunks_skipped, 3, "already-present chunks re-sent");

        for i in 0..8 {
            let id = format!("p{}", i);
            let cid = dst.control.pointer_log.resolve(&id).unwrap();
            assert_eq!(
                dst.control.store.get_chunk(&cid).unwrap(),
                format!("chunk {}", i).as_bytes()
            );
        }
    }

    #[test]
    fn unreferenced_content_is_not_replicated() {
        // Recursive roots are current pointer heads and effective pin targets.
        // Direct historical pointer targets are also offered, but content with
        // no current root, history reference, or pin is what collection is free
        // to delete. Pinning it is the statement that changes that.
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let orphan = put(&src, b"nobody points at me");
        let referenced = put(&src, b"a pointer names me");
        src.control
            .pointer_log
            .create("p", referenced.clone())
            .unwrap();

        push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        assert!(dst.control.store.has_chunk(&referenced).unwrap());
        assert!(
            !dst.control.store.has_chunk(&orphan).unwrap(),
            "unreferenced content was replicated; if that is now wanted it \
             should be an explicit opt-in, not a silent default"
        );

        // Pinning it is what makes it travel.
        src.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(orphan.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(dst.control.store.has_chunk(&orphan).unwrap());
    }

    #[test]
    fn a_chunked_file_travels_with_all_of_its_parts() {
        // A file over the chunk limit is a manifest linking its pieces. The
        // walk has to follow those links, or the replica would hold a manifest
        // naming chunks it does not have.
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let big: Vec<u8> = (0..(9 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
        let stored = dag_core::file::store_auto(
            src.control.store.as_ref(),
            std::io::Cursor::new(big.clone()),
            None,
            false,
            &dag_core::ChunkerConfig::default(),
        )
        .unwrap();
        let root = match stored {
            dag_core::StoredContent::File(r) => r.cid,
            dag_core::StoredContent::Chunk { cid, .. } => cid,
        };

        src.control.pointer_log.create("big", root.clone()).unwrap();
        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{:?}", report.failures);

        let mut out = Vec::new();
        dag_core::file::join(dst.control.store.as_ref(), &root, &mut out).unwrap();
        assert_eq!(out, big, "the replica reassembled different bytes");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let cid = put(&src, b"payload");
        src.control.pointer_log.create("p", cid.clone()).unwrap();

        let opts = SyncOptions {
            dry_run: true,
            ..Default::default()
        };
        let report = push(&src.control, &dst.control, &opts).unwrap();

        assert!(report.chunks_sent > 0, "dry run reported nothing to do");
        assert!(report.dry_run);
        assert!(!dst.control.store.has_chunk(&cid).unwrap());
        assert!(dst.control.pointer_log.list_pointers().unwrap().is_empty());
    }

    #[test]
    fn dry_run_reports_divergence_without_importing_or_rebuilding() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let source_value = put(&src, b"source");
        src.control
            .pointer_log
            .create("shared", source_value)
            .unwrap();
        let destination_value = put(&dst, b"destination");
        dst.control
            .pointer_log
            .create("shared", destination_value.clone())
            .unwrap();
        let before = dst.control.pointer_log.event_cids().unwrap();

        let report = push(
            &src.control,
            &dst.control,
            &SyncOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(!report.is_complete());
        assert_eq!(report.divergent.len(), 1, "{report:?}");
        assert_eq!(dst.control.pointer_log.event_cids().unwrap(), before);
        assert_eq!(
            dst.control.pointer_log.resolve("shared").unwrap(),
            destination_value
        );
    }

    #[test]
    fn pull_is_push_with_the_arguments_swapped() {
        let a = TestControl::new().unwrap();
        let b = TestControl::new().unwrap();

        let cid = a.control.store.put_chunk(b"from a", None).unwrap();
        a.control.pointer_log.create("p", cid.clone()).unwrap();

        pull(&b.control, &a.control, &SyncOptions::default()).unwrap();

        assert_eq!(b.control.pointer_log.resolve("p").unwrap(), cid);
    }

    #[test]
    fn signatures_travel_even_though_nothing_links_to_them() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let target = put(&src, b"signed content");
        src.control.pointer_log.create("p", target.clone()).unwrap();

        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sig_cid = src
            .control
            .signature_log
            .sign(&target, Some("release".into()), serde_json::json!({}), &key)
            .unwrap();

        push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        assert!(dst.control.store.has_chunk(&sig_cid).unwrap());
        assert_eq!(
            dst.control.signature_log.list_for(&target).unwrap(),
            vec![sig_cid]
        );
    }

    #[test]
    fn a_directly_pinned_signature_is_indexed_for_a_preexisting_unrelated_target() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        let target = put(&src, b"preexisting destination target");
        dst.control
            .store
            .put_chunk(&src.control.store.get_chunk(&target).unwrap(), None)
            .unwrap();

        let key = ed25519_dalek::SigningKey::from_bytes(&[47u8; 32]);
        let signature = src
            .control
            .signature_log
            .sign(&target, None, serde_json::json!({}), &key)
            .unwrap();
        src.control
            .pin_log
            .create(
                "signature-only-root",
                PinTarget::Direct(signature.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        assert!(report.is_complete(), "{report:?}");
        assert!(dst.control.store.has_chunk(&signature).unwrap());
        assert_eq!(
            dst.control.signature_log.list_for(&target).unwrap(),
            vec![signature]
        );
    }

    #[test]
    fn index_candidate_overflow_refuses_before_event_publication() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        let target = put(&src, b"candidate-limit-target");
        src.control.pointer_log.create("release", target).unwrap();
        let event = src.control.pointer_log.event_cids().unwrap().remove(0);
        let bytes = src.control.store.get_chunk(&event.2).unwrap();
        dst.control.store.put_chunk(&bytes, None).unwrap();
        let before_generation = dst.control.sync_event_generation().unwrap();
        let candidates = vec![event.2.clone(); MAX_SYNC_INDEX_CANDIDATES + 1];

        let error = dst
            .control
            .publish_durable_sync_snapshot_with_candidates(
                std::slice::from_ref(&event),
                &[],
                &candidates,
            )
            .unwrap_err();

        assert!(matches!(error, ControlError::Capacity(_)), "{error}");
        assert!(dst.control.pointer_log.event_cids().unwrap().is_empty());
        assert_eq!(
            dst.control.sync_event_generation().unwrap(),
            before_generation
        );
    }

    #[test]
    fn event_signatures_and_countersignatures_replicate_to_a_fixed_point() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);

        let pointer_target = put(&src, b"pointer target");
        src.control
            .pointer_log
            .create("release", pointer_target)
            .unwrap();
        let pointer_event = src.control.pointer_log.event_cids().unwrap()[0].2.clone();

        let pin_target = put(&src, b"pin target");
        src.control
            .pin_log
            .create(
                "hold",
                PinTarget::Direct(pin_target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        let pin_event = src.control.pin_log.event_cids().unwrap()[0].2.clone();

        let pointer_signature = src
            .control
            .signature_log
            .sign(&pointer_event, None, serde_json::json!({}), &key)
            .unwrap();
        let countersignature = src
            .control
            .signature_log
            .sign(
                &pointer_signature,
                Some("counter".into()),
                serde_json::json!({}),
                &key,
            )
            .unwrap();
        let pin_signature = src
            .control
            .signature_log
            .sign(&pin_event, None, serde_json::json!({}), &key)
            .unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{report:?}");
        for cid in [&pointer_signature, &countersignature, &pin_signature] {
            assert!(dst.control.store.has_chunk(cid).unwrap(), "missing {cid}");
        }
        assert_eq!(
            dst.control.signature_log.list_for(&pointer_event).unwrap(),
            vec![pointer_signature.clone()]
        );
        assert_eq!(
            dst.control
                .signature_log
                .list_for(&pointer_signature)
                .unwrap(),
            vec![countersignature]
        );
        assert_eq!(
            dst.control.signature_log.list_for(&pin_event).unwrap(),
            vec![pin_signature]
        );
    }

    #[test]
    fn trusted_keys_are_not_replicated() {
        // Trust is a local operational decision. A source must not be able to
        // decide what its replica trusts.
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let public_hex = hex::encode(key.verifying_key().to_bytes());
        src.control
            .signature_log
            .trust_key(
                &public_hex,
                Some("source's own trust".into()),
                &[crate::TrustPurpose::Verify],
            )
            .unwrap();

        let target = put(&src, b"content");
        src.control.pointer_log.create("p", target.clone()).unwrap();
        src.control
            .signature_log
            .sign(&target, None, serde_json::json!({}), &key)
            .unwrap();

        push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        assert!(
            dst.control.signature_log.trusted_keys().unwrap().is_empty(),
            "the source's keyring reached the replica"
        );

        // The signature arrived and is internally valid, but untrusted here.
        let statuses = dst.control.signature_log.verify(&target).unwrap();
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].valid);
        assert!(!statuses[0].trusted);
    }

    #[test]
    fn divergent_history_is_refused_rather_than_overwritten() {
        // Two directories that independently created the same pointer name.
        // Sync must not silently rewrite one with the other.
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let a = put(&src, b"source's first value");
        src.control.pointer_log.create("shared", a).unwrap();

        let b = dst.control.store.put_chunk(b"other value", None).unwrap();
        dst.control.pointer_log.create("shared", b.clone()).unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

        assert!(
            !report.is_complete(),
            "conflicting history was accepted silently"
        );
        assert!(
            report.divergent.iter().any(|f| f.reason.contains("shared")),
            "failures={:?} divergent={:?}",
            report.failures,
            report.divergent
        );
        assert!(
            report.failures.is_empty(),
            "divergent history is not a missing chunk: {:?}",
            report.failures
        );
        assert!(report.publication_blocked);
        assert_eq!(report.pointers_rebuilt, 0);
        // The destination kept its own value.
        assert_eq!(dst.control.pointer_log.resolve("shared").unwrap(), b);
    }

    #[test]
    fn an_event_cannot_be_filed_under_another_pointer() {
        let tc = TestControl::new().unwrap();
        let cid = tc.control.store.put_chunk(b"v", None).unwrap();
        tc.control.pointer_log.create("real", cid).unwrap();

        let (_, _, event_cid) = tc.control.pointer_log.event_cids().unwrap()[0].clone();

        let err = tc
            .control
            .pointer_log
            .import_event("impostor", 1, &event_cid)
            .unwrap_err();
        assert!(err.to_string().contains("impostor"), "{}", err);
        assert!(tc
            .control
            .pointer_log
            .event_cids()
            .unwrap()
            .iter()
            .all(|(id, _, _)| id == "real"));
    }

    #[test]
    fn an_event_whose_chunk_is_missing_cannot_be_filed() {
        // The ordering guarantee: content moves first, so a mapping is never
        // written for an event whose bytes did not arrive.
        let tc = TestControl::new().unwrap();
        let absent = Cid::compute(b"never stored");

        let err = tc
            .control
            .pointer_log
            .import_event("p", 1, &absent)
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        assert!(tc.control.pointer_log.event_cids().unwrap().is_empty());
    }

    /// The pin counterpart of `an_event_cannot_be_filed_under_another_pointer`.
    #[test]
    fn a_pin_event_cannot_be_filed_under_another_pin() {
        let tc = TestControl::new().unwrap();
        let cid = tc.control.store.put_chunk(b"target", None).unwrap();
        tc.control
            .pin_log
            .create("real", PinTarget::Direct(cid), PinScope::Global, None, None)
            .unwrap();

        let (_, _, event_cid) = tc.control.pin_log.event_cids().unwrap()[0].clone();

        let err = tc
            .control
            .pin_log
            .import_event("impostor", 1, &event_cid)
            .unwrap_err();
        assert!(err.to_string().contains("impostor"), "{}", err);
        assert!(tc
            .control
            .pin_log
            .event_cids()
            .unwrap()
            .iter()
            .all(|(id, _, _)| id == "real"));
    }

    /// The pin counterpart of `a_gap_in_the_chain_is_refused`. Without it,
    /// seq 2 can be filed under a pin that has no seq 1 at all — which is how
    /// a hostile remote injects a deactivation.
    #[test]
    fn a_pin_event_cannot_be_filed_before_its_predecessor() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let target = put(&src, b"keep me");
        src.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        src.control.pin_log.deactivate("keep", None).unwrap();

        let events = src.control.pin_log.event_cids().unwrap();
        let (_, seq2, cid2) = events.iter().find(|(_, s, _)| *s == 2).unwrap().clone();

        // Move the bytes across but skip seq 1.
        let bytes = src.control.store.get_chunk(&cid2).unwrap();
        dst.control.store.put_chunk(&bytes, None).unwrap();

        let err = dst
            .control
            .pin_log
            .import_event("keep", seq2, &cid2)
            .unwrap_err();
        assert!(err.to_string().contains("before seq 1"), "{}", err);
        assert!(dst.control.pin_log.event_cids().unwrap().is_empty());
    }

    /// The measured attack, stated end to end: a hostile remote offers a
    /// deactivation of a pin *it* created, under a name the destination is
    /// already using for a live pin of its own. Filing it would switch the
    /// local pin off and unprotect its content, with sync reporting success.
    #[test]
    fn a_remote_cannot_deactivate_a_local_pin() {
        let hostile = TestControl::new().unwrap();
        let local = TestControl::new().unwrap();

        // The local pin that must survive.
        let mine = local.control.store.put_chunk(b"my content", None).unwrap();
        local
            .control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(mine.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        // The hostile remote's own chain under the same name, deactivated.
        let theirs = put(&hostile, b"their content");
        hostile
            .control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(theirs),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        hostile.control.pin_log.deactivate("keep", None).unwrap();

        let report = pull(&local.control, &hostile.control, &SyncOptions::default()).unwrap();

        assert!(
            !report.is_complete(),
            "a conflicting pin history was accepted silently: {:?}",
            report
        );
        assert!(
            report.divergent.iter().any(|f| f.reason.contains("keep")),
            "failures={:?} divergent={:?}",
            report.failures,
            report.divergent
        );

        let head = local.control.pin_log.head("keep").unwrap();
        assert_eq!(head.event.seq, 1, "the local pin's chain was extended");
        assert!(
            matches!(head.event.state, dag_core::PinState::Active),
            "the local pin was switched off by a remote"
        );
        assert_eq!(head.event.target, PinTarget::Direct(mine.clone()));
        local.control.retention.refresh_cache().unwrap();
        assert!(
            matches!(
                local.control.retention.status(&mine).unwrap(),
                crate::RetentionStatus::Protected(_)
            ),
            "content protected by a local pin became collectable"
        );
    }

    /// The reason the `prev` check is unconditional rather than "checked when
    /// present".
    ///
    /// Contiguity refuses seq N when seq N-1 is missing — but a chain that is
    /// *longer* than the local one has no gap to trip over. An attacker only
    /// has to hand-build an event one past the local head, and if a missing
    /// `prev` were tolerated as legacy history, it would be filed. That is a
    /// deactivation of somebody else's live pin, so the field is required.
    #[test]
    fn a_prev_less_event_cannot_be_grafted_onto_the_end_of_a_chain() {
        use dag_core::{Entry, PinEvent, PinState};

        let tc = TestControl::new().unwrap();
        let target = put(&tc, b"protected");
        tc.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        // Hand-built: no API can produce a `prev`-less event past seq 1, which
        // is the point — this is what a hostile or ancient peer offers.
        let forged = PinEvent {
            seq: 2,
            pin_id: "keep".to_string(),
            target: PinTarget::Direct(target.clone()),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 1,
            author: Some("not me".into()),
            prev: None,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&forged, &mut payload).unwrap();
        let forged_cid = tc
            .control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();

        let err = tc
            .control
            .pin_log
            .import_event("keep", 2, &forged_cid)
            .unwrap_err();
        assert!(err.to_string().contains("no `prev`"), "{}", err);

        tc.control.rebuild_pins(false).unwrap();
        let head = tc.control.pin_log.head("keep").unwrap();
        assert_eq!(head.event.seq, 1);
        assert!(matches!(head.event.state, PinState::Active));
    }

    /// A divergent seq 2: the predecessor is present, but the event claims to
    /// follow a *different* one. Refused, naming both CIDs.
    #[test]
    fn a_divergent_pin_event_is_refused() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        // Both sides create "keep" over the same target, so seq 1 is identical
        // — except for the timestamp, which is why we transfer seq 1 rather
        // than creating it locally.
        let target = put(&src, b"shared target");
        src.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        src.control.pin_log.deactivate("keep", None).unwrap();

        let events = src.control.pin_log.event_cids().unwrap();
        let (_, _, cid1) = events.iter().find(|(_, s, _)| *s == 1).unwrap().clone();
        let (_, _, cid2) = events.iter().find(|(_, s, _)| *s == 2).unwrap().clone();

        // Give the destination a *different* seq 1 for the same pin, then move
        // the source's seq 2 bytes across and try to graft it on.
        dst.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(put(&dst, b"other target")),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        for cid in [&cid1, &cid2] {
            let bytes = src.control.store.get_chunk(cid).unwrap();
            dst.control.store.put_chunk(&bytes, None).unwrap();
        }

        let err = dst
            .control
            .pin_log
            .import_event("keep", 2, &cid2)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("keep"), "{}", msg);
        assert!(msg.contains("breaks the chain"), "{}", msg);
        assert!(msg.contains(&cid1.to_hex()), "{}", msg);
    }

    /// The honest path still works: a pin created and later deactivated on the
    /// source replicates, chain intact, with the replica's events byte-identical.
    #[test]
    fn an_honest_pin_history_replicates_whole() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let target = put(&src, b"transient");
        src.control
            .pin_log
            .create(
                "temp",
                PinTarget::Direct(target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        src.control.pin_log.deactivate("temp", None).unwrap();

        let report = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(report.is_complete(), "{:?}", report.failures);
        assert_eq!(report.pin_events, 2);

        assert_eq!(
            src.control.pin_log.event_cids().unwrap(),
            dst.control.pin_log.event_cids().unwrap(),
            "the replica's pin log is not byte-identical"
        );
        let head = dst.control.pin_log.head("temp").unwrap();
        assert_eq!(head.event.seq, 2);
        assert!(matches!(head.event.state, dag_core::PinState::Deactivated));
    }

    /// A pin transfer interrupted after seq 1 converges when re-run — the
    /// contiguity check must not turn resumption into a permanent failure.
    #[test]
    fn a_partial_pin_transfer_converges_when_resumed() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let target = put(&src, b"payload");
        src.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let first = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(first.is_complete(), "{:?}", first.failures);
        assert_eq!(first.pin_events, 1);

        // The source deactivates after the first sync; the second must file
        // seq 2 on top of the seq 1 already there.
        src.control.pin_log.deactivate("keep", None).unwrap();

        let second = push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(second.is_complete(), "{:?}", second.failures);
        assert_eq!(second.pin_events, 1, "seq 2 did not arrive");
        assert_eq!(
            src.control.pin_log.event_cids().unwrap(),
            dst.control.pin_log.event_cids().unwrap()
        );
    }

    #[test]
    fn a_gap_in_the_chain_is_refused() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let v1 = put(&src, b"one");
        let v2 = put(&src, b"two");
        src.control.pointer_log.create("p", v1).unwrap();
        src.control.pointer_log.update("p", v2).unwrap();

        let events = src.control.pointer_log.event_cids().unwrap();
        let (_, seq2, cid2) = events.iter().find(|(_, s, _)| *s == 2).unwrap().clone();

        // Move the bytes across but skip seq 1.
        let bytes = src.control.store.get_chunk(&cid2).unwrap();
        dst.control.store.put_chunk(&bytes, None).unwrap();

        let err = dst
            .control
            .pointer_log
            .import_event("p", seq2, &cid2)
            .unwrap_err();
        assert!(err.to_string().contains("before seq 1"), "{}", err);
    }

    fn copy_enumerated_chunks(src: &TestControl, dst: &TestControl) -> SyncEnumeration {
        let enumeration = SyncSource::enumerate(&src.control, &SyncOptions::default()).unwrap();
        for cid in &enumeration.wanted {
            if let Ok(bytes) = src.control.store.get_chunk(cid) {
                dst.control.store.put_chunk(&bytes, None).unwrap();
            }
        }
        enumeration
    }

    #[test]
    fn invalid_late_pointer_event_leaves_no_prefix_for_a_later_finalize() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        let v1 = put(&src, b"atomic-pointer-v1");
        let v2 = put(&src, b"atomic-pointer-v2");
        src.control.pointer_log.create("release", v1).unwrap();
        src.control.pointer_log.update("release", v2).unwrap();
        let mut offered = copy_enumerated_chunks(&src, &dst).pointer_events;
        assert_eq!(offered.len(), 2);
        offered[1].0 = "wrong-id".into();

        let outcome = dst.control.import_event_batch(&offered, &[]).unwrap();
        assert!(matches!(outcome, EventBatchOutcome::Rejected(_)));
        assert!(dst.control.pointer_log.event_cids().unwrap().is_empty());

        let unrelated = TestControl::new().unwrap();
        let cid = put(&unrelated, b"unrelated");
        unrelated.control.pointer_log.create("other", cid).unwrap();
        let first = push(&unrelated.control, &dst.control, &SyncOptions::default()).unwrap();
        assert!(first.is_complete(), "{first:?}");
        assert_eq!(dst.control.pointer_log.event_cids().unwrap()[0].0, "other");
        let repeat = push(&unrelated.control, &dst.control, &SyncOptions::default()).unwrap();
        assert_eq!(repeat.pointer_events, 0, "repeat was not idempotent");
    }

    #[test]
    fn invalid_late_pin_rolls_back_pointer_and_pin_prefixes_together() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        let target = put(&src, b"atomic-pin-target");
        src.control
            .pointer_log
            .create("release", target.clone())
            .unwrap();
        src.control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        src.control.pin_log.deactivate("keep", None).unwrap();
        let enumeration = copy_enumerated_chunks(&src, &dst);
        let mut pins = enumeration.pin_events;
        assert_eq!(pins.len(), 2);
        pins[1].0 = "wrong-pin".into();

        let outcome = dst
            .control
            .import_event_batch(&enumeration.pointer_events, &pins)
            .unwrap();
        assert!(matches!(outcome, EventBatchOutcome::Rejected(_)));
        assert!(dst.control.pointer_log.event_cids().unwrap().is_empty());
        assert!(dst.control.pin_log.event_cids().unwrap().is_empty());

        let error = SyncDestination::finalize(&dst.control).unwrap_err();
        assert!(error.to_string().contains("sessionless"));
        assert!(dst.control.pointer_log.list_pointers().unwrap().is_empty());
        assert!(dst.control.pin_log.list().unwrap().is_empty());
    }

    #[test]
    fn unrecovered_finalize_rolls_back_every_derived_table_without_minting_recovery() {
        let tc = TestControl::new().unwrap();
        let first = put(&tc, b"first pointer target");
        let second = put(&tc, b"second pointer target");
        tc.control
            .pointer_log
            .create("release", first.clone())
            .unwrap();
        tc.control
            .pin_log
            .create(
                "hold",
                PinTarget::Direct(first.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        let pin_first_cid = tc.control.pin_log.event_cids().unwrap()[0].2.clone();

        let pointer_update =
            PointerEvent::update_event("release", 2, first.clone(), second.clone(), 2);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&pointer_update, &mut payload).unwrap();
        let pointer_event_cid = tc
            .control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();

        let pin_update = PinEvent {
            seq: 2,
            pin_id: "hold".into(),
            target: PinTarget::Direct(first.clone()),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: Some(pin_first_cid),
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&pin_update, &mut payload).unwrap();
        let pin_event_cid = tc
            .control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();

        // Simulate the event-only state left by a pre-atomic implementation
        // or recovered legacy database. The public SyncDestination path now
        // publishes these mappings and all derived state in one transaction.
        assert!(tc
            .control
            .pointer_log
            .import_event("release", 2, &pointer_event_cid)
            .unwrap());
        assert!(tc
            .control
            .pin_log
            .import_event("hold", 2, &pin_event_cid)
            .unwrap());

        // Primary entries that are deliberately not yet present in their
        // derived indexes. A successful finalize discovers both.
        let signer = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let signature_cid = dag_core::signing::sign_cid(
            tc.control.store.as_ref(),
            &second,
            None,
            serde_json::json!({}),
            &signer,
        )
        .unwrap();
        let effect_key = EffectKey::new(
            JobId::from("atomic-finalize".to_string()),
            Cid::compute(b"manifest"),
            "effect".into(),
        );
        let claim_cid = tc
            .control
            .store
            .put_entry(&crate::effects::claim_entry(
                &effect_key,
                &[("out".into(), second.clone())],
            ))
            .unwrap();

        for stage in 1..=5 {
            let error = tc.control.finalize_sync_state(Some(stage)).unwrap_err();
            assert!(error.to_string().contains("injected finalize failure"));
            assert_eq!(tc.control.pointer_log.get_head("release").unwrap().seq, 1);
            assert_eq!(tc.control.pin_log.head("hold").unwrap().event.seq, 1);
            assert!(tc
                .control
                .signature_log
                .list_for(&second)
                .unwrap()
                .is_empty());
            assert!(tc
                .control
                .job_log
                .claims_for_key(&effect_key)
                .unwrap()
                .is_empty());
            assert!(!tc.control.is_recovered().unwrap());
        }

        let counts = tc.control.finalize_sync_state(None).unwrap();
        assert_eq!(counts.pointers_rebuilt, 1);
        assert_eq!(counts.pins_rebuilt, 1);
        assert_eq!(tc.control.pointer_log.get_head("release").unwrap().seq, 2);
        assert_eq!(tc.control.pin_log.head("hold").unwrap().event.seq, 2);
        assert_eq!(
            tc.control.signature_log.list_for(&second).unwrap(),
            vec![signature_cid]
        );
        assert_eq!(
            tc.control.job_log.claims_for_key(&effect_key).unwrap(),
            vec![claim_cid]
        );
        assert!(
            !tc.control.is_recovered().unwrap(),
            "table-oriented sync finalization must not mint a full-store recovery verdict"
        );
    }

    #[test]
    fn empty_atomic_publication_preserves_an_existing_full_recovery_verdict() {
        let tc = TestControl::new().unwrap();
        tc.control.recovery_state.mark_complete_for_test().unwrap();
        let before_generation = tc.control.sync_event_generation().unwrap();

        let (outcome, counts) = tc
            .control
            .publish_durable_sync_snapshot_with_candidates(&[], &[], &[])
            .unwrap();

        assert_eq!(
            outcome,
            EventBatchOutcome::Applied {
                pointer_events: 0,
                pin_events: 0,
            }
        );
        assert_eq!(counts.pointers_rebuilt, 0);
        assert_eq!(counts.pins_rebuilt, 0);
        assert_eq!(counts.signatures_indexed, 0);
        assert_eq!(counts.claims_indexed, 0);
        assert_eq!(
            tc.control.sync_event_generation().unwrap(),
            before_generation
        );
        assert!(tc.control.is_recovered().unwrap());
    }

    #[test]
    fn bulk_sessionless_finalize_is_refused_without_mutation() {
        let tc = TestControl::new().unwrap();
        let target = put(&tc, b"bulk finalize pin target");
        tc.control
            .pin_log
            .create(
                "hold",
                PinTarget::Direct(target),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();

        let bulk = BulkDestination::new(&tc.control).unwrap();
        let error = SyncDestination::finalize(&bulk).unwrap_err();
        assert!(error.to_string().contains("sessionless"));
        assert_eq!(tc.control.pin_log.head("hold").unwrap().event.seq, 1);
    }

    #[test]
    fn atomic_publication_waits_for_mutations_before_excluding_content_writes() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(dir.path()).unwrap());
        let target = control.store.put_chunk(b"initial", None).unwrap();
        control
            .pointer_log
            .create("release", target.clone())
            .unwrap();

        // Hold a normal writer's first lock. A publication that takes the
        // durability barrier before waiting for the mutation barrier will now
        // block the independent content write below, reproducing the old
        // two-thread cycle. The fixed publication waits here without owning
        // durability, so the write must complete.
        let mutation_guard = control
            .mutation_gate
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let (publish_started_tx, publish_started_rx) = mpsc::channel();
        let (publish_done_tx, publish_done_rx) = mpsc::channel();
        let publishing = control.clone();
        let publish_thread = std::thread::spawn(move || {
            publish_started_tx.send(()).unwrap();
            publish_done_tx
                .send(publishing.publish_durable_sync_snapshot_with_candidates(&[], &[], &[target]))
                .unwrap();
        });
        publish_started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(50));

        let (write_done_tx, write_done_rx) = mpsc::channel();
        let writing = control.clone();
        let write_thread = std::thread::spawn(move || {
            write_done_tx
                .send(writing.store.put_chunk(b"concurrent", None))
                .unwrap();
        });
        let write_result = write_done_rx.recv_timeout(Duration::from_secs(2));

        // Always release and join before asserting so a regression reports a
        // failure instead of leaving blocked test threads behind.
        drop(mutation_guard);
        assert!(publish_done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_ok());
        publish_thread.join().unwrap();
        write_thread.join().unwrap();
        assert!(
            write_result.unwrap().is_ok(),
            "publication acquired durability while it was still waiting for the mutation barrier"
        );
    }

    #[test]
    fn publish_sync_snapshot_files_events_and_heads_in_one_commit() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();
        assert!(!dst.control.is_recovered().unwrap());
        let target = put(&src, b"atomic publish target");
        src.control
            .pointer_log
            .create("release", target.clone())
            .unwrap();
        src.control
            .pin_log
            .create(
                "hold",
                PinTarget::Direct(target.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        let enumeration = copy_enumerated_chunks(&src, &dst);

        let (outcome, counts) = dst
            .control
            .publish_sync_snapshot(&enumeration.pointer_events, &enumeration.pin_events)
            .unwrap();
        assert!(matches!(
            outcome,
            EventBatchOutcome::Applied {
                pointer_events: 1,
                pin_events: 1
            }
        ));
        assert_eq!(counts.pointers_rebuilt, 1);
        assert_eq!(counts.pins_rebuilt, 1);
        assert_eq!(dst.control.pointer_log.resolve("release").unwrap(), target);
        assert_eq!(dst.control.pin_log.head("hold").unwrap().event.seq, 1);
        assert!(
            !dst.control.is_recovered().unwrap(),
            "publishing a bounded sync snapshot must not certify the destination's pre-existing store"
        );

        dst.control.recovery_state.mark_complete_for_test().unwrap();

        let (repeat, _) = dst
            .control
            .publish_sync_snapshot(&enumeration.pointer_events, &enumeration.pin_events)
            .unwrap();
        assert!(matches!(
            repeat,
            EventBatchOutcome::Applied {
                pointer_events: 0,
                pin_events: 0
            }
        ));
        assert!(
            dst.control.is_recovered().unwrap(),
            "a publication may preserve a prior full-store recovery verdict"
        );
    }

    #[test]
    fn missing_new_head_descendant_leaves_old_publication_unchanged() {
        let src = TestControl::new().unwrap();
        let dst = TestControl::new().unwrap();

        let old_target = put(&dst, b"old published target");
        dst.control
            .pointer_log
            .create("old", old_target.clone())
            .unwrap();
        let before_events = dst.control.pointer_log.event_cids().unwrap();
        let before_pointers = dst.control.pointer_log.list_pointers().unwrap();

        let child = put(&src, b"required descendant");
        let root = src
            .control
            .store
            .put_entry(&Entry {
                payload: Vec::new(),
                links: vec![Link {
                    name: Some("child".to_string()),
                    target: child,
                }],
                meta: None,
            })
            .unwrap();
        src.control.pointer_log.create("new", root.clone()).unwrap();
        let offered = src.control.pointer_log.event_cids().unwrap();

        // Copy the event entry and its root, but intentionally not the
        // root's child. Event-chain validation alone therefore succeeds;
        // full publication-closure validation must fail before the write txn.
        for cid in offered
            .iter()
            .map(|(_, _, cid)| cid)
            .chain(std::iter::once(&root))
        {
            let bytes = src.control.store.get_chunk(cid).unwrap();
            assert_eq!(dst.control.store.put_chunk(&bytes, None).unwrap(), *cid);
        }

        assert!(dst.control.publish_sync_snapshot(&offered, &[]).is_err());
        assert_eq!(dst.control.pointer_log.event_cids().unwrap(), before_events);
        assert_eq!(
            dst.control.pointer_log.list_pointers().unwrap(),
            before_pointers
        );
        assert_eq!(dst.control.pointer_log.resolve("old").unwrap(), old_target);
        assert!(dst.control.pointer_log.resolve("new").is_err());
    }
}
