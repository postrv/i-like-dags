use crate::gc::{BatchDelete, GcCapableStore};
use crate::{ChunkIndex, ChunkLocation};
use dag_core::{Cid, ContentStore, CoreError, CID_LEN, MAX_CHUNK_SIZE};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
#[cfg(not(unix))]
use tempfile::NamedTempFile;
use tracing::{debug, info};

#[cfg(unix)]
use rustix::fs::{self as unix_fs, AtFlags, Dir, FileType, Mode, OFlags};
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// How hard [`FsStore`] works to make a chunk survive power loss.
///
/// The store is one half of a pair: the redb index commits with redb's default
/// immediate durability, so *it* is fsynced on every insert. If chunk bytes
/// were not, the two halves would disagree after a crash in the worst possible
/// direction — a durable index naming files that are absent or truncated,
/// which is data loss reached without anyone deleting anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DurabilityPolicy {
    /// Every chunk is durable before the index names it. The default.
    ///
    /// Costs two fsyncs per chunk (the file, then the directory whose rename
    /// published it), plus a third the first time a shard directory is
    /// created. See [`FsStore::put_chunk`] for the ordering.
    #[default]
    Durable,
    /// Skip the fsyncs at write time and do them in
    /// [`ContentStore::sync`].
    ///
    /// **This trades durability for throughput.** Between a `put_chunk` and
    /// the next `sync`, a crash can lose the chunk. It is the right choice
    /// only when the writer can replay its input: a bulk import that can be
    /// re-run, a cache, a test.
    ///
    /// What it does *not* trade away is the ordering invariant: the index
    /// entry is deferred along with the fsyncs and written after them, so a
    /// crash mid-ingest leaves unindexed files — garbage, which `reindex` or
    /// the next collection sweeps up — rather than a durable index naming
    /// bytes that never landed. Deferring the fsyncs alone would have
    /// reintroduced exactly the corruption [`DurabilityPolicy::Durable`]
    /// exists to prevent, for the whole window between a write and its sync.
    ///
    /// The pending set is bounded by [`FsStore::DEFERRED_SYNC_THRESHOLD`], at
    /// which point the store flushes itself, so "forgot to call sync" costs at
    /// most that many chunks rather than everything ever written.
    Deferred,
}

/// How many fsyncs the store has issued, for operators asking where the time
/// went and for tests asserting that it issued any at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityStats {
    /// Chunk files fsynced.
    pub file_syncs: u64,
    /// Directories fsynced. Higher than `file_syncs` is normal: a new shard
    /// costs the shard directory *and* the data directory that names it.
    pub dir_syncs: u64,
}

/// Work owed under [`DurabilityPolicy::Deferred`].
#[derive(Clone, Default)]
struct Pending {
    /// Canonical chunk names whose file contents still need an fsync.
    ///
    /// CIDs, rather than paths, are retained deliberately. A later flush
    /// re-opens each file relative to the anchored data-directory descriptor;
    /// keeping a path here would reintroduce the shard-symlink escape on the
    /// delayed durability path.
    files: HashSet<Cid>,
    /// Two-hex shard names whose directory entries still need an fsync.
    dirs: HashSet<String>,
    /// A newly-created shard made the data directory itself dirty.
    root_dirty: bool,
    /// Index entries held back until the bytes they name are durable.
    ///
    /// Keyed by CID so re-putting the same chunk cannot grow this without
    /// bound: it stays one entry per pending file, which is what lets
    /// [`FsStore::DEFERRED_SYNC_THRESHOLD`] bound the whole set.
    index: HashMap<Cid, ChunkLocation>,
}

impl Pending {
    fn merge(&mut self, other: Self) {
        self.files.extend(other.files);
        self.dirs.extend(other.dirs);
        self.index.extend(other.index);
        self.root_dirty |= other.root_dirty;
    }
}

/// Shared deferred-write state for every [`FsStore`] view over one data
/// directory.
///
/// A control plane has a durable store and may create several deferred bulk
/// views over the same bytes and index. Publication must wait for mutations
/// through *all* of those views and flush all of their pending writes, not
/// merely the view that happens to publish an event. [`FsStore::coordination`]
/// and [`FsStore::with_coordination`] let the owner make that relationship
/// explicit without exposing the locks themselves.
#[derive(Clone, Default)]
pub struct DurabilityCoordination {
    gate: Arc<RwLock<()>>,
    pending: Arc<Mutex<Pending>>,
}

/// The state [`InFlightRegistry`] guards: the recent writes and the counter
/// that drives its opportunistic pruning.
struct InFlightInner {
    writes: HashMap<Cid, Instant>,
    /// Writes recorded since the last opportunistic prune.
    since_prune: usize,
}

/// Shared record of which CIDs a set of cooperating [`FsStore`]s wrote — or
/// referenced by deduplication — recently, and when.
///
/// Collection unions this into its protected set and consults it as a last
/// gate, so a chunk touched moments ago is off limits even while it is
/// unreferenced and unpinned. See the `recent_writes` field on [`FsStore`]
/// for the full rationale.
///
/// It is a handle, not a copy. [`FsStore::in_flight_registry`] hands one out
/// and [`FsStore::with_in_flight_registry`] adopts it, so two stores over the
/// same directory — a bulk-ingest view and the control-plane store it was
/// forked from — answer [`FsStore::recently_written`] and
/// [`GcCapableStore::is_in_flight`] as one. Without sharing, a write through
/// one view is invisible to a collection driven through the other, which is
/// how a bulk ingest could have a chunk collected out from under it.
#[derive(Clone)]
pub struct InFlightRegistry {
    inner: Arc<Mutex<InFlightInner>>,
    /// Prune every this many `note`s. See [`InFlightRegistry::note`].
    prune_interval: usize,
    /// On a prune, drop everything older than this. See
    /// [`InFlightRegistry::note`].
    ceiling: Duration,
}

impl InFlightRegistry {
    /// How many `note`s trigger an opportunistic prune.
    ///
    /// Large enough that the prune is off the hot path of any realistic write
    /// burst, small enough that a runaway map is caught long before it matters.
    const DEFAULT_PRUNE_INTERVAL: usize = 4096;

    /// The age past which an opportunistic prune drops an entry.
    ///
    /// This must comfortably exceed any plausible single ingest, because an
    /// entry is what keeps a chunk that ingest deduplicated against safe from a
    /// concurrent collection. One hour does: the largest `split` the review
    /// measured ran for minutes, not hours.
    ///
    /// The residual exposure is an ingest that runs *longer* than this while
    /// deduplicating against old chunks, racing an in-process collection: an
    /// entry pruned at the ceiling would stop protecting a chunk the still-live
    /// ingest depends on. It is not reachable today — collection and ingest
    /// cannot both hold the same directory across processes (the redb lock),
    /// and no in-process path drives them together — and the ceiling is set so
    /// that even when such a path exists, only a pathologically long ingest
    /// could reach it.
    const DEFAULT_PRUNE_CEILING: Duration = Duration::from_secs(3600);

    fn new() -> Self {
        Self::with_bounds(Self::DEFAULT_PRUNE_INTERVAL, Self::DEFAULT_PRUNE_CEILING)
    }

    /// Build a registry with explicit bounds.
    ///
    /// `pub(crate)` for the pruning test, which needs the prune to fire without
    /// issuing [`InFlightRegistry::DEFAULT_PRUNE_INTERVAL`] writes; production
    /// goes through [`InFlightRegistry::new`].
    pub(crate) fn with_bounds(prune_interval: usize, ceiling: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InFlightInner {
                writes: HashMap::new(),
                since_prune: 0,
            })),
            prune_interval,
            ceiling,
        }
    }

    /// Record that `cid` was just written or referenced.
    ///
    /// Prunes opportunistically: once [`InFlightRegistry::prune_interval`]
    /// writes have landed since the last prune, it drops everything older than
    /// [`InFlightRegistry::ceiling`]. Without this the map only ever shrank
    /// inside `recently_written`, which a collection drives — so a server that
    /// writes constantly and never collects grew it forever.
    fn note(&self, cid: &Cid) {
        let mut inner = self.inner.lock();
        Self::note_locked(&mut inner, cid, self.prune_interval, self.ceiling);
    }

    /// Note `cid` **and**, without releasing the lock, run the final presence
    /// check supplied by the store.
    ///
    /// The two halves have to be one step. A deduplicating write checks that
    /// a file is present, verifies its bytes, and then indexes it — and
    /// [`FsStore::delete_chunks`] holds this same lock across its whole
    /// batch. Registering and re-checking separately lets a batch land in
    /// between, after which the write indexes a file that is gone and
    /// returns success: the caller is told the chunk is stored, the index
    /// agrees, and the bytes are not there. Under the lock the two
    /// operations are serialised against the batch, so the answer is either
    /// "noted, and the batch will now skip it" or "the batch already took
    /// it, and you must write the bytes again".
    fn note_and_check<T, E>(
        &self,
        cid: &Cid,
        check: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let mut inner = self.inner.lock();
        Self::note_locked(&mut inner, cid, self.prune_interval, self.ceiling);
        check()
    }

    /// The body of [`Self::note`], for callers already holding the lock.
    fn note_locked(inner: &mut InFlightInner, cid: &Cid, prune_interval: usize, ceiling: Duration) {
        inner.writes.insert(cid.clone(), Instant::now());
        inner.since_prune += 1;
        if inner.since_prune >= prune_interval {
            let now = Instant::now();
            inner
                .writes
                .retain(|_, at| now.duration_since(*at) < ceiling);
            inner.since_prune = 0;
        }
    }

    /// CIDs noted within the last `within`, pruning older entries as it goes
    /// so the set cannot grow without bound across collections.
    fn recent(&self, within: Duration) -> HashSet<Cid> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        inner
            .writes
            .retain(|_, at| now.duration_since(*at) < within);
        inner.writes.keys().cloned().collect()
    }

    /// Whether `cid` was noted within the last `within`. A zero window
    /// protects nothing.
    fn is_recent(&self, cid: &Cid, within: Duration) -> bool {
        !within.is_zero()
            && self
                .inner
                .lock()
                .writes
                .get(cid)
                .is_some_and(|at| at.elapsed() < within)
    }

    /// Run `f` with the registry locked, handing it a recency check over the
    /// held state.
    ///
    /// This is the atomicity a batched deletion needs. Check-then-delete has
    /// a window: a `note` landing between the check and the unlink names a
    /// chunk the sweep then removes — the concurrency soak caught exactly
    /// that, an adopted revert losing its bytes. Holding the lock across
    /// check *and* removal closes it both ways: a name registered before the
    /// check is honoured, and one racing the batch blocks until the batch is
    /// done — after which the namer's own read-back reports the chunk gone,
    /// which is the honest answer for content that was garbage when the
    /// sweep began. Writers stall for the batch duration (tens of
    /// milliseconds per 512 chunks); correctness is worth every one of them.
    fn with_exclusive_check<T>(&self, f: impl FnOnce(&dyn Fn(&Cid, Duration) -> bool) -> T) -> T {
        let inner = self.inner.lock();
        let check = |cid: &Cid, within: Duration| {
            !within.is_zero()
                && inner
                    .writes
                    .get(cid)
                    .is_some_and(|at| at.elapsed() < within)
        };
        f(&check)
    }

    /// Number of CIDs currently tracked, before any age filter.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inner.lock().writes.len()
    }
}

/// The deployment's data directory, opened once and retained as the authority
/// for every descendant operation.
///
/// On Unix this is a directory descriptor. Opening shard directories relative
/// to it with `O_NOFOLLOW` means replacing `<data>/aa` with a symlink can never
/// redirect a read, rename, or unlink to the symlink's target. The path remains
/// only for diagnostics and the public `chunk_path` helper.
struct StoreRoot {
    #[cfg(unix)]
    directory: fs::File,
}

impl StoreRoot {
    fn open(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(unsafe_path_error(
                path,
                "data directory is not a real directory",
            ));
        }

        #[cfg(unix)]
        {
            let descriptor = unix_fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?;
            let directory = fs::File::from(descriptor);
            if !directory.metadata()?.is_dir() {
                return Err(unsafe_path_error(
                    path,
                    "data directory changed type while opening",
                ));
            }
            Ok(Self { directory })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

/// One verified two-hex shard directory.
struct ShardDirectory {
    name: String,
    path: PathBuf,
    created: bool,
    #[cfg(unix)]
    directory: fs::File,
}

/// A verified regular chunk file and the shard descriptor that anchors it.
struct OpenChunk {
    file: fs::File,
    shard: ShardDirectory,
}

/// A chunk selected for deletion after every path component was validated.
struct DeleteTarget {
    cid: Cid,
    leaf: String,
    shard: Option<ShardDirectory>,
}

/// Unique names for descriptor-relative temporary files. `O_EXCL` remains the
/// authority; the counter only makes collisions exceptional rather than a hot
/// loop.
#[cfg(unix)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unsafe_path_error(path: &Path, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsafe chunk-store path {}: {detail}", path.display()),
    )
}

fn is_hex_name(name: &str, len: usize) -> bool {
    name.len() == len
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub struct FsStore {
    data_dir: PathBuf,
    /// Descriptor-anchored authority for `data_dir`; see [`StoreRoot`].
    root: Arc<StoreRoot>,
    index: Option<Arc<ChunkIndex>>,
    durability: DurabilityPolicy,
    coordination: DurabilityCoordination,
    file_syncs: AtomicU64,
    dir_syncs: AtomicU64,
    /// CIDs this process has written, and when.
    ///
    /// A chunk is unreferenced and unpinned between the moment it is written
    /// and the moment something names it — for a large file that window spans
    /// the whole ingest, and a concurrent collection would take the lot.
    /// Collection consults this so recent writes are off limits.
    ///
    /// In memory, and only this process's writes, which is exactly right:
    /// redb locks a data directory to one process, so there is no other
    /// writer whose in-flight work could be missed.
    ///
    /// It also repairs a hole in the file-mtime approach it supplements —
    /// deduplication reuses an existing file untouched, so an old mtime made
    /// a just-referenced chunk look ancient and collectable.
    ///
    /// Held behind [`InFlightRegistry`] so a forked view (a bulk-ingest store
    /// over the same directory) can share it rather than keep its own that a
    /// collection driven through this store would never see.
    recent_writes: InFlightRegistry,
    /// Optional per-deployment registry; see [`FsStore::with_metrics`].
    metrics: Option<Arc<dag_core::Metrics>>,
    /// Deferred self-flush point; see [`FsStore::with_deferred_sync_threshold`].
    deferred_sync_threshold: usize,
}

/// Windows has no directory handle reachable through `std::fs::File`, and NTFS
/// journals directory metadata, so there is nothing to do and nothing to fake.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

impl FsStore {
    /// Deferred writes flush themselves once this many chunks are outstanding.
    ///
    /// Bounds the pending set's memory and the blast radius of a caller who
    /// never calls [`FsStore::sync`]. At this default the amortisation is
    /// modest — roughly one fsync per chunk, since a flush of N files costs
    /// N fsyncs — which is the right trade for a store that might not be
    /// re-runnable. Bulk paths that *are* re-runnable raise it with
    /// [`FsStore::with_deferred_sync_threshold`].
    pub const DEFERRED_SYNC_THRESHOLD: usize = 1024;

    pub fn new<P: AsRef<Path>>(data_dir: P) -> io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        let root = Arc::new(StoreRoot::open(&data_dir)?);
        Ok(Self::from_parts(data_dir, root, None))
    }

    fn from_parts(data_dir: PathBuf, root: Arc<StoreRoot>, index: Option<Arc<ChunkIndex>>) -> Self {
        Self {
            data_dir,
            root,
            index,
            durability: DurabilityPolicy::default(),
            coordination: DurabilityCoordination::default(),
            file_syncs: AtomicU64::new(0),
            recent_writes: InFlightRegistry::new(),
            dir_syncs: AtomicU64::new(0),
            metrics: None,
            deferred_sync_threshold: Self::DEFERRED_SYNC_THRESHOLD,
        }
    }

    /// Raise (or lower) the deferred self-flush threshold.
    ///
    /// Each pending entry holds a path and an index location — call it a few
    /// hundred bytes — so 65 536 outstanding chunks is tens of megabytes of
    /// memory and, on a crash, that many re-ingestable files to sweep. For a
    /// replayable bulk writer that is the right side of the trade: the
    /// per-chunk fsync tax is what made a million-chunk ingest I/O-bound on
    /// the *flushes* rather than the writes (scale-envelope experiment).
    /// Ignored under [`DurabilityPolicy::Durable`], which has no pending set.
    pub fn with_deferred_sync_threshold(mut self, threshold: usize) -> Self {
        self.deferred_sync_threshold = threshold.max(1);
        self
    }

    /// Record put/get counts, bytes and latency into `metrics`.
    ///
    /// Off unless wired: a bare `FsStore` stays observation-free, and the
    /// control plane passes its own registry in so every store sharing one
    /// directory reports to one place.
    pub fn with_metrics(mut self, metrics: Arc<dag_core::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Whether the data directory holds any chunk at all, stopping at the
    /// first one found.
    ///
    /// The cheap counterpart of `list_all_cids` for callers that only need
    /// emptiness: at a million chunks the full walk costs minutes, and
    /// "is there anything here" is answerable from the first directory
    /// entry.
    pub fn has_any_chunk(&self) -> bool {
        match self.scan_cids(Some(1)) {
            Ok(cids) => !cids.is_empty(),
            Err(error) => {
                // This is an evidence probe used before recovery. An unsafe
                // tree must not look empty and let recovery/GC proceed.
                tracing::warn!(
                    path = %self.data_dir.display(),
                    error = %error,
                    "chunk-store emptiness probe refused an unsafe entry"
                );
                true
            }
        }
    }

    /// A handle to this store's in-flight registry, to hand to another store
    /// over the same directory so the two share one view of recent writes.
    /// See [`InFlightRegistry`].
    pub fn in_flight_registry(&self) -> InFlightRegistry {
        self.recent_writes.clone()
    }

    /// Share `registry` in place of this store's own, so writes here are
    /// visible to [`FsStore::recently_written`] and
    /// [`GcCapableStore::is_in_flight`] on every store that holds it.
    pub fn with_in_flight_registry(mut self, registry: InFlightRegistry) -> Self {
        self.recent_writes = registry;
        self
    }

    /// Choose a [`DurabilityPolicy`]; the default is
    /// [`DurabilityPolicy::Durable`].
    ///
    /// ```
    /// use dag_storage::{DurabilityPolicy, FsStore};
    /// use dag_core::ContentStore;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// // A bulk import that can be re-run if the machine dies mid-way.
    /// let store = FsStore::new(dir.path()).unwrap()
    ///     .with_durability(DurabilityPolicy::Deferred);
    /// store.put_chunk(b"one of many", None).unwrap();
    /// store.sync().unwrap(); // …and only now is any of it durable.
    /// ```
    pub fn with_durability(mut self, durability: DurabilityPolicy) -> Self {
        self.durability = durability;
        self
    }

    /// Return the deferred-write coordinator used by this store.
    ///
    /// Hand this to every other [`FsStore`] opened over the same data
    /// directory and index. That makes a publication barrier cover in-flight
    /// writes and pending fsyncs from every view, including concurrent bulk
    /// ingests.
    pub fn coordination(&self) -> DurabilityCoordination {
        self.coordination.clone()
    }

    /// Join the deferred-write coordinator of another view over this store.
    ///
    /// The caller must use a coordinator from the same data directory and
    /// index. Owners such as `dag-control` establish that invariant when they
    /// construct their staging views.
    pub fn with_coordination(mut self, coordination: DurabilityCoordination) -> Self {
        self.coordination = coordination;
        self
    }

    /// Make every coordinated write durable, then run one metadata
    /// publication while new content mutations remain excluded.
    ///
    /// This is the crash-consistency boundary for event import and derived
    /// head rebuilding. A plain `sync()` followed by publication is not
    /// sufficient: another writer can rename a deferred chunk into view in
    /// the gap. Keeping the exclusive gate through `publish` removes that
    /// check-then-act window.
    pub fn with_durable_publication<T, E>(
        &self,
        publish: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<CoreError>,
    {
        let _publication = self.coordination.gate.write();
        self.sync_exclusive()?;
        publish()
    }

    /// Flush the coordinated pending registry and return how many chunk files
    /// the barrier observed.
    ///
    /// Counting and taking the registry happen under the same exclusive gate,
    /// so the value cannot under-report a put that the call itself flushes.
    pub fn flush_pending_writes(&self) -> Result<usize, CoreError> {
        let _publication = self.coordination.gate.write();
        let pending = self.coordination.pending.lock().files.len();
        self.sync_exclusive()?;
        Ok(pending)
    }

    pub fn durability(&self) -> DurabilityPolicy {
        self.durability
    }

    pub fn durability_stats(&self) -> DurabilityStats {
        DurabilityStats {
            file_syncs: self.file_syncs.load(Ordering::Relaxed),
            dir_syncs: self.dir_syncs.load(Ordering::Relaxed),
        }
    }

    /// Chunks written through any coordinated view but not yet made durable.
    ///
    /// A standalone durable store reports zero. A durable owner that shares
    /// coordination with deferred staging views reports their pending work.
    pub fn pending_sync_count(&self) -> usize {
        self.coordination.pending.lock().files.len()
    }

    /// Note that `cid` was just written, so collection leaves it alone for a
    /// while. See [`FsStore::recent_writes`] for why this exists.
    fn note_write(&self, cid: &Cid) {
        self.recent_writes.note(cid);
    }

    /// CIDs this process wrote within the last `within`, pruning older
    /// entries as it goes so the set cannot grow without bound.
    ///
    /// Collection unions this into its protected set. Passing the same
    /// `within` it uses for the minimum chunk age keeps one notion of "too
    /// young to collect" rather than two that can disagree.
    pub fn recently_written(&self, within: Duration) -> HashSet<Cid> {
        self.recent_writes.recent(within)
    }

    /// Open a store with its own standalone index database.
    ///
    /// `index_db_path` names a redb *file* (pre-migration layouts used a sled
    /// directory here; `dag migrate` converts them).
    pub fn with_index<P: AsRef<Path>>(data_dir: P, index_db_path: P) -> Result<Self, CoreError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        let root = Arc::new(StoreRoot::open(&data_dir)?);

        let index = Arc::new(ChunkIndex::new(index_db_path)?);
        Ok(Self::from_parts(data_dir, root, Some(index)))
    }

    /// Open a store over an index the caller already built.
    ///
    /// This is how `Control` shares one database file across the whole control
    /// plane: it constructs the [`ChunkIndex`] on its own database and hands it
    /// in here.
    pub fn with_chunk_index<P: AsRef<Path>>(
        data_dir: P,
        index: Arc<ChunkIndex>,
    ) -> Result<Self, CoreError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;
        let root = Arc::new(StoreRoot::open(&data_dir)?);
        Ok(Self::from_parts(data_dir, root, Some(index)))
    }

    /// On-disk location of a chunk: `<data_dir>/<first-two-hex>/<rest>`.
    ///
    /// Public so operators and tests can reach a chunk's bytes without
    /// re-deriving the sharded layout — a copy of this rule that drifts from
    /// the real one fails silently, which is exactly the kind of bug an
    /// integrity checker exists to catch.
    pub fn chunk_path(&self, cid: &Cid) -> PathBuf {
        let hex = cid.to_hex();

        // A well-formed CID is 64 hex characters. Anything else cannot name a
        // stored chunk, so it gets a path that is guaranteed not to exist and
        // cannot alias one: `malformed` is seven characters, and every shard
        // directory is exactly two. Returning a miss beats panicking on the
        // `split_at` boundary, which a malformed CID reaching this far used to
        // do.
        if hex.len() != CID_LEN * 2 {
            return self.data_dir.join("malformed").join(hex);
        }

        let (prefix, rest) = hex.split_at(2);
        self.data_dir.join(prefix).join(rest)
    }

    pub fn get_index(&self) -> Option<Arc<ChunkIndex>> {
        self.index.clone()
    }

    fn chunk_names(cid: &Cid) -> (String, String) {
        let hex = cid.to_hex();
        // `Cid` itself guarantees 32 digest bytes. Keep the defensive branch
        // in `chunk_path` for malformed future implementations, but internal
        // descriptor-relative operations never accept a non-canonical name.
        let (shard, leaf) = hex.split_at(2);
        (shard.to_owned(), leaf.to_owned())
    }

    /// Open one shard relative to the anchored root, optionally creating it.
    /// Symlinks and non-directories are errors, never aliases for a shard.
    #[cfg(unix)]
    fn open_shard_name(&self, name: &str, create: bool) -> io::Result<Option<ShardDirectory>> {
        if !is_hex_name(name, 2) {
            return Err(unsafe_path_error(
                &self.data_dir.join(name),
                "shard name is not two hexadecimal characters",
            ));
        }

        let created = if create {
            match unix_fs::mkdirat(&self.root.directory, name, Mode::from(0o755)) {
                Ok(()) => true,
                Err(error) if error == rustix::io::Errno::EXIST => false,
                Err(error) => return Err(io::Error::from(error)),
            }
        } else {
            false
        };

        let descriptor = match unix_fs::openat(
            &self.root.directory,
            name,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if !create && error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(io::Error::from(error)),
        };
        let directory = fs::File::from(descriptor);
        if !directory.metadata()?.is_dir() {
            return Err(unsafe_path_error(
                &self.data_dir.join(name),
                "shard changed type while opening",
            ));
        }
        Ok(Some(ShardDirectory {
            name: name.to_owned(),
            path: self.data_dir.join(name),
            created,
            directory,
        }))
    }

    #[cfg(not(unix))]
    fn open_shard_name(&self, name: &str, create: bool) -> io::Result<Option<ShardDirectory>> {
        if !is_hex_name(name, 2) {
            return Err(unsafe_path_error(
                &self.data_dir.join(name),
                "shard name is not two hexadecimal characters",
            ));
        }
        // Re-check the root on every path-based platform operation. Unix uses
        // a stable descriptor above; this is the strongest portable fallback
        // without platform-specific reparse-point handles.
        let root_metadata = fs::symlink_metadata(&self.data_dir)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(unsafe_path_error(
                &self.data_dir,
                "data directory is not a real directory",
            ));
        }

        let path = self.data_dir.join(name);
        let created = if create {
            match fs::create_dir(&path) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(unsafe_path_error(&path, "shard is not a real directory"));
        }
        Ok(Some(ShardDirectory {
            name: name.to_owned(),
            path,
            created,
        }))
    }

    fn open_shard(&self, cid: &Cid, create: bool) -> io::Result<Option<ShardDirectory>> {
        let (name, _) = Self::chunk_names(cid);
        self.open_shard_name(&name, create)
    }

    /// Check the final component without following it.
    ///
    /// `Ok(false)` is only absence. A symlink, directory, device, FIFO, or
    /// socket is an integrity error and must not be treated as a cache miss: a
    /// put that silently repaired such an entry could act on a path an attacker
    /// controls, and a GC pass must never unlink through one.
    #[cfg(unix)]
    fn chunk_entry_is_regular(&self, shard: &ShardDirectory, leaf: &str) -> io::Result<bool> {
        let stat = match unix_fs::statat(&shard.directory, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
            Err(error) => return Err(io::Error::from(error)),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(unsafe_path_error(
                &shard.path.join(leaf),
                "chunk entry is a symlink or special file",
            ));
        }
        Ok(true)
    }

    #[cfg(not(unix))]
    fn chunk_entry_is_regular(&self, shard: &ShardDirectory, leaf: &str) -> io::Result<bool> {
        // Validate the shard again immediately before touching its child.
        let shard_metadata = fs::symlink_metadata(&shard.path)?;
        if shard_metadata.file_type().is_symlink() || !shard_metadata.is_dir() {
            return Err(unsafe_path_error(
                &shard.path,
                "shard is not a real directory",
            ));
        }
        let path = shard.path.join(leaf);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(unsafe_path_error(
                &path,
                "chunk entry is a symlink or special file",
            ));
        }
        Ok(true)
    }

    fn open_chunk_file(&self, cid: &Cid) -> io::Result<Option<OpenChunk>> {
        let (_, leaf) = Self::chunk_names(cid);
        let Some(shard) = self.open_shard(cid, false)? else {
            return Ok(None);
        };
        if !self.chunk_entry_is_regular(&shard, &leaf)? {
            return Ok(None);
        }

        #[cfg(unix)]
        let file = {
            let descriptor = unix_fs::openat(
                &shard.directory,
                leaf.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?;
            fs::File::from(descriptor)
        };
        #[cfg(not(unix))]
        let file = fs::File::open(shard.path.join(&leaf))?;

        if !file.metadata()?.is_file() {
            return Err(unsafe_path_error(
                &shard.path.join(&leaf),
                "chunk changed type while opening",
            ));
        }
        Ok(Some(OpenChunk { file, shard }))
    }

    fn read_chunk_bytes(&self, mut file: fs::File, path: &Path) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_CHUNK_SIZE as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(unsafe_path_error(
                path,
                "chunk file exceeds the maximum chunk size",
            ));
        }
        Ok(bytes)
    }

    #[cfg(unix)]
    fn same_open_file(&self, cid: &Cid, expected: &fs::File) -> io::Result<bool> {
        let expected = expected.metadata()?;
        let Some(current) = self.open_chunk_file(cid)? else {
            return Ok(false);
        };
        let current = current.file.metadata()?;
        Ok(expected.dev() == current.dev() && expected.ino() == current.ino())
    }

    #[cfg(not(unix))]
    fn same_open_file(&self, cid: &Cid, expected: &fs::File) -> io::Result<bool> {
        let expected = expected.metadata()?;
        let Some(current) = self.open_chunk_file(cid)? else {
            return Ok(false);
        };
        let current = current.file.metadata()?;
        Ok(expected.len() == current.len() && expected.modified().ok() == current.modified().ok())
    }

    fn sync_root_counted(&self) -> Result<(), CoreError> {
        #[cfg(unix)]
        self.root.directory.sync_all().map_err(CoreError::Io)?;
        #[cfg(not(unix))]
        sync_dir(&self.data_dir).map_err(CoreError::Io)?;
        self.dir_syncs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn sync_shard_counted(&self, shard: &ShardDirectory) -> Result<(), CoreError> {
        #[cfg(unix)]
        shard.directory.sync_all().map_err(CoreError::Io)?;
        #[cfg(not(unix))]
        sync_dir(&shard.path).map_err(CoreError::Io)?;
        self.dir_syncs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(unix)]
    fn create_temp_in_shard(&self, shard: &ShardDirectory) -> io::Result<(fs::File, String)> {
        for _ in 0..128 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".dag-tmp-{}-{sequence:016x}", std::process::id());
            match unix_fs::openat(
                &shard.directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from(0o600),
            ) {
                Ok(descriptor) => return Ok((fs::File::from(descriptor), name)),
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(io::Error::from(error)),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary chunk name",
        ))
    }

    fn prepare_delete(&self, cid: &Cid) -> io::Result<DeleteTarget> {
        let (_, leaf) = Self::chunk_names(cid);
        let Some(shard) = self.open_shard(cid, false)? else {
            return Ok(DeleteTarget {
                cid: cid.clone(),
                leaf,
                shard: None,
            });
        };
        let shard = if self.chunk_entry_is_regular(&shard, &leaf)? {
            Some(shard)
        } else {
            None
        };
        Ok(DeleteTarget {
            cid: cid.clone(),
            leaf,
            shard,
        })
    }

    fn unlink_target(&self, target: &DeleteTarget) -> io::Result<()> {
        let Some(shard) = &target.shard else {
            return Ok(());
        };
        #[cfg(unix)]
        {
            match unix_fs::unlinkat(&shard.directory, target.leaf.as_str(), AtFlags::empty()) {
                Ok(()) => Ok(()),
                Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
                Err(error) => Err(io::Error::from(error)),
            }
        }
        #[cfg(not(unix))]
        {
            // Revalidate both path components immediately before the portable
            // path-based unlink. A raced replacement can at worst make this
            // call fail; symlinks and special files are never accepted.
            if !self.chunk_entry_is_regular(shard, &target.leaf)? {
                return Ok(());
            }
            match fs::remove_file(shard.path.join(&target.leaf)) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
    }

    /// Enumerate canonical chunk names without following any filesystem link.
    /// `limit=Some(1)` is the cheap emptiness probe; `None` is the GC/reindex
    /// inventory. Unsafe entries fail the inventory closed rather than being
    /// silently traversed or mistaken for content.
    #[cfg(unix)]
    fn scan_cids(&self, limit: Option<usize>) -> io::Result<Vec<Cid>> {
        let mut cids = Vec::new();
        let root = rustix::io::dup(&self.root.directory).map_err(io::Error::from)?;
        let root = fs::File::from(root);
        let root_entries = Dir::read_from(&root).map_err(io::Error::from)?;
        for entry in root_entries {
            let entry = entry.map_err(io::Error::from)?;
            let name = OsString::from_vec(entry.file_name().to_bytes().to_vec());
            if name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            let path = self.data_dir.join(&name);
            let stat = unix_fs::statat(&self.root.directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from)?;
            let kind = FileType::from_raw_mode(stat.st_mode);
            let canonical_shard = name.to_str().is_some_and(|name| is_hex_name(name, 2));

            if !canonical_shard {
                match kind {
                    // Ordinary operator debris is not a chunk. Never recurse
                    // into it, so it cannot become an alternate route outside.
                    FileType::RegularFile | FileType::Directory => continue,
                    _ => {
                        return Err(unsafe_path_error(
                            &path,
                            "top-level entry is a symlink or special file",
                        ))
                    }
                }
            }
            if kind != FileType::Directory {
                return Err(unsafe_path_error(
                    &path,
                    "canonical shard entry is not a real directory",
                ));
            }

            let shard_name = name.to_str().expect("canonical shard was valid UTF-8");
            let shard = self
                .open_shard_name(shard_name, false)?
                .ok_or_else(|| unsafe_path_error(&path, "shard vanished while scanning"))?;
            let duplicate = rustix::io::dup(&shard.directory).map_err(io::Error::from)?;
            let directory = fs::File::from(duplicate);
            let entries = Dir::read_from(&directory).map_err(io::Error::from)?;
            for child in entries {
                let child = child.map_err(io::Error::from)?;
                let leaf = OsString::from_vec(child.file_name().to_bytes().to_vec());
                if leaf == OsStr::new(".") || leaf == OsStr::new("..") {
                    continue;
                }
                let child_path = shard.path.join(&leaf);
                let stat = unix_fs::statat(&shard.directory, &leaf, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(io::Error::from)?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                    return Err(unsafe_path_error(
                        &child_path,
                        "entry inside a shard is a symlink or special file",
                    ));
                }

                let Some(leaf) = leaf.to_str() else {
                    continue;
                };
                if !is_hex_name(leaf, CID_LEN * 2 - 2) {
                    continue;
                }
                let cid = Cid::from_hex(&format!("{shard_name}{leaf}"))
                    .map_err(|error| unsafe_path_error(&child_path, &error.to_string()))?;
                cids.push(cid);
                if limit.is_some_and(|limit| cids.len() >= limit) {
                    return Ok(cids);
                }
            }
        }
        Ok(cids)
    }

    #[cfg(not(unix))]
    fn scan_cids(&self, limit: Option<usize>) -> io::Result<Vec<Cid>> {
        let root = fs::symlink_metadata(&self.data_dir)?;
        if root.file_type().is_symlink() || !root.is_dir() {
            return Err(unsafe_path_error(
                &self.data_dir,
                "data directory is not a real directory",
            ));
        }
        let mut cids = Vec::new();
        for entry in fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            let name = entry.file_name();
            let canonical_shard = name.to_str().is_some_and(|name| is_hex_name(name, 2));
            if !canonical_shard {
                if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                    return Err(unsafe_path_error(
                        &path,
                        "top-level entry is a symlink or special file",
                    ));
                }
                continue;
            }
            if kind.is_symlink() || !kind.is_dir() {
                return Err(unsafe_path_error(
                    &path,
                    "canonical shard entry is not a real directory",
                ));
            }
            let shard_name = name.to_str().expect("canonical shard was valid UTF-8");
            let shard = self
                .open_shard_name(shard_name, false)?
                .ok_or_else(|| unsafe_path_error(&path, "shard vanished while scanning"))?;
            for child in fs::read_dir(&shard.path)? {
                let child = child?;
                let child_path = child.path();
                let kind = child.file_type()?;
                if kind.is_symlink() || !kind.is_file() {
                    return Err(unsafe_path_error(
                        &child_path,
                        "entry inside a shard is a symlink or special file",
                    ));
                }
                let leaf = child.file_name();
                let Some(leaf) = leaf.to_str() else {
                    continue;
                };
                if !is_hex_name(leaf, CID_LEN * 2 - 2) {
                    continue;
                }
                let cid = Cid::from_hex(&format!("{shard_name}{leaf}"))
                    .map_err(|error| unsafe_path_error(&child_path, &error.to_string()))?;
                cids.push(cid);
                if limit.is_some_and(|limit| cids.len() >= limit) {
                    return Ok(cids);
                }
            }
        }
        Ok(cids)
    }

    fn flush_pending(&self, owed: &Pending) -> Result<(), CoreError> {
        // Files, then the directories that name them, then the index: the same
        // order as the durable write path, for the same reason. Anything that
        // moves the index insert earlier turns a crash from "some garbage
        // files" into "the index names bytes that are not there".
        // Paths that vanished between the write and this flush. Their index
        // entries must not be written: an entry naming a deleted file is the
        // exact corruption the deferred ordering exists to prevent, and it
        // outlives the process — `stats` counts it and `verify` reports a
        // phantom. Collected out from under a long-lived staging store is
        // the reachable case, since a collection driven through a *different*
        // FsStore over the same directory cannot clear this pending set.
        let mut vanished: HashSet<Cid> = HashSet::new();
        for cid in &owed.files {
            match self.open_chunk_file(cid).map_err(CoreError::Io)? {
                Some(opened) => {
                    opened.file.sync_all().map_err(CoreError::Io)?;
                    self.file_syncs.fetch_add(1, Ordering::Relaxed);
                }
                // Collected or repaired between the write and the sync. The
                // caller asked for these bytes to be durable, not to exist.
                None => {
                    debug!("deferred sync: {} is gone, skipping", cid);
                    vanished.insert(cid.clone());
                }
            }
        }
        for name in &owed.dirs {
            if let Some(shard) = self.open_shard_name(name, false).map_err(CoreError::Io)? {
                self.sync_shard_counted(&shard)?;
            }
        }
        if owed.root_dirty {
            self.sync_root_counted()?;
        }

        if let Some(ref index) = self.index {
            // One transaction for the whole batch. Per-chunk inserts were the
            // single largest remaining cost of a bulk ingest, because redb
            // commits with immediate durability.
            let entries: Vec<(Cid, ChunkLocation)> = owed
                .index
                .iter()
                .filter(|(cid, _)| !vanished.contains(*cid))
                .map(|(cid, location)| (cid.clone(), location.clone()))
                .collect();
            index.insert_many(&entries)?;
        }
        Ok(())
    }

    /// Flush an owned pending batch, restoring it to the shared registry if
    /// any fsync or index commit fails so the next barrier can retry it.
    fn flush_or_restore(&self, owed: Pending) -> Result<(), CoreError> {
        match self.flush_pending(&owed) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.coordination.pending.lock().merge(owed);
                Err(error)
            }
        }
    }

    /// Flush every pending write while the caller holds the exclusive
    /// publication gate.
    fn sync_exclusive(&self) -> Result<(), CoreError> {
        let owed = std::mem::take(&mut *self.coordination.pending.lock());
        self.flush_or_restore(owed)
    }

    /// Make a chunk's bytes durable *before* the rename that publishes them.
    ///
    /// Ordering the fsync before the rename is what stops a crash from leaving
    /// a file under the canonical name whose contents are still in page cache:
    /// with the rename first, that file reads as present to `has_chunk` and
    /// fails its hash check to everyone else.
    fn sync_before_rename(&self, temp: &fs::File) -> Result<(), CoreError> {
        if self.durability == DurabilityPolicy::Durable {
            temp.sync_all().map_err(CoreError::Io)?;
            self.file_syncs.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Make the open chunk and its descriptor-anchored shard durable, or record
    /// their canonical CID/shard names as owed under
    /// [`DurabilityPolicy::Deferred`].
    ///
    /// `already_written` is the file itself, and is `Some` only on the path
    /// where the bytes were *not* fsynced by [`Self::sync_before_rename`] —
    /// deduplicating against a chunk that was already on disk. Passing it
    /// keeps the invariant unconditional: the index never names bytes that are
    /// not durable, whichever path put them there.
    ///
    /// `shard.created` asks for the data directory to be covered too: a new
    /// shard directory is itself a name that has to survive, and losing it
    /// loses every chunk inside.
    fn publish(
        &self,
        already_written: Option<&fs::File>,
        cid: &Cid,
        shard: &ShardDirectory,
    ) -> Result<(), CoreError> {
        match self.durability {
            DurabilityPolicy::Durable => {
                if let Some(file) = already_written {
                    file.sync_all().map_err(CoreError::Io)?;
                    self.file_syncs.fetch_add(1, Ordering::Relaxed);
                }
                self.sync_shard_counted(shard)?;
                if shard.created {
                    self.sync_root_counted()?;
                }
                Ok(())
            }
            DurabilityPolicy::Deferred => {
                let overflow = {
                    let mut pending = self.coordination.pending.lock();
                    pending.files.insert(cid.clone());
                    pending.dirs.insert(shard.name.clone());
                    pending.root_dirty |= shard.created;
                    if pending.files.len() >= self.deferred_sync_threshold {
                        Some(std::mem::take(&mut *pending))
                    } else {
                        None
                    }
                };
                // Flushed outside the lock: an fsync storm must not block
                // every other writer on this store.
                match overflow {
                    Some(owed) => self.flush_or_restore(owed),
                    None => Ok(()),
                }
            }
        }
    }

    /// Rebuild the index from one fully verified store inventory.
    pub fn reindex(&self) -> Result<usize, CoreError> {
        let Some(ref index) = self.index else {
            return Err(CoreError::PreconditionFailed(
                "No index available for reindexing".to_string(),
            ));
        };

        // Replace-all must observe one store epoch. Coordinated puts hold the
        // shared side across rename and index publication; taking the exclusive
        // side here prevents a chunk inserted during the walk from having its
        // fresh index row erased by the final replacement. It also flushes any
        // deferred writers before the inventory begins.
        let _mutation = self.coordination.gate.write();
        self.sync_exclusive()?;

        info!(
            "Starting reindex of data directory: {}",
            self.data_dir.display()
        );

        // Inventory and verify completely before touching the old index. A
        // traversal/I/O failure therefore preserves the last usable index;
        // only a complete snapshot is published by `replace_all` below.
        let candidates = self.scan_cids(None).map_err(CoreError::Io)?;
        let mut entries = Vec::with_capacity(candidates.len());
        let mut skipped = 0usize;
        for expected_cid in candidates {
            let path = self.chunk_path(&expected_cid);
            let opened = self
                .open_chunk_file(&expected_cid)
                .map_err(CoreError::Io)?
                .ok_or_else(|| {
                    CoreError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("chunk vanished during reindex: {}", path.display()),
                    ))
                })?;
            let bytes = self
                .read_chunk_bytes(opened.file, &path)
                .map_err(CoreError::Io)?;
            let computed_cid = Cid::compute(&bytes);
            if computed_cid != expected_cid {
                skipped += 1;
                tracing::warn!(
                    "reindex: skipping {} — bytes hash to {}, not the {} its path names",
                    path.display(),
                    computed_cid,
                    expected_cid
                );
                continue;
            }
            entries.push((
                expected_cid.clone(),
                ChunkLocation {
                    path: path.to_string_lossy().to_string(),
                    length: bytes.len() as u64,
                    sha256_hash: expected_cid.to_hex(),
                },
            ));
        }

        // One redb transaction replaces both rows and aggregate counters. A
        // stale entry that no longer exists on disk is removed, while a failed
        // inventory above leaves the previous table untouched.
        index.replace_all(&entries)?;
        info!(
            "Reindex completed successfully: {} files indexed, {} corrupt files skipped",
            entries.len(),
            skipped
        );
        Ok(entries.len())
    }

    /// Replace the chunk index from a caller's already ceiling-checked,
    /// complete filesystem inventory.
    ///
    /// Full recovery uses this form so losing `control.redb` also reconstructs
    /// the derived catalogue without silently doing a second unbounded walk.
    /// The supplied set is compared with a fresh bounded snapshot while the
    /// store mutation gate is exclusive, then every object is hash-verified
    /// before the single replacement transaction.
    pub fn reindex_from_inventory(&self, supplied: &[Cid]) -> Result<usize, CoreError> {
        let Some(ref index) = self.index else {
            return Err(CoreError::PreconditionFailed(
                "No index available for reindexing".to_string(),
            ));
        };
        let limit = supplied.len().checked_add(1).ok_or_else(|| {
            CoreError::PreconditionFailed("reindex inventory length overflowed".into())
        })?;

        let _mutation = self.coordination.gate.write();
        self.sync_exclusive()?;
        let mut current = self.scan_cids(Some(limit)).map_err(CoreError::Io)?;
        let mut expected = supplied.to_vec();
        current.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        expected.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if current != expected {
            return Err(CoreError::PreconditionFailed(
                "store inventory changed after recovery preflight; retry offline".into(),
            ));
        }

        let mut entries = Vec::with_capacity(expected.len());
        for cid in &expected {
            let bytes = self.get_chunk(cid)?;
            let path = self.chunk_path(cid);
            entries.push((
                cid.clone(),
                ChunkLocation {
                    path: path.to_string_lossy().to_string(),
                    length: u64::try_from(bytes.len())
                        .map_err(|_| CoreError::Backend("chunk length does not fit u64".into()))?,
                    sha256_hash: cid.to_hex(),
                },
            ));
        }
        index.replace_all(&entries)?;
        Ok(entries.len())
    }
}

/// What a chunk file already sitting at the canonical path turned out to be.
enum Existing {
    /// Its bytes hash to the CID that names it; nothing to write.
    Adopted,
    /// It is there but its bytes are something else. Carries what they hash
    /// to, which is the only useful thing to say about them.
    Corrupt(Cid),
    /// It is there and could not be read.
    Unreadable(io::Error),
    /// It was there, and a collection batch took it out from under the
    /// adoption. The caller still holds the bytes, so the answer is to write
    /// them again rather than to fail.
    Collected,
}

impl FsStore {
    /// Record an index entry for a chunk that is on disk.
    ///
    /// Called last on every write path, and never before the bytes it names
    /// are durable — the index commits with redb's immediate durability, so an
    /// entry written first would outlive the chunk it points at. Under
    /// [`DurabilityPolicy::Deferred`] the bytes are not durable yet, so the
    /// entry waits in the pending set and is written by the same flush that
    /// fsyncs them.
    fn index_chunk(&self, cid: &Cid, path: &Path, length: u64) -> Result<(), CoreError> {
        // Before the early return, and on the deduplication path as well as
        // the fresh-write one: a chunk this ingest is *about* to reference is
        // in flight whether or not we had to write its bytes again.
        self.note_write(cid);

        let Some(ref index) = self.index else {
            return Ok(());
        };

        let location = ChunkLocation {
            path: path.to_string_lossy().to_string(),
            length,
            sha256_hash: cid.to_hex(),
        };

        match self.durability {
            DurabilityPolicy::Durable => index.insert(cid, location),
            DurabilityPolicy::Deferred => {
                self.coordination
                    .pending
                    .lock()
                    .index
                    .insert(cid.clone(), location);
                Ok(())
            }
        }
    }

    /// Inspect the chunk already at `path`, and if it is intact make it
    /// durable and index it.
    ///
    /// The fsync looks redundant — the bytes are already there — but "already
    /// there" and "durable" are different claims, and this path is about to
    /// add an index entry that outlives a crash. On an unchanged file the
    /// fsync finds nothing dirty and costs a syscall.
    fn adopt_existing(&self, cid: &Cid) -> Result<Existing, CoreError> {
        let path = self.chunk_path(cid);
        let Some(opened) = self.open_chunk_file(cid).map_err(CoreError::Io)? else {
            return Ok(Existing::Collected);
        };
        let OpenChunk { file, shard } = opened;
        let existing_bytes =
            match self.read_chunk_bytes(file.try_clone().map_err(CoreError::Io)?, &path) {
                Ok(bytes) => bytes,
                Err(error) => return Ok(Existing::Unreadable(error)),
            };

        let computed_cid = Cid::compute(&existing_bytes);
        if computed_cid != *cid {
            return Ok(Existing::Corrupt(computed_cid));
        }

        self.publish(Some(&file), cid, &shard)?;

        // Register the reference and confirm the file survived, in one step
        // (see `note_and_check`). A collection batch running right now holds
        // the registry lock; if it took this chunk before we got the lock,
        // adopting would index bytes that are gone and report success.
        if !self
            .recent_writes
            .note_and_check(cid, || self.same_open_file(cid, &file))
            .map_err(CoreError::Io)?
        {
            return Ok(Existing::Collected);
        }

        self.index_chunk(cid, &path, existing_bytes.len() as u64)?;
        Ok(Existing::Adopted)
    }
}

impl ContentStore for FsStore {
    /// Store `bytes`, returning the CID that names them.
    ///
    /// The steps are ordered so that the index never names bytes that are not
    /// on disk: write to a temporary file, fsync it, rename it into place,
    /// fsync the directory that now names it, and only then insert the index
    /// entry. The reverse order — the one this had before — leaves a durable
    /// index pointing at files a crash never finished writing, which reads as
    /// data loss to every caller and cannot be told apart from it.
    ///
    /// [`DurabilityPolicy::Deferred`] moves the two fsyncs to
    /// [`FsStore::sync`]; the relative order is unchanged.
    fn put_chunk(&self, bytes: &[u8], _meta: Option<dag_core::MetaHint>) -> Result<Cid, CoreError> {
        // Publication takes the matching write lock across fsync *and* the
        // control-plane commit. Holding this read side for the complete put
        // makes the canonical rename, deferred registration and index update
        // one mutation from that barrier's point of view.
        let _mutation = self.coordination.gate.read();
        // The closure is the whole original body; the wrapper only measures.
        // Latency is recorded for failures too — a slow error is still slow.
        let put_started = std::time::Instant::now();
        let result = (|| {
            if bytes.len() > MAX_CHUNK_SIZE {
                return Err(CoreError::ChunkTooLarge {
                    size: bytes.len(),
                    max_size: MAX_CHUNK_SIZE,
                });
            }

            let cid = Cid::compute(bytes);
            let final_path = self.chunk_path(&cid);

            // Check if a regular file already exists and verify its integrity.
            // `open_chunk_file` refuses a symlink/special shard or final entry;
            // unsafe entries are not cache misses and are never "repaired" by
            // following them.
            if self.open_chunk_file(&cid).map_err(CoreError::Io)?.is_some() {
                debug!("Chunk {} already exists, verifying integrity", cid);

                match self.adopt_existing(&cid)? {
                    Existing::Adopted => {
                        debug!("Chunk {} integrity verified", cid);
                        return Ok(cid);
                    }
                    Existing::Corrupt(found) => {
                        info!(
                            "Chunk {} corrupted (expected {}, found {}), repairing",
                            cid, cid, found
                        );
                        // Continue to rewrite the file
                    }
                    Existing::Unreadable(e) => {
                        info!("Failed to read existing chunk {}: {}, rewriting", cid, e);
                        // Continue to rewrite the file
                    }
                    Existing::Collected => {
                        info!("Chunk {} was collected while being adopted, rewriting", cid);
                        // Continue to rewrite the file — we still hold the bytes.
                    }
                }
            }

            let shard = self
                .open_shard(&cid, true)
                .map_err(CoreError::Io)?
                .ok_or_else(|| {
                    CoreError::Io(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("newly-created shard vanished for {cid}"),
                    ))
                })?;
            let (_, leaf) = Self::chunk_names(&cid);

            #[cfg(unix)]
            {
                let (mut temp_file, temp_name) =
                    self.create_temp_in_shard(&shard).map_err(CoreError::Io)?;
                let publish_result = (|| {
                    temp_file.write_all(bytes).map_err(CoreError::Io)?;

                    // The bytes have to be on disk before the descriptor-relative
                    // rename publishes them under their canonical name.
                    self.sync_before_rename(&temp_file)?;

                    // A final symlink or special file is an integrity violation.
                    // A regular file may be atomically replaced to repair corrupt
                    // bytes; absence is the ordinary first-write case.
                    let _ = self
                        .chunk_entry_is_regular(&shard, &leaf)
                        .map_err(CoreError::Io)?;
                    unix_fs::renameat(
                        &shard.directory,
                        temp_name.as_str(),
                        &shard.directory,
                        leaf.as_str(),
                    )
                    .map_err(io::Error::from)
                    .map_err(CoreError::Io)?;
                    self.publish(None, &cid, &shard)
                })();
                // After a successful rename the old name is absent; after any
                // failure it is our private staging file and safe to remove.
                let _ = unix_fs::unlinkat(&shard.directory, temp_name.as_str(), AtFlags::empty());
                publish_result?;
            }

            #[cfg(not(unix))]
            {
                // Portable fallback: validate each component without following
                // links before every path-based operation. Unix above closes the
                // remaining check/use race with directory descriptors.
                let temp_file = NamedTempFile::new_in(&shard.path).map_err(CoreError::Io)?;
                temp_file
                    .as_file()
                    .write_all(bytes)
                    .map_err(CoreError::Io)?;
                self.sync_before_rename(temp_file.as_file())?;
                let _ = self
                    .chunk_entry_is_regular(&shard, &leaf)
                    .map_err(CoreError::Io)?;
                match temp_file.persist(&final_path) {
                    Ok(_) => self.publish(None, &cid, &shard)?,
                    Err(persist_error) => {
                        // Windows may refuse replacement when another writer won
                        // the name. Adopt only through the same no-follow gates.
                        match self.adopt_existing(&cid)? {
                            Existing::Adopted => return Ok(cid),
                            Existing::Corrupt(found) => {
                                return Err(CoreError::CidMismatch {
                                    expected: cid.clone(),
                                    computed: found,
                                })
                            }
                            Existing::Unreadable(_) | Existing::Collected => {
                                return Err(CoreError::Io(persist_error.error))
                            }
                        }
                    }
                }
            }

            // Durable on disk: the index may now name it.
            self.index_chunk(&cid, &final_path, bytes.len() as u64)?;

            info!("Stored chunk {} ({} bytes)", cid, bytes.len());
            Ok(cid)
        })();
        if let Some(metrics) = &self.metrics {
            metrics.store_put_seconds.observe(put_started.elapsed());
            if result.is_ok() {
                metrics.store_put_total.inc();
                metrics.store_put_bytes_total.add(bytes.len() as u64);
            }
        }
        result
    }

    fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError> {
        let get_started = std::time::Instant::now();
        let result = (|| {
            let path = self.chunk_path(cid);

            // A missing chunk is its own error, not an I/O failure: callers need to
            // tell "no such CID" apart from "the disk is broken" without matching
            // on error strings.
            let Some(opened) = self.open_chunk_file(cid).map_err(CoreError::Io)? else {
                return Err(CoreError::ChunkNotFound(cid.to_hex()));
            };
            let bytes = self
                .read_chunk_bytes(opened.file, &path)
                .map_err(CoreError::Io)?;

            // Verify CID integrity
            let computed_cid = Cid::compute(&bytes);
            if computed_cid != *cid {
                return Err(CoreError::CidMismatch {
                    expected: cid.clone(),
                    computed: computed_cid,
                });
            }

            debug!("Retrieved chunk {} ({} bytes)", cid, bytes.len());
            Ok(bytes)
        })();
        if let Some(metrics) = &self.metrics {
            metrics.store_get_seconds.observe(get_started.elapsed());
            if let Ok(bytes) = &result {
                metrics.store_get_total.inc();
                metrics.store_get_bytes_total.add(bytes.len() as u64);
            }
        }
        result
    }

    /// Whether a file exists at the CID's canonical path.
    ///
    /// **This is presence, not integrity.** A truncated or corrupt file reads
    /// as present here, and three callers act on that answer: garbage
    /// collection, the replication skip check in `dag_control::sync`, and the
    /// chunker's deduplication. The alternative — re-hashing on every call —
    /// would turn each of those from a `stat` into a full read of the store,
    /// so the cheap answer is deliberate.
    ///
    /// The hazard is contained rather than ignored: [`ContentStore::get_chunk`]
    /// verifies the hash on every read, [`FsStore::put_chunk`] repairs a
    /// mismatched file in place, and [`crate::IntegrityScanner`] exists to
    /// find them in the background. Anything that must *know* the bytes are
    /// good should read them.
    fn has_chunk(&self, cid: &Cid) -> Result<bool, CoreError> {
        Ok(self.open_chunk_file(cid).map_err(CoreError::Io)?.is_some())
    }

    /// Make every deferred write durable, and only then let the index name it.
    ///
    /// A no-op under [`DurabilityPolicy::Durable`] — nothing is ever owed —
    /// so a bulk writer can call it unconditionally when it finishes.
    fn sync(&self) -> Result<(), CoreError> {
        self.flush_pending_writes().map(|_| ())
    }

    /// A chunk this ingest is about to reference by deduplication is in flight
    /// just as much as one it wrote, so it goes in the same registry.
    ///
    /// The record is the only cost: no bytes are read, hashed or written, so
    /// deduplication stays as cheap as a `stat`. See the `recent_writes` field
    /// for what the registry protects against.
    fn note_reference(&self, cid: &Cid) {
        self.note_write(cid);
    }
}

impl GcCapableStore for FsStore {
    fn is_in_flight(&self, cid: &Cid, within: Duration) -> bool {
        self.recent_writes.is_recent(cid, within)
    }

    fn list_cids(&self, limit: Option<usize>) -> Result<Vec<Cid>, CoreError> {
        self.scan_cids(limit).map_err(CoreError::Io)
    }

    fn prepare_gc_inventory(&self, max_examined: usize) -> Result<Vec<Cid>, CoreError> {
        // A put holds the shared side from before its canonical rename through
        // index publication. Take the exclusive side across pending-write
        // flush, filesystem enumeration and exact index validation so GC can
        // never mistake that legitimate intermediate state for stale recovery
        // evidence. This lock is intentionally released after the snapshot:
        // batched deletion takes it again and parking_lot RwLocks are not
        // reentrant.
        let _inventory = self.coordination.gate.write();
        self.sync_exclusive()?;
        let inventory_limit = max_examined.checked_add(1).filter(|_| max_examined > 0);
        let cids = self.scan_cids(inventory_limit).map_err(CoreError::Io)?;
        if max_examined > 0 && cids.len() > max_examined {
            return Err(CoreError::GcInventoryLimit {
                limit: max_examined,
            });
        }
        self.validate_gc_inventory(&cids)?;
        Ok(cids)
    }

    fn validate_gc_inventory(&self, filesystem_cids: &[Cid]) -> Result<(), CoreError> {
        match &self.index {
            Some(index) => index.validate_gc_inventory(filesystem_cids),
            None => Ok(()),
        }
    }

    fn validate_gc_snapshot(&self, prepared_cids: &[Cid]) -> Result<(), CoreError> {
        // Flush and inspect under the same writer exclusion used for the exact
        // initial snapshot. New rows are legitimate post-snapshot writes and
        // remain outside this pass; losing any prepared row is fail-closed.
        let _inventory = self.coordination.gate.write();
        self.sync_exclusive()?;
        match &self.index {
            Some(index) => index.validate_gc_snapshot(prepared_cids),
            None => Ok(()),
        }
    }

    fn get_chunk_age(&self, cid: &Cid) -> Result<Option<Duration>, CoreError> {
        let metadata = match self.open_chunk_file(cid).map_err(CoreError::Io)? {
            Some(opened) => opened.file.metadata().map_err(CoreError::Io)?,
            None => return Ok(None),
        };
        // An unreadable timestamp is unknown, not old. Returning `None` here
        // used to bypass the minimum-age gate and let collection proceed on a
        // file whose recency it could not establish.
        let modified = metadata.modified().map_err(CoreError::Io)?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::ZERO);
        Ok(Some(age))
    }

    fn get_chunk_size(&self, cid: &Cid) -> Result<usize, CoreError> {
        let opened = self.open_chunk_file(cid).map_err(CoreError::Io)?;
        let Some(opened) = opened else {
            return Err(CoreError::ChunkNotFound(cid.to_hex()));
        };
        let length = opened.file.metadata().map_err(CoreError::Io)?.len();
        usize::try_from(length).map_err(|_| {
            CoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk {cid} length does not fit usize"),
            ))
        })
    }

    fn get_inventory_chunk_size(&self, cid: &Cid) -> Result<usize, CoreError> {
        let (_, leaf) = Self::chunk_names(cid);
        let Some(shard) = self.open_shard(cid, false).map_err(CoreError::Io)? else {
            return Err(CoreError::ChunkNotFound(cid.to_hex()));
        };

        #[cfg(unix)]
        let length = {
            let stat = unix_fs::statat(&shard.directory, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| CoreError::Io(io::Error::from(error)))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(CoreError::Io(unsafe_path_error(
                    &shard.path.join(&leaf),
                    "chunk entry is a symlink or special file",
                )));
            }
            u64::try_from(stat.st_size).map_err(|_| {
                CoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("chunk {cid} has a negative size"),
                ))
            })?
        };

        #[cfg(not(unix))]
        let length = {
            let path = shard.path.join(&leaf);
            let metadata = fs::symlink_metadata(&path).map_err(CoreError::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(CoreError::Io(unsafe_path_error(
                    &path,
                    "chunk entry is a symlink or special file",
                )));
            }
            metadata.len()
        };

        usize::try_from(length).map_err(|_| {
            CoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk {cid} length does not fit usize"),
            ))
        })
    }

    /// Remove a chunk: index entry first, bytes second.
    ///
    /// The order is the write path's, reversed, and for the same reason. A
    /// crash between the two steps leaves either a file with no index entry —
    /// garbage, which `reindex` or the next collection sweeps up — or, with
    /// the steps the other way round, an index entry naming nothing, which is
    /// corruption that nothing repairs.
    ///
    /// The index entry is cleared even when the file has already gone, so this
    /// is also how an operator clears an entry left behind by the older order.
    fn delete_chunk(&self, cid: &Cid) -> Result<(), CoreError> {
        // Deletion must exclude both puts and publication. Treating it as a
        // shared mutation lets an overflow flush resurrect an index entry for
        // a file this call has just removed.
        let _publication = self.coordination.gate.write();
        // Validate and anchor the target before mutating the index. An unsafe
        // path refuses the whole deletion and leaves bookkeeping intact.
        let target = self.prepare_delete(cid).map_err(CoreError::Io)?;

        // Drop the owed work before clearing the durable entry, not after: a
        // pending insert flushed in between would resurrect the entry this
        // call exists to remove. A stale entry in the deferred file set would
        // also make `sync` re-open a path that no longer exists — it tolerates
        // that, but not carrying the garbage is cheaper than tolerating it.
        if self.durability == DurabilityPolicy::Deferred {
            let mut pending = self.coordination.pending.lock();
            pending.files.remove(cid);
            pending.index.remove(cid);
        }

        if let Some(index) = &self.index {
            index.remove(cid)?;
        }

        self.unlink_target(&target).map_err(CoreError::Io)?;
        debug!(
            "Deleted chunk {} from {}",
            cid,
            self.chunk_path(cid).display()
        );

        Ok(())
    }

    /// The batched form: one index transaction — one fsync — per call.
    ///
    /// Ordering per batch matches [`Self::delete_chunk`]: pending work
    /// dropped, then the index entries cleared durably, then the files
    /// unlinked. A crash between the commit and the unlinks leaves unindexed
    /// files — the same artifact an interrupted ingest leaves, swept by
    /// `reindex` or the next collection — never a durable index naming
    /// deleted bytes.
    ///
    /// The in-flight gate runs here, per chunk, immediately before the
    /// transaction opens; the caller's earlier check has aged by however
    /// long the batch took to accumulate.
    fn delete_chunks(&self, cids: &[Cid], in_flight_within: Duration) -> BatchDelete {
        // Lock order is publication gate, then in-flight registry. `put_chunk`
        // uses the same order when adoption registers a reference.
        let _publication = self.coordination.gate.write();
        // The whole batch — final gate, index transaction, unlinks — runs
        // under the in-flight registry's lock. A concurrent `note_reference`
        // (a pointer naming old content mid-sweep) either lands before the
        // gate and is honoured, or blocks here until the batch is done and
        // finds the chunk already gone. Anything less is the lost-revert
        // race the concurrency soak caught.
        self.recent_writes.with_exclusive_check(|is_recent| {
            let mut outcome = BatchDelete::default();
            let mut doomed: Vec<DeleteTarget> = Vec::with_capacity(cids.len());

            for cid in cids {
                if is_recent(cid, in_flight_within) {
                    outcome.skipped_in_flight.push(cid.clone());
                } else {
                    match self.prepare_delete(cid) {
                        Ok(target) => doomed.push(target),
                        Err(error) => outcome
                            .errors
                            .push(format!("Failed to delete {}: {}", cid, error)),
                    }
                }
            }
            if doomed.is_empty() {
                return outcome;
            }

            if self.durability == DurabilityPolicy::Deferred {
                let mut pending = self.coordination.pending.lock();
                for target in &doomed {
                    pending.files.remove(&target.cid);
                    pending.index.remove(&target.cid);
                }
            }

            if let Some(index) = &self.index {
                let cids: Vec<Cid> = doomed.iter().map(|target| target.cid.clone()).collect();
                if let Err(e) = index.remove_batch(&cids) {
                    // The index refused the whole transaction: nothing
                    // was removed anywhere, so every chunk failed alike.
                    for target in doomed {
                        outcome
                            .errors
                            .push(format!("Failed to delete {}: {}", target.cid, e));
                    }
                    return outcome;
                }
            }

            for target in doomed {
                match self.unlink_target(&target) {
                    Ok(()) => outcome.deleted.push(target.cid),
                    Err(error) => outcome
                        .errors
                        .push(format!("Failed to delete {}: {}", target.cid, error)),
                }
            }

            outcome
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_store() -> (FsStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = FsStore::new(temp_dir.path()).unwrap();
        (store, temp_dir)
    }

    #[test]
    fn gc_inventory_limit_is_applied_during_filesystem_enumeration() {
        let (store, _temp) = create_test_store();
        for i in 0..5 {
            store
                .put_chunk(format!("bounded-inventory-{i}").as_bytes(), None)
                .unwrap();
        }

        assert_eq!(store.list_cids(Some(3)).unwrap().len(), 3);
        assert_eq!(store.list_all_cids().unwrap().len(), 5);
    }

    #[test]
    fn durable_publication_waits_for_and_flushes_every_coordinated_writer() {
        use std::sync::{mpsc, Arc};
        use std::time::{Duration, Instant};

        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        let owner = FsStore::with_index(&data_dir, &temp.path().join("index.redb")).unwrap();
        let index = owner.get_index().unwrap();
        let coordination = owner.coordination();

        // Two genuinely separate staging views reproduce the production
        // topology: one RPC can be writing while another publishes.
        let writer = Arc::new(
            FsStore::with_chunk_index(&data_dir, index.clone())
                .unwrap()
                .with_coordination(coordination.clone())
                .with_durability(DurabilityPolicy::Deferred),
        );
        let publisher = Arc::new(
            FsStore::with_chunk_index(&data_dir, index.clone())
                .unwrap()
                .with_coordination(coordination.clone())
                .with_durability(DurabilityPolicy::Deferred),
        );

        let bytes = b"visible by rename, not yet registered or durable".to_vec();
        let cid = Cid::compute(&bytes);
        let path = writer.chunk_path(&cid);

        // Pause the put exactly after its canonical rename: `publish` needs
        // this mutex to register the deferred file, while the put still holds
        // the shared mutation side of the publication gate.
        let pending = coordination.pending.lock();
        let writer_thread = {
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || writer.put_chunk(&bytes, None).unwrap())
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "writer never reached the post-rename barrier"
            );
            std::thread::yield_now();
        }

        let (published_tx, published_rx) = mpsc::channel();
        let publication_thread = std::thread::spawn(move || {
            publisher
                .with_durable_publication(|| {
                    published_tx.send(()).unwrap();
                    Ok::<(), CoreError>(())
                })
                .unwrap();
        });

        assert!(
            published_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "metadata publication crossed while a renamed chunk was still in flight"
        );

        drop(pending);
        assert_eq!(writer_thread.join().unwrap(), cid);
        published_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("publication did not resume after the writer completed");
        publication_thread.join().unwrap();

        assert_eq!(coordination.pending.lock().files.len(), 0);
        assert!(
            index.get(&cid).unwrap().is_some(),
            "publication did not flush and index the coordinated writer"
        );
    }

    #[test]
    fn gc_inventory_waits_for_rename_to_index_publication() {
        use std::sync::{mpsc, Arc};
        use std::time::{Duration, Instant};

        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        let owner =
            Arc::new(FsStore::with_index(&data_dir, &temp.path().join("index.redb")).unwrap());
        let index = owner.get_index().unwrap();
        let coordination = owner.coordination();
        let writer = Arc::new(
            FsStore::with_chunk_index(&data_dir, index.clone())
                .unwrap()
                .with_coordination(coordination.clone())
                .with_durability(DurabilityPolicy::Deferred),
        );

        let bytes = b"GC must not sample between rename and index".to_vec();
        let cid = Cid::compute(&bytes);
        let path = writer.chunk_path(&cid);

        // Deferred publication needs this mutex immediately after the
        // canonical rename, while put_chunk still owns the shared durability
        // gate. This creates the exact filesystem=1/index=0 state that the
        // concurrency soak exposed without relying on scheduler luck.
        let pending = coordination.pending.lock();
        let writer_thread = {
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || writer.put_chunk(&bytes, None))
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "writer never reached the post-rename/pre-index state"
            );
            std::thread::yield_now();
        }

        let (started_tx, started_rx) = mpsc::channel();
        let (inventory_tx, inventory_rx) = mpsc::channel();
        let inventory_thread = {
            let owner = Arc::clone(&owner);
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                inventory_tx
                    .send(crate::GarbageCollector::new(owner).prepare_inventory(100, 1024))
                    .unwrap();
            })
        };
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("GC inventory thread did not start");
        assert!(
            inventory_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "GC sampled a filesystem/index split while the writer was in flight"
        );

        drop(pending);
        assert_eq!(writer_thread.join().unwrap().unwrap(), cid);
        let inventory = inventory_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("GC inventory did not resume after the writer completed")
            .unwrap();
        inventory_thread.join().unwrap();

        assert_eq!(inventory.cids(), std::slice::from_ref(&cid));
        assert!(
            index.get(&cid).unwrap().is_some(),
            "GC snapshot did not flush the coordinated pending index row"
        );
    }

    #[test]
    fn the_in_flight_registry_prunes_itself_and_stays_bounded() {
        use std::time::Duration;

        // A long-lived server that writes constantly and never collects must
        // not leak the in-flight registry: pruning only happened inside
        // `recently_written`, which only a collection calls. With a tiny
        // interval and a zero ceiling, every prune drops everything already
        // elapsed, so the set can never exceed the interval no matter how many
        // writes arrive.
        let reg = InFlightRegistry::with_bounds(8, Duration::ZERO);
        for i in 0..1000u64 {
            reg.note(&Cid::compute(&i.to_le_bytes()));
            assert!(
                reg.tracked() <= 8,
                "in-flight registry grew past its prune interval at write {i}: {} entries",
                reg.tracked()
            );
        }
    }

    #[test]
    fn test_put_get_roundtrip() {
        let (store, _temp_dir) = create_test_store();
        let data = b"hello world";

        let cid = store.put_chunk(data, None).unwrap();
        let retrieved = store.get_chunk(&cid).unwrap();

        assert_eq!(data, &retrieved[..]);
    }

    #[test]
    fn test_chunk_too_large() {
        let (store, _temp_dir) = create_test_store();
        let large_data = vec![0u8; MAX_CHUNK_SIZE + 1];

        let result = store.put_chunk(&large_data, None);

        assert!(matches!(result, Err(CoreError::ChunkTooLarge { .. })));
    }

    #[test]
    fn test_duplicate_put_same_cid() {
        let (store, _temp_dir) = create_test_store();
        let data = b"test data";

        let cid1 = store.put_chunk(data, None).unwrap();
        let cid2 = store.put_chunk(data, None).unwrap();

        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_get_nonexistent_chunk() {
        let (store, _temp_dir) = create_test_store();
        let fake_cid = Cid::compute(b"nonexistent");

        let result = store.get_chunk(&fake_cid);

        assert!(matches!(result, Err(CoreError::ChunkNotFound(_))));
    }

    fn create_test_store_with_index() -> (FsStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().join("data");
        let index_dir = temp_dir.path().join("index");
        let store = FsStore::with_index(&data_dir, &index_dir).unwrap();
        (store, temp_dir)
    }

    #[test]
    fn test_store_with_index_integration() {
        let (store, _temp_dir) = create_test_store_with_index();

        // Store 3 chunks
        let data1 = b"hello world";
        let data2 = b"foo bar";
        let data3 = b"test data";

        let cid1 = store.put_chunk(data1, None).unwrap();
        let cid2 = store.put_chunk(data2, None).unwrap();
        let cid3 = store.put_chunk(data3, None).unwrap();

        // Verify index has all 3
        let index = store.get_index().unwrap();
        assert_eq!(index.count().unwrap(), 3);

        // Verify index entries are correct
        let loc1 = index.get(&cid1).unwrap().unwrap();
        assert_eq!(loc1.length, data1.len() as u64);
        assert_eq!(loc1.sha256_hash, cid1.to_hex());

        let loc2 = index.get(&cid2).unwrap().unwrap();
        assert_eq!(loc2.length, data2.len() as u64);
        assert_eq!(loc2.sha256_hash, cid2.to_hex());

        let loc3 = index.get(&cid3).unwrap().unwrap();
        assert_eq!(loc3.length, data3.len() as u64);
        assert_eq!(loc3.sha256_hash, cid3.to_hex());

        // Verify retrieval still works
        let retrieved1 = store.get_chunk(&cid1).unwrap();
        assert_eq!(data1, &retrieved1[..]);
    }

    #[test]
    fn reindex_indexes_only_real_chunks_and_reports_the_rest() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        let store = FsStore::with_index(&data_dir, &temp.path().join("index.redb")).unwrap();

        // One legitimate chunk, at its canonical CID-derived path.
        let good = store.put_chunk(b"a legitimate chunk", None).unwrap();

        // A leftover temp file in a shard directory, as an interrupted write
        // (a persisted-but-not-renamed NamedTempFile) leaves behind.
        let shard = store.chunk_path(&good).parent().unwrap().to_path_buf();
        std::fs::write(shard.join(".tmpABC123"), b"interrupted write garbage").unwrap();

        // A misplaced file: a well-formed chunk path whose bytes do NOT hash to
        // the CID the path names — a file moved to the wrong shard, or one whose
        // bytes rotted after it was written.
        let elsewhere = Cid::compute(b"some other content entirely");
        let wrong_path = store.chunk_path(&elsewhere);
        std::fs::create_dir_all(wrong_path.parent().unwrap()).unwrap();
        std::fs::write(&wrong_path, b"bytes that do not hash to this path").unwrap();

        // A stray file at the top of the data directory, under no shard at all.
        std::fs::write(data_dir.join("stray-note.txt"), b"not a chunk").unwrap();

        let indexed = store.reindex().unwrap();
        let index = store.get_index().unwrap();

        assert_eq!(indexed, 1, "reindex should index only the one valid chunk");
        assert_eq!(
            index.count().unwrap(),
            1,
            "the index must name exactly the valid chunk"
        );
        assert!(index.get(&good).unwrap().is_some());

        // None of the junk may be adopted — not at the path's CID, and not at
        // the file's own content hash (which is how the old reindex smuggled
        // every stray byte into the index at a location `get_chunk` can never
        // serve).
        for junk in [
            elsewhere,
            Cid::compute(b"interrupted write garbage"),
            Cid::compute(b"bytes that do not hash to this path"),
            Cid::compute(b"not a chunk"),
        ] {
            assert!(
                index.get(&junk).unwrap().is_none(),
                "reindex adopted a file that is not a valid chunk"
            );
        }
    }

    #[test]
    fn test_corruption_repair() {
        let (store, _temp_dir) = create_test_store_with_index();
        let data = b"hello world";

        // Store the chunk initially
        let cid = store.put_chunk(data, None).unwrap();

        // Corrupt the file by writing wrong bytes
        let chunk_path = store.chunk_path(&cid);
        fs::write(&chunk_path, b"corrupted data").unwrap();

        // Verify the file is corrupted
        let corrupted_bytes = fs::read(&chunk_path).unwrap();
        assert_ne!(data, &corrupted_bytes[..]);

        // Put the same chunk again - should detect corruption and repair
        let cid2 = store.put_chunk(data, None).unwrap();
        assert_eq!(cid, cid2);

        // Verify the file is now correct
        let repaired_bytes = fs::read(&chunk_path).unwrap();
        assert_eq!(data, &repaired_bytes[..]);

        // Verify retrieval works correctly
        let retrieved = store.get_chunk(&cid).unwrap();
        assert_eq!(data, &retrieved[..]);
    }

    #[test]
    fn test_entry_operations() {
        use dag_core::{ContentStore, Entry, Link};

        let (store, _temp_dir) = create_test_store_with_index();

        // Create some target CIDs for links
        let chunk1_cid = store.put_chunk(b"chunk 1 data", None).unwrap();
        let chunk2_cid = store.put_chunk(b"chunk 2 data", None).unwrap();

        // Create an entry with payload and links
        let payload = b"entry payload data".to_vec();
        let links = vec![
            Link::named(chunk1_cid, "first-chunk"),
            Link::unnamed(chunk2_cid),
        ];

        let entry = Entry::new(payload, links.clone(), None);

        // Store the entry
        let entry_cid = store.put_entry(&entry).unwrap();

        // Retrieve the links
        let retrieved_links = store.get_links(&entry_cid).unwrap();
        assert_eq!(retrieved_links, links);

        // Retrieve the full entry
        let retrieved_entry = store.get_entry(&entry_cid).unwrap();
        assert_eq!(retrieved_entry, entry);
    }

    #[test]
    fn test_entry_roundtrip_deterministic() {
        use dag_core::{Cid, ContentStore, Entry, Link};

        let (store, _temp_dir) = create_test_store_with_index();

        // Create a deterministic entry
        let payload = b"deterministic test payload".to_vec();
        let target_cid = Cid::compute(b"target data");
        let links = vec![Link::named(target_cid, "test-link")];

        let entry = Entry::new(payload, links, None);

        // Store the entry multiple times
        let cid1 = store.put_entry(&entry).unwrap();
        let cid2 = store.put_entry(&entry).unwrap();

        // Should get the same CID (deterministic encoding)
        assert_eq!(cid1, cid2);
    }
}
