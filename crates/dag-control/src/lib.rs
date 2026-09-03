//! # dag-control
//!
//! The orchestrator control plane: pointers, pins, retention, jobs, recovery
//! and the unified event stream.
//!
//! [`Control`] is the single entry point. It owns one on-disk layout and hands
//! out every subsystem that shares it, so callers (CLI, HTTP API, tests) can
//! never accidentally open two halves of the same deployment at different
//! paths.
//!
//! ## On-disk layout
//!
//! Everything lives under one data directory (default `.dag`):
//!
//! ```text
//! <data_dir>/
//!   data/          chunk bytes, sharded by CID hex prefix
//!   control.redb   one redb database: chunk index, pointer/pin/job logs,
//!                  event journal, recovery gate flags — one table each
//! ```
//!
//! Earlier releases used six separate sled databases here; `dag migrate`
//! converts them, and [`Control::open`] refuses a pre-migration directory
//! with a message naming that command.

pub mod blocking;
pub mod effects;
pub mod error;
pub mod events;
pub mod http_sync;
pub mod integration;
pub mod job;
pub mod pin;
pub mod pointer;
pub mod recovery;
mod reference;
pub mod retention;
pub mod scheduler;
pub mod schema;
pub mod signatures;
pub mod sync;
mod sync_generation;

pub use dag_core::validate_pin_id;
pub use effects::{EffectAttester, EffectClaim};
pub use error::{ControlError, Result};
pub use events::{
    reclaim_control_db, CompactionReport, Event, EventBus, EventEnvelope, ReclaimReport, Replay,
    Truncated, DEFAULT_JOURNAL_RETENTION, JOURNAL_RETENTION_ENV, MAX_EVENT_ENVELOPE_BYTES,
};
pub use http_sync::{is_http_remote, HttpDestination};
pub use integration::{AttestedEffects, EffectCache, EffectClaimSink, PinCreator};
pub use job::{
    ClaimedRun, DeadLetterCompactionReport, JobEvent, JobHead, JobLog, JobRebuildReport,
    JobReconcileReport, JobStoreRebuildReport, RunClaim, RunCompactionReport, TriggerDeadLetter,
    TriggerDrainReport, MAX_DEAD_LETTER_DELETE, MAX_DEAD_LETTER_LIST, MAX_PENDING_RUNS,
    MAX_RUN_COMPACTION_DELETE, MAX_RUN_HISTORY_PAGE,
};
pub use pin::{PinLog, PinRebuildReport, PinReconcileReport, PinStoreRebuildReport};
pub use pointer::{
    validate_pointer_id, PointerError, PointerHead, PointerLog, PointerReconcileReport,
    PointerStoreRebuildReport,
};
pub use recovery::RecoveryState;
pub use retention::{
    EffectiveRetention, IncompleteExpansion, RetentionIndex, RetentionStatus,
    SubtreeExpansionReport,
};
pub use scheduler::Scheduler;
pub use schema::{SchemaState, SCHEMA_VERSION};
pub use signatures::{SignatureLog, SignatureStatus, TrustPurpose, TrustedKey};
pub use sync::{SyncFailure, SyncOptions, SyncReport};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;

use dag_core::{
    Cid, ContentStore, EffectKey, GcReport, JobId, JobRun, JobSpec, PinScope, PinTarget,
};
use dag_storage::{
    ChunkIndex, FsStore, GarbageCollector, GcCapableStore, GcConfig, SystemDataPolicy,
    DEFAULT_GC_MAX_BYTES_EXAMINED, DEFAULT_GC_MAX_EXAMINED,
};
use redb::Database;

/// Filename of the single control-plane database inside a data directory.
pub const CONTROL_DB_FILE: &str = "control.redb";

/// Default store-inventory ceiling for a full offline recovery.
///
/// Recovery materialises several safety-relevant derived views. Keeping the
/// ordinary command finite avoids turning a mistaken invocation into an
/// unbounded memory/availability event; an operator can raise the ceiling
/// after sizing the deployment, or explicitly select zero offline.
pub const DEFAULT_RECOVERY_MAX_OBJECTS: usize = 100_000;

/// Default aggregate store bytes admitted by a full recovery (1 GiB).
pub const DEFAULT_RECOVERY_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Durable marker directory owned by an in-progress sled-to-redb migration.
///
/// Public so the narrowly-scoped `dag migrate` compatibility command can
/// create it. Normal [`Control::open`] calls refuse while it exists.
pub const MIGRATION_STATE_DIR: &str = ".control-redb-migration-v1";

/// Same-filesystem redb staging file used by `dag migrate`.
pub const MIGRATION_STAGE_FILE: &str = ".control-redb-migration-v1.stage";

/// Permanent migration receipt. Renaming the active marker directory here is
/// the final atomic state transition and preserves the legacy provenance.
pub const MIGRATION_COMPLETE_DIR: &str = ".control-redb-migration-v1.complete";

/// Sled-era paths whose presence marks a pre-migration data directory.
pub const LEGACY_SLED_PATHS: [&str; 6] = [
    "index",
    "pointer.db",
    "pin.db",
    "job.db",
    "events.db",
    "recovery.db",
];

/// In-process test harness. Available to downstream crates via the
/// `test-utils` feature, and always available to this crate's own tests.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// Default bound on subtree pin expansion during retention snapshots.
///
/// This is a guard against a runaway walk, not a policy limit. It used to be
/// 10_000 and expansion silently truncated at it, so a pin over anything
/// larger protected a prefix and collection ate the rest — at the default
/// chunk size that was any pinned artefact over about 10 GB. Hitting the
/// ceiling now refuses to collect ([`ControlError::RetentionIncomplete`])
/// rather than under-protecting, so it can sit high enough not to be reached
/// in normal use.
pub(crate) const DEFAULT_MAX_SUBTREE_EXPANSION: usize = 5_000_000;

/// Default event broadcast channel capacity.
const DEFAULT_EVENT_CAPACITY: usize = 1024;

/// Serialises recovery snapshots against mutations of the derived state they
/// replace. Normal pointer, pin, signature-index and claim-index writers take
/// a shared guard; recovery/finalize takes the exclusive guard from before it
/// reads authoritative state until the replacement transaction commits.
pub(crate) type MutationGate = Arc<RwLock<()>>;

/// The control plane: one data directory, every subsystem wired to it.
///
/// All fields are `Arc`-shared and every method takes `&self`, so a single
/// `Control` can be shared across threads (or an async server) without locking.
pub struct Control {
    /// Content-addressed chunk store (`<data_dir>/data` + `<data_dir>/index`).
    pub store: Arc<FsStore>,
    /// Job specs, runs, effect cache and pointer subscriptions.
    pub job_log: Arc<JobLog>,
    /// Append-only pin event log.
    pub pin_log: Arc<PinLog<FsStore>>,
    /// Append-only pointer event log.
    pub pointer_log: Arc<PointerLog<FsStore>>,
    /// Effective retention derived from the pin log.
    pub retention: Arc<RetentionIndex<FsStore>>,
    /// Signature index and local trust keyring.
    pub signature_log: Arc<SignatureLog<FsStore>>,
    /// Recovery gate state (pointer + retention rebuild flags).
    pub recovery_state: Arc<RecoveryState>,
    /// Unified event stream with a durable journal.
    pub event_bus: EventBus,
    /// Operational counters and latency histograms for this deployment,
    /// rendered by the HTTP API at `/metrics`. One registry per open
    /// directory — not a global — so embedders and tests count in isolation.
    pub metrics: Arc<dag_core::Metrics>,
    /// Cross-log publication barrier used by recovery and sync finalization.
    mutation_gate: MutationGate,
    data_dir: PathBuf,
    /// One-shot deterministic pause after GC has completed its protected-root
    /// snapshot. Test-only: production collection has no hook or extra lock.
    #[cfg(test)]
    gc_test_pause: parking_lot::Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

#[cfg(all(test, unix))]
mod unix_permission_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_new_control_directory_and_database_are_private() {
        let parent = tempfile::tempdir().unwrap();
        let data_dir = parent.path().join("new-deployment");
        let control = Control::open(&data_dir).unwrap();

        let dir_mode = std::fs::metadata(control.path())
            .unwrap()
            .permissions()
            .mode();
        let db_mode = std::fs::metadata(data_dir.join(CONTROL_DB_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o077, 0, "data directory mode {dir_mode:04o}");
        assert_eq!(db_mode & 0o077, 0, "control database mode {db_mode:04o}");
    }
}

#[cfg(test)]
mod migration_open_tests {
    use super::*;

    fn open_error(path: &Path) -> ControlError {
        match Control::open(path) {
            Ok(_) => panic!("Control::open unexpectedly accepted an unsafe migration layout"),
            Err(error) => error,
        }
    }

    #[test]
    fn active_migration_marker_blocks_normal_open_even_after_publication() {
        let directory = tempfile::tempdir().unwrap();
        drop(Control::open(directory.path()).unwrap());
        std::fs::create_dir(directory.path().join(MIGRATION_STATE_DIR)).unwrap();

        assert!(matches!(
            open_error(directory.path()),
            ControlError::MigrationInProgress { .. }
        ));
    }

    #[test]
    fn unmarked_mixed_sled_and_redb_layout_is_never_accepted() {
        let directory = tempfile::tempdir().unwrap();
        drop(Control::open(directory.path()).unwrap());
        std::fs::create_dir(directory.path().join("pointer.db")).unwrap();

        assert!(matches!(
            open_error(directory.path()),
            ControlError::MixedStorageLayout { .. }
        ));
    }

    #[test]
    fn completed_receipt_or_retired_backup_prevents_empty_database_initialization() {
        for artifact in [
            MIGRATION_COMPLETE_DIR.to_string(),
            "pointer.db.sled.bak".into(),
        ] {
            let directory = tempfile::tempdir().unwrap();
            std::fs::create_dir(directory.path().join(&artifact)).unwrap();

            assert!(matches!(
                open_error(directory.path()),
                ControlError::UnsafeMigrationLayout { .. }
            ));
            assert!(
                !directory.path().join(CONTROL_DB_FILE).exists(),
                "migration evidence {artifact} must prevent a fresh database"
            );
        }
    }

    #[test]
    fn orphaned_stage_blocks_normal_open_even_beside_a_valid_database() {
        let directory = tempfile::tempdir().unwrap();
        drop(Control::open(directory.path()).unwrap());
        std::fs::write(
            directory.path().join(MIGRATION_STAGE_FILE),
            b"orphaned stage",
        )
        .unwrap();

        assert!(matches!(
            open_error(directory.path()),
            ControlError::UnsafeMigrationLayout { .. }
        ));
    }

    #[test]
    fn strict_existing_open_never_creates_a_missing_database() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            Control::open_existing(directory.path()),
            Err(ControlError::ControlDbUnreadable { .. })
        ));
        assert!(!directory.path().join(CONTROL_DB_FILE).exists());
    }
}

/// Options for a garbage collection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcRequest {
    /// Node whose local-scoped pins should be honoured alongside global pins.
    #[serde(default = "default_node_id")]
    pub node_id: String,
    /// Report what would be deleted without deleting it.
    #[serde(default)]
    pub dry_run: bool,
    /// Cap on deletions in one pass.
    ///
    /// A nonzero value also selects the ordinary finite inventory ceiling.
    /// Zero removes both ceilings and is reserved for an explicit offline CLI
    /// pass; the HTTP API refuses it.
    #[serde(default = "default_max_delete")]
    pub max_delete: usize,
    /// Chunks younger than this are never collected.
    #[serde(default = "default_min_age_secs")]
    pub min_age_secs: u64,
    /// Protect control-plane logs and NodeLinks.
    #[serde(default = "default_true")]
    pub system_protection: bool,
}

const DEFAULT_NODE_ID: &str = "local";

fn default_node_id() -> String {
    DEFAULT_NODE_ID.to_string()
}
fn default_min_age_secs() -> u64 {
    60
}
fn default_max_delete() -> usize {
    dag_storage::DEFAULT_GC_MAX_DELETIONS
}
fn default_true() -> bool {
    true
}

impl Default for GcRequest {
    fn default() -> Self {
        Self {
            node_id: default_node_id(),
            dry_run: false,
            max_delete: default_max_delete(),
            min_age_secs: default_min_age_secs(),
            system_protection: true,
        }
    }
}

#[derive(Default)]
struct GcInventoryEvidence {
    /// Unfiled but schema-valid control records are ambiguous user content.
    /// Treat their referenced content as roots for this pass rather than
    /// either deleting it or permanently bricking recovery.
    conservative_roots: Vec<(Cid, reference::ReferenceDepth)>,
    /// Evidence objects with a missing derived lookup remain protected even
    /// when they do not themselves root a content graph.
    conservative_objects: HashSet<Cid>,
    unfiled_records: usize,
}

/// What [`Control::recover`] brought back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Pointer heads rebuilt from the events table.
    pub pointers_rebuilt: u32,
    /// Pointer events the store held that the table lacked. Non-zero means
    /// the table was behind — the truncated-`control.redb` case — and is
    /// surfaced rather than hidden, because a store scan cannot tell a
    /// stranded event from a forged one.
    pub pointer_events_adopted: usize,
    /// Pin heads rebuilt from the events table.
    pub pins_rebuilt: u32,
    /// Pin events adopted from the store; see `pointer_events_adopted`.
    pub pin_events_adopted: usize,
    /// Job heads rebuilt from the events table.
    pub jobs_rebuilt: u32,
    /// Job events adopted from the store; see `pointer_events_adopted`.
    pub job_events_adopted: usize,
    /// Signature entries re-indexed, so collection can protect them again.
    pub signatures_indexed: u32,
    /// Effect-claim entries re-indexed (ADR-003).
    pub claims_indexed: u32,
    /// Whether the recovery gate is now satisfied.
    pub recovered: bool,
}

/// A point-in-time summary of the deployment, for dashboards and `status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStats {
    /// Chunks tracked in the index.
    pub chunks: usize,
    /// Total bytes across all stored chunks.
    pub bytes: u64,
    /// Number of distinct pointers.
    pub pointers: usize,
    /// Number of distinct pins (any state).
    pub pins: usize,
    /// Pins currently providing retention (active and unexpired).
    pub active_pins: usize,
    /// Number of registered jobs.
    pub jobs: usize,
    /// Runs waiting for a worker lease.
    pub pending_runs: u64,
    /// Runs currently owned by a heartbeating worker (or direct executor).
    pub running_runs: u64,
    /// Durable pointer-trigger intents not yet converted to runs.
    pub trigger_queue: u64,
    /// Permanent trigger failures requiring operator inspection.
    pub trigger_dead_letters: u64,
    /// Latest sequence number in the event journal.
    pub event_seq: u64,
    /// Whether the recovery gate is satisfied.
    pub recovered: bool,
}

/// Create a new deployment directory without granting group/world access.
///
/// `create_dir_all` inherits `0777 & !umask`, which is commonly `0755`.
/// That is too broad for a directory containing job configuration, trust
/// policy and (under `keys/`) signing seeds. `DirBuilderExt::mode` applies
/// only to newly created components; an existing operator-managed directory
/// is diagnosed below rather than silently chmodded.
fn create_private_data_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Test a path without following its final component and without collapsing
/// permission or I/O failures into "absent".
fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ControlError::io(
            format!("reading metadata for {}", path.display()),
            error,
        )),
    }
}

/// Require an existing control database to be a real regular file. This is
/// deliberately stricter than `OpenOptions`: following a substituted symlink
/// or initialising a zero-length placeholder can make a damaged deployment
/// look like a healthy empty one.
fn control_database_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(ControlError::ControlDbUnreadable {
            path: path.display().to_string(),
            detail: "the path is not a regular file".into(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ControlError::io(
            format!("reading metadata for {}", path.display()),
            error,
        )),
    }
}

/// Open or initialize redb through a descriptor created with a private mode.
///
/// Opening by pathname through redb itself uses the process umask and can
/// otherwise leave `control.redb` world-readable on a typical `0022` host.
/// The mode is ignored by the OS when the file already exists.
fn open_control_database(
    path: &Path,
    create: bool,
) -> std::result::Result<Database, redb::DatabaseError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        if !create {
            // `create_file` would initialize an existing zero-length file.
            // Migration validation must instead prove that the staged or
            // published inode is already a complete redb database.
            return Database::builder().open(path);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        Database::builder().create_file(file)
    }

    #[cfg(not(unix))]
    {
        if create {
            Database::create(path)
        } else {
            Database::open(path)
        }
    }
}

/// Flag legacy/operator-created paths whose access policy is broader than the
/// secure default. Group-shared deployments may be intentional, so opening
/// remains non-destructive and the operator gets an actionable warning.
#[cfg(unix)]
fn warn_if_broad_unix_permissions(path: &Path, kind: &str, recommended: u32) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            target: "dag::permissions",
            path = %path.display(),
            mode = format_args!("{mode:04o}"),
            recommended = format_args!("{recommended:04o}"),
            "{kind} grants group or world access; restrict it unless this is an intentional shared deployment"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_broad_unix_permissions(_path: &Path, _kind: &str, _recommended: u32) {}

impl Control {
    /// Open the default control plane, rooted at `.dag`.
    pub fn open_default() -> Result<Self> {
        Self::open(Path::new(".dag"))
    }

    /// Open (creating if needed) the control plane rooted at `data_dir`.
    ///
    /// Every subsystem is derived from this one path — see the module docs for
    /// the layout. Opening the same directory twice in one process will fail on
    /// the redb file lock, which is intentional: one `Control` per directory.
    ///
    /// A directory written by a pre-redb release is refused rather than
    /// silently reinitialised: this is provenance data, and an empty database
    /// beside six full sled directories would *look* like data loss even
    /// though nothing was touched. `dag migrate` performs the conversion.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_waiting(data_dir, Duration::ZERO)
    }

    /// Open an existing deployment without ever creating `control.redb`.
    ///
    /// Backup restore uses this after copying a supposedly complete snapshot:
    /// validation must reject a missing or zero-length database, not initialise
    /// one and publish an empty control plane.
    #[doc(hidden)]
    pub fn open_existing(data_dir: &Path) -> Result<Self> {
        Self::open_once_with_policy(data_dir, false)
    }

    /// Open the control plane, waiting up to `lock_timeout` for another
    /// process to release the directory.
    ///
    /// redb locks the database file to a single handle, so concurrent `dag`
    /// invocations against one directory collide. That is the design, but
    /// failing instantly is a poor way to express it: a build or CI job firing
    /// several commands has no recourse but to serialise them itself. Waiting
    /// turns a hard failure into a queue.
    ///
    /// `Duration::ZERO` means try once, which is what [`Control::open`] does.
    pub fn open_waiting(data_dir: &Path, lock_timeout: Duration) -> Result<Self> {
        let deadline = std::time::Instant::now() + lock_timeout;
        let mut backoff = Duration::from_millis(20);
        loop {
            match Self::open_once(data_dir) {
                Err(ControlError::DatabaseLocked { path })
                    if std::time::Instant::now() < deadline =>
                {
                    // Someone else owns it; wait and try again rather than
                    // handing the caller an error it can only sleep on itself.
                    let _ = path;
                    std::thread::sleep(backoff.min(Duration::from_millis(250)));
                    backoff *= 2;
                }
                other => return other,
            }
        }
    }

    fn open_once(data_dir: &Path) -> Result<Self> {
        Self::open_once_with_policy(data_dir, true)
    }

    fn open_once_with_policy(data_dir: &Path, create_if_missing: bool) -> Result<Self> {
        let marker = data_dir.join(MIGRATION_STATE_DIR);
        if path_exists_no_follow(&marker)? {
            return Err(ControlError::MigrationInProgress {
                path: data_dir.display().to_string(),
                marker: marker.display().to_string(),
            });
        }

        let stage = data_dir.join(MIGRATION_STAGE_FILE);
        if path_exists_no_follow(&stage)? {
            return Err(ControlError::UnsafeMigrationLayout {
                path: data_dir.display().to_string(),
                database: CONTROL_DB_FILE.to_string(),
                found: MIGRATION_STAGE_FILE.to_string(),
            });
        }

        let mut legacy = Vec::new();
        for path in LEGACY_SLED_PATHS {
            if path_exists_no_follow(&data_dir.join(path))? {
                legacy.push(path);
            }
        }
        let db_path = data_dir.join(CONTROL_DB_FILE);
        let database_exists = control_database_exists(&db_path)?;
        if !legacy.is_empty() {
            if database_exists {
                return Err(ControlError::MixedStorageLayout {
                    path: data_dir.display().to_string(),
                    database: CONTROL_DB_FILE.to_string(),
                    found: legacy.join(", "),
                });
            }
            return Err(ControlError::LegacyDataDir {
                path: data_dir.display().to_string(),
                found: legacy.join(", "),
            });
        }

        if !database_exists {
            let mut migration_artifacts = Vec::new();
            if path_exists_no_follow(&data_dir.join(MIGRATION_COMPLETE_DIR))? {
                migration_artifacts.push(MIGRATION_COMPLETE_DIR.to_string());
            }
            for source in LEGACY_SLED_PATHS {
                let backup = format!("{source}.sled.bak");
                if path_exists_no_follow(&data_dir.join(&backup))? {
                    migration_artifacts.push(backup);
                }
            }
            if !migration_artifacts.is_empty() {
                return Err(ControlError::UnsafeMigrationLayout {
                    path: data_dir.display().to_string(),
                    database: CONTROL_DB_FILE.to_string(),
                    found: migration_artifacts.join(", "),
                });
            }
            if !create_if_missing {
                return Err(ControlError::ControlDbUnreadable {
                    path: db_path.display().to_string(),
                    detail: "the file is missing".into(),
                });
            }
        }

        // Existing files are always opened strictly. In particular, an
        // existing zero-length file is corruption, not permission to create a
        // fresh database. Creation is reserved for an artifact-free directory.
        Self::open_database_at(data_dir, &db_path, !database_exists)
    }

    /// Open the private same-directory database used by `dag migrate` while
    /// retaining the real deployment's content path.
    ///
    /// This is intentionally not a general alternate-database constructor:
    /// it accepts only the fixed staging/final names and only while the
    /// durable migration marker is a real directory. The migration command
    /// uses it to run schema initialization and every standard rebuild before
    /// publishing the staged file, and to validate an interrupted publish on
    /// resume. Normal callers must use [`Control::open`].
    #[doc(hidden)]
    pub fn open_migration_database(data_dir: &Path, database_path: &Path) -> Result<Self> {
        let marker = data_dir.join(MIGRATION_STATE_DIR);
        let marker_meta = std::fs::symlink_metadata(&marker).map_err(|error| {
            ControlError::io(
                format!("reading migration marker {}", marker.display()),
                error,
            )
        })?;
        if !marker_meta.file_type().is_dir() || marker_meta.file_type().is_symlink() {
            return Err(ControlError::Invalid(format!(
                "migration marker {} is not a real directory",
                marker.display()
            )));
        }
        let staged = data_dir.join(MIGRATION_STAGE_FILE);
        let published = data_dir.join(CONTROL_DB_FILE);
        if database_path != staged && database_path != published {
            return Err(ControlError::Invalid(format!(
                "migration database path {} is not the fixed stage or publication path",
                database_path.display()
            )));
        }
        let database_meta = std::fs::symlink_metadata(database_path).map_err(|error| {
            ControlError::io(
                format!("reading migration database {}", database_path.display()),
                error,
            )
        })?;
        if database_meta.file_type().is_symlink() || !database_meta.file_type().is_file() {
            return Err(ControlError::Invalid(format!(
                "migration database {} is not a regular file",
                database_path.display()
            )));
        }
        Self::open_database_at(data_dir, database_path, false)
    }

    fn open_database_at(data_dir: &Path, db_path: &Path, create: bool) -> Result<Self> {
        create_private_data_dir(data_dir)
            .map_err(|e| ControlError::io(format!("failed to create {}", data_dir.display()), e))?;

        // One database file; every subsystem gets a table in it.
        // redb answers a *truncated* file with a panic rather than an error —
        // an assertion deep in its page manager, which reaches the operator
        // as exit 101 and a path inside ~/.cargo/registry. A half-written
        // database is the ordinary artifact of an interrupted copy or a full
        // disk, so it deserves a sentence rather than a backtrace. The panic
        // unwinds, so it can be caught and named.
        let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            open_control_database(db_path, create)
        }))
        .map_err(|_| ControlError::ControlDbUnreadable {
            path: db_path.display().to_string(),
            detail: "the file is shorter than its own header claims".into(),
        })?;

        let db = Arc::new(opened.map_err(|e| match e {
            // Keep this one distinguishable. Flattening it into a string
            // told every caller "internal error" for what is really "wait
            // your turn" — and left the CLI reporting EX_SOFTWARE for a
            // routine collision.
            redb::DatabaseError::DatabaseAlreadyOpen => ControlError::DatabaseLocked {
                path: data_dir.display().to_string(),
            },
            redb::DatabaseError::Storage(inner) => ControlError::ControlDbUnreadable {
                path: db_path.display().to_string(),
                detail: inner.to_string(),
            },
            other => ControlError::db("opening control database", other),
        })?);

        warn_if_broad_unix_permissions(data_dir, "data directory", 0o700);
        warn_if_broad_unix_permissions(db_path, "control database", 0o600);

        // Before any subsystem opens a table, so a directory this build
        // cannot read is refused without being written to.
        if let SchemaState::Upgraded { from } = schema::check_and_stamp(&db)? {
            // Not a silent step: from here on this directory holds events an
            // older binary cannot decode, and the operator should learn that
            // now rather than from a failed downgrade.
            tracing::warn!(
                target: "dag::schema",
                from,
                to = SCHEMA_VERSION,
                "upgraded the on-disk schema; older builds will now refuse this directory"
            );
        }

        // One registry for everything below: the store times its I/O into it,
        // the event bus counts emissions, collection and sync record here too.
        let metrics = Arc::new(dag_core::Metrics::default());

        let index = Arc::new(ChunkIndex::with_database(db.clone())?);
        let store = Arc::new(
            FsStore::with_chunk_index(data_dir.join("data"), index)?.with_metrics(metrics.clone()),
        );

        // Event bus first, so every log can be wired to it as it is built.
        let event_bus = EventBus::with_journal(DEFAULT_EVENT_CAPACITY, db.clone())?
            .with_metrics(metrics.clone());

        let mutation_gate = Arc::new(RwLock::new(()));

        let job_log = Arc::new(
            JobLog::new(db.clone(), store.clone())?
                .with_mutation_gate(mutation_gate.clone())
                .with_event_bus(event_bus.clone()),
        );

        let pin_log = Arc::new(
            PinLog::new(store.clone(), db.clone())?
                .with_mutation_gate(mutation_gate.clone())
                .with_event_bus(event_bus.clone()),
        );

        let pointer_log = Arc::new(
            PointerLog::new(store.clone(), db.clone())?
                .with_mutation_gate(mutation_gate.clone())
                .with_event_bus(event_bus.clone()),
        );

        // Schema 4 makes this token authoritative and prevents an older
        // binary from appending an event without bumping it. Existing logs
        // need only one seed; continuations are O(1).
        sync_generation::initialize(&db)
            .map_err(|error| ControlError::db("initializing sync generation", error))?;

        let retention = Arc::new(RetentionIndex::new(
            pin_log.clone(),
            store.clone(),
            DEFAULT_MAX_SUBTREE_EXPANSION,
        ));

        let signature_log = Arc::new(
            SignatureLog::new(store.clone(), db.clone())?.with_mutation_gate(mutation_gate.clone()),
        );

        let recovery_state = Arc::new(RecoveryState::new(db)?);

        Ok(Self {
            store,
            job_log,
            pin_log,
            pointer_log,
            retention,
            signature_log,
            recovery_state,
            event_bus,
            metrics,
            mutation_gate,
            data_dir: data_dir.to_path_buf(),
            #[cfg(test)]
            gc_test_pause: parking_lot::Mutex::new(None),
        })
    }

    /// The data directory this control plane was opened against.
    pub fn path(&self) -> &Path {
        &self.data_dir
    }

    /// Run a bulk write against a store that batches its fsyncs, and make it
    /// durable before returning.
    ///
    /// [`Control::store`] is durable per chunk: every write costs an fsync of
    /// the bytes, an fsync of the directory naming them, and a redb commit for
    /// the index entry. That is the right default for a pointer update. It is
    /// the wrong one for ingesting a large file, which is one chunk per
    /// megabyte and so three device flushes per megabyte — the difference
    /// between an ingest bounded by the disk and one bounded by flush latency.
    ///
    /// `f` receives a second view of *the same* data directory and *the same*
    /// index, opened under
    /// [`DurabilityPolicy::Deferred`](dag_storage::DurabilityPolicy::Deferred).
    /// Nothing about
    /// [`Control::store`] changes, which is the point: a concurrent pointer
    /// update on another thread keeps the durability it was promised, and a
    /// panic inside `f` cannot leave a downgraded store behind for everything
    /// afterwards — the view is dropped with its owed work, and the caller
    /// never got a CID for any of it.
    ///
    /// On the way out — and only on the success path — the view is flushed:
    /// bytes and directories first, index entries after, so a crash at any
    /// point leaves unindexed files rather than an index naming bytes that
    /// never landed. If `f` fails or panics, the partial writes are unindexed
    /// garbage that `dag index reindex` or the next collection reclaims.
    ///
    /// **The residual trade.** A crash can leave unindexed files, including a
    /// short file at a final CID path. They are not published as indexed
    /// content: a re-run offers every chunk through `put_chunk`, which hashes
    /// and adopts an intact orphan or repairs a mismatched one before the new
    /// manifest is returned. The caller still needs replayable input because
    /// the interrupted invocation itself returns no root CID.
    pub fn bulk_ingest<T, E>(
        &self,
        f: impl FnOnce(&FsStore) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<dag_core::CoreError>,
    {
        let staging = self.staging_store()?;
        let out = f(&staging)?;
        staging.sync()?;
        Ok(out)
    }

    /// A second, deferred-durability view of this directory's store, for bulk
    /// writers that can replay their input.
    ///
    /// This is the store [`Control::bulk_ingest`] hands its closure, exposed
    /// for callers whose write phase does not fit a closure — the sync
    /// destination, the gRPC node server. The contract is the same: nothing
    /// written here is durable, or visible to the index, until
    /// [`ContentStore::sync`] runs, so callers must flush before recording
    /// anything that *names* what they wrote.
    pub fn staging_store(&self) -> Result<FsStore, dag_core::CoreError> {
        let index = self.store.get_index().ok_or_else(|| {
            dag_core::CoreError::PreconditionFailed(
                "control store was opened without an index".to_string(),
            )
        })?;
        Ok(
            FsStore::with_chunk_index(self.data_dir.join("data"), index)?
                // Every view over this directory participates in one
                // durability/publication gate and one pending registry. A
                // publication through this view therefore flushes writes
                // made by concurrent bulk views as well as its own.
                .with_coordination(self.store.coordination())
                .with_durability(dag_storage::DurabilityPolicy::Deferred)
                // Bulk writers are replayable by contract, so the self-flush
                // point trades crash blast-radius for fsync amortisation: at
                // the default 1024 a bulk ingest still pays roughly one fsync
                // per chunk, which the scale experiment measured as the whole
                // cost of a million-chunk ingest.
                .with_deferred_sync_threshold(65_536)
                // Share the control store's in-flight registry, so a chunk this
                // ingest writes is off limits to a collection driven through
                // `Control::store` — the two are the same directory, and the
                // collector only ever consults that store's registry.
                .with_in_flight_registry(self.store.in_flight_registry())
                .with_metrics(self.metrics.clone()),
        )
    }

    /// Subscribe to the live event stream.
    ///
    /// The receiver sees every event emitted after this call. Use
    /// [`EventBus::replay_from`] on [`Control::event_bus`] for history.
    pub fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
        self.event_bus.subscribe()
    }

    // ---- jobs ----------------------------------------------------------

    /// Register a job spec. Returns its id.
    pub fn create_job(&self, spec: JobSpec) -> Result<JobId> {
        let job_id = spec.job_id.clone();
        let manifest = if matches!(spec.policy.trigger, dag_core::TriggerPolicy::OnCreate) {
            Some(self.resolve_job_inputs(&spec)?)
        } else {
            None
        };
        self.job_log.create_job_with_manifest(spec, manifest)?;
        Ok(job_id)
    }

    /// Replace a registered job's spec, appending a chained `Updated` event.
    ///
    /// The job id in `spec` selects the job; it cannot be changed. Runs and
    /// the effect cache survive — they are keyed by job id — but a spec change
    /// changes the effect key, so previously cached effects stop matching
    /// rather than being served for the new spec (J4).
    pub fn update_job(&self, spec: JobSpec) -> Result<JobId> {
        let job_id = spec.job_id.clone();
        self.job_log.update_job(spec)?;
        Ok(job_id)
    }

    /// Enqueue a run for a job without executing it.
    pub fn trigger_job(&self, job_id: JobId) -> Result<()> {
        self.enqueue_job_run(&job_id, "manual")?;
        Ok(())
    }

    /// Enqueue a run and return its exact ID. Inputs are resolved against the
    /// immutable spec selected while the job log's writer lock is held.
    pub fn enqueue_job_run(&self, job_id: &JobId, reason: &str) -> Result<dag_core::RunId> {
        self.job_log
            .trigger_job_resolved(job_id, reason, |spec| self.resolve_job_inputs(spec))
    }

    /// Drain durable pointer triggers with enqueue-time input snapshots.
    pub fn drain_job_trigger_queue(&self, limit: usize) -> Result<TriggerDrainReport> {
        self.job_log
            .drain_trigger_queue_resolved(limit, |spec| self.resolve_job_inputs(spec))
    }

    fn resolve_job_inputs(&self, spec: &JobSpec) -> Result<dag_core::InputManifest> {
        let mut pointer_heads = Vec::with_capacity(spec.inputs.pointer_inputs.len());
        for pointer_id in &spec.inputs.pointer_inputs {
            let head = self.pointer_log.get_head(pointer_id)?;
            pointer_heads.push(dag_core::ResolvedPointer {
                pointer_id: pointer_id.clone(),
                head_cid: head.current_cid,
                log_seq: head.seq,
            });
        }
        Ok(dag_core::InputManifest {
            static_inputs: spec.inputs.static_inputs.clone(),
            pointer_heads,
            resolved_at_unix: now_unix(),
        })
    }

    /// Publish a signed effect claim: "this effect key produced these
    /// outputs, says this key" (ADR-003).
    ///
    /// Stores the claim entry, pins it as a subtree, indexes it under the key,
    /// and signs it, so the claim *and its outputs* become roots for sync
    /// and GC. Idempotent throughout: the entry is deterministic, the index
    /// insert deduplicates, and Ed25519 signatures are deterministic, so
    /// re-attesting the same fact changes nothing.
    pub fn attest_effect(
        &self,
        key: &EffectKey,
        outputs: &[(String, Cid)],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Cid> {
        // Refuse to claim outputs nobody could check — the same rule
        // sign_cid applies to its target, and all the way down for a chunked
        // output: a *signed* claim over a manifest whose parts are missing
        // is a node vouching for bytes it cannot produce, which is precisely
        // what the signature is supposed to rule out.
        for (name, cid) in outputs {
            dag_core::file::verify_deep(self.store.as_ref(), cid).map_err(|e| {
                dag_core::CoreError::InvalidCid(format!(
                    "refusing to claim output {:?}: {}",
                    name, e
                ))
            })?;
            let bytes = self.store.get_chunk(cid)?;
            let computed = Cid::compute(&bytes);
            if computed != *cid {
                return Err(dag_core::CoreError::InvalidCid(format!(
                    "refusing to claim output {:?}: stored bytes hash to {}",
                    name, computed
                ))
                .into());
            }
        }

        let entry = effects::claim_entry(key, outputs);
        let encoded = entry.to_bytes_cbor()?;
        if effects::claim_from_bytes(&encoded).is_none() {
            return Err(ControlError::Invalid(
                "effect claim exceeds schema, key, output-count, or output-name limits".into(),
            ));
        }
        let claim_cid = self.store.put_entry(&entry)?;

        // Publish retention before either derived lookup or signature. A
        // crash/error can then leave only safe over-retention; the opposite
        // order left a filed, signed claim whose claim and outputs GC could
        // delete before the final pin landed.
        integration::PinCreator::ensure_pin(
            &*self.pin_log,
            &format!("effect/{}", claim_cid.to_hex()),
            PinTarget::Subtree {
                root: claim_cid.clone(),
                max_depth: None,
            },
            PinScope::Global,
            None,
        )?;
        self.job_log.index_claim(&key.to_binary_key(), &claim_cid)?;
        self.signature_log.sign(
            &claim_cid,
            Some("effect-claim".into()),
            serde_json::json!({
                "type": effects::EFFECT_CLAIM_KIND,
                "effectKey": hex::encode(key.to_binary_key()),
            }),
            signing_key,
        )?;
        Ok(claim_cid)
    }

    /// Outputs from a trusted effect claim for `key`, if one exists.
    ///
    /// Returns `Some` only when every gate passes (invariant J7): the claim
    /// decodes and names exactly this effect key; a signature over the claim
    /// verifies against the *keyring's* copy of a key trusted **for
    /// adoption** (ADR-004) — never the key embedded in the record; and
    /// every claimed output is present with bytes that hash to its CID.
    /// Anything less is `None`: the index is never trusted, and a failed
    /// gate degrades to "execute normally".
    pub fn adopt_attested(&self, key: &EffectKey) -> Result<Option<Vec<(String, Cid)>>> {
        const MAX_CLAIMS_EXAMINED: usize = 256;
        const MAX_CLAIM_BYTES_EXAMINED: usize = 64 * 1024 * 1024;

        let want = hex::encode(key.to_binary_key());
        let claims = self.job_log.claims_for_key(key)?;
        if claims.len() > MAX_CLAIMS_EXAMINED {
            tracing::warn!(
                effect_key = %want,
                indexed_claims = claims.len(),
                limit = MAX_CLAIMS_EXAMINED,
                "effect adoption is examining a bounded prefix; a miss safely falls back to execution"
            );
        }
        let mut claim_bytes_remaining = MAX_CLAIM_BYTES_EXAMINED;
        let mut signature_records_remaining = signatures::MAX_SIGNATURE_AGGREGATE_RECORDS;
        let mut signature_bytes_remaining = signatures::MAX_SIGNATURE_AGGREGATE_BYTES;

        for claim_cid in claims.into_iter().take(MAX_CLAIMS_EXAMINED) {
            let Ok(bytes) = self.store.get_chunk(&claim_cid) else {
                continue;
            };
            if bytes.len() > claim_bytes_remaining {
                tracing::warn!(
                    effect_key = %want,
                    limit = MAX_CLAIM_BYTES_EXAMINED,
                    "effect adoption exhausted its aggregate claim-byte budget; falling back to execution"
                );
                return Ok(None);
            }
            claim_bytes_remaining -= bytes.len();
            let Some((claim, _)) = effects::claim_from_bytes(&bytes) else {
                continue;
            };
            if claim.effect_key != want {
                continue;
            }
            // Trusted *for adoption* (ADR-004): a verify-only grant leaves
            // the claim usable as evidence, never as substitute outputs.
            if !self.signature_log.has_trusted_signature_for_bounded(
                &claim_cid,
                TrustPurpose::Adopt,
                &mut signature_records_remaining,
                &mut signature_bytes_remaining,
            )? {
                if signature_records_remaining == 0 || signature_bytes_remaining == 0 {
                    tracing::warn!(
                        effect_key = %want,
                        record_limit = signatures::MAX_SIGNATURE_AGGREGATE_RECORDS,
                        byte_limit = signatures::MAX_SIGNATURE_AGGREGATE_BYTES,
                        "effect adoption exhausted its aggregate signature budget; falling back to execution"
                    );
                    return Ok(None);
                }
                continue;
            }
            let Ok(outputs) = effects::claim_outputs(&claim) else {
                continue;
            };
            // Gate 4, all the way down. An exec output over 4 MiB is a
            // manifest, and re-hashing *the manifest* proves only that the
            // list of parts is intact — an adoption that passed on that
            // handed back outputs whose data chunks were gone, and then
            // wrote them into the local effect cache, so the next run was a
            // plain cache hit that never consulted the claim again. Broken
            // and sticky. `verify_deep` walks the manifest.
            let intact = outputs
                .iter()
                .all(|(_, cid)| dag_core::file::verify_deep(self.store.as_ref(), cid).is_ok());
            if !intact {
                continue;
            }
            return Ok(Some(outputs));
        }
        Ok(None)
    }

    /// Rebuild the effect-claim index by scanning the complete store without
    /// an inventory ceiling (ADR-003).
    ///
    /// Like every derived table, the index reconstructs from primary data —
    /// the claim entries themselves. Sync calls this at the destination so
    /// transferred claims become findable. Returns the number indexed. This
    /// public compatibility method is an explicit offline/embedder operation;
    /// operator-facing full recovery uses the finite object and byte ceilings
    /// on [`Self::recover`].
    pub fn rebuild_effect_claims(&self) -> Result<u32> {
        let cids = self
            .store
            .list_all_cids()
            .map_err(|e| ControlError::db("listing store", e))?;
        self.rebuild_effect_claims_from_cids(&cids)
    }

    /// Rebuild effect claims from a caller-owned inventory snapshot.
    fn rebuild_effect_claims_from_cids(&self, cids: &[Cid]) -> Result<u32> {
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let plan = self.prepare_effect_claim_rebuild_from_cids(cids)?;
        let count = plan.count();
        let db = self.pointer_log.import_database();
        let txn = db
            .begin_write()
            .map_err(|e| ControlError::db("begin effect-claim rebuild", e))?;
        self.job_log.apply_claim_rebuild(&txn, &plan)?;
        txn.commit()
            .map_err(|e| ControlError::db("commit effect-claim rebuild", e))?;
        Ok(count)
    }

    /// Scan immutable claim entries and prepare the derived lookup replacement.
    #[cfg(test)]
    pub(crate) fn prepare_effect_claim_rebuild(&self) -> Result<job::ClaimRebuildPlan> {
        let cids = self
            .store
            .list_all_cids()
            .map_err(|e| ControlError::db("listing store", e))?;
        self.prepare_effect_claim_rebuild_from_cids(&cids)
    }

    /// Prepare the claim lookup from a caller-owned inventory snapshot.
    fn prepare_effect_claim_rebuild_from_cids(
        &self,
        cids: &[Cid],
    ) -> Result<job::ClaimRebuildPlan> {
        let mut by_key: std::collections::HashMap<
            Vec<u8>,
            std::collections::BTreeMap<Vec<u8>, Cid>,
        > = std::collections::HashMap::new();
        for cid in cids {
            // A read failure cannot be classified as "not an effect claim".
            // Omitting it would publish an incomplete retention lookup.
            let bytes = self.store.get_chunk(cid)?;
            let Some((claim, _)) = effects::claim_from_bytes(&bytes) else {
                continue;
            };
            let Ok(key_bytes) = hex::decode(&claim.effect_key) else {
                continue;
            };
            let claims = by_key.entry(key_bytes).or_default();
            claims.insert(cid.as_bytes().to_vec(), cid.clone());
            if claims.len() > job::MAX_EFFECT_CLAIMS_PER_KEY {
                // The index is a cache: omission causes execution instead of
                // adoption, never a false adoption. Keep a deterministic
                // bounded subset rather than letting surplus claim-shaped
                // user content permanently brick offline recovery.
                claims.pop_last();
            }
        }
        JobLog::prepare_claim_rebuild(
            by_key
                .into_iter()
                .map(|(key, claims)| (key, claims.into_values().collect()))
                .collect(),
        )
    }

    /// Wire a job to fire whenever `pointer_id` is updated.
    pub fn subscribe_pointer(&self, pointer_id: &str, job_id: JobId) -> Result<()> {
        self.job_log.subscribe_pointer(pointer_id, &job_id)
    }

    /// Remove one explicit pointer-trigger subscription.
    pub fn unsubscribe_pointer(&self, pointer_id: &str, job_id: JobId) -> Result<bool> {
        self.job_log.unsubscribe_pointer(pointer_id, &job_id)
    }

    /// Most recent runs for a job, newest first.
    pub fn runs(&self, job_id: JobId, limit: usize) -> Result<Vec<JobRun>> {
        self.job_log.get_job_runs(&job_id, Some(limit))
    }

    /// Explicitly compact old terminal run history for one job.
    pub fn compact_job_runs(
        &self,
        job_id: JobId,
        keep_terminal: usize,
        max_delete: usize,
        dry_run: bool,
    ) -> Result<RunCompactionReport> {
        self.job_log
            .compact_terminal_runs(&job_id, keep_terminal, max_delete, dry_run)
    }

    // ---- recovery ------------------------------------------------------

    /// Whether every safety-relevant rebuild completed against the current
    /// chunk-index replacement epoch.
    ///
    /// Garbage collection refuses to run until this is true — see
    /// [`Control::run_gc`].
    pub fn is_recovered(&self) -> Result<bool> {
        let generation = self.chunk_index_rebuild_generation()?;
        self.recovery_state.is_recovered(generation)
    }

    /// Complete chunk-index replacement epoch observed by this control plane.
    /// A `reindex` changes it and thereby invalidates any recovery verdict
    /// recorded against the previous derived catalogue.
    fn chunk_index_rebuild_generation(&self) -> Result<u64> {
        self.store
            .get_index()
            .ok_or_else(|| ControlError::Invalid("control store has no chunk index".into()))?
            .rebuild_generation()
            .map_err(ControlError::from)
    }

    /// Persisted rows that recovery or collection may scan/materialise while
    /// rebuilding safety roots and derived indexes.
    fn safety_control_row_count(&self) -> Result<u64> {
        [
            self.pointer_log.recovery_row_count()?,
            self.pin_log.recovery_row_count()?,
            self.job_log.recovery_row_count()?,
            self.signature_log.recovery_row_count()?,
        ]
        .into_iter()
        .try_fold(0u64, |total, rows| {
            total
                .checked_add(rows)
                .ok_or_else(|| ControlError::Capacity("control row count overflow".into()))
        })
    }

    /// Materialise a store inventory only after enforcing independent object
    /// and aggregate-byte ceilings. Zero explicitly removes the corresponding
    /// ceiling for offline/embedder repair operations.
    ///
    /// The extra object is requested from the store itself, so an oversized
    /// inventory is refused without first collecting it in memory. Chunk
    /// sizes are then charged before any caller is allowed to mutate a derived
    /// control table.
    fn store_inventory_with_limits(&self, max_objects: usize, max_bytes: u64) -> Result<Vec<Cid>> {
        let inventory_limit = (max_objects > 0).then(|| max_objects.saturating_add(1));
        let inventory = self.store.list_cids(inventory_limit)?;
        if max_objects > 0 && inventory.len() > max_objects {
            return Err(ControlError::RecoveryInventoryLimit { limit: max_objects });
        }

        let mut inventory_bytes = 0u64;
        for cid in &inventory {
            let size = u64::try_from(self.store.get_inventory_chunk_size(cid)?).map_err(|_| {
                ControlError::Invalid("chunk length does not fit inventory byte counter".into())
            })?;
            inventory_bytes = inventory_bytes.checked_add(size).ok_or_else(|| {
                ControlError::Invalid("store inventory byte count overflowed".into())
            })?;
            if max_bytes > 0 && inventory_bytes > max_bytes {
                return Err(ControlError::RecoveryBytesLimit {
                    limit: max_bytes,
                    required: inventory_bytes,
                });
            }
        }
        Ok(inventory)
    }

    /// Strictly decoded control-history objects present in the store but
    /// absent from their authoritative database tables.
    ///
    /// Pointer, pin, and job entries are intentionally ordinary immutable
    /// content, and legacy records are unsigned. After a lost database, shape
    /// alone therefore cannot distinguish genuine stranded history from bytes
    /// planted by a content-store writer. Full recovery refuses that authority
    /// promotion unless the offline operator explicitly opts in.
    fn unfiled_store_control_candidates(&self, inventory: &[Cid]) -> Result<(usize, usize, usize)> {
        let pointer_events: HashSet<Cid> = self
            .pointer_log
            .event_cids()?
            .into_iter()
            .map(|(_, _, cid)| cid)
            .collect();
        let pin_events: HashSet<Cid> = self
            .pin_log
            .event_cids()?
            .into_iter()
            .map(|(_, _, cid)| cid)
            .collect();
        let job_events: HashSet<Cid> = self
            .job_log
            .event_cids()?
            .into_iter()
            .map(|(_, _, cid)| cid)
            .collect();

        let mut pointers = 0usize;
        let mut pins = 0usize;
        let mut jobs = 0usize;
        for cid in inventory {
            let bytes = self.store.get_chunk(cid)?;
            let Ok(entry) = dag_core::Entry::from_bytes_cbor(&bytes) else {
                continue;
            };
            if !pointer_events.contains(cid)
                && pointer::decode_pointer_event(&entry.payload).is_ok()
            {
                pointers = pointers.saturating_add(1);
            }
            if !pin_events.contains(cid) && pin::decode_pin_event(&entry.payload).is_ok() {
                pins = pins.saturating_add(1);
            }
            if !job_events.contains(cid) && job::decode_job_event(&entry.payload).is_ok() {
                jobs = jobs.saturating_add(1);
            }
        }
        Ok((pointers, pins, jobs))
    }

    /// Whether the content store holds nothing at all.
    ///
    /// The discriminator the recovery gate turns on: "there was nothing to
    /// recover" and "the log that says what to recover is gone" produce the
    /// same cheerful zero from a table rebuild, and only one of them is safe
    /// to collect against.
    pub fn store_is_empty(&self) -> Result<bool> {
        use dag_storage::GcCapableStore;
        Ok(self.store.list_cids(Some(1))?.is_empty())
    }

    /// Whether the control database looks *lost* rather than merely empty.
    ///
    /// Both event tables empty while `data/` holds content. A table rebuild
    /// cannot tell that apart from a deployment that genuinely has no
    /// pointers and no pins — both produce a cheerful zero — and the
    /// difference decides whether collecting is routine or catastrophic:
    /// against a lost database the protected set is empty and every pinned
    /// and pointed byte in the directory is unreferenced. Measured before
    /// this check existed: certifying only the pointer/pin table rebuilds and
    /// then collecting deleted the pinned artifact and the pointer target
    /// alike. Recovery is now a complete offline protocol; there is no HTTP
    /// recovery route.
    ///
    /// The signal is the **chunk index**, not the logs. An empty pointer log
    /// is ordinary — plenty of deployments only ever `dag put` — so it says
    /// nothing. But the index lives in the same `control.redb` as the logs
    /// and is written on every write, so an index that knows about *nothing*
    /// while `data/` holds files means that file is new or restored from
    /// before the content was: exactly the case where the logs are empty for
    /// the wrong reason, and where the table rebuild reports a cheerful zero
    /// over a directory full of pinned bytes.
    ///
    /// Recovering from it means reading and reconciling every safety-relevant
    /// record in `data/` — see [`Self::recover`], invoked by the offline
    /// `dag recover --max-objects … --max-bytes …` command. A partial pointer
    /// rebuild cannot certify the signature, effect-claim, job or chunk index.
    fn control_db_appears_lost(&self) -> Result<bool> {
        let index_empty = match self.store.get_index() {
            Some(index) => index.count()? == 0,
            // No index to compare against; fall back to the logs alone.
            None => return Ok(false),
        };
        Ok(index_empty && self.store.has_any_chunk())
    }

    /// Rebuild pointer heads from the event log. Returns the number rebuilt.
    ///
    /// Updates the pointer phase marker unless the control database appears
    /// lost — see `control_db_appears_lost`. That marker alone is not a full
    /// recovery certificate; [`Self::recover`] must reconcile every phase.
    pub fn rebuild_pointers(&self) -> Result<u32> {
        let rebuilt = self.pointer_log.rebuild_from_events()?;
        if !self.control_db_appears_lost()? {
            self.recovery_state.mark_pointer_rebuilt()?;
        }
        Ok(rebuilt)
    }

    /// Rebuild pin heads from the event log. A successful non-dry-run updates
    /// the retention phase marker under the same rule as
    /// [`Self::rebuild_pointers`], but does not certify full recovery.
    pub fn rebuild_pins(&self, dry_run: bool) -> Result<PinRebuildReport> {
        let report = self.pin_log.rebuild(dry_run)?;
        if !dry_run && report.validation_errors == 0 && !self.control_db_appears_lost()? {
            self.recovery_state.mark_retention_rebuilt()?;
        }
        Ok(report)
    }

    /// Recover every GC-safety-relevant derived lookup plus job heads with the
    /// ordinary finite inventory ceiling.
    ///
    /// Rebuilds filed logs and their derived tables, and scans the bounded
    /// content inventory for every safety-relevant index. The ordinary path
    /// refuses strict-decoding pointer, pin, or job records that exist only in
    /// the store before adopting any of them; only the explicitly trusting
    /// recovery variant reconciles those unsigned candidates after an operator
    /// provenance decision. Signature and effect-claim indexes are rebuilt in
    /// either case because collection consults them to decide what to keep.
    pub fn recover(&self) -> Result<RecoveryReport> {
        self.recover_with_limits(DEFAULT_RECOVERY_MAX_OBJECTS, DEFAULT_RECOVERY_MAX_BYTES)
    }

    /// Recover every safety-relevant derived table with an explicit object/row
    /// ceiling. This compatibility helper applies the ordinary byte ceiling as
    /// well; `0` selects an operator-sized unbounded offline pass for both.
    ///
    /// The inventory preflight happens before the durable in-progress marker
    /// or any recovery mutation. Once a phase starts, that marker keeps GC
    /// closed across every later error, crash, and process reopen. Only
    /// successful chunk-index, pointer, pin, job, signature, and effect-claim
    /// recovery clears it.
    pub fn recover_with_limit(&self, max_objects: usize) -> Result<RecoveryReport> {
        self.recover_with_limits(
            max_objects,
            if max_objects == 0 {
                0
            } else {
                DEFAULT_RECOVERY_MAX_BYTES
            },
        )
    }

    /// Recover with independent object/row and aggregate-byte ceilings.
    /// Zero selects an explicitly unbounded offline dimension.
    pub fn recover_with_limits(
        &self,
        max_objects: usize,
        max_bytes: u64,
    ) -> Result<RecoveryReport> {
        self.recover_with_limits_inner(max_objects, max_bytes, false)
    }

    /// Recover while explicitly trusting unfiled, unsigned pointer, pin, and
    /// job records discovered among ordinary stored content.
    ///
    /// This is the disaster-recovery escape hatch for a genuinely lost or
    /// truncated control database. It must only be invoked offline after the
    /// operator has established that every writer able to place bytes in the
    /// store was authorised to reconstruct control-plane history. Ordinary
    /// recovery deliberately refuses this promotion.
    pub fn recover_with_limits_trusting_store_control_events(
        &self,
        max_objects: usize,
        max_bytes: u64,
    ) -> Result<RecoveryReport> {
        self.recover_with_limits_inner(max_objects, max_bytes, true)
    }

    fn recover_with_limits_inner(
        &self,
        max_objects: usize,
        max_bytes: u64,
        trust_unfiled_control_events: bool,
    ) -> Result<RecoveryReport> {
        if max_objects > 0 {
            let control_rows = self.safety_control_row_count()?;
            let ceiling = u64::try_from(max_objects).unwrap_or(u64::MAX);
            if control_rows > ceiling {
                return Err(ControlError::RecoveryTableLimit {
                    limit: max_objects,
                    rows: control_rows,
                });
            }
        }

        let inventory_limit = (max_objects > 0).then(|| max_objects.saturating_add(1));
        let inventory = self.store_inventory_with_limits(max_objects, max_bytes)?;
        self.recovery_state.begin_full_recovery()?;

        // A read/hash failure cannot be classified as irrelevant: the object
        // may be the only copy of a retention or control event. Validate the
        // complete enumerated set while the durable marker already holds the
        // GC gate closed, then let the schema-specific passes classify it.
        for cid in &inventory {
            self.store.get_chunk(cid)?;
        }
        let (unfiled_pointers, unfiled_pins, unfiled_jobs) =
            self.unfiled_store_control_candidates(&inventory)?;
        if !trust_unfiled_control_events
            && (unfiled_pointers != 0 || unfiled_pins != 0 || unfiled_jobs != 0)
        {
            return Err(ControlError::RecoveryIncomplete {
                detail: format!(
                    "the store contains {unfiled_pointers} unfiled pointer, {unfiled_pins} unfiled pin, and {unfiled_jobs} unfiled job record(s). Legacy control records are unsigned ordinary content, so recovery will not promote them to authority by shape alone. Verify the store's writer provenance, then rerun the offline CLI with `--trust-unfiled-control-events` only if every candidate is trusted"
                ),
            });
        }
        // `control.redb` owns the chunk index as well as the control tables.
        // A lost/restored database therefore needs the catalogue rebuilt from
        // this same finite, verified snapshot before a recovery verdict can
        // ever make collection eligible.
        self.store.reindex_from_inventory(&inventory)?;

        let pointers = PointerReconcileReport {
            from_table: self.pointer_log.rebuild_from_events()?,
            store: self.pointer_log.rebuild_from_cids(&inventory)?,
        };
        if pointers.store.events_skipped != 0 {
            return Err(ControlError::RecoveryIncomplete {
                detail: format!(
                    "pointer reconciliation refused {} event(s); repair or restore the reported chains and rerun `dag recover`",
                    pointers.store.events_skipped
                ),
            });
        }

        let pins = PinReconcileReport {
            table: self.pin_log.rebuild(false)?,
            store: self.pin_log.rebuild_from_cids(&inventory)?,
        };
        if pins.table.validation_errors != 0 || pins.store.events_skipped != 0 {
            return Err(ControlError::RecoveryIncomplete {
                detail: format!(
                    "pin reconciliation reported {} table validation error(s) and refused {} store event(s); repair or restore the reported chains and rerun `dag recover`",
                    pins.table.validation_errors, pins.store.events_skipped
                ),
            });
        }

        let jobs = JobReconcileReport {
            table: self.job_log.rebuild()?,
            store: self.job_log.rebuild_from_store(&inventory)?,
        };
        if jobs.table.validation_errors != 0 || jobs.store.events_skipped != 0 {
            return Err(ControlError::RecoveryIncomplete {
                detail: format!(
                    "job reconciliation reported {} table validation error(s) and refused {} store event(s); repair or restore the reported chains and rerun `dag recover`",
                    jobs.table.validation_errors, jobs.store.events_skipped
                ),
            });
        }

        let signatures = self.signature_log.rebuild_from_cids(&inventory)?;
        let claims = self.rebuild_effect_claims_from_cids(&inventory)?;

        // Safety-index writers take the shared side of this gate. Acquire the
        // exclusive side for the final inventory proof and verdict commit so
        // a signature/effect claim cannot land between the stale scan and the
        // moment recovery is certified. If anything committed during an
        // earlier phase, the changed inventory forces an explicit retry.
        let _completion_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let final_inventory = self.store.list_cids(inventory_limit)?;
        if max_objects > 0 && final_inventory.len() > max_objects {
            return Err(ControlError::RecoveryIncomplete {
                detail: format!(
                    "the store grew beyond the {max_objects}-object ceiling while recovery was running; retry offline with a sized ceiling"
                ),
            });
        }
        let mut expected = inventory.clone();
        let mut observed = final_inventory;
        expected.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        observed.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if expected != observed {
            return Err(ControlError::RecoveryIncomplete {
                detail: "the store inventory changed while recovery was running; stop concurrent writers and retry `dag recover`".into(),
            });
        }
        for cid in &observed {
            self.store.get_chunk(cid)?;
        }
        let index_generation = self.chunk_index_rebuild_generation()?;
        self.recovery_state
            .complete_full_recovery(index_generation)?;

        Ok(RecoveryReport {
            pointers_rebuilt: pointers.from_table,
            pointer_events_adopted: pointers.store.events_added,
            pins_rebuilt: pins.table.heads_rebuilt,
            pin_events_adopted: pins.store.events_added,
            jobs_rebuilt: jobs.table.heads_rebuilt,
            job_events_adopted: jobs.store.events_added,
            signatures_indexed: signatures,
            claims_indexed: claims,
            recovered: self.is_recovered()?,
        })
    }

    /// Rebuild pointer heads by scanning the complete content store without an
    /// inventory ceiling. This explicit embedder/offline compatibility method
    /// is a diagnostic/repair phase, not a complete recovery certificate; use
    /// [`Self::recover`] before garbage collection. Operator-facing callers
    /// should prefer [`Self::rebuild_pointers_from_store_with_limits`].
    ///
    /// This is the narrow store-scan phase used only after a caller explicitly
    /// accepts the unsigned-control-record trust boundary. For a lost
    /// `control.redb`, use the bounded full recovery protocol (and its explicit
    /// trust option) rather than treating this partial phase as a certificate.
    /// [`Control::rebuild_pointers`] reads only the filed events table; the
    /// event entries themselves remain in `data/` for this scan.
    pub fn rebuild_pointers_from_store(&self) -> Result<pointer::PointerStoreRebuildReport> {
        self.rebuild_pointers_from_store_with_limits(0, 0)
    }

    /// Rebuild pointer heads from a preflighted store inventory. Zero
    /// explicitly removes the corresponding offline ceiling.
    pub fn rebuild_pointers_from_store_with_limits(
        &self,
        max_objects: usize,
        max_bytes: u64,
    ) -> Result<pointer::PointerStoreRebuildReport> {
        let inventory = self.store_inventory_with_limits(max_objects, max_bytes)?;
        let report = self.pointer_log.rebuild_from_cids(&inventory)?;
        if report.events_skipped == 0 {
            self.recovery_state.mark_pointer_rebuilt()?;
        }
        Ok(report)
    }

    /// Rebuild pin heads and the pin target index by scanning the complete
    /// content store without an inventory ceiling. This explicit
    /// embedder/offline compatibility method is a diagnostic/repair phase, not
    /// a complete recovery certificate; the caller must explicitly accept the
    /// unsigned-store trust boundary, and must use [`Self::recover`] before
    /// garbage collection. Operator-facing callers should prefer
    /// [`Self::rebuild_pins_from_store_with_limits`].
    pub fn rebuild_pins_from_store(&self) -> Result<pin::PinStoreRebuildReport> {
        self.rebuild_pins_from_store_with_limits(0, 0)
    }

    /// Rebuild pin heads and reverse rows from a preflighted store inventory.
    /// Zero explicitly removes the corresponding offline ceiling.
    pub fn rebuild_pins_from_store_with_limits(
        &self,
        max_objects: usize,
        max_bytes: u64,
    ) -> Result<pin::PinStoreRebuildReport> {
        let inventory = self.store_inventory_with_limits(max_objects, max_bytes)?;
        let report = self.pin_log.rebuild_from_cids(&inventory)?;
        if report.events_skipped == 0 {
            self.recovery_state.mark_retention_rebuilt()?;
        }
        Ok(report)
    }

    /// Rebuild job heads by scanning the complete content store without an
    /// inventory ceiling. This is an explicit embedder/offline compatibility
    /// method; operator-facing callers should prefer
    /// [`Self::rebuild_jobs_from_store_with_limits`].
    ///
    /// Job *runs* live only in the database and do not come back; see
    /// [`JobLog::rebuild_from_store`]. This is an explicit unsigned-store trust
    /// operation and does not certify full recovery.
    pub fn rebuild_jobs_from_store(&self) -> Result<job::JobStoreRebuildReport> {
        self.rebuild_jobs_from_store_with_limits(0, 0)
    }

    /// Rebuild job heads from a preflighted store inventory. Zero explicitly
    /// removes the corresponding offline ceiling.
    pub fn rebuild_jobs_from_store_with_limits(
        &self,
        max_objects: usize,
        max_bytes: u64,
    ) -> Result<job::JobStoreRebuildReport> {
        let inventory = self.store_inventory_with_limits(max_objects, max_bytes)?;
        self.job_log.rebuild_from_store(&inventory)
    }

    /// Rebuild pointer heads from the events table, then reconcile against the
    /// content store, adopting any events the store holds beyond the table.
    /// This repairs one subsystem but does not certify the full recovery gate;
    /// use [`Self::recover`] before garbage collection.
    ///
    /// This legacy programmatic diagnostic can heal a *truncated* events table
    /// (`control.redb` restored from an old backup over a newer `data/`), which
    /// [`Control::rebuild_pointers`] alone cannot: that trusts the table and
    /// stops at whatever sequence the table remembers. The ordinary CLI
    /// rebuild is now table-only; its explicit `--from-store` mode and full
    /// disaster recovery require the separate store-writer trust
    /// acknowledgement.
    ///
    /// Merge-only and advance-only: it never overwrites a filed mapping (a
    /// disagreement at the same `(id, seq)` is refused and reported, never
    /// silently picked) and never lowers a head. It cannot, however,
    /// distinguish a genuine stranded event from one forged into `data/` — the
    /// store-scan trust boundary of ADR-002's unsigned logs — so a non-zero
    /// `store.events_added` is surfaced rather than hidden.
    pub fn rebuild_pointers_reconciled(&self) -> Result<pointer::PointerReconcileReport> {
        let from_table = self.pointer_log.rebuild_from_events()?;
        let store = self.pointer_log.rebuild_from_store()?;
        if store.events_skipped == 0 {
            self.recovery_state.mark_pointer_rebuilt()?;
        }
        Ok(pointer::PointerReconcileReport { from_table, store })
    }

    /// Rebuild pin heads from the events table, then reconcile against the
    /// content store. This repairs one subsystem but does not certify the full
    /// recovery gate; use [`Self::recover`] before garbage collection.
    ///
    /// The pin counterpart of [`Control::rebuild_pointers_reconciled`]. A pin
    /// deactivated since a `control.redb` backup would otherwise come back
    /// *active* off the truncated table and re-protect released content; the
    /// store scan adopts the deactivation the store proves. See that method for
    /// the merge-only/advance-only guarantees.
    pub fn rebuild_pins_reconciled(&self) -> Result<pin::PinReconcileReport> {
        let table = self.pin_log.rebuild(false)?;
        let store = self.pin_log.rebuild_from_store()?;
        if table.validation_errors == 0 && store.events_skipped == 0 {
            self.recovery_state.mark_retention_rebuilt()?;
        }
        Ok(pin::PinReconcileReport { table, store })
    }

    /// Rebuild job heads from the events table, then reconcile against the
    /// content store. Only specs come back through the store scan (runs, the
    /// effect cache and subscriptions are database-only); see
    /// [`JobLog::rebuild_from_store`]. This diagnostic does not certify the
    /// complete recovery protocol, which also reconciles every GC-safety index.
    pub fn rebuild_jobs_reconciled(&self) -> Result<job::JobReconcileReport> {
        let table = self.job_log.rebuild()?;
        let cids = self.store.list_all_cids()?;
        let store = self.job_log.rebuild_from_store(&cids)?;
        Ok(job::JobReconcileReport { table, store })
    }

    /// Rebuild job heads from the job event log and runs table.
    ///
    /// This diagnostic is available whenever job heads are suspect and is also
    /// used by migration. It does not certify the complete recovery protocol;
    /// use [`Self::recover`] to reconcile every GC-safety index and job phase.
    pub fn rebuild_jobs(&self) -> Result<job::JobRebuildReport> {
        self.job_log.rebuild()
    }

    // ---- retention & GC ------------------------------------------------

    /// Effective retention for a CID, optionally including a node's local pins.
    pub fn retention_status(
        &self,
        cid: &Cid,
        node_id: Option<&str>,
    ) -> Result<RetentionStatus, dag_core::PinError> {
        match node_id {
            Some(node) => self.retention.status_for_node(cid, node),
            None => self.retention.status(cid),
        }
    }

    /// Run garbage collection, honouring the recovery gate.
    ///
    /// Returns [`ControlError::NotRecovered`] unless [`Control::is_recovered`]
    /// is true: collecting against a half-rebuilt retention index could delete
    /// pinned data.
    pub fn run_gc(&self, req: &GcRequest) -> Result<GcReport, ControlError> {
        self.run_gc_with_details(req, true)
    }

    /// Run collection with exact counters but without retaining one report
    /// row per deleted chunk.
    ///
    /// Use this for bounded operational summaries. [`Self::run_gc`] remains
    /// the disposition-grade form used by JSON/recording callers.
    pub fn run_gc_summary(&self, req: &GcRequest) -> Result<GcReport, ControlError> {
        self.run_gc_with_details(req, false)
    }

    fn run_gc_with_details(
        &self,
        req: &GcRequest,
        collect_details: bool,
    ) -> Result<GcReport, ControlError> {
        let started = std::time::Instant::now();
        let result = self.run_gc_inner(req, collect_details);
        match &result {
            Ok(report) => {
                self.metrics.gc_runs_total.inc();
                self.metrics
                    .gc_examined_total
                    .add(report.total_chunks_examined as u64);
                self.metrics
                    .gc_deleted_total
                    .add(report.chunks_deleted as u64);
                self.metrics
                    .gc_bytes_freed_total
                    .add(report.bytes_freed as u64);
                self.metrics.gc_seconds.observe(started.elapsed());
                tracing::info!(
                    target: "dag::gc",
                    node_id = %req.node_id,
                    dry_run = req.dry_run,
                    chunks_examined = report.total_chunks_examined,
                    chunks_deleted = report.chunks_deleted,
                    bytes_freed = report.bytes_freed,
                    duration_ms = started.elapsed().as_millis() as u64,
                    "collection complete"
                );
            }
            // Refusals are the gates working, counted apart from failures so
            // an operator can tell "held the line" from "broke".
            Err(
                ControlError::NotRecovered
                | ControlError::GcControlStateLimit { .. }
                | ControlError::RetentionIncomplete { .. }
                | ControlError::RetentionUnreadable { .. },
            ) => {
                self.metrics.gc_refused_total.inc();
            }
            Err(ControlError::Core(
                dag_core::CoreError::GcInventoryLimit { .. }
                | dag_core::CoreError::GcIndexMismatch { .. },
            )) => {
                self.metrics.gc_refused_total.inc();
            }
            Err(_) => {}
        }
        result
    }

    /// Store a collection report in the ledger itself — a disposition record.
    ///
    /// For deployments where deletion must be *defensible* (legal hold,
    /// regulated retention), a report that scrolled past on stdout is not a
    /// record. This writes it as content: the full report — every collected
    /// CID with size and age — stored as a (chunked, if large) JSON file, and
    /// a small `gc-disposition/v1` entry linking to it and to the previous
    /// record. The pointer `system/gc/dispositions` names the newest record,
    /// and because a live pointer head is a transitive GC root, the *whole
    /// chain* of dispositions retains itself — each record's `prev` link is
    /// what keeps its predecessor reachable. No pin needed, nothing to
    /// remember; the mechanism that makes anything durable here makes the
    /// record of deletion durable.
    ///
    /// Returns the new record entry's CID. Being ordinary content, the record
    /// can be signed (`dag sign --cid`), exported, and replicated — sync
    /// carries pointer history, so replicas hold the disposition trail too.
    pub fn record_gc_disposition(&self, report: &GcReport) -> Result<Cid> {
        const POINTER_ID: &str = "system/gc/dispositions";
        const RECORD_KIND: &str = "gc-disposition/v1";

        if report.collected.len() != report.chunks_deleted {
            return Err(ControlError::Invalid(format!(
                "cannot record a summary-only GC report: {} itemised rows for {} deletions",
                report.collected.len(),
                report.chunks_deleted
            )));
        }

        // The full report as a file: `collected` can be many lines, and
        // an Entry payload cannot (2 MiB ceiling) — store_auto chunks it.
        let report_json = serde_json::to_vec_pretty(report)?;
        let stored = dag_core::file::store_auto(
            self.store.as_ref(),
            std::io::Cursor::new(report_json),
            Some("application/json".to_string()),
            false,
            &dag_core::ChunkerConfig::default(),
        )?;
        let report_cid = match stored {
            dag_core::StoredContent::File(f) => f.cid,
            dag_core::StoredContent::Chunk { cid, .. } => cid,
        };

        let prev = match self.pointer_log.resolve(POINTER_ID) {
            Ok(cid) => Some(cid),
            Err(pointer::PointerError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };

        let summary = serde_json::json!({
            "kind": RECORD_KIND,
            "recorded_at": now_unix(),
            "node_id": report.node_id,
            "collection_epoch": report.collection_epoch,
            "chunks_examined": report.total_chunks_examined,
            "chunks_deleted": report.chunks_deleted,
            "bytes_freed": report.bytes_freed,
            "errors": report.errors.len(),
            "errors_truncated": report.errors_truncated,
            "truncated_by_max_delete": report.truncated_by_max_deletions,
        });
        let mut links = vec![dag_core::Link {
            name: Some("report".into()),
            target: report_cid,
        }];
        if let Some(prev) = prev {
            links.push(dag_core::Link {
                name: Some("prev".into()),
                target: prev,
            });
        }
        let entry = dag_core::Entry {
            payload: serde_json::to_vec(&summary)?,
            links,
            meta: None,
        };
        let record_cid = self.store.put_entry(&entry)?;

        match self.pointer_log.resolve(POINTER_ID) {
            Ok(_) => {
                self.pointer_log.update(POINTER_ID, record_cid.clone())?;
            }
            Err(pointer::PointerError::NotFound(_)) => {
                self.pointer_log.create(POINTER_ID, record_cid.clone())?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(record_cid)
    }

    /// [`Self::run_gc`] without the measurement wrapper.
    fn run_gc_inner(
        &self,
        req: &GcRequest,
        collect_details: bool,
    ) -> Result<GcReport, ControlError> {
        // Collection is the exclusive side of the root-publication protocol.
        // This guard deliberately starts before the recovery check and remains
        // alive through every retention/control-log snapshot and the final
        // deletion. Pointer/pin publishers hold the shared side from closure
        // validation through commit, giving exactly two safe serialisations:
        // publication first (this snapshot sees the new root), or GC first
        // (the later publication revalidates and refuses any deleted child).
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|error| error.into_inner());

        if !self.is_recovered()? {
            return Err(ControlError::NotRecovered);
        }

        let max_examined = if req.max_delete == 0 {
            0
        } else {
            DEFAULT_GC_MAX_EXAMINED
        };
        if max_examined > 0 {
            let rows = self.safety_control_row_count()?;
            let limit = u64::try_from(max_examined).unwrap_or(u64::MAX);
            if rows > limit {
                return Err(ControlError::GcControlStateLimit {
                    limit: max_examined,
                    rows,
                });
            }
        }

        let config = GcConfig {
            node_id: Some(req.node_id.clone()),
            system_policy: SystemDataPolicy {
                enabled: req.system_protection,
                protect_node_links: true,
            },
            max_deletions: req.max_delete,
            max_examined,
            max_bytes_examined: if max_examined == 0 {
                0
            } else {
                DEFAULT_GC_MAX_BYTES_EXAMINED
            },
            dry_run: req.dry_run,
            min_chunk_age: Duration::from_secs(req.min_age_secs),
            collect_details,
        };
        let collector = GarbageCollector::new(self.store.clone());

        // Prove both the filesystem ceiling and its exact agreement with the
        // derived chunk index before expanding a single root. This catches an
        // older database restored over newer `data/` even when that database
        // carries a stale true recovery flag.
        let inventory = match collector.prepare_inventory(max_examined, config.max_bytes_examined) {
            Ok(inventory) => inventory,
            Err(error @ dag_core::CoreError::GcIndexMismatch { .. }) => {
                self.recovery_state.begin_full_recovery()?;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        // Root correctness is never optional. `--no-system-protection` may
        // allow deletion of event/audit objects themselves, but it cannot make
        // a target referenced by an unfiled deduplicated event safe to delete.
        let evidence = self.inspect_gc_control_inventory(inventory.cids(), &req.node_id)?;

        // Build pointer and applicable-pin closures in one deduplicated walk.
        // The old retention-cache path expanded every pin independently, so N
        // overlapping pins could spend N times the advertised work ceiling
        // while holding the global mutation barrier.
        let root_budget = if max_examined == 0 {
            self.retention.max_expansion()
        } else {
            self.retention.max_expansion().min(max_examined)
        };
        let root_report = self.gc_root_closure(&req.node_id, root_budget)?;
        let remaining_root_work = root_budget.saturating_sub(root_report.work);
        let mut protected = root_report.cids;
        protected.extend(self.gc_conservative_root_closure(
            evidence.conservative_roots,
            remaining_root_work,
            root_report.coverage,
        )?);
        // These objects are the only immutable witnesses for roots absent
        // from a restored derived table. Once used to correct the root set,
        // they must survive this and subsequent passes even when the operator
        // disables the broader audit-log policy.
        protected.extend(evidence.conservative_objects);

        if req.system_protection {
            // The control plane knows its own event entries exactly. The
            // collector has a heuristic for the same job, kept as a backstop,
            // but a fuzzy CBOR match is not what the append-only history
            // should be resting on.
            protected.extend(self.control_plane_cids()?);
        }

        // A signature is evidence about its target, and it points *at* the
        // content rather than being reachable *from* it — so no pin, pointer
        // or subtree walk above can cover it. While the target is retained
        // its bounded, indexed signature selection is retained with it
        // (transitively: a counter-signature on a kept signature stays too);
        // when the target is collectable they fall together. Overflow records
        // outside the per-target index need their own pin. Without this,
        // signing a pinned release and running routine collection deleted even
        // the indexed signature.
        protected.extend(
            self.signature_log
                .covering_bounded(&protected, root_budget)?,
        );

        #[cfg(test)]
        let pause = { self.gc_test_pause.lock().take() };
        #[cfg(test)]
        if let Some((snapshot_reached, resume)) = pause {
            snapshot_reached.wait();
            resume.wait();
        }

        Ok(collector.collect_prepared(&protected, &config, inventory)?)
    }

    /// Find plausible immutable control records that the database lookup used
    /// by collection does not represent.
    ///
    /// Exact filesystem/index equality alone is insufficient: content-addressed
    /// deduplication means a future event can already exist before an older
    /// database snapshot is taken. Filing that event later changes only redb;
    /// restoring the snapshot then leaves the CID sets equal but the pointer
    /// or pin head stale. Schema-shaped user content is ambiguous, however: a
    /// foreign mid-chain event must not permanently brick GC. Gaps therefore
    /// become conservative roots/objects for this bounded pass and are
    /// reported, never trusted as mutations and never deleted.
    fn inspect_gc_control_inventory(
        &self,
        cids: &[Cid],
        node_id: &str,
    ) -> Result<GcInventoryEvidence> {
        // Preserve positions as well as CIDs. A schema-shaped chunk is useful
        // recovery evidence only when it forms a unique, contiguous history
        // from seq 1 and agrees with every position the database still knows.
        // Treating every decoded `new` as a root let one foreign seq-2 object
        // with an absent target brick every collection forever.
        let pointer_rows = self.pointer_log.event_cids()?;
        let filed_pointer_positions: HashMap<(String, u64), Cid> = pointer_rows
            .iter()
            .map(|(id, seq, cid)| ((id.clone(), *seq), cid.clone()))
            .collect();
        let filed_pointer_cids: HashSet<Cid> =
            pointer_rows.into_iter().map(|(_, _, cid)| cid).collect();

        let pin_rows = self.pin_log.event_cids()?;
        let filed_pin_positions: HashMap<(String, u64), Cid> = pin_rows
            .iter()
            .map(|(id, seq, cid)| ((id.clone(), *seq), cid.clone()))
            .collect();
        let filed_pin_cids: HashSet<Cid> = pin_rows.into_iter().map(|(_, _, cid)| cid).collect();
        let job_events: HashSet<Cid> = self
            .job_log
            .event_cids()?
            .into_iter()
            .map(|(_, _, cid)| cid)
            .collect();

        let inventory: HashSet<Cid> = cids.iter().cloned().collect();
        let mut pointer_candidates: BTreeMap<
            String,
            BTreeMap<u64, Vec<(Cid, dag_core::PointerEvent)>>,
        > = BTreeMap::new();
        let mut pin_candidates: BTreeMap<String, BTreeMap<u64, Vec<(Cid, dag_core::PinEvent)>>> =
            BTreeMap::new();
        let mut evidence = GcInventoryEvidence::default();
        for cid in cids {
            // Classification is advisory and conservative. Leave unreadable
            // objects for the root walk (which can name the affected pin) or
            // the collector's mandatory whole-inventory verification. Both
            // happen before deletion; propagating here would erase the more
            // actionable retention-root diagnostic.
            let Ok(bytes) = self.store.get_chunk(cid) else {
                continue;
            };
            let entry = dag_core::Entry::from_bytes_cbor(&bytes).ok();

            if let Some(entry) = &entry {
                if let Ok(event) = pointer::decode_pointer_event(&entry.payload) {
                    pointer_candidates
                        .entry(event.pointer_id.clone())
                        .or_default()
                        .entry(event.seq)
                        .or_default()
                        .push((cid.clone(), event));
                }

                if let Ok(event) = pin::decode_pin_event(&entry.payload) {
                    pin_candidates
                        .entry(event.pin_id.clone())
                        .or_default()
                        .entry(event.seq)
                        .or_default()
                        .push((cid.clone(), event));
                }

                if let Ok(event) = job::decode_job_event(&entry.payload) {
                    if event
                        .spec()
                        .is_some_and(|spec| dag_core::validate_job_spec(spec).is_ok())
                        && !job_events.contains(cid)
                    {
                        evidence.conservative_objects.insert(cid.clone());
                        evidence.unfiled_records += 1;
                    }
                }
            }
        }

        // Validate pointer candidates in stable ID/sequence order. At an
        // unfiled ambiguous fork, retain every readable candidate target at
        // that position but stop: no later event can prove which predecessor
        // it extends. Missing targets are not roots — there are no bytes for
        // this pass to delete, and recovery could not publish such an event.
        for (pointer_id, positions) in pointer_candidates {
            let mut expected_seq = 1u64;
            let mut previous_target: Option<Cid> = None;
            let mut validated_chain = Vec::new();
            while let Some(candidates) = positions.get(&expected_seq) {
                let filed = filed_pointer_positions.get(&(pointer_id.clone(), expected_seq));
                let valid: Vec<&(Cid, dag_core::PointerEvent)> = candidates
                    .iter()
                    .filter(|(cid, event)| {
                        filed.is_none_or(|known| known == cid)
                            && if expected_seq == 1 {
                                event.prev.is_none()
                            } else {
                                event.prev.as_ref() == previous_target.as_ref()
                            }
                    })
                    .collect();
                if valid.is_empty() {
                    break;
                }

                // A filed position is authoritative and therefore unique. An
                // unfiled fork is ambiguous; protect all complete candidates
                // at this position and do not infer a continuation.
                if valid.len() > 1 {
                    let has_unfiled = valid
                        .iter()
                        .any(|(cid, _)| !filed_pointer_cids.contains(cid));
                    if has_unfiled {
                        evidence
                            .conservative_objects
                            .extend(validated_chain.iter().cloned());
                    }
                    for (cid, event) in valid {
                        if !filed_pointer_cids.contains(cid) {
                            evidence.conservative_objects.insert(cid.clone());
                            if inventory.contains(&event.new) {
                                evidence.conservative_objects.insert(event.new.clone());
                                evidence.conservative_roots.push((
                                    event.new.clone(),
                                    reference::ReferenceDepth::Unlimited,
                                ));
                            }
                            evidence.unfiled_records += 1;
                        }
                    }
                    break;
                }

                let (cid, event) = valid[0];
                validated_chain.push(cid.clone());
                if !filed_pointer_cids.contains(cid) {
                    // A future pass needs the whole predecessor chain to
                    // prove this continuation again. Preserve those filed
                    // witnesses even when broad audit-log retention is off.
                    evidence
                        .conservative_objects
                        .extend(validated_chain.iter().cloned());
                    if inventory.contains(&event.new) {
                        evidence.conservative_objects.insert(event.new.clone());
                        evidence
                            .conservative_roots
                            .push((event.new.clone(), reference::ReferenceDepth::Unlimited));
                    }
                    evidence.unfiled_records += 1;
                }
                previous_target = Some(event.new.clone());
                let Some(next) = expected_seq.checked_add(1) else {
                    break;
                };
                expected_seq = next;
            }
        }

        let now = now_unix();
        for (pin_id, positions) in pin_candidates {
            let mut expected_seq = 1u64;
            let mut previous_event_cid: Option<Cid> = None;
            let mut validated_chain = Vec::new();
            while let Some(candidates) = positions.get(&expected_seq) {
                let filed = filed_pin_positions.get(&(pin_id.clone(), expected_seq));
                let valid: Vec<&(Cid, dag_core::PinEvent)> = candidates
                    .iter()
                    .filter(|(cid, event)| {
                        filed.is_none_or(|known| known == cid)
                            && if expected_seq == 1 {
                                event.prev.is_none()
                            } else {
                                event.prev.as_ref() == previous_event_cid.as_ref()
                            }
                    })
                    .collect();
                if valid.is_empty() {
                    break;
                }

                let retain = |cid: &Cid,
                              event: &dag_core::PinEvent,
                              chain: &[Cid],
                              evidence: &mut GcInventoryEvidence| {
                    if filed_pin_cids.contains(cid) {
                        return;
                    }
                    evidence.conservative_objects.extend(chain.iter().cloned());
                    evidence.conservative_objects.insert(cid.clone());
                    let applies = match &event.scope {
                        PinScope::Global => true,
                        PinScope::Local { node_id: pin_node } => pin_node == node_id,
                    };
                    if applies && event.is_providing_retention(now) {
                        let root = match &event.target {
                            PinTarget::Direct(target) => {
                                (target.clone(), reference::ReferenceDepth::Named)
                            }
                            PinTarget::Subtree { root, max_depth } => (
                                root.clone(),
                                max_depth.map_or(
                                    reference::ReferenceDepth::Unlimited,
                                    reference::ReferenceDepth::Descendants,
                                ),
                            ),
                        };
                        if inventory.contains(&root.0) {
                            evidence.conservative_objects.insert(root.0.clone());
                            evidence.conservative_roots.push(root);
                        }
                    }
                    evidence.unfiled_records += 1;
                };

                if valid.len() > 1 {
                    for (cid, event) in valid {
                        retain(cid, event, &validated_chain, &mut evidence);
                    }
                    break;
                }
                let (cid, event) = valid[0];
                retain(cid, event, &validated_chain, &mut evidence);
                validated_chain.push(cid.clone());
                previous_event_cid = Some(cid.clone());
                let Some(next) = expected_seq.checked_add(1) else {
                    break;
                };
                expected_seq = next;
            }
        }

        if evidence.unfiled_records > 0 {
            tracing::warn!(
                unfiled_records = evidence.unfiled_records,
                "GC conservatively retained schema-valid control evidence absent from derived tables; run `dag recover` offline if these records are expected local history"
            );
        }
        Ok(evidence)
    }

    /// Everything reachable from current pointer heads, applicable active
    /// pins, and immutable manifests for authorized nonterminal work, in one
    /// shared and globally bounded traversal.
    ///
    /// Transitive rather than head-only on purpose: protecting just the entry
    /// a name resolves to would still leave the dataset card's inputs, or a
    /// file manifest's chunks, collectable — which is the same broken promise
    /// one level down.
    ///
    /// The heads are collected first and expanded in a single shared walk
    /// ([`RetentionIndex::expand_roots`]), so pointers resolving into one DAG
    /// cost one traversal between them rather than one each — the closure was
    /// O(pointers x graph) when every pointer re-walked from scratch.
    fn gc_root_closure(
        &self,
        node_id: &str,
        max_expansion: usize,
    ) -> Result<reference::ReferenceValidation, ControlError> {
        let mut roots = Vec::new();
        for pointer_id in self.pointer_log.list_pointers()? {
            // An unreadable head is an unknown retention root. Treating it as
            // absent would make collection fail open and delete whatever the
            // corrupt row used to protect.
            roots.push((
                self.pointer_log.get_head(&pointer_id)?.current_cid,
                reference::ReferenceDepth::Unlimited,
            ));
        }
        let now = now_unix();
        for pin_id in self.pin_log.list()? {
            let head = self.pin_log.head(&pin_id)?;
            if !head.is_providing_retention(now) {
                continue;
            }
            let applies = match &head.event.scope {
                PinScope::Global => true,
                PinScope::Local { node_id: pin_node } => pin_node == node_id,
            };
            if !applies {
                continue;
            }
            roots.push(match &head.event.target {
                PinTarget::Direct(cid) => (cid.clone(), reference::ReferenceDepth::Named),
                PinTarget::Subtree { root, max_depth } => (
                    root.clone(),
                    max_depth.map_or(
                        reference::ReferenceDepth::Unlimited,
                        reference::ReferenceDepth::Descendants,
                    ),
                ),
            });
        }
        let remaining_seed_budget = max_expansion.saturating_sub(roots.len());
        for cid in self
            .job_log
            .active_work_retention_roots(remaining_seed_budget)?
        {
            // Job inputs are executable DAG roots, not merely named chunks.
            // A pending transform must retain the complete file/tree it was
            // authorized against after its source pointer advances.
            roots.push((cid, reference::ReferenceDepth::Unlimited));
        }

        match reference::validate_and_note_references_with_work(
            self.store.as_ref(),
            roots,
            max_expansion,
        ) {
            Ok(reachable) => Ok(reachable),
            Err(reference::ReferenceValidationError::Limit {
                validated,
                max_expansion,
            }) => Err(ControlError::RetentionIncomplete {
                // A shared walk has no single guilty pointer. Name the set
                // honestly and keep the configured remedy explicit.
                pin_id: "GC pointer/pin/active-work roots (shared closure)".to_string(),
                expanded: validated,
                max_expansion,
            }),
            Err(reference::ReferenceValidationError::Unreadable { cid, .. }) => {
                Err(ControlError::RetentionUnreadable {
                    pin_id: "GC pointer/pin/active-work roots (shared closure)".to_string(),
                    cid: cid.to_hex(),
                })
            }
        }
    }

    /// Validate unfiled candidate roots without letting one merely
    /// schema-shaped, incomplete DAG become a permanent availability attack.
    ///
    /// Candidates spend one shared global work budget. An unreadable closure
    /// could never have passed normal pointer or pin publication, so it is
    /// ignored as a root (its event and named root remain protected). If the
    /// shared ceiling is exhausted, stop expanding ambiguous candidates: they
    /// cannot grant retention to unrelated inventory merely by resembling a
    /// control record.
    fn gc_conservative_root_closure(
        &self,
        roots: Vec<(Cid, reference::ReferenceDepth)>,
        max_work: usize,
        mut known_coverage: HashMap<Cid, reference::ReferenceDepth>,
    ) -> Result<HashSet<Cid>, ControlError> {
        if roots.is_empty() {
            return Ok(HashSet::new());
        }

        let mut deepest: HashMap<Cid, reference::ReferenceDepth> = HashMap::new();
        for (cid, depth) in roots {
            deepest
                .entry(cid)
                .and_modify(|current| {
                    if !current.covers(depth) {
                        *current = depth;
                    }
                })
                .or_insert(depth);
        }
        let mut roots: Vec<_> = deepest.into_iter().collect();
        roots.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

        let mut protected = HashSet::new();
        let mut remaining_work = max_work;
        for (cid, depth) in roots {
            if remaining_work == 0 {
                tracing::warn!(
                    "unfiled control-candidate validation exhausted its shared work budget; leaving unproved descendants unprotected"
                );
                break;
            }
            match reference::validate_and_note_references_with_seeded_work(
                self.store.as_ref(),
                [(cid.clone(), depth)],
                remaining_work,
                &known_coverage,
            ) {
                Ok(report) => {
                    remaining_work = remaining_work.saturating_sub(report.work);
                    for (proved_cid, proved_depth) in report.coverage {
                        known_coverage
                            .entry(proved_cid)
                            .and_modify(|current| {
                                if !current.covers(proved_depth) {
                                    *current = proved_depth;
                                }
                            })
                            .or_insert(proved_depth);
                    }
                    protected.extend(report.cids);
                }
                Err(reference::ReferenceValidationError::Unreadable {
                    cid: unreadable,
                    detail,
                    work,
                    ..
                }) => {
                    remaining_work = remaining_work.saturating_sub(work);
                    tracing::warn!(
                        candidate_root = %cid,
                        unreadable = %unreadable,
                        detail,
                        "ignoring an unfiled control candidate whose closure could not pass normal publication validation"
                    );
                }
                Err(reference::ReferenceValidationError::Limit { .. }) => {
                    tracing::warn!(
                        candidate_root = %cid,
                        "unfiled control-candidate validation reached the shared work ceiling; leaving unproved descendants unprotected"
                    );
                    break;
                }
            }
        }
        Ok(protected)
    }

    /// The CIDs of every control-plane event entry, read from the logs that
    /// own them.
    ///
    /// All three append-only logs are covered. Job events are as much
    /// control-plane history as pointer and pin events: `JobLog` stores each
    /// as an entry in the content store, and `JobLog::rebuild_from_store`
    /// recovers job specs from exactly those entries after a lost
    /// `control.redb`. Omitting them let a default `dag gc run` collect them as
    /// ordinary unpinned chunks, leaving that recovery with nothing to read.
    fn control_plane_cids(&self) -> Result<HashSet<Cid>, ControlError> {
        let mut cids = HashSet::new();
        for (_, _, cid) in self.pointer_log.event_cids()? {
            cids.insert(cid);
        }
        for (_, _, cid) in self.pin_log.event_cids()? {
            cids.insert(cid);
        }
        for (_, _, cid) in self.job_log.event_cids()? {
            cids.insert(cid);
        }
        Ok(cids)
    }

    /// Change the ceiling on how many objects one pin's subtree may enumerate.
    ///
    /// Raise this when [`ControlError::RetentionIncomplete`] names a pin whose
    /// coverage is genuinely that large.
    pub fn set_max_subtree_expansion(&self, max_expansion: usize) {
        self.retention.set_max_expansion(max_expansion);
        self.pointer_log.set_max_reference_expansion(max_expansion);
        self.pin_log.set_max_reference_expansion(max_expansion);
    }

    /// Validate every root an atomic cross-log rebuild would publish.
    ///
    /// Sync/finalize callers already own the mutation gate and the FsStore
    /// durability gate, in that order. Keeping the combined walk here gives
    /// pointer and pin roots one shared, configurable work ceiling instead of
    /// permitting each log to spend the ceiling independently. On the current
    /// unconfigured destination identity, Global and
    /// `Local { node_id: "local" }` pins are live roots; other Local scopes
    /// replicate as provenance metadata only.
    #[cfg(test)]
    pub(crate) fn validate_sync_rebuild_roots(
        &self,
        pointers: &pointer::PointerRebuildPlan,
        pins: &pin::PinRebuildPlan,
    ) -> Result<()> {
        let pointer_roots = pointers
            .roots()
            .iter()
            .cloned()
            .map(|cid| (cid, reference::ReferenceDepth::Unlimited));
        let now = now_unix();
        let pin_roots = pins
            .retention_roots()
            .iter()
            .filter(|root| root.is_unexpired(now) && root.applies_to(DEFAULT_NODE_ID))
            .map(|retention| match &retention.target {
                PinTarget::Direct(cid) => (cid.clone(), reference::ReferenceDepth::Named),
                PinTarget::Subtree { root, max_depth } => (
                    root.clone(),
                    max_depth.map_or(
                        reference::ReferenceDepth::Unlimited,
                        reference::ReferenceDepth::Descendants,
                    ),
                ),
            });

        reference::validate_and_note_references(
            self.store.as_ref(),
            pointer_roots.chain(pin_roots),
            self.retention.max_expansion(),
        )
        .map(|_| ())
        .map_err(|error| {
            ControlError::Invalid(format!(
                "refusing to publish replicated pointer/pin roots: {error}"
            ))
        })
    }

    /// Validate the roots newly exposed by one bounded incremental sync
    /// publication. Pointer and applicable pin roots share one work budget;
    /// local pins for another node remain replicated provenance, not roots on
    /// this destination.
    pub(crate) fn validate_incremental_sync_roots(
        &self,
        pointers: &pointer::PointerIncrementalSyncPlan,
        pins: &pin::PinIncrementalSyncPlan,
    ) -> Result<()> {
        let pointer_roots = pointers
            .roots()
            .iter()
            .cloned()
            .map(|cid| (cid, reference::ReferenceDepth::Unlimited));
        let now = now_unix();
        let pin_roots = pins
            .retention_roots()
            .iter()
            .filter(|root| root.is_unexpired(now) && root.applies_to(DEFAULT_NODE_ID))
            .map(|retention| match &retention.target {
                PinTarget::Direct(cid) => (cid.clone(), reference::ReferenceDepth::Named),
                PinTarget::Subtree { root, max_depth } => (
                    root.clone(),
                    max_depth.map_or(
                        reference::ReferenceDepth::Unlimited,
                        reference::ReferenceDepth::Descendants,
                    ),
                ),
            });

        reference::validate_and_note_references(
            self.store.as_ref(),
            pointer_roots.chain(pin_roots),
            self.retention.max_expansion(),
        )
        .map(|_| ())
        .map_err(|error| {
            ControlError::Invalid(format!(
                "refusing to publish replicated pointer/pin roots: {error}"
            ))
        })
    }

    // ---- summary -------------------------------------------------------

    /// Summarise the deployment for dashboards and status output.
    pub fn stats(&self) -> Result<ControlStats> {
        use dag_storage::GcCapableStore;

        // The index knows both numbers and answers in one scan. Walking the
        // filesystem and stat-ing every chunk — what this did — cost 228
        // seconds at 1.1M chunks (scale experiment) against 0.2 for the
        // index, and `/metrics` calls this on every scrape.
        //
        // It is also the *documented* meaning: `chunks` is "tracked in the
        // index". A file the index does not know about is an orphan from an
        // interrupted ingest, awaiting `reindex` or collection — counting it
        // as stored content overstated what the deployment holds.
        let (chunks, bytes) = match self.store.get_index() {
            Some(index) => index.summary()?,
            // No index (a bare store): fall back to the filesystem, which is
            // the only authority left.
            None => {
                let cids = self.store.list_all_cids()?;
                let bytes = cids.iter().try_fold(0u64, |total, cid| {
                    let size = self.store.get_chunk_size(cid)? as u64;
                    total.checked_add(size).ok_or_else(|| {
                        ControlError::Invalid("stored byte count exceeds u64::MAX".into())
                    })
                })?;
                (cids.len(), bytes)
            }
        };

        let now = now_unix();
        let pointers = self.pointer_log.head_count()?;
        let (pins, active_pins) = self.pin_log.head_counts(now)?;

        let (pending_runs, running_runs) = self.job_log.active_run_counts()?;
        let (trigger_queue, trigger_dead_letters) = self.job_log.trigger_queue_depths()?;
        let jobs = usize::try_from(self.job_log.job_count()?)
            .map_err(|_| ControlError::Database("job count does not fit usize".into()))?;

        Ok(ControlStats {
            chunks,
            bytes,
            pointers,
            pins,
            active_pins,
            jobs,
            pending_runs,
            running_runs,
            trigger_queue,
            trigger_dead_letters,
            event_seq: self.event_bus.current_seq(),
            recovered: self.is_recovered()?,
        })
    }
}

/// Current wall-clock time as POSIX epoch seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod recovery_safety_tests {
    use super::*;
    use dag_core::{
        ContentStore, Determinism, Entry, JobId, JobInput, JobPolicy, JobSpec, Link, PinEvent,
        PinScope, PinState, PinTarget, TriggerPolicy,
    };
    use std::sync::{mpsc, Arc, Barrier};
    use std::time::Duration;

    fn mark_recovered(control: &Control) {
        control.recovery_state.mark_complete_for_test().unwrap();
    }

    fn zero_age_gc() -> GcRequest {
        GcRequest {
            node_id: "local".into(),
            dry_run: false,
            max_delete: 0,
            min_age_secs: 0,
            system_protection: true,
        }
    }

    fn node_link(control: &Control, child: Cid) -> Cid {
        control
            .store
            .put_entry(&Entry::new(
                Vec::new(),
                vec![Link {
                    name: Some("child".into()),
                    target: child,
                }],
                None,
            ))
            .unwrap()
    }

    fn enqueue_secondary_input_trigger(control: &Control) -> (JobId, Cid, Cid) {
        let old_child = control.store.put_chunk(b"queued old child", None).unwrap();
        let old_root = node_link(control, old_child.clone());
        let trigger_v1 = control.store.put_chunk(b"trigger v1", None).unwrap();
        control
            .pointer_log
            .create("active-input", old_root.clone())
            .unwrap();
        control
            .pointer_log
            .create("active-trigger", trigger_v1)
            .unwrap();
        let job = JobSpec {
            job_id: JobId::from("active-work-retention"),
            placement: None,
            inputs: JobInput::new().with_pointer("active-input"),
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
        control
            .subscribe_pointer("active-trigger", job.job_id.clone())
            .unwrap();
        let trigger_v2 = control.store.put_chunk(b"trigger v2", None).unwrap();
        control
            .pointer_log
            .update("active-trigger", trigger_v2)
            .unwrap();
        assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (1, 0));
        (job.job_id, old_root, old_child)
    }

    fn missing_pin_offer(control: &Control, pin_id: &str, scope: PinScope) -> (Cid, Cid) {
        let missing = Cid::compute(format!("missing target for {pin_id}").as_bytes());
        let event = PinEvent {
            seq: 1,
            pin_id: pin_id.to_string(),
            target: PinTarget::Subtree {
                root: missing.clone(),
                max_depth: None,
            },
            scope,
            expires_at: None,
            state: PinState::Active,
            ts: now_unix(),
            author: None,
            prev: None,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let event_cid = control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();
        (missing, event_cid)
    }

    #[test]
    fn sync_publication_refuses_a_missing_global_pin_closure() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let (_, event) = missing_pin_offer(&control, "global", PinScope::Global);

        let error = control
            .publish_durable_sync_snapshot(&[], &[("global".to_string(), 1, event)])
            .unwrap_err();
        assert!(error.to_string().contains("unreadable"));
        assert!(matches!(
            control.pin_log.head("global"),
            Err(dag_core::PinError::PinNotFound(_))
        ));
    }

    #[test]
    fn sync_publication_refuses_a_missing_matching_local_pin_closure() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let (_, event) = missing_pin_offer(
            &control,
            "matching-local",
            PinScope::Local {
                node_id: DEFAULT_NODE_ID.to_string(),
            },
        );

        let error = control
            .publish_durable_sync_snapshot(&[], &[("matching-local".to_string(), 1, event)])
            .unwrap_err();
        assert!(error.to_string().contains("unreadable"));
        assert!(matches!(
            control.pin_log.head("matching-local"),
            Err(dag_core::PinError::PinNotFound(_))
        ));
    }

    #[test]
    fn sync_publication_excludes_foreign_local_pin_closures() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let (missing, event) = missing_pin_offer(
            &control,
            "foreign-local",
            PinScope::Local {
                node_id: "other-node".to_string(),
            },
        );

        control
            .publish_durable_sync_snapshot(&[], &[("foreign-local".to_string(), 1, event)])
            .unwrap();
        assert_eq!(
            control.pin_log.head("foreign-local").unwrap().event.target,
            PinTarget::Subtree {
                root: missing,
                max_depth: None,
            }
        );
    }

    #[test]
    fn garbage_collection_refuses_an_unreadable_pointer_head() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let target = control.store.put_chunk(b"must survive", None).unwrap();
        control
            .pointer_log
            .create("release", target.clone())
            .unwrap();
        control.recovery_state.mark_complete_for_test().unwrap();
        control
            .pointer_log
            .overwrite_head_for_test("release", b"not cbor")
            .unwrap();

        let error = control
            .run_gc(&GcRequest {
                node_id: "local".into(),
                dry_run: false,
                max_delete: 0,
                min_age_secs: 0,
                system_protection: true,
            })
            .unwrap_err();
        assert!(matches!(error, ControlError::Pointer(_)));
        assert_eq!(control.store.get_chunk(&target).unwrap(), b"must survive");
    }

    #[test]
    fn garbage_collection_refuses_an_unreadable_pointer_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let child = control.store.put_chunk(b"child", None).unwrap();
        let root = node_link(&control, child.clone());
        control.pointer_log.create("release", root.clone()).unwrap();
        mark_recovered(&control);

        std::fs::write(control.store.chunk_path(&child), b"corrupt bytes").unwrap();
        let error = control.run_gc(&zero_age_gc()).unwrap_err();
        assert!(matches!(
            error,
            ControlError::RetentionUnreadable { ref pin_id, ref cid }
                if pin_id == "GC pointer/pin/active-work roots (shared closure)" && cid == &child.to_hex()
        ));
        assert!(control.store.has_chunk(&root).unwrap());
        assert!(control.store.chunk_path(&child).exists());
    }

    #[test]
    fn gc_retains_full_manifest_closure_for_unadmitted_trigger_intent() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let (job_id, old_root, old_child) = enqueue_secondary_input_trigger(&control);
        let replacement = control.store.put_chunk(b"replacement input", None).unwrap();
        control
            .pointer_log
            .update("active-input", replacement)
            .unwrap();
        mark_recovered(&control);

        control.run_gc(&zero_age_gc()).unwrap();
        assert!(control.store.has_chunk(&old_root).unwrap());
        assert!(control.store.has_chunk(&old_child).unwrap());

        let drained = control.drain_job_trigger_queue(1).unwrap();
        assert_eq!(drained.enqueued, 1);
        let run = control.runs(job_id, 1).unwrap().remove(0);
        assert_eq!(run.manifest.pointer_heads[0].head_cid, old_root);
    }

    #[test]
    fn gc_retains_full_manifest_closure_for_admitted_pending_run() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        let (job_id, old_root, old_child) = enqueue_secondary_input_trigger(&control);
        assert_eq!(control.drain_job_trigger_queue(1).unwrap().enqueued, 1);
        assert_eq!(control.job_log.active_run_counts().unwrap(), (1, 0));
        let replacement = control.store.put_chunk(b"later input", None).unwrap();
        control
            .pointer_log
            .update("active-input", replacement)
            .unwrap();
        mark_recovered(&control);

        control.run_gc(&zero_age_gc()).unwrap();
        assert!(control.store.has_chunk(&old_root).unwrap());
        assert!(control.store.has_chunk(&old_child).unwrap());
        let run = control.runs(job_id, 1).unwrap().remove(0);
        assert!(matches!(run.status, dag_core::RunStatus::Pending));
        assert_eq!(run.manifest.pointer_heads[0].head_cid, old_root);
    }

    #[test]
    fn gc_refuses_before_deletion_when_active_work_root_aggregate_exceeds_budget() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();
        enqueue_secondary_input_trigger(&control);
        for sequence in 3..=10 {
            let next = control
                .store
                .put_chunk(format!("trigger v{sequence}").as_bytes(), None)
                .unwrap();
            control.pointer_log.update("active-trigger", next).unwrap();
        }
        assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (9, 0));

        let otherwise_collectable = control
            .store
            .put_chunk(b"must survive aggregate-root refusal", None)
            .unwrap();
        mark_recovered(&control);
        // Two current pointer roots leave room for only three active-work
        // roots. Every frozen intent needs its revision event plus its input,
        // so the aggregate is refused before the collector can delete.
        control.set_max_subtree_expansion(5);
        let error = control.run_gc(&zero_age_gc()).unwrap_err();
        assert!(matches!(error, ControlError::Capacity(_)), "{error}");
        assert!(control.store.has_chunk(&otherwise_collectable).unwrap());
    }

    #[test]
    fn new_roots_refuse_missing_or_corrupt_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let control = Control::open(dir.path()).unwrap();

        let missing = Cid::compute(b"never stored");
        let missing_root = node_link(&control, missing);
        let pointer_error = control
            .pointer_log
            .create("missing", missing_root)
            .unwrap_err();
        assert!(pointer_error.to_string().contains("unreadable"));
        assert!(matches!(
            control.pointer_log.resolve("missing"),
            Err(pointer::PointerError::NotFound(_))
        ));

        let corrupt = control.store.put_chunk(b"before corruption", None).unwrap();
        let corrupt_root = node_link(&control, corrupt.clone());
        std::fs::write(control.store.chunk_path(&corrupt), b"after corruption").unwrap();
        let pin_error = control
            .pin_log
            .create(
                "corrupt",
                PinTarget::Subtree {
                    root: corrupt_root,
                    max_depth: None,
                },
                PinScope::Global,
                None,
                None,
            )
            .unwrap_err();
        assert!(pin_error.to_string().contains("unreadable"));
        assert!(matches!(
            control.pin_log.head("corrupt"),
            Err(dag_core::PinError::PinNotFound(_))
        ));
    }

    #[test]
    fn pointer_publication_winning_first_is_visible_to_gc() {
        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(dir.path()).unwrap());
        mark_recovered(&control);
        let child = control.store.put_chunk(b"published child", None).unwrap();
        let root = node_link(&control, child.clone());

        let validated = Arc::new(Barrier::new(2));
        let resume_publication = Arc::new(Barrier::new(2));
        control
            .pointer_log
            .pause_next_publication_for_test(validated.clone(), resume_publication.clone());
        let publishing = control.clone();
        let pointer_root = root.clone();
        let (publication_tx, publication_rx) = mpsc::channel();
        let publisher = std::thread::spawn(move || {
            publication_tx
                .send(publishing.pointer_log.create("first", pointer_root))
                .unwrap();
        });
        validated.wait();

        let collecting = control.clone();
        let (gc_tx, gc_rx) = mpsc::channel();
        let collector = std::thread::spawn(move || {
            gc_tx.send(collecting.run_gc(&zero_age_gc())).unwrap();
        });
        assert!(gc_rx.recv_timeout(Duration::from_millis(100)).is_err());

        resume_publication.wait();
        publication_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        let report = gc_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        publisher.join().unwrap();
        collector.join().unwrap();

        assert!(!report.collected.iter().any(|item| item.cid == child));
        assert!(control.store.has_chunk(&root).unwrap());
        assert!(control.store.has_chunk(&child).unwrap());
    }

    #[test]
    fn subtree_pin_publication_winning_first_is_visible_to_gc() {
        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(dir.path()).unwrap());
        mark_recovered(&control);
        let child = control
            .store
            .put_chunk(b"published pinned child", None)
            .unwrap();
        let root = node_link(&control, child.clone());

        let validated = Arc::new(Barrier::new(2));
        let resume_publication = Arc::new(Barrier::new(2));
        control
            .pin_log
            .pause_next_publication_for_test(validated.clone(), resume_publication.clone());
        let publishing = control.clone();
        let pin_root = root.clone();
        let (publication_tx, publication_rx) = mpsc::channel();
        let publisher = std::thread::spawn(move || {
            publication_tx
                .send(publishing.pin_log.create(
                    "first",
                    PinTarget::Subtree {
                        root: pin_root,
                        max_depth: None,
                    },
                    PinScope::Global,
                    None,
                    None,
                ))
                .unwrap();
        });
        validated.wait();

        let collecting = control.clone();
        let (gc_tx, gc_rx) = mpsc::channel();
        let collector = std::thread::spawn(move || {
            gc_tx.send(collecting.run_gc(&zero_age_gc())).unwrap();
        });
        assert!(gc_rx.recv_timeout(Duration::from_millis(100)).is_err());

        resume_publication.wait();
        publication_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        let report = gc_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        publisher.join().unwrap();
        collector.join().unwrap();

        assert!(!report.collected.iter().any(|item| item.cid == child));
        assert!(control.store.has_chunk(&root).unwrap());
        assert!(control.store.has_chunk(&child).unwrap());
    }

    #[test]
    fn gc_winning_first_makes_pointer_publication_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(dir.path()).unwrap());
        mark_recovered(&control);
        let child = control.store.put_chunk(b"old child", None).unwrap();
        // Empty-payload NodeLinks are system-protected, so this pass removes
        // the old descendant while leaving the proposed root readable.
        let root = node_link(&control, child.clone());

        let snapshot_reached = Arc::new(Barrier::new(2));
        let resume_gc = Arc::new(Barrier::new(2));
        *control.gc_test_pause.lock() = Some((snapshot_reached.clone(), resume_gc.clone()));

        let collecting = control.clone();
        let gc_thread = std::thread::spawn(move || collecting.run_gc(&zero_age_gc()));
        snapshot_reached.wait();

        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let publishing = control.clone();
        let pointer_root = root.clone();
        let pointer_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx
                .send(publishing.pointer_log.create("late", pointer_root))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());

        resume_gc.wait();
        let report = gc_thread.join().unwrap().unwrap();
        let publication = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        pointer_thread.join().unwrap();

        assert!(report.collected.iter().any(|item| item.cid == child));
        assert!(control.store.has_chunk(&root).unwrap());
        assert!(!control.store.has_chunk(&child).unwrap());
        assert!(publication.is_err());
        assert!(matches!(
            control.pointer_log.resolve("late"),
            Err(pointer::PointerError::NotFound(_))
        ));
    }

    #[test]
    fn gc_winning_first_makes_subtree_pin_publication_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(dir.path()).unwrap());
        mark_recovered(&control);
        let child = control.store.put_chunk(b"old pinned child", None).unwrap();
        let root = node_link(&control, child.clone());

        let snapshot_reached = Arc::new(Barrier::new(2));
        let resume_gc = Arc::new(Barrier::new(2));
        *control.gc_test_pause.lock() = Some((snapshot_reached.clone(), resume_gc.clone()));

        let collecting = control.clone();
        let gc_thread = std::thread::spawn(move || collecting.run_gc(&zero_age_gc()));
        snapshot_reached.wait();

        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let publishing = control.clone();
        let pin_root = root.clone();
        let pin_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx
                .send(publishing.pin_log.create(
                    "late",
                    PinTarget::Subtree {
                        root: pin_root,
                        max_depth: None,
                    },
                    PinScope::Global,
                    None,
                    None,
                ))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());

        resume_gc.wait();
        let report = gc_thread.join().unwrap().unwrap();
        let publication = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        pin_thread.join().unwrap();

        assert!(report.collected.iter().any(|item| item.cid == child));
        assert!(control.store.has_chunk(&root).unwrap());
        assert!(!control.store.has_chunk(&child).unwrap());
        assert!(publication.is_err());
        assert!(matches!(
            control.pin_log.head("late"),
            Err(dag_core::PinError::PinNotFound(_))
        ));
    }
}
