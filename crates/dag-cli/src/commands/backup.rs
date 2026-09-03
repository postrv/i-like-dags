//! Complete deployment backups.
//!
//! Replication deliberately transfers the content graph and its replicated
//! metadata, not every local control-plane table. A backup has a different
//! contract: it is an exact, offline-restorable snapshot of the whole data
//! directory, including job runs, the trust keyring, subscriptions and the
//! event journal.

use std::fs::{self, File, Metadata};
use std::io::{BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
use rustix::fs::RenameFlags;
#[cfg(unix)]
use rustix::fs::{self as unix_fs, AtFlags, Dir, FileType, Mode, OFlags};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use dag_control::{
    CONTROL_DB_FILE, LEGACY_SLED_PATHS, MIGRATION_COMPLETE_DIR, MIGRATION_STAGE_FILE,
    MIGRATION_STATE_DIR, SCHEMA_VERSION,
};
use redb::{ReadOnlyDatabase, ReadableDatabase, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::output::{terminal_text, Format};

const MANIFEST_FILE: &str = "dag-backup-manifest.json";
const BACKUP_FORMAT: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BACKUP_FILES: usize = 1_000_000;
const MAX_BACKUP_ENTRIES: usize = 1_000_000;
const MAX_MANIFEST_PATH_BYTES: usize = 4096;
const MAX_PERMISSION_MODE: u32 = 0o777;
/// Default aggregate deployment bytes admitted by backup verify/restore (1 TiB).
///
/// Backup media is an external trust boundary. A finite default prevents a
/// small, valid manifest from driving an unlimited hash/copy operation. Zero
/// remains an explicit offline operator opt-out for larger deployments.
pub const DEFAULT_BACKUP_MAX_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const SCHEMA_TABLE: TableDefinition<&str, u32> = TableDefinition::new("schema");
const SCHEMA_VERSION_KEY: &str = "version";
const BASELINE_BYTES_TABLES: &[&str] = &[
    "chunk_index",
    "pointer_heads",
    "pointer_events",
    "pin_heads",
    "pin_events",
    "pin_by_target",
    "job_heads",
    "job_events",
    "job_runs",
    "effect_cache",
    "pointer_subscriptions",
    "event_journal",
    "recovery",
];
const EXPLICIT_SCHEMA_BYTES_TABLES: &[&str] = &["effect_claims", "sig_by_target", "trusted_keys"];
const SCHEMA_5_BYTES_TABLES: &[&str] = &[
    "job_pending_by_adapter",
    "job_trigger_queue",
    "job_trigger_dead_letters",
    "job_run_leases",
    "job_run_quarantine",
];
const SCHEMA_5_BYTES_U64_TABLES: &[&str] = &[
    "chunk_index_meta",
    "job_pending_runs",
    "job_run_queue_meta",
    "job_trigger_receipts",
    "job_legacy_prev_cutoffs",
];

#[derive(Subcommand, Debug)]
pub enum BackupCmd {
    /// Create a complete snapshot while holding the data-directory lock
    ///
    /// The data directory must not contain the reserved backup manifest name.
    Create {
        /// New directory to create; it must not exist and its parent must exist
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify every file against a backup manifest
    Verify {
        /// Backup directory
        #[arg(long)]
        source: PathBuf,
        /// Maximum aggregate deployment bytes to hash (0 = explicit unlimited offline scan)
        #[arg(long, default_value_t = DEFAULT_BACKUP_MAX_BYTES)]
        max_bytes: u64,
    },
    /// Restore into a new data directory
    ///
    /// The destination must not exist. Restoring alongside the old directory
    /// makes rollback explicit and avoids an in-place overwrite of live data;
    /// its parent directory must already exist.
    Restore {
        /// Backup directory
        #[arg(long)]
        source: PathBuf,
        /// Maximum aggregate deployment bytes to verify and copy (0 = explicit unlimited offline restore)
        #[arg(long, default_value_t = DEFAULT_BACKUP_MAX_BYTES)]
        max_bytes: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifest {
    format: u32,
    schema_version: u32,
    created_at_unix: i64,
    root_mode: u32,
    directories: Vec<BackupDirectory>,
    files: Vec<BackupFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupDirectory {
    path: String,
    mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupFile {
    path: String,
    bytes: u64,
    sha256: String,
    mode: u32,
}

#[derive(Debug)]
struct CollectedTree {
    root_mode: u32,
    directories: Vec<CollectedDirectory>,
    files: Vec<CollectedFile>,
}

#[derive(Debug)]
struct CollectedDirectory {
    path: PathBuf,
    mode: u32,
}

#[derive(Debug, Clone)]
struct CollectedFile {
    path: PathBuf,
    stamp: FileStamp,
    mode: u32,
}

/// Metadata which must still identify the same immutable source file when it
/// is opened later. On Unix, ctime makes same-size in-place replacement
/// detectable even when an attacker restores mtime.
#[derive(Debug, Clone, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mtime: i64,
    #[cfg(unix)]
    mtime_nsec: i64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

/// A source directory anchored for the lifetime of a create/verify/restore
/// operation. Unix opens every descendant relative to this descriptor with
/// `O_NOFOLLOW`, so renaming or symlinking a path cannot redirect a read.
struct BackupRoot {
    display: PathBuf,
    #[cfg(unix)]
    directory: File,
}

struct VerifiedBackup {
    manifest: BackupManifest,
    files: Vec<CollectedFile>,
    _database_lock: ReadOnlyDatabase,
}

#[derive(Debug, Serialize)]
struct BackupReport {
    path: String,
    files: usize,
    bytes: u64,
    schema_version: u32,
}

#[derive(Debug)]
struct AggregateByteBudget {
    limit: Option<u64>,
    observed: u64,
}

impl AggregateByteBudget {
    fn new(max_bytes: u64) -> Self {
        Self {
            limit: (max_bytes > 0).then_some(max_bytes),
            observed: 0,
        }
    }

    fn check_declared(&self, declared: u64) -> Result<()> {
        if let Some(limit) = self.limit.filter(|limit| declared > *limit) {
            bail!(
                "backup manifest declares {declared} aggregate deployment bytes; configured maximum is {limit} (pass --max-bytes 0 only for a deliberately unbounded offline operation)"
            );
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.observed = self
            .observed
            .checked_add(bytes as u64)
            .context("backup observed byte count overflow")?;
        if let Some(limit) = self.limit.filter(|limit| self.observed > *limit) {
            bail!(
                "backup contains more than the configured maximum of {limit} aggregate deployment bytes"
            );
        }
        Ok(())
    }
}

/// Create an exact snapshot without upgrading or otherwise opening the source
/// through the mutating control-plane constructors. The read-only redb handle
/// is the lock: no process can write `control.redb` while the snapshot is
/// copied, and immutable store objects make the resulting directory one
/// coherent point.
#[cfg(test)]
pub fn create(source: &Path, out: &Path, fmt: Format) -> Result<()> {
    create_with_lock_hook(source, out, fmt, || {})
}

/// Create while honoring the CLI's global lock-wait policy.
pub fn create_waiting(
    source: &Path,
    out: &Path,
    fmt: Format,
    lock_timeout: std::time::Duration,
) -> Result<()> {
    create_with_lock_timeout_hook(source, out, fmt, lock_timeout, || {})
}

#[cfg(test)]
fn create_with_lock_hook(
    source: &Path,
    out: &Path,
    fmt: Format,
    after_lock: impl FnOnce(),
) -> Result<()> {
    create_with_lock_timeout_hook(source, out, fmt, std::time::Duration::ZERO, after_lock)
}

fn create_with_lock_timeout_hook(
    source: &Path,
    out: &Path,
    fmt: Format,
    lock_timeout: std::time::Duration,
    after_lock: impl FnOnce(),
) -> Result<()> {
    let source_abs = source
        .canonicalize()
        .with_context(|| format!("resolving data directory {}", source.display()))?;
    let source_root = BackupRoot::open(&source_abs)?;
    let out_abs = resolved_target(out)?;
    if out_abs.starts_with(&source_abs) {
        bail!(
            "backup destination {} is inside the data directory; choose a separate directory",
            out.display()
        );
    }
    if path_exists_no_follow(&out_abs)? {
        bail!("backup destination {} already exists", out.display());
    }

    // Validate the pathname without following links, then acquire redb's
    // ownership lock before hashing or enumerating any source state. Comparing
    // the anchored identity after the lock closes the path/open race.
    let database_rel = Path::new(CONTROL_DB_FILE);
    let database_path = source_abs.join(CONTROL_DB_FILE);
    let (database_file, database_stamp, database_mode, database_lock) =
        acquire_source_database_lock(&source_root, &database_path, lock_timeout)?;
    after_lock();

    let preflight_database = CollectedFile {
        path: database_rel.to_path_buf(),
        stamp: database_stamp,
        mode: database_mode,
    };
    let database_before = hash_open_file(database_file, &preflight_database.stamp, database_rel)?;
    let database_schema_version = validate_open_control_database(&database_lock, &database_path)?;
    let database_after_validation = hash_collected(&source_root, &preflight_database)?;
    ensure_same_database(
        &database_before,
        &database_after_validation,
        "read-only source validation",
    )?;

    let mut tree = source_root.collect()?;
    validate_deployment_entries(
        tree.files.iter().map(|entry| entry.path.as_path()),
        tree.directories.iter().map(|entry| entry.path.as_path()),
    )?;
    let database_entry = tree
        .files
        .iter()
        .find(|entry| entry.path == database_rel)
        .cloned()
        .context("validated deployment lost its control database entry")?;
    if database_entry.stamp != preflight_database.stamp
        || database_entry.mode != preflight_database.mode
    {
        bail!("control database changed while enumerating the locked backup source");
    }

    let scratch = scratch_path(&out_abs, "backup")?;
    create_private_directory(&scratch)
        .with_context(|| format!("creating staging directory {}", scratch.display()))?;

    let result = (|| {
        tree.directories.sort_by(|a, b| a.path.cmp(&b.path));
        for directory in &tree.directories {
            validate_relative(&directory.path)?;
            let destination = scratch.join(&directory.path);
            fs::create_dir_all(&destination)
                .with_context(|| format!("creating {}", destination.display()))?;
        }

        // Copy the database last. No writes are occurring, but this ordering
        // also means an interrupted staging directory never looks complete.
        tree.files
            .sort_by_key(|entry| entry.path.file_name().is_some_and(|n| n == "control.redb"));

        let mut manifest_files = Vec::with_capacity(tree.files.len());
        for source_file in &tree.files {
            let rel = &source_file.path;
            validate_relative(rel)?;
            let destination = scratch.join(rel);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let opened = source_root.open_collected(source_file)?;
            let (bytes, sha256) =
                copy_hash_and_sync(opened, &destination, source_file.mode, &source_file.stamp)?;
            manifest_files.push(BackupFile {
                path: portable_path(rel)?,
                bytes,
                sha256,
                mode: source_file.mode,
            });
        }
        manifest_files.sort_by(|a, b| a.path.cmp(&b.path));
        let copied_database = manifest_files
            .iter()
            .find(|entry| entry.path == CONTROL_DB_FILE)
            .context("copied backup lost its control database entry")?;
        let copied_database_hash = (copied_database.bytes, copied_database.sha256.clone());
        ensure_same_database(
            &database_before,
            &copied_database_hash,
            "copying the control database",
        )?;
        let database_after_copy = hash_collected(&source_root, &database_entry)?;
        ensure_same_database(
            &database_before,
            &database_after_copy,
            "copying the source snapshot",
        )?;
        let manifest_directories = tree
            .directories
            .iter()
            .map(|entry| {
                Ok(BackupDirectory {
                    path: portable_path(&entry.path)?,
                    mode: entry.mode,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let manifest = BackupManifest {
            format: BACKUP_FORMAT,
            schema_version: database_schema_version,
            created_at_unix: chrono::Utc::now().timestamp(),
            root_mode: tree.root_mode,
            directories: manifest_directories,
            files: manifest_files,
        };
        write_manifest(&scratch, &manifest)?;
        // Flush directory entries before making their final permissions more
        // restrictive. Each chmod is then flushed through the already-opened
        // directory handle, including mode 000 directories.
        sync_tree_dirs(&scratch)?;
        apply_manifest_directory_modes(&scratch, &manifest)?;
        publish_new(&scratch, &out_abs).with_context(|| {
            format!(
                "publishing completed backup {} as {}",
                scratch.display(),
                out_abs.display()
            )
        })?;
        sync_dir(parent_dir(&out_abs))?;
        Ok::<_, anyhow::Error>(manifest)
    })();

    let manifest = match result {
        Ok(manifest) => manifest,
        Err(error) => {
            // This path was created by this invocation and was never
            // published as a backup. Best effort cleanup cannot destroy user
            // data because scratch_path requires a previously absent target.
            let _ = fs::remove_dir_all(&scratch);
            return Err(error);
        }
    };

    emit_report(out, &manifest, fmt, "backup created")
}

/// Verify while holding the backup database's read-only redb lock.
#[cfg(test)]
pub fn verify(source: &Path, fmt: Format) -> Result<()> {
    verify_bounded(source, fmt, DEFAULT_BACKUP_MAX_BYTES)
}

/// Verify with an explicit aggregate deployment-byte ceiling. Zero is an
/// operator-selected unbounded offline scan.
pub fn verify_bounded(source: &Path, fmt: Format, max_bytes: u64) -> Result<()> {
    let source_root = BackupRoot::open(source)?;
    let verified = verify_manifest_root(&source_root, max_bytes)?;
    emit_report(source, &verified.manifest, fmt, "backup verified")
}

/// Restore to a path that does not exist. This intentionally has no
/// `--force`: swapping a production directory is an operator action, and the
/// old deployment should remain available for rollback.
#[cfg(test)]
pub fn restore(source: &Path, destination: &Path, fmt: Format) -> Result<()> {
    restore_bounded(source, destination, fmt, DEFAULT_BACKUP_MAX_BYTES)
}

/// Restore with an explicit aggregate deployment-byte ceiling. Zero is an
/// operator-selected unbounded offline restore.
pub fn restore_bounded(
    source: &Path,
    destination: &Path,
    fmt: Format,
    max_bytes: u64,
) -> Result<()> {
    restore_with_byte_limits(source, destination, fmt, max_bytes, max_bytes)
}

fn restore_with_byte_limits(
    source: &Path,
    destination: &Path,
    fmt: Format,
    verify_max_bytes: u64,
    copy_max_bytes: u64,
) -> Result<()> {
    let source_abs = source
        .canonicalize()
        .with_context(|| format!("resolving backup {}", source.display()))?;
    let source_root = BackupRoot::open(&source_abs)?;
    let destination_abs = resolved_target(destination)?;
    if destination_abs.starts_with(&source_abs) {
        bail!("restore destination cannot be inside the backup directory");
    }
    if path_exists_no_follow(&destination_abs)? {
        bail!(
            "restore destination {} already exists; restore to a new --data-dir and switch over after verification",
            destination.display()
        );
    }

    let verified = verify_manifest_root(&source_root, verify_max_bytes)?;
    let manifest = &verified.manifest;
    let scratch = scratch_path(&destination_abs, "restore")?;
    create_private_directory(&scratch)
        .with_context(|| format!("creating restore staging directory {}", scratch.display()))?;

    let result = (|| {
        for directory in &manifest.directories {
            let rel = Path::new(&directory.path);
            validate_relative(rel)?;
            let path = scratch.join(rel);
            fs::create_dir_all(&path).with_context(|| format!("creating {}", path.display()))?;
        }

        let mut copied_bytes = AggregateByteBudget::new(copy_max_bytes);
        for (entry, source_file) in manifest.files.iter().zip(&verified.files) {
            let rel = Path::new(&entry.path);
            validate_relative(rel)?;
            let to = scratch.join(rel);
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let opened = source_root.open_collected(source_file)?;
            // Hash the same descriptor that is copied. This both closes the
            // verify/copy gap on mutable backup storage and avoids reopening
            // the staged destination through an attacker-controlled path.
            let (bytes, digest) = copy_hash_and_sync_bounded(
                opened,
                &to,
                entry.mode,
                &source_file.stamp,
                &mut copied_bytes,
            )?;
            if bytes != entry.bytes || digest != entry.sha256 {
                bail!(
                    "backup changed while restoring {}: expected {} bytes sha256 {}, got {} bytes sha256 {}",
                    entry.path,
                    entry.bytes,
                    entry.sha256,
                    bytes,
                    digest
                );
            }
        }
        sync_tree_dirs(&scratch)?;

        let database_manifest = manifest
            .files
            .iter()
            .find(|entry| entry.path == CONTROL_DB_FILE)
            .context("verified backup lost its control database manifest entry")?;
        validate_database_path_unchanged(
            &scratch.join(CONTROL_DB_FILE),
            manifest.schema_version,
            database_manifest.bytes,
            &database_manifest.sha256,
        )?;

        // Apply the authenticated final modes only after read-only database
        // validation has closed every handle, then flush the metadata updates.
        apply_manifest_directory_modes(&scratch, manifest)?;

        publish_new(&scratch, &destination_abs).with_context(|| {
            format!(
                "publishing restored deployment {} as {}",
                scratch.display(),
                destination_abs.display()
            )
        })?;
        sync_dir(parent_dir(&destination_abs))?;
        Ok::<_, anyhow::Error>(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_dir_all(&scratch);
        return Err(error);
    }

    emit_report(destination, manifest, fmt, "backup restored")
}

#[cfg(test)]
fn verify_manifest(source: &Path) -> Result<BackupManifest> {
    let source_root = BackupRoot::open(source)?;
    Ok(verify_manifest_root(&source_root, DEFAULT_BACKUP_MAX_BYTES)?.manifest)
}

fn verify_manifest_root(source: &BackupRoot, max_bytes: u64) -> Result<VerifiedBackup> {
    let database_rel = Path::new(CONTROL_DB_FILE);
    let (_, database_stamp, database_mode) = source.open_regular(database_rel)?;
    let database_path = source.display.join(CONTROL_DB_FILE);
    let database_lock = open_control_database_read_only(&database_path)?;
    let (_, locked_stamp, locked_mode) = source.open_regular(database_rel)?;
    if locked_stamp != database_stamp || locked_mode != database_mode {
        bail!("control database changed while acquiring the read-only backup lock");
    }

    let manifest_rel = Path::new(MANIFEST_FILE);
    let (manifest_file, manifest_stamp, _) = source.open_regular(manifest_rel)?;
    if manifest_stamp.len > MAX_MANIFEST_BYTES {
        bail!(
            "backup manifest is {} bytes; maximum is {}",
            manifest_stamp.len,
            MAX_MANIFEST_BYTES
        );
    }
    let manifest_path = source.display.join(MANIFEST_FILE);
    let encoded = read_bounded(
        &manifest_file,
        MAX_MANIFEST_BYTES,
        &format!("backup manifest {}", manifest_path.display()),
    )?;
    let manifest: BackupManifest = serde_json::from_slice(&encoded)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    ensure_unchanged(&manifest_file, &manifest_stamp, manifest_rel)?;
    if manifest.format != BACKUP_FORMAT {
        bail!(
            "unsupported backup format {} (this build supports {})",
            manifest.format,
            BACKUP_FORMAT
        );
    }
    if manifest.schema_version > SCHEMA_VERSION {
        bail!(
            "backup schema {} is newer than this build supports ({})",
            manifest.schema_version,
            SCHEMA_VERSION
        );
    }
    validate_mode(manifest.root_mode, "backup root")?;
    if manifest.files.len() > MAX_BACKUP_FILES {
        bail!(
            "backup manifest contains {} files; maximum is {}",
            manifest.files.len(),
            MAX_BACKUP_FILES
        );
    }
    let manifest_entries = manifest
        .files
        .len()
        .checked_add(manifest.directories.len())
        .context("backup manifest entry count overflow")?;
    if manifest_entries > MAX_BACKUP_ENTRIES {
        bail!(
            "backup manifest contains {} entries; maximum is {}",
            manifest_entries,
            MAX_BACKUP_ENTRIES
        );
    }

    let mut listed_files = Vec::with_capacity(manifest.files.len());
    let mut total_bytes = 0u64;
    for entry in &manifest.files {
        let rel = Path::new(&entry.path);
        validate_relative(rel)?;
        if rel == manifest_rel {
            bail!("backup manifest cannot list itself as a deployment file");
        }
        validate_mode(entry.mode, &entry.path)?;
        validate_sha256(&entry.sha256, &entry.path)?;
        total_bytes = total_bytes
            .checked_add(entry.bytes)
            .context("backup byte count overflow")?;
        listed_files.push(entry.path.clone());
    }
    let mut observed_bytes = AggregateByteBudget::new(max_bytes);
    observed_bytes.check_declared(total_bytes)?;
    ensure_sorted_unique(&listed_files, "file")?;

    let mut listed_directories = Vec::with_capacity(manifest.directories.len());
    for entry in &manifest.directories {
        let rel = Path::new(&entry.path);
        validate_relative(rel)?;
        validate_mode(entry.mode, &entry.path)?;
        listed_directories.push(entry.path.clone());
    }
    ensure_sorted_unique(&listed_directories, "directory")?;

    validate_deployment_entries(
        manifest.files.iter().map(|entry| Path::new(&entry.path)),
        manifest
            .directories
            .iter()
            .map(|entry| Path::new(&entry.path)),
    )?;

    // The manifest is metadata added by backup creation, not a deployment
    // entry. Reserve exactly one extra entry/file while collecting, then
    // remove it before enforcing the authenticated deployment limits below.
    let mut actual = source.collect_backup_snapshot()?;
    if actual.root_mode != manifest.root_mode {
        bail!(
            "backup root permission mode changed: manifest {:03o}, actual {:03o}",
            manifest.root_mode,
            actual.root_mode
        );
    }
    actual.files.retain(|entry| entry.path != manifest_rel);
    actual.files.sort_by(|a, b| a.path.cmp(&b.path));
    actual.directories.sort_by(|a, b| a.path.cmp(&b.path));

    let actual_files = actual
        .files
        .iter()
        .map(|entry| portable_path(&entry.path))
        .collect::<Result<Vec<_>>>()?;
    if listed_files != actual_files {
        bail!("backup file set does not match its manifest");
    }
    let actual_directories = actual
        .directories
        .iter()
        .map(|entry| portable_path(&entry.path))
        .collect::<Result<Vec<_>>>()?;
    if listed_directories != actual_directories {
        bail!("backup directory set does not match its manifest");
    }

    for (entry, collected) in manifest.files.iter().zip(&actual.files) {
        if entry.mode != collected.mode {
            bail!(
                "backup permission check failed for {}: expected {:03o}, got {:03o}",
                entry.path,
                entry.mode,
                collected.mode
            );
        }
        let file = source.open_collected(collected)?;
        let (bytes, digest) =
            hash_open_file_bounded(file, &collected.stamp, &collected.path, &mut observed_bytes)?;
        if bytes != entry.bytes || digest != entry.sha256 {
            bail!(
                "backup integrity check failed for {}: expected {} bytes sha256 {}, got {} bytes sha256 {}",
                entry.path,
                entry.bytes,
                entry.sha256,
                bytes,
                digest
            );
        }
    }
    for (entry, collected) in manifest.directories.iter().zip(&actual.directories) {
        if entry.mode != collected.mode {
            bail!(
                "backup permission check failed for directory {}: expected {:03o}, got {:03o}",
                entry.path,
                entry.mode,
                collected.mode
            );
        }
    }

    let database_index = manifest
        .files
        .iter()
        .position(|entry| entry.path == CONTROL_DB_FILE)
        .context("backup manifest lost its required control database entry")?;
    let database_manifest = &manifest.files[database_index];
    validate_database_root_unchanged(
        source,
        &actual.files[database_index],
        &database_lock,
        manifest.schema_version,
        database_manifest.bytes,
        &database_manifest.sha256,
    )?;

    Ok(VerifiedBackup {
        manifest,
        files: actual.files,
        _database_lock: database_lock,
    })
}

/// A complete backup is a current redb deployment, not an arbitrary directory
/// that happens to carry a self-consistent manifest. Requiring the database
/// here prevents restore validation from manufacturing an empty one. Active or
/// orphaned migration state is excluded; the permanent completion receipt and
/// `*.sled.bak` provenance directories remain valid alongside `control.redb`.
fn validate_deployment_entries<'a>(
    files: impl Iterator<Item = &'a Path>,
    directories: impl Iterator<Item = &'a Path>,
) -> Result<()> {
    let files = files.collect::<Vec<_>>();
    let directories = directories.collect::<Vec<_>>();
    let database = Path::new(CONTROL_DB_FILE);
    if !files.contains(&database) {
        bail!("complete backup is missing the required regular file {CONTROL_DB_FILE}");
    }

    let manifest = Path::new(MANIFEST_FILE);
    if files.contains(&manifest) || directories.contains(&manifest) {
        bail!(
            "data directory contains reserved backup manifest path {MANIFEST_FILE}; remove or rename it before creating a backup"
        );
    }

    let forbidden_roots = std::iter::once(MIGRATION_STATE_DIR)
        .chain(std::iter::once(MIGRATION_STAGE_FILE))
        .chain(LEGACY_SLED_PATHS);
    for forbidden in forbidden_roots {
        let root = Path::new(forbidden);
        if files
            .iter()
            .chain(&directories)
            .any(|path| *path == root || path.starts_with(root))
        {
            bail!(
                "complete backup contains unsafe migration/legacy artifact {forbidden}; finish or repair the migration before backing up"
            );
        }
    }

    let completed = Path::new(MIGRATION_COMPLETE_DIR);
    if files.contains(&completed) {
        bail!(
            "completed migration receipt {MIGRATION_COMPLETE_DIR} must be a directory, not a file"
        );
    }
    for source in LEGACY_SLED_PATHS {
        let backup = format!("{source}.sled.bak");
        if files.iter().any(|path| *path == Path::new(&backup)) {
            bail!("legacy provenance backup {backup} must be a directory, not a file");
        }
    }
    Ok(())
}

impl BackupRoot {
    fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let descriptor = unix_fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| {
                format!(
                    "opening backup root {} without following links",
                    path.display()
                )
            })?;
            let directory = File::from(descriptor);
            if !directory.metadata()?.is_dir() {
                bail!("{} is not a directory", path.display());
            }
            Ok(Self {
                display: path.to_path_buf(),
                directory,
            })
        }

        #[cfg(not(unix))]
        {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("reading {}", path.display()))?;
            if !metadata.file_type().is_dir() {
                bail!("{} is not a directory", path.display());
            }
            Ok(Self {
                display: path.to_path_buf(),
            })
        }
    }

    fn collect(&self) -> Result<CollectedTree> {
        self.collect_with_limits(MAX_BACKUP_ENTRIES, MAX_BACKUP_FILES)
    }

    fn collect_backup_snapshot(&self) -> Result<CollectedTree> {
        self.collect_backup_snapshot_with_limits(MAX_BACKUP_ENTRIES, MAX_BACKUP_FILES)
    }

    fn collect_backup_snapshot_with_limits(
        &self,
        max_deployment_entries: usize,
        max_deployment_files: usize,
    ) -> Result<CollectedTree> {
        let max_entries = max_deployment_entries
            .checked_add(1)
            .context("backup entry limit overflow")?;
        let max_files = max_deployment_files
            .checked_add(1)
            .context("backup file limit overflow")?;
        self.collect_with_limits(max_entries, max_files)
    }

    #[cfg(test)]
    fn collect_with_entry_limit(&self, max_entries: usize) -> Result<CollectedTree> {
        self.collect_with_limits(max_entries, MAX_BACKUP_FILES)
    }

    #[cfg(unix)]
    fn collect_with_limits(&self, max_entries: usize, max_files: usize) -> Result<CollectedTree> {
        let root_mode = permission_mode(&self.directory.metadata()?);
        let duplicate = rustix::io::dup(&self.directory)
            .context("duplicating backup root directory descriptor")?;
        let mut pending = vec![(File::from(duplicate), PathBuf::new())];
        let mut directories = Vec::new();
        let mut files = Vec::new();
        let mut visited = 0usize;

        while let Some((directory, relative_dir)) = pending.pop() {
            let entries = Dir::read_from(&directory).with_context(|| {
                format!("reading {}", self.display.join(&relative_dir).display())
            })?;
            for entry in entries {
                let entry = entry?;
                let name = OsString::from_vec(entry.file_name().to_bytes().to_vec());
                if name == OsStr::new(".") || name == OsStr::new("..") {
                    continue;
                }
                visited = visited
                    .checked_add(1)
                    .context("backup entry count overflow")?;
                if visited > max_entries {
                    bail!("data directory contains more than {max_entries} entries");
                }
                let relative = relative_dir.join(&name);
                validate_relative(&relative)?;
                let stat = unix_fs::statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                    .with_context(|| {
                        format!("reading type of {}", self.display.join(&relative).display())
                    })?;
                match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Directory => {
                        let child = unix_fs::openat(
                            &directory,
                            &name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .with_context(|| {
                            format!(
                                "opening directory {} without following links",
                                self.display.join(&relative).display()
                            )
                        })?;
                        let child = File::from(child);
                        let metadata = child.metadata()?;
                        if !metadata.is_dir() {
                            bail!(
                                "backup entry changed type while scanning: {}",
                                self.display.join(&relative).display()
                            );
                        }
                        directories.push(CollectedDirectory {
                            path: relative.clone(),
                            mode: permission_mode(&metadata),
                        });
                        pending.push((child, relative));
                    }
                    FileType::RegularFile => {
                        let child = openat_regular(&directory, &name).with_context(|| {
                            format!(
                                "opening file {} without following links",
                                self.display.join(&relative).display()
                            )
                        })?;
                        let metadata = child.metadata()?;
                        if !metadata.is_file() {
                            bail!(
                                "backup entry changed type while scanning: {}",
                                self.display.join(&relative).display()
                            );
                        }
                        if files.len() >= max_files {
                            bail!("data directory contains more than {max_files} files");
                        }
                        files.push(CollectedFile {
                            path: relative,
                            stamp: FileStamp::from_metadata(&metadata),
                            mode: permission_mode(&metadata),
                        });
                    }
                    FileType::Symlink => bail!(
                        "refusing symlink in snapshot: {}",
                        self.display.join(&relative).display()
                    ),
                    _ => bail!(
                        "refusing non-regular file in snapshot: {}",
                        self.display.join(&relative).display()
                    ),
                }
            }
        }
        Ok(CollectedTree {
            root_mode,
            directories,
            files,
        })
    }

    #[cfg(not(unix))]
    fn collect_with_limits(&self, max_entries: usize, max_files: usize) -> Result<CollectedTree> {
        let metadata = fs::symlink_metadata(&self.display)
            .with_context(|| format!("reading {}", self.display.display()))?;
        if !metadata.file_type().is_dir() {
            bail!("{} is not a directory", self.display.display());
        }
        let root_mode = permission_mode(&metadata);
        let mut pending = vec![PathBuf::new()];
        let mut directories = Vec::new();
        let mut files = Vec::new();
        let mut visited = 0usize;
        while let Some(relative_dir) = pending.pop() {
            let path = self.display.join(&relative_dir);
            let entries =
                fs::read_dir(&path).with_context(|| format!("reading {}", path.display()))?;
            for entry in entries {
                let entry = entry?;
                visited = visited
                    .checked_add(1)
                    .context("backup entry count overflow")?;
                if visited > max_entries {
                    bail!("data directory contains more than {max_entries} entries");
                }
                let relative = relative_dir.join(entry.file_name());
                validate_relative(&relative)?;
                let metadata = fs::symlink_metadata(entry.path())?;
                let kind = metadata.file_type();
                if kind.is_symlink() {
                    bail!("refusing symlink in snapshot: {}", entry.path().display());
                } else if kind.is_dir() {
                    directories.push(CollectedDirectory {
                        path: relative.clone(),
                        mode: permission_mode(&metadata),
                    });
                    pending.push(relative);
                } else if kind.is_file() {
                    if files.len() >= max_files {
                        bail!("data directory contains more than {max_files} files");
                    }
                    files.push(CollectedFile {
                        path: relative,
                        stamp: FileStamp::from_metadata(&metadata),
                        mode: permission_mode(&metadata),
                    });
                } else {
                    bail!(
                        "refusing non-regular file in snapshot: {}",
                        entry.path().display()
                    );
                }
            }
        }
        Ok(CollectedTree {
            root_mode,
            directories,
            files,
        })
    }

    fn open_collected(&self, entry: &CollectedFile) -> Result<File> {
        let (file, stamp, mode) = self.open_regular(&entry.path)?;
        if stamp != entry.stamp || mode != entry.mode {
            bail!(
                "backup source changed before it could be read: {}",
                self.display.join(&entry.path).display()
            );
        }
        Ok(file)
    }

    #[cfg(unix)]
    fn open_regular(&self, relative: &Path) -> Result<(File, FileStamp, u32)> {
        validate_relative(relative)?;
        let mut owned_parent = None;
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                unreachable!("validate_relative accepted only normal components")
            };
            let parent = owned_parent.as_ref().unwrap_or(&self.directory);
            if components.peek().is_some() {
                let next = unix_fs::openat(
                    parent,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| {
                    format!(
                        "opening parent of {} without following links",
                        self.display.join(relative).display()
                    )
                })?;
                owned_parent = Some(File::from(next));
            } else {
                let file = openat_regular(parent, name).with_context(|| {
                    format!(
                        "opening {} without following links",
                        self.display.join(relative).display()
                    )
                })?;
                let metadata = file.metadata()?;
                if !metadata.is_file() {
                    bail!("backup entry {} is not a regular file", relative.display());
                }
                let stamp = FileStamp::from_metadata(&metadata);
                let mode = permission_mode(&metadata);
                return Ok((file, stamp, mode));
            }
        }
        unreachable!("validate_relative rejected empty paths")
    }

    #[cfg(not(unix))]
    fn open_regular(&self, relative: &Path) -> Result<(File, FileStamp, u32)> {
        validate_relative(relative)?;
        let mut path = self.display.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                unreachable!("validate_relative accepted only normal components")
            };
            path.push(name);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                bail!("refusing symlink in snapshot: {}", path.display());
            }
        }
        let file = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("backup entry {} is not a regular file", relative.display());
        }
        let stamp = FileStamp::from_metadata(&metadata);
        let mode = permission_mode(&metadata);
        Ok((file, stamp, mode))
    }
}

#[cfg(unix)]
fn openat_regular(parent: &File, name: &OsStr) -> Result<File> {
    let descriptor = unix_fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(File::from(descriptor))
}

impl FileStamp {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
            #[cfg(unix)]
            mtime: metadata.mtime(),
            #[cfg(unix)]
            mtime_nsec: metadata.mtime_nsec(),
            #[cfg(unix)]
            ctime: metadata.ctime(),
            #[cfg(unix)]
            ctime_nsec: metadata.ctime_nsec(),
            #[cfg(not(unix))]
            modified: metadata.modified().ok(),
        }
    }
}

fn ensure_unchanged(file: &File, expected: &FileStamp, path: &Path) -> Result<()> {
    let actual = FileStamp::from_metadata(&file.metadata()?);
    if &actual != expected {
        bail!("backup source changed while reading {}", path.display());
    }
    Ok(())
}

fn hash_open_file(file: File, expected: &FileStamp, path: &Path) -> Result<(u64, String)> {
    let mut budget = AggregateByteBudget::new(0);
    hash_open_file_bounded(file, expected, path, &mut budget)
}

fn hash_open_file_bounded(
    mut file: File,
    expected: &FileStamp,
    path: &Path,
    budget: &mut AggregateByteBudget,
) -> Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading backup file {}", path.display()))?;
        if read == 0 {
            break;
        }
        budget.charge(read)?;
        bytes = bytes
            .checked_add(read as u64)
            .context("backup size overflow")?;
        hash.update(&buffer[..read]);
    }
    ensure_unchanged(&file, expected, path)?;
    Ok((bytes, hex::encode(hash.finalize())))
}

fn hash_collected(root: &BackupRoot, entry: &CollectedFile) -> Result<(u64, String)> {
    let file = root.open_collected(entry)?;
    hash_open_file(file, &entry.stamp, &entry.path)
}

fn hash_regular_path(path: &Path) -> Result<(u64, String)> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading control database {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("control database {} is not a regular file", path.display());
    }
    let file =
        File::open(path).with_context(|| format!("opening control database {}", path.display()))?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        bail!("control database {} is not a regular file", path.display());
    }
    let stamp = FileStamp::from_metadata(&opened_metadata);
    hash_open_file(file, &stamp, path)
}

fn ensure_same_database(
    expected: &(u64, String),
    actual: &(u64, String),
    action: &str,
) -> Result<()> {
    if actual != expected {
        bail!(
            "control database changed while {action}: expected {} bytes sha256 {}, got {} bytes sha256 {}",
            expected.0,
            expected.1,
            actual.0,
            actual.1
        );
    }
    Ok(())
}

fn is_database_locked(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<dag_control::ControlError>(),
            Some(dag_control::ControlError::DatabaseLocked { .. })
        )
    })
}

fn acquire_source_database_lock(
    root: &BackupRoot,
    path: &Path,
    lock_timeout: std::time::Duration,
) -> Result<(File, FileStamp, u32, ReadOnlyDatabase)> {
    let deadline = std::time::Instant::now()
        .checked_add(lock_timeout)
        .context("backup lock timeout is too large")?;
    let mut backoff = std::time::Duration::from_millis(20);
    loop {
        let (file, stamp, mode) = root.open_regular(Path::new(CONTROL_DB_FILE))?;
        match open_control_database_read_only(path) {
            Ok(database) => {
                let (_, locked_stamp, locked_mode) =
                    root.open_regular(Path::new(CONTROL_DB_FILE))?;
                if locked_stamp != stamp || locked_mode != mode {
                    bail!("control database changed while acquiring the read-only backup lock");
                }
                return Ok((file, stamp, mode, database));
            }
            Err(error) if is_database_locked(&error) && std::time::Instant::now() < deadline => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                std::thread::sleep(backoff.min(remaining));
                backoff = (backoff * 2).min(std::time::Duration::from_millis(250));
            }
            Err(error) => return Err(error),
        }
    }
}

fn open_control_database_read_only(path: &Path) -> Result<ReadOnlyDatabase> {
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ReadOnlyDatabase::open(path)
    }))
    .map_err(|_| dag_control::ControlError::ControlDbUnreadable {
        path: path.display().to_string(),
        detail: "the file is shorter than its own header claims".into(),
    })?;
    match opened {
        Ok(database) => Ok(database),
        Err(redb::DatabaseError::DatabaseAlreadyOpen) => {
            Err(dag_control::ControlError::DatabaseLocked {
                path: parent_dir(path).display().to_string(),
            }
            .into())
        }
        Err(error) => Err(dag_control::ControlError::ControlDbUnreadable {
            path: path.display().to_string(),
            detail: error.to_string(),
        })
        .with_context(|| {
            format!(
                "control database {} is not a readable redb database",
                path.display()
            )
        }),
    }
}

fn validate_required_tables<K, V>(
    txn: &redb::ReadTransaction,
    names: &'static [&'static str],
) -> Result<()>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    for &name in names {
        let table = txn
            .open_table(TableDefinition::<K, V>::new(name))
            .with_context(|| format!("opening required control database table {name}"))?;
        table
            .stats()
            .with_context(|| format!("validating required control database table {name}"))?;
    }
    Ok(())
}

fn validate_open_control_database(database: &ReadOnlyDatabase, path: &Path) -> Result<u32> {
    let txn = database
        .begin_read()
        .with_context(|| format!("reading control database {}", path.display()))?;
    let (schema_version, has_explicit_schema) = match txn.open_table(SCHEMA_TABLE) {
        Ok(table) => {
            let version = table
                .get(SCHEMA_VERSION_KEY)
                .context("reading control database schema version")?;
            (
                version
                    .map(|version| version.value())
                    .context("control database schema table is missing its version row")?,
                true,
            )
        }
        Err(redb::TableError::TableDoesNotExist(_)) => (1, false),
        Err(error) => return Err(error).context("opening control database schema table"),
    };
    if schema_version == 0 {
        bail!("control database schema 0 is not supported");
    }
    if schema_version > SCHEMA_VERSION {
        bail!(
            "control database schema {} is newer than this build supports ({})",
            schema_version,
            SCHEMA_VERSION
        );
    }

    validate_required_tables::<&[u8], &[u8]>(&txn, BASELINE_BYTES_TABLES)?;
    if has_explicit_schema {
        validate_required_tables::<&[u8], &[u8]>(&txn, EXPLICIT_SCHEMA_BYTES_TABLES)?;
    }
    if schema_version >= 3 {
        validate_required_tables::<&[u8], u64>(&txn, &["job_run_watermarks"])?;
    }
    if schema_version >= 4 {
        validate_required_tables::<&[u8], &[u8]>(&txn, &["sync_meta"])?;
    }
    if schema_version >= 5 {
        validate_required_tables::<&[u8], &[u8]>(&txn, SCHEMA_5_BYTES_TABLES)?;
        validate_required_tables::<&[u8], u64>(&txn, SCHEMA_5_BYTES_U64_TABLES)?;
        validate_required_tables::<u64, &[u8]>(&txn, &["job_pending_by_order"])?;
        validate_required_tables::<&[u8], u8>(&txn, &["job_running_runs"])?;
    }

    let tables = txn
        .list_tables()
        .context("listing control database tables")?
        .collect::<Vec<_>>();
    for table in tables {
        txn.open_untyped_table(table)
            .context("opening control database table for validation")?
            .stats()
            .context("validating control database table")?;
    }
    let multimap_tables = txn
        .list_multimap_tables()
        .context("listing control database multimap tables")?
        .collect::<Vec<_>>();
    for table in multimap_tables {
        txn.open_untyped_multimap_table(table)
            .context("opening control database multimap table for validation")?
            .stats()
            .context("validating control database multimap table")?;
    }
    Ok(schema_version)
}

fn validate_database_schema(actual: u32, expected: u32) -> Result<()> {
    if actual != expected {
        bail!(
            "backup manifest declares control database schema {expected}, but the database contains schema {actual}"
        );
    }
    Ok(())
}

fn validate_database_root_unchanged(
    root: &BackupRoot,
    entry: &CollectedFile,
    database: &ReadOnlyDatabase,
    expected_schema: u32,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<()> {
    let expected = (expected_bytes, expected_sha256.to_string());
    let before = hash_collected(root, entry)?;
    ensure_same_database(&expected, &before, "checking the backup manifest")?;
    let path = root.display.join(CONTROL_DB_FILE);
    let actual_schema = validate_open_control_database(database, &path)?;
    validate_database_schema(actual_schema, expected_schema)?;
    let after = hash_collected(root, entry)?;
    ensure_same_database(&before, &after, "read-only backup validation")
}

fn validate_database_path_unchanged(
    path: &Path,
    expected_schema: u32,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<()> {
    let expected = (expected_bytes, expected_sha256.to_string());
    let before = hash_regular_path(path)?;
    ensure_same_database(&expected, &before, "checking the staged restore")?;
    let database = open_control_database_read_only(path)?;
    let actual_schema = validate_open_control_database(&database, path)?;
    validate_database_schema(actual_schema, expected_schema)?;
    drop(database);
    let after = hash_regular_path(path)?;
    ensure_same_database(&before, &after, "read-only restore validation")
}

fn copy_hash_and_sync(
    source: File,
    destination: &Path,
    mode: u32,
    expected: &FileStamp,
) -> Result<(u64, String)> {
    let mut budget = AggregateByteBudget::new(0);
    copy_hash_and_sync_bounded(source, destination, mode, expected, &mut budget)
}

fn copy_hash_and_sync_bounded(
    mut source: File,
    destination: &Path,
    mode: u32,
    expected: &FileStamp,
    budget: &mut AggregateByteBudget,
) -> Result<(u64, String)> {
    validate_mode(mode, &destination.display().to_string())?;
    let mut target = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("creating copied file {}", destination.display()))?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .with_context(|| format!("reading source for {}", destination.display()))?;
        if read == 0 {
            break;
        }
        budget.charge(read)?;
        bytes = bytes
            .checked_add(read as u64)
            .context("backup size overflow")?;
        hash.update(&buffer[..read]);
        target
            .write_all(&buffer[..read])
            .with_context(|| format!("writing {}", destination.display()))?;
    }
    ensure_unchanged(&source, expected, destination)?;
    apply_file_mode(&target, mode)?;
    target
        .sync_all()
        .with_context(|| format!("syncing copied file {}", destination.display()))?;
    Ok((bytes, hex::encode(hash.finalize())))
}

fn read_bounded(reader: impl Read, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let read_limit = max_bytes
        .checked_add(1)
        .context("bounded read limit overflow")?;
    let mut encoded = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut encoded)
        .with_context(|| format!("reading {label}"))?;
    if encoded.len() as u64 > max_bytes {
        bail!("{label} exceeds the maximum of {max_bytes} bytes");
    }
    Ok(encoded)
}

fn validate_sha256(digest: &str, path: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid sha256 digest in backup manifest for {path}");
    }
    Ok(())
}

fn validate_mode(mode: u32, path: &str) -> Result<()> {
    if mode > MAX_PERMISSION_MODE {
        bail!(
            "invalid permission mode {:o} in backup manifest for {}",
            mode,
            path
        );
    }
    Ok(())
}

fn ensure_sorted_unique(paths: &[String], kind: &str) -> Result<()> {
    for pair in paths.windows(2) {
        if pair[0] == pair[1] {
            bail!("backup manifest contains duplicate {kind} paths");
        }
        if pair[0] > pair[1] {
            bail!("backup manifest {kind} paths are not in canonical order");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn permission_mode(metadata: &Metadata) -> u32 {
    metadata.permissions().mode() & MAX_PERMISSION_MODE
}

#[cfg(not(unix))]
fn permission_mode(metadata: &Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else if metadata.is_dir() {
        0o700
    } else {
        0o600
    }
}

fn apply_file_mode(file: &File, mode: u32) -> Result<()> {
    validate_mode(mode, "restored file")?;
    #[cfg(unix)]
    let permissions = Permissions::from_mode(mode);
    #[cfg(not(unix))]
    let permissions = {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(mode & 0o222 == 0);
        permissions
    };
    file.set_permissions(permissions)
        .context("applying restored file permissions")
}

fn apply_directory_mode(path: &Path, mode: u32) -> Result<()> {
    validate_mode(mode, &path.display().to_string())?;
    #[cfg(unix)]
    {
        // Open before chmod so even mode 000 can be flushed through this
        // descriptor after the metadata change.
        let directory =
            File::open(path).with_context(|| format!("opening directory {}", path.display()))?;
        directory
            .set_permissions(Permissions::from_mode(mode))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("syncing permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(mode & 0o222 == 0);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

fn apply_manifest_directory_modes(root: &Path, manifest: &BackupManifest) -> Result<()> {
    // Children first so restrictive parent permissions cannot make a child
    // unreachable before its own metadata has been made durable.
    for entry in manifest.directories.iter().rev() {
        apply_directory_mode(&root.join(&entry.path), entry.mode)?;
    }
    apply_directory_mode(root, manifest.root_mode)
}

fn write_manifest(root: &Path, manifest: &BackupManifest) -> Result<()> {
    let path = root.join(MANIFEST_FILE);
    let file = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let mut encoded = serde_json::to_vec_pretty(manifest)
        .with_context(|| format!("encoding {}", path.display()))?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_MANIFEST_BYTES {
        bail!(
            "backup manifest would be {} bytes; maximum is {}",
            encoded.len(),
            MAX_MANIFEST_BYTES
        );
    }
    writer.write_all(&encoded)?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("backup path must be a non-empty relative path");
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_MANIFEST_PATH_BYTES {
        bail!(
            "backup path exceeds {} bytes: {}",
            MAX_MANIFEST_PATH_BYTES,
            path.display()
        );
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("unsafe path in backup manifest: {}", path.display());
        }
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<String> {
    validate_relative(path)?;
    let components = path
        .components()
        .map(|part| match part {
            Component::Normal(name) => name
                .to_str()
                .map(str::to_owned)
                .context("backup paths must be valid UTF-8"),
            _ => unreachable!("validate_relative accepted only normal components"),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(components.join("/"))
}

fn resolved_target(path: &Path) -> Result<PathBuf> {
    let parent = parent_dir(path);
    let parent = parent
        .canonicalize()
        .with_context(|| format!("resolving destination parent {}", parent.display()))?;
    let name = path
        .file_name()
        .context("backup/restore target must name a directory")?;
    Ok(parent.join(name))
}

fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("checking whether {} exists", path.display()))
        }
    }
}

/// Create an unpublished backup/restore tree without exposing its contents
/// through the caller's ambient umask. The manifest-recorded mode is
/// applied only after the tree is complete and durable.
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::DirBuilder::new().create(path)
    }
}

fn scratch_path(target: &Path, purpose: &str) -> Result<PathBuf> {
    let parent = parent_dir(target);
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .context("backup/restore target must have a UTF-8 file name")?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow::anyhow!("generating staging name: {error}"))?;
    let scratch = parent.join(format!(".{name}.{purpose}-{}", hex::encode(random)));
    if path_exists_no_follow(&scratch)? {
        bail!("staging path collision at {}", scratch.display());
    }
    Ok(scratch)
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Publish a completed directory without ever replacing a path that appeared
/// after the initial existence check. Linux and Apple provide an atomic
/// no-replace rename. Windows' rename operation already refuses an existing
/// directory; other Unix targets retain a final no-follow check as the best
/// portable fallback available through `std`.
fn publish_new(staged: &Path, target: &Path) -> Result<()> {
    if parent_dir(staged) != parent_dir(target) {
        bail!("staging and publication paths must have the same parent");
    }

    #[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
    {
        let parent = parent_dir(target)
            .canonicalize()
            .with_context(|| format!("resolving publication parent for {}", target.display()))?;
        let parent = unix_fs::open(
            &parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let staged_name = staged
            .file_name()
            .context("staging path must have a file name")?;
        let target_name = target
            .file_name()
            .context("publication path must have a file name")?;
        unix_fs::renameat_with(
            &parent,
            staged_name,
            &parent,
            target_name,
            RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "linux", target_vendor = "apple")))]
    {
        if path_exists_no_follow(target)? {
            bail!("publication target {} already exists", target.display());
        }
        fs::rename(staged, target)?;
        Ok(())
    }
}

fn sync_tree_dirs(root: &Path) -> Result<()> {
    let mut dirs = vec![root.to_path_buf()];
    let mut index = 0;
    while index < dirs.len() {
        let dir = dirs[index].clone();
        index += 1;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            }
        }
    }
    for dir in dirs.into_iter().rev() {
        sync_dir(&dir)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    // std does not expose a portable directory handle that can be flushed on
    // Windows. Every file is still sync_all'd before publication.
    Ok(())
}

fn emit_report(path: &Path, manifest: &BackupManifest, fmt: Format, action: &str) -> Result<()> {
    let bytes = manifest.files.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .context("backup byte count overflow")
    })?;
    let report = BackupReport {
        path: path.display().to_string(),
        files: manifest.files.len(),
        bytes,
        schema_version: manifest.schema_version,
    };
    fmt.emit(&report, |r| {
        format!(
            "{action}: {} files, {} bytes, schema {}, at {}",
            r.files,
            r.bytes,
            r.schema_version,
            terminal_text(&r.path)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_control::Control;
    use dag_core::ContentStore;

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn create_after_closing(control: Control, out: &Path, format: Format) -> Result<()> {
        let source = control.path().to_path_buf();
        drop(control);
        create(&source, out, format)
    }

    fn tree_fingerprint(path: &Path) -> Vec<(String, String)> {
        let root = BackupRoot::open(path).unwrap();
        let tree = root.collect().unwrap();
        let mut fingerprint = vec![(String::new(), format!("directory:{:03o}", tree.root_mode))];
        for directory in tree.directories {
            fingerprint.push((
                portable_path(&directory.path).unwrap(),
                format!("directory:{:03o}", directory.mode),
            ));
        }
        for file in tree.files {
            let (bytes, digest) = hash_collected(&root, &file).unwrap();
            fingerprint.push((
                portable_path(&file.path).unwrap(),
                format!("file:{:03o}:{bytes}:{digest}", file.mode),
            ));
        }
        fingerprint.sort();
        fingerprint
    }

    #[test]
    fn manifest_paths_cannot_escape() {
        assert!(validate_relative(Path::new("data/aa/chunk")).is_ok());
        assert!(validate_relative(Path::new("../control.redb")).is_err());
        assert!(validate_relative(Path::new("/etc/passwd")).is_err());
        assert!(validate_relative(Path::new(".")).is_err());
    }

    #[test]
    fn bounded_reader_rejects_an_unending_or_growing_manifest() {
        let error = read_bounded(std::io::repeat(b'x'), 16, "test manifest").unwrap_err();
        assert!(
            error.to_string().contains("maximum of 16 bytes"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn directory_enumeration_enforces_its_limit_while_streaming() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("one"), b"1").unwrap();
        fs::write(root.path().join("two"), b"2").unwrap();
        fs::write(root.path().join("three"), b"3").unwrap();

        let anchored = BackupRoot::open(root.path()).unwrap();
        let error = anchored.collect_with_entry_limit(2).unwrap_err();
        assert!(
            error.to_string().contains("more than 2 entries"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn backup_collection_reserves_one_manifest_slot_at_the_exact_limit() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(CONTROL_DB_FILE), b"database").unwrap();
        fs::write(root.path().join("payload"), b"payload").unwrap();
        fs::write(root.path().join(MANIFEST_FILE), b"manifest").unwrap();

        let anchored = BackupRoot::open(root.path()).unwrap();
        let mut tree = anchored.collect_backup_snapshot_with_limits(2, 2).unwrap();
        assert_eq!(tree.files.len(), 3);
        tree.files
            .retain(|entry| entry.path != Path::new(MANIFEST_FILE));
        assert_eq!(
            tree.files.len(),
            2,
            "the deployment is exactly at its limit"
        );
    }

    #[test]
    fn create_holds_the_read_only_database_lock_before_source_enumeration() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        drop(Control::open(&live).unwrap());
        let source_before = tree_fingerprint(&live);
        let format = Format {
            json: false,
            pretty: false,
        };

        create_with_lock_hook(&live, &snapshot, format, || {
            let error = match Control::open(&live) {
                Ok(_) => panic!("a writer opened while backup held its read-only lock"),
                Err(error) => error,
            };
            assert!(
                matches!(error, dag_control::ControlError::DatabaseLocked { .. }),
                "unexpected writer error: {error:#}"
            );
        })
        .unwrap();

        assert_eq!(tree_fingerprint(&live), source_before);
        verify(&snapshot, format).unwrap();
    }

    #[test]
    fn create_waiting_honors_the_global_lock_timeout_without_preopening_mutably() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(control);
        });
        let format = Format {
            json: false,
            pretty: false,
        };

        create_waiting(&live, &snapshot, format, std::time::Duration::from_secs(2)).unwrap();
        release.join().unwrap();
        verify(&snapshot, format).unwrap();
    }

    #[test]
    fn create_rejects_a_missing_authoritative_baseline_table_without_repairing_it() {
        const EVENT_JOURNAL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("event_journal");

        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        drop(Control::open(&live).unwrap());
        let database = redb::Database::open(live.join(CONTROL_DB_FILE)).unwrap();
        let txn = database.begin_write().unwrap();
        assert!(txn.delete_table(EVENT_JOURNAL).unwrap());
        txn.commit().unwrap();
        drop(database);
        let source_before = tree_fingerprint(&live);
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create(&live, &snapshot, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("event_journal"),
            "unexpected error: {error:#}"
        );
        assert_eq!(tree_fingerprint(&live), source_before);
        assert!(!snapshot.exists());
    }

    #[test]
    fn create_rejects_a_missing_schema_required_table_without_upgrading() {
        const SYNC_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sync_meta");

        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        drop(Control::open(&live).unwrap());
        let database = redb::Database::open(live.join(CONTROL_DB_FILE)).unwrap();
        let txn = database.begin_write().unwrap();
        {
            txn.open_table(SCHEMA_TABLE)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, 4)
                .unwrap();
            assert!(txn.delete_table(SYNC_META).unwrap());
        }
        txn.commit().unwrap();
        drop(database);
        let source_before = tree_fingerprint(&live);
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create(&live, &snapshot, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("sync_meta"),
            "unexpected error: {error:#}"
        );
        assert_eq!(tree_fingerprint(&live), source_before);
        assert!(!snapshot.exists());
    }

    #[test]
    fn explicit_old_schema_requires_its_trust_and_evidence_tables() {
        const TRUSTED_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("trusted_keys");

        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        drop(Control::open(&live).unwrap());
        let database = redb::Database::open(live.join(CONTROL_DB_FILE)).unwrap();
        let txn = database.begin_write().unwrap();
        {
            txn.open_table(SCHEMA_TABLE)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, 4)
                .unwrap();
            assert!(txn.delete_table(TRUSTED_KEYS).unwrap());
        }
        txn.commit().unwrap();
        drop(database);
        let source_before = tree_fingerprint(&live);
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create(&live, &snapshot, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("trusted_keys"),
            "unexpected error: {error:#}"
        );
        assert_eq!(tree_fingerprint(&live), source_before);
        assert!(!snapshot.exists());
    }

    #[test]
    fn existing_schema_table_without_version_cannot_bypass_current_requirements() {
        const TRUSTED_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("trusted_keys");

        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        drop(Control::open(&live).unwrap());
        let database = redb::Database::open(live.join(CONTROL_DB_FILE)).unwrap();
        let txn = database.begin_write().unwrap();
        {
            assert!(txn
                .open_table(SCHEMA_TABLE)
                .unwrap()
                .remove(SCHEMA_VERSION_KEY)
                .unwrap()
                .is_some());
            assert!(txn.delete_table(TRUSTED_KEYS).unwrap());
        }
        txn.commit().unwrap();
        drop(database);
        let source_before = tree_fingerprint(&live);
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create(&live, &snapshot, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("missing its version row"),
            "unexpected error: {error:#}"
        );
        assert_eq!(tree_fingerprint(&live), source_before);
        assert!(!snapshot.exists());
    }

    #[test]
    fn complete_snapshot_verifies_and_restores_content() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        let cid = control
            .store
            .put_chunk(b"complete backup round trip", None)
            .unwrap();
        fs::create_dir(live.join("empty-directory")).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        create_after_closing(control, &snapshot, format).unwrap();
        verify(&snapshot, format).unwrap();
        restore(&snapshot, &restored_path, format).unwrap();

        let restored = Control::open(&restored_path).unwrap();
        assert_eq!(
            restored.store.get_chunk(&cid).unwrap(),
            b"complete backup round trip"
        );
        assert!(
            restored_path.join("empty-directory").is_dir(),
            "complete backups must preserve empty deployment directories"
        );
    }

    #[test]
    fn verify_and_restore_refuse_a_declared_aggregate_over_the_ceiling() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        control
            .store
            .put_chunk(b"bounded backup declaration", None)
            .unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();

        let manifest = verify_manifest(&snapshot).unwrap();
        let declared = manifest
            .files
            .iter()
            .try_fold(0u64, |total, entry| total.checked_add(entry.bytes))
            .unwrap();
        assert!(declared > 0);
        let limit = declared - 1;

        let verify_error = verify_bounded(&snapshot, format, limit).unwrap_err();
        assert!(
            format!("{verify_error:#}").contains("manifest declares"),
            "unexpected error: {verify_error:#}"
        );
        let restore_error = restore_bounded(&snapshot, &restored_path, format, limit).unwrap_err();
        assert!(
            format!("{restore_error:#}").contains("manifest declares"),
            "unexpected error: {restore_error:#}"
        );
        assert!(
            !restored_path.exists(),
            "a refused bounded restore must not publish a partial deployment"
        );

        // Zero is deliberate and explicit, not an accidental default.
        verify_bounded(&snapshot, format, 0).unwrap();
    }

    #[test]
    fn observed_copy_overflow_cleans_the_unpublished_restore() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        control
            .store
            .put_chunk(b"bounded backup observation", None)
            .unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();
        let manifest = verify_manifest(&snapshot).unwrap();
        let actual = manifest.files.iter().map(|entry| entry.bytes).sum::<u64>();
        assert!(actual > 0);

        // The production path uses the same limit for both phases. Separate
        // limits here deterministically model backup media growing after the
        // verification pass but before/during the descriptor-bound copy.
        let error =
            restore_with_byte_limits(&snapshot, &restored_path, format, 0, actual - 1).unwrap_err();
        assert!(
            format!("{error:#}").contains("configured maximum"),
            "unexpected error: {error:#}"
        );
        assert!(
            !restored_path.exists(),
            "an observed byte overflow must remove staging and publish nothing"
        );
        let scratch_prefix = format!(
            ".{}.restore-",
            restored_path.file_name().unwrap().to_string_lossy()
        );
        assert!(
            fs::read_dir(root.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&scratch_prefix)),
            "an observed overflow must remove its private restore staging directory"
        );
    }

    #[test]
    fn create_requires_an_existing_source_without_creating_any_path() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("typo-live");
        let snapshot = root.path().join("snapshot");
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create(&missing, &snapshot, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("resolving data directory"),
            "unexpected error: {error:#}"
        );
        assert!(!missing.exists(), "a source typo must not be initialised");
        assert!(
            !snapshot.exists(),
            "a source typo must not publish a backup"
        );
    }

    #[test]
    fn rejected_nested_create_does_not_create_a_parent_inside_the_source() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let control = Control::open(&live).unwrap();
        drop(control);
        let before = tree_fingerprint(&live);
        let snapshot = live.join("would-have-been-created/snapshot");
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create(&live, &snapshot, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("resolving destination parent"),
            "unexpected error: {error:#}"
        );
        assert_eq!(tree_fingerprint(&live), before);
        assert!(!live.join("would-have-been-created").exists());
    }

    #[test]
    fn rejected_nested_restore_does_not_create_a_parent_inside_the_backup() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();
        let before = tree_fingerprint(&snapshot);
        let destination = snapshot.join("would-have-been-created/restored");

        let error = restore(&snapshot, &destination, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("resolving destination parent"),
            "unexpected error: {error:#}"
        );
        assert_eq!(tree_fingerprint(&snapshot), before);
        assert!(!snapshot.join("would-have-been-created").exists());
    }

    #[test]
    fn old_schema_active_rows_survive_backup_and_restore_byte_for_byte() {
        const JOB_RUNS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_runs");
        const PENDING_RUNS: TableDefinition<&[u8], u64> = TableDefinition::new("job_pending_runs");

        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored = root.path().join("restored");
        drop(Control::open(&live).unwrap());

        let job = b"pre-upgrade";
        let mut run_key = Vec::new();
        run_key.extend_from_slice(&(job.len() as u32).to_be_bytes());
        run_key.extend_from_slice(job);
        run_key.extend_from_slice(&1u64.to_be_bytes());
        let active_row = b"opaque pre-v5 active run";
        let database = redb::Database::open(live.join(CONTROL_DB_FILE)).unwrap();
        let txn = database.begin_write().unwrap();
        {
            txn.open_table(SCHEMA_TABLE)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, 4)
                .unwrap();
            txn.open_table(JOB_RUNS)
                .unwrap()
                .insert(run_key.as_slice(), active_row.as_slice())
                .unwrap();
            txn.open_table(PENDING_RUNS)
                .unwrap()
                .insert(run_key.as_slice(), 7)
                .unwrap();
        }
        txn.commit().unwrap();
        drop(database);

        let source_before = tree_fingerprint(&live);
        let database_before = hash_regular_path(&live.join(CONTROL_DB_FILE)).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create(&live, &snapshot, format).unwrap();
        assert_eq!(tree_fingerprint(&live), source_before);

        let manifest = verify_manifest(&snapshot).unwrap();
        assert_eq!(manifest.schema_version, 4);
        assert_eq!(
            hash_regular_path(&snapshot.join(CONTROL_DB_FILE)).unwrap(),
            database_before
        );
        let backup_before_restore = tree_fingerprint(&snapshot);
        restore(&snapshot, &restored, format).unwrap();
        assert_eq!(tree_fingerprint(&snapshot), backup_before_restore);
        assert_eq!(
            hash_regular_path(&restored.join(CONTROL_DB_FILE)).unwrap(),
            database_before
        );

        let database = ReadOnlyDatabase::open(restored.join(CONTROL_DB_FILE)).unwrap();
        let txn = database.begin_read().unwrap();
        assert_eq!(
            txn.open_table(SCHEMA_TABLE)
                .unwrap()
                .get(SCHEMA_VERSION_KEY)
                .unwrap()
                .unwrap()
                .value(),
            4
        );
        assert_eq!(
            txn.open_table(JOB_RUNS)
                .unwrap()
                .get(run_key.as_slice())
                .unwrap()
                .unwrap()
                .value(),
            active_row
        );
        assert_eq!(
            txn.open_table(PENDING_RUNS)
                .unwrap()
                .get(run_key.as_slice())
                .unwrap()
                .unwrap()
                .value(),
            7
        );
    }

    #[test]
    fn create_refuses_a_reserved_source_manifest_before_staging() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        let reserved = live.join(MANIFEST_FILE);
        fs::write(&reserved, b"deployment-owned data").unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create_after_closing(control, &snapshot, format).unwrap_err();
        assert!(
            error.to_string().contains("reserved backup manifest path"),
            "unexpected error: {error:#}"
        );
        assert!(
            !snapshot.exists(),
            "a rejected source must not publish a partial backup"
        );
        assert_eq!(fs::read(&reserved).unwrap(), b"deployment-owned data");
        let staging_entries = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".snapshot.backup-"))
            .collect::<Vec<_>>();
        assert!(
            staging_entries.is_empty(),
            "reserved-name validation must happen before staging: {staging_entries:?}"
        );
    }

    #[test]
    fn create_refuses_a_reserved_source_manifest_directory() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        fs::create_dir(live.join(MANIFEST_FILE)).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create_after_closing(control, &snapshot, format).unwrap_err();
        assert!(
            error.to_string().contains("reserved backup manifest path"),
            "unexpected error: {error:#}"
        );
        assert!(!snapshot.exists());
    }

    #[test]
    fn reserved_source_failure_never_replaces_an_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        fs::write(live.join(MANIFEST_FILE), b"deployment-owned data").unwrap();
        fs::create_dir(&snapshot).unwrap();
        let marker = snapshot.join("keep-me");
        fs::write(&marker, b"existing destination").unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create_after_closing(control, &snapshot, format).unwrap_err();
        assert!(
            error.to_string().contains("already exists"),
            "unexpected error: {error:#}"
        );
        assert_eq!(fs::read(marker).unwrap(), b"existing destination");
    }

    #[test]
    fn manifest_without_control_database_is_not_a_complete_backup() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();

        let mut manifest = verify_manifest(&snapshot).unwrap();
        manifest.files.retain(|entry| entry.path != CONTROL_DB_FILE);
        fs::remove_file(snapshot.join(CONTROL_DB_FILE)).unwrap();
        write_manifest(&snapshot, &manifest).unwrap();

        let error = verify_manifest(&snapshot).unwrap_err();
        assert!(
            format!("{error:#}").contains(CONTROL_DB_FILE),
            "unexpected error: {error:#}"
        );
        assert!(restore(&snapshot, &restored_path, format).is_err());
        assert!(!restored_path.exists());
    }

    #[test]
    fn restore_does_not_initialize_an_unreadable_control_database() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();

        let mut manifest = verify_manifest(&snapshot).unwrap();
        let database = snapshot.join(CONTROL_DB_FILE);
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&database)
            .unwrap()
            .sync_all()
            .unwrap();
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == CONTROL_DB_FILE)
            .unwrap();
        entry.bytes = 0;
        entry.sha256 = hex::encode(Sha256::digest([]));
        write_manifest(&snapshot, &manifest).unwrap();

        let verify_error = verify(&snapshot, format).unwrap_err();
        assert!(
            format!("{verify_error:#}").contains("not a readable redb database"),
            "unexpected error: {verify_error:#}"
        );

        let error = restore(&snapshot, &restored_path, format).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a readable redb database"),
            "unexpected error: {error:#}"
        );
        assert!(!restored_path.exists());
    }

    #[test]
    fn completed_migration_provenance_is_preserved_by_backup() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        fs::create_dir(live.join(MIGRATION_COMPLETE_DIR)).unwrap();
        fs::create_dir(live.join("pointer.db.sled.bak")).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        create_after_closing(control, &snapshot, format).unwrap();
        verify(&snapshot, format).unwrap();
        restore(&snapshot, &restored_path, format).unwrap();

        assert!(restored_path.join(MIGRATION_COMPLETE_DIR).is_dir());
        assert!(restored_path.join("pointer.db.sled.bak").is_dir());
        drop(Control::open(&restored_path).unwrap());
    }

    #[test]
    fn create_refuses_orphaned_active_migration_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        fs::write(live.join(MIGRATION_STAGE_FILE), b"orphaned stage").unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        let error = create_after_closing(control, &snapshot, format).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsafe migration/legacy artifact"),
            "unexpected error: {error:#}"
        );
        assert!(!snapshot.exists());
    }

    #[test]
    fn verify_and_restore_reject_a_manifested_migration_stage() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();

        let mut manifest = verify_manifest(&snapshot).unwrap();
        let stage = snapshot.join(MIGRATION_STAGE_FILE);
        fs::write(&stage, b"apparently complete stage").unwrap();
        let metadata = fs::metadata(&stage).unwrap();
        manifest.files.push(BackupFile {
            path: MIGRATION_STAGE_FILE.to_string(),
            bytes: metadata.len(),
            sha256: hex::encode(Sha256::digest(b"apparently complete stage")),
            mode: permission_mode(&metadata),
        });
        manifest.files.sort_by(|a, b| a.path.cmp(&b.path));
        write_manifest(&snapshot, &manifest).unwrap();

        let error = verify(&snapshot, format).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsafe migration/legacy artifact"),
            "unexpected error: {error:#}"
        );
        assert!(restore(&snapshot, &restored_path, format).is_err());
        assert!(!restored_path.exists());
    }

    #[test]
    fn verification_rejects_a_modified_snapshot_file() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        control.store.put_chunk(b"tamper target", None).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();
        let manifest = verify_manifest(&snapshot).unwrap();
        let target = manifest
            .files
            .iter()
            .find(|entry| entry.path != "control.redb")
            .expect("snapshot includes a content file");
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(snapshot.join(&target.path))
            .unwrap();
        file.write_all(b"tampered").unwrap();
        file.sync_all().unwrap();

        assert!(verify_manifest(&snapshot).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn source_file_replacement_is_rejected_after_collection() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("value"), b"original").unwrap();

        let anchored = BackupRoot::open(&source).unwrap();
        let tree = anchored.collect().unwrap();
        let collected = tree
            .files
            .iter()
            .find(|entry| entry.path == Path::new("value"))
            .unwrap();

        fs::rename(source.join("value"), source.join("old-value")).unwrap();
        fs::write(source.join("value"), b"replacement").unwrap();
        let error = anchored.open_collected(collected).unwrap_err();
        assert!(
            error.to_string().contains("changed before"),
            "unexpected error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nested_directory_symlink_replacement_cannot_redirect_an_anchored_read() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let outside = root.path().join("outside");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(source.join("nested/value"), b"expected").unwrap();
        fs::write(outside.join("value"), b"secret outside the backup").unwrap();

        let anchored = BackupRoot::open(&source).unwrap();
        let tree = anchored.collect().unwrap();
        let collected = tree
            .files
            .iter()
            .find(|entry| entry.path == Path::new("nested/value"))
            .unwrap();

        fs::rename(source.join("nested"), source.join("old-nested")).unwrap();
        symlink(&outside, source.join("nested")).unwrap();
        let error = anchored.open_collected(collected).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("without following links"),
            "unexpected error: {rendered}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_preserves_authenticated_file_and_directory_modes() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let restored_path = root.path().join("restored");
        let control = Control::open(&live).unwrap();
        let keys = live.join("keys");
        fs::create_dir(&keys).unwrap();
        let secret = keys.join("signing-key.json");
        fs::write(&secret, b"secret").unwrap();
        fs::set_permissions(&live, Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&keys, Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&secret, Permissions::from_mode(0o600)).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };

        create_after_closing(control, &snapshot, format).unwrap();
        restore(&snapshot, &restored_path, format).unwrap();

        assert_eq!(
            fs::metadata(&restored_path).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(restored_path.join("keys"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(restored_path.join("keys/signing-key.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn verification_rejects_duplicate_manifest_paths_before_copying() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        control.store.put_chunk(b"duplicate target", None).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();
        let mut manifest = verify_manifest(&snapshot).unwrap();
        manifest.files.push(manifest.files[0].clone());
        manifest.files.sort_by(|a, b| a.path.cmp(&b.path));
        write_manifest(&snapshot, &manifest).unwrap();

        let error = verify_manifest(&snapshot).unwrap_err();
        assert!(
            error.to_string().contains("duplicate file paths"),
            "unexpected error: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verification_authenticates_permission_modes() {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("live");
        let snapshot = root.path().join("snapshot");
        let control = Control::open(&live).unwrap();
        let secret = live.join("secret");
        fs::write(&secret, b"not world readable").unwrap();
        fs::set_permissions(&secret, Permissions::from_mode(0o600)).unwrap();
        let format = Format {
            json: false,
            pretty: false,
        };
        create_after_closing(control, &snapshot, format).unwrap();

        let mut manifest = verify_manifest(&snapshot).unwrap();
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "secret")
            .unwrap();
        entry.mode = 0o644;
        write_manifest(&snapshot, &manifest).unwrap();

        let error = verify_manifest(&snapshot).unwrap_err();
        assert!(
            error.to_string().contains("permission check failed"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn publication_never_replaces_a_destination_that_appeared() {
        let root = tempfile::tempdir().unwrap();
        let staged = root.path().join(".snapshot.staged");
        let target = root.path().join("snapshot");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("completed"), b"complete snapshot").unwrap();
        fs::create_dir(&target).unwrap();

        assert!(publish_new(&staged, &target).is_err());
        assert!(target.is_dir(), "the concurrent destination must survive");
        assert!(
            staged.join("completed").is_file(),
            "the staged backup must not be silently discarded"
        );
    }
}
