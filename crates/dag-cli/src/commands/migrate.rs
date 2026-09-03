//! `dag migrate` — crash-resumable conversion of a sled data directory.
//!
//! Migration is an offline, explicitly journaled state machine. The old sled
//! directories remain authoritative while a private redb file is copied and
//! put through the normal schema/recovery machinery. Only that fully rebuilt
//! file is atomically published as `control.redb`. The sled directories are
//! then retired one at a time to `*.sled.bak`; a durable marker after every
//! rename makes that phase idempotently resumable.
//!
//! The active marker is finally renamed to a permanent completion receipt.
//! `Control::open` refuses both an active marker and an unmarked mixed
//! sled/redb layout, so an interrupted migration cannot be mistaken for a
//! complete deployment.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dag_control::{
    Control, CONTROL_DB_FILE, LEGACY_SLED_PATHS, MIGRATION_COMPLETE_DIR, MIGRATION_STAGE_FILE,
    MIGRATION_STATE_DIR,
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
use rustix::fs::{self as unix_fs, Mode, OFlags, RenameFlags};

use crate::output::{terminal_text, Format};

const MIGRATION_PROTOCOL: u32 = 1;
const PLAN_FILE: &str = "plan.json";
const VALIDATED_FILE: &str = "validated.json";
const PUBLISHED_FILE: &str = "published";
const COMPLETE_FILE: &str = "complete";
const MAX_STATE_FILE_BYTES: u64 = 1024 * 1024;

/// (sled db dir, sled tree name, redb table name)
///
/// Tree names are sled's internal identifiers; table names are the redb ones
/// the control plane declares. Missing trees are treated as empty without
/// calling `open_tree`, because that sled API creates a tree as a side effect.
const COPY_PLAN: &[(&str, &str, &str)] = &[
    ("pointer.db", "events", "pointer_events"),
    ("pointer.db", "heads", "pointer_heads"),
    ("pin.db", "pin_events", "pin_events"),
    ("pin.db", "pin_heads", "pin_heads"),
    ("pin.db", "pin_by_target", "pin_by_target"),
    ("job.db", "job_events", "job_events"),
    ("job.db", "job_heads", "job_heads"),
    ("job.db", "job_runs", "job_runs"),
    ("job.db", "effect_cache", "effect_cache"),
    ("job.db", "pointer_subscriptions", "pointer_subscriptions"),
    ("events.db", "event_journal", "event_journal"),
];

/// Legacy derived state that is deliberately rebuilt instead of copied.
///
/// Both sled-era implementations used their database's default tree. Keep
/// this list source-specific: a nonempty default tree anywhere else remains
/// unknown input and must fail closed.
const REBUILT_DERIVED_TREES: &[(&str, &str)] = &[
    ("index", "__sled__default"),
    ("recovery.db", "__sled__default"),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MigrationPlan {
    protocol: u32,
    sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CopiedTable {
    source: String,
    tree: String,
    table: String,
    rows: u64,
    sha256: String,
    key_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceSnapshot {
    source: String,
    trees: Vec<TreeSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TreeSnapshot {
    name_hex: String,
    rows: u64,
    sha256: String,
}

impl CopiedTable {
    fn label(&self) -> String {
        format!("{}/{} -> {}", self.source, self.tree, self.table)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RebuildSummary {
    chunks_reindexed: usize,
    pointers_rebuilt: u32,
    pin_heads_rebuilt: u32,
    job_heads_rebuilt: u32,
    recovered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ValidationReceipt {
    protocol: u32,
    copied: Vec<CopiedTable>,
    sources: Vec<SourceSnapshot>,
    rebuilt: RebuildSummary,
}

struct LegacySource {
    db: sled::Db,
    trees: BTreeSet<Vec<u8>>,
}

type LegacySources = BTreeMap<String, LegacySource>;

/// Run the migration. With `dry_run`, preflight and report without writing.
pub fn handle(data_dir: &Path, dry_run: bool, fmt: Format) -> Result<()> {
    let mut no_fail = |_point: &str| Ok(());
    handle_with_failpoints(data_dir, dry_run, fmt, &mut no_fail)
}

fn handle_with_failpoints(
    data_dir: &Path,
    dry_run: bool,
    fmt: Format,
    failpoint: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    require_real_directory(data_dir, "data directory")?;

    let marker = data_dir.join(MIGRATION_STATE_DIR);
    let marker_meta = metadata_no_follow(&marker)?;
    let (plan, mut source_locks, resumed) = match marker_meta {
        Some(metadata) => {
            require_directory_metadata(&marker, &metadata, "migration marker")?;
            require_private_directory(&marker, &metadata)?;
            if dry_run {
                bail!(
                    "{} records an interrupted migration; rerun without --dry-run to resume it",
                    marker.display()
                );
            }
            cleanup_incomplete_phase_writes(&marker)?;
            require_absent(
                &data_dir.join(MIGRATION_COMPLETE_DIR),
                "completed migration receipt",
            )?;

            let plan_path = marker.join(PLAN_FILE);
            if metadata_no_follow(&plan_path)?.is_some() {
                let plan: MigrationPlan = read_json_file(&plan_path, "migration plan")?;
                validate_plan(&plan)?;
                validate_marker_entries(&marker, &plan)?;
                (plan, None, true)
            } else {
                // The only legitimate empty-marker state is a crash after the
                // marker directory was synced but before plan.json was filed.
                if fs::read_dir(&marker)
                    .with_context(|| format!("reading {}", marker.display()))?
                    .next()
                    .is_some()
                {
                    bail!(
                        "migration marker {} has no {} but is not empty",
                        marker.display(),
                        PLAN_FILE
                    );
                }
                let plan = preflight_fresh(data_dir, true)?;
                let locks = open_sources(data_dir, &plan.sources)?;
                write_json_new(&plan_path, &plan, "migration plan")?;
                sync_dir(&marker)?;
                (plan, Some(locks), true)
            }
        }
        None => {
            let plan = preflight_fresh(data_dir, false)?;
            let locks = open_sources(data_dir, &plan.sources)?;
            if dry_run {
                let copied = survey_copy_plan(&locks)?;
                return report(fmt, data_dir, &copied, None, true, false);
            }
            create_private_directory(&marker)?;
            sync_dir(data_dir)?;
            write_json_new(&marker.join(PLAN_FILE), &plan, "migration plan")?;
            sync_dir(&marker)?;
            (plan, Some(locks), false)
        }
    };

    validate_plan_filesystem(data_dir, &plan)?;
    if source_locks.is_none() {
        // Acquire every still-live sled database before reading or advancing
        // any migration phase. This is the offline gate on resume, including
        // the post-publication retirement window.
        source_locks = Some(open_planned_locations(data_dir, &plan)?);
    }
    let stage_path = data_dir.join(MIGRATION_STAGE_FILE);
    let final_path = data_dir.join(CONTROL_DB_FILE);
    let validated_path = marker.join(VALIDATED_FILE);

    let receipt = if metadata_no_follow(&validated_path)?.is_some() {
        let receipt: ValidationReceipt =
            read_json_file(&validated_path, "migration validation receipt")?;
        validate_receipt(&receipt, &plan)?;
        receipt
    } else {
        ensure_prepublication_layout(data_dir, &plan)?;
        if let Some(metadata) = metadata_no_follow(&stage_path)? {
            require_regular_metadata(&stage_path, &metadata, "migration staging file")?;
            require_private_file(&stage_path, &metadata)?;
            fs::remove_file(&stage_path)
                .with_context(|| format!("removing incomplete stage {}", stage_path.display()))?;
            sync_dir(data_dir)?;
        }
        let locks = match source_locks.take() {
            Some(locks) => locks,
            None => open_sources(data_dir, &plan.sources)?,
        };
        let copied = copy_to_stage(data_dir, &stage_path, &locks, failpoint)?;
        let sources = snapshot_sources(&locks, &plan.sources)?;
        let rebuilt = validate_and_rebuild(data_dir, &stage_path)?;
        let receipt = ValidationReceipt {
            protocol: MIGRATION_PROTOCOL,
            copied,
            sources,
            rebuilt,
        };
        validate_rebuilt_copy(&stage_path, &receipt)?;
        write_json_new(&validated_path, &receipt, "migration validation receipt")?;
        sync_dir(&marker)?;
        failpoint("validated")?;
        source_locks = Some(locks);
        receipt
    };

    verify_sources_unchanged(
        source_locks
            .as_ref()
            .context("migration lost its offline sled locks")?,
        &receipt,
    )?;

    let published_marker = marker.join(PUBLISHED_FILE);
    let stage_meta = metadata_no_follow(&stage_path)?;
    let final_meta = metadata_no_follow(&final_path)?;
    match (stage_meta, final_meta) {
        (Some(stage), None) => {
            require_regular_metadata(&stage_path, &stage, "migration staging file")?;
            require_private_file(&stage_path, &stage)?;
            ensure_no_retirement_started(data_dir, &plan)?;
            if metadata_no_follow(&published_marker)?.is_some() {
                bail!(
                    "{} records publication but only the staged database exists",
                    published_marker.display()
                );
            }

            // A resumed validated stage is opened and rebuilt once more. The
            // receipt is durable only after the stage file was synced, but
            // this also catches storage damage between process lifetimes.
            if resumed {
                let rebuilt = validate_and_rebuild(data_dir, &stage_path)?;
                if rebuilt != receipt.rebuilt {
                    bail!(
                        "revalidating {} produced a different rebuild result than {}",
                        stage_path.display(),
                        validated_path.display()
                    );
                }
                validate_rebuilt_copy(&stage_path, &receipt)?;
            }
            publish_noreplace(&stage_path, &final_path)?;
            sync_dir(data_dir)?;
            failpoint("publish")?;
            write_phase_new(&published_marker, "v1\n", "published phase")?;
            sync_dir(&marker)?;
        }
        (None, Some(final_file)) => {
            require_regular_metadata(&final_path, &final_file, "published control database")?;
            require_private_file(&final_path, &final_file)?;
            if metadata_no_follow(&published_marker)?.is_none() {
                // Atomic publication happened, then the process died before
                // its phase file. Validate the exact published inode before
                // advancing the journal.
                let rebuilt = validate_and_rebuild(data_dir, &final_path)?;
                if rebuilt != receipt.rebuilt {
                    bail!(
                        "published database rebuild result differs from the durable validation receipt"
                    );
                }
                validate_rebuilt_copy(&final_path, &receipt)?;
                write_phase_new(&published_marker, "v1\n", "published phase")?;
                sync_dir(&marker)?;
            } else {
                read_expected_phase(&published_marker, "v1\n", "published phase")?;
            }
        }
        (Some(_), Some(_)) => bail!(
            "both {} and {} exist; refusing to choose or overwrite either",
            stage_path.display(),
            final_path.display()
        ),
        (None, None) => bail!(
            "migration receipt {} exists but neither staged nor published database is present",
            validated_path.display()
        ),
    }

    validate_rebuilt_copy(&final_path, &receipt)?;

    // Holding the redb lock keeps another current migration process out while
    // sled directories are retired. It also validates the final path (not
    // merely the pre-rename pathname) before any original moves.
    let published_control = Control::open_migration_database(data_dir, &final_path)
        .context("opening the published migration database")?;
    let final_rebuild = rebuild_open_control(&published_control)?;
    if final_rebuild != receipt.rebuilt {
        bail!("published database changed after validation; legacy sources were left intact");
    }

    if source_locks.is_none() {
        source_locks = Some(open_planned_locations(data_dir, &plan)?);
    }
    retire_sources(
        data_dir,
        &marker,
        &plan,
        &receipt,
        source_locks.take().unwrap_or_default(),
        failpoint,
    )?;

    // Recheck the complete source set after the potentially long copy and
    // rebuild. A newly appeared legacy path must leave the active marker in
    // place rather than produce a supposedly complete mixed layout.
    validate_plan_filesystem(data_dir, &plan)?;

    let complete_marker = marker.join(COMPLETE_FILE);
    if metadata_no_follow(&complete_marker)?.is_some() {
        read_expected_phase(&complete_marker, "v1\n", "complete phase")?;
    } else {
        write_phase_new(&complete_marker, "v1\n", "complete phase")?;
        sync_dir(&marker)?;
    }

    drop(published_control);
    let completed = data_dir.join(MIGRATION_COMPLETE_DIR);
    publish_noreplace(&marker, &completed)?;
    sync_dir(data_dir)?;

    // Exercise the ordinary (non-migration) open path after the active marker
    // is gone and all live sled paths have moved to their provenance backups.
    drop(Control::open(data_dir).context("opening the completed migration")?);

    report(
        fmt,
        data_dir,
        &receipt.copied,
        Some(receipt.rebuilt),
        false,
        resumed,
    )
}

fn preflight_fresh(data_dir: &Path, marker_already_exists: bool) -> Result<MigrationPlan> {
    require_absent(&data_dir.join(CONTROL_DB_FILE), "control database")?;
    require_absent(
        &data_dir.join(MIGRATION_STAGE_FILE),
        "migration staging file",
    )?;
    require_absent(
        &data_dir.join(MIGRATION_COMPLETE_DIR),
        "completed migration receipt",
    )?;
    if !marker_already_exists {
        require_absent(
            &data_dir.join(MIGRATION_STATE_DIR),
            "active migration marker",
        )?;
    }

    let mut sources = Vec::new();
    let mut missing = Vec::new();
    for name in LEGACY_SLED_PATHS {
        let source = data_dir.join(name);
        if let Some(metadata) = metadata_no_follow(&source)? {
            require_directory_metadata(&source, &metadata, "legacy sled source")?;
            validate_sled_layout(&source, "legacy sled source")?;
            sources.push(name.to_string());
        } else {
            missing.push(name);
        }

        // Check every possible destination, not only destinations associated
        // with a source found above. A stale backup makes provenance
        // ambiguous and is never silently replaced or merged.
        require_absent(&backup_path(data_dir, name), "legacy backup destination")?;
    }
    if !missing.is_empty() {
        bail!(
            "{} is not a complete pre-redb data directory; missing legacy source(s): {}",
            data_dir.display(),
            missing.join(", ")
        );
    }
    Ok(MigrationPlan {
        protocol: MIGRATION_PROTOCOL,
        sources,
    })
}

fn validate_plan(plan: &MigrationPlan) -> Result<()> {
    if plan.protocol != MIGRATION_PROTOCOL {
        bail!(
            "migration marker protocol {} is unsupported (expected {})",
            plan.protocol,
            MIGRATION_PROTOCOL
        );
    }
    if plan.sources.is_empty() {
        bail!("migration plan has no legacy sources");
    }
    let mut previous = None;
    for source in &plan.sources {
        let index = LEGACY_SLED_PATHS
            .iter()
            .position(|known| *known == source.as_str())
            .with_context(|| format!("migration plan names unknown source {source}"))?;
        if previous.is_some_and(|prior| index <= prior) {
            bail!("migration plan sources are duplicated or out of canonical order");
        }
        previous = Some(index);
    }
    if plan.sources.len() != LEGACY_SLED_PATHS.len() {
        bail!(
            "migration plan has an incomplete legacy source set (found {}, expected {})",
            plan.sources.len(),
            LEGACY_SLED_PATHS.len()
        );
    }
    Ok(())
}

fn validate_plan_filesystem(data_dir: &Path, plan: &MigrationPlan) -> Result<()> {
    require_absent(
        &data_dir.join(MIGRATION_COMPLETE_DIR),
        "completed migration receipt",
    )?;
    for name in LEGACY_SLED_PATHS {
        let planned = plan.sources.iter().any(|source| source == name);
        let source = data_dir.join(name);
        let backup = backup_path(data_dir, name);
        let source_meta = metadata_no_follow(&source)?;
        let backup_meta = metadata_no_follow(&backup)?;
        if !planned && (source_meta.is_some() || backup_meta.is_some()) {
            bail!(
                "{} appeared after the migration plan was filed; refusing source-set drift",
                if source_meta.is_some() {
                    source.display()
                } else {
                    backup.display()
                }
            );
        }
        if let Some(metadata) = source_meta {
            require_directory_metadata(&source, &metadata, "legacy sled source")?;
            validate_sled_layout(&source, "legacy sled source")?;
        }
        if let Some(metadata) = backup_meta {
            require_directory_metadata(&backup, &metadata, "legacy sled backup")?;
            validate_sled_layout(&backup, "legacy sled backup")?;
        }
        if planned
            && metadata_no_follow(&source)?.is_some()
            && metadata_no_follow(&backup)?.is_some()
        {
            bail!(
                "both {} and {} exist; refusing to overwrite or merge provenance",
                source.display(),
                backup.display()
            );
        }
        if planned
            && metadata_no_follow(&source)?.is_none()
            && metadata_no_follow(&backup)?.is_none()
        {
            bail!(
                "planned legacy source {} and its backup are both missing",
                source.display()
            );
        }
    }
    Ok(())
}

fn ensure_prepublication_layout(data_dir: &Path, plan: &MigrationPlan) -> Result<()> {
    require_absent(&data_dir.join(CONTROL_DB_FILE), "control database")?;
    for source in &plan.sources {
        require_real_directory(&data_dir.join(source), "legacy sled source")?;
        require_absent(&backup_path(data_dir, source), "legacy backup destination")?;
    }
    Ok(())
}

fn ensure_no_retirement_started(data_dir: &Path, plan: &MigrationPlan) -> Result<()> {
    for source in &plan.sources {
        require_real_directory(&data_dir.join(source), "legacy sled source")?;
        require_absent(&backup_path(data_dir, source), "legacy backup destination")?;
    }
    Ok(())
}

fn open_sources(data_dir: &Path, names: &[String]) -> Result<LegacySources> {
    let mut opened = BTreeMap::new();
    for name in names {
        let path = data_dir.join(name);
        opened.insert(name.clone(), open_legacy_at(&path, "legacy sled source")?);
    }
    reject_unmapped_tree_rows(&opened)?;
    Ok(opened)
}

/// Open the one authoritative sled location for every planned source. Before
/// publication that is always the live name; during retirement it may be the
/// no-replace backup name. Locking and hashing backups on resume prevents a
/// renamed-but-modified directory from being blessed merely because it exists.
fn open_planned_locations(data_dir: &Path, plan: &MigrationPlan) -> Result<LegacySources> {
    let mut opened = BTreeMap::new();
    for name in &plan.sources {
        let source = data_dir.join(name);
        let backup = backup_path(data_dir, name);
        let (path, kind) = match (metadata_no_follow(&source)?, metadata_no_follow(&backup)?) {
            (Some(_), None) => (source, "legacy sled source"),
            (None, Some(_)) => (backup, "legacy sled backup"),
            (Some(_), Some(_)) => bail!(
                "both {} and {} exist; refusing to choose or merge provenance",
                source.display(),
                backup.display()
            ),
            (None, None) => bail!(
                "planned legacy source {} and its backup are both missing",
                source.display()
            ),
        };
        if opened
            .insert(name.clone(), open_legacy_at(&path, kind)?)
            .is_some()
        {
            bail!("migration plan contains duplicate source {name}");
        }
    }
    reject_unmapped_tree_rows(&opened)?;
    Ok(opened)
}

fn open_legacy_at(path: &Path, kind: &str) -> Result<LegacySource> {
    require_real_directory(path, kind)?;
    validate_sled_layout(path, kind)?;
    let db = sled::open(path).with_context(|| {
        format!(
            "opening {} exclusively; stop every process using this data directory",
            path.display()
        )
    })?;
    let trees = db
        .tree_names()
        .into_iter()
        .map(|name| name.to_vec())
        .collect();
    Ok(LegacySource { db, trees })
}

fn tree_if_present(source: &LegacySource, tree_name: &str) -> Result<Option<sled::Tree>> {
    if !source.trees.contains(tree_name.as_bytes()) {
        return Ok(None);
    }
    source
        .db
        .open_tree(tree_name)
        .with_context(|| format!("opening existing sled tree {tree_name}"))
        .map(Some)
}

/// Refuse to retire a legacy database while it contains rows that the fixed
/// copy/rebuild plans do not understand. Sled always exposes its default tree
/// and older/newer builds may have created additional trees, so an unexpected
/// *empty* tree is harmless. Any row in one would otherwise be omitted while
/// migration still reported success and renamed the only source database.
/// Rebuilt trees still participate in the whole-source snapshot and drift
/// checks; this allowlist only prevents treating their known rows as unknown.
fn reject_unmapped_tree_rows(sources: &LegacySources) -> Result<()> {
    for (source_name, source) in sources {
        let mapped = COPY_PLAN
            .iter()
            .filter_map(|(planned_source, tree, _)| {
                (*planned_source == source_name).then_some(tree.as_bytes())
            })
            .collect::<BTreeSet<_>>();
        let rebuilt = REBUILT_DERIVED_TREES
            .iter()
            .filter_map(|(planned_source, tree)| {
                (*planned_source == source_name).then_some(tree.as_bytes())
            })
            .collect::<BTreeSet<_>>();
        for tree_name in &source.trees {
            if mapped.contains(tree_name.as_slice()) || rebuilt.contains(tree_name.as_slice()) {
                continue;
            }
            let tree = source
                .db
                .open_tree(tree_name.as_slice())
                .with_context(|| format!("opening existing sled tree in {source_name}"))?;
            if !tree.is_empty() {
                bail!(
                    "legacy source {source_name} contains {} row(s) in unmapped sled tree {}; refusing a lossy migration",
                    tree.len(),
                    hex::encode(tree_name)
                );
            }
        }
    }
    Ok(())
}

fn hash_key(hash: &mut Sha256, key: &[u8]) {
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key);
}

fn hash_row(hash: &mut Sha256, key: &[u8], value: &[u8]) {
    hash_key(hash, key);
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn digest_optional_tree(tree: Option<sled::Tree>) -> Result<(u64, String, String)> {
    let mut rows = 0u64;
    let mut hash = Sha256::new();
    let mut key_hash = Sha256::new();
    if let Some(tree) = tree {
        for item in tree.iter() {
            let (key, value) = item?;
            hash_row(&mut hash, key.as_ref(), value.as_ref());
            hash_key(&mut key_hash, key.as_ref());
            rows = rows
                .checked_add(1)
                .context("migration row count overflow")?;
        }
    }
    Ok((
        rows,
        hex::encode(hash.finalize()),
        hex::encode(key_hash.finalize()),
    ))
}

fn snapshot_sources(sources: &LegacySources, order: &[String]) -> Result<Vec<SourceSnapshot>> {
    order
        .iter()
        .map(|name| {
            let source = sources
                .get(name)
                .with_context(|| format!("missing locked source {name}"))?;
            snapshot_source(name, source)
        })
        .collect()
}

fn snapshot_source(name: &str, source: &LegacySource) -> Result<SourceSnapshot> {
    let mut trees = Vec::with_capacity(source.trees.len());
    for tree_name in &source.trees {
        let tree = source
            .db
            .open_tree(tree_name.as_slice())
            .with_context(|| format!("opening existing sled tree in {name}"))?;
        let (rows, sha256, _) = digest_optional_tree(Some(tree))?;
        trees.push(TreeSnapshot {
            name_hex: hex::encode(tree_name),
            rows,
            sha256,
        });
    }
    Ok(SourceSnapshot {
        source: name.to_string(),
        trees,
    })
}

fn verify_sources_unchanged(sources: &LegacySources, receipt: &ValidationReceipt) -> Result<()> {
    for (name, source) in sources {
        verify_source_unchanged(name, source, receipt)?;
    }
    Ok(())
}

fn verify_source_unchanged(
    name: &str,
    source: &LegacySource,
    receipt: &ValidationReceipt,
) -> Result<()> {
    let expected = receipt
        .sources
        .iter()
        .find(|snapshot| snapshot.source == name)
        .with_context(|| format!("validation receipt has no snapshot for {name}"))?;
    let actual = snapshot_source(name, source)?;
    if actual != *expected {
        bail!(
            "legacy source or backup {} changed after validation; refusing to publish or retire it",
            name
        );
    }
    Ok(())
}

fn survey_copy_plan(sources: &LegacySources) -> Result<Vec<CopiedTable>> {
    let mut copied = Vec::new();
    for &(source_name, tree_name, table_name) in COPY_PLAN {
        let Some(source) = sources.get(source_name) else {
            continue;
        };
        let (rows, sha256, key_sha256) = digest_optional_tree(tree_if_present(source, tree_name)?)?;
        copied.push(CopiedTable {
            source: source_name.to_string(),
            tree: tree_name.to_string(),
            table: table_name.to_string(),
            rows,
            sha256,
            key_sha256,
        });
    }
    Ok(copied)
}

fn copy_to_stage(
    data_dir: &Path,
    stage_path: &Path,
    sources: &LegacySources,
    failpoint: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Vec<CopiedTable>> {
    let stage_file = create_private_file(stage_path, "migration staging file")?;
    let redb = redb::Database::builder()
        .create_file(stage_file)
        .with_context(|| format!("creating staged database {}", stage_path.display()))?;
    let mut copied = Vec::new();

    for &(source_name, tree_name, table_name) in COPY_PLAN {
        let Some(source) = sources.get(source_name) else {
            continue;
        };
        let tree = tree_if_present(source, tree_name)?;
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new(table_name);
        let txn = redb.begin_write()?;
        let mut rows = 0u64;
        let mut hash = Sha256::new();
        let mut key_hash = Sha256::new();
        {
            let mut table = txn.open_table(definition)?;
            if let Some(tree) = &tree {
                for item in tree.iter() {
                    let (key, value) = item?;
                    table.insert(key.as_ref(), value.as_ref())?;
                    hash_row(&mut hash, key.as_ref(), value.as_ref());
                    hash_key(&mut key_hash, key.as_ref());
                    rows = rows
                        .checked_add(1)
                        .context("migration row count overflow")?;
                }
            }
        }
        txn.commit()?;
        copied.push(CopiedTable {
            source: source_name.to_string(),
            tree: tree_name.to_string(),
            table: table_name.to_string(),
            rows,
            sha256: hex::encode(hash.finalize()),
            key_sha256: hex::encode(key_hash.finalize()),
        });
        failpoint(&format!("copy:{table_name}"))?;
    }

    validate_copied_rows(&redb, sources, &copied)?;
    drop(redb);
    sync_file(stage_path)?;
    sync_dir(data_dir)?;
    Ok(copied)
}

fn validate_copied_rows(
    redb: &redb::Database,
    sources: &LegacySources,
    copied: &[CopiedTable],
) -> Result<()> {
    let txn = redb.begin_read()?;
    for copy in copied {
        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new(&copy.table);
        let table = txn.open_table(definition)?;
        let actual = table.len()?;
        if actual != copy.rows {
            bail!(
                "copy validation failed for {}: source has {} rows, stage has {}",
                copy.label(),
                copy.rows,
                actual
            );
        }
        let source = sources
            .get(&copy.source)
            .with_context(|| format!("missing locked source {}", copy.source))?;
        if let Some(tree) = tree_if_present(source, &copy.tree)? {
            let mut hash = Sha256::new();
            let mut key_hash = Sha256::new();
            let mut rows = 0u64;
            for item in tree.iter() {
                let (key, value) = item?;
                hash_row(&mut hash, key.as_ref(), value.as_ref());
                hash_key(&mut key_hash, key.as_ref());
                rows = rows
                    .checked_add(1)
                    .context("migration row count overflow")?;
                let staged = table.get(key.as_ref())?.with_context(|| {
                    format!("stage lost a row from {}/{}", copy.source, copy.tree)
                })?;
                if staged.value() != value.as_ref() {
                    bail!(
                        "copy validation found different bytes in {} for one source key",
                        copy.label()
                    );
                }
            }
            if rows != copy.rows
                || hex::encode(hash.finalize()) != copy.sha256
                || hex::encode(key_hash.finalize()) != copy.key_sha256
            {
                bail!("source changed while copying {}", copy.label());
            }
        } else {
            let empty = hex::encode(Sha256::new().finalize());
            if copy.rows != 0 || copy.sha256 != empty || copy.key_sha256 != empty {
                bail!(
                    "copy receipt for missing tree {} is inconsistent",
                    copy.label()
                );
            }
        }
    }
    Ok(())
}

/// Rebuilds deliberately replace head/index tables, and the schema-5 upgrade
/// may terminalise legacy active run values. Everything else copied from sled
/// must remain byte-for-byte identical; run keys and counts must remain
/// identical. Rechecking this after rebuild and again after publication keeps
/// a valid-but-wrong redb file from passing on coincidentally equal head
/// counts.
fn validate_rebuilt_copy(database_path: &Path, receipt: &ValidationReceipt) -> Result<()> {
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        redb::Database::open(database_path)
    }))
    .map_err(|_| {
        anyhow::anyhow!(
            "{} panicked redb while opening for copy validation",
            database_path.display()
        )
    })?;
    let database = opened
        .with_context(|| format!("opening {} for copy validation", database_path.display()))?;
    let transaction = database.begin_read()?;
    for copy in &receipt.copied {
        let preserve_values = matches!(
            copy.table.as_str(),
            "pointer_events"
                | "pin_events"
                | "job_events"
                | "effect_cache"
                | "pointer_subscriptions"
                | "event_journal"
        );
        let preserve_keys = preserve_values || copy.table == "job_runs";
        if !preserve_keys {
            continue;
        }

        let definition: TableDefinition<&[u8], &[u8]> = TableDefinition::new(&copy.table);
        let table = transaction.open_table(definition)?;
        let mut rows = 0u64;
        let mut hash = Sha256::new();
        let mut key_hash = Sha256::new();
        for row in table.iter()? {
            let (key, value) = row?;
            hash_key(&mut key_hash, key.value());
            if preserve_values {
                hash_row(&mut hash, key.value(), value.value());
            }
            rows = rows
                .checked_add(1)
                .context("migration row count overflow")?;
        }
        if rows != copy.rows || hex::encode(key_hash.finalize()) != copy.key_sha256 {
            bail!(
                "rebuilt database changed the rows or keys copied from {}/{}",
                copy.source,
                copy.tree
            );
        }
        if preserve_values && hex::encode(hash.finalize()) != copy.sha256 {
            bail!(
                "rebuilt database changed bytes copied from {}/{}",
                copy.source,
                copy.tree
            );
        }
    }
    Ok(())
}

fn validate_and_rebuild(data_dir: &Path, database_path: &Path) -> Result<RebuildSummary> {
    let control = Control::open_migration_database(data_dir, database_path)
        .with_context(|| format!("opening migration database {}", database_path.display()))?;
    let rebuilt = rebuild_open_control(&control)?;
    drop(control);
    sync_file(database_path)?;
    sync_dir(data_dir)?;
    Ok(rebuilt)
}

fn rebuild_open_control(control: &Control) -> Result<RebuildSummary> {
    let chunks = control
        .store
        .reindex()
        .map_err(|error| anyhow::anyhow!("reindexing chunks: {error}"))?;
    // Migration is already an explicit offline, operator-sized operation.
    // Rebuild every GC-safety index, not only the two historical gate flags;
    // zero is the deliberate unbounded setting for this compatibility path.
    let recovery = control.recover_with_limit(0)?;
    let recovered = recovery.recovered;
    if !recovered {
        bail!("migration recovery gate remained incomplete; refusing publication");
    }
    Ok(RebuildSummary {
        chunks_reindexed: chunks,
        pointers_rebuilt: recovery.pointers_rebuilt,
        pin_heads_rebuilt: recovery.pins_rebuilt,
        job_heads_rebuilt: recovery.jobs_rebuilt,
        recovered,
    })
}

fn validate_receipt(receipt: &ValidationReceipt, plan: &MigrationPlan) -> Result<()> {
    if receipt.protocol != MIGRATION_PROTOCOL {
        bail!("validation receipt uses an unsupported migration protocol");
    }
    if !receipt.rebuilt.recovered {
        bail!("validation receipt does not prove a complete recovery gate");
    }
    let expected: Vec<(&str, &str, &str)> = COPY_PLAN
        .iter()
        .copied()
        .filter(|(source, _, _)| plan.sources.iter().any(|planned| planned == source))
        .collect();
    if receipt.copied.len() != expected.len() {
        bail!("validation receipt has the wrong copy-plan length");
    }
    for (copy, (source, tree, table)) in receipt.copied.iter().zip(expected) {
        if copy.source != source || copy.tree != tree || copy.table != table {
            bail!("validation receipt copy plan does not match this build");
        }
        validate_sha256(&copy.sha256, "copied table")?;
        validate_sha256(&copy.key_sha256, "copied table key")?;
    }
    if receipt.sources.len() != plan.sources.len() {
        bail!("validation receipt has the wrong source snapshot count");
    }
    for (snapshot, expected_source) in receipt.sources.iter().zip(&plan.sources) {
        if snapshot.source != *expected_source {
            bail!("validation receipt source snapshots are out of canonical order");
        }
        let mut previous: Option<&str> = None;
        for tree in &snapshot.trees {
            if tree.name_hex.len() % 2 != 0
                || !tree.name_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("validation receipt has an invalid sled tree name");
            }
            if previous.is_some_and(|name| name >= tree.name_hex.as_str()) {
                bail!("validation receipt sled trees are duplicated or out of order");
            }
            previous = Some(&tree.name_hex);
            validate_sha256(&tree.sha256, "sled tree")?;
        }
    }
    Ok(())
}

fn validate_sha256(digest: &str, kind: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("validation receipt has an invalid {kind} SHA-256 digest");
    }
    Ok(())
}

fn retire_sources(
    data_dir: &Path,
    marker: &Path,
    plan: &MigrationPlan,
    receipt: &ValidationReceipt,
    mut locks: LegacySources,
    failpoint: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    for (index, source_name) in plan.sources.iter().enumerate() {
        let source = data_dir.join(source_name);
        let backup = backup_path(data_dir, source_name);
        let phase = marker.join(retired_phase_name(index));
        let phase_present = metadata_no_follow(&phase)?.is_some();
        if phase_present {
            read_expected_phase(&phase, &format!("{source_name}\n"), "retirement phase")?;
        }

        match (metadata_no_follow(&source)?, metadata_no_follow(&backup)?) {
            (Some(source_meta), None) => {
                require_directory_metadata(&source, &source_meta, "legacy sled source")?;
                if phase_present {
                    bail!(
                        "{} says {} was retired, but the live source still exists",
                        phase.display(),
                        source_name
                    );
                }
                // On platforms that cannot rename an open sled directory,
                // dropping this one handle is necessary. The published redb
                // lock and active marker still exclude current binaries.
                let live_lock = locks.remove(source_name).with_context(|| {
                    format!("migration lost its lock on live legacy source {source_name}")
                })?;
                drop(live_lock);
                publish_noreplace(&source, &backup).with_context(|| {
                    format!("retiring {} to {}", source.display(), backup.display())
                })?;
                sync_dir(data_dir)?;
                failpoint(&format!("retire:{source_name}"))?;
                let retired = open_legacy_at(&backup, "legacy sled backup")?;
                verify_source_unchanged(source_name, &retired, receipt)?;
                if locks.insert(source_name.clone(), retired).is_some() {
                    bail!("migration retained two locks for source {source_name}");
                }
                write_phase_new(&phase, &format!("{source_name}\n"), "retirement phase")?;
                sync_dir(marker)?;
            }
            (None, Some(backup_meta)) => {
                require_directory_metadata(&backup, &backup_meta, "legacy sled backup")?;
                let retired = locks.get(source_name).with_context(|| {
                    format!("migration lost its lock on legacy backup {source_name}")
                })?;
                verify_source_unchanged(source_name, retired, receipt)?;
                if !phase_present {
                    // Rename was durable but the process died before its phase
                    // record. Observing exactly one backup is sufficient to
                    // complete that idempotent state transition.
                    write_phase_new(&phase, &format!("{source_name}\n"), "retirement phase")?;
                    sync_dir(marker)?;
                }
            }
            (Some(_), Some(_)) => bail!(
                "both {} and {} exist; refusing to overwrite or merge provenance",
                source.display(),
                backup.display()
            ),
            (None, None) => bail!(
                "planned legacy source {} and its backup are both missing",
                source.display()
            ),
        }
    }
    Ok(())
}

fn validate_marker_entries(marker: &Path, plan: &MigrationPlan) -> Result<()> {
    let mut allowed = BTreeSet::from([
        PLAN_FILE.to_string(),
        VALIDATED_FILE.to_string(),
        PUBLISHED_FILE.to_string(),
        COMPLETE_FILE.to_string(),
    ]);
    for index in 0..plan.sources.len() {
        allowed.insert(retired_phase_name(index));
    }
    for entry in fs::read_dir(marker).with_context(|| format!("reading {}", marker.display()))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("migration marker contains a non-UTF-8 file name"))?;
        if !allowed.contains(&name) {
            bail!("migration marker contains unexpected entry {name}");
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        require_regular_metadata(&entry.path(), &metadata, "migration phase file")?;
        require_private_file(&entry.path(), &metadata)?;
    }

    let validated = metadata_no_follow(&marker.join(VALIDATED_FILE))?.is_some();
    let published = metadata_no_follow(&marker.join(PUBLISHED_FILE))?.is_some();
    let complete = metadata_no_follow(&marker.join(COMPLETE_FILE))?.is_some();
    if published && !validated {
        bail!("migration marker records publication before validation");
    }
    let mut missing_retirement = false;
    for index in 0..plan.sources.len() {
        let present = metadata_no_follow(&marker.join(retired_phase_name(index)))?.is_some();
        if present && (!published || missing_retirement) {
            bail!("migration marker retirement phases are out of order");
        }
        missing_retirement |= !present;
    }
    if complete && missing_retirement {
        bail!("migration marker records completion before every retirement");
    }
    Ok(())
}

fn retired_phase_name(index: usize) -> String {
    format!("retired-{index:02}")
}

fn backup_path(data_dir: &Path, source: &str) -> PathBuf {
    data_dir.join(format!("{source}.sled.bak"))
}

fn metadata_no_follow(path: &Path) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("reading metadata for {}", path.display()))
        }
    }
}

fn require_absent(path: &Path, kind: &str) -> Result<()> {
    if metadata_no_follow(path)?.is_some() {
        bail!(
            "{kind} {} already exists; refusing to overwrite it",
            path.display()
        );
    }
    Ok(())
}

fn require_real_directory(path: &Path, kind: &str) -> Result<()> {
    let metadata = metadata_no_follow(path)?
        .with_context(|| format!("{kind} {} does not exist", path.display()))?;
    require_directory_metadata(path, &metadata, kind)
}

fn require_directory_metadata(path: &Path, metadata: &Metadata, kind: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("{kind} {} is not a real directory", path.display());
    }
    Ok(())
}

fn require_regular_metadata(path: &Path, metadata: &Metadata, kind: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("{kind} {} is not a regular file", path.display());
    }
    Ok(())
}

/// Refuse to let `sled::open` initialize an arbitrary empty directory or
/// follow a substituted database/config/blob path. A real sled 0.34 database
/// always has these three entries after its first successful open.
fn validate_sled_layout(path: &Path, kind: &str) -> Result<()> {
    for name in ["db", "conf"] {
        let child = path.join(name);
        let metadata = metadata_no_follow(&child)?
            .with_context(|| format!("{kind} {} is missing {name}", path.display()))?;
        require_regular_metadata(&child, &metadata, kind)?;
    }
    require_real_directory(&path.join("blobs"), kind)
}

#[cfg(unix)]
fn require_private_file(path: &Path, metadata: &Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "migration file {} has mode {mode:04o}; expected no group/world access",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file(_path: &Path, _metadata: &Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn require_private_directory(path: &Path, metadata: &Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "migration marker {} has mode {mode:04o}; expected no group/world access",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_directory(_path: &Path, _metadata: &Metadata) -> Result<()> {
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("creating private directory {}", path.display()))
}

fn create_private_file(path: &Path, kind: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("creating {kind} {}", path.display()))
}

fn write_json_new<T: Serialize>(path: &Path, value: &T, kind: &str) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("encoding {kind} {}", path.display()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
        bail!("{kind} exceeds the {} byte limit", MAX_STATE_FILE_BYTES);
    }
    write_bytes_new(path, &bytes, kind)
}

fn write_phase_new(path: &Path, contents: &str, kind: &str) -> Result<()> {
    write_bytes_new(path, contents.as_bytes(), kind)
}

fn write_bytes_new(path: &Path, contents: &[u8], kind: &str) -> Result<()> {
    require_absent(path, kind)?;
    let temporary = phase_temp_path(path)?;
    require_absent(&temporary, "incomplete migration phase write")?;
    let mut file = create_private_file(&temporary, kind)?;
    file.write_all(contents)
        .with_context(|| format!("writing {kind} {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {kind} {}", temporary.display()))?;
    drop(file);
    publish_noreplace(&temporary, path)?;
    sync_dir(
        path.parent()
            .context("migration phase path has no parent directory")?,
    )
}

fn phase_temp_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("migration phase path has a non-UTF-8 or missing file name")?;
    Ok(path.with_file_name(format!(".{name}.tmp")))
}

/// A phase file is published only after its temporary file is complete and
/// synced. Any temporary name surviving a crash is therefore disposable: the
/// authoritative filesystem state lets the phase be recomputed safely.
fn cleanup_incomplete_phase_writes(marker: &Path) -> Result<()> {
    let mut allowed = BTreeSet::from([
        format!(".{PLAN_FILE}.tmp"),
        format!(".{VALIDATED_FILE}.tmp"),
        format!(".{PUBLISHED_FILE}.tmp"),
        format!(".{COMPLETE_FILE}.tmp"),
    ]);
    for index in 0..LEGACY_SLED_PATHS.len() {
        allowed.insert(format!(".{}.tmp", retired_phase_name(index)));
    }

    let mut removed = false;
    for entry in fs::read_dir(marker).with_context(|| format!("reading {}", marker.display()))? {
        let entry = entry?;
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if !allowed.contains(&name) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require_regular_metadata(&path, &metadata, "incomplete migration phase write")?;
        require_private_file(&path, &metadata)?;
        fs::remove_file(&path)
            .with_context(|| format!("removing incomplete phase write {}", path.display()))?;
        removed = true;
    }
    if removed {
        sync_dir(marker)?;
    }
    Ok(())
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path, kind: &str) -> Result<T> {
    let bytes = read_bounded_file(path, kind)?;
    serde_json::from_slice(&bytes).with_context(|| format!("decoding {kind} {}", path.display()))
}

fn read_expected_phase(path: &Path, expected: &str, kind: &str) -> Result<()> {
    let bytes = read_bounded_file(path, kind)?;
    if bytes != expected.as_bytes() {
        bail!("{kind} {} has unexpected contents", path.display());
    }
    Ok(())
}

fn read_bounded_file(path: &Path, kind: &str) -> Result<Vec<u8>> {
    let metadata = metadata_no_follow(path)?
        .with_context(|| format!("{kind} {} is missing", path.display()))?;
    require_regular_metadata(path, &metadata, kind)?;
    require_private_file(path, &metadata)?;
    if metadata.len() > MAX_STATE_FILE_BYTES {
        bail!("{kind} {} exceeds the size limit", path.display());
    }
    let mut file =
        open_read_nofollow(path).with_context(|| format!("opening {kind} {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {kind} {}", path.display()))?;
    if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
        bail!("{kind} {} exceeds the size limit", path.display());
    }
    Ok(bytes)
}

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    unix_fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "android", target_os = "linux", target_vendor = "apple")))]
fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
fn sync_file(path: &Path) -> Result<()> {
    File::from(unix_fs::open(
        path,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
    .sync_all()
    .with_context(|| format!("syncing {}", path.display()))
}

#[cfg(not(any(target_os = "android", target_os = "linux", target_vendor = "apple")))]
fn sync_file(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
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
    // `std` exposes no portable directory fsync. Every staged/phase file is
    // still individually sync_all'd before a name becomes authoritative.
    Ok(())
}

/// Atomically publish a same-directory path without replacing a target.
fn publish_noreplace(staged: &Path, target: &Path) -> Result<()> {
    if staged.parent() != target.parent() {
        bail!("migration staging and target paths must have the same parent");
    }

    #[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
    {
        let parent = target
            .parent()
            .context("migration publication target has no parent")?
            .canonicalize()
            .with_context(|| format!("resolving parent for {}", target.display()))?;
        let parent = unix_fs::open(
            &parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let staged_name = staged
            .file_name()
            .context("migration staging path has no file name")?;
        let target_name = target
            .file_name()
            .context("migration target path has no file name")?;
        unix_fs::renameat_with(
            &parent,
            staged_name,
            &parent,
            target_name,
            RenameFlags::NOREPLACE,
        )
        .with_context(|| {
            format!(
                "publishing {} as {} without replacement",
                staged.display(),
                target.display()
            )
        })?;
        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "linux", target_vendor = "apple")))]
    {
        // Windows refuses replacing a directory with rename. Other targets
        // receive the strongest check available in `std`; supported Linux and
        // Apple builds use the race-free branch above.
        require_absent(target, "migration publication target")?;
        fs::rename(staged, target)
            .with_context(|| format!("publishing {} as {}", staged.display(), target.display()))
    }
}

fn report(
    fmt: Format,
    data_dir: &Path,
    copied: &[CopiedTable],
    rebuilt: Option<RebuildSummary>,
    dry_run: bool,
    resumed: bool,
) -> Result<()> {
    let payload = serde_json::json!({
        "data_dir": data_dir.display().to_string(),
        "dry_run": dry_run,
        "resumed": resumed,
        "copied": copied.iter()
            .map(|copy| serde_json::json!({ "table": copy.label(), "rows": copy.rows }))
            .collect::<Vec<_>>(),
        "rebuilt": rebuilt.as_ref().map(|summary| serde_json::json!({
            "chunks_reindexed": summary.chunks_reindexed,
            "pointers": summary.pointers_rebuilt,
            "pin_heads": summary.pin_heads_rebuilt,
            "job_heads": summary.job_heads_rebuilt,
            "recovered": summary.recovered,
        })),
        "migration_receipt": rebuilt.as_ref().map(|_| {
            data_dir.join(MIGRATION_COMPLETE_DIR).display().to_string()
        }),
    });

    fmt.emit(&payload, |_| {
        let mut output = String::new();
        if dry_run {
            output.push_str("would copy:\n");
        } else if resumed {
            output.push_str("resumed migration; copied:\n");
        } else {
            output.push_str("copied:\n");
        }
        for copy in copied {
            output.push_str(&format!(
                "  {:>6}  {}\n",
                copy.rows,
                terminal_text(&copy.label())
            ));
        }
        match &rebuilt {
            Some(summary) => output.push_str(&format!(
                "\nvalidated and rebuilt before atomic publication:\n  \
                 {} chunks reindexed, {} pointers, {} pin heads, {} job heads\n  \
                 recovery {}\n\nold sled databases retained as *.sled.bak; \
                 durable migration receipt: {}",
                summary.chunks_reindexed,
                summary.pointers_rebuilt,
                summary.pin_heads_rebuilt,
                summary.job_heads_rebuilt,
                if summary.recovered {
                    "complete"
                } else {
                    "INCOMPLETE"
                },
                terminal_text(&data_dir.join(MIGRATION_COMPLETE_DIR).display().to_string()),
            )),
            None => output.push_str("\nrun without --dry-run to migrate"),
        }
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format() -> Format {
        Format {
            json: false,
            pretty: false,
        }
    }

    fn legacy_fixture(root: &Path) {
        for name in LEGACY_SLED_PATHS {
            let db = sled::open(root.join(name)).unwrap();
            for &(source, tree, _) in COPY_PLAN {
                if source == name {
                    db.open_tree(tree).unwrap();
                }
            }
            if name == "job.db" {
                let mut subscription = Vec::new();
                ciborium::ser::into_writer(&vec!["fixture-job".to_string()], &mut subscription)
                    .unwrap();
                db.open_tree("pointer_subscriptions")
                    .unwrap()
                    .insert(b"fixture-pointer", subscription)
                    .unwrap();
            }
            if name == "index" {
                db.insert(b"fixture-derived-index", b"rebuilt-from-content")
                    .unwrap();
            }
            if name == "recovery.db" {
                db.insert(b"fixture-derived-recovery", b"rebuilt-from-primary-state")
                    .unwrap();
            }
            db.flush().unwrap();
        }
    }

    fn run_with_failure(root: &Path, point: &str) -> Result<()> {
        let mut injected = |current: &str| {
            if current == point {
                bail!("injected migration failure at {current}");
            }
            Ok(())
        };
        handle_with_failpoints(root, false, format(), &mut injected)
    }

    fn resume(root: &Path) {
        let mut no_fail = |_point: &str| Ok(());
        handle_with_failpoints(root, false, format(), &mut no_fail).unwrap();
    }

    fn assert_completed(root: &Path) {
        assert!(root.join(CONTROL_DB_FILE).is_file());
        assert!(!root.join(MIGRATION_STAGE_FILE).exists());
        assert!(!root.join(MIGRATION_STATE_DIR).exists());
        assert!(root.join(MIGRATION_COMPLETE_DIR).is_dir());
        for name in LEGACY_SLED_PATHS {
            assert!(!root.join(name).exists(), "live source {name} remains");
            assert!(backup_path(root, name).is_dir(), "backup {name} missing");
        }
        let control = Control::open(root).unwrap();
        assert_eq!(
            control
                .job_log
                .get_pointer_subscriptions("fixture-pointer")
                .unwrap(),
            vec![dag_core::JobId::from("fixture-job")]
        );
    }

    fn control_open_error(root: &Path) -> dag_control::ControlError {
        match Control::open(root) {
            Ok(_) => panic!("Control::open unexpectedly accepted an active migration"),
            Err(error) => error,
        }
    }

    #[test]
    fn nonempty_known_derived_default_trees_are_rebuilt_and_retained() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());

        handle(root.path(), true, format()).unwrap();
        assert!(!root.path().join(MIGRATION_STATE_DIR).exists());

        handle(root.path(), false, format()).unwrap();
        assert_completed(root.path());

        let index = sled::open(backup_path(root.path(), "index")).unwrap();
        assert_eq!(
            index.get(b"fixture-derived-index").unwrap().as_deref(),
            Some(b"rebuilt-from-content".as_slice())
        );
        drop(index);

        let recovery = sled::open(backup_path(root.path(), "recovery.db")).unwrap();
        assert_eq!(
            recovery
                .get(b"fixture-derived-recovery")
                .unwrap()
                .as_deref(),
            Some(b"rebuilt-from-primary-state".as_slice())
        );
    }

    #[test]
    fn nonempty_unmapped_sled_tree_is_refused_before_migration_state_is_created() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());
        let database = sled::open(root.path().join("pointer.db")).unwrap();
        database
            .open_tree("future-or-unknown-tree")
            .unwrap()
            .insert(b"unmapped-key", b"must-not-be-lost")
            .unwrap();
        database.flush().unwrap();
        drop(database);

        let error = handle(root.path(), true, format()).unwrap_err();
        assert!(
            error.to_string().contains("unmapped sled tree"),
            "unexpected dry-run error: {error:#}"
        );
        assert!(!root.path().join(MIGRATION_STATE_DIR).exists());
        assert!(!root.path().join(MIGRATION_STAGE_FILE).exists());
        assert!(!root.path().join(CONTROL_DB_FILE).exists());

        let error = handle(root.path(), false, format()).unwrap_err();
        assert!(
            error.to_string().contains("unmapped sled tree"),
            "unexpected migration error: {error:#}"
        );
        assert!(!root.path().join(MIGRATION_STATE_DIR).exists());
        assert!(!root.path().join(MIGRATION_STAGE_FILE).exists());
        assert!(!root.path().join(CONTROL_DB_FILE).exists());
        assert!(root.path().join("pointer.db").is_dir());
        assert!(!backup_path(root.path(), "pointer.db").exists());
    }

    #[test]
    fn every_missing_legacy_source_is_refused_before_migration_state_is_created() {
        for missing in LEGACY_SLED_PATHS {
            let root = tempfile::tempdir().unwrap();
            legacy_fixture(root.path());
            fs::remove_dir_all(root.path().join(missing)).unwrap();

            for dry_run in [true, false] {
                let error = handle(root.path(), dry_run, format()).unwrap_err();
                let message = error.to_string();
                assert!(
                    message.contains("not a complete pre-redb data directory")
                        && message.contains(missing),
                    "unexpected error with {missing} missing: {error:#}"
                );
                assert!(!root.path().join(MIGRATION_STATE_DIR).exists());
                assert!(!root.path().join(MIGRATION_STAGE_FILE).exists());
                assert!(!root.path().join(CONTROL_DB_FILE).exists());
                assert!(!root.path().join(MIGRATION_COMPLETE_DIR).exists());
                for source in LEGACY_SLED_PATHS {
                    assert!(!backup_path(root.path(), source).exists());
                    if source != missing {
                        assert!(root.path().join(source).is_dir());
                    }
                }
            }
        }
    }

    #[test]
    fn interrupted_copy_is_discarded_and_rebuilt_from_intact_sources() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());

        let error = run_with_failure(root.path(), "copy:pointer_events").unwrap_err();
        assert!(error.to_string().contains("injected migration failure"));
        assert!(root.path().join(MIGRATION_STAGE_FILE).is_file());
        assert!(root.path().join(MIGRATION_STATE_DIR).is_dir());
        assert!(!root.path().join(CONTROL_DB_FILE).exists());
        for name in LEGACY_SLED_PATHS {
            assert!(root.path().join(name).is_dir());
            assert!(!backup_path(root.path(), name).exists());
        }
        let partial_phase =
            phase_temp_path(&root.path().join(MIGRATION_STATE_DIR).join(VALIDATED_FILE)).unwrap();
        let mut partial = create_private_file(&partial_phase, "test partial phase").unwrap();
        partial.write_all(b"{\"protocol\":").unwrap();
        partial.sync_all().unwrap();
        drop(partial);
        assert!(matches!(
            control_open_error(root.path()),
            dag_control::ControlError::MigrationInProgress { .. }
        ));

        resume(root.path());
        assert_completed(root.path());
    }

    #[test]
    fn source_drift_after_validation_is_refused_before_publication() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());
        run_with_failure(root.path(), "validated").unwrap_err();

        let db = sled::open(root.path().join("job.db")).unwrap();
        let mut changed = Vec::new();
        ciborium::ser::into_writer(
            &vec!["fixture-job".to_string(), "late-job".to_string()],
            &mut changed,
        )
        .unwrap();
        db.open_tree("pointer_subscriptions")
            .unwrap()
            .insert(b"fixture-pointer", changed)
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let mut no_fail = |_point: &str| Ok(());
        let error = handle_with_failpoints(root.path(), false, format(), &mut no_fail).unwrap_err();
        assert!(error.to_string().contains("changed after validation"));
        assert!(!root.path().join(CONTROL_DB_FILE).exists());
        assert!(root.path().join(MIGRATION_STAGE_FILE).is_file());
        for name in LEGACY_SLED_PATHS {
            assert!(root.path().join(name).is_dir());
            assert!(!backup_path(root.path(), name).exists());
        }
    }

    #[test]
    fn derived_default_tree_drift_after_validation_is_refused() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());
        run_with_failure(root.path(), "validated").unwrap_err();

        let db = sled::open(root.path().join("index")).unwrap();
        db.insert(b"late-derived-index", b"must-change-the-source-digest")
            .unwrap();
        db.flush().unwrap();
        drop(db);

        let mut no_fail = |_point: &str| Ok(());
        let error = handle_with_failpoints(root.path(), false, format(), &mut no_fail).unwrap_err();
        assert!(
            error.to_string().contains("changed after validation"),
            "unexpected error: {error:#}"
        );
        assert!(!root.path().join(CONTROL_DB_FILE).exists());
        assert!(root.path().join(MIGRATION_STAGE_FILE).is_file());
        for name in LEGACY_SLED_PATHS {
            assert!(root.path().join(name).is_dir());
            assert!(!backup_path(root.path(), name).exists());
        }
    }

    #[test]
    fn interrupted_publication_is_not_accepted_and_resumes_retirement() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());

        run_with_failure(root.path(), "publish").unwrap_err();
        assert!(root.path().join(CONTROL_DB_FILE).is_file());
        assert!(!root.path().join(MIGRATION_STAGE_FILE).exists());
        for name in LEGACY_SLED_PATHS {
            assert!(root.path().join(name).is_dir());
        }
        assert!(matches!(
            control_open_error(root.path()),
            dag_control::ControlError::MigrationInProgress { .. }
        ));

        resume(root.path());
        assert_completed(root.path());
    }

    #[test]
    fn a_valid_but_wrong_published_database_is_refused_before_retirement() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());
        run_with_failure(root.path(), "publish").unwrap_err();

        let final_path = root.path().join(CONTROL_DB_FILE);
        fs::remove_file(&final_path).unwrap();
        let replacement = create_private_file(&final_path, "test replacement database").unwrap();
        drop(redb::Database::builder().create_file(replacement).unwrap());
        sync_file(&final_path).unwrap();

        let mut no_fail = |_point: &str| Ok(());
        let error = handle_with_failpoints(root.path(), false, format(), &mut no_fail).unwrap_err();
        assert!(
            error.to_string().contains("changed the rows or keys")
                || error.to_string().contains("changed bytes"),
            "{error:#}"
        );
        assert!(!root
            .path()
            .join(MIGRATION_STATE_DIR)
            .join(PUBLISHED_FILE)
            .exists());
        for name in LEGACY_SLED_PATHS {
            assert!(root.path().join(name).is_dir());
            assert!(!backup_path(root.path(), name).exists());
        }
    }

    #[test]
    fn every_interrupted_retirement_resumes_without_clobbering() {
        for source in LEGACY_SLED_PATHS {
            let root = tempfile::tempdir().unwrap();
            legacy_fixture(root.path());

            run_with_failure(root.path(), &format!("retire:{source}")).unwrap_err();
            assert!(!root.path().join(source).exists());
            assert!(backup_path(root.path(), source).is_dir());
            assert!(root.path().join(MIGRATION_STATE_DIR).is_dir());
            assert!(matches!(
                control_open_error(root.path()),
                dag_control::ControlError::MigrationInProgress { .. }
            ));

            resume(root.path());
            assert_completed(root.path());
        }
    }

    #[test]
    fn a_changed_retired_backup_is_never_blessed_on_resume() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());

        run_with_failure(root.path(), "retire:pointer.db").unwrap_err();
        let retired = backup_path(root.path(), "pointer.db");
        let database = sled::open(&retired).unwrap();
        database
            .open_tree("events")
            .unwrap()
            .insert(b"late-key", b"late-value")
            .unwrap();
        database.flush().unwrap();
        drop(database);

        let mut no_fail = |_point: &str| Ok(());
        let error = handle_with_failpoints(root.path(), false, format(), &mut no_fail).unwrap_err();
        assert!(
            error.to_string().contains("changed after validation"),
            "unexpected error: {error:#}"
        );
        assert!(root.path().join(MIGRATION_STATE_DIR).is_dir());
        assert!(retired.is_dir());
        assert!(!root
            .path()
            .join(MIGRATION_STATE_DIR)
            .join(retired_phase_name(1))
            .exists());
    }

    #[test]
    fn any_existing_backup_is_refused_before_a_marker_or_database_is_created() {
        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());
        fs::create_dir(backup_path(root.path(), "pointer.db")).unwrap();

        let mut no_fail = |_point: &str| Ok(());
        let error = handle_with_failpoints(root.path(), false, format(), &mut no_fail).unwrap_err();
        assert!(error.to_string().contains("refusing to overwrite"));
        assert!(!root.path().join(MIGRATION_STATE_DIR).exists());
        assert!(!root.path().join(MIGRATION_STAGE_FILE).exists());
        assert!(!root.path().join(CONTROL_DB_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn staged_published_and_marker_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        legacy_fixture(root.path());
        run_with_failure(root.path(), "copy:pointer_events").unwrap_err();

        let stage_mode = fs::metadata(root.path().join(MIGRATION_STAGE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(stage_mode & 0o077, 0, "stage mode {stage_mode:04o}");

        // Resuming discards the deliberately incomplete stage, recreates it
        // privately, validates it, and then atomically publishes that inode.
        run_with_failure(root.path(), "publish").unwrap_err();

        let database_mode = fs::metadata(root.path().join(CONTROL_DB_FILE))
            .unwrap()
            .permissions()
            .mode();
        let marker_mode = fs::metadata(root.path().join(MIGRATION_STATE_DIR))
            .unwrap()
            .permissions()
            .mode();
        let plan_mode = fs::metadata(root.path().join(MIGRATION_STATE_DIR).join(PLAN_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            database_mode & 0o077,
            0,
            "database mode {database_mode:04o}"
        );
        assert_eq!(marker_mode & 0o077, 0, "marker mode {marker_mode:04o}");
        assert_eq!(plan_mode & 0o077, 0, "plan mode {plan_mode:04o}");

        resume(root.path());
        assert_completed(root.path());
    }
}
