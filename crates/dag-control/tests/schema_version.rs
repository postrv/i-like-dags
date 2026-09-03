//! A data directory now says which format wrote it.
//!
//! The case that matters is *newer file, older binary*. redb reports its own
//! format skew as `Corrupted(..)`, and against a provenance store the word
//! "corrupted" sends an operator to restore from a backup when the fix is to
//! run the newer binary. Nothing above redb recorded a version at all, so
//! there was no layer that could say so.

use anyhow::Result;
use dag_control::{Control, ControlError, CONTROL_DB_FILE, SCHEMA_VERSION};
use dag_core::{Cid, ContentStore};
use dag_storage::ChunkLocation;
use redb::{Database, ReadableDatabase, TableDefinition, TableHandle};
use tempfile::TempDir;

const SCHEMA: TableDefinition<&str, u32> = TableDefinition::new("schema");
const CHUNK_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chunk_index");
const CHUNK_INDEX_META: TableDefinition<&[u8], u64> = TableDefinition::new("chunk_index_meta");

/// Write a version directly, as a build from another era would have.
fn set_version(dir: &TempDir, version: u32) -> Result<()> {
    let db = Database::create(dir.path().join(CONTROL_DB_FILE))?;
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(SCHEMA)?;
        table.insert("version", version)?;
    }
    txn.commit()?;
    Ok(())
}

fn read_version(dir: &TempDir) -> Result<Option<u32>> {
    let db = Database::create(dir.path().join(CONTROL_DB_FILE))?;
    let txn = db.begin_read()?;
    let table = txn.open_table(SCHEMA)?;
    Ok(table.get("version")?.map(|v| v.value()))
}

/// Every redb table present in the directory's `control.redb`, sorted.
///
/// Opening read-only is enough to enumerate them; the point is to see which
/// subsystems have run, because each one creates its tables eagerly on open.
fn table_names(dir: &TempDir) -> Result<Vec<String>> {
    let db = Database::create(dir.path().join(CONTROL_DB_FILE))?;
    let txn = db.begin_read()?;
    let mut names: Vec<String> = txn.list_tables()?.map(|t| t.name().to_string()).collect();
    names.sort();
    Ok(names)
}

#[test]
fn opening_a_directory_stamps_it_with_the_current_version() -> Result<()> {
    let dir = TempDir::new()?;
    {
        let _control = Control::open(dir.path())?;
    }
    assert_eq!(read_version(&dir)?, Some(SCHEMA_VERSION));
    Ok(())
}

#[test]
fn schema_upgrade_with_a_malformed_legacy_index_opens_for_reindex_recovery() -> Result<()> {
    let dir = TempDir::new()?;
    let good_bytes = b"intact indexed bytes";
    {
        let control = Control::open(dir.path())?;
        control.store.put_chunk(good_bytes, None)?;
    }

    // Model the state before transactional byte summaries existed, including
    // one corrupt derived row. Also make schema migration happen in the same
    // open: schema stamping commits first, then the independent summary
    // backfill must record a durable dirty marker rather than strand recovery.
    let malformed = Cid::compute(b"malformed legacy index row");
    {
        let db = Database::create(dir.path().join(CONTROL_DB_FILE))?;
        let txn = db.begin_write()?;
        {
            txn.open_table(SCHEMA)?
                .insert("version", SCHEMA_VERSION - 1)?;
            txn.open_table(CHUNK_INDEX)?
                .insert(malformed.as_bytes(), b"not cbor".as_slice())?;
            let mut meta = txn.open_table(CHUNK_INDEX_META)?;
            meta.remove(b"total_bytes".as_slice())?;
            meta.remove(b"summary_dirty".as_slice())?;
        }
        txn.commit()?;
    }

    let control = Control::open(dir.path())?;
    let index = control
        .store
        .get_index()
        .expect("control store has an index");
    assert_eq!(index.count()?, 2);
    assert!(
        control
            .stats()
            .unwrap_err()
            .to_string()
            .contains("summary is dirty"),
        "a dirty summary must never become successful metrics"
    );

    let attempted = Cid::compute(b"counter-dependent mutation");
    assert!(index
        .insert(
            &attempted,
            ChunkLocation {
                path: "/data/attempted".into(),
                length: 26,
                sha256_hash: attempted.to_hex(),
            },
        )
        .unwrap_err()
        .to_string()
        .contains("summary is dirty"));
    assert!(
        index.get(&attempted)?.is_none(),
        "the refused mutation must roll its index row back"
    );
    drop(index);
    drop(control);

    // Schema upgrade and summary-state publication are separate redb
    // transactions. Prove the first one is already durable before the
    // operator runs recovery, then prove the dirty marker survives reopen.
    assert_eq!(read_version(&dir)?, Some(SCHEMA_VERSION));
    let control = Control::open(dir.path())?;
    let index = control
        .store
        .get_index()
        .expect("control store has an index");
    assert!(control
        .stats()
        .unwrap_err()
        .to_string()
        .contains("summary is dirty"));

    // This is the storage operation behind `dag index reindex`.
    assert_eq!(control.store.reindex()?, 1);
    let stats = control.stats()?;
    assert_eq!(stats.chunks, 1);
    assert_eq!(stats.bytes, good_bytes.len() as u64);
    assert!(index.get(&malformed)?.is_none());
    drop(index);
    drop(control);
    Ok(())
}

#[test]
fn an_existing_unversioned_directory_is_adopted_not_refused() -> Result<()> {
    // Every directory written before this check existed has no version. They
    // are version 1 — refusing them would strand every deployment in the
    // field to gain nothing.
    let dir = TempDir::new()?;
    let cid = {
        let control = Control::open(dir.path())?;
        let cid = control
            .store
            .put_chunk(b"written before versioning", None)?;
        control.pointer_log.create("thing", cid.clone())?;
        // Remove the stamp, leaving an otherwise ordinary directory.
        let db = Database::create(dir.path().join(CONTROL_DB_FILE));
        drop(db);
        cid
    };
    {
        let db = Database::create(dir.path().join(CONTROL_DB_FILE))?;
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(SCHEMA)?;
            table.remove("version")?;
        }
        txn.commit()?;
    }

    let control = Control::open(dir.path())?;
    assert_eq!(control.pointer_log.resolve("thing")?, cid);
    drop(control);
    assert_eq!(
        read_version(&dir)?,
        Some(SCHEMA_VERSION),
        "and it is stamped on the way through, so the next open is a plain match"
    );
    Ok(())
}

#[test]
fn a_directory_from_a_newer_release_is_refused_with_the_remedy() -> Result<()> {
    let dir = TempDir::new()?;
    set_version(&dir, SCHEMA_VERSION + 1)?;

    let err = match Control::open(dir.path()) {
        Ok(_) => panic!("a directory this build cannot read must not open"),
        Err(e) => e,
    };

    match err {
        ControlError::SchemaTooNew { found, supported } => {
            assert_eq!(found, SCHEMA_VERSION + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("expected SchemaTooNew, got {other:?}"),
    }

    // The message has to point somewhere useful, because the failure mode it
    // replaces sent people to their backups.
    let text = err.to_string();
    assert!(
        text.contains("newer release") && text.contains("nothing is wrong with it"),
        "the message must say the directory is fine and the binary is old: {text}"
    );
    Ok(())
}

#[test]
fn refusing_a_newer_directory_leaves_it_untouched() -> Result<()> {
    let dir = TempDir::new()?;
    set_version(&dir, SCHEMA_VERSION + 3)?;

    assert!(Control::open(dir.path()).is_err());

    assert_eq!(
        read_version(&dir)?,
        Some(SCHEMA_VERSION + 3),
        "the check runs before any subsystem opens a table, so a refusal writes nothing"
    );

    // "Writes nothing" is a claim about *this layer*, and this is where it is
    // pinned down: a refused open must not have created a single subsystem
    // table. `check_and_stamp` runs before `ChunkIndex`, the logs, the event
    // journal and `RecoveryState` are constructed, each of which creates its
    // tables eagerly — so a real open leaves seventeen tables and a refused
    // one leaves only the `schema` table the newer binary already wrote. If
    // this ever grows a `pin_events` or a `recovery`, the refusal has started
    // running subsystems against a directory it does not understand.
    assert_eq!(
        table_names(&dir)?,
        vec!["schema".to_string()],
        "a refused open must not construct any subsystem's tables"
    );

    // Note on what is deliberately *not* asserted here: byte-for-byte
    // identity of `control.redb`. It does not hold, and asserting it would be
    // wrong. `redb::Database::create` rewrites its own superblock/commit
    // header (observed: a change at offset ~112, same file length) every time
    // it opens an existing file — this is redb's clean-open/recovery
    // bookkeeping, and it runs *before* `check_and_stamp` can refuse. The
    // guarantee the schema layer actually owns is the two assertions above:
    // the version is unchanged and no subsystem ran. The operative promise —
    // "nothing is wrong with it, run the newer binary" — survives that
    // benign redb write, because the version and all table data are intact.
    Ok(())
}

#[test]
fn a_truncated_control_database_is_an_error_not_a_panic() -> Result<()> {
    // The expected artifact of an interrupted copy, a full disk, or a killed
    // process. redb answers it with an assertion failure, which reached the
    // operator as exit 101 and a path inside ~/.cargo/registry.
    let dir = TempDir::new()?;
    {
        let control = Control::open(dir.path())?;
        control.store.put_chunk(b"some content", None)?;
    }

    let path = dir.path().join(CONTROL_DB_FILE);
    let len = std::fs::metadata(&path)?.len();
    let file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.set_len(len / 2)?;
    drop(file);

    // Snapshot the half-written file. Unlike a *valid* redb file — which redb
    // rewrites on open — a truncated one fails redb's header read and panics
    // before it writes anything, so a refused open must leave these bytes
    // exactly as they are. If that ever stops holding, "restore it or move it
    // aside" is no longer safe advice: a failed open would be corrupting the
    // evidence an operator is about to recover from.
    let before = std::fs::read(&path)?;

    match Control::open(dir.path()) {
        Ok(_) => panic!("a half-written database must not open"),
        Err(ControlError::ControlDbUnreadable { ref path, .. }) => {
            assert!(path.contains(CONTROL_DB_FILE), "the message names the file");
            let text = Control::open(dir.path()).err().unwrap().to_string();
            assert!(
                text.contains("rebuild") || text.contains("restore"),
                "and says what to do about it: {text}"
            );
        }
        Err(other) => panic!("expected ControlDbUnreadable, got {other:?}"),
    }

    let after = std::fs::read(&path)?;
    assert_eq!(
        before, after,
        "a failed open of a truncated database must not modify it — twice over, \
         since the assertions above opened it a second time"
    );
    Ok(())
}

/// The truncated-database recovery above is not self-contained: it depends on
/// a release-profile setting that lives in the workspace `Cargo.toml`, and
/// nothing else in the tree fails if that setting is changed.
///
/// `Control::open` wraps `redb::Database::create` in `catch_unwind`, because
/// redb answers a truncated file with a panic deep in its page manager rather
/// than an `Err`. Catching a panic requires it to *unwind*. Under
/// `panic = "abort"` the same truncated file would abort the whole process —
/// SIGABRT, exit 134, no `ControlError`, no message naming the file — which is
/// precisely the operator experience the `ControlDbUnreadable` path exists to
/// replace. The coupling is invisible: flip the profile to `abort` and every
/// test in this file still passes under `cargo test` (which builds the dev
/// profile, still unwind), while the shipped release binary silently loses the
/// recovery. This test is the tripwire.
#[test]
fn the_release_profile_must_unwind_or_a_torn_database_aborts() -> Result<()> {
    // CARGO_MANIFEST_DIR is crates/dag-control; the workspace root is two up.
    let workspace_toml = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Cargo.toml");
    let text = std::fs::read_to_string(&workspace_toml)
        .unwrap_or_else(|e| panic!("reading {}: {e}", workspace_toml.display()));

    let panic_strategy = profile_release_panic(&text).unwrap_or_else(|| {
        panic!(
            "[profile.release] in {} sets no `panic` strategy; it must be \
             `panic = \"unwind\"` so Control::open can catch redb's \
             truncated-file panic. Under the default/`abort`, that panic \
             aborts the process (exit 134) instead of becoming \
             ControlError::ControlDbUnreadable.",
            workspace_toml.display()
        )
    });

    assert_eq!(
        panic_strategy, "unwind",
        "[profile.release] sets panic = {panic_strategy:?}, but Control::open \
         relies on catch_unwind to turn redb's truncated-file panic into \
         ControlError::ControlDbUnreadable. Under panic = \"abort\" that panic \
         becomes a process abort (SIGABRT, exit 134) with no error and no file \
         named — the exact backtrace-to-cargo-registry experience the \
         ControlDbUnreadable path was written to remove."
    );
    Ok(())
}

/// The `panic` value set directly under `[profile.release]`, if any.
///
/// A deliberately small, format-tolerant scan rather than a TOML-parser
/// dependency: it reads the `[profile.release]` table (stopping at the next
/// `[...]` header, so it never wanders into `[profile.release.build-override]`
/// or another profile), strips `#` comments, and returns the unquoted value of
/// a `panic` key. It tolerates surrounding whitespace and `panic="abort"` with
/// or without spaces.
fn profile_release_panic(cargo_toml: &str) -> Option<String> {
    let mut in_section = false;
    for line in cargo_toml.lines() {
        // Strip a trailing comment. Values here never contain '#'.
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_section = code == "[profile.release]";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(rest) = code.strip_prefix("panic") {
            // The key must be exactly `panic`, so what follows (once trimmed)
            // is the `=`. This rejects e.g. a hypothetical `panic_abort` key.
            if let Some(value) = rest.trim_start().strip_prefix('=') {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}
