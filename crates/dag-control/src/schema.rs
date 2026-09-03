//! # On-disk schema version
//!
//! One number, written once, checked on every open.
//!
//! ## Why this exists
//!
//! Before it, nothing on disk recorded which version of the format had
//! written it — not `control.redb`, not `Entry`, not the key files. Version
//! detection was a single filesystem heuristic ("is `control.redb` absent and
//! a sled directory present"), which answers exactly one historical question
//! and cannot answer a future one. All sixteen redb tables are
//! `TableDefinition<&[u8], &[u8]>`, so redb's own table-type check can never
//! fire either: the schema lives in opaque blobs it cannot inspect.
//!
//! The consequence that matters is the *newer file, older binary* case.
//! redb reports its own format skew as `Corrupted("Expected file format
//! version <= 3, found 4")`, and against a provenance store the word
//! "corrupted" sends an operator to restore from backup when the fix is
//! "run the newer binary". A version this layer owns lets that be said
//! plainly.
//!
//! ## What a version bump means
//!
//! Bump [`SCHEMA_VERSION`] when a directory written by the new code cannot be
//! read correctly by the old — a table's key or value encoding changes, a
//! stored enum gains a variant an older build would misread, a required field
//! appears on an event type. Adding a *purely additive table* does not need a bump: every
//! constructor creates its tables eagerly, so a new binary on an old database
//! already works, which is how the ADR-003 and ADR-004 tables arrived
//! silently. A table that becomes authoritative after destructive compaction
//! is not purely additive: an older binary ignoring it could reuse IDs, so
//! that change does require a bump. Nor does adding an optional field with
//! `skip_serializing_if = "Option::is_none"`, which is CID-preserving.
//!
//! When a bump does happen, this is the place to add the migration: the
//! version is read before any subsystem opens its tables.

use crate::error::{ControlError, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

/// The layout this build writes and understands.
///
/// - **1** — the redb layout introduced by ADR-001, retroactively named.
///   Directories written before this constant existed carry no version at
///   all and are adopted as version 1, which is what they are.
/// - **2** — `PinEvent` lost `importance`. A version-1 event still decodes
///   here (serde ignores the key), so a v1 directory is *upgraded in place*
///   on open rather than migrated. The reverse does not hold: a pin written
///   here has no `importance`, and a version-1 binary's `PinEvent` requires
///   one, so it would fail to decode. That asymmetry is the whole reason the
///   number moved.
/// - **3** — job run-ID watermarks survive terminal-history compaction. A
///   version-2 binary ignores the watermark and could lower `trigger_count`
///   during rebuild, reusing a compacted run ID, so downgrade must be refused.
/// - **4** — replication event pagination uses an authoritative generation
///   bumped with every pointer/pin log mutation. Older writers would leave it
///   stale, so downgrade must be refused.
/// - **5** — every runnable job row names an immutable filed job-event
///   revision, carries its resolved input snapshot, and participates in the
///   adapter/order index. Pre-v5 active rows cannot be executed safely after a
///   spec update, so the one-way migration terminalises them fail-closed.
pub const SCHEMA_VERSION: u32 = 5;

/// Versions this build can read and upgrade in place, lowest first.
///
/// Membership is a claim that *every* table written by that version decodes
/// correctly here — not merely that the directory opens. Adding a version to
/// this list without checking that is how a silent misread ships.
const UPGRADABLE_FROM: &[u32] = &[1, 2, 3, 4];

/// Typed on purpose, unlike the sixteen `&[u8]`-keyed tables around it: redb
/// checks the types it is given, and there is no reason to opt out of that
/// for a new table.
const SCHEMA: TableDefinition<&str, u32> = TableDefinition::new("schema");

const KEY_VERSION: &str = "version";
const KEY_JOB_V5_MIGRATION_PENDING: &str = "job_v5_migration_pending";

const JOB_EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("job_events");
pub(crate) const JOB_LEGACY_PREV_CUTOFFS: TableDefinition<&[u8], u64> =
    TableDefinition::new("job_legacy_prev_cutoffs");

fn db_err(e: impl std::fmt::Display) -> ControlError {
    ControlError::db("schema table", e)
}

/// What was found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaState {
    /// The directory is new, or predates versioning; it now carries
    /// [`SCHEMA_VERSION`].
    Stamped,
    /// The directory already declared a version this build understands.
    Current(u32),
    /// The directory declared an older version this build can read, and now
    /// carries [`SCHEMA_VERSION`].
    ///
    /// Worth surfacing rather than doing quietly: the upgrade is one-way from
    /// the operator's point of view. Nothing is rewritten, but once this build
    /// writes a pin the directory contains events an older binary cannot
    /// decode, and the stamp says so up front instead of letting them find out
    /// by downgrading.
    Upgraded { from: u32 },
}

/// Read the directory's schema version, refusing one this build cannot read,
/// and stamping one that has none.
///
/// Called before any other subsystem opens its tables, so a refusal happens
/// before anything writes.
pub fn check_and_stamp(db: &Database) -> Result<SchemaState> {
    let found = {
        let txn = db.begin_read().map_err(db_err)?;
        match txn.open_table(SCHEMA) {
            Ok(table) => table.get(KEY_VERSION).map_err(db_err)?.map(|v| v.value()),
            // No table yet: a fresh directory, or one written before this
            // check existed. Both are version 1 by definition.
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(db_err(e)),
        }
    };

    match found {
        Some(v) if v == SCHEMA_VERSION => Ok(SchemaState::Current(v)),
        Some(v) if v > SCHEMA_VERSION => Err(ControlError::SchemaTooNew {
            found: v,
            supported: SCHEMA_VERSION,
        }),
        // Older than we are, and readable: restamp so the version on disk
        // matches what will now be written to it. No data is rewritten —
        // schema 2 differs from 1 only by a field this build ignores on read
        // and omits on write.
        Some(v) if UPGRADABLE_FROM.contains(&v) => {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(SCHEMA).map_err(db_err)?;
                if v < 5 {
                    prepare_job_v5_migration(&txn, v == 1)?;
                    table
                        .insert(KEY_JOB_V5_MIGRATION_PENDING, 1)
                        .map_err(db_err)?;
                }
                table.insert(KEY_VERSION, SCHEMA_VERSION).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
            Ok(SchemaState::Upgraded { from: v })
        }
        // Older than we are and *not* readable. No such version exists yet,
        // but the branch is where one lands the day a change is not
        // backward-compatible, rather than being silently upgraded.
        Some(v) => Err(ControlError::SchemaTooOld {
            found: v,
            supported: SCHEMA_VERSION,
        }),
        None => {
            let txn = db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(SCHEMA).map_err(db_err)?;
                // An unstamped directory is schema 1 by definition. Derive
                // the only compatibility exception from rows that are
                // already filed, in the same commit as the version stamp.
                prepare_job_v5_migration(&txn, true)?;
                table
                    .insert(KEY_JOB_V5_MIGRATION_PENDING, 1)
                    .map_err(db_err)?;
                table.insert(KEY_VERSION, SCHEMA_VERSION).map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
            Ok(SchemaState::Stamped)
        }
    }
}

/// Persist the last sequence at which a schema-1 writer may have emitted an
/// `Updated` event without `prev`.
///
/// The exception is intentionally derived from the existing *filed* table,
/// never a content-store scan. A future planted event therefore cannot grow a
/// cutoff, and a lost database has no exception to reconstruct.
fn prepare_job_v5_migration(txn: &WriteTransaction, legacy_v1: bool) -> Result<()> {
    let mut cutoffs = txn.open_table(JOB_LEGACY_PREV_CUTOFFS).map_err(db_err)?;
    // No pre-v5 writer owned this table. Replace any planted/manual rows so
    // the only authority is the filed event set observed in this transaction.
    cutoffs.retain(|_, _| false).map_err(db_err)?;
    if !legacy_v1 {
        return Ok(());
    }

    let events = txn.open_table(JOB_EVENTS).map_err(db_err)?;
    let mut current_job: Option<Vec<u8>> = None;
    let mut current_max = 0u64;
    for row in events.range::<&[u8]>(..).map_err(db_err)? {
        let (key, _) = row.map_err(db_err)?;
        let (job, seq) = decode_job_event_key(key.value())?;
        if current_job.as_deref() != Some(job) {
            if let Some(previous) = current_job.take() {
                cutoffs
                    .insert(previous.as_slice(), current_max)
                    .map_err(db_err)?;
            }
            current_job = Some(job.to_vec());
            current_max = seq;
        } else {
            current_max = current_max.max(seq);
        }
    }
    if let Some(previous) = current_job {
        cutoffs
            .insert(previous.as_slice(), current_max)
            .map_err(db_err)?;
    }
    Ok(())
}

fn decode_job_event_key(key: &[u8]) -> Result<(&[u8], u64)> {
    let len_bytes: [u8; 4] = key
        .get(..4)
        .ok_or_else(|| {
            ControlError::Database("schema-5 migration found a truncated job-event key".into())
        })?
        .try_into()
        .expect("slice length checked");
    let len = u32::from_be_bytes(len_bytes) as usize;
    let end = 4usize.checked_add(len).ok_or_else(|| {
        ControlError::Database("schema-5 migration job-event key length overflowed".into())
    })?;
    if key.len()
        != end.checked_add(8).ok_or_else(|| {
            ControlError::Database("schema-5 migration job-event key length overflowed".into())
        })?
    {
        return Err(ControlError::Database(
            "schema-5 migration found a malformed job-event key".into(),
        ));
    }
    let job = &key[4..end];
    let job_id = std::str::from_utf8(job).map_err(|error| {
        ControlError::Database(format!(
            "schema-5 migration job-event key is not UTF-8: {error}"
        ))
    })?;
    dag_core::validate_job_id(job_id).map_err(|error| {
        ControlError::Database(format!(
            "schema-5 migration job-event key contains an invalid job ID: {error}"
        ))
    })?;
    let seq = u64::from_be_bytes(
        key[end..]
            .try_into()
            .expect("exact eight-byte suffix checked above"),
    );
    if seq == 0 {
        return Err(ControlError::Database(
            "schema-5 migration job-event key contains sequence zero".into(),
        ));
    }
    Ok((job, seq))
}

pub(crate) fn job_v5_migration_pending(db: &Database) -> Result<bool> {
    let txn = db.begin_read().map_err(db_err)?;
    let table = txn.open_table(SCHEMA).map_err(db_err)?;
    Ok(table
        .get(KEY_JOB_V5_MIGRATION_PENDING)
        .map_err(db_err)?
        .is_some())
}

pub(crate) fn finish_job_v5_migration(txn: &WriteTransaction) -> Result<()> {
    let mut table = txn.open_table(SCHEMA).map_err(db_err)?;
    table.remove(KEY_JOB_V5_MIGRATION_PENDING).map_err(db_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn db(dir: &TempDir) -> Database {
        Database::create(dir.path().join("control.redb")).unwrap()
    }

    #[test]
    fn a_fresh_directory_is_stamped_and_then_recognised() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);

        assert_eq!(check_and_stamp(&db).unwrap(), SchemaState::Stamped);
        assert_eq!(
            check_and_stamp(&db).unwrap(),
            SchemaState::Current(SCHEMA_VERSION),
            "the second open must see the stamp the first wrote"
        );
    }

    /// Older readable directories open here and are restamped, without a
    /// data rewrite.
    ///
    /// This is the claim that makes the schema-2 bump cheap for anyone
    /// already running: schema 2 differs from 1 only by a `PinEvent` field
    /// this build ignores on read, so nothing has to be rewritten. The
    /// companion check — that a schema-1 pin event still *decodes* — lives in
    /// `dag_core::pin`, because that is where the bytes are.
    #[test]
    fn a_version_1_directory_is_upgraded_in_place() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SCHEMA).unwrap();
            table.insert(KEY_VERSION, 1u32).unwrap();
        }
        txn.commit().unwrap();

        assert_eq!(
            check_and_stamp(&db).unwrap(),
            SchemaState::Upgraded { from: 1 },
            "a readable older directory must be upgraded, not refused"
        );
        assert_eq!(
            check_and_stamp(&db).unwrap(),
            SchemaState::Current(SCHEMA_VERSION),
            "the upgrade must be persisted, not recomputed every open"
        );
    }

    #[test]
    fn a_version_2_directory_is_upgraded_before_watermarks_are_written() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SCHEMA).unwrap();
            table.insert(KEY_VERSION, 2u32).unwrap();
        }
        txn.commit().unwrap();

        assert_eq!(
            check_and_stamp(&db).unwrap(),
            SchemaState::Upgraded { from: 2 }
        );
        assert_eq!(
            check_and_stamp(&db).unwrap(),
            SchemaState::Current(SCHEMA_VERSION)
        );
    }

    #[test]
    fn schema_one_cutoffs_replace_planted_rows_and_come_only_from_filed_events() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);
        let txn = db.begin_write().unwrap();
        {
            let mut schema = txn.open_table(SCHEMA).unwrap();
            schema.insert(KEY_VERSION, 1).unwrap();
            let mut cutoffs = txn.open_table(JOB_LEGACY_PREV_CUTOFFS).unwrap();
            cutoffs.insert(b"legacy".as_slice(), u64::MAX).unwrap();
            cutoffs.insert(b"planted".as_slice(), u64::MAX).unwrap();
            let mut events = txn.open_table(JOB_EVENTS).unwrap();
            let key = |job: &str, seq: u64| {
                let mut key = Vec::new();
                key.extend_from_slice(&(job.len() as u32).to_be_bytes());
                key.extend_from_slice(job.as_bytes());
                key.extend_from_slice(&seq.to_be_bytes());
                key
            };
            events
                .insert(key("legacy", 1).as_slice(), b"a".as_slice())
                .unwrap();
            events
                .insert(key("legacy", 2).as_slice(), b"b".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        assert_eq!(
            check_and_stamp(&db).unwrap(),
            SchemaState::Upgraded { from: 1 }
        );
        let txn = db.begin_read().unwrap();
        let cutoffs = txn.open_table(JOB_LEGACY_PREV_CUTOFFS).unwrap();
        assert_eq!(
            cutoffs.get(b"legacy".as_slice()).unwrap().unwrap().value(),
            2
        );
        assert!(cutoffs.get(b"planted".as_slice()).unwrap().is_none());
    }

    #[test]
    fn malformed_authoritative_event_keys_abort_the_upgrade_atomically() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);
        let txn = db.begin_write().unwrap();
        {
            txn.open_table(SCHEMA)
                .unwrap()
                .insert(KEY_VERSION, 1)
                .unwrap();
            txn.open_table(JOB_LEGACY_PREV_CUTOFFS)
                .unwrap()
                .insert(b"planted".as_slice(), u64::MAX)
                .unwrap();
            // Declares one byte of job ID, but that byte is not UTF-8.
            let invalid_utf8 = [0, 0, 0, 1, 0xff, 0, 0, 0, 0, 0, 0, 0, 1];
            txn.open_table(JOB_EVENTS)
                .unwrap()
                .insert(invalid_utf8.as_slice(), b"cid".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        assert!(matches!(
            check_and_stamp(&db),
            Err(ControlError::Database(_))
        ));
        let txn = db.begin_read().unwrap();
        let schema = txn.open_table(SCHEMA).unwrap();
        assert_eq!(schema.get(KEY_VERSION).unwrap().unwrap().value(), 1);
        let cutoffs = txn.open_table(JOB_LEGACY_PREV_CUTOFFS).unwrap();
        assert_eq!(
            cutoffs.get(b"planted".as_slice()).unwrap().unwrap().value(),
            u64::MAX,
            "the failed migration transaction must not partially clear or stamp state"
        );
    }

    #[test]
    fn non_legacy_upgrade_clears_any_planted_cutoff() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);
        let txn = db.begin_write().unwrap();
        {
            txn.open_table(SCHEMA)
                .unwrap()
                .insert(KEY_VERSION, 4)
                .unwrap();
            txn.open_table(JOB_LEGACY_PREV_CUTOFFS)
                .unwrap()
                .insert(b"forged".as_slice(), u64::MAX)
                .unwrap();
        }
        txn.commit().unwrap();
        check_and_stamp(&db).unwrap();
        let txn = db.begin_read().unwrap();
        let cutoffs = txn.open_table(JOB_LEGACY_PREV_CUTOFFS).unwrap();
        assert!(cutoffs.get(b"forged".as_slice()).unwrap().is_none());
    }

    /// An older version this build does *not* claim to read is refused rather
    /// than upgraded. Nothing hits this today; the test exists so that adding
    /// a version to `UPGRADABLE_FROM` is a deliberate act.
    #[test]
    fn an_unreadable_older_version_is_refused() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SCHEMA).unwrap();
            table.insert(KEY_VERSION, 0u32).unwrap();
        }
        txn.commit().unwrap();

        assert!(!UPGRADABLE_FROM.contains(&0), "test premise");
        match check_and_stamp(&db) {
            Err(ControlError::SchemaTooOld { found, .. }) => assert_eq!(found, 0),
            other => panic!("expected SchemaTooOld, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_from_the_future_is_refused_by_name() {
        let dir = TempDir::new().unwrap();
        let db = db(&dir);

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SCHEMA).unwrap();
            table.insert(KEY_VERSION, SCHEMA_VERSION + 7).unwrap();
        }
        txn.commit().unwrap();

        match check_and_stamp(&db) {
            Err(ControlError::SchemaTooNew { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 7);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }

    #[test]
    fn refusing_a_future_directory_does_not_write_to_it() {
        // The point of checking before anything else opens its tables: a
        // refusal must leave the directory exactly as the newer binary left
        // it, or "run the newer binary" stops being sound advice.
        let dir = TempDir::new().unwrap();
        let db = db(&dir);

        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SCHEMA).unwrap();
            table.insert(KEY_VERSION, SCHEMA_VERSION + 1).unwrap();
        }
        txn.commit().unwrap();

        assert!(check_and_stamp(&db).is_err());

        let txn = db.begin_read().unwrap();
        let table = txn.open_table(SCHEMA).unwrap();
        assert_eq!(
            table.get(KEY_VERSION).unwrap().unwrap().value(),
            SCHEMA_VERSION + 1,
            "the version we refused must still be the version on disk"
        );
    }
}
