//! The CID→location index, backed by redb.
//!
//! The index is derived data: the filesystem under `data/` is the truth, and
//! [`crate::FsStore::reindex`] can rebuild this table from it at any time.
//! It exists so lookups and integrity scans don't have to walk the directory
//! tree.

use dag_core::{Cid, CoreError};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

/// Where a chunk's bytes live on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkLocation {
    /// Absolute path recorded when the chunk was written — a diagnostic, not
    /// an address.
    ///
    /// It is machine-local and does not survive a move, a copy or a restore,
    /// so nothing that reads bytes may follow it: derive the path from the
    /// store's own data directory with [`crate::FsStore::chunk_path`], as
    /// every read path and the integrity scanner do. Following this field is
    /// how `dag index verify` once re-hashed a *different* directory than the
    /// one it was pointed at.
    pub path: String,
    pub length: u64,
    pub sha256_hash: String,
}

const CHUNK_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chunk_index");
const CHUNK_INDEX_META: TableDefinition<&[u8], u64> = TableDefinition::new("chunk_index_meta");
const META_TOTAL_BYTES: &[u8] = b"total_bytes";
/// Monotonic epoch incremented only when the complete derived index is
/// replaced. Recovery records the epoch it certified, so running `reindex`
/// can never accidentally preserve an older recovery verdict.
const META_REBUILD_GENERATION: &[u8] = b"rebuild_generation";
/// Presence means the byte summary could not be derived from a legacy index.
///
/// The value is deliberately immaterial: presence is the fail-closed state,
/// and only a complete [`ChunkIndex::replace_all`] is allowed to clear it.
const META_SUMMARY_DIRTY: &[u8] = b"summary_dirty";
const MAX_INTEGRITY_PAGE_ROWS: usize = 256;
/// A location contains one local path, a u64 length, and one SHA-256 string.
/// Leave generous path/encoding headroom while refusing a locally forged or
/// untrusted-restored redb value before CBOR can allocate from it.
const MAX_ENCODED_CHUNK_LOCATION_BYTES: usize = 16 * 1024;

/// CID→[`ChunkLocation`] index.
///
/// Either owns its own single-file redb database, or shares one with the rest
/// of the control plane — `Control` passes its database in so that the whole
/// deployment is one file.
pub struct ChunkIndex {
    db: Arc<Database>,
}

fn db_err(e: impl std::fmt::Display) -> CoreError {
    CoreError::Backend(format!("chunk index: {}", e))
}

impl ChunkIndex {
    /// Open (creating if needed) a standalone index database at `path`.
    ///
    /// `path` names a file, not a directory — redb is single-file.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, CoreError> {
        let db = Database::create(path).map_err(db_err)?;
        Self::with_database(Arc::new(db))
    }

    /// Build the index over an already-open database, creating its table.
    pub fn with_database(db: Arc<Database>) -> Result<Self, CoreError> {
        // Create the table up front: opening a missing table in a read
        // transaction is an error, and every read path would otherwise have to
        // special-case the first run.
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(CHUNK_INDEX).map_err(db_err)?;
        txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;

        let needs_summary = {
            let meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
            let total_missing = meta.get(META_TOTAL_BYTES).map_err(db_err)?.is_none();
            let already_dirty = meta.get(META_SUMMARY_DIRTY).map_err(db_err)?.is_some();
            total_missing && !already_dirty
        };
        if needs_summary {
            // One-time upgrade for databases created before transactional
            // counters existed. A malformed derived row must not strand the
            // deployment before `dag index reindex` can run, but neither may
            // it become a reassuring false total. Persist an explicit dirty
            // state and make every counter-dependent operation refuse until a
            // complete replace-all repairs both rows and summary atomically.
            let derived = derive_legacy_total(&txn)?;
            let mut meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
            match derived {
                LegacyTotal::Valid(total) => {
                    meta.insert(META_TOTAL_BYTES, total).map_err(db_err)?;
                }
                LegacyTotal::Dirty(reason) => {
                    meta.remove(META_TOTAL_BYTES).map_err(db_err)?;
                    meta.insert(META_SUMMARY_DIRTY, 1).map_err(db_err)?;
                    tracing::warn!(
                        error = %reason,
                        "legacy chunk index summary is dirty; run `dag index reindex` before writes or metrics"
                    );
                }
            }
        }
        {
            let mut meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
            let missing = meta.get(META_REBUILD_GENERATION).map_err(db_err)?.is_none();
            if missing {
                meta.insert(META_REBUILD_GENERATION, 0).map_err(db_err)?;
            }
        }
        txn.commit().map_err(db_err)?;
        Ok(Self { db })
    }

    pub fn insert(&self, cid: &Cid, location: ChunkLocation) -> Result<(), CoreError> {
        let value = encode_location(&location)?;

        let txn = self.db.begin_write().map_err(db_err)?;
        let prior_length = {
            let mut table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
            let prior = table
                .insert(cid.as_bytes(), value.as_slice())
                .map_err(db_err)?;
            prior
                .map(|value| decode_location(value.value()).map(|location| location.length))
                .transpose()?
                .unwrap_or(0)
        };
        update_total_bytes(&txn, prior_length, location.length)?;
        txn.commit().map_err(db_err)?;

        debug!("Indexed chunk {} at {}", cid, location.path);
        Ok(())
    }

    /// Insert a batch of locations in a single transaction.
    ///
    /// One commit — and so one fsync — for the whole batch, where the
    /// per-chunk form pays one each. That difference is most of what a
    /// deferred bulk write saves: the index commits with redb's immediate
    /// durability, so before this existed a chunked ingest paid a device
    /// flush per chunk here no matter what the chunk store did.
    ///
    /// An empty batch commits nothing, so a flush with no owed entries costs
    /// no I/O at all.
    pub fn insert_many(&self, entries: &[(Cid, ChunkLocation)]) -> Result<(), CoreError> {
        if entries.is_empty() {
            return Ok(());
        }

        let encoded = entries
            .iter()
            .map(|(cid, location)| Ok((cid, location, encode_location(location)?)))
            .collect::<Result<Vec<_>, CoreError>>()?;

        let txn = self.db.begin_write().map_err(db_err)?;
        let mut total = read_total_bytes(&txn)?;
        {
            let mut table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
            for (cid, location, value) in encoded {
                let prior = table
                    .insert(cid.as_bytes(), value.as_slice())
                    .map_err(db_err)?;
                let prior_length = prior
                    .map(|value| decode_location(value.value()).map(|old| old.length))
                    .transpose()?
                    .unwrap_or(0);
                total = adjusted_total(total, prior_length, location.length)?;
            }
        }
        write_total_bytes(&txn, total)?;
        txn.commit().map_err(db_err)?;

        debug!("Indexed {} chunks in one transaction", entries.len());
        Ok(())
    }

    pub fn get(&self, cid: &Cid) -> Result<Option<ChunkLocation>, CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;

        match table.get(cid.as_bytes()).map_err(db_err)? {
            Some(guard) => {
                let location = decode_location(guard.value())?;
                Ok(Some(location))
            }
            None => Ok(None),
        }
    }

    /// Remove many entries in one committed transaction.
    ///
    /// One commit — one durable write — for the whole batch, which is what
    /// makes large collections affordable: per-entry commits put an fsync
    /// under every deletion, measured at ~5.6 ms each (scale-envelope
    /// experiment), which is ninety minutes for a million chunks.
    ///
    /// Returns how many of `cids` were actually present.
    pub fn remove_batch(&self, cids: &[Cid]) -> Result<usize, CoreError> {
        if cids.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        let mut existed = 0usize;
        let mut total = read_total_bytes(&txn)?;
        {
            let mut table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
            for cid in cids {
                if let Some(prior) = table.remove(cid.as_bytes()).map_err(db_err)? {
                    let length = decode_location(prior.value())?.length;
                    total = adjusted_total(total, length, 0)?;
                    existed = existed.checked_add(1).ok_or_else(|| {
                        CoreError::Backend("removed chunk count does not fit usize".into())
                    })?;
                }
            }
        }
        write_total_bytes(&txn, total)?;
        txn.commit().map_err(db_err)?;
        Ok(existed)
    }

    pub fn remove(&self, cid: &Cid) -> Result<bool, CoreError> {
        let txn = self.db.begin_write().map_err(db_err)?;
        let prior_length = {
            let mut table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
            // The guard returned by remove borrows the table and must drop
            // before it (redb 4.0 enforces this with a Drop impl).
            let prior = table.remove(cid.as_bytes()).map_err(db_err)?;
            prior
                .map(|value| decode_location(value.value()).map(|location| location.length))
                .transpose()?
        };
        if let Some(length) = prior_length {
            update_total_bytes(&txn, length, 0)?;
        }
        txn.commit().map_err(db_err)?;

        if prior_length.is_some() {
            debug!("Removed chunk {} from index", cid);
        }

        Ok(prior_length.is_some())
    }

    /// Atomically replace the complete derived index and its counters.
    ///
    /// Reindex callers first validate every filesystem candidate, then commit
    /// the replacement in one transaction. A failed walk therefore leaves the
    /// old usable index intact instead of publishing an empty/partial rebuild.
    pub fn replace_all(&self, entries: &[(Cid, ChunkLocation)]) -> Result<(), CoreError> {
        let mut seen = HashSet::with_capacity(entries.len());
        let mut total = 0u64;
        let mut encoded = Vec::with_capacity(entries.len());
        for (cid, location) in entries {
            if !seen.insert(cid.as_bytes().to_vec()) {
                return Err(CoreError::Backend(format!(
                    "duplicate CID {cid} in replacement chunk index"
                )));
            }
            total = total.checked_add(location.length).ok_or_else(|| {
                CoreError::Backend("chunk index byte total exceeds u64::MAX".into())
            })?;
            encoded.push((cid, encode_location(location)?));
        }

        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
            table.retain(|_, _| false).map_err(db_err)?;
            for (cid, value) in encoded {
                table
                    .insert(cid.as_bytes(), value.as_slice())
                    .map_err(db_err)?;
            }
        }
        repair_total_bytes(&txn, total)?;
        {
            let mut meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
            let current = meta
                .get(META_REBUILD_GENERATION)
                .map_err(db_err)?
                .map(|value| value.value())
                .unwrap_or(0);
            let next = current.checked_add(1).ok_or_else(|| {
                CoreError::Backend("chunk index rebuild generation overflowed".into())
            })?;
            meta.insert(META_REBUILD_GENERATION, next).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Epoch of the last complete index replacement.
    pub fn rebuild_generation(&self) -> Result<u64, CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
        Ok(meta
            .get(META_REBUILD_GENERATION)
            .map_err(db_err)?
            .map(|value| value.value())
            .unwrap_or(0))
    }

    /// Prove that a filesystem inventory and this derived index name exactly
    /// the same CID set before a destructive collection starts.
    pub fn validate_gc_inventory(&self, filesystem_cids: &[Cid]) -> Result<(), CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
        let indexed = usize::try_from(table.len().map_err(db_err)?)
            .map_err(|_| CoreError::Backend("chunk index count does not fit usize".into()))?;
        if indexed != filesystem_cids.len() {
            return Err(CoreError::GcIndexMismatch {
                filesystem: filesystem_cids.len(),
                indexed,
                detail: "the two inventories have different cardinalities".into(),
            });
        }

        for cid in filesystem_cids {
            let Some(value) = table.get(cid.as_bytes()).map_err(db_err)? else {
                return Err(CoreError::GcIndexMismatch {
                    filesystem: filesystem_cids.len(),
                    indexed,
                    detail: format!("filesystem CID {cid} has no index row"),
                });
            };
            // A malformed row is not an inventory witness. Decode it here so
            // matching keys alone cannot bless a damaged restored index.
            decode_location(value.value())?;
        }
        Ok(())
    }

    /// Prove that every CID from a previously exact filesystem snapshot still
    /// has a well-formed index witness.
    ///
    /// Unlike [`Self::validate_gc_inventory`], rows added after the snapshot
    /// are allowed. They are not deletion candidates in the prepared pass, so
    /// treating them as corruption would make normal concurrent ingestion
    /// spuriously close the recovery gate.
    pub fn validate_gc_snapshot(&self, prepared_cids: &[Cid]) -> Result<(), CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
        let indexed = usize::try_from(table.len().map_err(db_err)?)
            .map_err(|_| CoreError::Backend("chunk index count does not fit usize".into()))?;
        if indexed < prepared_cids.len() {
            return Err(CoreError::GcIndexMismatch {
                filesystem: prepared_cids.len(),
                indexed,
                detail: "the index has fewer rows than the prepared filesystem snapshot".into(),
            });
        }

        for cid in prepared_cids {
            let Some(value) = table.get(cid.as_bytes()).map_err(db_err)? else {
                return Err(CoreError::GcIndexMismatch {
                    filesystem: prepared_cids.len(),
                    indexed,
                    detail: format!("prepared filesystem CID {cid} has no index row"),
                });
            };
            // Matching keys alone cannot bless a damaged restored index.
            decode_location(value.value())?;
        }
        Ok(())
    }

    /// Every indexed CID.
    ///
    /// Returns a collected `Vec` rather than an iterator: a redb iterator
    /// borrows its read transaction, and the index at control-plane scale is
    /// small enough that materialising it is cheaper than threading that
    /// lifetime through every caller.
    pub fn cids(&self) -> Result<Vec<Cid>, CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;

        let mut out = Vec::new();
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (key, _) = item.map_err(db_err)?;
            out.push(Cid::from_bytes(key.value()).map_err(db_err)?);
        }
        Ok(out)
    }

    /// A bounded page of CID and expected-length pairs for integrity scanning.
    ///
    /// The cursor is exclusive and rows are ordered by the CID's canonical
    /// bytes. Each call owns only one short read transaction, so a full scan
    /// neither materialises the complete index nor pins one database snapshot
    /// while chunk bytes are being hashed.
    pub(crate) fn integrity_page_after(
        &self,
        after: Option<&Cid>,
        limit: usize,
    ) -> Result<Vec<(Cid, u64)>, CoreError> {
        // This is intentionally enforced here as well as by the scanner. A
        // future crate-internal caller must not be able to turn a bounded page
        // helper into an attacker-sized preallocation by passing usize::MAX.
        let limit = limit.min(MAX_INTEGRITY_PAGE_ROWS);
        if limit == 0 {
            return Ok(Vec::new());
        }

        use std::ops::Bound::{Excluded, Unbounded};

        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
        let range = (
            after.map_or(Unbounded, |cid| Excluded(cid.as_bytes())),
            Unbounded,
        );
        let mut out = Vec::with_capacity(limit);
        for item in table.range::<&[u8]>(range).map_err(db_err)?.take(limit) {
            let (key, value) = item.map_err(db_err)?;
            let cid = Cid::from_bytes(key.value()).map_err(db_err)?;
            let length = decode_location(value.value())?.length;
            out.push((cid, length));
        }
        Ok(out)
    }

    /// Count indexed chunks while preserving database failures.
    ///
    /// Treating an unreadable index as empty changes “database error” into
    /// “database was lost”, which is unsafe both for operator reports and for
    /// recovery decisions.
    pub fn count(&self) -> Result<usize, CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
        usize::try_from(table.len().map_err(db_err)?)
            .map_err(|_| CoreError::Backend("chunk index count does not fit usize".into()))
    }

    /// How many chunks the index tracks, and how many bytes they hold.
    ///
    /// O(1): redb maintains the row count and every index mutation updates the
    /// byte total in the same transaction. Public metrics therefore cannot be
    /// turned into an index-sized decode scan.
    pub fn summary(&self) -> Result<(usize, u64), CoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
        let chunks = usize::try_from(table.len().map_err(db_err)?)
            .map_err(|_| CoreError::Backend("chunk index count does not fit usize".into()))?;
        drop(table);
        let meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
        if meta.get(META_SUMMARY_DIRTY).map_err(db_err)?.is_some() {
            return Err(dirty_summary_error());
        }
        let bytes = meta
            .get(META_TOTAL_BYTES)
            .map_err(db_err)?
            .ok_or_else(|| CoreError::Backend("chunk index byte counter is missing".into()))?
            .value();
        Ok((chunks, bytes))
    }
}

fn encode_location(location: &ChunkLocation) -> Result<Vec<u8>, CoreError> {
    let mut value = Vec::new();
    ciborium::ser::into_writer(location, &mut value).map_err(|error| {
        CoreError::Serialization(format!("Failed to serialize ChunkLocation: {error}"))
    })?;
    Ok(value)
}

fn decode_location(value: &[u8]) -> Result<ChunkLocation, CoreError> {
    if value.len() > MAX_ENCODED_CHUNK_LOCATION_BYTES {
        return Err(CoreError::Deserialization(format!(
            "encoded ChunkLocation is {} bytes; limit is {}",
            value.len(),
            MAX_ENCODED_CHUNK_LOCATION_BYTES
        )));
    }
    let mut cursor = std::io::Cursor::new(value);
    let location = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| CoreError::Deserialization(error.to_string()))?;
    let consumed = usize::try_from(cursor.position()).map_err(|_| {
        CoreError::Deserialization("encoded ChunkLocation length does not fit usize".into())
    })?;
    if consumed != value.len() {
        return Err(CoreError::Deserialization(
            "encoded ChunkLocation has trailing bytes".into(),
        ));
    }
    Ok(location)
}

enum LegacyTotal {
    Valid(u64),
    Dirty(String),
}

/// Derive the first transactional summary without converting physical redb
/// failures into repairable row damage.
///
/// A malformed location or an impossible aggregate is derived-index damage:
/// reindex can replace it from the filesystem. Failure to iterate the redb
/// table itself remains a hard database error because there is no evidence a
/// replacement transaction can safely operate on that database.
fn derive_legacy_total(txn: &redb::WriteTransaction) -> Result<LegacyTotal, CoreError> {
    let table = txn.open_table(CHUNK_INDEX).map_err(db_err)?;
    let mut bytes = 0u64;
    for item in table.iter().map_err(db_err)? {
        let (_key, value) = item.map_err(db_err)?;
        let location = match decode_location(value.value()) {
            Ok(location) => location,
            Err(error) => return Ok(LegacyTotal::Dirty(error.to_string())),
        };
        let Some(total) = bytes.checked_add(location.length) else {
            return Ok(LegacyTotal::Dirty(
                "chunk index byte total exceeds u64::MAX".into(),
            ));
        };
        bytes = total;
    }
    Ok(LegacyTotal::Valid(bytes))
}

fn dirty_summary_error() -> CoreError {
    CoreError::Backend(
        "chunk index byte summary is dirty; run `dag index reindex` to repair it".into(),
    )
}

fn read_total_bytes(txn: &redb::WriteTransaction) -> Result<u64, CoreError> {
    let meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
    if meta.get(META_SUMMARY_DIRTY).map_err(db_err)?.is_some() {
        return Err(dirty_summary_error());
    }
    let total = meta
        .get(META_TOTAL_BYTES)
        .map_err(db_err)?
        .ok_or_else(|| CoreError::Backend("chunk index byte counter is missing".into()))?
        .value();
    Ok(total)
}

fn write_total_bytes(txn: &redb::WriteTransaction, total: u64) -> Result<(), CoreError> {
    let mut meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
    if meta.get(META_SUMMARY_DIRTY).map_err(db_err)?.is_some() {
        return Err(dirty_summary_error());
    }
    meta.insert(META_TOTAL_BYTES, total).map_err(db_err)?;
    Ok(())
}

/// Publish a completely rebuilt total and clear the dirty state in the same
/// transaction that replaced every index row.
fn repair_total_bytes(txn: &redb::WriteTransaction, total: u64) -> Result<(), CoreError> {
    let mut meta = txn.open_table(CHUNK_INDEX_META).map_err(db_err)?;
    meta.insert(META_TOTAL_BYTES, total).map_err(db_err)?;
    meta.remove(META_SUMMARY_DIRTY).map_err(db_err)?;
    Ok(())
}

fn adjusted_total(total: u64, old: u64, new: u64) -> Result<u64, CoreError> {
    total
        .checked_sub(old)
        .and_then(|without_old| without_old.checked_add(new))
        .ok_or_else(|| CoreError::Backend("chunk index byte counter overflow/underflow".into()))
}

fn update_total_bytes(txn: &redb::WriteTransaction, old: u64, new: u64) -> Result<(), CoreError> {
    let total = adjusted_total(read_total_bytes(txn)?, old, new)?;
    write_total_bytes(txn, total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_index() -> (ChunkIndex, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let index = ChunkIndex::new(temp_dir.path().join("index.redb")).unwrap();
        (index, temp_dir)
    }

    fn create_legacy_index(entries: &[(Cid, Vec<u8>)]) -> (std::path::PathBuf, TempDir) {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("legacy.redb");
        let db = Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(CHUNK_INDEX).unwrap();
            for (cid, value) in entries {
                table.insert(cid.as_bytes(), value.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
        drop(db);
        (path, temp)
    }

    fn assert_summary_is_dirty(index: &ChunkIndex) {
        let error = index.summary().unwrap_err();
        assert!(
            error.to_string().contains("summary is dirty"),
            "unexpected dirty-summary error: {error}"
        );

        let txn = index.db.begin_read().unwrap();
        let meta = txn.open_table(CHUNK_INDEX_META).unwrap();
        assert!(meta.get(META_TOTAL_BYTES).unwrap().is_none());
        assert_eq!(meta.get(META_SUMMARY_DIRTY).unwrap().unwrap().value(), 1);
    }

    #[test]
    fn encoded_locations_are_bounded_and_must_consume_the_complete_row() {
        let cid = Cid::compute(b"bounded location");
        let mut encoded = encode_location(&ChunkLocation {
            path: "/data/bounded".into(),
            length: 7,
            sha256_hash: cid.to_hex(),
        })
        .unwrap();
        encoded.push(0);
        assert!(decode_location(&encoded)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes"));

        let oversized = vec![0; MAX_ENCODED_CHUNK_LOCATION_BYTES + 1];
        assert!(decode_location(&oversized)
            .unwrap_err()
            .to_string()
            .contains("limit is"));
    }

    #[test]
    fn a_clean_legacy_index_gets_one_atomic_summary_backfill() {
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"bb");
        let entries = [
            (
                a.clone(),
                encode_location(&ChunkLocation {
                    path: "/data/a".into(),
                    length: 1,
                    sha256_hash: a.to_hex(),
                })
                .unwrap(),
            ),
            (
                b.clone(),
                encode_location(&ChunkLocation {
                    path: "/data/b".into(),
                    length: 2,
                    sha256_hash: b.to_hex(),
                })
                .unwrap(),
            ),
        ];
        let (path, _temp) = create_legacy_index(&entries);

        let index = ChunkIndex::new(&path).unwrap();
        assert_eq!(index.summary().unwrap(), (2, 3));
        drop(index);

        // Reopening consumes the persisted counter rather than changing it.
        let reopened = ChunkIndex::new(path).unwrap();
        assert_eq!(reopened.summary().unwrap(), (2, 3));
    }

    #[test]
    fn a_malformed_legacy_row_opens_dirty_and_reindex_repairs_it() {
        let malformed = Cid::compute(b"malformed legacy row");
        let legacy_valid = Cid::compute(b"valid legacy row");
        let valid_location = ChunkLocation {
            path: "/data/legacy-valid".into(),
            length: 16,
            sha256_hash: legacy_valid.to_hex(),
        };
        let (path, temp) = create_legacy_index(&[
            (malformed.clone(), b"not cbor".to_vec()),
            (
                legacy_valid.clone(),
                encode_location(&valid_location).unwrap(),
            ),
        ]);

        let index =
            Arc::new(ChunkIndex::new(&path).expect("derived corruption must not block open"));
        assert_eq!(index.count().unwrap(), 2);
        assert_summary_is_dirty(&index);

        // Counter-dependent writes fail without publishing a partial row.
        let attempted = Cid::compute(b"must roll back");
        let error = index
            .insert(
                &attempted,
                ChunkLocation {
                    path: "/data/attempted".into(),
                    length: 14,
                    sha256_hash: attempted.to_hex(),
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("summary is dirty"));
        assert_eq!(index.count().unwrap(), 2);
        assert!(index.get(&attempted).unwrap().is_none());

        let batched = Cid::compute(b"batched mutation");
        let batched_location = ChunkLocation {
            path: "/data/batched".into(),
            length: 16,
            sha256_hash: batched.to_hex(),
        };
        assert!(index
            .insert_many(&[(batched.clone(), batched_location)])
            .unwrap_err()
            .to_string()
            .contains("summary is dirty"));
        assert!(index.get(&batched).unwrap().is_none());

        assert!(index
            .remove(&legacy_valid)
            .unwrap_err()
            .to_string()
            .contains("summary is dirty"));
        assert!(index.get(&legacy_valid).unwrap().is_some());
        assert!(index
            .remove_batch(std::slice::from_ref(&legacy_valid))
            .unwrap_err()
            .to_string()
            .contains("summary is dirty"));
        assert!(index.get(&legacy_valid).unwrap().is_some());

        // Reindex derives a complete replacement from the filesystem and is
        // the sole path that clears the dirty state.
        let data_dir = temp.path().join("data");
        let bare = crate::FsStore::new(&data_dir).unwrap();
        let good = dag_core::ContentStore::put_chunk(&bare, b"intact bytes", None).unwrap();
        drop(bare);
        let store = crate::FsStore::with_chunk_index(data_dir, Arc::clone(&index)).unwrap();
        assert_eq!(store.reindex().unwrap(), 1);
        assert_eq!(index.summary().unwrap(), (1, 12));
        assert!(index.get(&malformed).unwrap().is_none());
        assert!(index.get(&good).unwrap().is_some());

        drop(store);
        drop(index);
        let reopened = ChunkIndex::new(path).unwrap();
        assert_eq!(reopened.summary().unwrap(), (1, 12));
    }

    #[test]
    fn an_overflowing_legacy_summary_is_marked_dirty_not_published() {
        let a = Cid::compute(b"max");
        let b = Cid::compute(b"overflow");
        let location = |cid: &Cid, length| {
            encode_location(&ChunkLocation {
                path: format!("/data/{cid}"),
                length,
                sha256_hash: cid.to_hex(),
            })
            .unwrap()
        };
        let (path, _temp) = create_legacy_index(&[
            (a.clone(), location(&a, u64::MAX)),
            (b.clone(), location(&b, 1)),
        ]);

        let index = ChunkIndex::new(path).expect("overflow is repairable derived-index damage");
        assert_eq!(index.count().unwrap(), 2);
        assert_summary_is_dirty(&index);
    }

    #[test]
    fn test_insert_get_roundtrip() {
        let (index, _temp_dir) = create_test_index();
        let cid = Cid::compute(b"test data");
        let location = ChunkLocation {
            path: "/data/ab/cdef...".to_string(),
            length: 9,
            sha256_hash: cid.to_hex(),
        };

        index.insert(&cid, location.clone()).unwrap();
        let retrieved = index.get(&cid).unwrap().unwrap();

        assert_eq!(location.path, retrieved.path);
        assert_eq!(location.length, retrieved.length);
        assert_eq!(location.sha256_hash, retrieved.sha256_hash);
    }

    #[test]
    fn test_get_nonexistent() {
        let (index, _temp_dir) = create_test_index();
        let cid = Cid::compute(b"nonexistent");

        let result = index.get(&cid).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_remove() {
        let (index, _temp_dir) = create_test_index();
        let cid = Cid::compute(b"test data");
        let location = ChunkLocation {
            path: "/data/test".to_string(),
            length: 9,
            sha256_hash: cid.to_hex(),
        };

        index.insert(&cid, location).unwrap();
        assert!(index.get(&cid).unwrap().is_some());

        let existed = index.remove(&cid).unwrap();
        assert!(existed);
        assert!(index.get(&cid).unwrap().is_none());

        let existed_again = index.remove(&cid).unwrap();
        assert!(!existed_again);
    }

    #[test]
    fn test_count_and_iter() {
        let (index, _temp_dir) = create_test_index();

        assert_eq!(index.count().unwrap(), 0);

        let cids: Vec<_> = (0..5)
            .map(|i| {
                let cid = Cid::compute(&i.to_string().into_bytes());
                let location = ChunkLocation {
                    path: format!("/data/{}", i),
                    length: 1,
                    sha256_hash: cid.to_hex(),
                };
                index.insert(&cid, location).unwrap();
                cid
            })
            .collect();

        assert_eq!(index.count().unwrap(), 5);

        let retrieved_cids = index.cids().unwrap();
        assert_eq!(retrieved_cids.len(), 5);

        for cid in &cids {
            assert!(retrieved_cids.contains(cid));
        }

        assert_eq!(index.summary().unwrap(), (5, 5));
    }

    #[test]
    fn summary_counters_track_replacement_batch_and_removal() {
        let (index, _temp_dir) = create_test_index();
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"bb");
        let location = |cid: &Cid, length| ChunkLocation {
            path: format!("/data/{cid}"),
            length,
            sha256_hash: cid.to_hex(),
        };

        index.insert(&a, location(&a, 1)).unwrap();
        index.insert(&a, location(&a, 7)).unwrap();
        index.insert_many(&[(b.clone(), location(&b, 2))]).unwrap();
        assert_eq!(index.summary().unwrap(), (2, 9));

        assert!(index.remove(&a).unwrap());
        assert_eq!(index.summary().unwrap(), (1, 2));
        assert_eq!(index.remove_batch(&[b.clone(), b]).unwrap(), 1);
        assert_eq!(index.summary().unwrap(), (0, 0));
    }

    #[test]
    fn integrity_pages_are_bounded_ordered_and_resume_exclusively() {
        let (index, _temp_dir) = create_test_index();
        let mut expected = Vec::new();
        for byte in 0u8..9 {
            let cid = Cid::compute(&[byte]);
            index
                .insert(
                    &cid,
                    ChunkLocation {
                        path: format!("/data/{cid}"),
                        length: u64::from(byte) + 1,
                        sha256_hash: cid.to_hex(),
                    },
                )
                .unwrap();
            expected.push((cid, u64::from(byte) + 1));
        }
        expected.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

        let mut actual = Vec::new();
        let mut cursor = None;
        loop {
            let page = index.integrity_page_after(cursor.as_ref(), 2).unwrap();
            assert!(page.len() <= 2);
            if page.is_empty() {
                break;
            }
            cursor = page.last().map(|(cid, _)| cid.clone());
            actual.extend(page);
        }

        assert_eq!(actual, expected);

        let oversized = index.integrity_page_after(None, usize::MAX).unwrap();
        assert!(oversized.len() <= MAX_INTEGRITY_PAGE_ROWS);
    }

    #[test]
    fn replace_all_is_complete_and_rejects_duplicates() {
        let (index, _temp_dir) = create_test_index();
        let old = Cid::compute(b"old");
        index
            .insert(
                &old,
                ChunkLocation {
                    path: "/data/old".into(),
                    length: 99,
                    sha256_hash: old.to_hex(),
                },
            )
            .unwrap();

        let fresh = Cid::compute(b"fresh");
        let fresh_location = ChunkLocation {
            path: "/data/fresh".into(),
            length: 5,
            sha256_hash: fresh.to_hex(),
        };
        index
            .replace_all(&[(fresh.clone(), fresh_location.clone())])
            .unwrap();
        assert!(index.get(&old).unwrap().is_none());
        assert!(index.get(&fresh).unwrap().is_some());
        assert_eq!(index.summary().unwrap(), (1, 5));

        let error = index
            .replace_all(&[
                (fresh.clone(), fresh_location.clone()),
                (fresh, fresh_location),
            ])
            .unwrap_err();
        assert!(error.to_string().contains("duplicate CID"));
        assert_eq!(index.summary().unwrap(), (1, 5));
    }

    /// The index must be shareable with a database owned by someone else —
    /// that is how `Control` keeps the whole deployment in one file.
    #[test]
    fn test_shared_database() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(Database::create(temp_dir.path().join("shared.redb")).unwrap());

        let index = ChunkIndex::with_database(db.clone()).unwrap();
        let cid = Cid::compute(b"shared");
        index
            .insert(
                &cid,
                ChunkLocation {
                    path: "/data/shared".to_string(),
                    length: 6,
                    sha256_hash: cid.to_hex(),
                },
            )
            .unwrap();

        // A second view over the same database sees the same data.
        let again = ChunkIndex::with_database(db).unwrap();
        assert_eq!(again.count().unwrap(), 1);
        assert!(again.get(&cid).unwrap().is_some());
    }
}
