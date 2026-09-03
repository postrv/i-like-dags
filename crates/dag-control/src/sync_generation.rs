//! Persisted O(1) generation for stable replication pagination.
//!
//! Every authoritative pointer/pin event mutation bumps this value in the
//! same redb transaction. A page request can therefore compare one eight-byte
//! value instead of rescanning the complete history.

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

const SYNC_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sync_meta");
const EVENT_GENERATION: &[u8] = b"event_generation";

pub(crate) fn initialize(db: &Database) -> Result<(), String> {
    let present = {
        let txn = db.begin_read().map_err(|error| error.to_string())?;
        match txn.open_table(SYNC_META) {
            Ok(table) => table
                .get(EVENT_GENERATION)
                .map_err(|error| error.to_string())?
                .is_some(),
            Err(redb::TableError::TableDoesNotExist(_)) => false,
            Err(error) => return Err(error.to_string()),
        }
    };
    if present {
        return Ok(());
    }
    let txn = db.begin_write().map_err(|error| error.to_string())?;
    {
        let mut table = txn
            .open_table(SYNC_META)
            .map_err(|error| error.to_string())?;
        if table
            .get(EVENT_GENERATION)
            .map_err(|error| error.to_string())?
            .is_none()
        {
            table
                .insert(EVENT_GENERATION, 1u64.to_be_bytes().as_slice())
                .map_err(|error| error.to_string())?;
        }
    }
    txn.commit().map_err(|error| error.to_string())
}

pub(crate) fn read(db: &Database) -> Result<u64, String> {
    let txn = db.begin_read().map_err(|error| error.to_string())?;
    let table = txn
        .open_table(SYNC_META)
        .map_err(|error| error.to_string())?;
    let bytes = table
        .get(EVENT_GENERATION)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "event generation is not initialized".to_string())?
        .value()
        .to_vec();
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "event generation has an invalid encoding".to_string())?;
    Ok(u64::from_be_bytes(bytes))
}

pub(crate) fn bump(txn: &WriteTransaction) -> Result<(), String> {
    let mut table = txn
        .open_table(SYNC_META)
        .map_err(|error| error.to_string())?;
    let current = table
        .get(EVENT_GENERATION)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "event generation is not initialized".to_string())?
        .value()
        .to_vec();
    let current: [u8; 8] = current
        .try_into()
        .map_err(|_| "event generation has an invalid encoding".to_string())?;
    let next = u64::from_be_bytes(current)
        .checked_add(1)
        .ok_or_else(|| "event generation exhausted u64".to_string())?;
    table
        .insert(EVENT_GENERATION, next.to_be_bytes().as_slice())
        .map_err(|error| error.to_string())?;
    Ok(())
}
