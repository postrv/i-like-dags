//! # Recovery State Tracking
//!
//! This module implements recovery state management for the DAG orchestrator.
//! It ensures that garbage collection cannot run until the system has completed
//! recovery operations (pointer rebuild, retention recomputation, and the
//! safety-relevant derived indexes used by collection).
//!
//! ## Recovery Invariants
//!
//! - **R1**: GC must not run before pointer heads are rebuilt from the event log
//! - **R2**: GC must not run before retention index is recomputed from pins
//! - **R3**: Recovery flags are persisted to survive orchestrator restarts
//! - **R4**: A full recovery keeps the gate closed through every phase and
//!   after an interrupted or failed attempt
//!
//! ## Storage
//!
//! Recovery state is stored in a dedicated table with boolean keys:
//! - `pointer_rebuilt`: true after successful pointer rebuild
//! - `retention_rebuilt`: true after successful retention recomputation
//! - `safety_indexes_rebuilt`: true only after the signature/effect-claim
//!   indexes were rebuilt alongside the pointer and retention views
//! - `chunk_index_rebuild_generation`: the complete index-replacement epoch
//!   certified by that full recovery
//! - `full_recovery_in_progress`: present from the start of a full recovery
//!   until chunk-index, pointer, pin, job, signature, and effect-claim state all
//!   completed
//!
//! The system is considered "recovered" only when all three completion flags
//! are true, the certified chunk-index generation is current, and no full
//! recovery is in progress.

use crate::error::{ControlError, Result};
use redb::{Database, ReadableDatabase, TableDefinition, WriteTransaction};
use std::sync::Arc;

const RECOVERY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("recovery");

const KEY_POINTER_REBUILT: &[u8] = b"pointer_rebuilt";
const KEY_RETENTION_REBUILT: &[u8] = b"retention_rebuilt";
const KEY_SAFETY_INDEXES_REBUILT: &[u8] = b"safety_indexes_rebuilt";
const KEY_FULL_RECOVERY_IN_PROGRESS: &[u8] = b"full_recovery_in_progress";
const KEY_CHUNK_INDEX_REBUILD_GENERATION: &[u8] = b"chunk_index_rebuild_generation";

fn db_err(e: impl std::fmt::Display) -> ControlError {
    ControlError::db("recovery state", e)
}

/// Recovery state tracker for orchestrator recovery operations
pub struct RecoveryState {
    db: Arc<Database>,
}

impl RecoveryState {
    /// Create a new recovery state tracker over the shared database.
    pub fn new(db: Arc<Database>) -> Result<Self> {
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(RECOVERY).map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(Self { db })
    }

    fn set(&self, key: &[u8]) -> Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(RECOVERY).map_err(db_err)?;
            table.insert(key, [1u8].as_slice()).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    fn is_set(&self, key: &[u8]) -> Result<bool> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(RECOVERY).map_err(db_err)?;
        Ok(table.get(key).map_err(db_err)?.is_some())
    }

    /// Mark pointer rebuild as complete
    ///
    /// This should be called after successfully rebuilding pointer heads from
    /// the event log (e.g., via `PointerLog::rebuild_from_events()`).
    pub fn mark_pointer_rebuilt(&self) -> Result<()> {
        self.set(KEY_POINTER_REBUILT)?;
        tracing::info!("marked pointer rebuild complete");
        Ok(())
    }

    /// Mark retention rebuild as complete
    ///
    /// This should be called after successfully recomputing the retention index
    /// from the pin log.
    pub fn mark_retention_rebuilt(&self) -> Result<()> {
        self.set(KEY_RETENTION_REBUILT)?;
        tracing::info!("marked retention rebuild complete");
        Ok(())
    }

    /// Persist that a multi-phase full recovery has started.
    ///
    /// This marker deliberately survives process interruption. Individual
    /// phases may update their own tables and completion flags, but GC remains
    /// closed until [`Self::complete_full_recovery`] removes this marker after
    /// every safety-relevant phase has succeeded.
    pub(crate) fn begin_full_recovery(&self) -> Result<()> {
        self.set(KEY_FULL_RECOVERY_IN_PROGRESS)?;
        tracing::info!("marked full recovery in progress");
        Ok(())
    }

    /// Set every recovery gate inside a caller-owned publication transaction.
    pub(crate) fn apply_complete(
        &self,
        txn: &WriteTransaction,
        chunk_index_rebuild_generation: u64,
    ) -> Result<()> {
        let mut table = txn.open_table(RECOVERY).map_err(db_err)?;
        table
            .insert(KEY_POINTER_REBUILT, [1u8].as_slice())
            .map_err(db_err)?;
        table
            .insert(KEY_RETENTION_REBUILT, [1u8].as_slice())
            .map_err(db_err)?;
        table
            .insert(KEY_SAFETY_INDEXES_REBUILT, [1u8].as_slice())
            .map_err(db_err)?;
        table
            .insert(
                KEY_CHUNK_INDEX_REBUILD_GENERATION,
                chunk_index_rebuild_generation.to_le_bytes().as_slice(),
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Atomically close every gate and clear the durable in-progress marker.
    pub(crate) fn complete_full_recovery(&self, chunk_index_rebuild_generation: u64) -> Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        self.apply_complete(&txn, chunk_index_rebuild_generation)?;
        {
            let mut table = txn.open_table(RECOVERY).map_err(db_err)?;
            let removed = table
                .remove(KEY_FULL_RECOVERY_IN_PROGRESS)
                .map_err(db_err)?;
            drop(removed);
        }
        txn.commit().map_err(db_err)?;
        tracing::info!("marked full recovery complete");
        Ok(())
    }

    /// Check if the system is fully recovered
    ///
    /// Returns true only if pointer, retention and safety-index rebuilds have
    /// completed against the current chunk-index generation and no full
    /// recovery is in progress. This is the gate that GC checks before running.
    pub fn is_recovered(&self, chunk_index_rebuild_generation: u64) -> Result<bool> {
        let pointer_ok = self.is_set(KEY_POINTER_REBUILT)?;
        let retention_ok = self.is_set(KEY_RETENTION_REBUILT)?;
        let safety_indexes_ok = self.is_set(KEY_SAFETY_INDEXES_REBUILT)?;
        let full_recovery_in_progress = self.is_set(KEY_FULL_RECOVERY_IN_PROGRESS)?;
        let witnessed_generation = {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(RECOVERY).map_err(db_err)?;
            table
                .get(KEY_CHUNK_INDEX_REBUILD_GENERATION)
                .map_err(db_err)?
                .map(|value| {
                    let bytes: [u8; 8] = value.value().try_into().map_err(|_| {
                        ControlError::Database(
                            "recovery chunk-index generation witness is malformed".into(),
                        )
                    })?;
                    Ok::<u64, ControlError>(u64::from_le_bytes(bytes))
                })
                .transpose()?
        };
        let generation_ok = witnessed_generation == Some(chunk_index_rebuild_generation);

        let recovered = pointer_ok
            && retention_ok
            && safety_indexes_ok
            && generation_ok
            && !full_recovery_in_progress;

        if !recovered {
            tracing::debug!(
                "recovery incomplete: pointer={}, retention={}, safety_indexes={}, index_generation={}, current_index_generation={}, full_recovery_in_progress={}",
                pointer_ok,
                retention_ok,
                safety_indexes_ok,
                witnessed_generation.map_or_else(|| "missing".into(), |value| value.to_string()),
                chunk_index_rebuild_generation,
                full_recovery_in_progress
            );
        }

        Ok(recovered)
    }

    /// Reset recovery state (for testing or manual recovery restart)
    #[cfg(test)]
    pub fn reset(&self) -> Result<()> {
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(RECOVERY).map_err(db_err)?;
            let a = table.remove(KEY_POINTER_REBUILT).map_err(db_err)?;
            drop(a);
            let b = table.remove(KEY_RETENTION_REBUILT).map_err(db_err)?;
            drop(b);
            let safety = table.remove(KEY_SAFETY_INDEXES_REBUILT).map_err(db_err)?;
            drop(safety);
            let generation = table
                .remove(KEY_CHUNK_INDEX_REBUILD_GENERATION)
                .map_err(db_err)?;
            drop(generation);
            let c = table
                .remove(KEY_FULL_RECOVERY_IN_PROGRESS)
                .map_err(db_err)?;
            drop(c);
        }
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Test-only shortcut for constructing an already recovered deployment.
    /// Production code must establish completion through full recovery. Atomic
    /// sync publication may preserve an existing verdict, but cannot mint one.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn mark_complete_for_test(&self) -> Result<()> {
        self.complete_full_recovery(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn recovery(dir: &std::path::Path) -> RecoveryState {
        let db = Arc::new(Database::create(dir.join("control.redb")).unwrap());
        RecoveryState::new(db).unwrap()
    }

    #[test]
    fn test_initial_state_not_recovered() {
        let dir = tempdir().unwrap();
        let recovery = recovery(dir.path());

        assert!(!recovery.is_recovered(0).unwrap());
    }

    #[test]
    fn test_pointer_rebuilt_alone_insufficient() {
        let dir = tempdir().unwrap();
        let recovery = recovery(dir.path());

        recovery.mark_pointer_rebuilt().unwrap();
        assert!(!recovery.is_recovered(0).unwrap());
    }

    #[test]
    fn test_retention_rebuilt_alone_insufficient() {
        let dir = tempdir().unwrap();
        let recovery = recovery(dir.path());

        recovery.mark_retention_rebuilt().unwrap();
        assert!(!recovery.is_recovered(0).unwrap());
    }

    #[test]
    fn partial_pointer_and_retention_marks_do_not_bypass_safety_indexes() {
        let dir = tempdir().unwrap();
        let recovery = recovery(dir.path());

        recovery.mark_pointer_rebuilt().unwrap();
        recovery.mark_retention_rebuilt().unwrap();
        assert!(!recovery.is_recovered(0).unwrap());
        recovery.mark_complete_for_test().unwrap();
        assert!(recovery.is_recovered(0).unwrap());
    }

    #[test]
    fn test_recovery_persists_across_instances() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("control.redb");

        {
            let db = Arc::new(Database::create(&db_path).unwrap());
            let recovery = RecoveryState::new(db).unwrap();
            recovery.mark_complete_for_test().unwrap();
        }

        // Reopen database
        let db = Arc::new(Database::create(&db_path).unwrap());
        let recovery = RecoveryState::new(db).unwrap();
        assert!(recovery.is_recovered(0).unwrap());
    }

    #[test]
    fn an_interrupted_full_recovery_holds_the_gate_across_reopen() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("control.redb");

        {
            let db = Arc::new(Database::create(&db_path).unwrap());
            let recovery = RecoveryState::new(db).unwrap();
            recovery.mark_complete_for_test().unwrap();
            assert!(recovery.is_recovered(0).unwrap());
            recovery.begin_full_recovery().unwrap();
            assert!(!recovery.is_recovered(0).unwrap());
        }

        let db = Arc::new(Database::create(&db_path).unwrap());
        let recovery = RecoveryState::new(db).unwrap();
        assert!(!recovery.is_recovered(0).unwrap());
        recovery.complete_full_recovery(0).unwrap();
        assert!(recovery.is_recovered(0).unwrap());
    }

    #[test]
    fn test_reset_clears_state() {
        let dir = tempdir().unwrap();
        let recovery = recovery(dir.path());

        recovery.mark_complete_for_test().unwrap();
        assert!(recovery.is_recovered(0).unwrap());

        recovery.reset().unwrap();
        assert!(!recovery.is_recovered(0).unwrap());
    }
}
