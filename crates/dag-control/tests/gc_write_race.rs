//! Collection running alongside an ingest must not take the ingest's chunks.
//!
//! A large file is written chunk by chunk and only *then* named by a
//! manifest, so for the whole ingest every chunk is unreferenced and
//! unpinned. The review reproduced a 38,606-chunk `split` that returned `Ok`
//! against a root that could not be read back, because a concurrent
//! collection had deleted the chunks underneath it.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::GcRequest;
use dag_core::{Cid, ContentStore};

fn recovered(tc: &TestControl) -> Result<()> {
    tc.control.recovery_state.mark_complete_for_test()?;
    Ok(())
}

#[test]
fn gc_flushes_a_coordinated_pending_write_without_closing_recovery() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    // A staging put has completed its canonical rename but intentionally owes
    // the durable index row. Before the gated inventory fix this deterministic
    // state was reported as restored-database corruption, and run_gc closed
    // the recovery gate even though both halves belonged to one live writer.
    let staging = tc.control.staging_store()?;
    let cid = staging.put_chunk(b"coordinated pending GC inventory", None)?;
    let index = tc.control.store.get_index().unwrap();
    assert!(tc.control.store.has_chunk(&cid)?);
    assert!(
        index.get(&cid)?.is_none(),
        "staging indexed before its flush"
    );

    let report = tc.control.run_gc(&GcRequest::default())?;
    assert!(!report.collected.iter().any(|item| item.cid == cid));
    assert!(
        index.get(&cid)?.is_some(),
        "GC did not flush the pending row"
    );
    assert!(tc.control.store.has_chunk(&cid)?);
    assert!(
        tc.control.is_recovered()?,
        "a legitimate in-process write must not close the recovery gate"
    );
    Ok(())
}

/// Deterministic pseudorandom bytes, so chunk boundaries are reproducible and
/// the content does not dedup against itself.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
fn a_file_written_while_collection_runs_is_still_readable() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    // Something collectable, so the collector has real work and is not
    // trivially a no-op.
    for i in 0..20 {
        tc.control
            .store
            .put_chunk(format!("garbage {i}").as_bytes(), None)?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let collector_stop = stop.clone();
    let sweeps = Arc::new(AtomicUsize::new(0));
    let collector_sweeps = sweeps.clone();
    let control = &tc.control;

    let root: Cid = std::thread::scope(|scope| -> Result<Cid> {
        scope.spawn(move || {
            // The stock request, which is what a scheduled collection or the
            // HTTP API's default actually sends.
            while !collector_stop.load(Ordering::Relaxed) {
                if control.run_gc(&GcRequest::default()).is_ok() {
                    collector_sweeps.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let config = dag_core::ChunkerConfig::default();
        let data = noise(6 * 1024 * 1024, 0xC0FFEE);
        let stored = dag_core::file::store_auto(
            control.store.as_ref(),
            std::io::Cursor::new(data.clone()),
            None,
            true,
            &config,
        )?;
        stop.store(true, Ordering::Relaxed);

        let root = match stored {
            dag_core::StoredContent::File(r) => r.cid,
            dag_core::StoredContent::Chunk { cid, .. } => cid,
        };

        // The claim under test: a CID handed back by a successful write is a
        // promise that the bytes are there.
        let mut readback = Vec::new();
        dag_core::file::join(control.store.as_ref(), &root, &mut readback)?;
        assert_eq!(
            readback, data,
            "the ingest reported success; its content must survive a concurrent collection"
        );
        Ok(root)
    })?;

    // Non-vacuity: collection really was sweeping the store while the ingest
    // ran. Without this the test would pass on a machine where the thread
    // never got scheduled, which proves nothing about racing anything.
    assert!(
        sweeps.load(Ordering::Relaxed) > 0,
        "the collector never completed a sweep during the ingest"
    );
    assert!(
        tc.control.store.has_chunk(&root)?,
        "the manifest itself must survive too, not just the chunks under it"
    );
    Ok(())
}

#[test]
fn a_deduplicated_chunk_is_protected_despite_an_old_mtime() -> Result<()> {
    // The hole file mtime cannot cover. Deduplication reuses the existing
    // file untouched, so a chunk a live ingest depends on keeps whatever
    // timestamp it had — potentially far outside any minimum-age window.
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let payload = b"shared between two ingests";
    let cid = tc.control.store.put_chunk(payload, None)?;

    // Age it well past any age gate.
    let old = filetime::FileTime::from_unix_time(1_000_000_000, 0);
    for entry in std::fs::read_dir(tc.path().join("data"))? {
        let shard = entry?.path();
        if shard.is_dir() {
            for f in std::fs::read_dir(&shard)? {
                filetime::set_file_mtime(f?.path(), old)?;
            }
        }
    }

    // A second put deduplicates: no bytes written, mtime untouched.
    let again = tc.control.store.put_chunk(payload, None)?;
    assert_eq!(again, cid);

    tc.control.run_gc(&GcRequest {
        node_id: "local".into(),
        dry_run: false,
        max_delete: 0,
        min_age_secs: 60,
        system_protection: true,
    })?;

    assert!(
        tc.control.store.has_chunk(&cid)?,
        "a chunk just handed to a caller must not be collected because its file is old"
    );
    Ok(())
}

/// Age every chunk file in a data directory, so nothing is spared by the
/// minimum-age gate.
fn age_all_files(data_dir: &std::path::Path, when: filetime::FileTime) -> Result<()> {
    for entry in std::fs::read_dir(data_dir)? {
        let shard = entry?.path();
        if shard.is_dir() {
            for f in std::fs::read_dir(&shard)? {
                filetime::set_file_mtime(f?.path(), when)?;
            }
        }
    }
    Ok(())
}

#[test]
fn a_split_deduplicated_chunk_survives_collection_despite_an_old_mtime() -> Result<()> {
    // The sibling test above dedups through `put_chunk`, whose adopt path notes
    // the write. `split` dedups through a bare `has_chunk` check and *skips*
    // the write entirely, so nothing noted it — the hole this covers. A chunk
    // an ingest references by deduplication, whose file is old, must still
    // survive a collection running the moment the ingest names it.
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let config = dag_core::ChunkerConfig::default();
    let content = noise(5 * 1024 * 1024, 0x5EED);

    // Seed the data directory through a throwaway store, so the chunks are on
    // disk *without* being in the control store's in-flight registry — the
    // state a previous process or a settled earlier ingest leaves behind.
    let data_dir = tc.path().join("data");
    {
        let seed = dag_storage::FsStore::new(&data_dir)?;
        dag_core::file::split(&seed, std::io::Cursor::new(content.clone()), None, &config)?;
    }
    // Age every chunk far past the default 60s minimum-age gate.
    age_all_files(
        &data_dir,
        filetime::FileTime::from_unix_time(1_000_000_000, 0),
    )?;

    // Ingest the same bytes through the control's own store: every data chunk
    // deduplicates and is skipped, so only `note_reference` protects it now.
    let stored = dag_core::file::store_auto(
        tc.control.store.as_ref(),
        std::io::Cursor::new(content.clone()),
        None,
        true,
        &config,
    )?;
    let root: Cid = match stored {
        dag_core::StoredContent::File(r) => r.cid,
        dag_core::StoredContent::Chunk { cid, .. } => cid,
    };

    // The stock collection request: 60s min-age, unlimited deletions.
    tc.control.run_gc(&GcRequest::default())?;

    let mut readback = Vec::new();
    dag_core::file::join(tc.control.store.as_ref(), &root, &mut readback)?;
    assert_eq!(
        readback, content,
        "a chunk `split` referenced by deduplication was collected because its file was old"
    );
    Ok(())
}
