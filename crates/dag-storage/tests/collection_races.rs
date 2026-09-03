//! The states a collection must never leave behind, exercised against the
//! interleavings that produce them.
//!
//! Every test here failed before the fix it names. They are deliberately
//! *store-level* rather than end-to-end: the soak in dag-control proves the
//! system survives contention, but it audits content readability, so it
//! could not fail on an index that names deleted bytes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use dag_core::{Cid, ContentStore};
use dag_storage::{ChunkIndex, DurabilityPolicy, FsStore, GcCapableStore};
use tempfile::tempdir;

fn store(dir: &std::path::Path) -> Arc<FsStore> {
    let index = Arc::new(ChunkIndex::new(dir.join("index.redb")).unwrap());
    Arc::new(FsStore::with_chunk_index(dir.join("data"), index).unwrap())
}

/// A deduplicating write that races a collection batch must never end with
/// the index naming a file the batch deleted.
///
/// The interleaving: `put_chunk` finds the file present, reads and verifies
/// it, then goes to index it — and blocks on the in-flight registry, which
/// the batch holds. The batch unlinks the file and clears the entry. If the
/// write then indexes what it adopted, the caller is told the chunk is
/// stored, the index agrees, and the bytes are gone.
#[test]
fn a_dedup_write_racing_a_deletion_never_leaves_a_phantom_index_entry() {
    let dir = tempdir().unwrap();
    let store = store(dir.path());

    // A batch big enough that the lock is held for a measurable window.
    // Seeded through a deferred view sharing the same index and registry, so
    // the setup costs one flush rather than 2000 — the test is about the
    // *deletion* interleaving, not about write durability.
    let seeder = FsStore::with_chunk_index(dir.path().join("data"), store.get_index().unwrap())
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred)
        .with_in_flight_registry(store.in_flight_registry());
    let mut doomed = Vec::new();
    for i in 0..2000u32 {
        doomed.push(
            seeder
                .put_chunk(format!("doomed {i}").as_bytes(), None)
                .unwrap(),
        );
    }
    // The chunk the writer will re-offer while the batch runs.
    let contested_bytes = b"contested".to_vec();
    let contested = seeder.put_chunk(&contested_bytes, None).unwrap();
    seeder.sync().unwrap();
    doomed.push(contested.clone());

    let barrier = Arc::new(Barrier::new(2));
    let collector = {
        let store = store.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            // Zero window: the in-flight guard is disabled, so nothing here
            // is protected by recency — the batch will genuinely delete.
            store.delete_chunks(&doomed, Duration::ZERO)
        })
    };

    let writer = {
        let store = store.clone();
        let barrier = barrier.clone();
        let cid = contested.clone();
        std::thread::spawn(move || {
            barrier.wait();
            // Hammer the same CID; some of these land mid-batch.
            let mut results = Vec::new();
            for _ in 0..50 {
                results.push(store.put_chunk(&contested_bytes, None));
                std::thread::sleep(Duration::from_micros(200));
            }
            (cid, results)
        })
    };

    let outcome = collector.join().unwrap();
    let (cid, results) = writer.join().unwrap();
    let _ = outcome;

    for result in &results {
        assert!(result.is_ok(), "a racing put failed: {:?}", result);
    }

    // The invariant: whatever the interleaving, the index and the disk agree.
    let indexed = store.get_index().unwrap().get(&cid).unwrap().is_some();
    let present = store.has_chunk(&cid).unwrap();
    assert_eq!(
        indexed, present,
        "index and disk disagree about {cid}: indexed={indexed}, present={present}"
    );

    // And every successful put must have left readable bytes: a put that
    // returns Ok is a promise the chunk is stored.
    if present {
        assert_eq!(store.get_chunk(&cid).unwrap(), b"contested");
    }
}

/// A deferred store whose file is collected between the write and the flush
/// must not index it. The pending index entry outlives the file otherwise,
/// and nothing sweeps it: `stats` counts it and `verify` reports a phantom.
#[test]
fn a_deferred_flush_does_not_index_a_file_that_was_collected() {
    let dir = tempdir().unwrap();
    let index = Arc::new(ChunkIndex::new(dir.path().join("index.redb")).unwrap());

    // Two views of one directory sharing an index and a registry — the
    // `Control::store` + `Control::staging_store` shape exactly.
    let durable =
        Arc::new(FsStore::with_chunk_index(dir.path().join("data"), index.clone()).unwrap());
    let staging = FsStore::with_chunk_index(dir.path().join("data"), index.clone())
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred)
        .with_in_flight_registry(durable.in_flight_registry());

    // Written through staging: file on disk, index entry owed.
    let cid = staging.put_chunk(b"transient", None).unwrap();
    assert!(staging.has_chunk(&cid).unwrap());
    assert!(index.get(&cid).unwrap().is_none(), "indexed too early");

    // Collected through the *other* view, which cannot clear staging's
    // pending set.
    let outcome = durable.delete_chunks(std::slice::from_ref(&cid), Duration::ZERO);
    assert_eq!(outcome.deleted.len(), 1, "the collection did not delete");
    assert!(!durable.has_chunk(&cid).unwrap());

    // The flush must notice the file is gone and drop the owed entry.
    staging.sync().unwrap();
    assert!(
        index.get(&cid).unwrap().is_none(),
        "flush indexed a file that had been collected"
    );
    assert!(!durable.has_chunk(&cid).unwrap());
}

/// A batch must still honour a reference registered before it started —
/// the property the whole locking arrangement exists for.
#[test]
fn a_reference_registered_before_the_batch_protects_its_chunk() {
    let dir = tempdir().unwrap();
    let store = store(dir.path());

    let protected = store.put_chunk(b"referenced", None).unwrap();
    let doomed = store.put_chunk(b"garbage", None).unwrap();

    // Both writes registered themselves — that is the ingest guard doing its
    // job. Let them age out of the window so the only thing still in flight
    // is the reference taken below, which is what this test is about.
    let window = Duration::from_millis(50);
    std::thread::sleep(window * 4);

    // A pointer or pin naming existing content, immediately before a sweep.
    store.note_reference(&protected);

    let outcome = store.delete_chunks(&[protected.clone(), doomed.clone()], window);
    assert_eq!(outcome.skipped_in_flight, vec![protected.clone()]);
    assert_eq!(outcome.deleted, vec![doomed]);
    assert!(store.has_chunk(&protected).unwrap());
}

/// A collection racing writers must never end with the index and the disk
/// disagreeing about *any* chunk — the general form of the first test.
#[test]
fn index_and_disk_agree_after_concurrent_collection_and_writes() {
    let dir = tempdir().unwrap();
    let store = store(dir.path());

    let mut all: Vec<Cid> = Vec::new();
    for i in 0..500u32 {
        all.push(
            store
                .put_chunk(format!("body {i}").as_bytes(), None)
                .unwrap(),
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let store = store.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut i = 0u32;
            while !stop.load(Ordering::Relaxed) {
                // Re-offer existing content (the dedup path) and new content.
                let _ = store.put_chunk(format!("body {}", i % 500).as_bytes(), None);
                let _ = store.put_chunk(format!("fresh {i}").as_bytes(), None);
                i += 1;
            }
        })
    };

    for batch in all.chunks(64) {
        store.delete_chunks(batch, Duration::ZERO);
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();

    let index = store.get_index().unwrap();
    for cid in index.cids().unwrap() {
        assert!(
            store.has_chunk(&cid).unwrap(),
            "index names {cid}, which is not on disk"
        );
        // And it is readable: an entry whose bytes do not verify would be
        // just as broken as one whose file is missing.
        store
            .get_chunk(&cid)
            .unwrap_or_else(|e| panic!("indexed chunk {cid} is unreadable: {e}"));
    }
}
