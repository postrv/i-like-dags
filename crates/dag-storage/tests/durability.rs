//! Durability and write/delete ordering for [`FsStore`].
//!
//! The rule these tests defend is one sentence: **the index must never name
//! bytes that are not on disk.** A stale index entry pointing at nothing is
//! corruption — `get_chunk` fails, sync's skip logic lies, GC counts a chunk it
//! cannot free. A stale *file* with no index entry is merely garbage, and
//! `reindex` or the next collection sweeps it up.
//!
//! That asymmetry fixes the order of every step:
//!
//! * writing:  bytes → fsync → rename → fsync parent dir → index insert
//! * deleting: index remove → unlink
//!
//! Only the second is directly observable without killing a process, and the
//! first two tests below observe it: a reader thread that finds a chunk file
//! missing re-reads the index, and if the index still names the chunk, the
//! order was wrong. The fsync steps are asserted through
//! [`FsStore::durability_stats`], and the last test measures what they cost.

use dag_core::{Cid, ContentStore};
use dag_storage::{DurabilityPolicy, FsStore, GcCapableStore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::TempDir;

fn store_with_index(temp: &TempDir) -> Arc<FsStore> {
    Arc::new(FsStore::with_index(temp.path().join("data"), temp.path().join("index.redb")).unwrap())
}

/// Every CID the index currently names must have bytes on disk.
///
/// Checked in the only order that is free of test-side races: look at the file
/// first, and only call a missing file a violation if the index *still* names
/// it afterwards. Under the correct delete order the index entry always
/// disappears first, so a missing file implies a missing index entry.
fn scan_for_violations(store: &FsStore) -> Vec<String> {
    let index = store.get_index().expect("store has an index");
    let mut violations = Vec::new();

    for cid in index.cids().unwrap_or_default() {
        let path = store.chunk_path(&cid);
        if path.exists() {
            continue;
        }
        if index.get(&cid).is_ok_and(|entry| entry.is_some()) {
            violations.push(format!(
                "index names {} but {} does not exist",
                cid,
                path.display()
            ));
        }
    }

    violations
}

/// Deleting must clear the index entry before unlinking the bytes.
///
/// With the steps the other way round there is a window the width of a redb
/// commit — an fsync, so milliseconds — in which the index names a file that
/// has already been unlinked. A reader scanning a few hundred entries takes
/// microseconds, so it lands inside that window readily.
#[test]
fn index_never_names_a_deleted_chunk() {
    let temp = TempDir::new().unwrap();
    let store = store_with_index(&temp);

    let cids: Vec<Cid> = (0..100)
        .map(|i| {
            store
                .put_chunk(format!("delete-ordering chunk {i}").as_bytes(), None)
                .unwrap()
        })
        .collect();

    let stop = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(Mutex::new(Vec::new()));

    let reader = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        let violations = Arc::clone(&violations);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let found = scan_for_violations(&store);
                if !found.is_empty() {
                    violations.lock().unwrap().extend(found);
                }
            }
        })
    };

    for cid in &cids {
        store.delete_chunk(cid).unwrap();
    }

    stop.store(true, Ordering::Relaxed);
    reader.join().unwrap();

    let violations = violations.lock().unwrap();
    assert!(
        violations.is_empty(),
        "index named {} chunk(s) whose bytes were already unlinked; \
         delete must remove the index entry first. First: {}",
        violations.len(),
        violations[0]
    );
}

/// Writing must publish the bytes before the index entry.
///
/// The mirror of the test above, and the one that guards against someone
/// "optimising" the index insert to the front of `put_chunk`.
#[test]
fn index_never_names_an_unwritten_chunk() {
    let temp = TempDir::new().unwrap();
    let store = store_with_index(&temp);

    let stop = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(Mutex::new(Vec::new()));

    let reader = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        let violations = Arc::clone(&violations);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let found = scan_for_violations(&store);
                if !found.is_empty() {
                    violations.lock().unwrap().extend(found);
                }
            }
        })
    };

    for i in 0..100 {
        store
            .put_chunk(format!("write-ordering chunk {i}").as_bytes(), None)
            .unwrap();
    }

    stop.store(true, Ordering::Relaxed);
    reader.join().unwrap();

    let violations = violations.lock().unwrap();
    assert!(
        violations.is_empty(),
        "index named {} chunk(s) before their bytes were on disk. First: {}",
        violations.len(),
        violations[0]
    );
}

/// A chunk whose file has already vanished must still lose its index entry.
///
/// This is the repair path for directories written by a build that unlinked
/// first and then crashed: the entry is corruption, and deleting the chunk is
/// how an operator clears it.
#[test]
fn delete_clears_the_index_entry_even_when_the_file_is_gone() {
    let temp = TempDir::new().unwrap();
    let store = store_with_index(&temp);
    let index = store.get_index().unwrap();

    let cid = store.put_chunk(b"vanishing bytes", None).unwrap();
    std::fs::remove_file(store.chunk_path(&cid)).unwrap();
    assert!(index.get(&cid).unwrap().is_some(), "precondition");

    store.delete_chunk(&cid).unwrap();

    assert!(
        index.get(&cid).unwrap().is_none(),
        "delete_chunk left a stale index entry behind"
    );
}

/// The default policy fsyncs the chunk and the directory that names it, and
/// does both before the index learns the chunk exists.
#[test]
fn durable_put_fsyncs_the_file_and_its_parent_directory() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::new(temp.path()).unwrap();
    assert_eq!(store.durability(), DurabilityPolicy::Durable);

    let before = store.durability_stats();
    store.put_chunk(b"durable bytes", None).unwrap();
    let after = store.durability_stats();

    assert_eq!(
        after.file_syncs - before.file_syncs,
        1,
        "the chunk's bytes were not fsynced"
    );
    assert!(
        after.dir_syncs > before.dir_syncs,
        "the rename that published the chunk was not fsynced"
    );
    assert_eq!(store.pending_sync_count(), 0, "nothing should be deferred");
}

/// Creating a shard directory is itself metadata that has to survive: without
/// an fsync of the data directory, a crash can take the new shard — and the
/// chunk inside it — with it.
#[test]
fn durable_put_fsyncs_the_data_directory_when_it_creates_a_shard() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::new(temp.path()).unwrap();

    // Two chunks whose CIDs start with different bytes land in different
    // shards; find a pair rather than assuming.
    let first = store.put_chunk(b"shard probe one", None).unwrap();
    let after_first = store.durability_stats();

    let mut i = 0;
    let second = loop {
        let bytes = format!("shard probe {i}").into_bytes();
        let cid = Cid::compute(&bytes);
        if cid.to_hex()[..2] != first.to_hex()[..2] {
            break store.put_chunk(&bytes, None).unwrap();
        }
        i += 1;
        assert!(i < 1000, "could not find a CID in a second shard");
    };
    let after_second = store.durability_stats();

    assert_ne!(first.to_hex()[..2], second.to_hex()[..2]);
    // A new shard costs an extra directory fsync: the shard itself, plus the
    // data directory that now names it.
    assert_eq!(
        after_second.dir_syncs - after_first.dir_syncs,
        2,
        "creating a shard directory must fsync the data directory too"
    );

    // Re-using an existing shard costs one.
    let before_third = store.durability_stats();
    let mut j = 0;
    loop {
        let bytes = format!("same shard probe {j}").into_bytes();
        if Cid::compute(&bytes).to_hex()[..2] == first.to_hex()[..2] {
            store.put_chunk(&bytes, None).unwrap();
            break;
        }
        j += 1;
        assert!(j < 2000, "could not find a second CID in the first shard");
    }
    let after_third = store.durability_stats();
    assert_eq!(
        after_third.dir_syncs - before_third.dir_syncs,
        1,
        "an existing shard should cost exactly one directory fsync"
    );
}

/// The opt-in fast path defers every fsync to `sync`, and `sync` performs them.
#[test]
fn deferred_put_defers_fsyncs_until_sync() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::new(temp.path())
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred);
    assert_eq!(store.durability(), DurabilityPolicy::Deferred);

    let mut cids = Vec::new();
    for i in 0..8 {
        cids.push(
            store
                .put_chunk(format!("deferred chunk {i}").as_bytes(), None)
                .unwrap(),
        );
    }

    let before = store.durability_stats();
    assert_eq!(
        before.file_syncs, 0,
        "deferred writes must not fsync inline"
    );
    assert_eq!(before.dir_syncs, 0, "deferred writes must not fsync inline");
    assert_eq!(store.pending_sync_count(), 8);

    store.sync().unwrap();

    let after = store.durability_stats();
    assert_eq!(after.file_syncs, 8, "sync must fsync every deferred chunk");
    assert!(after.dir_syncs > 0, "sync must fsync the directories too");
    assert_eq!(store.pending_sync_count(), 0);

    // Deferring durability must not cost correctness of the data itself.
    for (i, cid) in cids.iter().enumerate() {
        assert_eq!(
            store.get_chunk(cid).unwrap(),
            format!("deferred chunk {i}").into_bytes()
        );
    }

    // A second sync with nothing pending is free.
    store.sync().unwrap();
    assert_eq!(store.durability_stats().file_syncs, 8);
}

/// Deferring the fsyncs must not leave the index naming bytes that are not
/// there.
///
/// This is the whole reason the index entry is deferred along with them. With
/// only the fsyncs moved, the redb commit would still land immediately — and
/// redb commits durably — so every deferred chunk would spend the window
/// between its write and the next `sync` in exactly the state
/// [`DurabilityPolicy::Durable`] exists to prevent: a durable index entry
/// naming bytes a crash can still take. Deferred is a weaker promise about
/// *when* data lands, not a licence to lie about where it is.
#[test]
fn deferred_writes_stay_out_of_the_index_until_they_are_durable() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::with_index(temp.path().join("data"), temp.path().join("index.redb"))
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred);
    let index = store.get_index().unwrap();

    let cids: Vec<Cid> = (0..8)
        .map(|i| {
            store
                .put_chunk(format!("unindexed until synced {i}").as_bytes(), None)
                .unwrap()
        })
        .collect();

    assert_eq!(
        index.count().unwrap(),
        0,
        "the index named {} chunk(s) whose bytes had not been fsynced",
        index.count().unwrap()
    );
    // Readable all the same: deferring durability must not defer availability,
    // or the chunker's own deduplication would stop seeing its work.
    for cid in &cids {
        assert!(store.has_chunk(cid).unwrap());
        assert!(store.get_chunk(cid).is_ok());
    }

    store.sync().unwrap();

    assert_eq!(
        index.count().unwrap(),
        cids.len(),
        "sync must index what it flushed"
    );
    for cid in &cids {
        assert!(index.get(cid).unwrap().is_some(), "{} missing", cid);
    }
}

/// Deleting a chunk that is only pending must not resurrect it at the next
/// flush.
#[test]
fn deleting_a_pending_chunk_cancels_its_index_entry() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::with_index(temp.path().join("data"), temp.path().join("index.redb"))
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred);
    let index = store.get_index().unwrap();

    let doomed = store.put_chunk(b"written then deleted", None).unwrap();
    let kept = store.put_chunk(b"written and kept", None).unwrap();

    store.delete_chunk(&doomed).unwrap();
    store.sync().unwrap();

    assert!(
        index.get(&doomed).unwrap().is_none(),
        "sync re-indexed a chunk that had been deleted"
    );
    assert!(index.get(&kept).unwrap().is_some());
}

/// Deferred mode must not grow its pending set without bound: it flushes
/// itself once enough writes have piled up, which caps both the memory and the
/// number of chunks a crash can take.
#[test]
fn deferred_mode_flushes_itself_before_the_pending_set_grows_unbounded() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::new(temp.path())
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred);

    let limit = FsStore::DEFERRED_SYNC_THRESHOLD;
    for i in 0..(limit + 16) {
        store
            .put_chunk(format!("flood chunk {i}").as_bytes(), None)
            .unwrap();
        assert!(
            store.pending_sync_count() <= limit,
            "pending set exceeded the threshold at chunk {i}"
        );
    }

    assert!(
        store.durability_stats().file_syncs >= limit as u64,
        "the implicit flush never ran"
    );
}

/// What the safety costs, measured rather than guessed.
///
/// Run with `--nocapture` to see the numbers. This asserts only that every
/// chunk survives each policy; the timings are reported, not gated, because a
/// threshold that depends on the host's disk is a flake waiting to happen.
#[test]
fn durability_cost_report() {
    const CHUNKS: usize = 100;
    const CHUNK_SIZE: usize = 64 * 1024;

    let payloads: Vec<Vec<u8>> = (0..CHUNKS)
        .map(|i| {
            let mut v = vec![0u8; CHUNK_SIZE];
            v[..8].copy_from_slice(&(i as u64).to_be_bytes());
            v
        })
        .collect();

    /// One phase. `sync_at_end` false with a deferred policy reproduces the
    /// behaviour this store had before it fsynced anything, which is the only
    /// honest "before" number to compare the default against.
    fn run(
        label: &str,
        payloads: &[Vec<u8>],
        policy: DurabilityPolicy,
        with_index: bool,
        sync_at_end: bool,
    ) -> f64 {
        let temp = TempDir::new().unwrap();
        let store = if with_index {
            FsStore::with_index(temp.path().join("data"), temp.path().join("index.redb")).unwrap()
        } else {
            FsStore::new(temp.path().join("data")).unwrap()
        }
        .with_durability(policy);

        let start = Instant::now();
        let cids: Vec<Cid> = payloads
            .iter()
            .map(|p| store.put_chunk(p, None).unwrap())
            .collect();
        if sync_at_end {
            store.sync().unwrap();
        }
        let elapsed = start.elapsed();

        // The measurement is worthless if the bytes are not actually there.
        for (cid, payload) in cids.iter().zip(payloads) {
            assert_eq!(&store.get_chunk(cid).unwrap(), payload);
        }

        let per_chunk = elapsed.as_secs_f64() * 1e3 / payloads.len() as f64;
        let stats = store.durability_stats();
        println!(
            "  {label:<36} {:>8.1} ms  {:>7.2} ms/chunk  {:>4} fsyncs",
            elapsed.as_secs_f64() * 1e3,
            per_chunk,
            stats.file_syncs + stats.dir_syncs,
        );
        per_chunk
    }

    // Control: everything put_chunk does that is not I/O. In a debug build
    // SHA-256 is slow enough to be mistaken for disk time, so measure it
    // rather than leave the reader guessing.
    let start = Instant::now();
    let hashed: usize = payloads
        .iter()
        .map(|p| Cid::compute(p).to_hex().len())
        .sum();
    let hash_only = start.elapsed().as_secs_f64() * 1e3 / CHUNKS as f64;
    assert!(hashed > 0);

    println!(
        "\n{CHUNKS} chunks x {} KiB on {} ({} build)\n  \
         [only meaningful under --release --test-threads=1: the other tests in\n   \
         this file fsync too, and fsync latency is a shared resource]",
        CHUNK_SIZE / 1024,
        std::env::consts::OS,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    );
    println!(
        "  {:<36} {:>8.1} ms  {:>7.2} ms/chunk",
        "hashing only, no I/O (control)",
        hash_only * CHUNKS as f64,
        hash_only
    );

    println!("  -- chunk store alone --");
    let raw = run(
        "no fsync at all (old behaviour)",
        &payloads,
        DurabilityPolicy::Deferred,
        false,
        false,
    );
    let deferred = run(
        "deferred + one sync at the end",
        &payloads,
        DurabilityPolicy::Deferred,
        false,
        true,
    );
    let durable = run(
        "durable (the default)",
        &payloads,
        DurabilityPolicy::Durable,
        false,
        true,
    );

    println!("  -- chunk store + redb index, as Control uses it --");
    let indexed_raw = run(
        "no fsync at all (old behaviour)",
        &payloads,
        DurabilityPolicy::Deferred,
        true,
        false,
    );
    // Exactly what `Control::bulk_ingest` hands a caller: the index entries are
    // deferred with the fsyncs, so the whole batch costs one redb commit
    // instead of one per chunk.
    let indexed_deferred = run(
        "deferred + one sync at the end",
        &payloads,
        DurabilityPolicy::Deferred,
        true,
        true,
    );
    let indexed_durable = run(
        "durable (the default)",
        &payloads,
        DurabilityPolicy::Durable,
        true,
        true,
    );

    println!(
        "\n  durable costs {:+.2} ms/chunk over no fsync ({:.1}x) with the store alone,\n  \
         and {:+.2} ms/chunk ({:.1}x) once the index's own fsyncs are in the picture.\n  \
         Deferring to one sync recovers {:.0}% of that with the store alone,\n  \
         and {:.0}% with the index — {:.1}x faster than the default, which is what\n  \
         a bulk ingest through `Control::bulk_ingest` gets.\n",
        durable - raw,
        durable / raw,
        indexed_durable - indexed_raw,
        indexed_durable / indexed_raw,
        100.0 * (durable - deferred) / (durable - raw).max(f64::EPSILON),
        100.0 * (indexed_durable - indexed_deferred)
            / (indexed_durable - indexed_raw).max(f64::EPSILON),
        indexed_durable / indexed_deferred,
    );

    // Guard only against the report becoming meaningless.
    assert!(durable > 0.0 && indexed_durable > 0.0);
}

/// `sync` on a durable store is a no-op rather than an error, so callers can
/// call it unconditionally at the end of a bulk write.
#[test]
fn sync_is_a_no_op_under_the_durable_policy() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::new(temp.path()).unwrap();
    store.put_chunk(b"already durable", None).unwrap();

    let before = store.durability_stats();
    store.sync().unwrap();
    let after = store.durability_stats();

    assert_eq!(before.file_syncs, after.file_syncs);
    assert_eq!(before.dir_syncs, after.dir_syncs);
}

/// A store shared across threads keeps its counters and its pending set
/// coherent — `FsStore` is used behind an `Arc` everywhere in the workspace.
#[test]
fn concurrent_writers_share_one_pending_set() {
    let temp = TempDir::new().unwrap();
    let store = Arc::new(
        FsStore::new(temp.path())
            .unwrap()
            .with_durability(DurabilityPolicy::Deferred),
    );

    let threads: Vec<_> = (0..4)
        .map(|t| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for i in 0..25 {
                    store
                        .put_chunk(format!("thread {t} chunk {i}").as_bytes(), None)
                        .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }

    assert_eq!(store.pending_sync_count(), 100);
    store.sync().unwrap();
    assert_eq!(store.pending_sync_count(), 0);
    assert_eq!(store.durability_stats().file_syncs, 100);
}

/// The minimal statement of the ordering invariant under Deferred: a single
/// freshly-put chunk is absent from the index until `sync`, present after —
/// yet readable throughout, because deferring durability must not defer
/// availability.
#[test]
fn a_single_deferred_chunk_is_indexed_only_after_sync() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::with_index(temp.path().join("data"), temp.path().join("index.redb"))
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred);
    let index = store.get_index().unwrap();

    let cid = store.put_chunk(b"one deferred chunk", None).unwrap();
    assert_eq!(
        index.count().unwrap(),
        0,
        "a deferred write must not be indexed before its bytes are durable"
    );
    assert!(index.get(&cid).unwrap().is_none());
    assert!(
        store.has_chunk(&cid).unwrap(),
        "the chunk is readable even while its durability is owed"
    );

    store.sync().unwrap();
    assert!(
        index.get(&cid).unwrap().is_some(),
        "sync must index the chunk it just made durable"
    );
    assert_eq!(index.count().unwrap(), 1);
}

/// The self-flush fires at exactly `DEFERRED_SYNC_THRESHOLD`, and the index
/// never names a chunk before its bytes are durable.
///
/// One write below the threshold, everything is pending and *nothing* is
/// indexed. The write that reaches the threshold flushes the store: the
/// pending set empties, and the flush indexes exactly the chunks it made
/// durable. That triggering write's own index entry waits for the next flush —
/// its bytes are already durable, so the index merely lags the disk, which is
/// the survivable direction. A final `sync` settles it.
#[test]
fn the_deferred_self_flush_fires_exactly_at_the_threshold() {
    let temp = TempDir::new().unwrap();
    let store = FsStore::with_index(temp.path().join("data"), temp.path().join("index.redb"))
        .unwrap()
        .with_durability(DurabilityPolicy::Deferred);
    let index = store.get_index().unwrap();
    let threshold = FsStore::DEFERRED_SYNC_THRESHOLD;

    // One below the threshold: all pending, none durable, so none indexed.
    for i in 0..(threshold - 1) {
        store
            .put_chunk(format!("boundary chunk {i}").as_bytes(), None)
            .unwrap();
    }
    assert_eq!(
        store.pending_sync_count(),
        threshold - 1,
        "nothing should have flushed one write below the threshold"
    );
    assert_eq!(
        index.count().unwrap(),
        0,
        "the index must not name a chunk before its bytes are durable"
    );

    // The write that reaches the threshold flushes the store.
    store
        .put_chunk(format!("boundary chunk {}", threshold - 1).as_bytes(), None)
        .unwrap();
    assert_eq!(
        store.pending_sync_count(),
        0,
        "reaching the threshold must flush the whole pending set"
    );
    assert_eq!(
        index.count().unwrap(),
        threshold - 1,
        "the self-flush indexes exactly the chunks it made durable; the triggering write's \
         own entry waits, its bytes already durable"
    );

    // An explicit sync settles that last entry.
    store.sync().unwrap();
    assert_eq!(
        index.count().unwrap(),
        threshold,
        "sync indexes the final durable chunk"
    );
}
