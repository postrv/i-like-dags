//! `dag_core::file::split` must protect a chunk it *deduplicates* the same way
//! it protects one it writes.
//!
//! Cross-revision dedup still offers an existing chunk through `put_chunk` so
//! the store can verify/adopt it (and repair a torn orphan). For `FsStore`
//! that idempotent adoption also feeds the in-flight registry. The chunk is
//! about to be referenced by a manifest that does not exist yet, so a
//! concurrent collection must honour that registration even though no bytes
//! needed rewriting.

use dag_core::file::{join, split};
use dag_core::{ChunkerConfig, Cid, ContentStore};
use dag_storage::{FsStore, GcCapableStore};
use std::time::Duration;

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
fn a_split_deduplicated_chunk_enters_the_in_flight_registry() {
    let dir = tempfile::tempdir().unwrap();
    let config = ChunkerConfig::default();
    let content = noise(5 * 1024 * 1024, 0xABCD);

    // First ingest populates the directory. Its registry is discarded with the
    // store, standing in for an earlier, already-settled ingest or a previous
    // process — the chunks are on disk but nothing is tracking them as recent.
    let first = FsStore::new(dir.path()).unwrap();
    let report = split(&first, std::io::Cursor::new(content.clone()), None, &config).unwrap();
    assert_eq!(
        report.depth, 1,
        "keep the manifest single-level so its links are the data chunks"
    );
    let data_links = first.get_links(&report.cid).unwrap();
    let deduped: Cid = data_links[0].target.clone();
    drop(first);

    // Second ingest of the same bytes through a *fresh* store: every data
    // chunk is already on disk. `split` re-offers it through the idempotent
    // put gate, which verifies/adopts it and registers the live reference.
    let second = FsStore::new(dir.path()).unwrap();
    let report2 = split(&second, std::io::Cursor::new(content), None, &config).unwrap();
    assert_eq!(report2.cid, report.cid, "same bytes, same manifest root");

    let recent = second.recently_written(Duration::from_secs(60));
    assert!(
        recent.contains(&deduped),
        "a chunk `split` deduplicated never entered the in-flight registry, so a \
         concurrent collection could take it mid-ingest"
    );
    assert!(
        second.is_in_flight(&deduped, Duration::from_secs(60)),
        "is_in_flight must agree with recently_written for a deduplicated chunk"
    );
}

#[test]
fn a_split_repairs_and_indexes_a_corrupt_crash_orphan() {
    let seed_dir = tempfile::tempdir().unwrap();
    let seed = FsStore::new(seed_dir.path()).unwrap();
    let config = ChunkerConfig::default();
    let content = noise(5 * 1024 * 1024, 0x0BAD_5EED);

    // Learn one real data-chunk identity and the deterministic manifest root
    // from an independent, healthy store.
    let expected = split(&seed, std::io::Cursor::new(content.clone()), None, &config).unwrap();
    assert_eq!(expected.depth, 1, "test needs direct data links");
    let victim = seed.get_links(&expected.cid).unwrap()[0].target.clone();

    // Model a process dying after it published a canonical filename but
    // before the deferred write was flushed or indexed. Presence alone says
    // "dedup hit" even though the bytes are short and untrustworthy.
    let target_dir = tempfile::tempdir().unwrap();
    let target = FsStore::with_index(
        target_dir.path().join("data"),
        target_dir.path().join("index.redb"),
    )
    .unwrap();
    let victim_path = target.chunk_path(&victim);
    std::fs::create_dir_all(victim_path.parent().unwrap()).unwrap();
    std::fs::write(&victim_path, b"torn crash residue").unwrap();

    assert!(target.has_chunk(&victim).unwrap(), "presence is the trap");
    assert!(target.get_chunk(&victim).is_err(), "orphan must be corrupt");
    assert!(
        target.get_index().unwrap().get(&victim).unwrap().is_none(),
        "crash orphan must begin unindexed"
    );

    let repaired = split(
        &target,
        std::io::Cursor::new(content.clone()),
        None,
        &config,
    )
    .unwrap();
    assert_eq!(repaired.cid, expected.cid, "repair must preserve identity");

    let mut joined = Vec::new();
    join(&target, &repaired.cid, &mut joined).unwrap();
    assert_eq!(joined, content, "the published manifest must be readable");
    assert_eq!(
        target.get_chunk(&victim).unwrap(),
        seed.get_chunk(&victim).unwrap()
    );
    assert!(
        target.get_index().unwrap().get(&victim).unwrap().is_some(),
        "repair must adopt the chunk into the durable index"
    );
}
