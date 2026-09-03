//! `stats()` reports what the index tracks — the number its own field
//! documents, and the only one a scrape can afford at scale.

use dag_control::test_utils::TestControl;
use dag_core::ContentStore;

#[test]
fn stats_counts_indexed_chunks_and_their_recorded_lengths() {
    let tc = TestControl::new().unwrap();

    let bodies: [&[u8]; 3] = [b"one", b"two-two", b"three-three-three"];
    let expected_bytes: u64 = bodies.iter().map(|b| b.len() as u64).sum();
    for body in bodies {
        tc.control.store.put_chunk(body, None).unwrap();
    }

    let stats = tc.control.stats().unwrap();
    assert_eq!(stats.chunks, 3);
    assert_eq!(stats.bytes, expected_bytes);
}

#[test]
fn an_orphan_file_the_index_never_saw_is_not_counted_as_stored() {
    // The artifact an interrupted deferred ingest leaves behind: bytes at a
    // canonical path that no index entry names. `reindex` adopts them and
    // collection sweeps them; until then they are not content this
    // deployment holds, and reporting them as such overstated the store.
    let tc = TestControl::new().unwrap();
    let real = tc.control.store.put_chunk(b"tracked", None).unwrap();

    let orphan_bytes = b"never indexed";
    let orphan = dag_core::Cid::compute(orphan_bytes);
    let path = tc.control.store.chunk_path(&orphan);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, orphan_bytes).unwrap();

    let stats = tc.control.stats().unwrap();
    assert_eq!(stats.chunks, 1, "an unindexed orphan was counted");
    assert_eq!(stats.bytes, b"tracked".len() as u64);

    // Reindex adopts it, and only then does it count.
    tc.control.store.reindex().unwrap();
    let stats = tc.control.stats().unwrap();
    assert_eq!(stats.chunks, 2);
    assert_eq!(stats.bytes, (b"tracked".len() + orphan_bytes.len()) as u64);
    assert!(tc.control.store.has_chunk(&real).unwrap());
}

#[test]
fn collection_is_reflected_in_the_next_stats_read() {
    // The index is updated by deletion, so the gauge follows collection
    // without a reindex.
    let tc = TestControl::new().unwrap();
    tc.control.recovery_state.mark_complete_for_test().unwrap();

    let hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    for i in 0..4u32 {
        let cid = tc
            .control
            .store
            .put_chunk(format!("garbage {i}").as_bytes(), None)
            .unwrap();
        filetime::set_file_mtime(tc.control.store.chunk_path(&cid), hour_ago).unwrap();
    }
    assert_eq!(tc.control.stats().unwrap().chunks, 4);

    let report = tc
        .control
        .run_gc(&dag_control::GcRequest {
            min_age_secs: 0,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(report.chunks_deleted, 4);
    assert_eq!(tc.control.stats().unwrap().chunks, 0);
    assert_eq!(tc.control.stats().unwrap().bytes, 0);
}
