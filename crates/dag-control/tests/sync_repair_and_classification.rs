//! Two properties a replica depends on, both of which a review found broken.

use dag_control::test_utils::TestControl;
use dag_control::{sync, SyncOptions};
use dag_core::{Cid, ContentStore, Entry, Link};

fn put(tc: &TestControl, bytes: &[u8]) -> Cid {
    tc.control.store.put_chunk(bytes, None).unwrap()
}

/// A destination file that is present but *torn* must be re-sent and
/// repaired, not skipped for ever.
///
/// The state is reachable: the destination writes with deferred durability,
/// which renames a chunk into its canonical path before the bytes are
/// fsynced, so a crash mid-transfer can leave a complete-looking file with
/// incomplete contents. If `missing()` answered by file presence alone, that
/// file would never be re-offered — the repair path in `store_chunk` would
/// never see it, and the index-driven `verify` would never look at it,
/// because the index entry was deferred too.
#[test]
fn a_torn_destination_chunk_is_re_sent_and_repaired() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let body = b"the real contents of this chunk";
    let cid = put(&src, body);
    src.control.pointer_log.create("p", cid.clone()).unwrap();

    // Model the post-crash artifact exactly: right bytes' name, wrong bytes,
    // no index entry (both the fsync and the index insert were owed).
    let path = dst.control.store.chunk_path(&cid);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"torn").unwrap();
    assert!(dst.control.store.has_chunk(&cid).unwrap(), "setup");
    assert!(dst.control.store.get_chunk(&cid).is_err(), "setup: torn");

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert!(
        report.chunks_sent > 0,
        "the torn chunk was skipped as already present"
    );

    // Repaired: the bytes now verify, and the replica can read them.
    assert_eq!(dst.control.store.get_chunk(&cid).unwrap(), body);
    assert_eq!(dst.control.pointer_log.resolve("p").unwrap(), cid);
}

/// An index entry naming a file that is gone must also be re-sent — the
/// other direction of the same rule.
#[test]
fn a_destination_chunk_missing_from_disk_is_re_sent_despite_its_index_entry() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let body = b"content";
    let cid = put(&src, body);
    src.control.pointer_log.create("p", cid.clone()).unwrap();

    // Indexed at the destination, then the file removed underneath it.
    put(&dst, body);
    std::fs::remove_file(dst.control.store.chunk_path(&cid)).unwrap();

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert_eq!(dst.control.store.get_chunk(&cid).unwrap(), body);
}

/// An indexed path is only a claim about what was written previously. If its
/// bytes change later, replication must hash it, re-offer it, and drive the
/// store's repair path instead of reporting a false complete transfer.
#[test]
fn an_indexed_corrupt_destination_chunk_is_re_sent_and_repaired() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let body = b"content that must survive destination corruption";
    let cid = put(&src, body);
    src.control.pointer_log.create("p", cid.clone()).unwrap();

    put(&dst, body);
    std::fs::write(dst.control.store.chunk_path(&cid), b"corrupt").unwrap();
    assert!(dst.control.store.has_chunk(&cid).unwrap(), "setup");
    assert!(dst.control.store.get_chunk(&cid).is_err(), "setup: corrupt");

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert!(report.chunks_sent > 0, "indexed corruption was skipped");
    assert_eq!(dst.control.store.get_chunk(&cid).unwrap(), body);
}

/// Content a *live pointer head* names, absent at the source, is a failure —
/// not "collected history".
///
/// Both look identical by CID absence, and conflating them is the difference
/// between "your replica is fine" and "your replica's head resolves to
/// nothing". The exit code follows the report, so this is what makes a
/// backup script notice.
#[test]
fn an_absent_live_head_stays_a_failure_while_absent_history_does_not() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    // v1 becomes history, v2 is the live head. Both are then removed from
    // the source, as a collection of superseded content would do to v1.
    let v1 = put(&src, b"version one");
    let v2 = put(&src, b"version two");
    src.control.pointer_log.create("p", v1.clone()).unwrap();
    src.control.pointer_log.update("p", v2.clone()).unwrap();

    std::fs::remove_file(src.control.store.chunk_path(&v1)).unwrap();
    std::fs::remove_file(src.control.store.chunk_path(&v2)).unwrap();

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();

    // The superseded version: expected, reported, not a failure.
    assert!(
        report.missing_at_source.contains(&v1.to_hex()),
        "superseded history should be reported as absent at source: {:?}",
        report.missing_at_source
    );
    // The live head: a failure, so the transfer exits non-zero.
    assert!(
        report.failures.iter().any(|f| f.cid == v2.to_hex()),
        "an absent live head was not reported as a failure: {:?}",
        report
    );
    assert!(!report.is_complete(), "a dangling head reported success");
    assert!(report.publication_blocked);
    assert!(dst.control.pointer_log.list_pointers().unwrap().is_empty());
}

/// A readable root is not sufficient: publication requires its whole live
/// closure. This catches the subtler partial replica where resolve succeeds
/// but a file or dataset fails one link below the head.
#[test]
fn an_absent_live_descendant_blocks_head_publication() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let child = put(&src, b"required child");
    let root = src
        .control
        .store
        .put_entry(&Entry {
            payload: Vec::new(),
            links: vec![Link {
                name: Some("child".to_string()),
                target: child.clone(),
            }],
            meta: None,
        })
        .unwrap();
    src.control.pointer_log.create("release", root).unwrap();
    std::fs::remove_file(src.control.store.chunk_path(&child)).unwrap();

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
    assert!(report.failures.iter().any(|f| f.cid == child.to_hex()));
    assert!(report.publication_blocked);
    assert!(!report.is_complete());
    assert!(dst.control.pointer_log.event_cids().unwrap().is_empty());
    assert!(dst.control.pointer_log.list_pointers().unwrap().is_empty());
}

/// The case the classification exists for: history collected at the source
/// must *not* make every later sync fail.
#[test]
fn collected_history_alone_still_completes() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let v1 = put(&src, b"version one");
    let v2 = put(&src, b"version two");
    src.control.pointer_log.create("p", v1.clone()).unwrap();
    src.control.pointer_log.update("p", v2.clone()).unwrap();

    // Only the superseded version is gone; the head is intact.
    std::fs::remove_file(src.control.store.chunk_path(&v1)).unwrap();

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
    assert!(
        report.is_complete(),
        "collected history made the sync fail: {:?}",
        report.failures
    );
    assert_eq!(report.missing_at_source, vec![v1.to_hex()]);
    // The replica still resolves the pointer to readable bytes.
    assert_eq!(dst.control.pointer_log.resolve("p").unwrap(), v2);
    assert_eq!(dst.control.store.get_chunk(&v2).unwrap(), b"version two");
}

/// A readable target named only by superseded pointer history is still worth
/// offering. Protocol-v3 pages recover the direct target as a wanted-only
/// hint; omitting it here would also make a later source-side collection
/// invisible to `missing_at_source`.
#[test]
fn readable_superseded_history_target_is_still_offered() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let v1 = put(&src, b"version one");
    let v2 = put(&src, b"version two");
    src.control.pointer_log.create("p", v1.clone()).unwrap();
    src.control.pointer_log.update("p", v2).unwrap();

    let report = sync::push(&src.control, &dst.control, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(dst.control.store.get_chunk(&v1).unwrap(), b"version one");
}

#[test]
fn historical_target_hint_decoding_honours_the_aggregate_raw_byte_budget() {
    let src = TestControl::new().unwrap();
    let target = put(&src, b"version one");
    src.control.pointer_log.create("p", target).unwrap();
    let events = src.control.pointer_log.event_cids().unwrap();

    let mut bytes_read = sync::MAX_SYNC_POINTER_EVENT_READ_BYTES;
    let error = src
        .control
        .pointer_log
        .sync_target_hints(&events, &mut bytes_read)
        .unwrap_err();

    assert!(error.to_string().contains("event-read budget"));
}
