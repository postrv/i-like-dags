//! The acceptance test for ADR-002: a replica produced by `dag sync` passes
//! the same verification the original does.
//!
//! This lives in `dag-api` rather than `dag-control` because the worked
//! example — the thing worth replicating — is `dag_api::scenario`, and
//! `verify` walking a release back to its inputs is exactly the claim a
//! replica has to be able to support on its own.

use dag_api::scenario;
use dag_control::{sync, Control, SyncOptions};
use dag_core::ContentStore;
use tempfile::TempDir;

/// Seed the worked example into a fresh directory.
async fn seeded() -> (TempDir, Control) {
    let dir = TempDir::new().unwrap();
    let control = Control::open(dir.path()).unwrap();
    scenario::seed(&control, true).await.unwrap();
    (dir, control)
}

#[tokio::test]
async fn a_replica_verifies_the_release_lineage_on_its_own() {
    let (_src_dir, source) = seeded().await;

    let original = scenario::verify(&source, scenario::PTR_PRODUCTION).unwrap();
    assert!(original.verified, "the source itself failed to verify");
    assert!(
        original.total_nodes > 1,
        "the scenario should have a real lineage, got {} node(s)",
        original.total_nodes
    );

    let replica_dir = TempDir::new().unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();

    let report = sync::push(&source, &replica, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);

    // The replica answers the same question, from its own disk.
    let copied = scenario::verify(&replica, scenario::PTR_PRODUCTION).unwrap();

    assert!(copied.verified, "the replica failed to verify");
    assert_eq!(
        copied.root, original.root,
        "the replica's release resolves to different content"
    );
    assert_eq!(copied.total_nodes, original.total_nodes);
    assert_eq!(copied.intact, original.intact);
    assert_eq!(copied.corrupt, 0);
    assert_eq!(copied.total_bytes, original.total_bytes);

    // Retention has to survive too, or the replica would collect the lineage
    // it was created to preserve.
    assert!(
        copied.retained,
        "the replicated release is not protected from collection"
    );
}

#[tokio::test]
async fn pull_into_an_empty_directory_produces_the_same_replica() {
    let (_src_dir, source) = seeded().await;

    let replica_dir = TempDir::new().unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();

    // Same transfer, driven from the receiving side.
    let report = sync::pull(&replica, &source, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);

    let copied = scenario::verify(&replica, scenario::PTR_PRODUCTION).unwrap();
    assert!(copied.verified);
    assert_eq!(
        copied.root,
        scenario::verify(&source, scenario::PTR_PRODUCTION)
            .unwrap()
            .root
    );
}

#[tokio::test]
async fn every_pointer_in_the_scenario_survives_replication() {
    let (_src_dir, source) = seeded().await;

    let replica_dir = TempDir::new().unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();
    sync::push(&source, &replica, &SyncOptions::default()).unwrap();

    let source_pointers = source.pointer_log.list_pointers().unwrap();
    assert!(!source_pointers.is_empty());
    assert_eq!(
        replica.pointer_log.list_pointers().unwrap(),
        source_pointers
    );

    for id in &source_pointers {
        assert_eq!(
            replica.pointer_log.resolve(id).unwrap(),
            source.pointer_log.resolve(id).unwrap(),
            "pointer {} resolves differently on the replica",
            id
        );

        // History, not just the head: a replica that could only answer "what
        // is it now" would have dropped the provenance this system exists for.
        let head = source.pointer_log.get_head(id).unwrap();
        assert_eq!(
            replica.pointer_log.history(id, 1..head.seq + 1).unwrap(),
            source.pointer_log.history(id, 1..head.seq + 1).unwrap(),
            "pointer {} has different history on the replica",
            id
        );
    }
}

#[tokio::test]
async fn replicating_a_scenario_twice_transfers_nothing_the_second_time() {
    let (_src_dir, source) = seeded().await;

    let replica_dir = TempDir::new().unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();

    let first = sync::push(&source, &replica, &SyncOptions::default()).unwrap();
    assert!(first.chunks_sent > 0);

    let second = sync::push(&source, &replica, &SyncOptions::default()).unwrap();
    assert_eq!(second.chunks_sent, 0);
    assert_eq!(second.bytes_sent, 0);
    assert_eq!(second.chunks_skipped, first.chunks_sent);
    assert!(second.is_complete());

    // Still verifiable after a second pass — rebuilds are idempotent.
    assert!(
        scenario::verify(&replica, scenario::PTR_PRODUCTION)
            .unwrap()
            .verified
    );
}

#[tokio::test]
async fn a_replica_with_a_corrupted_chunk_reports_it_rather_than_verifying() {
    // Guards the acceptance claim itself: if `verify` passed regardless of the
    // bytes on disk, every test above would be vacuous.
    let (_src_dir, source) = seeded().await;

    let replica_dir = TempDir::new().unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();
    sync::push(&source, &replica, &SyncOptions::default()).unwrap();

    let root = replica
        .pointer_log
        .resolve(scenario::PTR_PRODUCTION)
        .unwrap();
    let leaf = replica
        .store
        .get_links(&root)
        .unwrap()
        .into_iter()
        .next()
        .expect("the release entry should link to something");

    std::fs::write(replica.store.chunk_path(&leaf.target), b"tampered").unwrap();

    let after = scenario::verify(&replica, scenario::PTR_PRODUCTION).unwrap();
    assert!(!after.verified, "tampering went undetected");
    assert!(after.corrupt >= 1);
}
