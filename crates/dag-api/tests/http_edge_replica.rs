//! Native HTTP-client smoke test against the explicitly non-production
//! `dag-edge/test-harness` fixture.
//!
//! Worker protocol, session atomicity, closure validation and recovery are
//! covered by the Workerd suites. This fixture must not be cited as Edge
//! acceptance or parity evidence.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

const TEST_TOKEN: &str = "test-edge-token-0123456789abcdef01";

use dag_api::scenario;
use dag_control::{sync, Control, HttpDestination, SyncOptions, SyncReport};
use dag_core::{file, Cid, ContentStore};
use dag_edge::{http, EdgeReplica};
use tempfile::TempDir;

async fn seeded() -> (TempDir, Control) {
    let dir = TempDir::new().unwrap();
    let control = Control::open(dir.path()).unwrap();
    scenario::seed(&control, true).await.unwrap();
    (dir, control)
}

async fn push_http(source: Arc<Control>, dest: HttpDestination) -> SyncReport {
    // ureq is synchronous; running it on a worker would stall the server
    // task that has to answer `/sync/missing`. Same reason dag-net's
    // remote adapters use spawn_blocking.
    tokio::task::spawn_blocking(move || {
        sync::replicate(source.as_ref(), &dest, &SyncOptions::default())
    })
    .await
    .expect("sync task")
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_destination_transport_smoke_transfers_and_verifies_seven_nodes() {
    let (_src_dir, source) = seeded().await;
    let original = scenario::verify(&source, scenario::PTR_PRODUCTION).unwrap();
    assert!(original.verified);
    assert_eq!(original.total_nodes, 7, "the worked example is 7 nodes");

    let replica = EdgeReplica::memory(TEST_TOKEN);
    let app = http::router(replica.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let source = Arc::new(source);
    let dest = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
    let report = push_http(source.clone(), dest).await;
    assert!(report.is_complete(), "push failed: {:?}", report.failures);
    assert!(report.chunks_sent > 0);
    assert!(report.pointer_events > 0);

    replica.finalize();
    let root = source
        .pointer_log
        .resolve(scenario::PTR_PRODUCTION)
        .unwrap();
    assert_eq!(
        replica.resolve(scenario::PTR_PRODUCTION).as_ref(),
        Some(&root)
    );

    let intact = walk_intact(replica.store(), &root);
    assert_eq!(intact, 7, "replica walked {intact} intact nodes, not 7");

    file::verify_deep(replica.store(), &root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_push_moves_nothing() {
    let (_src_dir, source) = seeded().await;
    let replica = EdgeReplica::memory(TEST_TOKEN);
    let app = http::router(replica);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let source = Arc::new(source);
    let dest = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
    let first = push_http(source.clone(), dest).await;
    let dest = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
    let second = push_http(source, dest).await;
    assert!(first.chunks_sent > 0);
    assert_eq!(second.chunks_sent, 0);
    assert_eq!(second.chunks_skipped, first.chunks_sent);
}

fn walk_intact<S: ContentStore>(store: &S, root: &Cid) -> usize {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut intact = 0usize;
    queue.push_back(root.clone());
    seen.insert(root.clone());
    while let Some(cid) = queue.pop_front() {
        let Ok(bytes) = store.get_chunk(&cid) else {
            continue;
        };
        if Cid::compute(&bytes) != cid {
            continue;
        }
        intact += 1;
        if let Ok(entry) = store.get_entry(&cid) {
            for link in entry.links {
                if seen.insert(link.target.clone()) {
                    queue.push_back(link.target);
                }
            }
        }
    }
    intact
}
