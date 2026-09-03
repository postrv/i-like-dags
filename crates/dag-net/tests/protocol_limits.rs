//! What a peer can make this node spend.
//!
//! The node port is authenticated, but a token is not a promise of good
//! behaviour — a replica whose token leaked, or a peer running older or buggy
//! code, is inside the boundary and still must not be able to exhaust the
//! machine. Every limit here bounds *work per request* rather than refusing
//! anything an honest peer does.

use std::sync::Arc;

use dag_control::Control;
use dag_core::{ContentStore, Entry, Link};
use dag_net::proto;
use dag_net::proto::sync_client::SyncClient;
use dag_net::{bind, ServeOptions};

/// Serve on an ephemeral loopback port with no token — allowed on loopback —
/// and hand back a raw generated client, so a test can say things the real
/// client never would.
async fn raw_client() -> (
    SyncClient<tonic::transport::Channel>,
    Arc<Control>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let control = Arc::new(Control::open(dir.path()).unwrap());
    let bound = bind(
        control.clone(),
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions::default(),
    )
    .await
    .unwrap();
    let url = format!("http://{}", bound.local_addr);
    tokio::spawn(bound.serve());
    (SyncClient::connect(url).await.unwrap(), control, dir)
}

fn frame(cid: Vec<u8>, total_len: u64, data: Vec<u8>) -> proto::ChunkFrame {
    proto::ChunkFrame {
        cid,
        total_len,
        data,
    }
}

/// The reassembly loop used to run until the sender chose to stop, and a
/// frame carrying no bytes advances nothing — so a peer could hold a request
/// open for as long as it liked, at a message of work per frame.
#[tokio::test]
async fn a_stream_of_empty_frames_is_refused_rather_than_followed() {
    let (mut client, _control, _dir) = raw_client().await;
    let cid = dag_core::Cid::compute(b"anything").as_bytes().to_vec();

    // Declares nothing, then never stops saying so. The budget for a
    // zero-length chunk is two frames.
    let frames: Vec<_> = std::iter::once(frame(cid.clone(), 0, Vec::new()))
        .chain((0..64).map(|_| frame(Vec::new(), 0, Vec::new())))
        .collect();

    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.put_chunk(tokio_stream::iter(frames)),
    )
    .await
    .expect("the call must return rather than follow the sender")
    .expect_err("empty frames past the budget must be refused");

    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("frames"),
        "the refusal should say what was exceeded: {}",
        status.message()
    );
}

/// The same budget applies to frames that do carry bytes: fragmenting a
/// chunk into single bytes is not a transfer, it is a way to buy work.
#[tokio::test]
async fn absurd_fragmentation_is_refused() {
    let (mut client, _control, _dir) = raw_client().await;
    let payload = vec![7u8; 64 * 1024];
    let cid = dag_core::Cid::compute(&payload).as_bytes().to_vec();
    let total = payload.len() as u64;

    let frames: Vec<_> = std::iter::once(frame(cid, total, vec![payload[0]]))
        .chain(payload[1..].iter().map(|b| frame(Vec::new(), 0, vec![*b])))
        .collect();

    let status = client
        .put_chunk(tokio_stream::iter(frames))
        .await
        .expect_err("64 Ki single-byte frames is past any sane budget");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// The other half: the limits must not refuse what the real client sends.
#[tokio::test]
async fn an_ordinary_chunk_still_arrives() {
    let (mut client, _control, _dir) = raw_client().await;
    // Two full frames and a remainder, which is what a real transfer of this
    // size looks like.
    let payload: Vec<u8> = (0..(dag_net::CHUNK_FRAME_BYTES * 2 + 17))
        .map(|i| (i % 251) as u8)
        .collect();
    let cid = dag_core::Cid::compute(&payload);
    let total = payload.len() as u64;

    let frames: Vec<_> = payload
        .chunks(dag_net::CHUNK_FRAME_BYTES)
        .enumerate()
        .map(|(i, window)| {
            frame(
                if i == 0 {
                    cid.as_bytes().to_vec()
                } else {
                    Vec::new()
                },
                if i == 0 { total } else { 0 },
                window.to_vec(),
            )
        })
        .collect();

    let stored = client
        .put_chunk(tokio_stream::iter(frames))
        .await
        .expect("an ordinary transfer must not trip the limits")
        .into_inner();
    assert_eq!(stored.stored_len, total);
}

/// A header that declares a size and then delivers nothing must not be a way
/// to reserve memory. The refusal is the observable half; the allocation
/// itself is pinned by the unit test on `initial_capacity`.
#[tokio::test]
async fn a_declared_size_with_no_bytes_is_refused() {
    let (mut client, _control, _dir) = raw_client().await;
    let cid = dag_core::Cid::compute(b"never sent").as_bytes().to_vec();

    let status = client
        .put_chunk(tokio_stream::iter(vec![frame(
            cid,
            dag_core::MAX_CHUNK_SIZE as u64,
            Vec::new(),
        )]))
        .await
        .expect_err("a chunk that never arrives is not stored");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("declared"),
        "unexpected refusal: {}",
        status.message()
    );
}

/// `max_walk` is the caller's cap on how much graph the *server* traverses
/// and holds. It arrived unclamped, so a peer could ask for everything.
/// Clamping must not break the request, only the ambition.
#[tokio::test]
async fn an_absurd_max_walk_is_clamped_rather_than_refused() {
    let (mut client, _control, _dir) = raw_client().await;

    let mut stream = client
        .enumerate(proto::EnumerateRequest {
            max_walk: u64::MAX,
            source_node_id: "local".to_string(),
            require_completeness_marker: true,
            ..Default::default()
        })
        .await
        .expect("an over-large walk is clamped, not an error")
        .into_inner();

    // An empty node enumerates to nothing; the point is that it returns.
    while stream
        .message()
        .await
        .expect("stream is well-formed")
        .is_some()
    {}
}

#[tokio::test]
async fn stat_chunks_caps_full_hash_work_to_sixteen_chunks() {
    let (mut client, _control, _dir) = raw_client().await;
    let status = client
        .stat_chunks(proto::StatChunksRequest {
            cids: vec![vec![0u8; 32]; 17],
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("at most 16"));
}

/// Protobuf additions are ignored by old clients. Without an explicit
/// capability bit, an old client would ignore the terminal truncation marker
/// and publish the prefix as complete.
#[tokio::test]
async fn truncation_is_refused_to_a_client_that_cannot_read_the_marker() {
    let (mut client, control, _dir) = raw_client().await;
    let child = control.store.put_chunk(b"child", None).unwrap();
    let root = control
        .store
        .put_entry(&Entry {
            payload: Vec::new(),
            links: vec![Link {
                name: None,
                target: child,
            }],
            meta: None,
        })
        .unwrap();
    control.pointer_log.create("release", root).unwrap();

    let status = client
        .enumerate(proto::EnumerateRequest {
            max_walk: 1,
            source_node_id: "local".to_string(),
            require_completeness_marker: false,
            ..Default::default()
        })
        .await
        .expect_err("an old client must not receive a silently truncated stream");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(status.message().contains("upgrade"), "{status}");
}
