//! The event stream over the wire: replay windows, the replay→live seam,
//! and kind filters — matching the local tail's semantics envelope for
//! envelope.

use std::sync::Arc;

use dag_control::Control;
use dag_core::{ContentStore, PinScope, PinTarget};
use dag_net::{bind, RemoteNode, ServeOptions};

fn fresh_control() -> (Arc<Control>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    (Arc::new(control), dir)
}

async fn serve_and_connect(control: Arc<Control>) -> RemoteNode {
    let bound = bind(
        control,
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions::default(),
    )
    .await
    .unwrap();
    let url = format!("grpc://{}", bound.local_addr);
    tokio::spawn(bound.serve());
    RemoteNode::connect(&url, None).await.unwrap()
}

/// Emit `n` pointer events by creating pointers.
fn emit_pointer_events(control: &Control, n: usize) {
    for i in 0..n {
        let cid = control
            .store
            .put_chunk(format!("content {i}").as_bytes(), None)
            .unwrap();
        control.pointer_log.create(&format!("p{i}"), cid).unwrap();
    }
}

#[tokio::test]
async fn a_replay_window_arrives_ordered_and_the_stream_ends() {
    let (server_control, _dir) = fresh_control();
    emit_pointer_events(&server_control, 3);

    let remote = serve_and_connect(server_control).await;
    let mut stream = remote
        .subscribe_events(true, 0, 0, &[], true) // replay, no follow
        .await
        .unwrap();

    let mut seqs = Vec::new();
    while let Some(envelope) = stream.message().await.unwrap() {
        // The payload is the full local-tail line: it parses as an envelope
        // and carries the same seq the proto field promises.
        let parsed: dag_control::events::EventEnvelope =
            serde_json::from_str(&envelope.json).unwrap();
        assert_eq!(parsed.seq, envelope.seq);
        seqs.push(envelope.seq);
    }
    assert_eq!(seqs, vec![0, 1, 2]);
}

#[tokio::test]
async fn the_live_tail_delivers_an_event_created_after_subscription() {
    let (server_control, _dir) = fresh_control();
    let remote = serve_and_connect(server_control.clone()).await;

    let mut stream = remote
        .subscribe_events(false, 0, 0, &[], false)
        .await
        .unwrap();

    // Now that the subscription exists, make something happen.
    emit_pointer_events(&server_control, 1);

    let envelope = stream.message().await.unwrap().unwrap();
    assert!(envelope.json.contains("PointerUpdate"), "{}", envelope.json);
    assert!(envelope.json.contains("p0"), "{}", envelope.json);
}

#[tokio::test]
async fn the_replay_to_live_seam_delivers_every_event_exactly_once() {
    let (server_control, _dir) = fresh_control();
    emit_pointer_events(&server_control, 2);

    let remote = serve_and_connect(server_control.clone()).await;
    let mut stream = remote
        .subscribe_events(true, 0, 0, &[], false)
        .await
        .unwrap();

    // Drain the replay: seqs 0 and 1.
    let first = stream.message().await.unwrap().unwrap();
    let second = stream.message().await.unwrap().unwrap();
    assert_eq!((first.seq, second.seq), (0, 1));

    // A third event lands after the replay was read.
    let cid = server_control.store.put_chunk(b"the third", None).unwrap();
    server_control.pointer_log.create("seam", cid).unwrap();

    let third = stream.message().await.unwrap().unwrap();
    assert_eq!(third.seq, 2, "the seam duplicated or dropped an event");
}

#[tokio::test]
async fn a_kind_filter_admits_only_that_kind() {
    let (server_control, _dir) = fresh_control();
    let remote = serve_and_connect(server_control.clone()).await;

    let mut stream = remote
        .subscribe_events(false, 0, 0, &["pin".to_string()], false)
        .await
        .unwrap();

    // A pointer event (filtered out), then a pin event (admitted).
    emit_pointer_events(&server_control, 1);
    let cid = server_control.store.put_chunk(b"pinned", None).unwrap();
    server_control
        .pin_log
        .create("keep", PinTarget::Direct(cid), PinScope::Global, None, None)
        .unwrap();

    let envelope = stream.message().await.unwrap().unwrap();
    assert!(
        envelope.json.contains("PinEvent"),
        "the filter admitted the wrong kind: {}",
        envelope.json
    );
    assert!(envelope.json.contains("keep"), "{}", envelope.json);
}

#[tokio::test]
async fn a_filtered_replay_counts_only_matching_events() {
    let (server_control, _dir) = fresh_control();

    // Interleave: pointer, pin, pointer.
    emit_pointer_events(&server_control, 1);
    let cid = server_control.store.put_chunk(b"pinned", None).unwrap();
    server_control
        .pin_log
        .create("keep", PinTarget::Direct(cid), PinScope::Global, None, None)
        .unwrap();
    let cid2 = server_control.store.put_chunk(b"more", None).unwrap();
    server_control.pointer_log.create("q0", cid2).unwrap();

    let remote = serve_and_connect(server_control).await;
    let mut stream = remote
        .subscribe_events(true, 0, 0, &["pin".to_string()], true)
        .await
        .unwrap();

    let mut kinds = Vec::new();
    while let Some(envelope) = stream.message().await.unwrap() {
        let parsed: dag_control::events::EventEnvelope =
            serde_json::from_str(&envelope.json).unwrap();
        kinds.push(parsed.event.kind());
    }
    assert_eq!(kinds, vec!["pin"], "the filter leaked other kinds");
}
