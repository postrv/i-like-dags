//! The CAS pointer write, over the wire: the primary serializes, stale
//! expectations are refused with the actual head named, and concurrent
//! remote writers cannot lose an update silently.

use std::sync::Arc;

use dag_control::Control;
use dag_core::{
    Cid, ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, TriggerPolicy,
};
use dag_net::{
    bind, AuthScope, CredentialSet, NetError, RemoteNode, ServeOptions, ServerCredential,
};

const POINTER_TOKEN: &str = "pointer-token-0123456789abcdef01234567";
const POINTER_TRIGGER_TOKEN: &str = "pointer-trigger-token-0123456789abcdef";
const TRIGGER_TOKEN: &str = "trigger-token-0123456789abcdef01234567";
const ADMIN_TOKEN: &str = "admin-token-0123456789abcdef012345678";

fn fresh_control() -> (Arc<Control>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    (Arc::new(control), dir)
}

async fn serve_and_connect(control: Arc<Control>) -> RemoteNode {
    serve_and_connect_with(control, CredentialSet::none(), None).await
}

async fn serve_and_connect_with(
    control: Arc<Control>,
    credentials: CredentialSet,
    token: Option<&str>,
) -> RemoteNode {
    let bound = bind(
        control,
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions {
            credentials,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let url = format!("grpc://{}", bound.local_addr);
    tokio::spawn(bound.serve());
    RemoteNode::connect(&url, token).await.unwrap()
}

async fn serve_with_scopes(
    control: Arc<Control>,
    token: &'static str,
    scopes: &[AuthScope],
) -> RemoteNode {
    let credential = ServerCredential::new(token, scopes.iter().copied()).unwrap();
    serve_and_connect_with(
        control,
        CredentialSet::rotating(credential, None),
        Some(token),
    )
    .await
}

fn put(control: &Control, bytes: &[u8]) -> Cid {
    control.store.put_chunk(bytes, None).unwrap()
}

fn subscribe_pointer_job(control: &Control, pointer_id: &str, job_id: &str) {
    let job = JobSpec {
        job_id: JobId::from(job_id),
        placement: None,
        inputs: JobInput::new().with_pointer(pointer_id),
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["hash".into()],
        code_ref: "hash".into(),
        policy: JobPolicy {
            trigger: TriggerPolicy::OnPointerUpdate,
            ..JobPolicy::default()
        },
        config: None,
    };
    control.create_job(job.clone()).unwrap();
    control.subscribe_pointer(pointer_id, job.job_id).unwrap();
}

fn assert_permission_denied(error: NetError) {
    match error {
        NetError::Status(status) => {
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
            assert_eq!(
                status.message(),
                "trigger scope is required for this pointer update"
            );
        }
        other => panic!("expected PermissionDenied, got {other}"),
    }
}

#[tokio::test]
async fn pointer_only_update_with_active_subscription_is_atomically_refused() {
    let (server_control, _dir) = fresh_control();
    let initial = put(&server_control, b"initial");
    let updated = put(&server_control, b"updated");
    server_control
        .pointer_log
        .create("release", initial.clone())
        .unwrap();
    subscribe_pointer_job(&server_control, "release", "release-hook");
    let events_before = server_control.pointer_log.event_cids().unwrap();
    let generation_before = server_control.sync_event_generation().unwrap();
    let store_before = server_control.stats().unwrap();
    let remote =
        serve_with_scopes(server_control.clone(), POINTER_TOKEN, &[AuthScope::Pointer]).await;

    for _ in 0..3 {
        assert_permission_denied(
            remote
                .update_pointer("release", &updated, 1)
                .await
                .unwrap_err(),
        );
    }

    let head = server_control.pointer_log.get_head("release").unwrap();
    assert_eq!(head.seq, 1);
    assert_eq!(head.current_cid, initial);
    assert_eq!(
        server_control.pointer_log.event_cids().unwrap(),
        events_before
    );
    assert_eq!(
        server_control.sync_event_generation().unwrap(),
        generation_before
    );
    assert_eq!(
        server_control.job_log.trigger_queue_depths().unwrap(),
        (0, 0)
    );
    let store_after = server_control.stats().unwrap();
    assert_eq!(store_after.chunks, store_before.chunks);
    assert_eq!(store_after.bytes, store_before.bytes);
}

#[tokio::test]
async fn pointer_only_create_with_active_subscription_is_atomically_refused() {
    let (server_control, _dir) = fresh_control();
    let target = put(&server_control, b"created");
    subscribe_pointer_job(&server_control, "new-release", "create-hook");
    let events_before = server_control.pointer_log.event_cids().unwrap();
    let generation_before = server_control.sync_event_generation().unwrap();
    let remote =
        serve_with_scopes(server_control.clone(), POINTER_TOKEN, &[AuthScope::Pointer]).await;

    assert_permission_denied(
        remote
            .update_pointer("new-release", &target, 0)
            .await
            .unwrap_err(),
    );

    assert!(matches!(
        server_control.pointer_log.get_head("new-release"),
        Err(dag_control::PointerError::NotFound(_))
    ));
    assert_eq!(
        server_control.pointer_log.event_cids().unwrap(),
        events_before
    );
    assert_eq!(
        server_control.sync_event_generation().unwrap(),
        generation_before
    );
    assert_eq!(
        server_control.job_log.trigger_queue_depths().unwrap(),
        (0, 0)
    );
}

#[tokio::test]
async fn pointer_and_trigger_scopes_authorize_subscribed_update() {
    let (server_control, _dir) = fresh_control();
    let initial = put(&server_control, b"initial");
    let updated = put(&server_control, b"updated");
    server_control
        .pointer_log
        .create("release", initial)
        .unwrap();
    subscribe_pointer_job(&server_control, "release", "release-hook");
    let remote = serve_with_scopes(
        server_control.clone(),
        POINTER_TRIGGER_TOKEN,
        &[AuthScope::Pointer, AuthScope::Trigger],
    )
    .await;

    assert_eq!(
        remote.update_pointer("release", &updated, 1).await.unwrap(),
        2
    );
    assert_eq!(
        server_control.pointer_log.resolve("release").unwrap(),
        updated
    );
    assert_eq!(
        server_control.job_log.trigger_queue_depths().unwrap(),
        (1, 0)
    );
}

#[tokio::test]
async fn pointer_only_scope_still_allows_create_and_update_without_subscriptions() {
    let (server_control, _dir) = fresh_control();
    let first = put(&server_control, b"first");
    let second = put(&server_control, b"second");
    let remote =
        serve_with_scopes(server_control.clone(), POINTER_TOKEN, &[AuthScope::Pointer]).await;

    assert_eq!(remote.update_pointer("plain", &first, 0).await.unwrap(), 1);
    assert_eq!(remote.update_pointer("plain", &second, 1).await.unwrap(), 2);
    assert_eq!(server_control.pointer_log.resolve("plain").unwrap(), second);
    assert_eq!(
        server_control.job_log.trigger_queue_depths().unwrap(),
        (0, 0)
    );
}

#[tokio::test]
async fn trigger_scope_without_pointer_scope_cannot_call_pointer_service() {
    let (server_control, _dir) = fresh_control();
    let target = put(&server_control, b"target");
    let remote =
        serve_with_scopes(server_control.clone(), TRIGGER_TOKEN, &[AuthScope::Trigger]).await;

    match remote
        .update_pointer("plain", &target, 0)
        .await
        .unwrap_err()
    {
        NetError::Status(status) => {
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
            assert_eq!(status.message(), "permission denied");
        }
        other => panic!("expected PermissionDenied, got {other}"),
    }
    assert!(server_control
        .pointer_log
        .list_pointers()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn legacy_admin_and_loopback_no_auth_preserve_subscribed_updates() {
    let (admin_control, _admin_dir) = fresh_control();
    let first = put(&admin_control, b"admin-first");
    let second = put(&admin_control, b"admin-second");
    admin_control
        .pointer_log
        .create("admin-release", first)
        .unwrap();
    subscribe_pointer_job(&admin_control, "admin-release", "admin-hook");
    let admin_remote = serve_and_connect_with(
        admin_control.clone(),
        CredentialSet::legacy_admin(Some(ADMIN_TOKEN)).unwrap(),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(
        admin_remote
            .update_pointer("admin-release", &second, 1)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        admin_control.job_log.trigger_queue_depths().unwrap(),
        (1, 0)
    );

    let (loopback_control, _loopback_dir) = fresh_control();
    let first = put(&loopback_control, b"loopback-first");
    let second = put(&loopback_control, b"loopback-second");
    loopback_control
        .pointer_log
        .create("loopback-release", first)
        .unwrap();
    subscribe_pointer_job(&loopback_control, "loopback-release", "loopback-hook");
    let loopback_remote = serve_and_connect(loopback_control.clone()).await;
    assert_eq!(
        loopback_remote
            .update_pointer("loopback-release", &second, 1)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        loopback_control.job_log.trigger_queue_depths().unwrap(),
        (1, 0)
    );
}

#[tokio::test]
async fn create_update_and_resolve_round_trip() {
    let (server_control, _dir) = fresh_control();
    let v1 = put(&server_control, b"one");
    let v2 = put(&server_control, b"two");
    let remote = serve_and_connect(server_control.clone()).await;

    // expect_seq 0 creates.
    let seq = remote.update_pointer("model", &v1, 0).await.unwrap();
    assert_eq!(seq, 1);

    // A matching expectation advances.
    let seq = remote.update_pointer("model", &v2, 1).await.unwrap();
    assert_eq!(seq, 2);

    let (cid, seq) = remote.resolve_pointer("model").await.unwrap();
    assert_eq!(cid, v2);
    assert_eq!(seq, 2);
    assert_eq!(remote.list_pointers().await.unwrap(), vec!["model"]);

    // The server's own view agrees — the write really landed in its log.
    assert_eq!(server_control.pointer_log.resolve("model").unwrap(), v2);
    assert_eq!(server_control.pointer_log.get_head("model").unwrap().seq, 2);
}

#[tokio::test]
async fn a_stale_expectation_is_refused_with_the_actual_head_named() {
    let (server_control, _dir) = fresh_control();
    let v1 = put(&server_control, b"one");
    let v2 = put(&server_control, b"two");
    let v3 = put(&server_control, b"three");
    let remote = serve_and_connect(server_control.clone()).await;

    remote.update_pointer("p", &v1, 0).await.unwrap();
    remote.update_pointer("p", &v2, 1).await.unwrap();

    // A writer whose view is one behind.
    let err = remote.update_pointer("p", &v3, 1).await.unwrap_err();
    match err {
        NetError::Status(status) => {
            assert_eq!(status.code(), tonic::Code::FailedPrecondition);
            assert!(status.message().contains("seq 2"), "{}", status.message());
            assert!(
                status.message().contains(&v2.to_hex()),
                "the refusal should name the head CID: {}",
                status.message()
            );
        }
        other => panic!("expected FailedPrecondition, got {other}"),
    }

    // Nothing moved.
    assert_eq!(server_control.pointer_log.resolve("p").unwrap(), v2);
}

#[tokio::test]
async fn resolving_an_unknown_pointer_is_not_found() {
    let (server_control, _dir) = fresh_control();
    let remote = serve_and_connect(server_control).await;

    match remote.resolve_pointer("ghost").await.unwrap_err() {
        NetError::Status(status) => assert_eq!(status.code(), tonic::Code::NotFound),
        other => panic!("expected NotFound, got {other}"),
    }
}

#[tokio::test]
async fn pointer_listing_is_bounded_and_cursor_paginated() {
    use dag_net::proto::pointers_client::PointersClient;

    let (server_control, _dir) = fresh_control();
    for id in ["alpha", "bravo", "charlie", "delta", "echo"] {
        let cid = put(&server_control, id.as_bytes());
        server_control.pointer_log.create(id, cid).unwrap();
    }
    let remote = serve_and_connect(server_control).await;
    let mut raw = PointersClient::connect(format!(
        "http://{}",
        remote.url.trim_start_matches("grpc://")
    ))
    .await
    .unwrap();

    let first = raw
        .list(dag_net::proto::ListPointersRequest {
            page_size: 2,
            after_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.ids, ["alpha", "bravo"]);
    assert_eq!(first.next_after_id, "bravo");

    let second = raw
        .list(dag_net::proto::ListPointersRequest {
            page_size: 2,
            after_id: first.next_after_id,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.ids, ["charlie", "delta"]);
    assert_eq!(second.next_after_id, "delta");

    let status = raw
        .list(dag_net::proto::ListPointersRequest {
            page_size: 1_001,
            after_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    assert_eq!(
        remote.list_pointers().await.unwrap(),
        ["alpha", "bravo", "charlie", "delta", "echo"]
    );
}

#[tokio::test]
async fn concurrent_remote_writers_get_exactly_one_win() {
    let (server_control, _dir) = fresh_control();
    let base = put(&server_control, b"base");
    let remote = serve_and_connect(server_control.clone()).await;
    remote.update_pointer("p", &base, 0).await.unwrap();

    // Sixteen concurrent RPCs, all expecting head seq 1.
    let mut handles = Vec::new();
    for i in 0..16 {
        let cid = put(&server_control, format!("candidate {i}").as_bytes());
        let remote = remote.clone();
        handles.push(tokio::spawn(async move {
            remote.update_pointer("p", &cid, 1).await
        }));
    }
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let wins = results.iter().filter(|r| r.is_ok()).count();
    let conflicts = results
        .iter()
        .filter(|r| {
            matches!(
                r,
                Err(NetError::Status(s)) if s.code() == tonic::Code::FailedPrecondition
            )
        })
        .count();

    assert_eq!(wins, 1, "the CAS admitted {wins} writers past one head");
    assert_eq!(conflicts, 15);
    assert_eq!(server_control.pointer_log.get_head("p").unwrap().seq, 2);
}

#[tokio::test]
async fn a_malformed_cid_is_refused_before_touching_the_log() {
    let (server_control, _dir) = fresh_control();
    let remote = serve_and_connect(server_control.clone()).await;

    // Drive the raw generated client to send 3 bytes where a CID belongs —
    // RemoteNode's typed API cannot express this, which is the point of
    // testing beneath it.
    use dag_net::proto::pointers_client::PointersClient;
    let mut raw = PointersClient::connect(format!(
        "http://{}",
        remote.url.trim_start_matches("grpc://")
    ))
    .await
    .unwrap();
    let err = raw
        .update(dag_net::proto::UpdatePointerRequest {
            id: "p".into(),
            new_cid: vec![1, 2, 3],
            expect_seq: 0,
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("32 bytes"), "{}", err.message());
    assert!(server_control
        .pointer_log
        .list_pointers()
        .unwrap()
        .is_empty());
}
