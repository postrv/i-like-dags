//! The ADR-002 acceptance suite, over the wire: a replica on the other side
//! of a socket is byte-identical, resumable, and no more trusting than a
//! replica on the other side of a directory path.

use std::sync::Arc;

use dag_control::sync::{EventBatchOutcome, SyncOptions};
use dag_control::Control;
use dag_core::{
    Cid, ContentStore, Determinism, Entry, JobId, JobInput, JobPolicy, JobSpec, Link, PinScope,
    PinTarget, TriggerPolicy,
};
use dag_net::{
    bind, AuthScope, CredentialSet, NetError, RemoteNode, ServeOptions, ServerCredential,
};

fn fresh_control() -> (Arc<Control>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    (Arc::new(control), dir)
}

/// Serve `control` on an ephemeral loopback port and connect to it.
async fn serve_and_connect(control: Arc<Control>, token: Option<&str>) -> RemoteNode {
    serve_and_connect_with(control, CredentialSet::legacy_admin(token).unwrap(), token).await
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

async fn serve_raw_sync(
    control: Arc<Control>,
) -> dag_net::proto::sync_client::SyncClient<tonic::transport::Channel> {
    let bound = bind(
        control,
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions::default(),
    )
    .await
    .unwrap();
    let endpoint = format!("http://{}", bound.local_addr);
    tokio::spawn(bound.serve());
    dag_net::proto::sync_client::SyncClient::connect(endpoint)
        .await
        .unwrap()
}

fn put(control: &Control, bytes: &[u8]) -> Cid {
    control.store.put_chunk(bytes, None).unwrap()
}

#[tokio::test]
async fn protocol_v2_is_rejected_before_replication() {
    let (destination, _d) = fresh_control();
    let mut client = serve_raw_sync(destination).await;
    let error = client
        .negotiate(dag_net::proto::ProtocolHello {
            protocol_major: 2,
            protocol_minor: 1,
            required_capabilities: vec!["atomic-sync-publication-v1".to_string()],
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("server requires 3"));
}

#[tokio::test]
async fn a_pushed_replica_resolves_the_same_pointer_to_the_same_cid() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();
    let remote = serve_and_connect(
        remote_control.clone(),
        Some("test-node-token-0123456789abcdef"),
    )
    .await;

    let v1 = put(&local, b"version one");
    let v2 = put(&local, b"version two");
    local.pointer_log.create("model", v1).unwrap();
    local.pointer_log.update("model", v2.clone()).unwrap();
    let source_events = local.pointer_log.event_cids().unwrap();
    for (_, _, event_cid) in &source_events {
        assert!(!remote_control.store.has_chunk(event_cid).unwrap());
    }

    let report = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert!(report.chunks_sent > 0);

    assert_eq!(remote_control.pointer_log.resolve("model").unwrap(), v2);
    assert_eq!(remote_control.store.get_chunk(&v2).unwrap(), b"version two");
    for (_, _, event_cid) in &source_events {
        assert!(
            remote_control.store.has_chunk(event_cid).unwrap(),
            "content-only enumeration omitted event chunk {event_cid}"
        );
    }
    // Byte-identical history, CID for CID — the ADR-002 guarantee.
    assert_eq!(
        source_events,
        remote_control.pointer_log.event_cids().unwrap()
    );
}

fn subscribed_release_job() -> JobSpec {
    JobSpec {
        job_id: JobId::from("destination-release-hook"),
        placement: None,
        inputs: JobInput::new().with_pointer("release"),
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["hash".into()],
        code_ref: "hash".into(),
        policy: JobPolicy {
            trigger: TriggerPolicy::OnPointerUpdate,
            ..JobPolicy::default()
        },
        config: None,
    }
}

#[tokio::test]
async fn sync_only_commit_cannot_advance_an_actively_subscribed_pointer() {
    let (local, _local_dir) = fresh_control();
    let (destination, _destination_dir) = fresh_control();
    let initial = put(&local, b"initial release");
    local
        .pointer_log
        .create("release", initial.clone())
        .unwrap();
    dag_control::sync::push(
        local.as_ref(),
        destination.as_ref(),
        &SyncOptions::default(),
    )
    .unwrap();

    let job = subscribed_release_job();
    destination.create_job(job.clone()).unwrap();
    destination
        .subscribe_pointer("release", job.job_id)
        .unwrap();
    let updated = put(&local, b"updated release");
    local.pointer_log.update("release", updated).unwrap();

    let head_before = destination.pointer_log.get_head("release").unwrap();
    let events_before = destination.pointer_log.event_cids().unwrap();
    let generation_before = destination.sync_event_generation().unwrap();

    let token = "sync-only-token-0123456789abcdef012345";
    let credential = ServerCredential::new(token, [AuthScope::Sync]).unwrap();
    let remote = serve_and_connect_with(
        destination.clone(),
        CredentialSet::rotating(credential, None),
        Some(token),
    )
    .await;
    let error = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("trigger scope"), "{error}");

    // The refused Commit restores its staged offer. Repeating the exact
    // resumable transfer reaches the same authorization decision rather than
    // observing a partial publication or a stranded committing session.
    let retry = dag_net::sync::push(local, &remote, &SyncOptions::default())
        .await
        .unwrap_err();
    assert!(retry.to_string().contains("trigger scope"), "{retry}");
    assert_eq!(
        destination.pointer_log.get_head("release").unwrap(),
        head_before
    );
    assert_eq!(destination.pointer_log.event_cids().unwrap(), events_before);
    assert_eq!(
        destination.sync_event_generation().unwrap(),
        generation_before
    );
    assert_eq!(destination.job_log.trigger_queue_depths().unwrap(), (0, 0));
}

#[tokio::test]
async fn sync_and_trigger_scopes_can_advance_an_actively_subscribed_pointer() {
    let (local, _local_dir) = fresh_control();
    let (destination, _destination_dir) = fresh_control();
    let initial = put(&local, b"initial release");
    local.pointer_log.create("release", initial).unwrap();
    dag_control::sync::push(
        local.as_ref(),
        destination.as_ref(),
        &SyncOptions::default(),
    )
    .unwrap();

    let job = subscribed_release_job();
    destination.create_job(job.clone()).unwrap();
    destination
        .subscribe_pointer("release", job.job_id)
        .unwrap();
    let updated = put(&local, b"trigger-authorized release");
    local
        .pointer_log
        .update("release", updated.clone())
        .unwrap();

    let token = "sync-trigger-token-0123456789abcdef01234";
    let credential = ServerCredential::new(token, [AuthScope::Sync, AuthScope::Trigger]).unwrap();
    let remote = serve_and_connect_with(
        destination.clone(),
        CredentialSet::rotating(credential, None),
        Some(token),
    )
    .await;
    let report = dag_net::sync::push(local, &remote, &SyncOptions::default())
        .await
        .unwrap();

    assert!(report.is_complete(), "{:?}", report.failures);
    assert_eq!(destination.pointer_log.resolve("release").unwrap(), updated);
    assert_eq!(
        destination.job_log.trigger_queue_depths().unwrap(),
        (0, 0),
        "replication publishes history but does not synthesize a local pointer-update intent"
    );
}

#[tokio::test]
async fn queued_trigger_freezes_secondary_pointer_and_job_revision_before_sync() {
    let (source, _source_dir) = fresh_control();
    let (destination, _destination_dir) = fresh_control();
    let trigger_v1 = put(&source, b"trigger-v1");
    let input_v1 = put(&source, b"input-v1");
    source.pointer_log.create("trigger", trigger_v1).unwrap();
    source
        .pointer_log
        .create("secondary", input_v1.clone())
        .unwrap();
    dag_control::sync::push(
        source.as_ref(),
        destination.as_ref(),
        &SyncOptions::default(),
    )
    .unwrap();

    let job = JobSpec {
        job_id: JobId::from("secondary-input-hook"),
        placement: None,
        inputs: JobInput::new().with_pointer("secondary"),
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["hash".into()],
        code_ref: "hash".into(),
        policy: JobPolicy {
            trigger: TriggerPolicy::OnPointerUpdate,
            ..JobPolicy::default()
        },
        config: None,
    };
    destination.create_job(job.clone()).unwrap();
    destination
        .subscribe_pointer("trigger", job.job_id.clone())
        .unwrap();
    let trigger_v2 = put(&destination, b"trigger-v2");
    destination
        .pointer_log
        .update("trigger", trigger_v2)
        .unwrap();
    assert_eq!(destination.job_log.trigger_queue_depths().unwrap(), (1, 0));

    // Mirror the exact triggering pointer event back to the source, then
    // remove the subscription and revise the destination job. Neither change
    // is allowed to rewrite the already-authorized intent.
    dag_control::sync::push(
        destination.as_ref(),
        source.as_ref(),
        &SyncOptions::default(),
    )
    .unwrap();
    assert!(destination
        .unsubscribe_pointer("trigger", job.job_id.clone())
        .unwrap());
    let mut revised = job.clone();
    revised.code_ref = "concat".into();
    revised.config = Some(serde_json::json!({"separator": "changed-after-enqueue"}));
    destination.update_job(revised).unwrap();

    let input_v2 = put(&source, b"input-v2");
    source
        .pointer_log
        .update("secondary", input_v2.clone())
        .unwrap();
    let token = "snapshot-sync-token-0123456789abcdef01234";
    let credential = ServerCredential::new(token, [AuthScope::Sync]).unwrap();
    let remote = serve_and_connect_with(
        destination.clone(),
        CredentialSet::rotating(credential, None),
        Some(token),
    )
    .await;
    let report = dag_net::sync::push(source, &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert_eq!(
        destination.pointer_log.resolve("secondary").unwrap(),
        input_v2
    );

    let drained = destination.drain_job_trigger_queue(10).unwrap();
    assert_eq!(drained.enqueued, 1);
    let run = destination.runs(job.job_id, 1).unwrap().remove(0);
    let revision = run.revision.expect("snapshot-backed run has a revision");
    assert_eq!(revision.event_seq, 1);
    assert_eq!(revision.code_ref, "hash");
    assert_eq!(run.manifest.pointer_heads.len(), 1);
    assert_eq!(run.manifest.pointer_heads[0].pointer_id, "secondary");
    assert_eq!(run.manifest.pointer_heads[0].head_cid, input_v1);
    assert_eq!(run.manifest.pointer_heads[0].log_seq, 1);
}

#[tokio::test]
async fn a_pull_replicates_the_remote_graph_and_its_pins() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let target = put(&remote_control, b"keep me");
    remote_control
        .pin_log
        .create(
            "keep",
            PinTarget::Direct(target.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::pull(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);

    assert!(local.store.has_chunk(&target).unwrap());
    // The pin travelled and is live at the destination. (This used to also
    // assert its `importance`; schema 2 removed that field.)
    let head = local.pin_log.head("keep").unwrap();
    assert_eq!(head.event.pin_id, "keep");
    assert!(head.is_providing_retention(dag_control::now_unix()));
    assert_eq!(
        local.pin_log.event_cids().unwrap(),
        remote_control.pin_log.event_cids().unwrap()
    );
}

#[tokio::test]
async fn a_pull_reports_absent_remote_history_without_blocking_publication() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let v1 = put(&remote_control, b"version one");
    let v2 = put(&remote_control, b"version two");
    remote_control
        .pointer_log
        .create("release", v1.clone())
        .unwrap();
    remote_control
        .pointer_log
        .update("release", v2.clone())
        .unwrap();
    std::fs::remove_file(remote_control.store.chunk_path(&v1)).unwrap();

    let remote = serve_and_connect(remote_control, None).await;
    let report = dag_net::sync::pull(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();

    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.missing_at_source, vec![v1.to_hex()]);
    assert_eq!(local.pointer_log.resolve("release").unwrap(), v2);
}

#[tokio::test]
async fn a_pull_keeps_an_absent_remote_live_head_fatal_but_classifies_history() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let v1 = put(&remote_control, b"version one");
    let v2 = put(&remote_control, b"version two");
    remote_control
        .pointer_log
        .create("release", v1.clone())
        .unwrap();
    remote_control
        .pointer_log
        .update("release", v2.clone())
        .unwrap();
    std::fs::remove_file(remote_control.store.chunk_path(&v1)).unwrap();
    std::fs::remove_file(remote_control.store.chunk_path(&v2)).unwrap();

    let remote = serve_and_connect(remote_control, None).await;
    let report = dag_net::sync::pull(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();

    assert_eq!(report.missing_at_source, vec![v1.to_hex()]);
    assert!(report
        .failures
        .iter()
        .any(|failure| failure.cid == v2.to_hex()));
    assert!(!report.is_complete());
    assert!(report.publication_blocked);
    assert!(local.pointer_log.list_pointers().unwrap().is_empty());
}

#[tokio::test]
async fn a_second_push_sends_nothing() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();
    let remote = serve_and_connect(remote_control.clone(), None).await;

    let cid = put(&local, b"payload");
    local.pointer_log.create("p", cid).unwrap();

    let first = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(first.chunks_sent > 0);

    let second = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert_eq!(second.chunks_sent, 0, "a repeat sync re-sent content");
    assert_eq!(second.pointer_events, 0, "a repeat sync re-filed events");
    assert_eq!(second.chunks_skipped, first.chunks_sent);
    assert!(second.is_complete());
}

#[tokio::test]
async fn a_push_repairs_an_indexed_corrupt_remote_chunk() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let body = b"remote integrity must be checked before skipping";
    let cid = put(&local, body);
    local.pointer_log.create("p", cid.clone()).unwrap();

    put(&remote_control, body);
    std::fs::write(remote_control.store.chunk_path(&cid), b"corrupt").unwrap();
    assert!(remote_control.store.get_chunk(&cid).is_err(), "setup");

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::push(local, &remote, &SyncOptions::default())
        .await
        .unwrap();

    assert!(report.is_complete(), "{report:?}");
    assert!(report.chunks_sent > 0, "remote corruption was skipped");
    assert_eq!(remote_control.store.get_chunk(&cid).unwrap(), body);
}

#[tokio::test]
async fn a_dry_run_push_measures_without_writing() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();
    let remote = serve_and_connect(remote_control.clone(), None).await;

    let cid = put(&local, b"payload");
    local.pointer_log.create("p", cid.clone()).unwrap();

    let opts = SyncOptions {
        dry_run: true,
        ..Default::default()
    };
    let report = dag_net::sync::push(local.clone(), &remote, &opts)
        .await
        .unwrap();

    assert!(report.dry_run);
    assert!(report.chunks_sent > 0, "dry run reported nothing to do");
    assert!(report.bytes_sent > 0);
    assert!(!remote_control.store.has_chunk(&cid).unwrap());
    assert!(remote_control
        .pointer_log
        .list_pointers()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_dry_run_push_reports_remote_divergence_without_writing() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let local_value = put(&local, b"local");
    local.pointer_log.create("shared", local_value).unwrap();
    let remote_value = put(&remote_control, b"remote");
    remote_control
        .pointer_log
        .create("shared", remote_value.clone())
        .unwrap();
    let before = remote_control.pointer_log.event_cids().unwrap();

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::push(
        local,
        &remote,
        &SyncOptions {
            dry_run: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(!report.is_complete());
    assert_eq!(report.divergent.len(), 1, "{report:?}");
    assert_eq!(remote_control.pointer_log.event_cids().unwrap(), before);
    assert_eq!(
        remote_control.pointer_log.resolve("shared").unwrap(),
        remote_value
    );
}

#[tokio::test]
async fn remote_walk_truncation_is_propagated_and_blocks_local_heads() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let child = put(&remote_control, b"child");
    let root = remote_control
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
    remote_control.pointer_log.create("release", root).unwrap();

    let remote = serve_and_connect(remote_control, None).await;
    let report = dag_net::sync::pull(
        local.clone(),
        &remote,
        &SyncOptions {
            max_walk: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(!report.is_complete());
    let truncation = report.truncation.expect("wire lost truncation metadata");
    assert_eq!(truncation.visited, 1);
    assert_eq!(truncation.limit, 1);
    assert!(truncation.remaining_frontier > 0);
    assert!(report.publication_blocked);
    assert!(local.pointer_log.list_pointers().unwrap().is_empty());
}

#[tokio::test]
async fn source_node_identity_selects_local_pin_roots_over_the_wire() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let matching = put(&remote_control, b"node-a");
    let other = put(&remote_control, b"node-b");
    remote_control
        .pin_log
        .create(
            "matching",
            PinTarget::Direct(matching.clone()),
            PinScope::Local {
                node_id: "node-a".to_string(),
            },
            None,
            None,
        )
        .unwrap();
    remote_control
        .pin_log
        .create(
            "other",
            PinTarget::Direct(other.clone()),
            PinScope::Local {
                node_id: "node-b".to_string(),
            },
            None,
            None,
        )
        .unwrap();

    let remote = serve_and_connect(remote_control, None).await;
    let report = dag_net::sync::pull(
        local.clone(),
        &remote,
        &SyncOptions {
            source_node_id: "node-a".to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(report.is_complete(), "{report:?}");
    assert!(local.store.has_chunk(&matching).unwrap());
    assert!(!local.store.has_chunk(&other).unwrap());
    assert_eq!(local.pin_log.event_cids().unwrap().len(), 2);
    assert!(matches!(
        local.retention_status(&matching, Some("local")).unwrap(),
        dag_control::RetentionStatus::Unprotected
    ));
}

#[tokio::test]
async fn divergent_history_is_refused_by_the_server_not_overwritten() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let a = put(&local, b"source's first value");
    local.pointer_log.create("shared", a).unwrap();

    let b = put(&remote_control, b"other value");
    remote_control
        .pointer_log
        .create("shared", b.clone())
        .unwrap();

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();

    assert!(
        !report.is_complete(),
        "conflicting history was accepted silently"
    );
    assert!(
        report.divergent.iter().any(|f| f.reason.contains("shared")),
        "failures={:?} divergent={:?}",
        report.failures,
        report.divergent
    );
    // The destination kept its own value.
    assert_eq!(remote_control.pointer_log.resolve("shared").unwrap(), b);
}

/// The measured attack from the directory suite, now arriving over a socket:
/// a hostile peer pushes a deactivation of a pin *it* created, under a name
/// the receiving node uses for a live pin of its own. The server's own
/// validation — not anything the client does — must refuse it.
#[tokio::test]
async fn a_remote_peer_cannot_deactivate_a_local_pin_over_the_wire() {
    let (hostile, _h) = fresh_control();
    let (victim_control, _v) = fresh_control();

    // The victim's pin that must survive.
    let mine = put(&victim_control, b"my content");
    victim_control
        .pin_log
        .create(
            "keep",
            PinTarget::Direct(mine.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    // The hostile peer's own chain under the same name, deactivated.
    let theirs = put(&hostile, b"their content");
    hostile
        .pin_log
        .create(
            "keep",
            PinTarget::Direct(theirs),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();
    hostile.pin_log.deactivate("keep", None).unwrap();

    let victim = serve_and_connect(
        victim_control.clone(),
        Some("test-node-token-0123456789abcdef"),
    )
    .await;
    let report = dag_net::sync::push(hostile.clone(), &victim, &SyncOptions::default())
        .await
        .unwrap();

    assert!(
        !report.is_complete(),
        "a conflicting pin history was accepted silently: {:?}",
        report
    );
    assert!(
        report.divergent.iter().any(|f| f.reason.contains("keep")),
        "failures={:?} divergent={:?}",
        report.failures,
        report.divergent
    );

    let head = victim_control.pin_log.head("keep").unwrap();
    assert_eq!(head.event.seq, 1, "the victim's pin chain was extended");
    assert!(
        matches!(head.event.state, dag_core::PinState::Active),
        "the victim's pin was switched off by a remote peer"
    );
}

#[tokio::test]
async fn an_interrupted_push_is_completed_by_running_it_again() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    for i in 0..8 {
        let cid = put(&local, format!("chunk {}", i).as_bytes());
        local.pointer_log.create(&format!("p{}", i), cid).unwrap();
    }

    // Stand in for an interruption: pre-copy some chunks directly, so the
    // destination starts partially populated.
    let events = local.pointer_log.event_cids().unwrap();
    for (_, _, cid) in events.iter().take(3) {
        let bytes = local.store.get_chunk(cid).unwrap();
        remote_control.store.put_chunk(&bytes, None).unwrap();
    }

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert_eq!(report.chunks_skipped, 3, "already-present chunks re-sent");

    for i in 0..8 {
        let cid = remote_control
            .pointer_log
            .resolve(&format!("p{}", i))
            .unwrap();
        assert_eq!(
            remote_control.store.get_chunk(&cid).unwrap(),
            format!("chunk {}", i).as_bytes()
        );
    }
}

#[tokio::test]
async fn grpc_event_batches_publish_pointer_and_pin_histories_all_or_none() {
    let (source, _s) = fresh_control();
    let (destination, _d) = fresh_control();
    let target1 = put(&source, b"grpc-atomic-one");
    let target2 = put(&source, b"grpc-atomic-two");
    source
        .pointer_log
        .create("release", target1.clone())
        .unwrap();
    source
        .pointer_log
        .update("release", target2.clone())
        .unwrap();
    source
        .pin_log
        .create(
            "keep",
            PinTarget::Direct(target1.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();
    source.pin_log.deactivate("keep", None).unwrap();

    let pointer_events = source.pointer_log.event_cids().unwrap();
    let pin_events = source.pin_log.event_cids().unwrap();
    let remote = serve_and_connect(destination.clone(), None).await;
    for (_, _, cid) in pointer_events.iter().chain(pin_events.iter()) {
        let bytes = source.store.get_chunk(cid).unwrap();
        remote.put_chunk(cid, &bytes).await.unwrap();
    }
    for cid in [&target1, &target2] {
        let bytes = source.store.get_chunk(cid).unwrap();
        remote.put_chunk(cid, &bytes).await.unwrap();
    }

    let mut bad_pointers = pointer_events.clone();
    bad_pointers[1].0 = "wrong-pointer".into();
    let rejected = remote
        .import_event_batch(&bad_pointers, &pin_events)
        .await
        .unwrap();
    assert!(matches!(rejected, EventBatchOutcome::Rejected(_)));
    assert!(destination.pointer_log.event_cids().unwrap().is_empty());
    assert!(destination.pin_log.event_cids().unwrap().is_empty());

    let mut bad_pins = pin_events.clone();
    bad_pins[1].0 = "wrong-pin".into();
    let rejected = remote
        .import_event_batch(&pointer_events, &bad_pins)
        .await
        .unwrap();
    assert!(matches!(rejected, EventBatchOutcome::Rejected(_)));
    assert!(destination.pointer_log.event_cids().unwrap().is_empty());
    assert!(destination.pin_log.event_cids().unwrap().is_empty());

    let applied = remote
        .import_event_batch(&pointer_events, &pin_events)
        .await
        .unwrap();
    assert_eq!(
        applied,
        EventBatchOutcome::Applied {
            pointer_events: 2,
            pin_events: 2,
        }
    );
    assert_eq!(
        destination.pointer_log.get_head("release").unwrap().seq,
        2,
        "session commit must publish derived heads in the same atomic marker"
    );
    assert_eq!(destination.pin_log.head("keep").unwrap().event.seq, 2);
    let repeat = remote
        .import_event_batch(&pointer_events, &pin_events)
        .await
        .unwrap();
    assert_eq!(
        repeat,
        EventBatchOutcome::Applied {
            pointer_events: 0,
            pin_events: 0,
        }
    );
    assert_eq!(
        destination.pointer_log.event_cids().unwrap(),
        pointer_events
    );
    assert_eq!(destination.pin_log.event_cids().unwrap(), pin_events);
}

#[tokio::test]
async fn legacy_streaming_event_import_is_refused_before_reading_or_publication() {
    let (source, _s) = fresh_control();
    let (destination, _d) = fresh_control();
    let target = put(&source, b"interrupted-event-batch");
    source.pointer_log.create("release", target).unwrap();
    let event = source.pointer_log.event_cids().unwrap().remove(0);
    let bytes = source.store.get_chunk(&event.2).unwrap();
    destination.store.put_chunk(&bytes, None).unwrap();

    let mut client = serve_raw_sync(destination.clone()).await;
    let frame = dag_net::proto::ImportEventBatchRequest {
        pointer_events: vec![dag_net::proto::EventRef {
            id: event.0,
            seq: event.1,
            event_cid: event.2.as_bytes().to_vec(),
        }],
        pin_events: Vec::new(),
        terminal: false,
    };
    let error = client
        .import_event_batch(tokio_stream::iter([frame]))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("protocol 3"));
    assert!(destination.pointer_log.event_cids().unwrap().is_empty());
    assert!(destination.pointer_log.list_pointers().unwrap().is_empty());
}

#[tokio::test]
async fn protocol_v3_refuses_staging_beyond_the_atomic_publication_limit() {
    const ATOMIC_LIMIT: usize = dag_control::sync::MAX_SYNC_EVENT_REFS;
    let (destination, _d) = fresh_control();
    let mut client = serve_raw_sync(destination).await;
    let session_id = "11111111111111111111111111111111".to_string();
    let begin = client
        .begin_event_import(dag_net::proto::BeginEventImportRequest {
            transfer_id: session_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(begin.next_page_index, 0);

    let mut page_index = 0u64;
    let mut staged = 0usize;
    while staged < ATOMIC_LIMIT {
        let take = (ATOMIC_LIMIT - staged).min(4_096);
        let events = (0..take)
            .map(|offset| {
                let seq = (staged + offset + 1) as u64;
                dag_net::proto::EventRef {
                    id: "large-history".to_string(),
                    seq,
                    event_cid: Cid::compute(&seq.to_be_bytes()).as_bytes().to_vec(),
                }
            })
            .collect();
        let receipt = client
            .stage_event_import(dag_net::proto::StageEventImportRequest {
                session_id: session_id.clone(),
                page_index,
                pointer_events: events,
                pin_events: Vec::new(),
            })
            .await
            .unwrap()
            .into_inner();
        staged += take;
        page_index += 1;
        assert_eq!(receipt.next_page_index, page_index);
        assert_eq!(receipt.pointer_events_staged, staged as u64);
    }
    let error = client
        .stage_event_import(dag_net::proto::StageEventImportRequest {
            session_id: session_id.clone(),
            page_index,
            pointer_events: vec![dag_net::proto::EventRef {
                id: "large-history".to_string(),
                seq: (ATOMIC_LIMIT + 1) as u64,
                event_cid: Cid::compute(b"over-atomic-limit").as_bytes().to_vec(),
            }],
            pin_events: Vec::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    let status = client
        .event_import_status(dag_net::proto::EventImportStatusRequest {
            session_id: session_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.state, "active");
    assert_eq!(status.pointer_events_staged, ATOMIC_LIMIT as u64);
    assert!(
        client
            .abort_event_import(dag_net::proto::AbortEventImportRequest { session_id })
            .await
            .unwrap()
            .into_inner()
            .aborted
    );
}

#[tokio::test]
async fn import_page_retry_is_idempotent_and_abort_is_idempotent() {
    let (destination, _d) = fresh_control();
    let mut client = serve_raw_sync(destination).await;
    let session_id = "22222222222222222222222222222222".to_string();
    for _ in 0..2 {
        let begin = client
            .begin_event_import(dag_net::proto::BeginEventImportRequest {
                transfer_id: session_id.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(begin.session_id, session_id);
    }
    let page = dag_net::proto::StageEventImportRequest {
        session_id: session_id.clone(),
        page_index: 0,
        pointer_events: vec![dag_net::proto::EventRef {
            id: "resume".to_string(),
            seq: 1,
            event_cid: Cid::compute(b"resume").as_bytes().to_vec(),
        }],
        pin_events: Vec::new(),
    };
    for _ in 0..2 {
        let receipt = client
            .stage_event_import(page.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(receipt.next_page_index, 1);
        assert_eq!(receipt.pointer_events_staged, 1);
    }
    assert!(
        client
            .abort_event_import(dag_net::proto::AbortEventImportRequest {
                session_id: session_id.clone(),
            })
            .await
            .unwrap()
            .into_inner()
            .aborted
    );
    assert!(
        !client
            .abort_event_import(dag_net::proto::AbortEventImportRequest { session_id })
            .await
            .unwrap()
            .into_inner()
            .aborted
    );
}

#[tokio::test]
async fn a_bad_final_marker_publishes_nothing() {
    let (source, _s) = fresh_control();
    let (destination, _d) = fresh_control();
    let target = put(&source, b"marker-target");
    source.pointer_log.create("release", target).unwrap();
    let event = source.pointer_log.event_cids().unwrap().remove(0);
    destination
        .store
        .put_chunk(&source.store.get_chunk(&event.2).unwrap(), None)
        .unwrap();
    let mut client = serve_raw_sync(destination.clone()).await;
    let session_id = "33333333333333333333333333333333".to_string();
    client
        .begin_event_import(dag_net::proto::BeginEventImportRequest {
            transfer_id: session_id.clone(),
        })
        .await
        .unwrap();
    client
        .stage_event_import(dag_net::proto::StageEventImportRequest {
            session_id: session_id.clone(),
            page_index: 0,
            pointer_events: vec![dag_net::proto::EventRef {
                id: event.0,
                seq: event.1,
                event_cid: event.2.as_bytes().to_vec(),
            }],
            pin_events: Vec::new(),
        })
        .await
        .unwrap();
    let legacy_error = client
        .commit_event_import(dag_net::proto::CommitEventImportRequest {
            session_id: session_id.clone(),
            expected_pages: 1,
            expected_pointer_events: 1,
            expected_pin_events: 0,
            offer_digest: vec![0; 32],
            index_candidates: Vec::new(),
            publication_capability: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(legacy_error.code(), tonic::Code::FailedPrecondition);
    assert!(legacy_error.message().contains("publication capability"));
    let error = client
        .commit_event_import(dag_net::proto::CommitEventImportRequest {
            session_id,
            expected_pages: 1,
            expected_pointer_events: 2,
            expected_pin_events: 0,
            offer_digest: vec![0; 32],
            index_candidates: Vec::new(),
            publication_capability: dag_net::ATOMIC_SYNC_INDEX_CAPABILITY.to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(destination.pointer_log.event_cids().unwrap().is_empty());
    assert!(destination.pointer_log.list_pointers().unwrap().is_empty());
}

#[tokio::test]
async fn source_generation_change_aborts_pagination() {
    let (source, _s) = fresh_control();
    let first_target = put(&source, b"first");
    source.pointer_log.create("release", first_target).unwrap();
    let mut client = serve_raw_sync(source.clone()).await;
    let first = client
        .page_events(dag_net::proto::EventPageRequest {
            kind: "pointer".to_string(),
            page_size: 1,
            after: None,
            snapshot_generation: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    let cursor = first.events.last().unwrap();

    let second_target = put(&source, b"second");
    source.pointer_log.update("release", second_target).unwrap();
    let error = client
        .page_events(dag_net::proto::EventPageRequest {
            kind: "pointer".to_string(),
            page_size: 1,
            after: Some(dag_net::proto::EventCursor {
                id: cursor.id.clone(),
                seq: cursor.seq,
            }),
            snapshot_generation: first.snapshot_generation,
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Aborted);
    assert!(error.message().contains("generation changed"));
}

#[tokio::test]
#[allow(deprecated)]
async fn candidate_blind_unary_imports_and_finalize_are_removed_in_protocol_v3() {
    let (source, _s) = fresh_control();
    let (destination, _d) = fresh_control();
    let target = put(&source, b"legacy-target");
    source.pointer_log.create("legacy", target.clone()).unwrap();
    let event = source.pointer_log.event_cids().unwrap().remove(0);
    destination
        .store
        .put_chunk(&source.store.get_chunk(&event.2).unwrap(), None)
        .unwrap();
    destination
        .store
        .put_chunk(&source.store.get_chunk(&target).unwrap(), None)
        .unwrap();

    let mut legacy = serve_raw_sync(destination.clone()).await;
    let request = dag_net::proto::ImportEventRequest {
        id: event.0,
        seq: event.1,
        event_cid: event.2.as_bytes().to_vec(),
    };
    let pointer_error = legacy
        .import_pointer_event(request.clone())
        .await
        .unwrap_err();
    assert_eq!(pointer_error.code(), tonic::Code::FailedPrecondition);
    assert!(pointer_error.message().contains("protocol 3"));
    let pin_error = legacy.import_pin_event(request).await.unwrap_err();
    assert_eq!(pin_error.code(), tonic::Code::FailedPrecondition);
    assert!(pin_error.message().contains("protocol 3"));
    assert!(destination.pointer_log.event_cids().unwrap().is_empty());
    assert!(destination.pointer_log.list_pointers().unwrap().is_empty());
    assert!(destination.pin_log.event_cids().unwrap().is_empty());
    assert!(destination.pin_log.list().unwrap().is_empty());

    let finalize_error = legacy
        .finalize(dag_net::proto::FinalizeRequest {})
        .await
        .unwrap_err();
    assert_eq!(finalize_error.code(), tonic::Code::FailedPrecondition);
    assert!(finalize_error.message().contains("protocol 3"));
    assert!(destination.pointer_log.event_cids().unwrap().is_empty());
    assert!(destination.pointer_log.list_pointers().unwrap().is_empty());
}

#[tokio::test]
async fn signatures_travel_and_trust_does_not() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let public_hex = hex::encode(key.verifying_key().to_bytes());
    local
        .signature_log
        .trust_key(
            &public_hex,
            Some("local trust".into()),
            &[dag_control::TrustPurpose::Verify],
        )
        .unwrap();

    let target = put(&local, b"signed content");
    local.pointer_log.create("p", target.clone()).unwrap();
    let sig_cid = local
        .signature_log
        .sign(&target, Some("release".into()), serde_json::json!({}), &key)
        .unwrap();
    let pointer_event = local.pointer_log.event_cids().unwrap()[0].2.clone();
    let event_signature = local
        .signature_log
        .sign(&pointer_event, None, serde_json::json!({}), &key)
        .unwrap();
    let countersignature = local
        .signature_log
        .sign(
            &event_signature,
            Some("counter".into()),
            serde_json::json!({}),
            &key,
        )
        .unwrap();

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    assert!(report.signatures_indexed > 0);

    // The signature arrived and was indexed by the server's finalize…
    assert!(remote_control.store.has_chunk(&sig_cid).unwrap());
    assert_eq!(
        remote_control.signature_log.list_for(&target).unwrap(),
        vec![sig_cid]
    );
    assert_eq!(
        remote_control
            .signature_log
            .list_for(&pointer_event)
            .unwrap(),
        vec![event_signature.clone()]
    );
    assert_eq!(
        remote_control
            .signature_log
            .list_for(&event_signature)
            .unwrap(),
        vec![countersignature]
    );
    // …but the keyring did not travel: valid there, trusted nowhere.
    assert!(
        remote_control
            .signature_log
            .trusted_keys()
            .unwrap()
            .is_empty(),
        "the source's keyring reached the replica"
    );
    let statuses = remote_control.signature_log.verify(&target).unwrap();
    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].valid);
    assert!(!statuses[0].trusted);
}

#[tokio::test]
async fn a_chunk_that_does_not_match_its_cid_is_refused_on_receipt() {
    let (remote_control, _r) = fresh_control();
    let remote = serve_and_connect(remote_control.clone(), None).await;

    let claimed = Cid::compute(b"what I promise");
    let err = remote
        .put_chunk(&claimed, b"what I actually send")
        .await
        .unwrap_err();

    match err {
        NetError::Status(status) => {
            assert_eq!(status.code(), tonic::Code::FailedPrecondition);
            assert!(
                status.message().contains("does not match"),
                "{}",
                status.message()
            );
        }
        other => panic!("expected a refusal, got {other}"),
    }
    assert!(!remote_control.store.has_chunk(&claimed).unwrap());
}

#[tokio::test]
async fn an_oversized_chunk_is_refused_before_it_is_buffered() {
    let (remote_control, _r) = fresh_control();
    let remote = serve_and_connect(remote_control.clone(), None).await;

    // Declare over the limit in the header frame; send no more than that.
    // The server must refuse on the declaration, not after buffering 5 MiB.
    let bytes = vec![0u8; dag_core::MAX_CHUNK_SIZE + 1];
    let cid = Cid::compute(&bytes);
    let err = remote.put_chunk(&cid, &bytes).await.unwrap_err();

    match err {
        NetError::Status(status) => {
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert!(status.message().contains("exceeds"), "{}", status.message());
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

#[tokio::test]
async fn a_large_chunked_file_round_trips_through_a_push() {
    let (local, _l) = fresh_control();
    let (remote_control, _r) = fresh_control();

    // Over the 4 MiB chunk limit, so it manifests into multiple chunks and
    // exercises multi-frame transfer both in count and in size.
    let big: Vec<u8> = (0..(9 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let stored = dag_core::file::store_auto(
        local.store.as_ref(),
        std::io::Cursor::new(big.clone()),
        None,
        false,
        &dag_core::ChunkerConfig::default(),
    )
    .unwrap();
    let root = match stored {
        dag_core::StoredContent::File(r) => r.cid,
        dag_core::StoredContent::Chunk { cid, .. } => cid,
    };
    local.pointer_log.create("big", root.clone()).unwrap();

    let remote = serve_and_connect(remote_control.clone(), None).await;
    let report = dag_net::sync::push(local.clone(), &remote, &SyncOptions::default())
        .await
        .unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);

    let mut out = Vec::new();
    dag_core::file::join(remote_control.store.as_ref(), &root, &mut out).unwrap();
    assert_eq!(out, big, "the replica reassembled different bytes");
}
