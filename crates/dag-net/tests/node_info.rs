//! The node port's ground rules: it answers, it authenticates, and it will
//! not open itself to the network without TLS and credentials.

use std::net::SocketAddr;
use std::sync::Arc;

use dag_control::Control;
use dag_core::ContentStore;
use dag_net::{
    bind, AuthScope, CredentialSet, NetError, RemoteNode, ServeOptions, ServerCredential,
    TlsIdentity,
};
use tonic::{Request, Response, Status};

#[derive(Default)]
struct ProtocolV1Node;

#[tonic::async_trait]
impl dag_net::proto::node_server::Node for ProtocolV1Node {
    async fn info(
        &self,
        _request: Request<dag_net::proto::InfoRequest>,
    ) -> Result<Response<dag_net::proto::InfoResponse>, Status> {
        Ok(Response::new(dag_net::proto::InfoResponse {
            version: "0.1.0-v1".to_string(),
            ..Default::default()
        }))
    }
}

/// An open control plane on a fresh directory, plus the guard that owns it.
fn fresh_control() -> (Arc<Control>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    (Arc::new(control), dir)
}

/// Serve `control` on an ephemeral loopback port; returns the URL.
async fn serve_ephemeral(control: Arc<Control>, token: Option<&str>) -> String {
    let credentials = CredentialSet::legacy_admin(token).unwrap();
    serve_with_credentials(control, credentials).await
}

async fn serve_with_credentials(control: Arc<Control>, credentials: CredentialSet) -> String {
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
    url
}

#[tokio::test]
async fn info_answers_with_version_schema_and_store_shape() {
    let (control, _dir) = fresh_control();
    control.store.put_chunk(b"some content", None).unwrap();
    let url = serve_ephemeral(control, None).await;

    let remote = RemoteNode::connect(&url, None).await.unwrap();
    let info = remote.info().await.unwrap();

    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.schema_version, dag_control::SCHEMA_VERSION);
    assert_eq!(info.chunks, 1);
    assert!(info.bytes > 0);
    assert_eq!(info.pointers, 0);
    assert_eq!(info.protocol_major, dag_net::PROTOCOL_MAJOR);
    assert_eq!(info.protocol_minor, dag_net::PROTOCOL_MINOR);
    for required in dag_net::REQUIRED_SYNC_CAPABILITIES {
        assert!(info.capabilities.iter().any(|offered| offered == required));
    }
}

#[tokio::test]
async fn shutdown_closes_established_channels_before_the_server_returns() {
    let (control, _dir) = fresh_control();
    let bound = bind(
        control,
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions::default(),
    )
    .await
    .unwrap();
    let url = format!("grpc://{}", bound.local_addr);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(bound.serve_until(async move {
        let _ = shutdown_rx.await;
    }));

    let remote = RemoteNode::connect(&url, None).await.unwrap();
    remote.info().await.unwrap();
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .expect("server shutdown retained an established connection")
        .unwrap()
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), remote.info())
        .await
        .expect("closed channel did not fail promptly");
    assert!(result.is_err(), "an RPC succeeded after server shutdown");
}

#[tokio::test]
async fn refusing_a_same_source_connection_does_not_kill_the_listener() {
    let (control, _dir) = fresh_control();
    let bound = bind(
        control,
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions::default(),
    )
    .await
    .unwrap();
    let address = bound.local_addr;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(bound.serve_until(async move {
        let _ = shutdown_rx.await;
    }));

    // Sixteen sockets occupy this source's share; the seventeenth exercises
    // the refusal path. These deliberately send no HTTP/2 preface.
    let mut sockets = Vec::new();
    for _ in 0..17 {
        sockets.push(tokio::net::TcpStream::connect(address).await.unwrap());
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(sockets);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let remote = RemoteNode::connect(&format!("grpc://{address}"), None)
        .await
        .unwrap();
    remote
        .info()
        .await
        .expect("one refused socket terminated the listener");

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_protocol_v3_client_refuses_an_old_peer_before_local_transfer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(dag_net::proto::node_server::NodeServer::new(ProtocolV1Node))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let remote = RemoteNode::connect(&format!("grpc://{address}"), None)
        .await
        .unwrap();
    let (local, _dir) = fresh_control();
    let before = local.stats().unwrap();
    let error = dag_net::sync::pull(
        local.clone(),
        &remote,
        &dag_control::sync::SyncOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("deploy upgraded servers before clients"),
        "{error}"
    );
    let after = local.stats().unwrap();
    assert_eq!(after.chunks, before.chunks);
    assert_eq!(after.pointers, before.pointers);
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_refused_and_the_right_one_admitted() {
    let (control, _dir) = fresh_control();
    let url = serve_ephemeral(control, Some("test-node-token-0123456789abcdef")).await;

    // No token offered.
    let remote = RemoteNode::connect(&url, None).await.unwrap();
    match remote.info().await {
        Err(NetError::Status(status)) => {
            assert_eq!(status.code(), tonic::Code::Unauthenticated);
            assert_eq!(status.message(), "authentication failed");
        }
        other => panic!("expected Unauthenticated, got {:?}", other.map(|_| ())),
    }

    // The wrong token offered.
    let remote = RemoteNode::connect(&url, Some("wrong-node-token-0123456789abcdef"))
        .await
        .unwrap();
    match remote.info().await {
        Err(NetError::Status(status)) => {
            assert_eq!(status.code(), tonic::Code::Unauthenticated);
            assert_eq!(status.message(), "authentication failed");
        }
        other => panic!("expected Unauthenticated, got {:?}", other.map(|_| ())),
    }

    // The right one.
    let remote = RemoteNode::connect(&url, Some("test-node-token-0123456789abcdef"))
        .await
        .unwrap();
    assert!(remote.info().await.is_ok());
}

#[tokio::test]
async fn a_non_loopback_plaintext_bind_is_refused_even_with_credentials() {
    let (control, _dir) = fresh_control();
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let credentials =
        CredentialSet::legacy_admin(Some("test-node-token-0123456789abcdef")).unwrap();

    match bind(
        control,
        addr,
        ServeOptions {
            credentials,
            ..Default::default()
        },
    )
    .await
    {
        Err(NetError::InsecureTransportRefused { destination }) => {
            assert_eq!(destination, addr.to_string());
        }
        Err(other) => panic!("expected InsecureTransportRefused, got {other}"),
        Ok(_) => panic!("a non-loopback plaintext bind was accepted"),
    }
}

#[tokio::test]
async fn the_explicit_insecure_override_still_requires_credentials() {
    let (control, _dir) = fresh_control();
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    match bind(
        control,
        addr,
        ServeOptions {
            allow_insecure_transport: true,
            ..Default::default()
        },
    )
    .await
    {
        Err(NetError::CredentialsRequired { addr: named }) => assert_eq!(named, addr),
        Err(other) => panic!("expected CredentialsRequired, got {other}"),
        Ok(_) => panic!("an unauthenticated non-loopback bind was accepted"),
    }
}

#[tokio::test]
async fn a_non_loopback_plaintext_bind_needs_the_explicit_override() {
    let (control, _dir) = fresh_control();

    let bound = bind(
        control,
        "0.0.0.0:0".parse().unwrap(),
        ServeOptions {
            credentials: CredentialSet::legacy_admin(Some("test-node-token-0123456789abcdef"))
                .unwrap(),
            allow_insecure_transport: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_ne!(bound.local_addr.port(), 0);
}

#[tokio::test]
async fn tls_on_non_loopback_still_requires_credentials() {
    let (control, _dir) = fresh_control();
    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

    match bind(
        control,
        addr,
        ServeOptions {
            tls: Some(TlsIdentity {
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
            }),
            ..Default::default()
        },
    )
    .await
    {
        Err(NetError::CredentialsRequired { addr: named }) => assert_eq!(named, addr),
        Err(other) => panic!("expected CredentialsRequired, got {other}"),
        Ok(_) => panic!("an unauthenticated non-loopback TLS bind was accepted"),
    }
}

#[tokio::test]
async fn current_and_previous_read_credentials_rotate_without_granting_sync() {
    let (control, _dir) = fresh_control();
    let current =
        ServerCredential::new("current-read-token-0123456789abcdef", [AuthScope::Read]).unwrap();
    let previous =
        ServerCredential::new("previous-read-token-0123456789abcde", [AuthScope::Read]).unwrap();
    let url =
        serve_with_credentials(control, CredentialSet::rotating(current, Some(previous))).await;

    for token in [
        "current-read-token-0123456789abcdef",
        "previous-read-token-0123456789abcde",
    ] {
        let remote = RemoteNode::connect(&url, Some(token)).await.unwrap();
        assert!(remote.info().await.is_ok(), "rotation token {token}");
    }

    let remote = RemoteNode::connect(&url, Some("current-read-token-0123456789abcdef"))
        .await
        .unwrap();
    match remote.enumerate(10).await {
        Err(NetError::Status(status)) => {
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
            assert_eq!(status.message(), "permission denied");
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unreachable_node_fails_at_connect_not_first_use() {
    // A port nothing listens on: bind one, learn the port, drop the listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    match RemoteNode::connect(&format!("grpc://127.0.0.1:{port}"), None).await {
        Err(err) => assert!(matches!(err, NetError::Transport(_)), "{err}"),
        Ok(_) => panic!("connecting to a dead port succeeded"),
    }
}

#[tokio::test]
async fn a_path_is_not_mistaken_for_a_remote_url() {
    assert!(RemoteNode::is_remote_url("grpc://10.0.0.1:7411"));
    assert!(!RemoteNode::is_remote_url("/Volumes/backup/dag"));
    assert!(!RemoteNode::is_remote_url("backup/dag"));
    assert!(!RemoteNode::is_remote_url("http://10.0.0.1:7411"));
}
