//! TLS on the node port: a grpcs:// client with the right CA gets through,
//! and everything mismatched fails at the transport before any RPC runs.

use std::sync::Arc;

use dag_control::Control;
use dag_net::{
    bind, ConnectOptions, CredentialSet, NetError, RemoteNode, ServeOptions, TlsIdentity,
};

fn fresh_control() -> (Arc<Control>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    (Arc::new(control), dir)
}

/// A self-signed identity for `localhost`, and its cert as the client's CA.
fn self_signed() -> (TlsIdentity, Vec<u8>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = key.cert.pem().into_bytes();
    let key_pem = key.signing_key.serialize_pem().into_bytes();
    (
        TlsIdentity {
            cert_pem: cert_pem.clone(),
            key_pem,
        },
        cert_pem,
    )
}

async fn serve_tls(control: Arc<Control>, identity: TlsIdentity, token: Option<&str>) -> u16 {
    let bound = bind(
        control,
        "127.0.0.1:0".parse().unwrap(),
        ServeOptions {
            credentials: CredentialSet::legacy_admin(token).unwrap(),
            tls: Some(identity),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let port = bound.local_addr.port();
    tokio::spawn(bound.serve());
    port
}

#[tokio::test]
async fn a_tls_round_trip_with_the_right_ca_and_token_works() {
    let (control, _dir) = fresh_control();
    let (identity, ca) = self_signed();
    let port = serve_tls(control, identity, Some("test-node-token-0123456789abcdef")).await;

    let remote = RemoteNode::connect_with(
        &format!("grpcs://localhost:{port}"),
        ConnectOptions {
            token: Some("test-node-token-0123456789abcdef".into()),
            ca_cert_pem: Some(ca),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let info = remote.info().await.unwrap();
    assert_eq!(info.schema_version, dag_control::SCHEMA_VERSION);
}

#[tokio::test]
async fn a_plaintext_client_cannot_reach_a_tls_server() {
    let (control, _dir) = fresh_control();
    let (identity, _ca) = self_signed();
    let port = serve_tls(control, identity, None).await;

    match RemoteNode::connect(&format!("grpc://127.0.0.1:{port}"), None).await {
        Err(NetError::Transport(_)) => {}
        Err(other) => panic!("expected a transport failure, got {other}"),
        Ok(remote) => {
            // Some stacks accept the TCP connection and fail on first use;
            // either way no RPC may succeed.
            assert!(remote.info().await.is_err(), "plaintext reached a TLS port");
        }
    }
}

#[tokio::test]
async fn a_client_without_the_ca_refuses_the_self_signed_server() {
    let (control, _dir) = fresh_control();
    let (identity, _ca) = self_signed();
    let port = serve_tls(control, identity, None).await;

    // Native roots only — the self-signed cert is vouched for by nobody.
    match RemoteNode::connect_with(
        &format!("grpcs://localhost:{port}"),
        ConnectOptions::default(),
    )
    .await
    {
        Err(NetError::Transport(_)) => {}
        Err(other) => panic!("expected a transport failure, got {other}"),
        Ok(remote) => {
            assert!(
                remote.info().await.is_err(),
                "an unvouched certificate was accepted"
            );
        }
    }
}

#[tokio::test]
async fn tls_domain_overrides_the_host_for_certificate_verification() {
    let (control, _dir) = fresh_control();
    let (identity, ca) = self_signed(); // certificate names `localhost`
    let port = serve_tls(control, identity, None).await;

    // Connect by IP — the certificate does not name 127.0.0.1, so
    // verification needs the domain override to succeed.
    let remote = RemoteNode::connect_with(
        &format!("grpcs://127.0.0.1:{port}"),
        ConnectOptions {
            ca_cert_pem: Some(ca),
            tls_domain: Some("localhost".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(remote.info().await.is_ok());
}

#[tokio::test]
async fn tls_options_on_a_plaintext_url_are_refused() {
    match RemoteNode::connect_with(
        "grpc://127.0.0.1:1",
        ConnectOptions {
            ca_cert_pem: Some(b"pem".to_vec()),
            ..Default::default()
        },
    )
    .await
    {
        Err(NetError::BadUrl { reason, .. }) => {
            assert!(reason.contains("grpcs://"), "{reason}")
        }
        Err(other) => panic!("expected BadUrl, got {other}"),
        Ok(_) => panic!("TLS options on grpc:// were accepted"),
    }
}
