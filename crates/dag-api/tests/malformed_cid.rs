//! A malformed CID must be a 400, never a panic.
//!
//! `dag serve` has no built-in authentication, so every value at its HTTP
//! boundary is untrusted. `Cid::from_hex` used to check
//! the hex alphabet but not the decoded length, so `?cid=` (empty) or `?cid=ab`
//! produced a `Cid` shorter than the two-character shard prefix — and
//! `FsStore::chunk_path` panicked slicing it, killing the handler task.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::test_utils::TestControl;
use std::sync::Arc;
use tower::ServiceExt;

/// CIDs that are well-formed hex but not a 32-byte digest, plus outright junk.
fn malformed() -> Vec<String> {
    vec![
        String::new(),
        "ab".to_string(),
        "abcd".to_string(),
        "ab".repeat(31),
        "ab".repeat(33),
        "abc".to_string(),
        "zz".repeat(32),
        "../../etc/passwd".to_string(),
    ]
}

/// Every endpoint that accepts a CID as a query parameter.
fn cid_endpoints() -> Vec<&'static str> {
    vec![
        "/api/chunks",
        "/api/entries",
        "/api/files",
        "/api/graph",
        "/api/signatures",
        "/api/gc/status",
    ]
}

#[tokio::test]
async fn malformed_cids_are_rejected_not_fatal() {
    let tc = TestControl::new().unwrap();
    let app = dag_api::router(Arc::new(tc.control));

    for endpoint in cid_endpoints() {
        for cid in malformed() {
            let uri = format!("{}?cid={}", endpoint, urlencoding(&cid));
            let response = app
                .clone()
                .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
                .await
                .expect("the handler panicked instead of returning a response");

            assert!(
                response.status().is_client_error(),
                "{} with cid {:?} returned {}, expected a 4xx",
                endpoint,
                cid,
                response.status()
            );
        }
    }
}

#[tokio::test]
async fn a_well_formed_cid_that_is_simply_absent_is_a_404() {
    // The counterpart: rejecting malformed input must not have turned every
    // miss into a 400, which would make the two indistinguishable.
    let tc = TestControl::new().unwrap();
    let app = dag_api::router(Arc::new(tc.control));

    let absent = dag_core::Cid::compute(b"never stored").to_hex();
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/chunks?cid={}", absent))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Minimal percent-encoding for the characters these test inputs contain.
fn urlencoding(s: &str) -> String {
    s.replace('/', "%2F").replace('.', "%2E")
}
