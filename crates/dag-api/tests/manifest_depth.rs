//! The `file/v1` recursion ceiling, as reached through HTTP.
//!
//! `depth` is read from a manifest payload, and a manifest is content anyone
//! with write access — including `POST /api/chunks` on an unauthenticated
//! `dag serve` — can author. `dag_core::file::join` recurses one frame per
//! declared level, and a Rust stack overflow is a `fatal runtime error` that
//! aborts the whole process and cannot be caught, so the bound has to be a
//! check *before* the descent. `dag_core` unit-tests that check in isolation;
//! these tests verify two things it cannot:
//!
//! 1. the ceiling is derived correctly — it covers the deepest manifest the
//!    loosest permitted `ChunkerConfig` could ever legitimately produce, with
//!    margin to spare, and is small enough to actually bind; and
//! 2. the check is on the code path an HTTP client reaches, `GET /api/files`
//!    → `download` → `join`, not merely on some internal helper.

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use dag_control::test_utils::TestControl;
use dag_core::file::MAX_MANIFEST_DEPTH;
use dag_core::{Cid, Entry, Link};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

/// The floors `ChunkerConfig::validate` enforces, restated here because they
/// are private to `dag_core`. If they change there, this test is where the
/// derivation of [`MAX_MANIFEST_DEPTH`] must be re-checked against them.
///
/// * `min_size >= 64` — fastcdc's own lower bound, so a chunk is at least 64
///   bytes and the whole `u64` size range holds at most `u64::MAX / 64` chunks.
/// * `links_per_manifest >= 2` — the shallowest fan-out, so the manifest tree
///   is at worst binary and therefore at its deepest.
const MIN_CHUNK_FLOOR: u64 = 64;
const MIN_FANOUT: u64 = 2;

/// Re-derive the deepest legitimate manifest from the config floors and assert
/// the ceiling both covers it and stays close enough to it to bind.
///
/// A manifest entry at depth `D` reaches at most `fanout^D` data chunks (each
/// fold in `split` divides the link count by the fanout and adds one level), so
/// the minimal depth for `N` chunks is `ceil(log_fanout(N))`. The worst case
/// takes the smallest fanout and the smallest chunks over the largest file.
#[test]
fn the_ceiling_covers_the_deepest_legitimate_manifest_and_still_binds() {
    // Largest file: `size` is a u64, so it cannot exceed u64::MAX bytes.
    let max_chunks = (u64::MAX / MIN_CHUNK_FLOOR) + 1; // ceil, in case of a short final chunk

    // Minimal depth D such that MIN_FANOUT^D >= max_chunks.
    let mut worst_case_depth: u32 = 1;
    let mut capacity: u128 = MIN_FANOUT as u128;
    while capacity < max_chunks as u128 {
        capacity *= MIN_FANOUT as u128;
        worst_case_depth += 1;
    }

    // Spelled out so the numbers are auditable: u64::MAX / 64 ≈ 2^58 chunks, a
    // binary tree over which is 58 levels deep.
    assert_eq!(
        worst_case_depth, 58,
        "the loosest config bottoms out at 58 levels; got {}",
        worst_case_depth
    );

    // Covers it: a legitimate manifest can never be refused.
    assert!(
        MAX_MANIFEST_DEPTH >= worst_case_depth,
        "ceiling {} is below the worst legitimate depth {}: legitimate files would break",
        MAX_MANIFEST_DEPTH,
        worst_case_depth
    );

    // Still binds: the ceiling is a small, fixed margin above the worst case,
    // not an astronomical number that would wave through a hostile manifest.
    // 64 - 58 = 6. A ceiling in the thousands would "cover" the worst case too,
    // yet fail to protect the stack.
    assert!(
        MAX_MANIFEST_DEPTH <= worst_case_depth + 16,
        "ceiling {} is {} levels above the worst case — too loose to bind",
        MAX_MANIFEST_DEPTH,
        MAX_MANIFEST_DEPTH - worst_case_depth
    );
}

fn harness() -> Result<(TestControl, Router)> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let options = dag_api::ServerOptions::new();
    Ok((tc, dag_api::router_with(control, &options)))
}

/// Store `bytes` as a raw chunk and return its CID.
async fn post_chunk(app: &Router, bytes: Vec<u8>) -> Cid {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/chunks")
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "POST /api/chunks");
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    Cid::from_hex(body["cid"].as_str().unwrap()).unwrap()
}

/// CBOR bytes of a `file-part/v1` entry at `depth` linking a single `child`.
fn part_entry(depth: u32, child: Cid) -> Vec<u8> {
    let payload = json!({ "kind": "file-part/v1", "depth": depth, "links": 1 });
    Entry::new(
        serde_json::to_vec(&payload).unwrap(),
        vec![Link::unnamed(child)],
        None,
    )
    .to_bytes_cbor()
    .unwrap()
}

/// CBOR bytes of a `file/v1` root manifest at `depth` over a single `child`.
fn root_entry(depth: u32, child: Cid, size: u64) -> Vec<u8> {
    let payload = json!({
        "kind": "file/v1",
        "depth": depth,
        "links": 1,
        "size": size,
        "chunks": 1,
    });
    Entry::new(
        serde_json::to_vec(&payload).unwrap(),
        vec![Link::unnamed(child)],
        None,
    )
    .to_bytes_cbor()
    .unwrap()
}

/// Store a *structurally valid* manifest chain `root_depth` levels tall over a
/// single leaf chunk, entirely through the HTTP chunk endpoint, and return the
/// root CID. "Valid" means every part declares exactly its parent's depth minus
/// one, so `join`'s per-level checks all pass — the only thing that can stop
/// reassembly is the depth ceiling. That is what makes the over-ceiling case a
/// real regression test: were the ceiling removed, this chain would reassemble.
async fn store_chain(app: &Router, root_depth: u32, payload: &[u8]) -> Cid {
    let leaf = post_chunk(app, payload.to_vec()).await;
    let mut child = leaf;
    // Parts occupy depths 1..root_depth; the root sits at root_depth.
    for depth in 1..root_depth {
        child = post_chunk(app, part_entry(depth, child)).await;
    }
    post_chunk(app, root_entry(root_depth, child, payload.len() as u64)).await
}

/// Reassemble `cid` through `GET /api/files` and return the body if the stream
/// completed, or `None` if it aborted (which is how `download` surfaces a
/// `join` error mid-stream).
async fn download(app: &Router, cid: &Cid) -> (StatusCode, Option<Vec<u8>>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/files?cid={}", cid.to_hex()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    match response.into_body().collect().await {
        Ok(body) => (status, Some(body.to_bytes().to_vec())),
        Err(_) => (status, None),
    }
}

/// A chain exactly at the ceiling must still reassemble through HTTP — the
/// ceiling is above anything legitimate, so it must not break a real file.
#[tokio::test]
async fn a_manifest_at_the_ceiling_still_downloads() -> Result<()> {
    let (_tc, app) = harness()?;
    let root = store_chain(&app, MAX_MANIFEST_DEPTH, b"payload").await;

    let (status, body) = download(&app, &root).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.as_deref(),
        Some(b"payload".as_slice()),
        "a legitimate ceiling-depth file must reassemble"
    );
    Ok(())
}

/// One level over the ceiling must be refused — and this chain is otherwise
/// valid, so if the depth check were removed the download would succeed and
/// return `payload`. That is the property under test: the guard, not some
/// incidental error, is what stops it.
#[tokio::test]
async fn a_manifest_one_over_the_ceiling_is_refused_on_the_download_path() -> Result<()> {
    let (_tc, app) = harness()?;
    let root = store_chain(&app, MAX_MANIFEST_DEPTH + 1, b"payload").await;

    let (_status, body) = download(&app, &root).await;
    assert_ne!(
        body.as_deref(),
        Some(b"payload".as_slice()),
        "a manifest past the ceiling must not reassemble through HTTP"
    );

    // The process is still alive and serving: an over-ceiling manifest is a
    // refused request, not a crashed server.
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(
        health.status(),
        StatusCode::OK,
        "server survived the attempt"
    );
    Ok(())
}

/// An absurd declared depth — the original 30 000-level abort — is refused, and
/// the server keeps serving. The leaf is real, so the only thing standing
/// between this request and 30 000 stack frames is the ceiling check `join`
/// runs before it descends.
#[tokio::test]
async fn an_absurd_declared_depth_does_not_abort_the_server() -> Result<()> {
    let (_tc, app) = harness()?;
    let leaf = post_chunk(&app, b"payload".to_vec()).await;
    let root = post_chunk(&app, root_entry(30_000, leaf, 7)).await;

    let (_status, body) = download(&app, &root).await;
    assert_ne!(body.as_deref(), Some(b"payload".as_slice()));

    let health = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(health.status(), StatusCode::OK);
    Ok(())
}
