//! One file, one CID — no matter which door it came through.
//!
//! Found live during the 2026-08 end-to-end pass: the CLI records
//! `--content-type` in the `file/v1` manifest, but the upload endpoint read
//! only its `?content_type=` query parameter and silently ignored the
//! standard `Content-Type` header every HTTP client sends. The same bytes,
//! declared the same way, produced different root CIDs from `dag put` and
//! `POST /api/files` — leaf chunks deduplicated, manifests did not. Same
//! species as the 2 MiB/4 MiB body-limit defect: two entry points
//! disagreeing about one contract.
//!
//! Also pinned here: an unknown query parameter is refused, not dropped.
//! The live pass sent `?filename=big.bin` and nothing said it did nothing.

use anyhow::Result;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use dag_control::test_utils::TestControl;
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

fn harness() -> Result<(TestControl, Arc<dag_control::Control>, axum::Router)> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let router = dag_api::router(Arc::clone(&control));
    Ok((tc, control, router))
}

/// What `dag put` does with the same bytes and declaration — the ground
/// truth the API must agree with.
fn cli_equivalent_cid(
    tc: &TestControl,
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<String> {
    let control = dag_control::Control::open(&tc.path().join("cli"))?;
    let stored = dag_core::file::store_auto(
        control.store.as_ref(),
        bytes,
        content_type.map(str::to_owned),
        true,
        &dag_core::ChunkerConfig::default(),
    )?;
    Ok(match stored {
        dag_core::StoredContent::Chunk { cid, .. } => cid.to_hex(),
        dag_core::StoredContent::File(r) => r.cid.to_hex(),
    })
}

async fn upload(
    router: &axum::Router,
    uri: &str,
    header_type: Option<&str>,
    bytes: Vec<u8>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(t) = header_type {
        builder = builder.header(header::CONTENT_TYPE, t);
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, body))
}

#[tokio::test]
async fn the_content_type_header_is_recorded_like_the_cli_flag() -> Result<()> {
    let (tc, _control, router) = harness()?;
    let bytes = vec![42u8; 100 * 1024];

    let (status, json) = upload(
        &router,
        "/api/files?chunked=true",
        Some("text/csv"),
        bytes.clone(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");

    let expected = cli_equivalent_cid(&tc, &bytes, Some("text/csv"))?;
    assert_eq!(
        json["cid"].as_str().unwrap(),
        expected,
        "the header-declared type must land in the manifest exactly as \
         `dag put --content-type` records it, or the two entry points \
         produce different CIDs for the same file"
    );
    Ok(())
}

/// The query parameter is the explicit override; the header is what every
/// client sends ambiently. Explicit wins.
#[tokio::test]
async fn the_query_parameter_overrides_the_header() -> Result<()> {
    let (tc, _control, router) = harness()?;
    let bytes = vec![7u8; 100 * 1024];

    let (status, json) = upload(
        &router,
        "/api/files?chunked=true&content_type=text/plain",
        Some("text/csv"),
        bytes.clone(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");

    let expected = cli_equivalent_cid(&tc, &bytes, Some("text/plain"))?;
    assert_eq!(json["cid"].as_str().unwrap(), expected);
    Ok(())
}

#[tokio::test]
async fn an_unknown_upload_parameter_is_refused() -> Result<()> {
    let (_tc, control, router) = harness()?;

    let (status, _json) = upload(
        &router,
        "/api/files?filename=big.bin",
        Some("application/octet-stream"),
        b"some bytes".to_vec(),
    )
    .await?;
    assert!(
        status.is_client_error(),
        "an unrecognised parameter must refuse the upload, got {status}"
    );
    assert_eq!(
        control.stats()?.chunks,
        0,
        "a refused upload must not have stored anything"
    );
    Ok(())
}
