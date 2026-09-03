//! `POST /api/gc/run` must never silently ignore the caller's parameters.
//!
//! Found live during the 2026-08 end-to-end pass: the handler read only a
//! JSON body, so `POST /api/gc/run?dry_run=true` dropped the query string on
//! the floor and ran a *real* collection — 83 chunks, ~105 MB — against an
//! explicit request not to. On an unauthenticated endpoint that deletes
//! data, a parameter that does not parse must refuse the request, not
//! default to destruction.
//!
//! The contract pinned here: parameters are accepted in the query string or
//! the JSON body; an unknown name in either place is refused; supplying
//! both is refused as ambiguous; and every refusal leaves the store
//! untouched.

use anyhow::Result;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use dag_control::test_utils::TestControl;
use dag_core::{Cid, ContentStore};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

/// A router over a recovered directory holding one collectable chunk.
fn harness() -> Result<(TestControl, Arc<dag_control::Control>, axum::Router, Cid)> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    control.recovery_state.mark_complete_for_test()?;
    let loose = control.store.put_chunk(b"collectable", None)?;
    let router = dag_api::router_with(Arc::clone(&control), &dag_api::ServerOptions::new());
    Ok((tc, control, router, loose))
}

async fn json_of(response: axum::response::Response) -> Result<Value> {
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

fn post(uri: &str, body: Option<&str>) -> Request<Body> {
    let builder = Request::builder().method("POST").uri(uri);
    match body {
        Some(json) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

#[tokio::test]
async fn dry_run_in_the_query_string_is_honoured() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    let response = router
        .oneshot(post("/api/gc/run?dry_run=true&min_age_secs=0", None))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_of(response).await?;
    assert_eq!(
        report["dry_run"], true,
        "the query string asked for a dry run"
    );
    assert!(
        report["deleted"].as_u64().unwrap() >= 1,
        "the dry run should have found the loose chunk"
    );
    assert!(
        control.store.get_chunk(&loose).is_ok(),
        "a dry run must not delete"
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_query_parameter_refuses_the_request() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    // The exact live failure: a misspelled `dry_run` must not fall through
    // to a live collection.
    let response = router
        .oneshot(post("/api/gc/run?dryrun=true&min_age_secs=0", None))
        .await?;
    assert!(
        response.status().is_client_error(),
        "an unknown parameter must refuse, got {}",
        response.status()
    );
    assert!(
        control.store.get_chunk(&loose).is_ok(),
        "a refused request must not have collected anything"
    );
    Ok(())
}

#[tokio::test]
async fn parameters_in_both_query_and_body_are_ambiguous() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    let response = router
        .oneshot(post(
            "/api/gc/run?dry_run=true",
            Some(r#"{"dry_run": false, "min_age_secs": 0}"#),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        control.store.get_chunk(&loose).is_ok(),
        "an ambiguous request must not have collected anything"
    );
    Ok(())
}

#[tokio::test]
async fn the_json_body_still_works() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    let response = router
        .oneshot(post(
            "/api/gc/run",
            Some(r#"{"dry_run": true, "min_age_secs": 0}"#),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_of(response).await?;
    assert_eq!(report["dry_run"], true);
    assert!(control.store.get_chunk(&loose).is_ok());
    Ok(())
}

#[tokio::test]
async fn an_unknown_body_field_refuses_the_request() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    let response = router
        .oneshot(post(
            "/api/gc/run",
            Some(r#"{"dryRun": true, "min_age_secs": 0}"#),
        ))
        .await?;
    assert!(
        response.status().is_client_error(),
        "an unknown body field must refuse, got {}",
        response.status()
    );
    assert!(
        control.store.get_chunk(&loose).is_ok(),
        "a refused request must not have collected anything"
    );
    Ok(())
}

#[tokio::test]
async fn http_refuses_the_unbounded_offline_gc_escape_hatch() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    let response = router
        .oneshot(post(
            "/api/gc/run?dry_run=true&min_age_secs=0&max_delete=0",
            None,
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        control.store.get_chunk(&loose).is_ok(),
        "a refused unbounded HTTP pass must not collect anything"
    );
    Ok(())
}

#[tokio::test]
async fn http_refuses_disabling_system_history_protection() -> Result<()> {
    let (_tc, control, router, loose) = harness()?;

    let response = router
        .oneshot(post(
            "/api/gc/run",
            Some(r#"{"dry_run":true,"system_protection":false}"#),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        control.store.get_chunk(&loose).is_ok(),
        "a refused history-destructive HTTP pass must not collect anything"
    );
    Ok(())
}

/// The unparameterised call keeps its meaning: a real collection with the
/// default minimum age, which the fresh loose chunk is younger than.
#[tokio::test]
async fn a_bare_post_still_runs_a_real_collection() -> Result<()> {
    let (_tc, _control, router, _loose) = harness()?;

    let response = router.oneshot(post("/api/gc/run", None)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_of(response).await?;
    assert_eq!(report["dry_run"], false);
    assert_eq!(report["truncated"], false);
    Ok(())
}
