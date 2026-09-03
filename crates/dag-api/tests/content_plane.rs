//! ADR-006: the content plane cannot mutate, and the console refuses a
//! public bind without `--expose-control`.

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::test_utils::TestControl;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

fn harness() -> Result<(TestControl, axum::Router, axum::Router)> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let console = dag_api::router(Arc::clone(&control));
    let content = dag_api::content_router(control);
    Ok((tc, console, content))
}

async fn status(app: axum::Router, method: &str, uri: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn content_plane_serves_reads_and_refuses_writes() -> Result<()> {
    let (_tc, _console, content) = harness()?;

    assert_eq!(
        status(content.clone(), "GET", "/api/health").await,
        StatusCode::OK
    );
    assert_eq!(
        status(content.clone(), "GET", "/api/pointers").await,
        StatusCode::OK
    );

    let gc = status(content.clone(), "POST", "/api/gc/run").await;
    assert!(
        gc == StatusCode::NOT_FOUND || gc == StatusCode::METHOD_NOT_ALLOWED,
        "content plane must not run collection, got {gc}"
    );

    let pointer = status(content.clone(), "POST", "/api/pointers").await;
    assert!(
        pointer == StatusCode::NOT_FOUND || pointer == StatusCode::METHOD_NOT_ALLOWED,
        "content plane must not write pointers, got {pointer}"
    );

    let chunk = status(content.clone(), "POST", "/api/chunks").await;
    assert!(
        chunk == StatusCode::NOT_FOUND || chunk == StatusCode::METHOD_NOT_ALLOWED,
        "content plane must not accept uploads, got {chunk}"
    );

    let seed = status(content, "POST", "/api/usecase/seed").await;
    assert!(
        seed == StatusCode::NOT_FOUND || seed == StatusCode::METHOD_NOT_ALLOWED,
        "content plane must not seed, got {seed}"
    );
    Ok(())
}

#[tokio::test]
async fn console_router_still_has_control_routes() -> Result<()> {
    let (_tc, console, _content) = harness()?;
    // Recovery-not-complete is a 409, not a 404: the route is mounted.
    let response = console
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/gc/run")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await?;
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let _ = response.into_body().collect().await?;
    Ok(())
}

#[tokio::test]
async fn non_loopback_console_is_refused_without_the_flag() {
    let err = dag_api::ControlPlaneBindRefused {
        addr: "1.2.3.4:8080".parse().unwrap(),
    };
    let message = err.to_string();
    assert!(message.contains("dag content serve"), "{message}");
    assert!(message.contains("--expose-control"), "{message}");
}

#[tokio::test]
async fn serve_with_refuses_non_loopback_before_binding() -> Result<()> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let addr = "1.2.3.4:9".parse().unwrap();
    let err = dag_api::serve_with(control, addr, dag_api::ServerOptions::new())
        .await
        .expect_err("must refuse before bind");
    assert!(
        err.downcast_ref::<dag_api::ControlPlaneBindRefused>()
            .is_some(),
        "{err:#}"
    );
    Ok(())
}
