//! A job run must not stall the event stream.
//!
//! `POST /api/jobs/run` does synchronous redb and store I/O around an `await`.
//! Held on a runtime worker, that work blocks whatever else the worker was
//! scheduled to run — and the SSE keep-alives feeding every connected console
//! share those workers, so a console looks frozen rather than slow.
//!
//! These run on a multi-threaded runtime deliberately: that is what
//! `#[tokio::main]` gives `dag serve`, and it is the flavour where
//! `block_in_place` actually does anything.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::test_utils::TestControl;
use dag_core::{Cid, ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn hash_job(input: Cid) -> JobSpec {
    JobSpec {
        job_id: JobId::from("hash-it"),
        placement: Default::default(),
        inputs: JobInput {
            static_inputs: vec![input],
            pointer_inputs: vec![],
        },
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["hash".to_string()],
        code_ref: "hash".to_string(),
        policy: JobPolicy::default(),
        config: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_run_does_not_stop_other_tasks_making_progress() {
    let tc = TestControl::new().unwrap();
    let input = tc.control.store.put_chunk(b"payload", None).unwrap();
    tc.control.create_job(hash_job(input)).unwrap();

    let app = dag_api::router(Arc::new(tc.control));

    // A ticker standing in for the SSE keep-alives: it shares the runtime with
    // the request and must keep being polled while the job runs.
    let ticks = Arc::new(AtomicU64::new(0));
    let counter = ticks.clone();
    let ticker = tokio::spawn(async move {
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs/run")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"id":"hash-it"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    ticker.await.unwrap();
    assert_eq!(
        ticks.load(Ordering::SeqCst),
        20,
        "the ticker was starved while the job ran"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seeding_the_scenario_does_not_stop_other_tasks() {
    // The other handler that cannot use `on_blocking_pool`: a long run of
    // synchronous store writes with two job runs in the middle.
    let tc = TestControl::new().unwrap();
    let app = dag_api::router(Arc::new(tc.control));

    let ticks = Arc::new(AtomicU64::new(0));
    let counter = ticks.clone();
    let ticker = tokio::spawn(async move {
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/usecase/seed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    ticker.await.unwrap();
    assert_eq!(
        ticks.load(Ordering::SeqCst),
        20,
        "the ticker was starved while the scenario seeded"
    );
}

#[tokio::test]
async fn a_job_still_runs_under_a_current_thread_runtime() {
    // `block_in_place` panics on this flavour, so `offload` has to detect it
    // and run inline. Every `#[tokio::test]` in the suite depends on that, but
    // this one says so explicitly.
    let tc = TestControl::new().unwrap();
    let input = tc.control.store.put_chunk(b"payload", None).unwrap();
    tc.control.create_job(hash_job(input)).unwrap();

    let app = dag_api::router(Arc::new(tc.control));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs/run")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"id":"hash-it"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
