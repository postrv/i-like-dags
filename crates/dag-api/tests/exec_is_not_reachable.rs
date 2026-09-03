//! The exec adapter must not be reachable through the HTTP API.
//!
//! `dag serve` has no built-in authentication. Its browser-origin controls are
//! useful defence in depth, but cannot be the authority to launch a process.
//! If `POST /api/jobs/run` could run a job whose `code_ref` is `exec`, one
//! exposed or proxied API call would become remote code execution.
//!
//! The guard is [`dag_jobs::Capabilities`], not the `exec` cargo feature:
//! cargo unifies features across a workspace build, so `dag-api` links a
//! `dag-jobs` that *has* the exec adapter compiled in. This test therefore runs
//! under exactly the conditions that matter — the adapter exists in the binary
//! — and asserts the API still refuses to invoke it.

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::test_utils::TestControl;
use dag_core::{Determinism, JobId, JobInput, JobPolicy, JobSpec};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

/// A job that would create a file on disk if its command ever ran.
fn exec_job(marker: &std::path::Path) -> JobSpec {
    JobSpec {
        job_id: JobId::from("exec-via-api"),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["stdout".into()],
        code_ref: "exec".into(),
        policy: JobPolicy::default(),
        config: Some(serde_json::json!({
            "command": "sh",
            "args": ["-c", format!("touch {}", marker.display())],
            "capture_stdout": true,
        })),
    }
}

#[tokio::test]
async fn the_api_refuses_to_run_an_exec_job() -> Result<()> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let app = dag_api::router(control.clone());

    // A marker the command would create. Its continued absence is the proof.
    let marker = tc.path().join("COMMAND-RAN");
    control.create_job(exec_job(&marker))?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/jobs/run")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"id":"exec-via-api"}"#))
        .unwrap();

    let response = app.oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    let text = String::from_utf8_lossy(&body);

    assert_ne!(status, StatusCode::OK, "the API ran an exec job: {}", text);
    assert!(
        !marker.exists(),
        "REMOTE CODE EXECUTION: the command actually ran via the HTTP API"
    );

    // And the refusal is because the adapter was never registered, which is
    // what keeps this true for any future exec-like adapter too.
    assert!(
        text.contains("exec"),
        "the error should name the unavailable adapter: {}",
        text
    );

    // The failure is still recorded as a failed run — the API did not silently
    // swallow the attempt.
    let runs = control
        .job_log
        .get_job_runs(&JobId::from("exec-via-api"), None)?;
    assert_eq!(runs.len(), 1);
    assert!(matches!(runs[0].status, dag_core::RunStatus::Failed { .. }));
    Ok(())
}

/// The same job runs fine when a caller explicitly grants the capability,
/// which is what the CLI's `--allow-exec` does. Without this the test above
/// could pass for the wrong reason (a broken spec, a missing `sh`).
#[tokio::test]
async fn the_same_job_runs_when_the_capability_is_granted() -> Result<()> {
    let tc = TestControl::new()?;
    let control = &tc.control;

    let marker = tc.path().join("COMMAND-RAN-WITH-CAPABILITY");
    control.create_job(exec_job(&marker))?;

    let outcome = dag_jobs::execute_once_with(
        control,
        &JobId::from("exec-via-api"),
        dag_jobs::Capabilities::none().with_exec(),
    )
    .await?;

    assert!(
        marker.exists(),
        "granting the capability should let the command run"
    );
    assert!(!outcome.outputs.is_empty());
    Ok(())
}
