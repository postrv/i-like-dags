//! HTTP-level tests for the API surface.
//!
//! These drive the real router against a real `Control`, so they cover
//! routing, extraction, serialisation and status mapping — the parts unit
//! tests on the control plane cannot reach.

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::test_utils::TestControl;
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

/// A router over a fresh, isolated control plane.
///
/// The `TestControl` owns the temp directory; the router gets its own
/// `Control` in a subdirectory because redb locks a database file to one
/// handle at a time.
fn harness() -> Result<(TestControl, axum::Router)> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    Ok((tc, dag_api::router(control)))
}

async fn call(router: &axum::Router, request: Request<Body>) -> Result<(StatusCode, Value)> {
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    Ok((status, body))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn health_and_empty_stats() -> Result<()> {
    let (_tc, app) = harness()?;

    let (status, body) = call(&app, get("/api/health")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["check"], "readiness");
    assert_eq!(body["recovered"], false);

    let (status, body) = call(&app, get("/api/stats")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["chunks"], 0);
    assert_eq!(body["recovered"], false);
    Ok(())
}

#[tokio::test]
async fn empty_and_past_end_run_pages_are_stable() -> Result<()> {
    let (_tc, app) = harness()?;
    let (status, page) = call(&app, get("/api/jobs/runs?id=missing&limit=25")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"], serde_json::json!([]));
    assert_eq!(page["next_cursor"], Value::Null);
    assert_eq!(page["truncated"], false);

    let (status, page) = call(
        &app,
        get("/api/jobs/runs?id=missing&limit=25&cursor=18446744073709551615"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"], serde_json::json!([]));

    let (status, _) = call(&app, get("/api/jobs/runs?id=missing&cursor=0")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, get("/api/jobs/runs?id=missing&cursor=not-a-run")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn full_recovery_is_offline_and_collection_waits_for_it() -> Result<()> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let app = dag_api::router(Arc::clone(&control));

    let (status, body) = call(
        &app,
        post("/api/gc/run", serde_json::json!({"dry_run": true})),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an unmet recovery gate is a caller-fixable conflict, not a server fault"
    );
    assert!(body["error"].as_str().unwrap().contains("recovery"));

    let (status, _) = call(&app, post("/api/recovery/rebuild", Value::Null)).await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "whole-store recovery must not be remotely triggerable"
    );

    control.recover()?;

    let (status, body) = call(
        &app,
        post("/api/gc/run", serde_json::json!({"dry_run": true})),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dry_run"], true);
    Ok(())
}

#[tokio::test]
async fn malformed_input_is_a_client_error() -> Result<()> {
    let (_tc, app) = harness()?;

    let (status, _) = call(&app, get("/api/entries?cid=not-hex")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(&app, get("/api/graph")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "graph needs a root");

    let missing = dag_core::Cid::compute(b"never stored").to_hex();
    let (status, _) = call(&app, get(&format!("/api/entries?cid={}", missing))).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(&app, get("/api/pointers/resolve?id=no-such-pointer")).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn seeding_exposes_the_whole_scenario() -> Result<()> {
    let (_tc, app) = harness()?;

    let (status, seed) = call(&app, post("/api/usecase/seed", Value::Null)).await?;
    assert_eq!(status, StatusCode::OK);
    let production = seed["production_pointer"].as_str().unwrap().to_string();

    // Pointer IDs contain slashes, which is why they travel as query params.
    let (status, pointers) = call(&app, get("/api/pointers")).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(pointers["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == production.as_str()));

    let (status, graph) = call(
        &app,
        get(&format!("/api/graph?pointer={}&depth=4", production)),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 7);
    assert!(
        graph["nodes"][0]["pinned"].as_bool().unwrap(),
        "the release subtree pin should mark the root as retained"
    );

    let (status, verify) = call(&app, get("/api/usecase/verify")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verify["verified"], true);
    assert_eq!(verify["corrupt"], 0);

    // A run must record which pointer revisions it resolved.
    let (status, runs) = call(&app, get("/api/jobs/runs?id=attest-release")).await?;
    assert_eq!(status, StatusCode::OK);
    let latest = &runs["items"][0];
    assert_eq!(latest["status"], "Succeeded");
    assert_eq!(latest["pointer_inputs"].as_array().unwrap().len(), 3);
    assert_eq!(latest["outputs"][0]["name"], "attestation");
    Ok(())
}

#[tokio::test]
async fn cids_are_hex_strings_on_the_wire() -> Result<()> {
    let (_tc, app) = harness()?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/chunks")
        .body(Body::from("hello"))
        .unwrap();
    let (status, body) = call(&app, request).await?;
    assert_eq!(status, StatusCode::OK);

    let cid = body["cid"]
        .as_str()
        .expect("cid must serialise as a string");
    assert_eq!(cid, dag_core::Cid::compute(b"hello").to_hex());

    let (_, pointer) = call(
        &app,
        post(
            "/api/pointers",
            serde_json::json!({ "id": "a/b", "cid": cid }),
        ),
    )
    .await?;
    assert_eq!(pointer["cid"], cid);

    // Events embed CIDs too, and they must be readable there as well.
    // The body is an object, not a bare array: it also has to carry where the
    // journal starts, so a trimmed history is distinguishable from a whole one.
    let (status, body) = call(&app, get("/api/events?limit=10")).await?;
    assert_eq!(status, StatusCode::OK);
    let update = body["events"].as_array().unwrap().last().unwrap();
    assert_eq!(update["event"]["new"], cid);
    Ok(())
}

#[tokio::test]
async fn pointer_post_creates_then_updates() -> Result<()> {
    let (_tc, app) = harness()?;

    let (status, stored) = call(&app, post_bytes("/api/chunks", b"one".to_vec())).await?;
    assert_eq!(status, StatusCode::OK);
    let first = stored["cid"].as_str().unwrap().to_string();
    let (status, stored) = call(&app, post_bytes("/api/chunks", b"two".to_vec())).await?;
    assert_eq!(status, StatusCode::OK);
    let second = stored["cid"].as_str().unwrap().to_string();

    let (_, created) = call(
        &app,
        post(
            "/api/pointers",
            serde_json::json!({ "id": "models/x", "cid": first }),
        ),
    )
    .await?;
    assert_eq!(created["seq"], 1);

    let (_, updated) = call(
        &app,
        post(
            "/api/pointers",
            serde_json::json!({ "id": "models/x", "cid": second }),
        ),
    )
    .await?;
    assert_eq!(
        updated["seq"], 2,
        "a second POST appends rather than failing"
    );

    let (status, history) = call(&app, get("/api/pointers/history?id=models/x")).await?;
    assert_eq!(status, StatusCode::OK);
    let history = history["items"].as_array().unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1]["previous_cid"], first.as_str());
    Ok(())
}

#[tokio::test]
async fn pointer_lists_and_histories_have_explicit_continuations() -> Result<()> {
    use dag_core::ContentStore;

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let target = control.store.put_chunk(b"page target", None)?;
    for id in ["pointer-01", "pointer-02", "pointer-03"] {
        control.pointer_log.create(id, target.clone())?;
    }
    control.pointer_log.update(
        "pointer-01",
        control.store.put_chunk(b"revision two", None)?,
    )?;
    control.pointer_log.update(
        "pointer-01",
        control.store.put_chunk(b"revision three", None)?,
    )?;
    let app = dag_api::router(control);

    let (status, first) = call(&app, get("/api/pointers?limit=2")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    assert_eq!(first["truncated"], true);
    assert_eq!(first["next_cursor"], "pointer-02");

    let (status, second) = call(&app, get("/api/pointers?limit=2&cursor=pointer-02")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["id"], "pointer-03");
    assert_eq!(second["truncated"], false);
    assert!(second["next_cursor"].is_null());

    let (status, first_history) =
        call(&app, get("/api/pointers/history?id=pointer-01&limit=2")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first_history["items"].as_array().unwrap().len(), 2);
    assert_eq!(first_history["next_cursor"], "3");

    let (status, final_history) = call(
        &app,
        get("/api/pointers/history?id=pointer-01&limit=2&cursor=3"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(final_history["items"].as_array().unwrap().len(), 1);
    assert_eq!(final_history["items"][0]["seq"], 3);
    assert_eq!(final_history["truncated"], false);

    for uri in [
        "/api/pointers?limit=0",
        "/api/pointers?limit=201",
        "/api/pointers/history?id=pointer-01&limit=201",
    ] {
        let (status, body) = call(&app, get(uri)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert!(body["error"].as_str().unwrap().contains("limit"));
    }
    Ok(())
}

#[tokio::test]
async fn graph_pointer_annotation_scan_is_bounded_and_declared() -> Result<()> {
    use dag_core::ContentStore;

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let target = control.store.put_chunk(b"graph target", None)?;
    for n in 0..=dag_api::routes::content::MAX_GRAPH_POINTER_LABELS {
        control
            .pointer_log
            .create(&format!("graph-pointer-{n:03}"), target.clone())?;
    }
    let app = dag_api::router(control);

    let (status, graph) = call(
        &app,
        get(&format!("/api/graph?cid={}&depth=0", target.to_hex())),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(graph["pointer_labels_truncated"], true);
    assert_eq!(
        graph["nodes"][0]["pointers"].as_array().unwrap().len(),
        dag_api::routes::content::MAX_GRAPH_POINTER_LABELS
    );
    Ok(())
}

#[tokio::test]
async fn graph_fanout_cannot_make_the_edge_response_unbounded() -> Result<()> {
    use dag_core::{ContentStore, Entry, Link};

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let links = (0..=dag_api::routes::content::MAX_GRAPH_EDGES)
        .map(|n| Link::unnamed(dag_core::Cid::compute(&n.to_le_bytes())))
        .collect();
    let root = control.store.put_entry(&Entry::with_links(links))?;
    let app = dag_api::router(control);

    let (status, graph) = call(
        &app,
        get(&format!("/api/graph?cid={}&depth=1", root.to_hex())),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(graph["truncated"], true);
    assert_eq!(
        graph["edges"].as_array().unwrap().len(),
        dag_api::routes::content::MAX_GRAPH_EDGES
    );
    Ok(())
}

#[tokio::test]
async fn public_scenario_verification_refuses_excess_fanout() -> Result<()> {
    use dag_core::{ContentStore, Entry, Link};

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let target = control.store.put_chunk(b"shared target", None)?;
    let root = control.store.put_entry(&Entry::with_links(
        (0..=dag_api::scenario::MAX_VERIFY_LINKS)
            .map(|_| Link::unnamed(target.clone()))
            .collect(),
    ))?;
    control.pointer_log.create("verify-limit", root)?;
    let app = dag_api::router(control);

    let (status, body) = call(&app, get("/api/usecase/verify?pointer=verify-limit")).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body["error"]
        .as_str()
        .is_some_and(|message| message.contains("verification links")));
    Ok(())
}

#[tokio::test]
async fn job_listing_is_a_lexicographic_cursor_page() -> Result<()> {
    use dag_core::{Determinism, JobId, JobInput, JobPolicy, JobSpec};

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    for id in ["job-01", "job-02", "job-03"] {
        control.create_job(JobSpec {
            job_id: JobId::from(id),
            placement: None,
            inputs: JobInput::default(),
            determinism: Determinism::Deterministic,
            declared_outputs: Vec::new(),
            code_ref: "hash".into(),
            policy: JobPolicy::default(),
            config: None,
        })?;
    }
    let app = dag_api::router(control);

    let (status, first) = call(&app, get("/api/jobs?limit=2")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    assert_eq!(first["next_cursor"], "job-02");
    assert_eq!(first["truncated"], true);

    let (status, second) = call(&app, get("/api/jobs?limit=2&cursor=job-02")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["id"], "job-03");
    assert_eq!(second["truncated"], false);

    let (status, body) = call(&app, get("/api/jobs?limit=201")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("limit"));
    Ok(())
}

#[tokio::test]
async fn pin_lists_and_histories_have_explicit_continuations() -> Result<()> {
    use dag_core::{ContentStore, PinScope, PinTarget};

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let target = control.store.put_chunk(b"pin page target", None)?;
    for id in ["pin-01", "pin-02", "pin-03"] {
        control.pin_log.create(
            id,
            PinTarget::Direct(target.clone()),
            PinScope::Global,
            None,
            None,
        )?;
    }
    control.pin_log.deactivate("pin-01", None)?;
    let app = dag_api::router(control);

    let (status, first) = call(&app, get("/api/pins?limit=2")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    assert_eq!(first["next_cursor"], "pin-02");
    assert_eq!(first["truncated"], true);

    let (status, second) = call(&app, get("/api/pins?limit=2&cursor=pin-02")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["id"], "pin-03");
    assert_eq!(second["truncated"], false);

    let (status, first_history) = call(&app, get("/api/pins/history?id=pin-01&limit=1")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first_history["items"].as_array().unwrap().len(), 1);
    assert_eq!(first_history["next_cursor"], "2");

    let (status, final_history) =
        call(&app, get("/api/pins/history?id=pin-01&limit=1&cursor=2")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(final_history["items"].as_array().unwrap().len(), 1);
    assert_eq!(final_history["items"][0]["seq"], 2);
    assert_eq!(final_history["truncated"], false);

    for uri in [
        "/api/pins?limit=201",
        "/api/pins/history?id=pin-01&limit=201",
    ] {
        let (status, body) = call(&app, get(uri)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert!(body["error"].as_str().unwrap().contains("limit"));
    }
    Ok(())
}

#[tokio::test]
async fn the_console_is_served() -> Result<()> {
    let (_tc, app) = harness()?;

    for (uri, expected) in [
        ("/", "dag console"),
        ("/app.css", "--accent"),
        ("/js/main.js", "import"),
    ] {
        let response = app.clone().oneshot(get(uri)).await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{} should be served",
            uri
        );
        let bytes = response.into_body().collect().await?.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains(expected), "{} looks wrong", uri);
    }

    let response = app.oneshot(get("/js/nope.js")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Raw (non-JSON) upload, for the content endpoints.
fn post_bytes(uri: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap()
}

/// I2 and acceptance criterion A promise 4 MiB. axum's default body limit is
/// 2 MiB, so before this was pinned the HTTP API rejected content the CLI
/// accepted — the two entry points disagreed about the system's own limit.
#[tokio::test]
async fn a_chunk_at_exactly_the_four_mib_limit_is_accepted() -> Result<()> {
    let (_tc, app) = harness()?;

    let body = vec![7u8; dag_core::MAX_CHUNK_SIZE];
    let (status, json) = call(&app, post_bytes("/api/chunks", body)).await?;

    assert_eq!(
        status,
        StatusCode::OK,
        "a chunk at MAX_CHUNK_SIZE must be accepted, got {}",
        json
    );
    assert_eq!(json["size"], dag_core::MAX_CHUNK_SIZE);
    Ok(())
}

/// Just over the limit must produce the domain's own error naming the ceiling,
/// not axum's bare "length limit exceeded" text — which is why the body limit
/// is set slightly above `MAX_CHUNK_SIZE` rather than exactly at it.
#[tokio::test]
async fn an_oversized_chunk_is_refused_with_a_structured_413() -> Result<()> {
    let (_tc, app) = harness()?;

    let body = vec![7u8; dag_core::MAX_CHUNK_SIZE + 1];
    let (status, json) = call(&app, post_bytes("/api/chunks", body)).await?;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let message = json["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("4194304") || message.to_lowercase().contains("too large"),
        "error should name the limit, got {:?}",
        message
    );
    Ok(())
}

/// The streaming file route must still have a finite transport backstop.
/// A declared body beyond the 1 GiB policy plus the splitter's one-chunk
/// diagnostic slack is rejected by middleware before it acquires a blocking
/// admission permit or reads any bytes.
#[tokio::test]
async fn an_obviously_overlimit_file_upload_is_rejected_before_body_work() -> Result<()> {
    let (_tc, app) = harness()?;
    let hard_backstop = dag_api::routes::files::MAX_HTTP_FILE_BYTES + dag_core::MAX_CHUNK_SIZE + 1;
    let request = Request::builder()
        .method("POST")
        .uri("/api/files")
        .header(axum::http::header::CONTENT_LENGTH, hard_backstop)
        .body(Body::empty())?;

    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

/// Deterministic pseudorandom bytes; incompressible, so chunk boundaries are
/// realistic.
fn file_noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The streaming endpoints round-trip content far beyond the 4 MiB chunk
/// limit — the API's equivalent of `dag put` / `dag get` on a large file.
#[tokio::test]
async fn files_endpoint_round_trips_a_six_mib_upload() -> Result<()> {
    let (_tc, app) = harness()?;
    let original = file_noise(6 * 1024 * 1024, 77);

    let request = Request::builder()
        .method("POST")
        .uri("/api/files?content_type=application/octet-stream")
        .body(Body::from(original.clone()))
        .unwrap();
    let (status, json) = call(&app, request).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["chunked"], true);
    assert_eq!(json["size"], original.len() as u64);
    assert!(json["chunks"].as_u64().unwrap() > 1);
    let cid = json["cid"].as_str().unwrap().to_string();

    // Download: byte-identical, with honest headers.
    let response = app
        .clone()
        .oneshot(get(&format!("/api/files?cid={}", cid)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_LENGTH],
        original.len().to_string().as_str()
    );
    assert_eq!(
        response.headers()[axum::http::header::CONTENT_TYPE],
        "application/octet-stream"
    );
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body.as_ref(), original.as_slice(), "must be byte-identical");
    Ok(())
}

/// Small uploads stay plain chunks, and the download endpoint serves them
/// too — callers never need to know whether content was chunked.
#[tokio::test]
async fn files_endpoint_handles_small_content_as_plain_chunks() -> Result<()> {
    let (_tc, app) = harness()?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/files")
        .body(Body::from("small payload"))
        .unwrap();
    let (status, json) = call(&app, request).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("chunked").is_none(), "small content stays a chunk");
    assert_eq!(
        json["cid"].as_str().unwrap(),
        dag_core::Cid::compute(b"small payload").to_hex()
    );

    let response = app
        .clone()
        .oneshot(get(&format!(
            "/api/files?cid={}",
            json["cid"].as_str().unwrap()
        )))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body.as_ref(), b"small payload");

    // Missing content is a clean 404, not a broken stream.
    let missing = dag_core::Cid::compute(b"never stored").to_hex();
    let (status, _) = call(&app, get(&format!("/api/files?cid={}", missing))).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

/// A verification failure mid-download must not deliver wrong bytes as if
/// they were right: with Content-Length committed, the stream aborts short.
#[tokio::test]
async fn a_tampered_chunk_aborts_the_download() -> Result<()> {
    let (_tc, app) = harness()?;
    let original = file_noise(6 * 1024 * 1024, 13);

    let request = Request::builder()
        .method("POST")
        .uri("/api/files")
        .body(Body::from(original))
        .unwrap();
    let (_, json) = call(&app, request).await?;
    let cid = json["cid"].as_str().unwrap().to_string();

    // Pick a middle data chunk via the manifest's own links, then corrupt it
    // on disk in the router's data directory.
    let (_, entry) = call(&app, get(&format!("/api/entries?cid={}", cid))).await?;
    let victim = dag_core::Cid::from_hex(entry["links"][2]["target"].as_str().unwrap())?;
    let hex = victim.to_hex();
    let (prefix, rest) = hex.split_at(2);
    std::fs::write(
        _tc.path().join("api").join("data").join(prefix).join(rest),
        b"tampered",
    )?;

    let response = app
        .clone()
        .oneshot(get(&format!("/api/files?cid={}", cid)))
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "headers are already sent"
    );
    let collected = response.into_body().collect().await;
    assert!(
        collected.is_err(),
        "a tampered chunk must abort the stream, not serve wrong bytes"
    );
    Ok(())
}

/// Signature verdicts over HTTP mirror the CLI's: trusted requires the
/// keyring, an unknown key is at best "valid". The router shares its
/// `Arc<Control>`, so the test signs through the same control plane the
/// endpoint reads.
#[tokio::test]
async fn signatures_endpoint_reports_both_verdicts() -> Result<()> {
    use dag_core::ContentStore;
    use ed25519_dalek::SigningKey;

    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    let app = dag_api::router(control.clone());

    let target = control.store.put_chunk(b"signed content", None)?;

    // No signatures yet.
    let (status, body) = call(
        &app,
        get(&format!("/api/signatures?cid={}", target.to_hex())),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["signatures"].as_array().unwrap().len(), 0);

    // A trusted signer and a stranger both sign.
    let trusted_key = SigningKey::from_bytes(&[9u8; 32]);
    control.signature_log.trust_key(
        &hex::encode(trusted_key.verifying_key().as_bytes()),
        Some("ci".into()),
        &[dag_control::TrustPurpose::Verify],
    )?;
    control
        .signature_log
        .sign(&target, None, serde_json::json!({}), &trusted_key)?;
    let stranger = SigningKey::from_bytes(&[10u8; 32]);
    control
        .signature_log
        .sign(&target, None, serde_json::json!({}), &stranger)?;

    let (status, body) = call(
        &app,
        get(&format!("/api/signatures?cid={}", target.to_hex())),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["trusted"], 1, "exactly one keyring-backed signature");
    assert_eq!(body["trusted_complete"], true);
    assert_eq!(body["truncated"], false);
    let sigs = body["signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2);
    let trusted_sig = sigs.iter().find(|s| s["trusted"] == true).unwrap();
    assert_eq!(trusted_sig["signer"], "ci");
    let untrusted_sig = sigs.iter().find(|s| s["trusted"] == false).unwrap();
    assert_eq!(
        untrusted_sig["valid"], true,
        "self-consistent but unvouched"
    );

    // Verification work is paged, and the distinct-key count says when it is
    // exact rather than presenting a partial count as a complete verdict.
    let (status, first) = call(
        &app,
        get(&format!("/api/signatures?cid={}&limit=1", target.to_hex())),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["signatures"].as_array().unwrap().len(), 1);
    assert_eq!(first["next_cursor"], "1");
    assert_eq!(first["truncated"], true);
    assert_eq!(first["trusted_complete"], false);

    let (status, second) = call(
        &app,
        get(&format!(
            "/api/signatures?cid={}&limit=1&cursor=1",
            target.to_hex()
        )),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["signatures"].as_array().unwrap().len(), 1);
    assert!(second["next_cursor"].is_null());
    // A later page is not a complete target-wide count even when it happens
    // to exhaust the collection.
    assert_eq!(second["trusted_complete"], false);

    let (status, body) = call(
        &app,
        get(&format!(
            "/api/signatures?cid={}&limit=201",
            target.to_hex()
        )),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("limit"));
    Ok(())
}

/// The generous chunk ceiling is scoped to `/chunks`. Every other endpoint
/// carries small JSON and must keep the cheap limit, so a route-level layer
/// cannot be allowed to leak outward into the rest of the router.
#[tokio::test]
async fn json_endpoints_keep_the_small_body_limit() -> Result<()> {
    let (_tc, app) = harness()?;

    let huge = serde_json::json!({ "id": "x".repeat(512 * 1024), "cid": "00" });
    let response = app.oneshot(post("/api/pointers", huge)).await?;

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "control endpoints must not inherit the chunk-sized limit"
    );
    Ok(())
}
