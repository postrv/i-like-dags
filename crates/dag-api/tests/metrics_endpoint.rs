//! `GET /metrics`: the scrape surface — registry series, scrape-time gauges,
//! and the server's own request accounting with bounded labels.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, String, Option<String>) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, body, content_type)
}

/// Build a router over a fresh directory, with some content in it.
fn app_with_content() -> (axum::Router, Arc<dag_control::Control>, tempfile::TempDir) {
    use dag_core::ContentStore;
    let dir = tempfile::tempdir().unwrap();
    let control = Arc::new(dag_control::Control::open(dir.path()).unwrap());
    control.store.put_chunk(b"observed content", None).unwrap();
    (dag_api::router(control.clone()), control, dir)
}

#[tokio::test]
async fn metrics_render_registry_series_gauges_and_the_right_content_type() {
    let (app, _control, _dir) = app_with_content();

    let (status, body, content_type) = get(&app, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        content_type.as_deref(),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );

    // Registry series, live: the put above was counted and timed.
    assert!(body.contains("\ndag_store_put_total 1\n"), "{body}");
    assert!(body.contains("dag_store_put_seconds_bucket{le=\"+Inf\"} 1"));
    // Scrape-time gauges from Control::stats.
    assert!(body.contains("\ndag_store_chunks 1\n"), "{body}");
    assert!(body.contains("# TYPE dag_store_bytes gauge"));
    assert!(body.contains("\ndag_recovered "), "{body}");
}

#[tokio::test]
async fn the_api_alias_serves_the_same_series() {
    let (app, _control, _dir) = app_with_content();

    let (status, body, _) = get(&app, "/api/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("dag_store_put_total"), "{body}");
}

#[tokio::test]
async fn http_requests_are_counted_by_matched_route_not_raw_path() {
    let (app, _control, _dir) = app_with_content();

    // Two API hits with different query strings — one route label.
    let _ = get(&app, "/api/stats").await;
    let _ = get(&app, "/api/stats?x=1").await;

    let (_, body, _) = get(&app, "/metrics").await;
    assert!(
        body.contains(
            "dag_http_requests_total{method=\"GET\",route=\"/api/stats\",status=\"200\"} 2"
        ),
        "{body}"
    );
    // The raw query string never becomes a label.
    assert!(!body.contains("x=1"), "{body}");
    // The scrape itself was recorded on an earlier line or will be next
    // scrape; the histogram exists either way.
    assert!(body.contains("# TYPE dag_http_request_seconds histogram"));
}

#[tokio::test]
async fn bare_health_answers_json_where_the_fallback_would_answer_html() {
    let (app, _control, _dir) = app_with_content();

    let (status, body, content_type) = get(&app, "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"status\":\"ok\""), "{body}");
    assert!(body.contains("\"check\":\"liveness\""), "{body}");
    assert!(
        content_type.unwrap().starts_with("application/json"),
        "a probe needs JSON, not a page"
    );

    // The contrast that makes the alias necessary: any *other* unmatched
    // path is the console's HTML with a 200 a probe would happily believe.
    let (spa_status, spa_body, _) = get(&app, "/not-a-route").await;
    assert_eq!(spa_status, StatusCode::OK);
    assert!(!spa_body.contains("\"status\":\"ok\""));
}

#[tokio::test]
async fn a_second_scrape_observes_the_first() {
    let (app, _control, _dir) = app_with_content();

    let _ = get(&app, "/metrics").await;
    let (_, body, _) = get(&app, "/metrics").await;
    assert!(
        body.contains("dag_http_requests_total{method=\"GET\",route=\"/metrics\",status=\"200\"}"),
        "{body}"
    );
}

#[tokio::test]
async fn store_reads_through_the_api_show_up_in_the_registry() {
    use dag_core::ContentStore;
    let (app, control, _dir) = app_with_content();
    let cid = control.store.put_chunk(b"fetch me", None).unwrap();

    let (status, _, _) = get(&app, &format!("/api/chunks?cid={}", cid.to_hex())).await;
    assert_eq!(status, StatusCode::OK);

    let (_, body, _) = get(&app, "/metrics").await;
    assert!(body.contains("\ndag_store_get_total 1\n"), "{body}");
}
