//! The event endpoints must not lose things quietly.
//!
//! Two failures this covers, both of which looked like success from outside:
//! a replay whose requested start had been trimmed away came back partial but
//! indistinguishable from complete, and an SSE subscriber that fell behind had
//! its `Lagged` error mapped to `None` inside a `filter_map`, so the loss
//! vanished entirely.

use std::sync::Arc;

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::{Control, Event, EventBus};
use dag_core::Cid;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

/// A router plus a handle on the control plane behind it, so a test can emit
/// events into the same bus the router is serving.
fn harness() -> Result<(tempfile::TempDir, Arc<Control>, axum::Router)> {
    let temp = tempfile::tempdir()?;
    let control = Arc::new(Control::open(temp.path())?);
    let router = dag_api::router(control.clone());
    Ok((temp, control, router))
}

fn pointer(i: u64) -> Event {
    Event::PointerUpdate {
        id: format!("ptr-{i}"),
        new: Cid::compute(&i.to_be_bytes()),
        ts: 0,
    }
}

async fn get_json(router: &axum::Router, uri: &str) -> Result<(StatusCode, Value)> {
    let request = Request::builder().uri(uri).body(Body::empty())?;
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
async fn replay_returns_the_newest_events_within_the_limit() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..50 {
        control.event_bus.emit(pointer(i));
    }

    let (status, body) = get_json(&app, "/api/events?since_seq=0&limit=3").await?;
    assert_eq!(status, StatusCode::OK);

    let seqs: Vec<u64> = body["events"]
        .as_array()
        .expect("events array")
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![47, 48, 49]);
    assert!(body.get("truncated").is_none());
    assert_eq!(body["scanned"], 3);
    assert_eq!(body["scan_truncated"], false);

    Ok(())
}

#[tokio::test]
async fn public_replay_never_materialises_more_than_five_hundred_events() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..525 {
        control.event_bus.emit(pointer(i));
    }

    let (status, body) = get_json(&app, "/api/events?since_seq=0&limit=10000").await?;
    assert_eq!(status, StatusCode::OK);
    let events = body["events"].as_array().expect("events array");
    assert_eq!(events.len(), 500);
    assert_eq!(events.first().unwrap()["seq"], 25);
    assert_eq!(events.last().unwrap()["seq"], 524);
    assert_eq!(body["scanned"], 500);
    assert_eq!(body["scan_truncated"], false);

    Ok(())
}

#[tokio::test]
async fn replay_admission_lasts_until_the_response_body_is_dropped() -> Result<()> {
    let (_temp, control, app) = harness()?;
    control.event_bus.emit(pointer(0));

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events?limit=1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let at_capacity = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events?limit=1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(at_capacity.status(), StatusCode::SERVICE_UNAVAILABLE);

    drop(first);

    let admitted_again = app
        .oneshot(
            Request::builder()
                .uri("/api/events?limit=1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(admitted_again.status(), StatusCode::OK);

    Ok(())
}

#[tokio::test]
async fn oversized_encoded_replay_is_a_safe_413_and_releases_admission() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..72 {
        control.event_bus.emit(Event::StorageHealth {
            check: format!("check-{i}-{}", "x".repeat(60_000)),
            ok: true,
            ts: 0,
        });
    }
    assert_eq!(control.event_bus.current_seq(), 72);

    let (status, body) = get_json(&app, "/api/events?since_seq=0&limit=500").await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let message = body["error"].as_str().expect("safe JSON error");
    assert!(message.contains("4194304-byte limit"), "{message}");

    let (status, body) = get_json(&app, "/api/events?since_seq=71&limit=1").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["events"].as_array().unwrap().len(), 1);

    Ok(())
}

#[tokio::test]
async fn replay_says_so_when_the_requested_start_is_gone() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..300 {
        control.event_bus.emit(pointer(i));
    }
    control.event_bus.compact_keep_last(100)?;

    let (status, body) = get_json(&app, "/api/events?since_seq=0&limit=500").await?;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body["earliest_seq"], 200);
    let truncated = body
        .get("truncated")
        .expect("a request from seq 0 after compaction is a partial answer");
    assert_eq!(truncated["requested_seq"], 0);
    assert_eq!(truncated["earliest_seq"], 200);
    assert_eq!(truncated["missing"], 200);

    Ok(())
}

#[tokio::test]
async fn replay_from_a_surviving_seq_is_not_truncated() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..300 {
        control.event_bus.emit(pointer(i));
    }
    control.event_bus.compact_keep_last(100)?;

    let (_, body) = get_json(&app, "/api/events?since_seq=200&limit=500").await?;
    assert!(body.get("truncated").is_none());
    assert_eq!(body["events"].as_array().unwrap().len(), 100);

    Ok(())
}

#[tokio::test]
async fn unknown_replay_and_stream_filters_are_rejected() -> Result<()> {
    let (_temp, _control, app) = harness()?;
    for uri in [
        "/api/events?filter=not-a-kind",
        "/api/events/stream?filter=not-a-kind",
    ] {
        let request = Request::builder().uri(uri).body(Body::empty())?;
        let response = app.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn sse_strictly_rejects_a_malformed_last_event_id() -> Result<()> {
    let (_temp, _control, app) = harness()?;
    for malformed in ["not-a-sequence", "+1", "01", "18446744073709551615"] {
        let request = Request::builder()
            .uri("/api/events/stream")
            .header("last-event-id", malformed)
            .body(Body::empty())?;
        let response = app.clone().oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{malformed:?}");
    }
    Ok(())
}

#[tokio::test]
async fn sse_resumes_from_last_event_id_then_continues_live() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..3 {
        control.event_bus.emit(pointer(i));
    }

    let request = Request::builder()
        .uri("/api/events/stream")
        .header("last-event-id", "0")
        .body(Body::empty())?;
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();

    let first = next_chunk(&mut body).await.expect("replayed seq 1")?;
    let second = next_chunk(&mut body).await.expect("replayed seq 2")?;
    assert_eq!(sse_id(&first), Some(1), "{first}");
    assert_eq!(sse_id(&second), Some(2), "{second}");

    control.event_bus.emit(pointer(3));
    let live = next_chunk(&mut body).await.expect("live seq 3")?;
    assert_eq!(sse_id(&live), Some(3), "{live}");

    Ok(())
}

#[tokio::test]
async fn sse_retention_loss_requires_replay_then_ends() -> Result<()> {
    let (_temp, control, app) = harness()?;
    for i in 0..6 {
        control.event_bus.emit(pointer(i));
    }
    control.event_bus.compact_keep_last(3)?;

    let request = Request::builder()
        .uri("/api/events/stream")
        .header("last-event-id", "0")
        .body(Body::empty())?;
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();

    let loss = next_chunk(&mut body).await.expect("loss frame")?;
    assert_eq!(sse_event(&loss), Some("replay-required"), "{loss}");
    let payload = sse_data(&loss).expect("loss JSON");
    assert_eq!(payload["reason"], "retention");
    assert_eq!(payload["requested_last_event_id"], 0);
    assert_eq!(payload["earliest_available_seq"], 3);
    assert!(
        next_chunk(&mut body).await.is_none(),
        "an incomplete retention replay must terminate"
    );

    Ok(())
}

#[tokio::test]
async fn sse_oversized_resume_requires_replay_instead_of_sending_a_suffix() -> Result<()> {
    let (_temp, control, app) = harness()?;
    // Cursor 0 leaves 501 matching events, one beyond the public resume cap.
    for i in 0..502 {
        control.event_bus.emit(pointer(i));
    }

    let request = Request::builder()
        .uri("/api/events/stream")
        .header("last-event-id", "0")
        .body(Body::empty())?;
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();

    let loss = next_chunk(&mut body).await.expect("loss frame")?;
    assert_eq!(sse_event(&loss), Some("replay-required"), "{loss}");
    let payload = sse_data(&loss).expect("loss JSON");
    assert_eq!(payload["reason"], "resume_limit");
    assert_eq!(payload["max_resume_events"], 500);
    assert!(
        next_chunk(&mut body).await.is_none(),
        "an oversized resume must terminate"
    );

    Ok(())
}

#[tokio::test]
async fn live_stream_admission_lasts_until_the_response_body_is_dropped() -> Result<()> {
    let (_temp, _control, app) = harness()?;
    let mut responses = Vec::new();
    for _ in 0..32 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/events/stream")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        responses.push(response);
    }

    let at_capacity = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events/stream")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(at_capacity.status(), StatusCode::SERVICE_UNAVAILABLE);

    responses.pop();
    let admitted_again = app
        .oneshot(
            Request::builder()
                .uri("/api/events/stream")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(admitted_again.status(), StatusCode::OK);

    Ok(())
}

/// The console always filters, so a gap in `seq` carries no information: the
/// non-matching events in between were never going to be sent. The loss has to
/// be its own message or it cannot be seen at all.
#[tokio::test]
async fn a_lagging_sse_subscriber_is_told_what_it_missed() -> Result<()> {
    let (_temp, control, app) = harness()?;

    // The handler subscribes while serving the request, so the subscription
    // exists before anything below is emitted.
    let request = Request::builder()
        .uri("/api/events/stream?filter=pointer")
        .body(Body::empty())?;
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    // Overrun the broadcast channel before the body is ever polled. The bus
    // buffers 1024 per subscriber, so a little past that is enough; each
    // journal write is an fsync, so "a little" matters.
    for i in 0..1_100 {
        control.event_bus.emit(pointer(i));
    }

    let mut body = response.into_body().into_data_stream();
    let mut seen = String::new();
    while seen.len() < 4096 {
        let Some(frame) = next_chunk(&mut body).await else {
            break;
        };
        seen.push_str(&frame?);
        if seen.contains("event: lagged") {
            break;
        }
    }

    assert!(
        seen.contains("event: lagged"),
        "a lagged subscriber got no notice; stream began: {}",
        &seen[..seen.len().min(400)]
    );
    let missed_line = seen
        .lines()
        .skip_while(|l| !l.contains("event: lagged"))
        .find(|l| l.starts_with("data:"))
        .expect("lagged message carries data");
    let payload: Value = serde_json::from_str(missed_line.trim_start_matches("data:").trim())?;
    assert!(
        payload["missed"].as_u64().unwrap_or(0) > 0,
        "lagged notice should name a count, got {payload}"
    );
    assert!(
        next_chunk(&mut body).await.is_none(),
        "a lagged stream must end so EventSource resumes from its last good ID"
    );

    Ok(())
}

/// A subscriber that keeps up is unaffected by the lag handling.
#[tokio::test]
async fn a_keeping_up_subscriber_sees_only_its_events() -> Result<()> {
    let (_temp, control, app) = harness()?;

    let request = Request::builder()
        .uri("/api/events/stream?filter=pointer")
        .body(Body::empty())?;
    let response = app.oneshot(request).await?;

    control.event_bus.emit(pointer(1));

    let mut body = response.into_body().into_data_stream();
    let chunk = next_chunk(&mut body).await.expect("one frame")?;

    assert!(chunk.contains("event: pointer"), "got: {chunk}");
    assert!(!chunk.contains("event: lagged"), "got: {chunk}");

    Ok(())
}

/// Guards the `dag-api` half of the retention story: the bus the server holds
/// is the bounded one.
#[test]
fn the_served_journal_is_bounded_by_default() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let control = Control::open(temp.path())?;
    assert_eq!(
        control.event_bus.journal_retention(),
        Some(dag_control::DEFAULT_JOURNAL_RETENTION)
    );
    Ok(())
}

/// A bus with no journal answers rather than panicking.
#[test]
fn a_journalless_bus_replays_empty() -> Result<()> {
    let bus = EventBus::new_default();
    let window = bus.replay(0, Some(10), &|_| true)?;
    assert!(window.events.is_empty());
    assert!(window.truncated.is_none());
    assert_eq!(window.scanned, 0);
    assert!(!window.scan_truncated);
    assert_eq!(bus.journal_retention(), None);
    Ok(())
}

/// Pull the next chunk of an SSE body as a string, bounded so a hung stream
/// fails this test rather than hanging the suite.
async fn next_chunk(body: &mut axum::body::BodyDataStream) -> Option<Result<String>> {
    use tokio_stream::StreamExt;
    match tokio::time::timeout(std::time::Duration::from_secs(10), body.next()).await {
        Ok(Some(Ok(bytes))) => Some(Ok(String::from_utf8_lossy(&bytes).into_owned())),
        Ok(Some(Err(e))) => Some(Err(e.into())),
        Ok(None) => None,
        Err(_) => Some(Err(anyhow::anyhow!("timed out waiting for an SSE frame"))),
    }
}

fn sse_field<'a>(frame: &'a str, field: &str) -> Option<&'a str> {
    frame.lines().find_map(|line| {
        let value = line.strip_prefix(field)?.strip_prefix(':')?;
        Some(value.trim())
    })
}

fn sse_id(frame: &str) -> Option<u64> {
    sse_field(frame, "id")?.parse().ok()
}

fn sse_event(frame: &str) -> Option<&str> {
    sse_field(frame, "event")
}

fn sse_data(frame: &str) -> Option<Value> {
    serde_json::from_str(sse_field(frame, "data")?).ok()
}
