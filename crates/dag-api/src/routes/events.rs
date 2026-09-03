//! Event endpoints: journal replay and a live SSE stream.

use std::convert::Infallible;
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::Response;
use dag_control::{Event, EventEnvelope, Replay as JournalReplay, Truncated};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;

use crate::blocking::on_blocking_pool;
use crate::error::{ApiError, ApiResult};
use crate::{admitted_bytes_body, AppState};

/// Replay window and filter.
#[derive(Debug, Deserialize)]
pub struct ReplayQuery {
    /// First journal sequence number to return.
    #[serde(default)]
    pub since_seq: u64,
    /// Maximum events to return, counted from the newest.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Comma-separated kinds: pointer, pin, job, storage.
    pub filter: Option<String>,
}

fn default_limit() -> usize {
    200
}

/// Most events one replay call will return, whatever it asks for.
///
/// The journal trims itself, so an uncapped `limit` was bounded — but only by
/// `DAG_EVENT_JOURNAL_KEEP`, which an operator may raise or disable, and one
/// short GET then serialised the entire journal to JSON. This is a page size,
/// and paging is what `since_seq` is for.
const MAX_REPLAY_LIMIT: usize = 500;

/// Maximum encoded body returned by one public replay.
///
/// Individual durable rows are bounded too, but a page of them still needs an
/// aggregate ceiling. Encoding writes through a capped sink, so this is also
/// the maximum response allocation rather than an after-the-fact check.
const MAX_REPLAY_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Most journal rows one public replay may inspect. A selective filter can
/// otherwise scan the full retained history while returning an empty page.
const MAX_REPLAY_SCAN: usize = 50_000;

/// Stable public representation of a failed job in the replay feed.
///
/// Adapter errors can contain local paths, command configuration, or bounded
/// stderr. The content router is intentionally public, so those details stay
/// in the local job-run record and operator logs rather than becoming public
/// observability data.
const REDACTED_JOB_FAILURE: &str = "job failed; inspect the local job run for details";

/// What `GET /api/events` returns.
///
/// The envelopes used to be the whole body. They are now a field, because a
/// client that asks for full history has to be able to tell that it did not get
/// it: retention trims the front of the journal, and a silently short answer
/// looks exactly like a complete one.
#[derive(Debug, Serialize)]
pub struct ReplayResponse {
    /// Matching envelopes, oldest first.
    pub events: Vec<EventEnvelope>,
    /// Oldest sequence number the journal still holds.
    pub earliest_seq: u64,
    /// Set when `since_seq` is older than anything that survives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<Truncated>,
    /// Number of durable rows inspected to build this page.
    pub scanned: u64,
    /// True when the scan budget was reached before all candidates were read.
    pub scan_truncated: bool,
}

/// The stream kind an event belongs to.
pub fn kind_of(event: &Event) -> &'static str {
    event.kind()
}

/// Parse a filter spec; `None` means "everything".
fn parse_filter(spec: Option<&str>) -> ApiResult<Option<HashSet<String>>> {
    let Some(spec) = spec else { return Ok(None) };
    let mut set = HashSet::new();
    for raw in spec.split(',') {
        let kind = raw.trim().to_ascii_lowercase();
        if kind.is_empty() {
            continue;
        }
        if !matches!(kind.as_str(), "pointer" | "pin" | "job" | "storage") {
            return Err(ApiError::bad_request(format!(
                "unknown event filter {kind:?}; expected pointer, pin, job, or storage"
            )));
        }
        set.insert(kind);
    }
    Ok((!set.is_empty()).then_some(set))
}

fn passes(filter: Option<&HashSet<String>>, event: &Event) -> bool {
    filter.is_none_or(|set| set.contains(kind_of(event)))
}

/// `GET /api/events?since_seq=…&limit=…&filter=…`
///
/// Returns the newest `limit` matching events at or after `since_seq`, oldest
/// first, so a client can render them in order and then follow the live stream
/// from the last seq. `dag events tail --since-seq … --limit …` applies the
/// same rule; it used to return the *oldest* `limit` from the same journal.
///
/// `truncated` is present when `since_seq` names events the journal no longer
/// holds.
pub async fn replay(
    State(state): State<AppState>,
    Query(q): Query<ReplayQuery>,
) -> ApiResult<Response> {
    let filter = parse_filter(q.filter.as_deref())?;

    // Replay reads the durable journal off disk, unlike `stream`, which only
    // subscribes to the in-memory broadcast and never blocks. JSON encoding
    // also stays on this pool because a maximum-size replay is real CPU work.
    let (encoded, replay_permit) = on_replay_pool(&state, move |control| {
        // The limit goes down into the journal rather than trimming a fully
        // materialised history: `since_seq=0&limit=10` should cost ten rows,
        // not the whole journal.
        let matches = |event: &Event| passes(filter.as_ref(), event);
        let window = control.event_bus.replay_with_scan_limit(
            q.since_seq,
            Some(q.limit.min(MAX_REPLAY_LIMIT)),
            Some(MAX_REPLAY_SCAN),
            &matches,
        )?;

        encode_replay_response(&ReplayResponse {
            events: window
                .events
                .into_iter()
                .map(redact_replay_failure)
                .collect(),
            earliest_seq: window.earliest_seq,
            truncated: window.truncated,
            scanned: window.scanned,
            scan_truncated: window.scan_truncated,
        })
    })
    .await?;

    let mut response = Response::new(admitted_bytes_body(Bytes::from(encoded), replay_permit));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

/// Run one materialised replay with its dedicated permit owned by the
/// blocking closure, then transfer that permit to the response body.
///
/// `spawn_blocking` work is not cancelled when its awaiting handler is
/// aborted. Capturing the permit here prevents a disconnected client from
/// reopening replay admission while that detached work is still running.
async fn on_replay_pool<T, F>(
    state: &AppState,
    operation: F,
) -> ApiResult<(T, tokio::sync::OwnedSemaphorePermit)>
where
    F: FnOnce(&dag_control::Control) -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    let replay_permit = state.try_event_replay_permit()?;
    on_blocking_pool(state, move |control| {
        let result = operation(control)?;
        Ok((result, replay_permit))
    })
    .await
}

/// A response encoder that refuses before its backing buffer crosses the
/// public replay ceiling.
struct ReplayWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl ReplayWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(64 * 1024),
            exceeded: false,
        }
    }
}

impl Write for ReplayWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("event replay size overflow"));
        };
        if next_len > MAX_REPLAY_RESPONSE_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("event replay exceeds limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_replay_response(response: &ReplayResponse) -> ApiResult<Vec<u8>> {
    let mut writer = ReplayWriter::new();
    match serde_json::to_writer(&mut writer, response) {
        Ok(()) => Ok(writer.bytes),
        Err(_) if writer.exceeded => Err(ApiError::payload_too_large(format!(
            "event replay response exceeds the {MAX_REPLAY_RESPONSE_BYTES}-byte limit; request a smaller limit or narrower filter"
        ))),
        Err(error) => Err(anyhow::Error::from(error).into()),
    }
}

fn redact_replay_failure(mut envelope: EventEnvelope) -> EventEnvelope {
    if let Event::JobRun {
        status: dag_core::RunStatus::Failed { message },
        ..
    } = &mut envelope.event
    {
        *message = REDACTED_JOB_FAILURE.to_owned();
    }
    envelope
}

/// Live filter selection.
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    /// Comma-separated kinds: pointer, pin, job, storage.
    pub filter: Option<String>,
}

/// The SSE event name carrying a loss notice.
pub const LAGGED_EVENT: &str = "lagged";

/// The SSE event name requiring the client to discard its cursor and
/// reconcile from authoritative API state before opening a fresh stream.
pub const REPLAY_REQUIRED_EVENT: &str = "replay-required";

/// Body of a [`LAGGED_EVENT`] message.
#[derive(Debug, Serialize)]
struct Lagged {
    /// How many events the broadcast channel dropped for this subscriber.
    missed: u64,
}

/// Why an SSE cursor could not be resumed without a possible gap.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReplayRequiredReason {
    /// Retention removed at least one requested sequence number.
    Retention,
    /// The bounded durable scan ended before continuity could be proven.
    ScanLimit,
    /// More matching events exist than one SSE resume is allowed to send.
    ResumeLimit,
    /// The cursor is not a sequence number this journal has emitted.
    CursorAhead,
    /// A stored envelope could not be represented on the SSE wire.
    Encoding,
}

/// Body of a [`REPLAY_REQUIRED_EVENT`] message.
///
/// This event deliberately has no SSE `id`: a reconnecting `EventSource`
/// retains the last successfully delivered event ID until the client closes
/// it. Clients must first refresh authoritative state, then create a new
/// `EventSource` so the stale cursor is not sent again.
#[derive(Debug, Serialize)]
struct ReplayRequired {
    reason: ReplayRequiredReason,
    message: &'static str,
    requested_last_event_id: Option<u64>,
    earliest_available_seq: Option<u64>,
    latest_available_seq: Option<u64>,
    scanned: u64,
    max_resume_events: usize,
}

impl ReplayRequired {
    fn from_snapshot(
        reason: ReplayRequiredReason,
        requested_last_event_id: u64,
        current_seq: u64,
        window: &JournalReplay,
    ) -> Self {
        let message = match reason {
            ReplayRequiredReason::Retention => {
                "event history needed for this cursor has expired; refresh authoritative state"
            }
            ReplayRequiredReason::ScanLimit => {
                "the bounded event scan could not prove a complete resume; refresh authoritative state"
            }
            ReplayRequiredReason::ResumeLimit => {
                "too many events are waiting for a bounded resume; refresh authoritative state"
            }
            ReplayRequiredReason::CursorAhead => {
                "the event cursor is ahead of this journal; refresh authoritative state"
            }
            ReplayRequiredReason::Encoding => {
                "an event could not be encoded; refresh authoritative state"
            }
        };
        Self {
            reason,
            message,
            requested_last_event_id: Some(requested_last_event_id),
            earliest_available_seq: Some(window.earliest_seq),
            latest_available_seq: current_seq.checked_sub(1),
            scanned: window.scanned,
            max_resume_events: MAX_REPLAY_LIMIT,
        }
    }

    fn encoding(last_seq: Option<u64>) -> Self {
        Self {
            reason: ReplayRequiredReason::Encoding,
            message: "an event could not be encoded; refresh authoritative state",
            requested_last_event_id: last_seq,
            earliest_available_seq: None,
            latest_available_seq: None,
            scanned: 0,
            max_resume_events: MAX_REPLAY_LIMIT,
        }
    }
}

struct ResumePlan {
    events: Vec<EventEnvelope>,
    loss: Option<ReplayRequired>,
}

/// Accept only the canonical decimal IDs emitted by this server.
///
/// SSE itself permits arbitrary strings, but this endpoint's IDs are journal
/// sequence numbers and are used in arithmetic. Rejecting signs, whitespace,
/// duplicate fields, non-canonical leading zeroes and `u64::MAX` prevents an
/// ambiguous cursor from being silently treated as a different position.
fn parse_last_event_id(headers: &HeaderMap) -> ApiResult<Option<u64>> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::bad_request(
            "Last-Event-ID must appear exactly once",
        ));
    }

    let raw = value.to_str().map_err(|_| {
        ApiError::bad_request("Last-Event-ID must be a canonical unsigned decimal integer")
    })?;
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::bad_request(
            "Last-Event-ID must be a canonical unsigned decimal integer",
        ));
    }
    let parsed = raw.parse::<u64>().map_err(|_| {
        ApiError::bad_request("Last-Event-ID is outside the supported sequence range")
    })?;
    if parsed == u64::MAX || parsed.to_string() != raw {
        return Err(ApiError::bad_request(
            "Last-Event-ID must be a canonical resumable sequence number",
        ));
    }
    Ok(Some(parsed))
}

fn plan_resume(last_event_id: u64, current_seq: u64, window: JournalReplay) -> ResumePlan {
    let reason = if window.truncated.is_some() {
        Some(ReplayRequiredReason::Retention)
    } else if window.scan_truncated {
        Some(ReplayRequiredReason::ScanLimit)
    } else if window.events.len() > MAX_REPLAY_LIMIT {
        Some(ReplayRequiredReason::ResumeLimit)
    } else if last_event_id >= current_seq {
        Some(ReplayRequiredReason::CursorAhead)
    } else {
        None
    };

    match reason {
        Some(reason) => ResumePlan {
            events: Vec::new(),
            loss: Some(ReplayRequired::from_snapshot(
                reason,
                last_event_id,
                current_seq,
                &window,
            )),
        },
        None => ResumePlan {
            events: window.events,
            loss: None,
        },
    }
}

fn replay_required_event(loss: &ReplayRequired) -> SseEvent {
    // Every field is a number, enum, option, or static string, so this cannot
    // fail with today's serializer. Keep a valid loss notice even if that
    // representation changes later instead of making encoding loss silent.
    let data = serde_json::to_string(loss).unwrap_or_else(|_| {
        r#"{"reason":"encoding","message":"an event could not be encoded; refresh authoritative state","requested_last_event_id":null,"earliest_available_seq":null,"latest_available_seq":null,"scanned":0,"max_resume_events":500}"#.to_owned()
    });
    SseEvent::default().event(REPLAY_REQUIRED_EVENT).data(data)
}

fn envelope_event(
    filter: Option<&HashSet<String>>,
    last_seq: &mut Option<u64>,
    envelope: EventEnvelope,
) -> Result<Option<SseEvent>, ()> {
    if last_seq.is_some_and(|last| envelope.seq <= last) || !passes(filter, &envelope.event) {
        return Ok(None);
    }

    let data = serde_json::to_string(&envelope).map_err(|_| ())?;
    *last_seq = Some(envelope.seq);
    Ok(Some(
        SseEvent::default()
            .id(envelope.seq.to_string())
            .event(kind_of(&envelope.event))
            .data(data),
    ))
}

/// Response-owned replay-plus-live stream.
///
/// The semaphore permit remains inside this value until the HTTP body is
/// dropped. `last_seq` is shared by replay and live delivery, making the seam
/// once-only even when an event was both durable by the snapshot and queued by
/// the subscription established immediately beforehand.
struct AdmittedEventStream {
    replay: std::vec::IntoIter<EventEnvelope>,
    live: BroadcastStream<EventEnvelope>,
    filter: Option<HashSet<String>>,
    last_seq: Option<u64>,
    initial_loss: Option<ReplayRequired>,
    finished: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Stream for AdmittedEventStream {
    type Item = Result<SseEvent, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }

        if let Some(loss) = this.initial_loss.take() {
            this.finished = true;
            return Poll::Ready(Some(Ok(replay_required_event(&loss))));
        }

        for envelope in this.replay.by_ref() {
            match envelope_event(this.filter.as_ref(), &mut this.last_seq, envelope) {
                Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                Ok(None) => {}
                Err(()) => {
                    this.finished = true;
                    let loss = ReplayRequired::encoding(this.last_seq);
                    return Poll::Ready(Some(Ok(replay_required_event(&loss))));
                }
            }
        }

        loop {
            match Pin::new(&mut this.live).poll_next(cx) {
                Poll::Ready(Some(Ok(envelope))) => {
                    match envelope_event(this.filter.as_ref(), &mut this.last_seq, envelope) {
                        Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                        Ok(None) => {}
                        Err(()) => {
                            this.finished = true;
                            let loss = ReplayRequired::encoding(this.last_seq);
                            return Poll::Ready(Some(Ok(replay_required_event(&loss))));
                        }
                    }
                }
                Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(missed)))) => {
                    // End after the notice. Continuing would make subsequent
                    // live events look contiguous; EventSource reconnects with
                    // the last successful numeric ID and enters bounded replay.
                    this.finished = true;
                    let data = serde_json::to_string(&Lagged { missed })
                        .unwrap_or_else(|_| format!(r#"{{"missed":{missed}}}"#));
                    return Poll::Ready(Some(Ok(SseEvent::default()
                        .event(LAGGED_EVENT)
                        .data(data))));
                }
                Poll::Ready(None) => {
                    this.finished = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// `GET /api/events/stream` — server-sent events, one JSON envelope per message.
///
/// `Last-Event-ID`, when present, must be the canonical decimal sequence ID
/// emitted by this endpoint. The handler subscribes before reading the durable
/// journal, replays at most 500 matching events from `Last-Event-ID + 1`, and
/// drops duplicate sequence numbers at the replay/live seam. Replay inspects at
/// most 50,000 rows.
///
/// If retention, the scan bound, or the replay count prevents a provably
/// complete resume, the only message is `replay-required` and the stream ends.
/// The client must reconcile from ordinary API state and create a fresh
/// `EventSource` without the stale cursor. A live subscriber that overruns the
/// broadcast buffer receives `lagged` with a count and the stream also ends;
/// its automatic reconnect then attempts the same bounded durable resume.
pub async fn stream(
    State(state): State<AppState>,
    Query(q): Query<StreamQuery>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    let filter = parse_filter(q.filter.as_deref())?;
    let last_event_id = parse_last_event_id(&headers)?;
    let stream_permit = state.try_live_event_permit()?;

    // This order is the continuity boundary: anything persisted while replay
    // is read is also queued here, then removed exactly once by `last_seq`.
    let rx = state.control.event_bus.subscribe();

    let plan = if let Some(last_event_id) = last_event_id {
        let start_seq = last_event_id
            .checked_add(1)
            .ok_or_else(|| ApiError::bad_request("Last-Event-ID cannot be resumed"))?;
        let replay_filter = filter.clone();
        let ((window, current_seq), replay_permit) = on_replay_pool(&state, move |control| {
            let matches = |event: &Event| passes(replay_filter.as_ref(), event);
            let window = control.event_bus.replay_with_scan_limit(
                start_seq,
                // One extra match proves whether the 500-event window is
                // complete; partial data is never sent on failure.
                Some(MAX_REPLAY_LIMIT + 1),
                Some(MAX_REPLAY_SCAN),
                &matches,
            )?;
            Ok((window, control.event_bus.current_seq()))
        })
        .await?;
        // Resume materialisation is complete. The distinct live-stream permit
        // remains response-owned below; replay admission need not be pinned by
        // an infinite body.
        drop(replay_permit);
        plan_resume(last_event_id, current_seq, window)
    } else {
        ResumePlan {
            events: Vec::new(),
            loss: None,
        }
    };

    let stream = AdmittedEventStream {
        replay: plan.events.into_iter(),
        live: BroadcastStream::new(rx),
        filter,
        last_seq: last_event_id,
        initial_loss: plan.loss,
        finished: false,
        _permit: stream_permit,
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt as _;

    fn pointer_event() -> Event {
        Event::PointerUpdate {
            id: "p".into(),
            new: dag_core::Cid::compute(b"x"),
            ts: 0,
        }
    }

    #[test]
    fn absent_or_empty_filter_matches_everything() {
        assert!(parse_filter(None).unwrap().is_none());
        assert!(parse_filter(Some("  ")).unwrap().is_none());
        assert!(passes(None, &pointer_event()));
    }

    #[test]
    fn filter_selects_by_kind() {
        let f = parse_filter(Some("pin, job")).unwrap().unwrap();
        assert!(!passes(Some(&f), &pointer_event()));
        assert!(passes(
            Some(&f),
            &Event::PinEvent {
                id: "a".into(),
                action: "created".into(),
                ts: 0
            }
        ));
    }

    #[test]
    fn unknown_filter_is_rejected() {
        let error = parse_filter(Some("pointer, impossible")).unwrap_err();
        assert_eq!(error.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn last_event_id_is_a_single_canonical_resumable_decimal() {
        let mut headers = HeaderMap::new();
        assert_eq!(parse_last_event_id(&headers).unwrap(), None);

        headers.insert("last-event-id", HeaderValue::from_static("42"));
        assert_eq!(parse_last_event_id(&headers).unwrap(), Some(42));

        for malformed in ["", "+1", "01", "1x", "18446744073709551615"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "last-event-id",
                HeaderValue::from_str(malformed).expect("valid header bytes"),
            );
            assert!(
                parse_last_event_id(&headers).is_err(),
                "accepted {malformed:?}"
            );
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append("last-event-id", HeaderValue::from_static("1"));
        duplicate.append("last-event-id", HeaderValue::from_static("2"));
        assert!(parse_last_event_id(&duplicate).is_err());
    }

    #[test]
    fn scan_limited_resume_requires_reconciliation() {
        let plan = plan_resume(
            0,
            10,
            JournalReplay {
                events: Vec::new(),
                earliest_seq: 0,
                truncated: None,
                scanned: MAX_REPLAY_SCAN as u64,
                scan_truncated: true,
            },
        );
        assert!(plan.events.is_empty());
        assert_eq!(
            plan.loss.expect("loss notice").reason,
            ReplayRequiredReason::ScanLimit
        );
    }

    #[tokio::test]
    async fn replay_live_seam_emits_a_sequence_once() {
        let temp = tempfile::tempdir().unwrap();
        let control = std::sync::Arc::new(dag_control::Control::open(temp.path()).unwrap());
        let state = AppState::new(control.clone());

        control.event_bus.emit(pointer_event()); // seq 0, represented by the cursor
        let rx = control.event_bus.subscribe();
        control.event_bus.emit(pointer_event()); // seq 1, in replay and the live queue
        let replay = control
            .event_bus
            .replay(1, Some(MAX_REPLAY_LIMIT + 1), &|_| true)
            .unwrap();

        let mut stream = AdmittedEventStream {
            replay: replay.events.into_iter(),
            live: BroadcastStream::new(rx),
            filter: None,
            last_seq: Some(0),
            initial_loss: None,
            finished: false,
            _permit: state.try_live_event_permit().unwrap(),
        };

        let _ = stream.next().await.expect("replayed seq 1").unwrap();
        assert_eq!(stream.last_seq, Some(1));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
                .await
                .is_err(),
            "the live copy of replayed seq 1 was emitted twice"
        );

        control.event_bus.emit(pointer_event()); // seq 2, live only
        let _ = stream.next().await.expect("live seq 2").unwrap();
        assert_eq!(stream.last_seq, Some(2));
    }

    /// The SSE stream dispatches every message under its event *name*, and the
    /// console registers one `addEventListener` per name — its `EVENT_KINDS`
    /// (`pointer`, `pin`, `job`, `storage`) plus `lagged`. A rename on either
    /// side silently breaks the live feed: that is exactly the regression that
    /// shipped once, invisible because nothing drove the names. If this test
    /// changes, `crates/dag-api/web/src/{main,types}.ts` must change with it.
    #[test]
    fn sse_event_names_match_the_console_listeners() {
        let cid = dag_core::Cid::compute(b"x");
        assert_eq!(
            kind_of(&Event::PointerUpdate {
                id: "p".into(),
                new: cid,
                ts: 0
            }),
            "pointer"
        );
        assert_eq!(
            kind_of(&Event::PinEvent {
                id: "p".into(),
                action: "created".into(),
                ts: 0
            }),
            "pin"
        );
        assert_eq!(
            kind_of(&Event::JobRun {
                job: "j".into(),
                run: "1".into(),
                status: dag_core::RunStatus::Succeeded,
                ts: 0
            }),
            "job"
        );
        assert_eq!(
            kind_of(&Event::StorageHealth {
                check: "c".into(),
                ok: true,
                ts: 0
            }),
            "storage"
        );
        assert_eq!(LAGGED_EVENT, "lagged");
        assert_eq!(REPLAY_REQUIRED_EVENT, "replay-required");
    }

    #[test]
    fn public_replay_redacts_job_failure_details() {
        let mut private_message = String::with_capacity(MAX_REPLAY_RESPONSE_BYTES * 2);
        private_message.push_str("/private/path: token=secret");
        let envelope = EventEnvelope {
            v: dag_control::events::ENVELOPE_SCHEMA_VERSION,
            seq: 1,
            envelope_ts: 2,
            event: Event::JobRun {
                job: "private-job".into(),
                run: "1".into(),
                status: dag_core::RunStatus::Failed {
                    message: private_message,
                },
                ts: 3,
            },
        };

        let redacted = redact_replay_failure(envelope);
        let Event::JobRun {
            status: dag_core::RunStatus::Failed { message },
            ..
        } = redacted.event
        else {
            panic!("expected a failed job event");
        };
        assert_eq!(message, REDACTED_JOB_FAILURE);
        assert!(
            message.capacity() < 1024,
            "redaction retained a private {}-byte allocation",
            message.capacity()
        );
    }

    #[test]
    fn replay_encoder_refuses_before_crossing_its_body_ceiling() {
        let response = ReplayResponse {
            events: vec![EventEnvelope {
                v: dag_control::events::ENVELOPE_SCHEMA_VERSION,
                seq: 1,
                envelope_ts: 2,
                event: Event::StorageHealth {
                    check: "x".repeat(MAX_REPLAY_RESPONSE_BYTES),
                    ok: true,
                    ts: 3,
                },
            }],
            earliest_seq: 0,
            truncated: None,
            scanned: 1,
            scan_truncated: false,
        };

        let error = encode_replay_response(&response).unwrap_err();
        assert_eq!(error.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_handler_cannot_release_admission_before_replay_work_exits() {
        let temp = tempfile::tempdir().unwrap();
        let control = std::sync::Arc::new(dag_control::Control::open(temp.path()).unwrap());
        let state = AppState::new(control);
        let state_for_task = state.clone();
        let release =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release_in_task = release.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            on_replay_pool(&state_for_task, move |_| {
                let _ = entered_tx.send(());
                let (lock, wake) = &*release_in_task;
                let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|error| error.into_inner());
                }
                Ok(())
            })
            .await
        });

        entered_rx.await.expect("blocking replay entered");
        task.abort();
        let _ = task.await;

        let premature = state.try_event_replay_permit();
        let premature_status = premature.as_ref().err().map(ApiError::status);
        drop(premature);

        let (lock, wake) = &*release;
        *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
        wake.notify_all();

        let recovered = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(permit) = state.try_event_replay_permit() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached blocking replay should eventually release admission");

        assert_eq!(
            premature_status,
            Some(axum::http::StatusCode::SERVICE_UNAVAILABLE)
        );
        drop(recovered);
    }
}
