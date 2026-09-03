//! The observability stream, remotely: journal replay then live tail.
//!
//! The payload of every envelope is the same JSON the local
//! `dag events tail` prints — one schema for both surfaces. The proto
//! duplicates `seq` and `ts` beside it so a consumer can filter and order
//! without parsing.

use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use dag_control::events::{Event, EventEnvelope};
use dag_control::Control;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::proto;
use crate::proto::events_server::Events;
use crate::server::on_blocking;

pub(crate) struct EventsService {
    pub(crate) control: Arc<Control>,
    /// A replay owns a materialized journal window until it has crossed the
    /// bounded socket queue. Admit only one such snapshot at a time.
    pub(crate) replay_slots: Arc<tokio::sync::Semaphore>,
    /// Aggregate lifetime admission for replay-only and followed streams.
    pub(crate) stream_slots: Arc<tokio::sync::Semaphore>,
}

/// Response stream that owns aggregate admission until the client consumes or
/// drops the body. The producer task can finish earlier for replay-only calls;
/// that must not release a socket-buffered response's slot.
pub(crate) struct AdmittedEventStream {
    inner: ReceiverStream<Result<proto::EventEnvelope, Status>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl tokio_stream::Stream for AdmittedEventStream {
    type Item = Result<proto::EventEnvelope, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Live-stream buffer: how many envelopes may sit between the bus and the
/// socket before backpressure applies to the forwarding task.
const STREAM_BUFFER: usize = 64;

/// Maximum durable rows inspected for a selective remote replay.
const MAX_REPLAY_SCAN: usize = 50_000;
/// The protocol has four event kinds. A little headroom keeps duplicate and
/// whitespace-normalized requests compatible without allowing an unbounded
/// attacker-controlled vector before stream admission.
const MAX_EVENT_FILTERS: usize = 8;
const MAX_EVENT_FILTER_BYTES: usize = 32;
pub(crate) const MAX_SUBSCRIBE_REQUEST_BYTES: usize = 1_024;
pub(crate) const MAX_EVENT_RESPONSE_BYTES: usize = 128 * 1_024;
const EVENT_KINDS: &[&str] = &["pointer", "pin", "job", "storage"];

fn passes(filter: Option<&HashSet<String>>, event: &Event) -> bool {
    filter.is_none_or(|set| set.contains(event.kind()))
}

fn to_wire(envelope: &EventEnvelope) -> Result<proto::EventEnvelope, Status> {
    Ok(proto::EventEnvelope {
        seq: envelope.seq,
        ts: envelope.envelope_ts,
        json: serde_json::to_string(envelope)
            .map_err(|error| internal_event_error("encoding an event", error))?,
    })
}

fn internal_event_error(context: &'static str, error: impl std::fmt::Display) -> Status {
    tracing::error!(%error, %context, "event service operation failed");
    Status::internal("event service operation failed")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayPlan {
    /// Rows requested from the journal, including a one-row completeness probe
    /// for the implicit server limit.
    read_limit: usize,
    /// Rows actually sent to the client.
    output_limit: usize,
    /// Whether the client selected the server default rather than an explicit
    /// newest-N window.
    implicit_limit: bool,
}

fn replay_plan(limit: u64) -> Result<ReplayPlan, Status> {
    if limit == 0 {
        return Ok(ReplayPlan {
            read_limit: crate::MAX_REMOTE_EVENT_REPLAY_EVENTS + 1,
            output_limit: crate::MAX_REMOTE_EVENT_REPLAY_EVENTS,
            implicit_limit: true,
        });
    }
    let limit = usize::try_from(limit)
        .map_err(|_| Status::invalid_argument("event replay limit is too large"))?;
    if limit > crate::MAX_REMOTE_EVENT_REPLAY_EVENTS {
        return Err(Status::invalid_argument(format!(
            "event replay limit must be at most {}",
            crate::MAX_REMOTE_EVENT_REPLAY_EVENTS
        )));
    }
    Ok(ReplayPlan {
        read_limit: limit,
        output_limit: limit,
        implicit_limit: false,
    })
}

#[tonic::async_trait]
impl Events for EventsService {
    type SubscribeStream = AdmittedEventStream;

    async fn subscribe(
        &self,
        request: Request<proto::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let stream_permit = self.stream_slots.clone().try_acquire_owned().map_err(|_| {
            Status::resource_exhausted("too many concurrent event subscriptions; retry later")
        })?;

        let req = request.into_inner();
        if req.types.len() > MAX_EVENT_FILTERS {
            return Err(Status::invalid_argument(format!(
                "at most {MAX_EVENT_FILTERS} event type filters are accepted"
            )));
        }
        if req
            .types
            .iter()
            .any(|event_type| event_type.len() > MAX_EVENT_FILTER_BYTES)
        {
            return Err(Status::invalid_argument(format!(
                "event type filters must be at most {MAX_EVENT_FILTER_BYTES} bytes"
            )));
        }
        let types: HashSet<String> = req
            .types
            .iter()
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if let Some(kind) = types
            .iter()
            .find(|kind| !EVENT_KINDS.contains(&kind.as_str()))
        {
            return Err(Status::invalid_argument(format!(
                "unknown event type {kind:?}; expected pointer, pin, job, or storage"
            )));
        }
        let filter = (!types.is_empty()).then_some(types);

        let replay_plan = req.replay.then(|| replay_plan(req.limit)).transpose()?;
        let replay_permit = if req.replay {
            Some(self.replay_slots.clone().try_acquire_owned().map_err(|_| {
                Status::resource_exhausted(
                    "another event replay is already in progress; retry later",
                )
            })?)
        } else {
            None
        };

        let bus = self.control.event_bus.clone();
        // Subscribe *before* replaying, so nothing emitted during the replay
        // read can fall between the two. The seam is deduplicated below by
        // sequence number instead.
        let mut live = bus.subscribe();

        let (tx, rx) = tokio::sync::mpsc::channel(STREAM_BUFFER);
        tokio::spawn(async move {
            let mut last_sent: Option<u64> = None;

            if req.replay {
                let since = req.since_seq;
                let replay_filter = filter.clone();
                let replayed = on_blocking(move || {
                    let matches = |event: &Event| passes(replay_filter.as_ref(), event);
                    bus.replay_with_scan_limit(
                        since,
                        replay_plan.map(|plan| plan.read_limit),
                        Some(MAX_REPLAY_SCAN),
                        &matches,
                    )
                    .map_err(|error| internal_event_error("reading event replay", error))
                })
                .await;

                let window = match replayed {
                    Ok(window) => window,
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        return;
                    }
                };

                if window.scan_truncated {
                    let _ = tx
                        .send(Err(Status::resource_exhausted(
                            "event replay scan budget reached; narrow since_seq or remove the filter",
                        )))
                        .await;
                    return;
                }

                let Some(plan) = replay_plan else {
                    let _ = tx
                        .send(Err(Status::internal(
                            "event replay plan was not initialized",
                        )))
                        .await;
                    return;
                };
                let incomplete = plan.implicit_limit && window.events.len() > plan.output_limit;
                let start = window.events.len().saturating_sub(plan.output_limit);
                for envelope in &window.events[start..] {
                    last_sent = Some(envelope.seq);
                    let item = match to_wire(envelope) {
                        Ok(item) => item,
                        Err(status) => {
                            let _ = tx.send(Err(status)).await;
                            return;
                        }
                    };
                    if tx.send(Ok(item)).await.is_err() {
                        return; // subscriber went away
                    }
                }
                if incomplete {
                    let _ = tx
                        .send(Err(Status::out_of_range(format!(
                            "event replay exceeded the implicit {}-event ceiling; retry with a later since_seq or choose an explicit --limit",
                            crate::MAX_REMOTE_EVENT_REPLAY_EVENTS
                        ))))
                        .await;
                    return;
                }
            }

            // The journal snapshot is gone once the bounded replay has been
            // handed to the socket queue; live following does not retain it.
            drop(replay_permit);

            if req.no_follow {
                return; // dropping tx ends the stream cleanly
            }

            loop {
                let received = tokio::select! {
                    // A quiet journal must still release admission immediately
                    // when the remote drops its response body.
                    _ = tx.closed() => return,
                    received = live.recv() => received,
                };
                match received {
                    Ok(envelope) => {
                        // The seam: an event emitted mid-replay reached both
                        // the journal read and this subscription. Sequence
                        // numbers are authoritative, so send each one once.
                        if req.replay && last_sent.is_some_and(|last| envelope.seq <= last) {
                            continue;
                        }
                        if !passes(filter.as_ref(), &envelope.event) {
                            continue;
                        }
                        let item = match to_wire(&envelope) {
                            Ok(item) => item,
                            Err(status) => {
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        };
                        if tx.send(Ok(item)).await.is_err() {
                            return;
                        }
                    }
                    // A lagged subscriber lost events the bus dropped; an
                    // unfiltered consumer sees the loss as a jump in `seq`,
                    // the same signal the local tail reads.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        let _ = tx
                            .send(Err(Status::data_loss(format!(
                                "event subscriber lagged and missed {missed} events; reconnect with replay"
                            ))))
                            .await;
                        return;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(AdmittedEventStream {
            inner: ReceiverStream::new(rx),
            _permit: stream_permit,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_control::events::Event;
    use tokio_stream::StreamExt;

    fn replay_request(limit: u64) -> Request<proto::SubscribeRequest> {
        Request::new(proto::SubscribeRequest {
            replay: true,
            since_seq: 0,
            types: Vec::new(),
            no_follow: true,
            limit,
        })
    }

    #[test]
    fn internal_event_errors_do_not_expose_storage_details() {
        let detail = "/srv/private/events.log: permission denied";
        let status = internal_event_error("reading test replay", detail);
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), "event service operation failed");
        assert!(!status.message().contains(detail));
    }

    #[tokio::test]
    async fn replay_snapshot_has_a_hard_limit_and_aggregate_admission() {
        let directory = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(directory.path()).unwrap());
        for index in 0..=STREAM_BUFFER {
            control.event_bus.emit(Event::StorageHealth {
                check: format!("check-{index}"),
                ok: true,
                ts: 0,
            });
        }
        let service = EventsService {
            control,
            replay_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            stream_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        };

        // The first replay cannot finish handing 65 events to a 64-entry
        // undrained channel, so its snapshot permit is deterministically held.
        let first = Events::subscribe(&service, replay_request(0))
            .await
            .unwrap();
        let second = match Events::subscribe(&service, replay_request(1)).await {
            Ok(_) => panic!("a second materialized replay was admitted"),
            Err(status) => status,
        };
        assert_eq!(second.code(), tonic::Code::ResourceExhausted);
        drop(first);

        let over_limit = match Events::subscribe(
            &service,
            replay_request((crate::MAX_REMOTE_EVENT_REPLAY_EVENTS + 1) as u64),
        )
        .await
        {
            Ok(_) => panic!("an over-limit replay was admitted"),
            Err(status) => status,
        };
        assert_eq!(over_limit.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn implicit_replay_limit_reserves_a_completeness_probe() {
        let implicit = replay_plan(0).unwrap();
        assert!(implicit.implicit_limit);
        assert_eq!(
            implicit.read_limit,
            crate::MAX_REMOTE_EVENT_REPLAY_EVENTS + 1
        );
        assert_eq!(implicit.output_limit, crate::MAX_REMOTE_EVENT_REPLAY_EVENTS);

        let explicit = replay_plan(7).unwrap();
        assert!(!explicit.implicit_limit);
        assert_eq!(explicit.read_limit, 7);
        assert_eq!(explicit.output_limit, 7);
    }

    #[tokio::test]
    async fn subscriptions_hold_aggregate_admission_for_their_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(directory.path()).unwrap());
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let service = EventsService {
            control,
            replay_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            stream_slots: slots.clone(),
        };
        let live = Events::subscribe(
            &service,
            Request::new(proto::SubscribeRequest {
                no_follow: false,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(slots.available_permits(), 0);

        let refused = match Events::subscribe(
            &service,
            Request::new(proto::SubscribeRequest {
                no_follow: false,
                ..Default::default()
            }),
        )
        .await
        {
            Ok(_) => panic!("a second live stream was admitted"),
            Err(error) => error,
        };
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);

        drop(live);
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn completed_replay_still_holds_admission_while_body_is_undrained() {
        let directory = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(directory.path()).unwrap());
        control.event_bus.emit(Event::StorageHealth {
            check: "ready".into(),
            ok: true,
            ts: 0,
        });
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let service = EventsService {
            control,
            replay_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            stream_slots: slots.clone(),
        };

        let response = Events::subscribe(&service, replay_request(1))
            .await
            .unwrap();
        let mut body = response.into_inner();
        assert!(body.next().await.unwrap().is_ok());
        assert!(body.next().await.is_none());
        // The producer has deterministically finished, but admission belongs
        // to the still-owned response body rather than the producer task.
        assert_eq!(slots.available_permits(), 0);
        let refused = match Events::subscribe(&service, replay_request(1)).await {
            Ok(_) => panic!("an undrained replay released admission early"),
            Err(error) => error,
        };
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);

        drop(body);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn filter_validation_is_bounded_and_runs_after_stream_admission() {
        let directory = tempfile::tempdir().unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let service = EventsService {
            control: Arc::new(Control::open(directory.path()).unwrap()),
            replay_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            stream_slots: slots.clone(),
        };
        let held = slots.clone().try_acquire_owned().unwrap();
        let oversized = Request::new(proto::SubscribeRequest {
            types: vec!["x".repeat(MAX_EVENT_FILTER_BYTES + 1); MAX_EVENT_FILTERS + 1],
            ..Default::default()
        });
        let saturated = match Events::subscribe(&service, oversized).await {
            Ok(_) => panic!("filter parsing bypassed stream admission"),
            Err(error) => error,
        };
        assert_eq!(saturated.code(), tonic::Code::ResourceExhausted);

        drop(held);
        let too_many = match Events::subscribe(
            &service,
            Request::new(proto::SubscribeRequest {
                types: vec!["pointer".into(); MAX_EVENT_FILTERS + 1],
                ..Default::default()
            }),
        )
        .await
        {
            Ok(_) => panic!("an oversized filter vector was admitted"),
            Err(error) => error,
        };
        assert_eq!(too_many.code(), tonic::Code::InvalidArgument);
        assert_eq!(slots.available_permits(), 1);

        let too_long = match Events::subscribe(
            &service,
            Request::new(proto::SubscribeRequest {
                types: vec!["x".repeat(MAX_EVENT_FILTER_BYTES + 1)],
                ..Default::default()
            }),
        )
        .await
        {
            Ok(_) => panic!("an oversized filter value was admitted"),
            Err(error) => error,
        };
        assert_eq!(too_long.code(), tonic::Code::InvalidArgument);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn unknown_event_types_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let service = EventsService {
            control: Arc::new(Control::open(directory.path()).unwrap()),
            replay_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            stream_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let error = match Events::subscribe(
            &service,
            Request::new(proto::SubscribeRequest {
                types: vec!["impossible".into()],
                ..Default::default()
            }),
        )
        .await
        {
            Ok(_) => panic!("an unknown filter was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
