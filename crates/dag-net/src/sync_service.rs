//! The server side of replication: this node as a sync source (for pulls)
//! and a sync destination (for pushes).
//!
//! Everything here delegates to the same `SyncSource`/`SyncDestination`
//! implementations on `Control` that the directory engine uses — the wire
//! adds transport, never authority. In particular the candidate-aware commit
//! runs the complete incremental history, closure, and derived-index validation
//! in this process, which makes a hostile peer's grafted history a refusal here
//! instead of a corruption there.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dag_control::pointer::{PointerError, PointerTriggerAuthority};
use dag_control::sync::{
    EventBatchOutcome, EventConflict, RebuildCounts, SyncDestination, SyncEnumeration, SyncOptions,
    SyncSource, SyncTruncation, MISSING_BATCH, PROBE_BATCH,
};
use dag_control::Control;
use dag_core::{Cid, ContentStore, PinError, MAX_CHUNK_SIZE};
use dag_storage::FsStore;
use sha2::{Digest, Sha256};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::auth::{AuthScope, GrantedScopes};
use crate::proto;
use crate::proto::sync_server::Sync;
use crate::server::{on_blocking, on_control};

/// Bytes of chunk data per [`proto::ChunkFrame`].
///
/// Small enough that the protocol's default message limits stay untouched;
/// a 4 MiB chunk is at most 16 frames.
pub const CHUNK_FRAME_BYTES: usize = 256 * 1024;

/// How many event refs or CIDs one [`proto::EnumerateBatch`] carries.
const ENUMERATE_BATCH: usize = 4096;

/// Full integrity verification reads each requested chunk, so this batch is
/// intentionally much smaller than the metadata-only `Missing` batch. At the
/// 4 MiB chunk ceiling one request hashes at most 64 MiB, not 16 GiB.
const STAT_CHUNKS_BATCH: usize = 16;

/// A sender must make progress within this interval between upload frames.
const PUT_FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Even a sender that dribbles frames under the idle threshold cannot occupy
/// one upload forever.
const PUT_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Complete atomic offers are bounded independently of frame size. At the
/// maximum 256-byte ID this is under 20 MiB of retained event metadata.
const MAX_ATOMIC_EVENT_REFS: usize = dag_control::sync::MAX_SYNC_EVENT_REFS;

/// Wire pages stay comfortably below tonic's default message ceiling.
const EVENT_PAGE_SIZE: usize = 4_096;
const MAX_RELATED_CIDS_PER_EVENT_PAGE: usize = 65_536;
/// Staging cannot retain more refs than the atomic publication marker can
/// accept. Refusing the first impossible page avoids holding attacker-chosen
/// metadata for a session that can never commit.
const MAX_IMPORT_REFS: usize = MAX_ATOMIC_EVENT_REFS;
const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;
const MAX_IMPORT_SESSIONS: usize = 4;
const MAX_IMPORT_RECEIPTS: usize = 64;
const MAX_IMPORT_GLOBAL_BYTES: usize = 512 * 1024 * 1024;
const IMPORT_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// How many frames a chunk of `total_len` bytes is allowed to arrive in.
///
/// The reassembly loop used to run until the *sender* chose to stop. A frame
/// carrying no data advances nothing, so a peer could hold a request open
/// indefinitely — and make the receiver do per-message work the whole time —
/// by streaming empty frames at it. This is the exit the sender does not get
/// to decline.
///
/// Sized at one frame per 4 KiB, which is 64x more generous than the
/// [`CHUNK_FRAME_BYTES`] windows our own sender uses: 1026 frames for a
/// full-size chunk, 2 for an empty one. A sender that needs more than that is
/// not fragmenting, it is stalling.
pub(crate) fn frame_budget(total_len: usize) -> usize {
    total_len.div_ceil(4096) + 2
}

/// Capacity to reserve for a chunk whose sender *claims* it will be
/// `total_len` bytes.
///
/// Reserving the declared length let a peer allocate 4 MiB per request out of
/// a header frame of a few dozen bytes, and then send nothing — around 80,000x
/// amplification, times however many requests it cared to open. Reserve one
/// frame; the vector grows against bytes that actually arrived, which for a
/// real 4 MiB chunk in 256 KiB frames is a handful of reallocations.
pub(crate) fn initial_capacity(total_len: usize) -> usize {
    total_len.min(CHUNK_FRAME_BYTES)
}

/// Ceiling on the entry walk a peer may ask [`SyncService::enumerate`] for.
///
/// `max_walk` is the caller's cap on how much of the graph the *server*
/// traverses and holds in memory, and it arrived over the wire unclamped —
/// so a peer could ask for `u64::MAX` and get a full-store walk materialised
/// twice. Clamped to the same figure the local default uses: no client asks
/// for more today (nothing exposes the knob), and a peer can still ask for
/// less.
const MAX_REMOTE_WALK: usize = 1_000_000;

pub(crate) struct SyncService {
    pub(crate) control: Arc<Control>,
    /// Deferred staging view of the same store: inbound chunks skip their
    /// per-write fsyncs, and `Flush` settles them all at once. Shared across
    /// concurrent pushers — settling more than one caller's chunks is
    /// harmless, and every import settles first anyway.
    pub(crate) staging: Arc<FsStore>,
    /// Enumeration materializes a bounded graph snapshot. Only one such
    /// snapshot may be retained by an outbound stream at a time.
    pub(crate) enumerate_slots: Arc<tokio::sync::Semaphore>,
    /// Aggregate admission around full chunk buffers. Eight calls cap each
    /// direction near 32 MiB of payload, plus bounded framing overhead.
    pub(crate) get_chunk_slots: Arc<tokio::sync::Semaphore>,
    pub(crate) put_chunk_slots: Arc<tokio::sync::Semaphore>,
    pub(crate) import_sessions: Arc<ImportSessions>,
}

#[derive(Default)]
pub(crate) struct ImportSessions {
    sessions: Mutex<HashMap<String, ImportSession>>,
}

struct ImportSession {
    expires_at: std::time::Instant,
    expires_unix: i64,
    page_digests: Vec<[u8; 32]>,
    pointer_events: Vec<(String, u64, Cid)>,
    pin_events: Vec<(String, u64, Cid)>,
    pointer_events_staged: u64,
    pin_events_staged: u64,
    retained_bytes: usize,
    committing: bool,
    result: Option<proto::CommitEventImportResponse>,
    final_digest: Option<[u8; 32]>,
}

impl ImportSession {
    fn new() -> Self {
        let (expires_at, expires_unix) = renewed_expiry();
        Self {
            expires_at,
            expires_unix,
            page_digests: Vec::new(),
            pointer_events: Vec::new(),
            pin_events: Vec::new(),
            pointer_events_staged: 0,
            pin_events_staged: 0,
            retained_bytes: 0,
            committing: false,
            result: None,
            final_digest: None,
        }
    }

    fn renew(&mut self) {
        (self.expires_at, self.expires_unix) = renewed_expiry();
    }
}

fn renewed_expiry() -> (std::time::Instant, i64) {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(IMPORT_SESSION_TTL.as_secs())
        .min(i64::MAX as u64) as i64;
    (std::time::Instant::now() + IMPORT_SESSION_TTL, unix)
}

fn clean_expired(sessions: &mut HashMap<String, ImportSession>) {
    let now = std::time::Instant::now();
    sessions.retain(|_, session| session.committing || session.expires_at > now);
}

fn admit_new_session(sessions: &mut HashMap<String, ImportSession>) -> Result<(), Status> {
    clean_expired(sessions);
    let active = sessions
        .values()
        .filter(|session| session.result.is_none())
        .count();
    if active >= MAX_IMPORT_SESSIONS {
        return Err(Status::resource_exhausted(format!(
            "at most {MAX_IMPORT_SESSIONS} event import sessions may be active"
        )));
    }

    // Completed/rejected receipts are tiny compared with staged refs, but an
    // authorised peer must not create them without limit during the TTL.
    // Evict the oldest receipt only when admitting a different live offer;
    // ordinary retries still find their receipt idempotently.
    while sessions.len() >= MAX_IMPORT_SESSIONS + MAX_IMPORT_RECEIPTS {
        let oldest = sessions
            .iter()
            .filter(|(_, session)| session.result.is_some())
            .min_by_key(|(_, session)| session.expires_at)
            .map(|(id, _)| id.clone());
        let Some(oldest) = oldest else {
            return Err(Status::resource_exhausted(
                "event import session record capacity is exhausted",
            ));
        };
        sessions.remove(&oldest);
    }
    Ok(())
}

fn valid_transfer_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn update_event_digest(hasher: &mut Sha256, kind: u8, event: &(String, u64, Cid)) {
    hasher.update([kind]);
    hasher.update((event.0.len() as u32).to_be_bytes());
    hasher.update(event.0.as_bytes());
    hasher.update(event.1.to_be_bytes());
    hasher.update(event.2.as_bytes());
}

fn event_offer_digest(
    pointer_events: &[(String, u64, Cid)],
    pin_events: &[(String, u64, Cid)],
    index_candidates: &[Cid],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"dag-net:event-offer:v3\0");
    for event in pointer_events {
        update_event_digest(&mut hasher, 0, event);
    }
    for event in pin_events {
        update_event_digest(&mut hasher, 1, event);
    }
    for cid in index_candidates {
        hasher.update([2]);
        hasher.update(cid.as_bytes());
    }
    hasher.finalize().into()
}

fn page_digest(
    pointer_events: &[(String, u64, Cid)],
    pin_events: &[(String, u64, Cid)],
) -> [u8; 32] {
    event_offer_digest(pointer_events, pin_events, &[])
}

fn event_bytes(events: &[(String, u64, Cid)]) -> Result<usize, Status> {
    events.iter().try_fold(0usize, |total, (id, _, _)| {
        total
            .checked_add(id.len() + 1 + 8 + 32)
            .ok_or_else(|| Status::resource_exhausted("event import size overflow"))
    })
}

/// Parse a wire CID, refusing anything that is not exactly 32 bytes.
pub(crate) fn cid_from_wire(bytes: &[u8]) -> Result<Cid, Status> {
    Cid::from_bytes(bytes)
        .map_err(|_| Status::invalid_argument(format!("CID must be 32 bytes, got {}", bytes.len())))
}

fn refuse(e: dag_control::ControlError) -> Status {
    tracing::warn!(error = %e, "native sync operation refused");
    match &e {
        dag_control::ControlError::Pointer(PointerError::TriggerPermissionRequired { .. }) => {
            Status::permission_denied(
                "trigger scope is required to publish an actively subscribed pointer",
            )
        }
        dag_control::ControlError::Capacity(_)
        | dag_control::ControlError::Pointer(PointerError::Capacity(_)) => {
            Status::resource_exhausted("sync destination capacity limit reached")
        }
        dag_control::ControlError::Invalid(_)
        | dag_control::ControlError::Pointer(
            PointerError::AlreadyExists(_)
            | PointerError::NotFound(_)
            | PointerError::Serialization(_)
            | PointerError::InvalidRange { .. }
            | PointerError::CasConflict { .. },
        )
        | dag_control::ControlError::Pin(
            PinError::InvalidPinId(_)
            | PinError::PinNotFound(_)
            | PinError::PinAlreadyExists(_)
            | PinError::InvalidSequence { .. },
        ) => Status::failed_precondition("sync request failed destination validation"),
        _ => Status::internal("sync destination operation failed"),
    }
}

fn internal_storage_failure(operation: &'static str, error: impl std::fmt::Display) -> Status {
    tracing::error!(operation, error = %error, "native sync storage operation failed");
    Status::internal("sync destination storage operation failed")
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

enum EnumerationPhase {
    PointerEvents,
    PinEvents,
    Wanted,
    LiveRoots,
    IndexCandidates,
    Terminal,
    Done,
}

/// Lazily converts one bounded enumeration snapshot into wire batches. The
/// source vectors are consumed as each message is polled, so memory never
/// holds the full snapshot plus a second full `Vec<EnumerateBatch>` copy.
struct EnumerationBatches {
    pointer_events: std::vec::IntoIter<(String, u64, Cid)>,
    pin_events: std::vec::IntoIter<(String, u64, Cid)>,
    wanted: std::vec::IntoIter<Cid>,
    live_roots: std::vec::IntoIter<Cid>,
    index_candidates: std::vec::IntoIter<Cid>,
    truncation: Option<SyncTruncation>,
    snapshot_generation: String,
    phase: EnumerationPhase,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl EnumerationBatches {
    fn new(
        enumeration: SyncEnumeration,
        permit: tokio::sync::OwnedSemaphorePermit,
        snapshot_generation: String,
    ) -> Self {
        Self {
            pointer_events: enumeration.pointer_events.into_iter(),
            pin_events: enumeration.pin_events.into_iter(),
            wanted: enumeration.wanted.into_iter(),
            live_roots: enumeration.live_roots.into_iter(),
            index_candidates: enumeration.index_candidates.into_iter(),
            truncation: enumeration.truncation,
            snapshot_generation,
            phase: EnumerationPhase::PointerEvents,
            _permit: permit,
        }
    }

    fn next_batch(&mut self) -> Option<proto::EnumerateBatch> {
        loop {
            match self.phase {
                EnumerationPhase::PointerEvents => {
                    let pointer_events = self
                        .pointer_events
                        .by_ref()
                        .take(ENUMERATE_BATCH)
                        .map(event_ref_owned)
                        .collect::<Vec<_>>();
                    if !pointer_events.is_empty() {
                        return Some(proto::EnumerateBatch {
                            pointer_events,
                            ..Default::default()
                        });
                    }
                    self.phase = EnumerationPhase::PinEvents;
                }
                EnumerationPhase::PinEvents => {
                    let pin_events = self
                        .pin_events
                        .by_ref()
                        .take(ENUMERATE_BATCH)
                        .map(event_ref_owned)
                        .collect::<Vec<_>>();
                    if !pin_events.is_empty() {
                        return Some(proto::EnumerateBatch {
                            pin_events,
                            ..Default::default()
                        });
                    }
                    self.phase = EnumerationPhase::Wanted;
                }
                EnumerationPhase::Wanted => {
                    let wanted = self
                        .wanted
                        .by_ref()
                        .take(ENUMERATE_BATCH)
                        .map(|cid| cid.as_bytes().to_vec())
                        .collect::<Vec<_>>();
                    if !wanted.is_empty() {
                        return Some(proto::EnumerateBatch {
                            wanted,
                            ..Default::default()
                        });
                    }
                    self.phase = EnumerationPhase::LiveRoots;
                }
                EnumerationPhase::LiveRoots => {
                    let live_roots = self
                        .live_roots
                        .by_ref()
                        .take(ENUMERATE_BATCH)
                        .map(|cid| cid.as_bytes().to_vec())
                        .collect::<Vec<_>>();
                    if !live_roots.is_empty() {
                        return Some(proto::EnumerateBatch {
                            live_roots,
                            ..Default::default()
                        });
                    }
                    self.phase = EnumerationPhase::IndexCandidates;
                }
                EnumerationPhase::IndexCandidates => {
                    let index_candidates = self
                        .index_candidates
                        .by_ref()
                        .take(ENUMERATE_BATCH)
                        .map(|cid| cid.as_bytes().to_vec())
                        .collect::<Vec<_>>();
                    if !index_candidates.is_empty() {
                        return Some(proto::EnumerateBatch {
                            index_candidates,
                            ..Default::default()
                        });
                    }
                    self.phase = EnumerationPhase::Terminal;
                }
                EnumerationPhase::Terminal => {
                    self.phase = EnumerationPhase::Done;
                    let (truncated, walked, walk_limit, remaining_frontier) = self
                        .truncation
                        .take()
                        .map(|truncation| {
                            (
                                true,
                                truncation.visited as u64,
                                truncation.limit as u64,
                                truncation.remaining_frontier as u64,
                            )
                        })
                        .unwrap_or((false, 0, 0, 0));
                    return Some(proto::EnumerateBatch {
                        terminal: true,
                        truncated,
                        walked,
                        walk_limit,
                        remaining_frontier,
                        snapshot_generation: std::mem::take(&mut self.snapshot_generation),
                        ..Default::default()
                    });
                }
                EnumerationPhase::Done => return None,
            }
        }
    }
}

async fn upload_frame_with_timeout<F>(
    future: F,
    deadline: tokio::time::Instant,
) -> Result<Option<proto::ChunkFrame>, Status>
where
    F: Future<Output = Result<Option<proto::ChunkFrame>, Status>>,
{
    let idle_deadline = tokio::time::Instant::now() + PUT_FRAME_IDLE_TIMEOUT;
    tokio::time::timeout_at(idle_deadline.min(deadline), future)
        .await
        .map_err(|_| Status::deadline_exceeded("chunk upload timed out"))?
}

#[tonic::async_trait]
impl Sync for SyncService {
    type EnumerateStream = BoxStream<proto::EnumerateBatch>;

    async fn negotiate(
        &self,
        request: Request<proto::ProtocolHello>,
    ) -> Result<Response<proto::ProtocolWelcome>, Status> {
        let hello = request.into_inner();
        if hello.protocol_major != crate::PROTOCOL_MAJOR {
            return Err(Status::failed_precondition(format!(
                "incompatible node protocol major {}; server requires {}",
                hello.protocol_major,
                crate::PROTOCOL_MAJOR
            )));
        }
        let capabilities = crate::protocol_capabilities();
        if let Some(missing) = hello
            .required_capabilities
            .iter()
            .find(|required| !capabilities.contains(required))
        {
            return Err(Status::failed_precondition(format!(
                "required node capability {missing:?} is unavailable"
            )));
        }
        Ok(Response::new(proto::ProtocolWelcome {
            protocol_major: crate::PROTOCOL_MAJOR,
            protocol_minor: crate::PROTOCOL_MINOR,
            capabilities,
        }))
    }

    async fn page_events(
        &self,
        request: Request<proto::EventPageRequest>,
    ) -> Result<Response<proto::EventPageResponse>, Status> {
        let req = request.into_inner();
        let page_size = if req.page_size == 0 {
            EVENT_PAGE_SIZE
        } else {
            usize::try_from(req.page_size).unwrap_or(usize::MAX)
        };
        if page_size == 0 || page_size > EVENT_PAGE_SIZE {
            return Err(Status::invalid_argument(format!(
                "event page size must be between 1 and {EVENT_PAGE_SIZE}"
            )));
        }
        let kind = req.kind;
        if kind != "pointer" && kind != "pin" {
            return Err(Status::invalid_argument(
                "event page kind must be pointer or pin",
            ));
        }
        let expected_generation = req.snapshot_generation;
        if !expected_generation.is_empty() && !valid_generation(&expected_generation) {
            return Err(Status::invalid_argument(
                "snapshot generation must be 16 lowercase hexadecimal characters",
            ));
        }
        let after = req.after.map(|cursor| (cursor.id, cursor.seq));
        if after.as_ref().is_some_and(|(id, _)| id.len() > 256) {
            return Err(Status::invalid_argument(
                "event cursor id must be at most 256 bytes",
            ));
        }
        if let Some((id, seq)) = &after {
            if *seq == 0 {
                return Err(Status::invalid_argument(
                    "event cursor sequence must be greater than zero",
                ));
            }
            let valid = if kind == "pointer" {
                dag_control::validate_pointer_id(id).map_err(|error| error.to_string())
            } else {
                dag_control::validate_pin_id(id).map_err(|error| error.to_string())
            };
            if let Err(error) = valid {
                return Err(Status::invalid_argument(format!(
                    "invalid event cursor id: {error}"
                )));
            }
        }

        let (
            events,
            related_cids,
            historical_targets,
            pointer_event_bytes_read,
            complete,
            generation,
        ) = on_control(&self.control, move |control| {
            let generation = control.sync_event_generation().map_err(refuse)?;
            if !expected_generation.is_empty() && expected_generation != generation {
                return Err(Status::aborted(
                    "source event generation changed; restart the snapshot",
                ));
            }
            let mut events = if kind == "pointer" {
                control
                    .pointer_log
                    .event_cids_page(
                        after.as_ref().map(|(id, seq)| (id.as_str(), *seq)),
                        page_size + 1,
                    )
                    .map_err(|error| refuse(error.into()))?
            } else {
                control
                    .pin_log
                    .event_cids_page(
                        after.as_ref().map(|(id, seq)| (id.as_str(), *seq)),
                        page_size + 1,
                    )
                    .map_err(|error| refuse(error.into()))?
            };
            let complete = events.len() <= page_size;
            if !complete {
                events.pop();
            }
            let targets: HashSet<Cid> = events.iter().map(|event| event.2.clone()).collect();
            let mut related_cids: Vec<Cid> = control
                .signature_log
                .covering(&targets)
                .map_err(refuse)?
                .into_iter()
                .collect();
            if related_cids.len() > MAX_RELATED_CIDS_PER_EVENT_PAGE {
                return Err(Status::resource_exhausted(
                    "event page has too many related signature chunks",
                ));
            }
            related_cids.sort_by_key(Cid::to_hex);
            let mut pointer_event_bytes_read = 0usize;
            let historical_targets = if kind == "pointer" {
                control
                    .pointer_log
                    .sync_target_hints(&events, &mut pointer_event_bytes_read)
                    .map_err(|error| refuse(error.into()))?
            } else {
                Vec::new()
            };
            let after_generation = control.sync_event_generation().map_err(refuse)?;
            if after_generation != generation {
                return Err(Status::aborted(
                    "source event generation changed while reading a page; restart the snapshot",
                ));
            }
            Ok((
                events,
                related_cids,
                historical_targets,
                pointer_event_bytes_read,
                complete,
                generation,
            ))
        })
        .await?;
        let next_after = if complete {
            None
        } else {
            events.last().map(|(id, seq, _)| proto::EventCursor {
                id: id.clone(),
                seq: *seq,
            })
        };
        Ok(Response::new(proto::EventPageResponse {
            events: events.into_iter().map(event_ref_owned).collect(),
            next_after,
            complete,
            snapshot_generation: generation,
            related_cids: related_cids
                .into_iter()
                .map(|cid| cid.as_bytes().to_vec())
                .collect(),
            historical_targets: historical_targets
                .into_iter()
                .map(|cid| cid.as_bytes().to_vec())
                .collect(),
            pointer_event_bytes_read: pointer_event_bytes_read as u64,
        }))
    }

    async fn begin_event_import(
        &self,
        request: Request<proto::BeginEventImportRequest>,
    ) -> Result<Response<proto::BeginEventImportResponse>, Status> {
        let transfer_id = request.into_inner().transfer_id;
        if !valid_transfer_id(&transfer_id) {
            return Err(Status::invalid_argument(
                "transfer_id must be 32 lowercase hexadecimal characters",
            ));
        }
        let mut sessions = self
            .import_sessions
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        clean_expired(&mut sessions);
        if !sessions.contains_key(&transfer_id) {
            admit_new_session(&mut sessions)?;
            sessions.insert(transfer_id.clone(), ImportSession::new());
        }
        let session = sessions.get_mut(&transfer_id).expect("inserted above");
        session.renew();
        Ok(Response::new(proto::BeginEventImportResponse {
            session_id: transfer_id,
            next_page_index: session.page_digests.len() as u64,
            expires_unix: session.expires_unix,
        }))
    }

    async fn stage_event_import(
        &self,
        request: Request<proto::StageEventImportRequest>,
    ) -> Result<Response<proto::StageEventImportResponse>, Status> {
        let req = request.into_inner();
        if !valid_transfer_id(&req.session_id) {
            return Err(Status::invalid_argument("invalid event import session id"));
        }
        let pointer_frame_len = req.pointer_events.len();
        let pin_frame_len = req.pin_events.len();
        let frame_len = pointer_frame_len + pin_frame_len;
        if frame_len == 0 || frame_len > EVENT_PAGE_SIZE {
            return Err(Status::invalid_argument(format!(
                "an import page must contain between 1 and {EVENT_PAGE_SIZE} refs"
            )));
        }
        let pointer_events = parse_event_refs(req.pointer_events)?;
        let pin_events = parse_event_refs(req.pin_events)?;
        let retained = event_bytes(&pointer_events)?
            .checked_add(event_bytes(&pin_events)?)
            .ok_or_else(|| Status::resource_exhausted("event import size overflow"))?;
        let digest = page_digest(&pointer_events, &pin_events);

        let mut sessions = self
            .import_sessions
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        clean_expired(&mut sessions);
        let global_bytes = sessions
            .values()
            .map(|session| session.retained_bytes)
            .sum::<usize>();
        let session = sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| Status::not_found("event import session is absent or expired"))?;
        if session.committing || session.result.is_some() {
            return Err(Status::failed_precondition(
                "event import session is no longer accepting pages",
            ));
        }
        let page_index = usize::try_from(req.page_index)
            .map_err(|_| Status::invalid_argument("page index does not fit this server"))?;
        if page_index < session.page_digests.len() {
            if session.page_digests[page_index] != digest {
                return Err(Status::already_exists(
                    "page index was already staged with different contents",
                ));
            }
            session.renew();
            return Ok(Response::new(proto::StageEventImportResponse {
                next_page_index: session.page_digests.len() as u64,
                pointer_events_staged: session.pointer_events_staged,
                pin_events_staged: session.pin_events_staged,
                expires_unix: session.expires_unix,
            }));
        }
        if page_index != session.page_digests.len() {
            return Err(Status::failed_precondition(format!(
                "expected event import page {}, got {page_index}",
                session.page_digests.len()
            )));
        }
        let refs = session
            .pointer_events
            .len()
            .saturating_add(session.pin_events.len())
            .saturating_add(frame_len);
        if refs > MAX_IMPORT_REFS
            || session.retained_bytes.saturating_add(retained) > MAX_IMPORT_BYTES
            || global_bytes.saturating_add(retained) > MAX_IMPORT_GLOBAL_BYTES
        {
            return Err(Status::resource_exhausted(
                "event import session exceeded its bounded staging quota",
            ));
        }
        session.page_digests.push(digest);
        session.pointer_events.extend(pointer_events);
        session.pin_events.extend(pin_events);
        session.pointer_events_staged = session
            .pointer_events_staged
            .saturating_add(pointer_frame_len as u64);
        session.pin_events_staged = session
            .pin_events_staged
            .saturating_add(pin_frame_len as u64);
        session.retained_bytes += retained;
        session.renew();
        Ok(Response::new(proto::StageEventImportResponse {
            next_page_index: session.page_digests.len() as u64,
            pointer_events_staged: session.pointer_events_staged,
            pin_events_staged: session.pin_events_staged,
            expires_unix: session.expires_unix,
        }))
    }

    async fn commit_event_import(
        &self,
        request: Request<proto::CommitEventImportRequest>,
    ) -> Result<Response<proto::CommitEventImportResponse>, Status> {
        let trigger_authority = if request
            .extensions()
            .get::<GrantedScopes>()
            .copied()
            .is_some_and(|scopes| scopes.grants(AuthScope::Trigger))
        {
            PointerTriggerAuthority::Granted
        } else {
            // Missing extensions fail closed. Normal requests always passed
            // through RequireToken, including loopback no-auth compatibility.
            PointerTriggerAuthority::Withheld
        };
        let req = request.into_inner();
        if req.publication_capability != crate::ATOMIC_SYNC_INDEX_CAPABILITY {
            return Err(Status::failed_precondition(format!(
                "CommitEventImport requires publication capability {:?}",
                crate::ATOMIC_SYNC_INDEX_CAPABILITY
            )));
        }
        if !valid_transfer_id(&req.session_id) || req.offer_digest.len() != 32 {
            return Err(Status::invalid_argument(
                "commit requires a valid session id and 32-byte offer digest",
            ));
        }
        let expected_digest: [u8; 32] = req
            .offer_digest
            .as_slice()
            .try_into()
            .expect("length checked");
        if req.index_candidates.len() > dag_control::sync::MAX_SYNC_INDEX_CANDIDATES {
            return Err(Status::resource_exhausted(format!(
                "sync publication has {} index candidates, above the {}-record limit",
                req.index_candidates.len(),
                dag_control::sync::MAX_SYNC_INDEX_CANDIDATES
            )));
        }
        let index_candidates: Vec<Cid> = req
            .index_candidates
            .iter()
            .map(|bytes| cid_from_wire(bytes))
            .collect::<Result<_, _>>()?;
        let (pointer_events, pin_events) = {
            let mut sessions = self
                .import_sessions
                .sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            clean_expired(&mut sessions);
            let session = sessions
                .get_mut(&req.session_id)
                .ok_or_else(|| Status::not_found("event import session is absent or expired"))?;
            if let Some(result) = &session.result {
                if session.final_digest == Some(expected_digest) {
                    return Ok(Response::new(result.clone()));
                }
                return Err(Status::failed_precondition(
                    "committed session was retried with a different offer",
                ));
            }
            if session.committing {
                return Err(Status::aborted(
                    "event import commit is already in progress; retry status",
                ));
            }
            if req.expected_pages != session.page_digests.len() as u64
                || req.expected_pointer_events != session.pointer_events_staged
                || req.expected_pin_events != session.pin_events_staged
                || event_offer_digest(
                    &session.pointer_events,
                    &session.pin_events,
                    &index_candidates,
                ) != expected_digest
            {
                return Err(Status::failed_precondition(
                    "event import commit marker does not match the staged offer",
                ));
            }
            session.committing = true;
            (
                std::mem::take(&mut session.pointer_events),
                std::mem::take(&mut session.pin_events),
            )
        };

        // Publication must outlive the request future. If the transport drops
        // after the marker was accepted, cancelling this handler must not
        // strand the session in `committing` after the redb transaction
        // actually published. The detached task records either an idempotent
        // receipt or restores the staged offer for a later retry.
        let publish_pointer_events = pointer_events.clone();
        let publish_pin_events = pin_events.clone();
        let publish_index_candidates = index_candidates;
        let control = self.control.clone();
        let import_sessions = self.import_sessions.clone();
        let session_id = req.session_id;
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let published = on_control(&control, move |control| {
                control
                    .publish_durable_sync_snapshot_with_candidates_and_trigger_authority(
                        &publish_pointer_events,
                        &publish_pin_events,
                        &publish_index_candidates,
                        trigger_authority,
                    )
                    .map_err(refuse)
            })
            .await;

            let result = {
                let mut sessions = import_sessions
                    .sessions
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let Some(session) = sessions.get_mut(&session_id) else {
                    let error = Status::aborted(
                        "event import session disappeared while publication completed",
                    );
                    let _ = finished_tx.send(Err(error));
                    return;
                };
                match published {
                    Ok((outcome, counts)) => {
                        let response = commit_response(outcome, counts);
                        session.committing = false;
                        session.retained_bytes = 0;
                        session.final_digest = Some(expected_digest);
                        session.result = Some(response.clone());
                        session.renew();
                        Ok(response)
                    }
                    Err(error) => {
                        session.pointer_events = pointer_events;
                        session.pin_events = pin_events;
                        session.committing = false;
                        session.renew();
                        Err(error)
                    }
                }
            };
            let _ = finished_tx.send(result);
        });

        let response = finished_rx.await.map_err(|_| {
            Status::internal("event import publication task ended without a receipt")
        })??;
        Ok(Response::new(response))
    }

    async fn event_import_status(
        &self,
        request: Request<proto::EventImportStatusRequest>,
    ) -> Result<Response<proto::EventImportStatusResponse>, Status> {
        let session_id = request.into_inner().session_id;
        if !valid_transfer_id(&session_id) {
            return Err(Status::invalid_argument("invalid event import session id"));
        }
        let mut sessions = self
            .import_sessions
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        clean_expired(&mut sessions);
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| Status::not_found("event import session is absent or expired"))?;
        Ok(Response::new(proto::EventImportStatusResponse {
            state: if session
                .result
                .as_ref()
                .is_some_and(|result| result.rejection.is_some())
            {
                "rejected"
            } else if session.result.is_some() {
                "committed"
            } else if session.committing {
                "committing"
            } else {
                "active"
            }
            .to_string(),
            next_page_index: session.page_digests.len() as u64,
            pointer_events_staged: session.pointer_events_staged,
            pin_events_staged: session.pin_events_staged,
            expires_unix: session.expires_unix,
            result: session.result.clone(),
        }))
    }

    async fn abort_event_import(
        &self,
        request: Request<proto::AbortEventImportRequest>,
    ) -> Result<Response<proto::AbortEventImportResponse>, Status> {
        let session_id = request.into_inner().session_id;
        if !valid_transfer_id(&session_id) {
            return Err(Status::invalid_argument("invalid event import session id"));
        }
        let mut sessions = self
            .import_sessions
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        clean_expired(&mut sessions);
        let aborted = match sessions.get(&session_id) {
            Some(session) if session.committing || session.result.is_some() => false,
            Some(_) => {
                sessions.remove(&session_id);
                true
            }
            None => false,
        };
        Ok(Response::new(proto::AbortEventImportResponse { aborted }))
    }

    async fn enumerate(
        &self,
        request: Request<proto::EnumerateRequest>,
    ) -> Result<Response<Self::EnumerateStream>, Status> {
        let req = request.into_inner();
        if req.source_node_id.len() > 256 {
            return Err(Status::invalid_argument(
                "source_node_id must be at most 256 bytes",
            ));
        }
        let opts = SyncOptions {
            dry_run: false,
            max_walk: if req.max_walk == 0 {
                SyncOptions::default().max_walk
            } else {
                usize::try_from(req.max_walk)
                    .unwrap_or(MAX_REMOTE_WALK)
                    .min(MAX_REMOTE_WALK)
            },
            source_node_id: if req.source_node_id.is_empty() {
                SyncOptions::default().source_node_id
            } else {
                req.source_node_id
            },
        };
        let expected_generation = req.snapshot_generation.clone();
        let omit_event_refs = req.omit_event_refs;
        if !expected_generation.is_empty() && !valid_generation(&expected_generation) {
            return Err(Status::invalid_argument(
                "snapshot generation must be 16 lowercase hexadecimal characters",
            ));
        }

        let permit = self
            .enumerate_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted(
                    "another graph enumeration is already in progress; retry later",
                )
            })?;

        let enumeration: SyncEnumeration = on_control(&self.control, move |control| {
            if !expected_generation.is_empty()
                && control.sync_event_generation().map_err(refuse)? != expected_generation
            {
                return Err(Status::aborted(
                    "source event generation changed; restart the snapshot",
                ));
            }
            let enumeration = if omit_event_refs {
                control.enumerate_content(&opts).map_err(refuse)?
            } else {
                control.enumerate(&opts).map_err(refuse)?
            };
            if !expected_generation.is_empty()
                && control.sync_event_generation().map_err(refuse)? != expected_generation
            {
                return Err(Status::aborted(
                    "source event generation changed during enumeration; restart the snapshot",
                ));
            }
            Ok(enumeration)
        })
        .await?;

        if enumeration.truncation.is_some() && !req.require_completeness_marker {
            return Err(Status::failed_precondition(
                "enumeration was truncated; this client cannot receive completeness metadata; upgrade the client",
            ));
        }

        // Convert only the next bounded message as the transport polls it.
        // The permit lives in the iterator and caps retained enumeration
        // snapshots across slow or concurrent clients.
        let mut batches = EnumerationBatches::new(enumeration, permit, req.snapshot_generation);
        let stream = tokio_stream::iter(std::iter::from_fn(move || batches.next_batch().map(Ok)));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn missing(
        &self,
        request: Request<proto::MissingRequest>,
    ) -> Result<Response<proto::MissingResponse>, Status> {
        let req = request.into_inner();
        if req.cids.len() > MISSING_BATCH {
            return Err(Status::invalid_argument(format!(
                "at most {} CIDs per call, got {}",
                MISSING_BATCH,
                req.cids.len()
            )));
        }
        let cids = req
            .cids
            .iter()
            .map(|b| cid_from_wire(b))
            .collect::<Result<Vec<_>, _>>()?;

        let missing = on_control(&self.control, move |control| {
            SyncDestination::missing(control, &cids).map_err(refuse)
        })
        .await?;

        Ok(Response::new(proto::MissingResponse {
            missing: missing.iter().map(|c| c.as_bytes().to_vec()).collect(),
        }))
    }

    async fn stat_chunks(
        &self,
        request: Request<proto::StatChunksRequest>,
    ) -> Result<Response<proto::StatChunksResponse>, Status> {
        let req = request.into_inner();
        if req.cids.len() > STAT_CHUNKS_BATCH {
            return Err(Status::invalid_argument(format!(
                "at most {} CIDs per call, got {}",
                STAT_CHUNKS_BATCH,
                req.cids.len()
            )));
        }
        let cids = req
            .cids
            .iter()
            .map(|b| cid_from_wire(b))
            .collect::<Result<Vec<_>, _>>()?;

        let stats = on_control(&self.control, move |control| {
            let mut out = Vec::new();
            for cid in &cids {
                // An absent or unreadable chunk is omitted, not an error: the
                // caller learns it is missing by its absence, exactly as a
                // dry run would report it.
                if let Ok(len) = control.chunk_len(cid) {
                    out.push(proto::stat_chunks_response::Stat {
                        cid: cid.as_bytes().to_vec(),
                        len: len as u64,
                    });
                }
            }
            Ok(out)
        })
        .await?;

        Ok(Response::new(proto::StatChunksResponse { stats }))
    }

    type GetChunkStream = BoxStream<proto::ChunkFrame>;

    async fn get_chunk(
        &self,
        request: Request<proto::GetChunkRequest>,
    ) -> Result<Response<Self::GetChunkStream>, Status> {
        let permit = self
            .get_chunk_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("too many concurrent chunk downloads; retry later")
            })?;
        let cid = cid_from_wire(&request.into_inner().cid)?;

        let (cid, bytes) = on_control(&self.control, move |control| {
            let bytes = control.fetch_chunk(&cid).map_err(|e| match e {
                // Absent is its own answer: the client classifies it as
                // collected-at-source history, not a transfer failure.
                dag_control::ControlError::Core(dag_core::CoreError::ChunkNotFound(_)) => {
                    Status::not_found(e.to_string())
                }
                other => refuse(other),
            })?;
            Ok((cid, bytes))
        })
        .await?;

        let total_len = bytes.len() as u64;
        let mut frames: Vec<proto::ChunkFrame> = Vec::new();
        if bytes.is_empty() {
            // A zero-length chunk still needs its header frame.
            frames.push(proto::ChunkFrame {
                cid: cid.as_bytes().to_vec(),
                total_len,
                data: Vec::new(),
            });
        }
        for (i, window) in bytes.chunks(CHUNK_FRAME_BYTES).enumerate() {
            frames.push(proto::ChunkFrame {
                cid: if i == 0 {
                    cid.as_bytes().to_vec()
                } else {
                    Vec::new()
                },
                total_len: if i == 0 { total_len } else { 0 },
                data: window.to_vec(),
            });
        }

        let mut frames = frames.into_iter();
        let stream = tokio_stream::iter(std::iter::from_fn(move || {
            // Keep admission until the response stream is consumed or
            // dropped, not merely until its backing Vec is constructed.
            let _permit = &permit;
            frames.next().map(Ok)
        }));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn put_chunk(
        &self,
        request: Request<Streaming<proto::ChunkFrame>>,
    ) -> Result<Response<proto::PutChunkResponse>, Status> {
        let _permit = self
            .put_chunk_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("too many concurrent chunk uploads; retry later")
            })?;
        let mut stream = request.into_inner();
        let deadline = tokio::time::Instant::now() + PUT_TOTAL_TIMEOUT;

        let first = upload_frame_with_timeout(stream.message(), deadline)
            .await?
            .ok_or_else(|| Status::invalid_argument("empty chunk stream"))?;
        let cid = cid_from_wire(&first.cid)?;
        let total_len = first.total_len as usize;

        // Refuse an over-limit chunk before buffering any of it — the wire
        // equivalent of the I2 size check at every other entry point.
        if total_len > MAX_CHUNK_SIZE {
            return Err(Status::invalid_argument(format!(
                "chunk of {} bytes exceeds the {} byte limit",
                total_len, MAX_CHUNK_SIZE
            )));
        }

        let budget = frame_budget(total_len);
        let mut frames = 1usize;
        let mut bytes: Vec<u8> = Vec::with_capacity(initial_capacity(total_len));
        bytes.extend_from_slice(&first.data);
        if bytes.len() > total_len {
            return Err(Status::invalid_argument(format!(
                "first chunk frame for {} exceeded its declared {} bytes",
                cid, total_len
            )));
        }
        while let Some(frame) = upload_frame_with_timeout(stream.message(), deadline).await? {
            frames += 1;
            if frames > budget {
                return Err(Status::invalid_argument(format!(
                    "chunk stream for {} used more than the {} frames a {} byte chunk is \
                     allowed; refusing to keep reassembling",
                    cid, budget, total_len
                )));
            }
            bytes.extend_from_slice(&frame.data);
            if bytes.len() > total_len {
                return Err(Status::invalid_argument(format!(
                    "chunk stream for {} exceeded its declared {} bytes",
                    cid, total_len
                )));
            }
        }
        if bytes.len() != total_len {
            return Err(Status::invalid_argument(format!(
                "chunk stream for {} ended at {} of {} declared bytes",
                cid,
                bytes.len(),
                total_len
            )));
        }

        let stored_len = bytes.len() as u64;
        let staging = self.staging.clone();
        let metrics = self.control.metrics.clone();
        tokio::time::timeout_at(
            deadline,
            on_blocking(move || {
                // The staging put re-hashes what actually arrived — receipt
                // verification happens here, in the destination, always. The
                // fsyncs are deferred to Flush; nothing can *name* this chunk
                // until settle() has run.
                let written = staging
                    .put_chunk(&bytes, None)
                    .map_err(|e| internal_storage_failure("stage chunk", e))?;
                if written != cid {
                    return Err(Status::failed_precondition(format!(
                        "chunk {} arrived as {}: content does not match its address",
                        cid, written
                    )));
                }
                metrics.sync_chunks_received_total.inc();
                metrics.sync_bytes_received_total.add(stored_len);
                Ok(())
            }),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("chunk upload timed out"))??;

        Ok(Response::new(proto::PutChunkResponse { stored_len }))
    }

    async fn probe_pointer_events(
        &self,
        request: Request<proto::ProbeEventsRequest>,
    ) -> Result<Response<proto::ProbeEventsResponse>, Status> {
        let events = probe_request(request.into_inner())?;
        let conflicts = on_control(&self.control, move |control| {
            SyncDestination::probe_pointer_events(control, &events)
                .map_err(refuse)?
                .ok_or_else(|| Status::unimplemented("pointer probes are unavailable"))
        })
        .await?;
        Ok(Response::new(probe_response(conflicts)))
    }

    async fn probe_pin_events(
        &self,
        request: Request<proto::ProbeEventsRequest>,
    ) -> Result<Response<proto::ProbeEventsResponse>, Status> {
        let events = probe_request(request.into_inner())?;
        let conflicts = on_control(&self.control, move |control| {
            SyncDestination::probe_pin_events(control, &events)
                .map_err(refuse)?
                .ok_or_else(|| Status::unimplemented("pin probes are unavailable"))
        })
        .await?;
        Ok(Response::new(probe_response(conflicts)))
    }

    async fn import_event_batch(
        &self,
        _request: Request<Streaming<proto::ImportEventBatchRequest>>,
    ) -> Result<Response<proto::ImportEventBatchResponse>, Status> {
        Err(Status::failed_precondition(
            "ImportEventBatch was removed in node protocol 3; use Begin/Stage/Commit so index candidates are digest-bound to atomic publication",
        ))
    }

    async fn import_pointer_event(
        &self,
        _request: Request<proto::ImportEventRequest>,
    ) -> Result<Response<proto::ImportEventResponse>, Status> {
        Err(Status::failed_precondition(
            "ImportPointerEvent was removed in node protocol 3; use Begin/Stage/Commit",
        ))
    }

    async fn import_pin_event(
        &self,
        _request: Request<proto::ImportEventRequest>,
    ) -> Result<Response<proto::ImportEventResponse>, Status> {
        Err(Status::failed_precondition(
            "ImportPinEvent was removed in node protocol 3; use Begin/Stage/Commit",
        ))
    }

    async fn flush(
        &self,
        _request: Request<proto::FlushRequest>,
    ) -> Result<Response<proto::FlushResponse>, Status> {
        let staging = self.staging.clone();
        let flushed = on_blocking(move || {
            staging
                .flush_pending_writes()
                .map(|pending| pending as u64)
                .map_err(|e| internal_storage_failure("flush staged chunks", e))
        })
        .await?;
        Ok(Response::new(proto::FlushResponse { flushed }))
    }

    async fn finalize(
        &self,
        _request: Request<proto::FinalizeRequest>,
    ) -> Result<Response<proto::FinalizeResponse>, Status> {
        Err(Status::failed_precondition(
            "Finalize was removed in node protocol 3; CommitEventImport is the sole atomic publication marker",
        ))
    }
}

fn event_ref_owned((id, seq, cid): (String, u64, Cid)) -> proto::EventRef {
    proto::EventRef {
        id,
        seq,
        event_cid: cid.as_bytes().to_vec(),
    }
}

fn commit_response(
    outcome: EventBatchOutcome,
    counts: RebuildCounts,
) -> proto::CommitEventImportResponse {
    match outcome {
        EventBatchOutcome::Applied {
            pointer_events,
            pin_events,
        } => proto::CommitEventImportResponse {
            pointer_events: pointer_events as u64,
            pin_events: pin_events as u64,
            rejection: None,
            pointers_rebuilt: counts.pointers_rebuilt,
            pins_rebuilt: counts.pins_rebuilt,
            signatures_indexed: counts.signatures_indexed,
            claims_indexed: counts.claims_indexed,
        },
        EventBatchOutcome::Rejected(rejection) => proto::CommitEventImportResponse {
            pointer_events: 0,
            pin_events: 0,
            rejection: Some(proto::EventBatchRejection {
                kind: rejection.kind,
                event: Some(proto::EventRef {
                    id: rejection.id,
                    seq: rejection.seq,
                    event_cid: rejection.cid.as_bytes().to_vec(),
                }),
                reason: rejection.reason,
                divergent: rejection.divergent,
            }),
            pointers_rebuilt: 0,
            pins_rebuilt: 0,
            signatures_indexed: 0,
            claims_indexed: 0,
        },
    }
}

fn probe_request(req: proto::ProbeEventsRequest) -> Result<Vec<(String, u64, Cid)>, Status> {
    if req.events.len() > PROBE_BATCH {
        return Err(Status::invalid_argument(format!(
            "at most {} events per probe, got {}",
            PROBE_BATCH,
            req.events.len()
        )));
    }
    req.events
        .into_iter()
        .map(|event| Ok((event.id, event.seq, cid_from_wire(&event.event_cid)?)))
        .collect()
}

fn parse_event_refs(events: Vec<proto::EventRef>) -> Result<Vec<(String, u64, Cid)>, Status> {
    events
        .into_iter()
        .map(|event| {
            if event.id.len() > 256 {
                return Err(Status::invalid_argument(
                    "event id must be at most 256 bytes",
                ));
            }
            Ok((event.id, event.seq, cid_from_wire(&event.event_cid)?))
        })
        .collect()
}

fn valid_generation(generation: &str) -> bool {
    generation.len() == 16
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn probe_response(conflicts: Vec<EventConflict>) -> proto::ProbeEventsResponse {
    proto::ProbeEventsResponse {
        conflicts: conflicts
            .into_iter()
            .map(|conflict| proto::EventConflict {
                offered: Some(proto::EventRef {
                    id: conflict.id,
                    seq: conflict.seq,
                    event_cid: conflict.offered.as_bytes().to_vec(),
                }),
                existing_cid: conflict.existing.as_bytes().to_vec(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_sync_failures_do_not_expose_private_paths() {
        let sentinel = "/private/sentinel/customer/control.redb";
        let control = refuse(dag_control::ControlError::Database(sentinel.into()));
        assert_eq!(control.code(), tonic::Code::Internal);
        assert!(!control.message().contains(sentinel));

        let storage = internal_storage_failure("test", sentinel);
        assert_eq!(storage.code(), tonic::Code::Internal);
        assert!(!storage.message().contains(sentinel));
    }

    /// The budget must be generous enough for any real sender and finite for
    /// every declared length, including the degenerate ones.
    #[test]
    fn the_frame_budget_is_finite_and_generous() {
        // Our own sender's shape, with room to spare.
        let full = MAX_CHUNK_SIZE;
        let ours = full.div_ceil(CHUNK_FRAME_BYTES);
        assert!(
            frame_budget(full) > ours * 8,
            "the budget must not crowd the sender we ship"
        );
        assert!(frame_budget(full) < 2_000, "but it must still be a bound");

        // A zero-length chunk is one header frame; two is already slack.
        assert_eq!(frame_budget(0), 2);
        assert_eq!(frame_budget(1), 3);
    }

    /// Reserving the declared length was the amplification: a header frame of
    /// a few dozen bytes reserved 4 MiB, per request.
    #[test]
    fn capacity_is_reserved_for_bytes_that_arrived_not_bytes_promised() {
        assert_eq!(initial_capacity(MAX_CHUNK_SIZE), CHUNK_FRAME_BYTES);
        assert_eq!(initial_capacity(0), 0);
        assert_eq!(initial_capacity(100), 100);
    }

    #[tokio::test]
    async fn an_idle_upload_frame_hits_its_absolute_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(5);
        let error = upload_frame_with_timeout(std::future::pending(), deadline)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    }

    #[test]
    fn enumeration_batches_are_lazy_and_hold_one_concurrency_permit() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let events = (0..ENUMERATE_BATCH + 1)
            .map(|seq| {
                (
                    "pointer".to_string(),
                    seq as u64,
                    Cid::compute(&seq.to_le_bytes()),
                )
            })
            .collect();
        let mut batches = EnumerationBatches::new(
            SyncEnumeration {
                pointer_events: events,
                ..Default::default()
            },
            permit,
            String::new(),
        );

        assert!(slots.clone().try_acquire_owned().is_err());
        assert_eq!(batches.next_batch().unwrap().pointer_events.len(), 4096);
        assert_eq!(batches.next_batch().unwrap().pointer_events.len(), 1);
        assert!(batches.next_batch().unwrap().terminal);
        assert!(batches.next_batch().is_none());
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(batches);
        assert!(slots.try_acquire_owned().is_ok());
    }

    #[test]
    fn stat_chunks_integrity_work_is_bounded_per_call() {
        assert_eq!(STAT_CHUNKS_BATCH, 16);
        let maximum_work = std::hint::black_box(STAT_CHUNKS_BATCH * MAX_CHUNK_SIZE);
        assert!(maximum_work <= 64 * 1024 * 1024);
    }

    #[test]
    fn expired_import_sessions_are_reclaimed_and_transfer_ids_are_strict() {
        let mut sessions = HashMap::new();
        let mut expired = ImportSession::new();
        expired.expires_at = std::time::Instant::now() - Duration::from_secs(1);
        sessions.insert("11111111111111111111111111111111".to_string(), expired);
        clean_expired(&mut sessions);
        assert!(sessions.is_empty());
        assert!(valid_transfer_id("00000000000000000000000000000000"));
        assert!(valid_transfer_id("abcdefabcdefabcdefabcdefabcdefab"));
        assert!(!valid_transfer_id("ABCDEFabcdefabcdefabcdefabcdefab"));
        assert!(!valid_transfer_id("short"));
    }

    #[test]
    fn completed_receipts_do_not_consume_live_session_admission() {
        let mut sessions = HashMap::new();
        for index in 0..MAX_IMPORT_SESSIONS {
            let mut completed = ImportSession::new();
            completed.result = Some(proto::CommitEventImportResponse::default());
            sessions.insert(format!("{index:032x}"), completed);
        }
        admit_new_session(&mut sessions).unwrap();

        for index in 0..MAX_IMPORT_SESSIONS {
            sessions.insert(format!("a{index:031x}"), ImportSession::new());
        }
        let error = admit_new_session(&mut sessions).unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn import_digest_binds_event_kind_order_and_position() {
        let cid = Cid::compute(b"event");
        let event = ("id".to_string(), 1, cid);
        let pointer = event_offer_digest(std::slice::from_ref(&event), &[], &[]);
        let pin = event_offer_digest(&[], std::slice::from_ref(&event), &[]);
        let later = event_offer_digest(&[(event.0.clone(), 2, event.2.clone())], &[], &[]);
        let candidate = event_offer_digest(&[], &[], std::slice::from_ref(&event.2));
        assert_ne!(pointer, pin);
        assert_ne!(pointer, later);
        assert_ne!(pointer, candidate);
    }
}
