//! The client side of the node protocol.

use dag_control::sync::{
    EventBatchOutcome, EventBatchRejection, EventConflict, RebuildCounts, SyncEnumeration,
    SyncTruncation, PROBE_BATCH,
};
use dag_core::{Cid, MAX_CHUNK_SIZE};
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

use crate::auth::{validate_token, AUTHORIZATION, BEARER};
use crate::error::NetError;
use crate::proto;
use crate::proto::events_client::EventsClient;
use crate::proto::node_client::NodeClient;
use crate::proto::pointers_client::PointersClient;
use crate::proto::sync_client::SyncClient;
use crate::sync_service::{frame_budget, initial_capacity, CHUNK_FRAME_BYTES};

/// A connection to another node.
///
/// Remote URLs use the `grpc://host:port` scheme — a deliberate mismatch
/// with filesystem paths so `dag sync --remote` can tell the two forms of
/// remote apart without guessing.
///
/// Cloning shares the underlying channel; it does not reconnect.
#[derive(Clone)]
pub struct RemoteNode {
    channel: Channel,
    token: AttachToken,
    /// The URL this connection was made from, for error reporting.
    pub url: String,
    negotiated: std::sync::Arc<tokio::sync::OnceCell<()>>,
}

/// One stable source-history page. Feed `next_after` and
/// `snapshot_generation` into the next call; `complete` ends this event kind.
#[derive(Debug, Clone)]
pub struct RemoteEventPage {
    pub events: Vec<(String, u64, Cid)>,
    pub next_after: Option<(String, u64)>,
    pub complete: bool,
    pub snapshot_generation: String,
    pub related_cids: Vec<Cid>,
    /// Direct targets named by readable pointer events. These are offered for
    /// transfer/reporting but are not required-live publication evidence.
    pub historical_targets: Vec<Cid>,
    /// Raw event-entry bytes the server charged before decoding target hints.
    pub pointer_event_bytes_read: usize,
}

/// Client-side interceptor that offers the bearer token on every call.
#[derive(Clone)]
pub(crate) struct AttachToken(Option<MetadataValue<tonic::metadata::Ascii>>);

impl Interceptor for AttachToken {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(value) = &self.0 {
            request.metadata_mut().insert(AUTHORIZATION, value.clone());
        }
        Ok(request)
    }
}

/// The URL scheme for a plaintext node connection.
pub const SCHEME: &str = "grpc://";

/// The URL scheme for a TLS node connection.
pub const TLS_SCHEME: &str = "grpcs://";

const UNARY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MUTATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const CHUNK_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn timed_request<T>(message: T, timeout: std::time::Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(timeout);
    request
}

/// Everything [`RemoteNode::connect_with`] can be told about a connection.
#[derive(Default)]
pub struct ConnectOptions {
    /// Bearer token offered on every call.
    pub token: Option<String>,
    /// PEM CA certificate to trust for a `grpcs://` connection — the file a
    /// self-signed node hands its peers. Without it, the platform's native
    /// roots decide, which is right for a publicly issued certificate.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Hostname to verify the server certificate against, when it differs
    /// from the host in the URL (connecting by IP to a cert naming a DNS
    /// name, say).
    pub tls_domain: Option<String>,
    /// Permit `grpc://` to a non-loopback host for remote development.
    ///
    /// A token does not imply this option: callers must explicitly accept
    /// that both the credential and request data will cross the network in
    /// plaintext.
    pub allow_insecure_transport: bool,
}

impl RemoteNode {
    /// Whether `remote` names a node URL rather than a filesystem path.
    pub fn is_remote_url(remote: &str) -> bool {
        remote.starts_with(SCHEME) || remote.starts_with(TLS_SCHEME)
    }

    /// Connect to `grpc://host:port`, eagerly — an unreachable node fails
    /// here, not on the first real call.
    pub async fn connect(url: &str, token: Option<&str>) -> Result<Self, NetError> {
        Self::connect_with(
            url,
            ConnectOptions {
                token: token.map(String::from),
                ..Default::default()
            },
        )
        .await
    }

    /// [`Self::connect`] with TLS options.
    pub async fn connect_with(url: &str, opts: ConnectOptions) -> Result<Self, NetError> {
        let (rest, tls) = if let Some(rest) = url.strip_prefix(TLS_SCHEME) {
            (rest, true)
        } else if let Some(rest) = url.strip_prefix(SCHEME) {
            (rest, false)
        } else {
            return Err(NetError::BadUrl {
                url: url.to_string(),
                reason: format!("expected a {SCHEME} or {TLS_SCHEME} host:port URL"),
            });
        };

        let token = match opts.token.as_deref() {
            Some(token) => {
                validate_token(token).map_err(|reason| NetError::BadUrl {
                    url: url.to_string(),
                    reason: reason.into(),
                })?;
                Some(
                    format!("{BEARER}{token}")
                        .parse()
                        .map_err(|_| NetError::BadUrl {
                            url: url.to_string(),
                            reason: "token contains characters that cannot travel in metadata"
                                .into(),
                        })?,
                )
            }
            None => None,
        };

        let http_scheme = if tls { "https" } else { "http" };
        let mut endpoint: Endpoint =
            format!("{http_scheme}://{rest}")
                .parse()
                .map_err(|e: tonic::transport::Error| NetError::BadUrl {
                    url: url.to_string(),
                    reason: e.to_string(),
                })?;

        if !tls && !is_loopback_host(endpoint.uri().host()) && !opts.allow_insecure_transport {
            return Err(NetError::InsecureTransportRefused {
                destination: url.to_string(),
            });
        }

        // A dead address on a filtered network otherwise waits out the full
        // TCP handshake timeout — minutes on some stacks. Ten seconds is
        // generous for any network worth replicating across. Deliberately no
        // per-call timeout: a chunk transfer or a followed event stream is
        // legitimately long-lived.
        endpoint = endpoint.connect_timeout(std::time::Duration::from_secs(10));

        if tls {
            let mut tls_config = tonic::transport::ClientTlsConfig::new().with_native_roots();
            if let Some(ca) = &opts.ca_cert_pem {
                tls_config = tls_config.ca_certificate(tonic::transport::Certificate::from_pem(ca));
            }
            if let Some(domain) = &opts.tls_domain {
                tls_config = tls_config.domain_name(domain);
            }
            endpoint = endpoint.tls_config(tls_config)?;
        } else if opts.ca_cert_pem.is_some() || opts.tls_domain.is_some() {
            return Err(NetError::BadUrl {
                url: url.to_string(),
                reason: format!("TLS options only apply to a {TLS_SCHEME} URL"),
            });
        }

        let channel = endpoint.connect().await?;

        Ok(Self {
            channel,
            token: AttachToken(token),
            url: url.to_string(),
            negotiated: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        })
    }

    fn node(&self) -> NodeClient<InterceptedService<Channel, AttachToken>> {
        NodeClient::with_interceptor(self.channel.clone(), self.token.clone())
    }

    /// The remote's version, schema and store shape.
    pub async fn info(&self) -> Result<proto::InfoResponse, NetError> {
        let response = self
            .node()
            .info(timed_request(proto::InfoRequest {}, UNARY_TIMEOUT))
            .await?;
        Ok(response.into_inner())
    }

    fn sync(&self) -> SyncClient<InterceptedService<Channel, AttachToken>> {
        SyncClient::with_interceptor(self.channel.clone(), self.token.clone())
    }

    /// Negotiate the replication contract before any enumeration or mutation.
    /// Results are shared by clones of this connection.
    pub async fn require_sync_protocol(&self) -> Result<(), NetError> {
        self.negotiated
            .get_or_try_init(|| async {
                let welcome = self
                    .sync()
                    .negotiate(timed_request(
                        proto::ProtocolHello {
                            protocol_major: crate::PROTOCOL_MAJOR,
                            protocol_minor: crate::PROTOCOL_MINOR,
                            required_capabilities: crate::protocol_capabilities(),
                        },
                        UNARY_TIMEOUT,
                    ))
                    .await
                    .map_err(|status| {
                        if status.code() == tonic::Code::Unimplemented {
                            NetError::Status(Status::failed_precondition(
                                "remote node does not support protocol-v3 negotiation; deploy upgraded servers before clients",
                            ))
                        } else {
                            status.into()
                        }
                    })?
                    .into_inner();
                validate_protocol(
                    welcome.protocol_major,
                    welcome.protocol_minor,
                    &welcome.capabilities,
                )
            })
            .await
            .map(|_| ())
    }

    /// Read a bounded page from a stable pointer or pin event generation.
    pub async fn page_events(
        &self,
        kind: &str,
        after: Option<(&str, u64)>,
        snapshot_generation: &str,
    ) -> Result<RemoteEventPage, NetError> {
        self.require_sync_protocol().await?;
        if kind != "pointer" && kind != "pin" {
            return Err(protocol("event page kind must be pointer or pin"));
        }
        let response = self
            .sync()
            .page_events(timed_request(
                proto::EventPageRequest {
                    kind: kind.to_string(),
                    page_size: PROBE_BATCH as u32,
                    after: after.map(|(id, seq)| proto::EventCursor {
                        id: id.to_string(),
                        seq,
                    }),
                    snapshot_generation: snapshot_generation.to_string(),
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner();
        if !valid_generation(&response.snapshot_generation)
            || (!snapshot_generation.is_empty()
                && response.snapshot_generation != snapshot_generation)
        {
            return Err(protocol(
                "remote event page changed or omitted its snapshot generation",
            ));
        }
        if response.events.len() > PROBE_BATCH {
            return Err(protocol("remote exceeded the negotiated event page size"));
        }
        if response.related_cids.len() > 65_536 {
            return Err(protocol("remote exceeded the related-CID page bound"));
        }
        if response.historical_targets.len() > response.events.len() {
            return Err(protocol(
                "remote returned more historical targets than event refs",
            ));
        }
        if kind == "pin"
            && (!response.historical_targets.is_empty() || response.pointer_event_bytes_read != 0)
        {
            return Err(protocol(
                "remote attached pointer-history hints to a pin page",
            ));
        }
        let pointer_event_bytes_read = usize::try_from(response.pointer_event_bytes_read)
            .map_err(|_| protocol("remote pointer-event byte count does not fit this platform"))?;
        if pointer_event_bytes_read > dag_control::sync::MAX_SYNC_POINTER_EVENT_READ_BYTES {
            return Err(protocol(
                "remote event page exceeded the pointer-event read budget",
            ));
        }
        let mut cursor = after.map(|(id, seq)| (id.to_string(), seq));
        let mut events = Vec::with_capacity(response.events.len());
        for event in response.events {
            if event.seq == 0 {
                return Err(protocol("remote event page contained sequence zero"));
            }
            if kind == "pointer" {
                dag_control::validate_pointer_id(&event.id).map_err(|error| {
                    protocol(format!(
                        "remote event page contained an invalid pointer ID: {error}"
                    ))
                })?;
            } else {
                dag_control::validate_pin_id(&event.id).map_err(|error| {
                    protocol(format!(
                        "remote event page contained an invalid pin ID: {error}"
                    ))
                })?;
            }
            let next = (event.id, event.seq, cid_from_remote(&event.event_cid)?);
            if cursor.as_ref().is_some_and(|previous| {
                event_cursor_key(&next.0, next.1) <= event_cursor_key(&previous.0, previous.1)
            }) {
                return Err(protocol("remote event page was not strictly ordered"));
            }
            cursor = Some((next.0.clone(), next.1));
            events.push(next);
        }
        let next_after = response.next_after.map(|next| (next.id, next.seq));
        let expected_next = events.last().map(|event| (event.0.clone(), event.1));
        if response.complete {
            if next_after.is_some() {
                return Err(protocol(
                    "complete event page carried a continuation cursor",
                ));
            }
        } else if events.is_empty() || next_after != expected_next {
            return Err(protocol(
                "incomplete event page omitted or mismatched its continuation cursor",
            ));
        }
        Ok(RemoteEventPage {
            events,
            next_after,
            complete: response.complete,
            snapshot_generation: response.snapshot_generation,
            related_cids: response
                .related_cids
                .iter()
                .map(|cid| cid_from_remote(cid))
                .collect::<Result<_, _>>()?,
            historical_targets: response
                .historical_targets
                .iter()
                .map(|cid| cid_from_remote(cid))
                .collect::<Result<_, _>>()?,
            pointer_event_bytes_read,
        })
    }

    /// Everything the remote offers: event mappings and wanted chunk CIDs,
    /// collected across the server's bounded batches.
    ///
    /// The accumulator is held to a fixed byte ceiling. It used to grow
    /// for as long as the remote kept sending, so a hostile source could fill
    /// the puller's heap from a machine holding nothing at all — measured at
    /// 137 MiB/s. The cap is on bytes rather than entries because bytes are
    /// the resource, and because only `wanted` is bounded by `max_walk`: the
    /// event lists are as long as the source's logs, so holding them to the
    /// walk would refuse an honest peer with a lot of history.
    pub async fn enumerate(&self, max_walk: usize) -> Result<SyncEnumeration, NetError> {
        self.enumerate_for(max_walk, "local").await
    }

    /// Enumerate using `source_node_id` to select applicable local pin roots.
    pub async fn enumerate_for(
        &self,
        max_walk: usize,
        source_node_id: &str,
    ) -> Result<SyncEnumeration, NetError> {
        self.require_sync_protocol().await?;
        let first_pointer = self.page_events("pointer", None, "").await?;
        let generation = first_pointer.snapshot_generation.clone();
        let mut enumeration = self
            .enumerate_content_for_generation(max_walk, source_node_id, &generation)
            .await?;
        let content_bytes = enumeration
            .wanted
            .len()
            .checked_add(enumeration.live_roots.len())
            .and_then(|count| count.checked_add(enumeration.index_candidates.len()))
            .and_then(|count| count.checked_mul(32))
            .ok_or_else(|| protocol("remote content snapshot size overflowed"))?;
        let mut held = content_bytes.saturating_add(
            first_pointer
                .events
                .iter()
                .map(event_ref_bytes)
                .sum::<usize>()
                .saturating_add(first_pointer.related_cids.len() * 32)
                .saturating_add(first_pointer.historical_targets.len() * 32),
        );
        if held > MAX_ENUMERATION_BYTES {
            return Err(protocol("remote snapshot exceeded its memory bound"));
        }
        let mut event_refs = first_pointer.events.len();
        let mut pointer_event_bytes_read = first_pointer.pointer_event_bytes_read;
        if pointer_event_bytes_read > dag_control::sync::MAX_SYNC_POINTER_EVENT_READ_BYTES {
            return Err(protocol(
                "remote snapshot exceeded the pointer-event read budget",
            ));
        }
        if event_refs > MAX_ENUMERATION_EVENT_REFS {
            return Err(protocol("remote event snapshot exceeded its ref bound"));
        }
        add_event_page_cids(&mut enumeration, &first_pointer);
        enumeration.pointer_events = first_pointer.events;

        let mut cursor = first_pointer.next_after;
        while let Some((id, seq)) = cursor {
            let page = self
                .page_events("pointer", Some((&id, seq)), &generation)
                .await?;
            held = held
                .checked_add(
                    page.events.iter().map(event_ref_bytes).sum::<usize>()
                        + page.related_cids.len() * 32
                        + page.historical_targets.len() * 32,
                )
                .ok_or_else(|| protocol("remote event snapshot size overflowed"))?;
            pointer_event_bytes_read = pointer_event_bytes_read
                .checked_add(page.pointer_event_bytes_read)
                .ok_or_else(|| protocol("remote pointer-event byte count overflowed"))?;
            event_refs = event_refs
                .checked_add(page.events.len())
                .ok_or_else(|| protocol("remote event snapshot ref count overflowed"))?;
            if held > MAX_ENUMERATION_BYTES {
                return Err(protocol("remote event snapshot exceeded its memory bound"));
            }
            if event_refs > MAX_ENUMERATION_EVENT_REFS {
                return Err(protocol("remote event snapshot exceeded its ref bound"));
            }
            if pointer_event_bytes_read > dag_control::sync::MAX_SYNC_POINTER_EVENT_READ_BYTES {
                return Err(protocol(
                    "remote snapshot exceeded the pointer-event read budget",
                ));
            }
            add_event_page_cids(&mut enumeration, &page);
            enumeration.pointer_events.extend(page.events);
            cursor = page.next_after;
        }

        let mut cursor: Option<(String, u64)> = None;
        loop {
            let page = self
                .page_events(
                    "pin",
                    cursor.as_ref().map(|(id, seq)| (id.as_str(), *seq)),
                    &generation,
                )
                .await?;
            held = held
                .checked_add(
                    page.events.iter().map(event_ref_bytes).sum::<usize>()
                        + page.related_cids.len() * 32,
                )
                .ok_or_else(|| protocol("remote event snapshot size overflowed"))?;
            event_refs = event_refs
                .checked_add(page.events.len())
                .ok_or_else(|| protocol("remote event snapshot ref count overflowed"))?;
            if held > MAX_ENUMERATION_BYTES {
                return Err(protocol("remote event snapshot exceeded its memory bound"));
            }
            if event_refs > MAX_ENUMERATION_EVENT_REFS {
                return Err(protocol("remote event snapshot exceeded its ref bound"));
            }
            add_event_page_cids(&mut enumeration, &page);
            enumeration.pin_events.extend(page.events);
            if page.complete {
                break;
            }
            cursor = page.next_after;
        }
        let mut candidate_seen = std::collections::HashSet::new();
        enumeration
            .index_candidates
            .retain(|cid| candidate_seen.insert(cid.clone()));
        if enumeration.index_candidates.len() > dag_control::sync::MAX_SYNC_INDEX_CANDIDATES {
            return Err(protocol(format!(
                "remote snapshot contains {} distinct index candidates; publication limit is {}",
                enumeration.index_candidates.len(),
                dag_control::sync::MAX_SYNC_INDEX_CANDIDATES
            )));
        }
        Ok(enumeration)
    }

    /// Enumerate graph/content metadata while event refs travel separately in
    /// stable pages bound to `snapshot_generation`.
    pub async fn enumerate_content_for_generation(
        &self,
        max_walk: usize,
        source_node_id: &str,
        snapshot_generation: &str,
    ) -> Result<SyncEnumeration, NetError> {
        self.require_sync_protocol().await?;
        if snapshot_generation.is_empty() {
            return Err(protocol("snapshot generation must not be empty"));
        }
        self.enumerate_snapshot(max_walk, source_node_id, snapshot_generation, true)
            .await
    }

    async fn enumerate_snapshot(
        &self,
        max_walk: usize,
        source_node_id: &str,
        snapshot_generation: &str,
        omit_event_refs: bool,
    ) -> Result<SyncEnumeration, NetError> {
        let mut stream = self
            .sync()
            .enumerate(proto::EnumerateRequest {
                max_walk: max_walk as u64,
                source_node_id: source_node_id.to_string(),
                require_completeness_marker: true,
                snapshot_generation: snapshot_generation.to_string(),
                omit_event_refs,
            })
            .await?
            .into_inner();

        let mut out = SyncEnumeration::default();
        let mut held = 0usize;
        let mut terminal = false;
        while let Some(batch) = next_message(&mut stream, "an enumeration").await? {
            if terminal {
                return Err(protocol(
                    "remote sent data after enumeration terminal batch",
                ));
            }
            held += batch_bytes(&batch);
            if held > MAX_ENUMERATION_BYTES {
                return Err(protocol(format!(
                    "remote's enumeration passed {} bytes without ending; refusing to keep \
                     buffering it",
                    MAX_ENUMERATION_BYTES
                )));
            }
            if batch.terminal {
                if !batch.pointer_events.is_empty()
                    || !batch.pin_events.is_empty()
                    || !batch.wanted.is_empty()
                    || !batch.live_roots.is_empty()
                    || !batch.index_candidates.is_empty()
                {
                    return Err(protocol(
                        "remote mixed enumeration data into its terminal batch",
                    ));
                }
                if batch.truncated {
                    let visited = usize::try_from(batch.walked)
                        .map_err(|_| protocol("remote walk count does not fit this platform"))?;
                    let limit = usize::try_from(batch.walk_limit)
                        .map_err(|_| protocol("remote walk limit does not fit this platform"))?;
                    let remaining_frontier =
                        usize::try_from(batch.remaining_frontier).map_err(|_| {
                            protocol("remote frontier count does not fit this platform")
                        })?;
                    if limit == 0 || visited > limit || remaining_frontier == 0 {
                        return Err(protocol("remote sent invalid truncation metadata"));
                    }
                    out.truncation = Some(SyncTruncation {
                        visited,
                        limit,
                        remaining_frontier,
                    });
                } else if batch.walked != 0
                    || batch.walk_limit != 0
                    || batch.remaining_frontier != 0
                {
                    return Err(protocol(
                        "remote sent walk metadata without declaring truncation",
                    ));
                }
                if batch.snapshot_generation != snapshot_generation {
                    return Err(protocol(
                        "remote enumeration terminal used a different snapshot generation",
                    ));
                }
                terminal = true;
                continue;
            }
            if batch.truncated
                || batch.walked != 0
                || batch.walk_limit != 0
                || batch.remaining_frontier != 0
                || !batch.snapshot_generation.is_empty()
            {
                return Err(protocol(
                    "remote sent truncation metadata before terminal batch",
                ));
            }
            for e in batch.pointer_events {
                out.pointer_events
                    .push((e.id, e.seq, cid_from_remote(&e.event_cid)?));
            }
            for e in batch.pin_events {
                out.pin_events
                    .push((e.id, e.seq, cid_from_remote(&e.event_cid)?));
            }
            for c in batch.wanted {
                out.wanted.push(cid_from_remote(&c)?);
            }
            for c in batch.live_roots {
                out.live_roots.push(cid_from_remote(&c)?);
            }
            for c in batch.index_candidates {
                out.index_candidates.push(cid_from_remote(&c)?);
                if out.index_candidates.len() > dag_control::sync::MAX_SYNC_INDEX_CANDIDATES {
                    return Err(protocol(format!(
                        "remote enumeration exceeded the {}-record index-candidate limit",
                        dag_control::sync::MAX_SYNC_INDEX_CANDIDATES
                    )));
                }
            }
        }
        if !terminal {
            return Err(protocol(
                "remote enumeration ended without a terminal completeness marker",
            ));
        }
        Ok(out)
    }

    /// The subset of `cids` the remote lacks.
    pub async fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>, NetError> {
        self.require_sync_protocol().await?;
        let response = self
            .sync()
            .missing(timed_request(
                proto::MissingRequest {
                    cids: cids.iter().map(|c| c.as_bytes().to_vec()).collect(),
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner();
        response
            .missing
            .iter()
            .map(|b| cid_from_remote(b))
            .collect()
    }

    /// One chunk's size on the remote, or `None` if it lacks the chunk.
    pub async fn chunk_len(&self, cid: &Cid) -> Result<Option<u64>, NetError> {
        self.require_sync_protocol().await?;
        let response = self
            .sync()
            .stat_chunks(timed_request(
                proto::StatChunksRequest {
                    cids: vec![cid.as_bytes().to_vec()],
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner();
        Ok(response.stats.first().map(|s| s.len))
    }

    /// One chunk's bytes from the remote.
    ///
    /// The frames are reassembled and length-checked here; *content*
    /// verification stays with whichever store the bytes are written to,
    /// which re-hashes on receipt.
    pub async fn fetch_chunk(&self, cid: &Cid) -> Result<Vec<u8>, NetError> {
        self.require_sync_protocol().await?;
        let mut stream = self
            .sync()
            .get_chunk(timed_request(
                proto::GetChunkRequest {
                    cid: cid.as_bytes().to_vec(),
                },
                CHUNK_CALL_TIMEOUT,
            ))
            .await?
            .into_inner();

        let first = next_frame(&mut stream)
            .await?
            .ok_or_else(|| protocol("empty chunk stream"))?;
        let total_len = first.total_len as usize;
        if total_len > MAX_CHUNK_SIZE {
            return Err(protocol(format!(
                "remote declared a {} byte chunk, over the {} limit",
                total_len, MAX_CHUNK_SIZE
            )));
        }

        let budget = frame_budget(total_len);
        let mut frames = 1usize;
        let mut bytes = Vec::with_capacity(initial_capacity(total_len));
        bytes.extend_from_slice(&first.data);
        while let Some(frame) = next_frame(&mut stream).await? {
            frames += 1;
            if frames > budget {
                return Err(protocol(format!(
                    "remote used more than the {} frames a {} byte chunk is allowed for {}",
                    budget, total_len, cid
                )));
            }
            bytes.extend_from_slice(&frame.data);
            if bytes.len() > total_len {
                return Err(protocol(format!(
                    "chunk stream for {} exceeded its declared {} bytes",
                    cid, total_len
                )));
            }
        }
        if bytes.len() != total_len {
            return Err(protocol(format!(
                "chunk stream for {} ended at {} of {} declared bytes",
                cid,
                bytes.len(),
                total_len
            )));
        }
        Ok(bytes)
    }

    /// Send one chunk to the remote, which re-hashes and refuses a mismatch.
    pub async fn put_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<(), NetError> {
        self.require_sync_protocol().await?;
        let total_len = bytes.len() as u64;
        let cid_bytes = cid.as_bytes().to_vec();

        let mut frames: Vec<proto::ChunkFrame> = Vec::new();
        if bytes.is_empty() {
            frames.push(proto::ChunkFrame {
                cid: cid_bytes.clone(),
                total_len,
                data: Vec::new(),
            });
        }
        for (i, window) in bytes.chunks(CHUNK_FRAME_BYTES).enumerate() {
            frames.push(proto::ChunkFrame {
                cid: if i == 0 {
                    cid_bytes.clone()
                } else {
                    Vec::new()
                },
                total_len: if i == 0 { total_len } else { 0 },
                data: window.to_vec(),
            });
        }

        self.sync()
            .put_chunk(timed_request(
                tokio_stream::iter(frames),
                CHUNK_CALL_TIMEOUT,
            ))
            .await?;
        Ok(())
    }

    /// Atomically offer complete pointer and pin event histories. Bounded,
    /// idempotent pages resume under a digest-derived session ID; the server
    /// publishes nothing until it validates the final marker.
    pub async fn import_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<EventBatchOutcome, NetError> {
        self.publish_event_batch(pointer_events, pin_events, &[])
            .await
            .map(|(outcome, _counts)| outcome)
    }

    /// Atomically publish a complete event offer and the bounded immutable
    /// records that need derived signature/effect lookup rows.
    pub async fn publish_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        index_candidates: &[Cid],
    ) -> Result<(EventBatchOutcome, RebuildCounts), NetError> {
        self.require_sync_protocol().await?;
        if index_candidates.len() > dag_control::sync::MAX_SYNC_INDEX_CANDIDATES {
            return Err(protocol(format!(
                "sync publication has {} index candidates, above the {}-record limit",
                index_candidates.len(),
                dag_control::sync::MAX_SYNC_INDEX_CANDIDATES
            )));
        }
        let offer_digest = event_offer_digest(pointer_events, pin_events, index_candidates);
        let transfer_id = transfer_id_for_offer(&offer_digest);
        let begin = self.begin_event_session(&transfer_id).await?;
        let pointer_pages = pointer_events.len().div_ceil(PROBE_BATCH) as u64;
        let pin_pages = pin_events.len().div_ceil(PROBE_BATCH) as u64;
        let expected_pages = pointer_pages
            .checked_add(pin_pages)
            .ok_or_else(|| protocol("event import page count overflowed"))?;
        if begin.session_id != transfer_id || begin.next_page_index > expected_pages {
            return Err(protocol(
                "remote returned an invalid resumable import session",
            ));
        }
        let resume_page = begin.next_page_index;
        if resume_page > 0 {
            let status = self.event_import_status(&transfer_id).await?;
            let pointer_page_count = resume_page.min(pointer_pages) as usize;
            let pin_page_count = resume_page.saturating_sub(pointer_pages) as usize;
            let expected_staged_pointers = pointer_page_count
                .saturating_mul(PROBE_BATCH)
                .min(pointer_events.len()) as u64;
            let expected_staged_pins = pin_page_count
                .saturating_mul(PROBE_BATCH)
                .min(pin_events.len()) as u64;
            if status.next_page_index != resume_page
                || status.pointer_events_staged != expected_staged_pointers
                || status.pin_events_staged != expected_staged_pins
            {
                return Err(protocol(
                    "remote resumable session receipt does not match this offer layout",
                ));
            }
            match status.state.as_str() {
                "committed" | "rejected" => {
                    let response = status.result.ok_or_else(|| {
                        protocol("remote completed session omitted its final receipt")
                    })?;
                    // A later high-level invocation observed an earlier
                    // commit. Nothing was newly filed by this run; an in-call
                    // lost-response retry still receives the original counts.
                    return parse_commit_publication(response, true);
                }
                "active" | "committing" if status.result.is_none() => {}
                _ => return Err(protocol("remote returned an invalid import session state")),
            }
        }

        let mut page_index = 0u64;
        let mut staged_pointers = 0u64;
        let mut staged_pins = 0u64;
        for events in pointer_events.chunks(PROBE_BATCH) {
            if page_index >= resume_page {
                let response = self
                    .stage_event_page(&transfer_id, page_index, events, &[])
                    .await?;
                validate_stage_receipt(
                    &response,
                    page_index + 1,
                    staged_pointers + events.len() as u64,
                    staged_pins,
                )?;
            }
            page_index += 1;
            staged_pointers += events.len() as u64;
        }
        for events in pin_events.chunks(PROBE_BATCH) {
            if page_index >= resume_page {
                let response = self
                    .stage_event_page(&transfer_id, page_index, &[], events)
                    .await?;
                validate_stage_receipt(
                    &response,
                    page_index + 1,
                    staged_pointers,
                    staged_pins + events.len() as u64,
                )?;
            }
            page_index += 1;
            staged_pins += events.len() as u64;
        }

        let response = self
            .commit_event_session(proto::CommitEventImportRequest {
                session_id: transfer_id,
                expected_pages,
                expected_pointer_events: pointer_events.len() as u64,
                expected_pin_events: pin_events.len() as u64,
                offer_digest: offer_digest.to_vec(),
                index_candidates: index_candidates
                    .iter()
                    .map(|cid| cid.as_bytes().to_vec())
                    .collect(),
                publication_capability: crate::ATOMIC_SYNC_INDEX_CAPABILITY.to_string(),
            })
            .await?;
        parse_commit_publication(response, false)
    }

    async fn stage_event_page(
        &self,
        session_id: &str,
        page_index: u64,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<proto::StageEventImportResponse, NetError> {
        let request = proto::StageEventImportRequest {
            session_id: session_id.to_string(),
            page_index,
            pointer_events: pointer_events.iter().map(event_ref).collect(),
            pin_events: pin_events.iter().map(event_ref).collect(),
        };
        let mut attempt = 0u8;
        loop {
            attempt += 1;
            match self
                .sync()
                .stage_event_import(timed_request(request.clone(), MUTATION_TIMEOUT))
                .await
            {
                Ok(response) => return Ok(response.into_inner()),
                Err(status) if attempt < 3 && retryable_status(&status) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25 * u64::from(attempt)))
                        .await;
                }
                Err(status) => return Err(status.into()),
            }
        }
    }

    async fn begin_event_session(
        &self,
        transfer_id: &str,
    ) -> Result<proto::BeginEventImportResponse, NetError> {
        let request = proto::BeginEventImportRequest {
            transfer_id: transfer_id.to_string(),
        };
        let mut attempt = 0u8;
        loop {
            attempt += 1;
            match self
                .sync()
                .begin_event_import(timed_request(request.clone(), MUTATION_TIMEOUT))
                .await
            {
                Ok(response) => return Ok(response.into_inner()),
                Err(status) if attempt < 3 && retryable_status(&status) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25 * u64::from(attempt)))
                        .await;
                }
                Err(status) => return Err(status.into()),
            }
        }
    }

    async fn commit_event_session(
        &self,
        request: proto::CommitEventImportRequest,
    ) -> Result<proto::CommitEventImportResponse, NetError> {
        let mut attempt = 0u8;
        loop {
            attempt += 1;
            match self
                .sync()
                .commit_event_import(timed_request(request.clone(), MUTATION_TIMEOUT))
                .await
            {
                Ok(response) => return Ok(response.into_inner()),
                Err(status) if attempt < 3 && retryable_status(&status) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25 * u64::from(attempt)))
                        .await;
                }
                Err(status) => return Err(status.into()),
            }
        }
    }

    /// Inspect a resumable event-import session. Absent or expired sessions
    /// return `NotFound`; committed receipts remain available until expiry.
    pub async fn event_import_status(
        &self,
        session_id: &str,
    ) -> Result<proto::EventImportStatusResponse, NetError> {
        self.require_sync_protocol().await?;
        Ok(self
            .sync()
            .event_import_status(timed_request(
                proto::EventImportStatusRequest {
                    session_id: session_id.to_string(),
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner())
    }

    /// Explicitly discard an uncommitted import. Repeating abort is safe and
    /// returns false after the first successful removal.
    pub async fn abort_event_import(&self, session_id: &str) -> Result<bool, NetError> {
        self.require_sync_protocol().await?;
        Ok(self
            .sync()
            .abort_event_import(timed_request(
                proto::AbortEventImportRequest {
                    session_id: session_id.to_string(),
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner()
            .aborted)
    }

    fn pointers(&self) -> PointersClient<InterceptedService<Channel, AttachToken>> {
        PointersClient::with_interceptor(self.channel.clone(), self.token.clone())
    }

    fn events(&self) -> EventsClient<InterceptedService<Channel, AttachToken>> {
        EventsClient::with_interceptor(self.channel.clone(), self.token.clone())
    }

    /// Subscribe to the remote's event stream.
    ///
    /// With `replay`, journal history at or after `since_seq` arrives first
    /// (at most `limit` events counting back from the newest; 0 selects the
    /// server's finite [`crate::MAX_REMOTE_EVENT_REPLAY_EVENTS`] ceiling and
    /// ends with a non-OK status if that ceiling omitted older matches);
    /// the live tail follows unless `no_follow` ends the stream at the end
    /// of the replay. `types` filters by event kind (`pointer`, `pin`,
    /// `job`, `storage`); empty means everything. Each envelope's `json` is
    /// exactly the line the local `dag events tail` would print.
    pub async fn subscribe_events(
        &self,
        replay: bool,
        since_seq: u64,
        limit: u64,
        types: &[String],
        no_follow: bool,
    ) -> Result<tonic::Streaming<proto::EventEnvelope>, NetError> {
        let response = self
            .events()
            .subscribe(proto::SubscribeRequest {
                replay,
                since_seq,
                types: types.to_vec(),
                no_follow,
                limit,
            })
            .await?;
        Ok(response.into_inner())
    }

    /// Resolve a pointer on the remote to `(cid, head_seq)`.
    pub async fn resolve_pointer(&self, id: &str) -> Result<(Cid, u64), NetError> {
        let response = self
            .pointers()
            .resolve(timed_request(
                proto::ResolveRequest { id: id.to_string() },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner();
        Ok((cid_from_remote(&response.cid)?, response.seq))
    }

    /// Every pointer id the remote holds.
    pub async fn list_pointers(&self) -> Result<Vec<String>, NetError> {
        const PAGE_SIZE: u32 = 1_000;
        const MAX_IDS: usize = 100_000;
        const MAX_BYTES: usize = 16 * 1024 * 1024;
        const MAX_PAGES: usize = MAX_IDS / PAGE_SIZE as usize;
        let mut ids = Vec::new();
        let mut after_id = String::new();
        let mut retained_bytes = 0usize;
        let mut pages = 0usize;
        loop {
            if pages >= MAX_PAGES {
                return Err(protocol(format!(
                    "remote pointer listing exceeded {MAX_PAGES} pages"
                )));
            }
            pages += 1;
            let response = self
                .pointers()
                .list(timed_request(
                    proto::ListPointersRequest {
                        page_size: PAGE_SIZE,
                        after_id: after_id.clone(),
                    },
                    UNARY_TIMEOUT,
                ))
                .await?
                .into_inner();

            if response.ids.len() > PAGE_SIZE as usize {
                return Err(protocol(format!(
                    "remote returned {} pointer IDs in a page capped at {PAGE_SIZE}",
                    response.ids.len()
                )));
            }
            for id in &response.ids {
                dag_control::validate_pointer_id(id)
                    .map_err(|e| protocol(format!("remote returned an invalid pointer ID: {e}")))?;
                if id <= &after_id {
                    return Err(protocol("remote pointer page was not strictly ordered"));
                }
                retained_bytes = retained_bytes
                    .checked_add(id.len())
                    .ok_or_else(|| protocol("remote pointer listing byte count overflowed"))?;
                if ids.len() + response.ids.len() > MAX_IDS || retained_bytes > MAX_BYTES {
                    return Err(protocol(format!(
                        "remote pointer listing exceeded {MAX_IDS} IDs or {MAX_BYTES} bytes"
                    )));
                }
                after_id = id.clone();
            }

            if !response.next_after_id.is_empty()
                && response.ids.last() != Some(&response.next_after_id)
            {
                return Err(protocol(
                    "remote pointer pagination cursor did not match the last returned ID",
                ));
            }
            ids.extend(response.ids);
            if response.next_after_id.is_empty() {
                return Ok(ids);
            }
            after_id = response.next_after_id;
        }
    }

    /// Compare-and-set update on the remote: apply only if its head is
    /// exactly `expect_seq` (0 = create). A stale expectation comes back as
    /// `FailedPrecondition` naming the actual head. Returns the new head
    /// sequence.
    pub async fn update_pointer(
        &self,
        id: &str,
        new_cid: &Cid,
        expect_seq: u64,
    ) -> Result<u64, NetError> {
        let response = self
            .pointers()
            .update(timed_request(
                proto::UpdatePointerRequest {
                    id: id.to_string(),
                    new_cid: new_cid.as_bytes().to_vec(),
                    expect_seq,
                },
                MUTATION_TIMEOUT,
            ))
            .await?
            .into_inner();
        Ok(response.seq)
    }

    /// Make every chunk sent so far durable on the remote.
    pub async fn flush(&self) -> Result<(), NetError> {
        self.require_sync_protocol().await?;
        self.sync()
            .flush(timed_request(proto::FlushRequest {}, MUTATION_TIMEOUT))
            .await?;
        Ok(())
    }

    /// Read-only conflict probe for a bounded pointer-event batch.
    pub async fn probe_pointer_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Vec<EventConflict>, NetError> {
        self.require_sync_protocol().await?;
        let response = self
            .sync()
            .probe_pointer_events(timed_request(
                proto::ProbeEventsRequest {
                    events: events.iter().map(event_ref).collect(),
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner();
        parse_conflicts(response)
    }

    /// Read-only conflict probe for a bounded pin-event batch.
    pub async fn probe_pin_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Vec<EventConflict>, NetError> {
        self.require_sync_protocol().await?;
        let response = self
            .sync()
            .probe_pin_events(timed_request(
                proto::ProbeEventsRequest {
                    events: events.iter().map(event_ref).collect(),
                },
                UNARY_TIMEOUT,
            ))
            .await?
            .into_inner();
        parse_conflicts(response)
    }

    /// Removed candidate-blind protocol-v2 publication marker.
    #[deprecated(
        since = "0.1.0",
        note = "protocol 3 publishes only through candidate-bound publish_event_batch"
    )]
    pub async fn finalize(&self) -> Result<RebuildCounts, NetError> {
        Err(NetError::Status(Status::failed_precondition(
            "Finalize was removed in node protocol 3; use candidate-bound publish_event_batch",
        )))
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn event_ref((id, seq, cid): &(String, u64, Cid)) -> proto::EventRef {
    proto::EventRef {
        id: id.clone(),
        seq: *seq,
        event_cid: cid.as_bytes().to_vec(),
    }
}

fn event_ref_bytes((id, _, _): &(String, u64, Cid)) -> usize {
    id.len() + 8 + 32
}

fn add_event_page_cids(enumeration: &mut SyncEnumeration, page: &RemoteEventPage) {
    for (_, _, cid) in &page.events {
        enumeration.wanted.push(cid.clone());
        enumeration.live_roots.push(cid.clone());
    }
    enumeration.wanted.extend(page.related_cids.iter().cloned());
    enumeration
        .live_roots
        .extend(page.related_cids.iter().cloned());
    enumeration
        .index_candidates
        .extend(page.related_cids.iter().cloned());
    enumeration
        .wanted
        .extend(page.historical_targets.iter().cloned());
}

fn event_cursor_key(id: &str, seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + id.len() + 8);
    key.extend_from_slice(&(id.len() as u32).to_be_bytes());
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn transfer_id_for_offer(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in &digest[..16] {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn valid_generation(generation: &str) -> bool {
    generation.len() == 16
        && generation
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

fn parse_commit_publication(
    response: proto::CommitEventImportResponse,
    previously_completed: bool,
) -> Result<(EventBatchOutcome, RebuildCounts), NetError> {
    if let Some(rejection) = response.rejection {
        let event = rejection
            .event
            .ok_or_else(|| protocol("remote batch rejection omitted its event"))?;
        return Ok((
            EventBatchOutcome::Rejected(EventBatchRejection {
                kind: rejection.kind,
                id: event.id,
                seq: event.seq,
                cid: cid_from_remote(&event.event_cid)?,
                reason: rejection.reason,
                divergent: rejection.divergent,
            }),
            RebuildCounts::default(),
        ));
    }
    let outcome = EventBatchOutcome::Applied {
        pointer_events: if previously_completed {
            0
        } else {
            usize::try_from(response.pointer_events)
                .map_err(|_| protocol("remote pointer import count exceeds usize"))?
        },
        pin_events: if previously_completed {
            0
        } else {
            usize::try_from(response.pin_events)
                .map_err(|_| protocol("remote pin import count exceeds usize"))?
        },
    };
    let counts = if previously_completed {
        RebuildCounts::default()
    } else {
        RebuildCounts {
            pointers_rebuilt: response.pointers_rebuilt,
            pins_rebuilt: response.pins_rebuilt,
            signatures_indexed: response.signatures_indexed,
            claims_indexed: response.claims_indexed,
        }
    };
    Ok((outcome, counts))
}

fn validate_stage_receipt(
    response: &proto::StageEventImportResponse,
    next_page: u64,
    pointer_events: u64,
    pin_events: u64,
) -> Result<(), NetError> {
    if response.next_page_index != next_page
        || response.pointer_events_staged != pointer_events
        || response.pin_events_staged != pin_events
    {
        return Err(protocol(
            "remote returned an inconsistent event page receipt",
        ));
    }
    Ok(())
}

fn retryable_status(status: &Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Aborted
    )
}

fn validate_protocol(major: u32, minor: u32, capabilities: &[String]) -> Result<(), NetError> {
    if major != crate::PROTOCOL_MAJOR {
        return Err(protocol(format!(
            "remote node protocol {major}.{minor} is incompatible with required {}.{}",
            crate::PROTOCOL_MAJOR,
            crate::PROTOCOL_MINOR
        )));
    }
    if minor.checked_sub(crate::PROTOCOL_MINOR).is_none() {
        return Err(protocol(format!(
            "remote node protocol {major}.{minor} is older than required {}.{}",
            crate::PROTOCOL_MAJOR,
            crate::PROTOCOL_MINOR
        )));
    }
    for required in crate::REQUIRED_SYNC_CAPABILITIES {
        if !capabilities.iter().any(|offered| offered == required) {
            return Err(protocol(format!(
                "remote node protocol is missing required capability {required:?}"
            )));
        }
    }
    Ok(())
}

fn parse_conflicts(response: proto::ProbeEventsResponse) -> Result<Vec<EventConflict>, NetError> {
    response
        .conflicts
        .into_iter()
        .map(|conflict| {
            let offered = conflict
                .offered
                .ok_or_else(|| protocol("remote conflict omitted the offered event"))?;
            Ok(EventConflict {
                id: offered.id,
                seq: offered.seq,
                offered: cid_from_remote(&offered.event_cid)?,
                existing: cid_from_remote(&conflict.existing_cid)?,
            })
        })
        .collect()
}

/// Parse a CID received from the remote.
fn cid_from_remote(bytes: &[u8]) -> Result<Cid, NetError> {
    Cid::from_bytes(bytes).map_err(|_| protocol(format!("remote sent a {} byte CID", bytes.len())))
}

fn protocol(reason: impl Into<String>) -> NetError {
    NetError::Status(Status::data_loss(reason.into()))
}

/// How much of a remote's enumeration this node will hold in memory.
///
/// At roughly 32 bytes per CID this is about 8 million entries — eight times
/// the largest store the scale envelope measured, so an honest peer inside
/// the reviewed envelope never meets it, while a source that simply never
/// stops meets it in a couple of seconds.
const MAX_ENUMERATION_BYTES: usize = 256 * 1024 * 1024;
/// Match the atomic publication contract so a source snapshot is refused
/// before accumulating an offer the destination can never publish.
const MAX_ENUMERATION_EVENT_REFS: usize = dag_control::sync::MAX_SYNC_EVENT_REFS;

/// What one enumeration batch will cost to hold, near enough.
///
/// Deliberately counts the retained shape rather than the wire encoding: a
/// CID is 32 bytes wherever it lands, and a pointer id is its own length.
/// Being approximate is fine — the point is that the total is bounded, not
/// that it is exact.
fn batch_bytes(batch: &proto::EnumerateBatch) -> usize {
    const CID_BYTES: usize = 32;
    const EVENT_OVERHEAD: usize = CID_BYTES + std::mem::size_of::<u64>();

    let events = |refs: &[proto::EventRef]| -> usize {
        refs.iter()
            .map(|e| EVENT_OVERHEAD + e.id.len())
            .sum::<usize>()
    };

    events(&batch.pointer_events)
        + events(&batch.pin_events)
        + (batch.wanted.len() + batch.live_roots.len() + batch.index_candidates.len()) * CID_BYTES
}

/// How long a stream may go without producing a message before the client
/// gives up on it.
///
/// There is deliberately no whole-call timeout — a 4 MiB chunk over a slow
/// link is legitimately long, and an event subscription is legitimately idle
/// for hours. What is *not* legitimate is a stream that opens and then
/// delivers nothing: without this, a remote that accepted `GetChunk` and went
/// quiet parked the calling thread until the process was killed, which for
/// `dag sync pull` means a scheduled replication that never returns and never
/// reports. Progress, not duration, is the thing being bounded.
const FRAME_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Await the next message on a stream, refusing to wait forever for one.
async fn next_message<T>(
    stream: &mut tonic::Streaming<T>,
    what: &str,
) -> Result<Option<T>, NetError> {
    match tokio::time::timeout(FRAME_IDLE_TIMEOUT, stream.message()).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(protocol(format!(
            "remote sent nothing for {} seconds while streaming {}",
            FRAME_IDLE_TIMEOUT.as_secs(),
            what
        ))),
    }
}

async fn next_frame(
    stream: &mut tonic::Streaming<proto::ChunkFrame>,
) -> Result<Option<proto::ChunkFrame>, NetError> {
    next_message(stream, "a chunk").await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accounting has to be roughly right in both directions: too low and
    /// the cap does not bind, too high and an honest peer is refused.
    #[test]
    fn a_batch_is_costed_by_what_it_retains() {
        let empty = proto::EnumerateBatch::default();
        assert_eq!(batch_bytes(&empty), 0);

        let cids = proto::EnumerateBatch {
            wanted: vec![vec![0u8; 32]; 10],
            live_roots: vec![vec![0u8; 32]; 5],
            ..Default::default()
        };
        assert_eq!(batch_bytes(&cids), 15 * 32);

        let events = proto::EnumerateBatch {
            pointer_events: vec![proto::EventRef {
                id: "model/prod".to_string(),
                seq: 7,
                event_cid: vec![0u8; 32],
            }],
            ..Default::default()
        };
        assert_eq!(batch_bytes(&events), 32 + 8 + "model/prod".len());
    }

    /// The cap must clear the largest store the scale envelope measured by a
    /// wide margin, or an honest peer meets it before a hostile one does.
    #[test]
    fn the_enumeration_cap_clears_the_measured_envelope() {
        let one_million_cids = 1_000_000 * 32;
        assert!(MAX_ENUMERATION_BYTES > one_million_cids * 4);
    }

    #[test]
    fn an_offer_has_a_stable_128_bit_resume_id() {
        let digest = event_offer_digest(
            &[("release".to_string(), 1, Cid::compute(b"event"))],
            &[],
            &[],
        );
        assert_eq!(
            transfer_id_for_offer(&digest),
            transfer_id_for_offer(&digest)
        );
        assert_eq!(transfer_id_for_offer(&digest).len(), 32);
        assert_eq!(
            transfer_id_for_offer(&[0; 32]),
            "00000000000000000000000000000000"
        );
    }

    #[test]
    fn loopback_host_detection_is_strict() {
        for host in ["127.0.0.1", "127.42.9.7", "::1", "localhost", "LOCALHOST."] {
            assert!(is_loopback_host(Some(host)), "{host}");
        }
        for host in [
            "0.0.0.0",
            "192.0.2.10",
            "example.test",
            "localhost.example",
            "127.0.0.1.example",
        ] {
            assert!(!is_loopback_host(Some(host)), "{host}");
        }
        assert!(!is_loopback_host(None));
    }

    #[tokio::test]
    async fn remote_plaintext_is_refused_before_any_connection_attempt() {
        let err = match RemoteNode::connect_with(
            "grpc://192.0.2.10:7411",
            ConnectOptions {
                token: Some("must-not-leave-over-plaintext-ever".into()),
                ..Default::default()
            },
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("remote plaintext was accepted"),
        };

        assert!(matches!(err, NetError::InsecureTransportRefused { .. }));
        assert!(!err
            .to_string()
            .contains("must-not-leave-over-plaintext-ever"));
    }

    #[tokio::test]
    async fn malformed_tokens_fail_before_any_connection_attempt() {
        for token in [
            "too-short".to_string(),
            format!("{} {}", "x".repeat(16), "y".repeat(16)),
            format!("{}!", "x".repeat(32)),
            format!("{}\u{7f}", "x".repeat(32)),
            format!("{}é", "x".repeat(32)),
        ] {
            let error = match RemoteNode::connect_with(
                "grpc://127.0.0.1:1",
                ConnectOptions {
                    token: Some(token.clone()),
                    ..Default::default()
                },
            )
            .await
            {
                Err(error) => error,
                Ok(_) => panic!("malformed token was accepted"),
            };
            assert!(matches!(error, NetError::BadUrl { .. }));
            assert!(error.to_string().contains("base64url") || token == "too-short");
            assert!(!error.to_string().contains(&token));
        }
    }
}
