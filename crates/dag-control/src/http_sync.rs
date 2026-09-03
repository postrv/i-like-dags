//! HTTP [`SyncDestination`] — push to an Edge replica (ADR-007).
//!
//! The three reasons ADR-002 rejected HTTP sync are answered here: a
//! bearer token, `POST /sync/missing`, and import validation that runs
//! in the destination. This type is only the client; the Worker (or the
//! in-process stand-in in `dag-edge`) is the destination.

use dag_core::Cid;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Read;
use url::{Host, Url};

use crate::error::ControlError;
use crate::sync::{
    EventBatchOutcome, EventBatchRejection, EventConflict, RebuildCounts, SyncDestination,
};
use crate::Result;

const SESSION_HEADER: &str = "X-Dag-Sync-Session";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionOperation {
    Import,
    Finalize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFailureAction {
    /// Retry the exact UUID automatically; publication may still be active.
    Retry,
    /// Return without clearing the UUID so a later caller can retry it.
    Retain,
    /// The server made this UUID terminal; clear only the local handle.
    Clear,
    /// A known import refusal happened before freeze; best-effort abort it.
    Abort,
}

struct RemoteStatusError {
    error: ControlError,
    status: u16,
    edge_code: Option<String>,
    retry_after: Option<std::time::Duration>,
}

struct ImportFailure {
    error: ControlError,
    edge_code: Option<String>,
    action: SessionFailureAction,
}

/// HTTP probes may fan one offer batch out to one Durable Object call per
/// distinct name. Seven hundred leaves the free/demo 1,000-subrequest ceiling
/// headroom for Catalog coordination, lease renewal, and response handling.
/// The Edge production endpoint may accept larger direct requests, but this
/// client uses one transport shape that is safe for either configured mode.
const HTTP_PROBE_BATCH: usize = 700;

/// Whether `remote` is an HTTP Edge replica rather than a directory or
/// a `grpc://` node.
pub fn is_http_remote(remote: &str) -> bool {
    remote.starts_with("http://") || remote.starts_with("https://")
}

/// A replica behind the ADR-007 HTTP contract.
pub struct HttpDestination {
    base: String,
    token: String,
    agent: ureq::Agent,
    /// Created lazily at the first event offer and retained across ambiguous
    /// failures so a retry resumes the same Edge staging transaction.
    session: parking_lot::Mutex<Option<String>>,
}

impl HttpDestination {
    const MAX_ERROR_BODY_BYTES: u64 = 512;
    const MAX_JSON_RESPONSE_BYTES: u64 = 128 * 1024;

    /// `base` is the replica origin (`https://replica.example`); `token`
    /// is sent as `Authorization: Bearer` on every write.
    ///
    /// Plaintext is accepted only for loopback destinations. Remote
    /// development that cannot use TLS must call
    /// [`Self::new_allowing_insecure_transport`] explicitly.
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        Self::build(base.into(), token.into(), false)
    }

    /// Construct a destination while explicitly accepting remote plaintext.
    ///
    /// This is a development escape hatch. It may send the bearer token and
    /// replicated data in the clear; production callers should use HTTPS.
    pub fn new_allowing_insecure_transport(
        base: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self> {
        Self::build(base.into(), token.into(), true)
    }

    fn build(base: String, token: String, allow_insecure_transport: bool) -> Result<Self> {
        if !(32..=256).contains(&token.len()) {
            return Err(ControlError::Invalid(
                "HTTP replica bearer token must be 32 to 256 UTF-8 bytes".into(),
            ));
        }
        if !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ControlError::Invalid(
                "HTTP replica bearer token must use only base64url characters (A-Z, a-z, 0-9, -, _)"
                    .into(),
            ));
        }

        let parsed = Url::parse(&base)
            .map_err(|error| ControlError::Invalid(format!("invalid HTTP replica URL: {error}")))?;
        if parsed.username() != "" || parsed.password().is_some() {
            return Err(ControlError::Invalid(
                "HTTP replica URL must not contain credentials".into(),
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ControlError::Invalid(
                "HTTP replica URL must not contain a query or fragment".into(),
            ));
        }
        match parsed.scheme() {
            "https" => {}
            "http" if is_loopback_url(&parsed) || allow_insecure_transport => {}
            "http" => {
                return Err(ControlError::Invalid(
                    "refusing plaintext HTTP transport to a non-loopback replica; use HTTPS, \
                     or pass --allow-insecure-transport only for remote development"
                        .into(),
                ));
            }
            _ => {
                return Err(ControlError::Invalid(
                    "HTTP replica URL must use http:// or https://".into(),
                ));
            }
        }

        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            // Redirects are refused: ureq would otherwise replay the
            // Authorization header onto whatever Location a peer sent.
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .redirects(0)
                .build(),
            session: parking_lot::Mutex::new(None),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn auth(&self, req: ureq::Request) -> ureq::Request {
        req.set("Authorization", &format!("Bearer {}", self.token))
    }

    fn session_auth(&self, req: ureq::Request, session: &str) -> ureq::Request {
        self.auth(req).set(SESSION_HEADER, session)
    }

    fn session_id(&self) -> Result<String> {
        let mut slot = self.session.lock();
        if let Some(session) = slot.as_ref() {
            return Ok(session.clone());
        }

        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|error| ControlError::Remote(format!("creating sync session: {error}")))?;
        // RFC 9562 UUIDv4: random payload with the version and variant bits.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let session = format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes(bytes[0..4].try_into().expect("fixed slice")),
            u16::from_be_bytes(bytes[4..6].try_into().expect("fixed slice")),
            u16::from_be_bytes(bytes[6..8].try_into().expect("fixed slice")),
            u16::from_be_bytes(bytes[8..10].try_into().expect("fixed slice")),
            u64::from_be_bytes([
                0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ])
        );
        *slot = Some(session.clone());
        Ok(session)
    }

    fn clear_session(&self, session: &str) {
        let mut slot = self.session.lock();
        if slot.as_deref() == Some(session) {
            *slot = None;
        }
    }

    /// Abort is deliberately best-effort. It is safe only after a definitive
    /// import refusal; transport uncertainty and finalize errors retain the
    /// session because publication may already be in progress.
    fn abort_session(&self, session: &str) {
        let _ = self
            .session_auth(self.agent.post(&self.url("/sync/abort")), session)
            .set("Content-Length", "0")
            .send_bytes(&[]);
        self.clear_session(session);
    }

    fn status_error(status: u16, resp: ureq::Response) -> RemoteStatusError {
        let retry_after = resp
            .header("Retry-After")
            .and_then(|value| value.parse::<u64>().ok())
            // Honor the server hint without letting a response stall this
            // synchronous client for an attacker-selected interval.
            .map(|seconds| std::time::Duration::from_secs(seconds.min(1)));
        let mut body = Vec::new();
        let read = resp
            .into_reader()
            .take(Self::MAX_ERROR_BODY_BYTES + 1)
            .read_to_end(&mut body);
        if read.is_err() {
            return RemoteStatusError {
                error: ControlError::Remote(format!(
                    "HTTP {status}: failed to read bounded error response"
                )),
                status,
                edge_code: None,
                retry_after,
            };
        }
        let truncated = body.len() > Self::MAX_ERROR_BODY_BYTES as usize;
        body.truncate(Self::MAX_ERROR_BODY_BYTES as usize);
        let envelope = (!truncated)
            .then(|| serde_json::from_slice::<RemoteErrorEnvelope>(&body).ok())
            .flatten();
        let edge_code = envelope.as_ref().map(|parsed| match &parsed.error {
            RemoteErrorValue::Detailed { code, .. } | RemoteErrorValue::Legacy(code) => {
                code.clone()
            }
        });
        let detail = match envelope {
            Some(RemoteErrorEnvelope {
                error: RemoteErrorValue::Detailed { code, message },
            }) => {
                let code = sanitize_diagnostic(&code);
                let message = sanitize_diagnostic(&message);
                if message.is_empty() {
                    code
                } else {
                    format!("{code}: {message}")
                }
            }
            Some(RemoteErrorEnvelope {
                error: RemoteErrorValue::Legacy(code),
            }) => sanitize_diagnostic(&code),
            None => {
                let raw = sanitize_diagnostic(&String::from_utf8_lossy(&body));
                format!("{raw}{}", if truncated { "…" } else { "" })
            }
        };
        RemoteStatusError {
            error: ControlError::Remote(format!("HTTP {status}: {detail}")),
            status,
            edge_code,
            retry_after,
        }
    }

    fn map_err(err: ureq::Error) -> ControlError {
        match err {
            ureq::Error::Status(code, resp) => Self::status_error(code, resp).error,
            other => ControlError::Remote(other.to_string()),
        }
    }

    fn ensure_success(response: ureq::Response) -> Result<ureq::Response> {
        let status = response.status();
        if (200..300).contains(&status) {
            Ok(response)
        } else if (300..400).contains(&status) {
            Err(ControlError::Remote(format!(
                "HTTP {status}: redirect refused"
            )))
        } else {
            Err(ControlError::Remote(format!(
                "HTTP {status}: unexpected response"
            )))
        }
    }

    fn decode_json<T: DeserializeOwned>(response: ureq::Response) -> Result<T> {
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(Self::MAX_JSON_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ControlError::Remote(format!("reading HTTP response: {error}")))?;
        if bytes.len() > Self::MAX_JSON_RESPONSE_BYTES as usize {
            return Err(ControlError::Remote(format!(
                "HTTP JSON response exceeds {} bytes",
                Self::MAX_JSON_RESPONSE_BYTES
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| ControlError::Remote(format!("decoding HTTP JSON response: {error}")))
    }
}

#[derive(Serialize)]
struct MissingRequest<'a> {
    cids: Vec<&'a str>,
}

#[derive(Deserialize)]
struct MissingResponse {
    missing: Vec<String>,
}

#[derive(Serialize)]
struct ImportRequest<'a> {
    id: &'a str,
    seq: u64,
    cid: String,
}

#[derive(Deserialize)]
struct ImportResponse {
    filed: bool,
}

#[derive(Deserialize)]
struct RemoteErrorEnvelope {
    error: RemoteErrorValue,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RemoteErrorValue {
    Detailed {
        code: String,
        #[serde(default)]
        message: String,
    },
    // One-release compatibility with the original Edge error shape. It is
    // still parsed as a complete JSON value; substring matching is forbidden.
    Legacy(String),
}

#[derive(Serialize)]
struct ProbeRequest<'a> {
    events: Vec<ProbeEvent<'a>>,
}

#[derive(Serialize)]
struct ProbeEvent<'a> {
    id: &'a str,
    seq: u64,
    cid: String,
}

#[derive(Deserialize)]
struct ProbeResponse {
    conflicts: Vec<ProbeConflict>,
}

#[derive(Deserialize)]
struct ProbeConflict {
    id: String,
    seq: u64,
    offered: String,
    existing: String,
}

#[derive(Deserialize)]
struct FinalizeResponse {
    pointers: u32,
    pins: u32,
    signatures: u32,
    claims: u32,
}

fn sanitize_diagnostic(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn classify_session_failure(
    operation: SessionOperation,
    status: u16,
    edge_code: Option<&str>,
) -> SessionFailureAction {
    let Some(code) = edge_code else {
        // A malformed/truncated body must never authorize abort or local
        // session loss. Retry responses that are normally transient, and
        // otherwise return while retaining the exact UUID for inspection.
        return if status == 409 || status == 429 || status >= 500 {
            SessionFailureAction::Retry
        } else {
            SessionFailureAction::Retain
        };
    };

    if matches!(
        code,
        "sync_busy"
            | "coordination_recovered"
            | "sync_context_changed"
            | "sync_revision_changed"
            | "sync_publication_incomplete"
            | "sync_publication_pending"
            | "sync_unavailable"
            | "rate_limited"
            | "internal_error"
    ) {
        return SessionFailureAction::Retry;
    }

    if matches!(
        code,
        "sync_session_unknown"
            | "sync_session_complete"
            | "sync_session_expired"
            | "sync_session_aborted"
            | "sync_session_validation_failed"
            | "sync_session_legacy_discarded"
            | "sync_session_missing"
    ) {
        return SessionFailureAction::Clear;
    }

    match operation {
        SessionOperation::Finalize => {
            if matches!(
                code,
                "reference_group_limit"
                    | "reference_unavailable"
                    | "reference_store_invalid"
                    | "reference_object_limit"
                    | "reference_byte_limit"
                    | "reference_link_limit"
                    | "reference_depth_limit"
                    | "reference_entry_decode_limit"
                    | "invalid_pin_head"
            ) {
                SessionFailureAction::Clear
            } else if status >= 500 {
                SessionFailureAction::Retry
            } else {
                // Authentication, invalid requests, and unknown conflicts do
                // not merit an automatic retry, but the server-side staging
                // transaction may still exist and must remain addressable.
                SessionFailureAction::Retain
            }
        }
        SessionOperation::Import => {
            if matches!(
                code,
                "invalid_request"
                    | "invalid_offer"
                    | "invalid_cid"
                    | "invalid_json"
                    | "invalid_content_length"
                    | "content_length_mismatch"
                    | "unsupported_media_type"
                    | "body_too_large"
                    | "body_too_fragmented"
                    | "invalid_pointer_id"
                    | "invalid_pin_id"
                    | "invalid_pointer_event"
                    | "invalid_pin_event"
                    | "event_unavailable"
                    | "identity_mismatch"
                    | "divergent"
                    | "zero_seq"
                    | "create_has_prev"
                    | "missing_predecessor"
                    | "chain_broken"
                    | "pin_prev_absent"
                    | "canonical_predecessor_invalid"
                    | "legacy_head_invalid"
                    | "legacy_head_unverified"
                    | "sync_session_changed"
                    | "sync_full"
                    | "catalog_full"
            ) {
                SessionFailureAction::Abort
            } else if status >= 500 {
                SessionFailureAction::Retry
            } else {
                SessionFailureAction::Retain
            }
        }
    }
}

impl SyncDestination for HttpDestination {
    fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>> {
        // Edge implementations commonly spend one storage subrequest per
        // CID. Staying below the 1,000-request free/demo ceiling leaves room
        // for authentication and bookkeeping without weakening the native
        // protocol's larger batch limit.
        const HTTP_MISSING_BATCH: usize = 900;

        let mut missing = Vec::new();
        for batch in cids.chunks(HTTP_MISSING_BATCH) {
            let hex: Vec<String> = batch.iter().map(|cid| cid.to_hex()).collect();
            let refs: Vec<&str> = hex.iter().map(String::as_str).collect();
            let resp = Self::ensure_success(
                self.auth(self.agent.post(&self.url("/sync/missing")))
                    .send_json(MissingRequest { cids: refs })
                    .map_err(Self::map_err)?,
            )?;
            let body: MissingResponse = Self::decode_json(resp)?;
            missing.extend(
                body.missing
                    .into_iter()
                    .map(|hex| {
                        Cid::from_hex(&hex)
                            .map_err(|error| ControlError::Invalid(error.to_string()))
                    })
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        Ok(missing)
    }

    fn store_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<()> {
        Self::ensure_success(
            self.auth(self.agent.put(&self.url(&format!("/c/{}", cid.to_hex()))))
                .set("Content-Type", "application/octet-stream")
                .send_bytes(bytes)
                .map_err(Self::map_err)?,
        )?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Self::ensure_success(
            self.auth(self.agent.post(&self.url("/sync/flush")))
                .send_string("")
                .map_err(Self::map_err)?,
        )?;
        Ok(())
    }

    fn probe_pointer_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        probe(self, "/sync/probe/pointer", events)
    }

    fn probe_pin_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>> {
        probe(self, "/sync/probe/pin", events)
    }

    fn import_pointer_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        import(self, "/sync/import/pointer", id, seq, cid).map_err(|failure| failure.error)
    }

    fn import_pin_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool> {
        import(self, "/sync/import/pin", id, seq, cid).map_err(|failure| failure.error)
    }

    fn import_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<EventBatchOutcome> {
        let mut pointer_imported = 0;
        let mut pin_imported = 0;
        for (kind, path, events, count) in [
            (
                "pointer",
                "/sync/import/pointer",
                pointer_events,
                &mut pointer_imported,
            ),
            ("pin", "/sync/import/pin", pin_events, &mut pin_imported),
        ] {
            for (id, seq, cid) in events {
                match import(self, path, id, *seq, cid) {
                    Ok(true) => *count += 1,
                    Ok(false) => {}
                    Err(failure) => {
                        if matches!(
                            failure.action,
                            SessionFailureAction::Retry | SessionFailureAction::Retain
                        ) {
                            return Err(failure.error);
                        }
                        let reason = failure.error.to_string();
                        return Ok(EventBatchOutcome::Rejected(EventBatchRejection {
                            kind: kind.into(),
                            id: id.clone(),
                            seq: *seq,
                            cid: cid.clone(),
                            divergent: failure.edge_code.as_deref() == Some("divergent"),
                            reason,
                        }));
                    }
                }
            }
        }
        Ok(EventBatchOutcome::Applied {
            pointer_events: pointer_imported,
            pin_events: pin_imported,
        })
    }

    fn finalize(&self) -> Result<RebuildCounts> {
        const ATTEMPTS: usize = 3;
        // No event offer means no remote session exists. Do not mint a UUID
        // solely for finalize: Edge deliberately refuses unknown UUIDs so a
        // delayed finalize can never masquerade as a successful empty push.
        let Some(session) = self.session.lock().clone() else {
            return Ok(RebuildCounts::default());
        };
        let mut last_error = None;
        for attempt in 0..ATTEMPTS {
            let response = self
                .session_auth(self.agent.post(&self.url("/sync/finalize")), &session)
                .set("Content-Length", "0")
                .send_bytes(&[]);
            let retry_after = match response {
                Ok(response) if (200..300).contains(&response.status()) => {
                    let body = match Self::decode_json::<FinalizeResponse>(response) {
                        Ok(body) => Some(body),
                        Err(error) => {
                            // The server may have committed before a malformed
                            // or truncated success receipt reached us. Retry
                            // the same UUID and let its bounded receipt decide.
                            last_error = Some(error);
                            None
                        }
                    };
                    let Some(body) = body else {
                        if attempt + 1 < ATTEMPTS {
                            std::thread::sleep(std::time::Duration::from_millis(
                                [50, 100][attempt],
                            ));
                        }
                        continue;
                    };
                    self.clear_session(&session);
                    return Ok(RebuildCounts {
                        pointers_rebuilt: body.pointers,
                        pins_rebuilt: body.pins,
                        signatures_indexed: body.signatures,
                        claims_indexed: body.claims,
                    });
                }
                Ok(response) => {
                    // Redirects are not evidence about the original session;
                    // do not retry or clear it automatically.
                    return Err(Self::ensure_success(response)
                        .expect_err("non-success response must be refused"));
                }
                Err(ureq::Error::Status(status, response)) => {
                    let remote = Self::status_error(status, response);
                    let action = classify_session_failure(
                        SessionOperation::Finalize,
                        remote.status,
                        remote.edge_code.as_deref(),
                    );
                    match action {
                        SessionFailureAction::Clear => {
                            self.clear_session(&session);
                            return Err(remote.error);
                        }
                        SessionFailureAction::Retain | SessionFailureAction::Abort => {
                            // Finalize never aborts: even a terminal response
                            // can race a publication that crossed its witness.
                            return Err(remote.error);
                        }
                        SessionFailureAction::Retry => {
                            last_error = Some(remote.error);
                            remote.retry_after
                        }
                    }
                }
                Err(error) => {
                    last_error = Some(Self::map_err(error));
                    None
                }
            };

            if attempt + 1 < ATTEMPTS {
                std::thread::sleep(
                    retry_after
                        .unwrap_or_else(|| std::time::Duration::from_millis([50, 100][attempt])),
                );
            }
        }

        // Never abort here: publication may have crossed its point of no
        // return. Retaining the ID also lets an embedding retry `finalize` on
        // this destination after the bounded automatic attempts are spent.
        Err(last_error.expect("at least one finalize attempt"))
    }
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(host)) => host.trim_end_matches('.').eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn import(
    dest: &HttpDestination,
    path: &str,
    id: &str,
    seq: u64,
    cid: &Cid,
) -> std::result::Result<bool, ImportFailure> {
    let session = dest.session_id().map_err(|error| ImportFailure {
        error,
        edge_code: None,
        action: SessionFailureAction::Retain,
    })?;
    let response = dest
        .session_auth(dest.agent.post(&dest.url(path)), &session)
        .send_json(ImportRequest {
            id,
            seq,
            cid: cid.to_hex(),
        });
    let resp = match response {
        Ok(response) => {
            HttpDestination::ensure_success(response).map_err(|error| ImportFailure {
                error,
                edge_code: None,
                action: SessionFailureAction::Retain,
            })?
        }
        Err(ureq::Error::Status(status, response)) => {
            let remote = HttpDestination::status_error(status, response);
            let action = classify_session_failure(
                SessionOperation::Import,
                remote.status,
                remote.edge_code.as_deref(),
            );
            match action {
                SessionFailureAction::Abort => dest.abort_session(&session),
                SessionFailureAction::Clear => dest.clear_session(&session),
                SessionFailureAction::Retry | SessionFailureAction::Retain => {}
            }
            return Err(ImportFailure {
                error: remote.error,
                edge_code: remote.edge_code,
                action,
            });
        }
        Err(error) => {
            return Err(ImportFailure {
                error: HttpDestination::map_err(error),
                edge_code: None,
                action: SessionFailureAction::Retry,
            })
        }
    };
    let body: ImportResponse =
        HttpDestination::decode_json(resp).map_err(|error| ImportFailure {
            error,
            edge_code: None,
            // The event may have staged before its success body was lost or
            // malformed. Retrying the exact offer under the same UUID is safe.
            action: SessionFailureAction::Retry,
        })?;
    Ok(body.filed)
}

fn probe(
    dest: &HttpDestination,
    path: &str,
    events: &[(String, u64, Cid)],
) -> Result<Option<Vec<EventConflict>>> {
    let mut conflicts = Vec::new();
    for batch in events.chunks(HTTP_PROBE_BATCH) {
        let body = ProbeRequest {
            events: batch
                .iter()
                .map(|(id, seq, cid)| ProbeEvent {
                    id,
                    seq: *seq,
                    cid: cid.to_hex(),
                })
                .collect(),
        };
        let response = dest.auth(dest.agent.post(&dest.url(path))).send_json(body);
        let response = match response {
            Ok(response) => HttpDestination::ensure_success(response)?,
            // A pre-probe Edge remains a truthful byte-transfer dry-run.
            // Returning None preserves that compatibility route without
            // making writes, even if an earlier bounded page was accepted.
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(error) => return Err(HttpDestination::map_err(error)),
        };
        let body: ProbeResponse = HttpDestination::decode_json(response)?;
        conflicts.extend(
            body.conflicts
                .into_iter()
                .map(|conflict| {
                    Ok(EventConflict {
                        id: conflict.id,
                        seq: conflict.seq,
                        offered: Cid::from_hex(&conflict.offered).map_err(|error| {
                            ControlError::Remote(format!("invalid offered CID: {error}"))
                        })?,
                        existing: Cid::from_hex(&conflict.existing).map_err(|error| {
                            ControlError::Remote(format!("invalid existing CID: {error}"))
                        })?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        );
    }
    Ok(Some(conflicts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const TEST_TOKEN: &str = "test-http-token-0123456789abcdef01";

    fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        let mut expected = None;
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if expected.is_none() {
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    expected = Some(header_end + 4 + content_length);
                }
            }
            if expected.is_some_and(|length| request.len() >= length) {
                break;
            }
        }
        request
    }

    fn write_response(stream: &mut std::net::TcpStream, status: &str, body: &[u8]) {
        let headers = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
    }

    fn request_path(request: &[u8]) -> &str {
        std::str::from_utf8(request)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
    }

    fn request_header<'a>(request: &'a [u8], wanted: &str) -> Option<&'a str> {
        std::str::from_utf8(request)
            .unwrap()
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(wanted).then_some(value.trim())
            })
    }

    fn is_uuid_v4(value: &str) -> bool {
        let bytes = value.as_bytes();
        value.len() == 36
            && [8, 13, 18, 23].into_iter().all(|i| bytes[i] == b'-')
            && value
                .chars()
                .enumerate()
                .all(|(i, c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
            && bytes[14] == b'4'
            && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
    }

    #[test]
    fn http_and_https_are_remote_urls() {
        assert!(is_http_remote("https://replica.example"));
        assert!(is_http_remote("http://127.0.0.1:8787"));
        assert!(!is_http_remote("grpc://127.0.0.1:7411"));
        assert!(!is_http_remote("/var/replica"));
    }

    #[test]
    fn plaintext_is_loopback_only_without_the_explicit_escape_hatch() {
        assert!(HttpDestination::new("http://127.0.0.1:8787", TEST_TOKEN).is_ok());
        assert!(HttpDestination::new("http://[::1]:8787", TEST_TOKEN).is_ok());
        assert!(HttpDestination::new("http://localhost:8787", TEST_TOKEN).is_ok());

        let secret = "do-not-log-me-0123456789abcdef0123456789";
        let err = HttpDestination::new("http://192.0.2.10:8787", secret)
            .err()
            .expect("remote plaintext was accepted");
        assert!(err.to_string().contains("refusing plaintext"));
        assert!(!err.to_string().contains(secret));

        assert!(HttpDestination::new_allowing_insecure_transport(
            "http://192.0.2.10:8787",
            TEST_TOKEN
        )
        .is_ok());
    }

    #[test]
    fn bearer_token_policy_is_checked_before_transport() {
        for invalid in [
            "x".repeat(31),
            "x".repeat(257),
            format!("{} {}", "x".repeat(16), "y".repeat(16)),
            "é".repeat(16),
            format!("{}:", "x".repeat(31)),
            format!("{}\u{7f}", "x".repeat(31)),
        ] {
            let error = HttpDestination::new("https://replica.example", &invalid)
                .err()
                .expect("invalid token was accepted");
            assert!(!error.to_string().contains(&invalid));
        }
        assert!(HttpDestination::new("https://replica.example", "x".repeat(32)).is_ok());
        assert!(HttpDestination::new("https://replica.example", "x".repeat(256)).is_ok());
    }

    #[test]
    fn structured_error_codes_drive_cleanup_and_untrusted_bodies_cannot() {
        let parsed = HttpDestination::status_error(
            409,
            ureq::Response::new(
                409,
                "Conflict",
                "{\"error\":{\"code\":\"divergent\",\"message\":\"bad\\u001b\\u202ediagnostic\"}}",
            )
            .unwrap(),
        );
        assert_eq!(parsed.edge_code.as_deref(), Some("divergent"));
        assert_eq!(
            classify_session_failure(
                SessionOperation::Import,
                parsed.status,
                parsed.edge_code.as_deref()
            ),
            SessionFailureAction::Abort
        );
        assert!(!parsed.error.to_string().contains('\u{1b}'));
        assert!(!parsed.error.to_string().contains('\u{202e}'));

        for body in ["{not json".to_string(), "x".repeat(513)] {
            let untrusted = HttpDestination::status_error(
                409,
                ureq::Response::new(409, "Conflict", &body).unwrap(),
            );
            assert!(untrusted.edge_code.is_none());
            assert_eq!(
                classify_session_failure(
                    SessionOperation::Import,
                    untrusted.status,
                    untrusted.edge_code.as_deref()
                ),
                SessionFailureAction::Retry,
                "an unparseable response authorized session cleanup"
            );
        }

        for code in [
            "canonical_predecessor_invalid",
            "legacy_head_invalid",
            "legacy_head_unverified",
        ] {
            assert_eq!(
                classify_session_failure(SessionOperation::Import, 502, Some(code)),
                SessionFailureAction::Abort,
                "deterministic predecessor/head corruption was retried"
            );
        }
        for code in [
            "canonical_predecessor_unavailable",
            "legacy_head_unavailable",
        ] {
            assert_eq!(
                classify_session_failure(SessionOperation::Import, 502, Some(code)),
                SessionFailureAction::Retry,
                "a transient predecessor/head read failure discarded the session"
            );
        }
    }

    #[test]
    fn redirects_are_not_followed_and_cannot_downgrade_or_retarget_auth() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let target_addr = target.local_addr().unwrap();

        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let request = read_request(&mut stream);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/sync/missing\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8(request).unwrap()
        });

        let destination =
            HttpDestination::new(format!("http://{origin_addr}"), TEST_TOKEN).unwrap();
        let error = destination
            .missing(&[Cid::compute(b"redirect probe")])
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 302"), "{error}");

        let origin_request = responder.join().unwrap();
        assert!(origin_request.contains(&format!("Authorization: Bearer {TEST_TOKEN}")));
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn missing_checks_are_split_below_edge_subrequest_limits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut sizes = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                let body_start = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let body: serde_json::Value =
                    serde_json::from_slice(&request[body_start..]).unwrap();
                sizes.push(body["cids"].as_array().unwrap().len());
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 14\r\nConnection: close\r\n\r\n{\"missing\":[]}",
                    )
                    .unwrap();
            }
            sizes
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let offered = (0u64..901)
            .map(|index| Cid::compute(&index.to_le_bytes()))
            .collect::<Vec<_>>();
        assert!(destination.missing(&offered).unwrap().is_empty());
        assert_eq!(responder.join().unwrap(), [900, 1]);
    }

    #[test]
    fn event_probes_are_split_below_demo_subrequest_limits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut sizes = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                let body_start = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let body: serde_json::Value =
                    serde_json::from_slice(&request[body_start..]).unwrap();
                sizes.push(body["events"].as_array().unwrap().len());
                write_response(&mut stream, "200 OK", b"{\"conflicts\":[]}");
            }
            sizes
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let offered = (0u64..701)
            .map(|index| {
                (
                    format!("pointer-{index}"),
                    1,
                    Cid::compute(&index.to_le_bytes()),
                )
            })
            .collect::<Vec<_>>();
        assert!(destination
            .probe_pointer_events(&offered)
            .unwrap()
            .unwrap()
            .is_empty());
        assert_eq!(responder.join().unwrap(), [HTTP_PROBE_BATCH, 1]);
    }

    #[test]
    fn finalize_without_an_import_is_a_local_noop() {
        let destination = HttpDestination::new("http://127.0.0.1:1", TEST_TOKEN).unwrap();
        let counts = destination.finalize().unwrap();
        assert_eq!(counts.pointers_rebuilt, 0);
        assert_eq!(counts.pins_rebuilt, 0);
        assert_eq!(counts.signatures_indexed, 0);
        assert_eq!(counts.claims_indexed, 0);
    }

    #[test]
    fn one_uuid_v4_session_spans_imports_and_finalize_then_rotates() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                let body: &[u8] = if index == 2 {
                    b"{\"pointers\":1,\"pins\":1,\"signatures\":0,\"claims\":0}"
                } else {
                    b"{\"filed\":true}"
                };
                write_response(&mut stream, "200 OK", body);
            }
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let first = Cid::compute(b"pointer event");
        let second = Cid::compute(b"pin event");
        assert!(destination.import_pointer_event("p", 1, &first).unwrap());
        assert!(destination.import_pin_event("q", 1, &second).unwrap());
        let counts = destination.finalize().unwrap();
        assert_eq!(counts.pointers_rebuilt, 1);
        assert!(destination.import_pointer_event("next", 1, &first).unwrap());

        let requests = responder.join().unwrap();
        assert_eq!(request_path(&requests[0]), "/sync/import/pointer");
        assert_eq!(request_path(&requests[1]), "/sync/import/pin");
        assert_eq!(request_path(&requests[2]), "/sync/finalize");
        let first_session = request_header(&requests[0], SESSION_HEADER).unwrap();
        assert!(is_uuid_v4(first_session), "{first_session}");
        assert_eq!(
            request_header(&requests[1], SESSION_HEADER),
            Some(first_session)
        );
        assert_eq!(
            request_header(&requests[2], SESSION_HEADER),
            Some(first_session)
        );
        let next_session = request_header(&requests[3], SESSION_HEADER).unwrap();
        assert!(is_uuid_v4(next_session));
        assert_ne!(next_session, first_session);
    }

    #[test]
    fn definitive_import_refusal_sends_best_effort_empty_abort() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let (mut import_stream, _) = listener.accept().unwrap();
            let import = read_request(&mut import_stream);
            write_response(
                &mut import_stream,
                "409 Conflict",
                b"{\"error\":{\"code\":\"divergent\",\"message\":\"position differs\"}}",
            );

            let (mut abort_stream, _) = listener.accept().unwrap();
            let abort = read_request(&mut abort_stream);
            write_response(&mut abort_stream, "204 No Content", b"");
            (import, abort)
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let error = destination
            .import_pointer_event("p", 1, &Cid::compute(b"event"))
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 409"));

        let (import, abort) = responder.join().unwrap();
        assert_eq!(request_path(&abort), "/sync/abort");
        assert_eq!(
            request_header(&abort, SESSION_HEADER),
            request_header(&import, SESSION_HEADER)
        );
        assert_eq!(request_header(&abort, "Content-Length"), Some("0"));
    }

    #[test]
    fn batch_divergence_comes_from_the_structured_error_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let (mut import_stream, _) = listener.accept().unwrap();
            let import = read_request(&mut import_stream);
            write_response(
                &mut import_stream,
                "409 Conflict",
                b"{\"error\":{\"code\":\"divergent\",\"message\":\"sanitized detail\"}}",
            );
            let (mut abort_stream, _) = listener.accept().unwrap();
            let abort = read_request(&mut abort_stream);
            write_response(&mut abort_stream, "204 No Content", b"");
            (import, abort)
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let cid = Cid::compute(b"divergent event");
        let outcome = destination
            .import_event_batch(&[("p".into(), 1, cid)], &[])
            .unwrap();
        let EventBatchOutcome::Rejected(rejection) = outcome else {
            panic!("structured divergence was not returned as a rejection");
        };
        assert!(rejection.divergent);
        assert!(rejection.reason.contains("divergent"));

        let (import, abort) = responder.join().unwrap();
        assert_eq!(request_path(&abort), "/sync/abort");
        assert_eq!(
            request_header(&abort, SESSION_HEADER),
            request_header(&import, SESSION_HEADER)
        );
    }

    #[test]
    fn busy_import_is_retryable_without_abort_or_session_rotation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                if index == 0 {
                    write_response(
                        &mut stream,
                        "409 Conflict",
                        b"{\"error\":{\"code\":\"sync_busy\",\"message\":\"busy\"}}",
                    );
                } else {
                    write_response(&mut stream, "200 OK", b"{\"filed\":true}");
                }
            }
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let cid = Cid::compute(b"event");
        assert!(destination.import_pointer_event("p", 1, &cid).is_err());
        assert!(destination.import_pointer_event("p", 1, &cid).unwrap());

        let requests = responder.join().unwrap();
        assert_eq!(request_path(&requests[0]), "/sync/import/pointer");
        assert_eq!(request_path(&requests[1]), "/sync/import/pointer");
        assert_eq!(
            request_header(&requests[0], SESSION_HEADER),
            request_header(&requests[1], SESSION_HEADER)
        );
    }

    #[test]
    fn recovered_and_changed_import_contexts_retain_the_exact_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for code in [
                Some("coordination_recovered"),
                Some("sync_context_changed"),
                None,
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                if let Some(code) = code {
                    let body =
                        format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"retry\"}}}}");
                    write_response(&mut stream, "409 Conflict", body.as_bytes());
                } else {
                    write_response(&mut stream, "200 OK", b"{\"filed\":true}");
                }
            }
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let cid = Cid::compute(b"event");
        assert!(destination.import_pointer_event("p", 1, &cid).is_err());
        assert!(destination.import_pointer_event("p", 1, &cid).is_err());
        assert!(destination.import_pointer_event("p", 1, &cid).unwrap());

        let requests = responder.join().unwrap();
        let session = request_header(&requests[0], SESSION_HEADER);
        assert!(requests
            .iter()
            .all(|request| request_header(request, SESSION_HEADER) == session));
    }

    #[test]
    fn finalize_failure_is_retried_with_the_same_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                match index {
                    0 => write_response(&mut stream, "200 OK", b"{\"filed\":true}"),
                    1 => write_response(
                        &mut stream,
                        "503 Service Unavailable",
                        b"{\"error\":{\"code\":\"sync_publication_incomplete\",\"message\":\"retry\"}}",
                    ),
                    _ => write_response(
                        &mut stream,
                        "200 OK",
                        b"{\"pointers\":0,\"pins\":0,\"signatures\":0,\"claims\":0}",
                    ),
                }
            }
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        destination
            .import_pointer_event("p", 1, &Cid::compute(b"event"))
            .unwrap();
        destination.finalize().unwrap();

        let requests = responder.join().unwrap();
        assert_eq!(request_path(&requests[1]), "/sync/finalize");
        assert_eq!(request_path(&requests[2]), "/sync/finalize");
        let session = request_header(&requests[0], SESSION_HEADER);
        assert_eq!(request_header(&requests[1], SESSION_HEADER), session);
        assert_eq!(request_header(&requests[2], SESSION_HEADER), session);
    }

    #[test]
    fn malformed_finalize_conflicts_retry_and_retain_the_exact_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                match index {
                    0 => write_response(&mut stream, "200 OK", b"{\"filed\":true}"),
                    1..=3 => write_response(&mut stream, "409 Conflict", b"{not json"),
                    _ => write_response(
                        &mut stream,
                        "200 OK",
                        b"{\"pointers\":1,\"pins\":0,\"signatures\":0,\"claims\":0}",
                    ),
                }
            }
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        destination
            .import_pointer_event("p", 1, &Cid::compute(b"event"))
            .unwrap();
        assert!(destination.finalize().is_err());
        assert!(destination.session.lock().is_some());
        assert_eq!(destination.finalize().unwrap().pointers_rebuilt, 1);

        let requests = responder.join().unwrap();
        let session = request_header(&requests[0], SESSION_HEADER);
        assert!(requests
            .iter()
            .all(|request| request_header(request, SESSION_HEADER) == session));
    }

    #[test]
    fn incomplete_success_receipts_retry_and_retain_the_exact_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                match index {
                    0 => write_response(&mut stream, "200 OK", b"{\"filed\":true}"),
                    1..=3 => write_response(&mut stream, "200 OK", b"{}"),
                    _ => write_response(
                        &mut stream,
                        "200 OK",
                        b"{\"pointers\":1,\"pins\":2,\"signatures\":3,\"claims\":4}",
                    ),
                }
            }
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        destination
            .import_pointer_event("p", 1, &Cid::compute(b"event"))
            .unwrap();
        assert!(destination.finalize().is_err());
        assert!(destination.session.lock().is_some());
        let counts = destination.finalize().unwrap();
        assert_eq!(counts.pointers_rebuilt, 1);
        assert_eq!(counts.pins_rebuilt, 2);
        assert_eq!(counts.signatures_indexed, 3);
        assert_eq!(counts.claims_indexed, 4);
        assert!(destination.session.lock().is_none());

        let requests = responder.join().unwrap();
        let session = request_header(&requests[0], SESSION_HEADER);
        assert!(requests
            .iter()
            .all(|request| request_header(request, SESSION_HEADER) == session));
    }

    #[test]
    fn validation_refusal_is_terminal_without_finalize_abort_or_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut requests = Vec::new();
            let (mut import_stream, _) = listener.accept().unwrap();
            requests.push(read_request(&mut import_stream));
            write_response(&mut import_stream, "200 OK", b"{\"filed\":true}");
            let (mut finalize_stream, _) = listener.accept().unwrap();
            requests.push(read_request(&mut finalize_stream));
            write_response(
                &mut finalize_stream,
                "409 Conflict",
                b"{\"error\":{\"code\":\"reference_unavailable\",\"message\":\"missing root\"}}",
            );
            requests
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        destination
            .import_pointer_event("p", 1, &Cid::compute(b"event"))
            .unwrap();
        let error = destination.finalize().unwrap_err();
        assert!(error.to_string().contains("reference_unavailable"));
        assert!(destination.session.lock().is_none());
        assert_eq!(destination.finalize().unwrap().pointers_rebuilt, 0);

        let requests = responder.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(request_path(&requests[1]), "/sync/finalize");
    }

    #[test]
    fn probes_are_sessionless_and_legacy_not_found_is_non_mutating_unknown() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let offered = Cid::compute(b"offered");
        let existing = Cid::compute(b"existing");
        let response = format!(
            "{{\"conflicts\":[{{\"id\":\"p\",\"seq\":1,\"offered\":\"{}\",\"existing\":\"{}\"}}]}}",
            offered.to_hex(),
            existing.to_hex()
        );
        let responder = std::thread::spawn(move || {
            let (mut pointer_stream, _) = listener.accept().unwrap();
            let pointer = read_request(&mut pointer_stream);
            write_response(&mut pointer_stream, "200 OK", response.as_bytes());
            let (mut pin_stream, _) = listener.accept().unwrap();
            let pin = read_request(&mut pin_stream);
            write_response(&mut pin_stream, "404 Not Found", b"{}");
            (pointer, pin)
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let conflicts = destination
            .probe_pointer_events(&[("p".into(), 1, offered.clone())])
            .unwrap()
            .unwrap();
        assert_eq!(conflicts[0].offered, offered);
        assert_eq!(conflicts[0].existing, existing);
        assert!(destination
            .probe_pin_events(&[("q".into(), 1, Cid::compute(b"pin"))])
            .unwrap()
            .is_none());

        let (pointer, pin) = responder.join().unwrap();
        assert_eq!(request_path(&pointer), "/sync/probe/pointer");
        assert_eq!(request_path(&pin), "/sync/probe/pin");
        assert!(request_header(&pointer, SESSION_HEADER).is_none());
        assert!(request_header(&pin, SESSION_HEADER).is_none());
    }

    #[test]
    fn success_and_error_response_bodies_are_read_through_hard_caps() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let (mut oversized_stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut oversized_stream);
            write_response(
                &mut oversized_stream,
                "200 OK",
                &vec![b'x'; HttpDestination::MAX_JSON_RESPONSE_BYTES as usize + 1],
            );
            let (mut error_stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut error_stream);
            let mut body = vec![b'e'; 8 * 1024];
            body.extend_from_slice(b"SECRET_TAIL_MARKER");
            write_response(&mut error_stream, "400 Bad Request", &body);
        });

        let destination = HttpDestination::new(format!("http://{addr}"), TEST_TOKEN).unwrap();
        let cid = Cid::compute(b"probe");
        let oversized = destination.missing(std::slice::from_ref(&cid)).unwrap_err();
        assert!(oversized.to_string().contains("exceeds"), "{oversized}");
        let bounded = destination.missing(&[cid]).unwrap_err().to_string();
        assert!(bounded.contains("HTTP 400"));
        assert!(bounded.ends_with('…'));
        assert!(!bounded.contains("SECRET_TAIL_MARKER"));
        assert!(
            bounded.len() < 600,
            "bounded error grew to {}",
            bounded.len()
        );
        responder.join().unwrap();
    }
}
