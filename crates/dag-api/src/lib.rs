//! HTTP API and web console for the content-addressed DAG system.
//!
//! Two postures, deliberately (ADR-006):
//!
//! * [`router`] / [`serve`] — the human console. Unauthenticated on loopback.
//!   A non-loopback bind without [`ServerOptions::expose_control`] is refused.
//! * [`content_router`] / [`serve_content`] — the read-only content plane.
//!   GET-by-CID, no writes, no console. It is safe from control-plane mutation;
//!   Internet deployments still terminate TLS and rate-limit at a proxy.
//!
//! The console and the CLI drive exactly the same [`Control`] methods, so
//! anything you can do in one is visible in the other.
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use std::sync::Arc;
//! use dag_control::Control;
//!
//! let control = Arc::new(Control::open(std::path::Path::new(".dag"))?);
//! dag_api::serve(control, "127.0.0.1:8080".parse()?).await?;
//! # Ok(())
//! # }
//! ```

pub mod assets;
pub mod blocking;
pub mod error;
pub mod integrity;
pub mod routes;
pub mod scenario;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dag_control::Control;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tower_http::trace::TraceLayer;

/// Body ceiling for chunk uploads.
///
/// axum defaults to 2 MiB, which silently made the HTTP API reject content the
/// CLI accepts and broke the 4 MiB guarantee in I2. The slack above
/// `MAX_CHUNK_SIZE` exists so that a chunk which is merely *too big* reaches the
/// handler and comes back as a structured `ChunkTooLarge` 413 naming the limit,
/// rather than axum's bare "length limit exceeded" text.
const CHUNK_BODY_LIMIT: usize = dag_core::MAX_CHUNK_SIZE + 64 * 1024;

/// Body ceiling for the JSON control endpoints, none of which carry content.
const JSON_BODY_LIMIT: usize = 256 * 1024;

/// Maximum time an upload may go without producing another body frame.
const FILE_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute lifetime of one file upload, including storage work.
const FILE_UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Transport backstop includes one maximum chunk of slack so the core
/// splitter can return its structured 1 GiB policy error for streaming bodies.
const FILE_UPLOAD_BODY_LIMIT: usize = routes::files::MAX_HTTP_FILE_BYTES + dag_core::MAX_CHUNK_SIZE;

/// How long a browser may cache a preflight for an allow-listed origin.
const CORS_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(600);

/// Aggregate admission for synchronous filesystem/redb work per HTTP router.
///
/// Tokio's blocking pool is intentionally large. Without a tighter service
/// boundary, a public content plane can fill it with slow disk walks or
/// backpressured file reassembly and starve unrelated runtime users.
const MAX_BLOCKING_OPERATIONS: usize = 32;
/// Default accepted HTTP connections across one listener.
const DEFAULT_MAX_HTTP_CONNECTIONS: usize = 256;
/// Default share one direct peer IP may consume.
const DEFAULT_MAX_HTTP_CONNECTIONS_PER_SOURCE: usize = 32;
/// TLS belongs at the deployment proxy. On this plaintext listener, the
/// initial request headers must reach Axum within this non-resettable window.
const HTTP_CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Once a response body is finished, the next keep-alive request must reach
/// Axum within this window. Active handlers and bodies are deliberately exempt.
const HTTP_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Responses that retain content buffers or a file-join worker until the body
/// is consumed have a smaller aggregate memory/I/O ceiling.
const MAX_CONTENT_RESPONSES: usize = 16;
/// Live SSE subscriptions are cheap but otherwise unbounded in count.
const MAX_LIVE_EVENT_STREAMS: usize = 32;
/// Replays materialise and encode a journal window, so admit only one at a
/// time independently of long-lived live streams and content downloads.
const MAX_EVENT_REPLAYS: usize = 1;
/// Each response-body poll hands the transport at most this much content.
pub(crate) const CONTENT_RESPONSE_FRAME_BYTES: usize = 64 * 1024;

/// Content Security Policy applied to every response.
///
/// The console is the only thing that should ever render this server's output,
/// and it is served from this same origin — so the policy is `'self'`, with
/// exactly the two concessions the shipped console needs: `'unsafe-inline'`
/// for *style*, because `ui.ts` and `graph.ts` emit `style="…"` attributes,
/// and `data:` for images, because `index.html` carries an inline SVG favicon.
///
/// Script deliberately gets no inline allowance. The console loads external ES
/// modules from `/js/`, so it does not need one, and withholding it is what
/// keeps a stored `<script>` or `onerror=` payload inert even if some future
/// handler were persuaded to serve content as HTML — defence behind the
/// content-type allow-list in `routes::files`, not instead of it.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     connect-src 'self'; \
     font-src 'self'; \
     object-src 'none'; \
     base-uri 'none'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// An allow-list entry that is not a usable origin.
#[derive(Debug, thiserror::Error)]
#[error("invalid origin {origin:?}: {reason}")]
pub struct InvalidOrigin {
    /// The rejected string, as given.
    pub origin: String,
    /// Why it was rejected.
    pub reason: String,
}

/// Cross-origin and bind policy for [`router_with`] and [`serve_with`].
///
/// The default grants nothing: the console is served from the same origin as
/// the API, so it needs no grant, and this server has no authentication, which
/// makes the browser's origin controls the only thing standing between a
/// random web page and `POST /api/gc/run`. Naming origins here is an explicit
/// operator decision for a deployment that genuinely embeds the API elsewhere.
///
/// [`Self::expose_control`] is the bind hatch, not an auth system: it lets
/// `dag serve` mount write routes on a non-loopback address. The process
/// still has no authentication. A proxy owns that, if anyone ever needs it.
#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    allowed_origins: Vec<HeaderValue>,
    expose_control: bool,
    connection_limits: HttpConnectionLimits,
}

/// HTTP listener connection admission.
#[derive(Clone, Copy, Debug)]
pub struct HttpConnectionLimits {
    /// Aggregate established and handshaking transports.
    pub total: usize,
    /// Transports attributed to one direct `peer_addr()` IP.
    pub per_source: usize,
}

impl Default for HttpConnectionLimits {
    fn default() -> Self {
        Self {
            total: DEFAULT_MAX_HTTP_CONNECTIONS,
            per_source: DEFAULT_MAX_HTTP_CONNECTIONS_PER_SOURCE,
        }
    }
}

/// Invalid HTTP connection admission configuration.
#[derive(Debug, thiserror::Error)]
#[error(
    "HTTP connection limits require 1 <= per_source ({per_source}) <= total ({total}) <= {max}"
)]
pub struct InvalidHttpConnectionLimits {
    total: usize,
    per_source: usize,
    max: usize,
}

impl ServerOptions {
    /// The safe default: no origin but this server's own, control plane
    /// only on loopback.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant the named origins cross-origin access.
    ///
    /// Each entry must be a complete origin — scheme, host and optional port,
    /// nothing else. `*` is rejected rather than accepted as a shorthand,
    /// because "allow everything" is the defect this list exists to prevent.
    pub fn allow_origins<I, S>(origins: I) -> Result<Self, InvalidOrigin>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowed_origins = Vec::new();
        for origin in origins {
            allowed_origins.push(parse_origin(origin.as_ref())?);
        }
        Ok(Self {
            allowed_origins,
            ..Self::default()
        })
    }

    /// Mount write/GC/job routes on a non-loopback bind.
    ///
    /// The server is still unauthenticated. Anyone who can reach the port
    /// can delete data. This is the explicit operator decision ADR-006
    /// requires instead of a warning operators learn to ignore.
    pub fn expose_control(mut self) -> Self {
        self.expose_control = true;
        self
    }

    /// Whether write routes may be served on a non-loopback address.
    pub fn exposes_control(&self) -> bool {
        self.expose_control
    }

    /// The granted origins, in header form. Empty by default.
    pub fn allowed_origins(&self) -> &[HeaderValue] {
        &self.allowed_origins
    }

    /// Set aggregate and per-direct-source listener admission.
    ///
    /// A trusted L4 proxy often makes many clients share one backend peer IP;
    /// size `per_source` for that topology and enforce real-client limits at
    /// the proxy.
    pub fn with_connection_limits(
        mut self,
        total: usize,
        per_source: usize,
    ) -> Result<Self, InvalidHttpConnectionLimits> {
        let limits = HttpConnectionLimits { total, per_source };
        validate_http_connection_limits(limits)?;
        self.connection_limits = limits;
        Ok(self)
    }

    /// Current listener admission limits.
    pub fn connection_limits(&self) -> HttpConnectionLimits {
        self.connection_limits
    }
}

fn validate_http_connection_limits(
    limits: HttpConnectionLimits,
) -> Result<(), InvalidHttpConnectionLimits> {
    let max = tokio::sync::Semaphore::MAX_PERMITS;
    if limits.total == 0
        || limits.per_source == 0
        || limits.per_source > limits.total
        || limits.total > max
    {
        return Err(InvalidHttpConnectionLimits {
            total: limits.total,
            per_source: limits.per_source,
            max,
        });
    }
    Ok(())
}

/// Refusing to bind the console's control plane on a public address.
///
/// ADR-006: a warning is not a control. `dag content serve` is the public
/// listener; `--expose-control` is the hatch for an operator who has a
/// proxy and accepts the blast radius.
#[derive(Debug, thiserror::Error)]
#[error(
    "refusing to bind {addr}: dag serve has no authentication and {addr} is \
     not loopback. Use `dag content serve` for a public read-only plane, or \
     pass --expose-control if a proxy is in front of this process and you \
     accept that anyone who can reach it can delete data"
)]
pub struct ControlPlaneBindRefused {
    /// The address that was refused.
    pub addr: SocketAddr,
}

fn parse_origin(origin: &str) -> Result<HeaderValue, InvalidOrigin> {
    let reject = |reason: &str| InvalidOrigin {
        origin: origin.to_string(),
        reason: reason.to_string(),
    };

    if origin == "*" {
        return Err(reject(
            "`*` grants every origin on the web, which is exactly what this \
             allow-list exists to avoid; name the origins instead",
        ));
    }
    let Some((_scheme, rest)) = origin.split_once("://") else {
        return Err(reject(
            "expected a whole origin including scheme, e.g. https://console.example",
        ));
    };
    if rest.is_empty() {
        return Err(reject(
            "expected a whole origin including scheme, e.g. https://console.example",
        ));
    }
    if rest.contains('/') {
        return Err(reject(
            "an origin is scheme, host and port only — no path, no trailing slash",
        ));
    }

    let parsed = url::Url::parse(origin).map_err(|_| reject("not a valid absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(reject(
            "only http:// and https:// web origins are supported",
        ));
    }
    if parsed.host().is_none() {
        return Err(reject("a web origin must contain a host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(reject("an origin must not contain user credentials"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(reject("an origin must not contain a query or fragment"));
    }

    // URL origin serialization normalizes scheme/host case, IDNs and default
    // ports to the same form browsers place in the Origin header. HeaderValue
    // then rejects control bytes, preventing header injection as a final gate.
    HeaderValue::from_str(&parsed.origin().ascii_serialization())
        .map_err(|_| reject("not representable as a header value"))
}

/// Shared handler state.
///
/// `Control` is internally `Arc`-shared and every method takes `&self`, so a
/// clone per request costs one refcount bump and no locking.
#[derive(Clone)]
pub struct AppState {
    /// The control plane every handler operates on.
    pub control: Arc<Control>,
    /// Shared finite admission for disk/database work and streaming joins.
    blocking_admission: Arc<tokio::sync::Semaphore>,
    /// Held for the complete lifetime of a content response body.
    content_response_admission: Arc<tokio::sync::Semaphore>,
    /// Held for the complete lifetime of an SSE event stream.
    live_event_admission: Arc<tokio::sync::Semaphore>,
    /// Held while a materialised event replay response remains live.
    event_replay_admission: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    /// Construct handler state with the production admission defaults.
    pub fn new(control: Arc<Control>) -> Self {
        Self {
            control,
            blocking_admission: Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_OPERATIONS)),
            content_response_admission: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONTENT_RESPONSES,
            )),
            live_event_admission: Arc::new(tokio::sync::Semaphore::new(MAX_LIVE_EVENT_STREAMS)),
            event_replay_admission: Arc::new(tokio::sync::Semaphore::new(MAX_EVENT_REPLAYS)),
        }
    }

    pub(crate) fn try_blocking_permit(
        &self,
    ) -> crate::error::ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.blocking_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                crate::error::ApiError::service_unavailable(
                    "server disk/database work is at capacity; retry shortly",
                )
            })
    }

    pub(crate) fn try_content_response_permit(
        &self,
    ) -> crate::error::ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.content_response_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                crate::error::ApiError::service_unavailable(
                    "content response capacity is full; retry shortly",
                )
            })
    }

    pub(crate) fn try_live_event_permit(
        &self,
    ) -> crate::error::ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.live_event_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                crate::error::ApiError::service_unavailable(
                    "event stream capacity is full; retry shortly",
                )
            })
    }

    pub(crate) fn try_event_replay_permit(
        &self,
    ) -> crate::error::ApiResult<tokio::sync::OwnedSemaphorePermit> {
        self.event_replay_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                crate::error::ApiError::service_unavailable(
                    "event replay capacity is full; retry shortly",
                )
            })
    }
}

/// Stream an in-memory content buffer in small zero-copy slices while holding
/// aggregate response admission until the body is consumed or dropped.
pub(crate) fn admitted_bytes_body(bytes: Bytes, permit: tokio::sync::OwnedSemaphorePermit) -> Body {
    let mut offset = 0usize;
    let stream = std::iter::from_fn(move || {
        let _permit = &permit;
        if offset >= bytes.len() {
            return None;
        }
        let end = offset
            .saturating_add(CONTENT_RESPONSE_FRAME_BYTES)
            .min(bytes.len());
        let frame = bytes.slice(offset..end);
        offset = end;
        Some(Ok::<_, std::convert::Infallible>(frame))
    });
    Body::from_stream(tokio_stream::iter(stream))
}

/// Build the application router with the safe default cross-origin policy.
///
/// See [`router_with`] for what that policy is and how to widen it.
pub fn router(control: Arc<Control>) -> Router {
    router_with(control, &ServerOptions::new())
}

/// Read-only content plane (ADR-006). No write routes, no console SPA.
pub fn content_router(control: Arc<Control>) -> Router {
    content_router_with(control, &ServerOptions::new())
}

/// Read-only content plane with an optional origin allow-list.
///
/// Pointer resolve is served and is **untrusted convenience**: the bytes
/// behind a CID are self-authenticating; the claim that a name currently
/// resolves to that CID is not, unless the client walks the event chain.
pub fn content_router_with(control: Arc<Control>, options: &ServerOptions) -> Router {
    let state = AppState::new(control);
    let allowed = Arc::new(options.allowed_origins.clone());
    let http_metrics = Arc::new(routes::metrics::HttpMetrics::default());

    let api = finish_api(
        content_api(),
        state.clone(),
        http_metrics.clone(),
        Arc::clone(&allowed),
    );

    let metrics_public = Router::new()
        .route("/metrics", get(routes::metrics::scrape))
        .route("/health", get(liveness))
        .route_layer(axum::middleware::from_fn_with_state(
            http_metrics.clone(),
            routes::metrics::track,
        ))
        .layer(axum::Extension(http_metrics))
        .with_state(state);

    let mut app = Router::new().nest("/api", api).merge(metrics_public);

    if !allowed.is_empty() {
        app = app.layer(
            CorsLayer::new()
                .allow_origin(allowed.as_ref().clone())
                .allow_methods([Method::GET, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE])
                .max_age(CORS_PREFLIGHT_MAX_AGE),
        );
    }

    app.layer(axum::middleware::map_response(security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(track_http_connection))
}

/// GET-only routes a public verifier may hit. No PUT, no mutating POST.
fn content_api() -> Router<AppState> {
    Router::new()
        .route("/health", get(readiness))
        .route("/metrics", get(routes::metrics::scrape))
        .route("/stats", get(stats))
        .route("/entries", get(routes::content::get_entry))
        .route("/chunks", get(routes::content::get_chunk))
        .route("/files", get(routes::files::download))
        .route("/graph", get(routes::content::graph))
        .route("/pointers", get(routes::pointers::list))
        .route("/pointers/resolve", get(routes::pointers::resolve))
        .route("/pointers/history", get(routes::pointers::history))
        .route("/pins", get(routes::pins::list))
        .route("/pins/history", get(routes::pins::history))
        .route("/signatures", get(routes::signatures::list))
        .route("/events", get(routes::events::replay))
        .route("/usecase/verify", get(routes::scenario::verify))
}

/// Write, delete, job, recovery, and operator-only reads.
fn control_api() -> Router<AppState> {
    Router::new()
        .route(
            "/chunks",
            post(routes::content::put_chunk).layer(DefaultBodyLimit::max(CHUNK_BODY_LIMIT)),
        )
        .route(
            "/files",
            post(routes::files::upload)
                .layer::<_, std::convert::Infallible>(RequestBodyTimeoutLayer::new(
                    FILE_UPLOAD_IDLE_TIMEOUT,
                ))
                .layer::<_, std::convert::Infallible>(RequestBodyLimitLayer::new(
                    FILE_UPLOAD_BODY_LIMIT,
                ))
                .layer::<_, std::convert::Infallible>(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    FILE_UPLOAD_TOTAL_TIMEOUT,
                )),
        )
        .route("/pointers", post(routes::pointers::set))
        .route("/pins", post(routes::pins::create))
        .route("/pins/deactivate", post(routes::pins::deactivate))
        .route("/jobs", get(routes::jobs::list))
        .route("/jobs/runs", get(routes::jobs::runs))
        .route("/jobs/run", post(routes::jobs::run_once))
        .route("/adapters", get(routes::jobs::adapters))
        .route("/gc/status", get(routes::gc::status))
        .route("/gc/run", post(routes::gc::run))
        .route("/integrity", get(routes::gc::integrity))
        .route("/events/stream", get(routes::events::stream))
        .route("/usecase/seed", post(routes::scenario::seed))
}

fn finish_api(
    api: Router<AppState>,
    state: AppState,
    http_metrics: Arc<routes::metrics::HttpMetrics>,
    allowed: Arc<Vec<HeaderValue>>,
) -> Router {
    // Keep unknown API paths inside the JSON API boundary. Without this
    // fallback, Axum can fall through to the console's GET-only SPA fallback
    // and report 405 for a removed POST endpoint, obscuring whether the API
    // route exists at all.
    api.fallback(api_not_found)
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT))
        .layer(RequestBodyTimeoutLayer::new(FILE_UPLOAD_IDLE_TIMEOUT))
        .route_layer(axum::middleware::from_fn_with_state(
            http_metrics.clone(),
            routes::metrics::track,
        ))
        .layer(axum::Extension(http_metrics))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            allowed,
            same_site_only,
        ))
}

async fn api_not_found() -> error::ApiError {
    error::ApiError::not_found("no such API endpoint")
}

/// Build the application router.
///
/// # Origins
///
/// The console is served from the same origin as the API, so it needs no
/// cross-origin grant, and by default none is given. That matters more here
/// than it would elsewhere: this server has no authentication, so the
/// browser's origin controls are the *only* thing between a page the operator
/// happened to open and an API that repoints production pointers and deletes
/// data. Being permissive would not merely fail to imply a security property —
/// it would remove the last one, turning any visited page into a full
/// read-write client of a localhost `dag serve`.
///
/// Two controls, because they answer different questions:
///
/// * **CORS** decides what a browser may *read back*. With no allow-listed
///   origins there is no `Access-Control-Allow-Origin` at all, so a
///   cross-origin response is unreadable.
/// * **`same_site_only`** decides what a browser may *reach*. A
///   `POST /api/gc/run` with no body is a CORS-simple request: it is
///   dispatched before the browser ever looks at the response headers, so the
///   data would already be gone by the time the reply was discarded. CORS
///   cannot express this; `Sec-Fetch-Site` can.
///
/// `options` widens the first for named origins and the second along with it.
pub fn router_with(control: Arc<Control>, options: &ServerOptions) -> Router {
    let state = AppState::new(control);
    let allowed = Arc::new(options.allowed_origins.clone());

    // One HTTP-metrics cell per router, shared by the tracking middleware and
    // the scrape handler that renders it.
    let http_metrics = Arc::new(routes::metrics::HttpMetrics::default());

    let api = finish_api(
        content_api().merge(control_api()),
        state.clone(),
        http_metrics.clone(),
        Arc::clone(&allowed),
    );

    // The scraper/probe-convention paths, outside the same-site guard: a
    // Prometheus agent or Kubernetes probe sends no Sec-Fetch headers, and a
    // browser cannot read the responses cross-origin without CORS. Without
    // the bare `/health` route the SPA fallback would answer it 200 with
    // HTML, which a probe happily believes. Same handlers, same registries.
    let metrics_public = Router::new()
        .route("/metrics", get(routes::metrics::scrape))
        .route("/health", get(liveness))
        .route_layer(axum::middleware::from_fn_with_state(
            http_metrics.clone(),
            routes::metrics::track,
        ))
        .layer(axum::Extension(http_metrics))
        .with_state(state);

    let mut app = Router::new()
        .nest("/api", api)
        .merge(metrics_public)
        .merge(assets::router());

    // No allow-list, no CORS layer: the absence of Access-Control-Allow-Origin
    // is itself the answer, and it is the one answer that cannot be widened by
    // a mistake in this configuration.
    if !allowed.is_empty() {
        app = app.layer(
            CorsLayer::new()
                .allow_origin(allowed.as_ref().clone())
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE])
                // Neither credentials nor `expose_headers(Any)`: an allow-list
                // grants reading the documented JSON, not the browser's
                // ambient authority.
                .max_age(CORS_PREFLIGHT_MAX_AGE),
        );
    }

    // A hostile page can defeat origin checks with DNS rebinding: load from
    // attacker.example, change that name to 127.0.0.1, then call the same
    // hostname and have the browser honestly label the request same-origin.
    // The Host authority is still attacker.example, so the loopback posture
    // rejects it. `--expose-control` disables this restriction because that
    // mode is explicitly for an authenticating reverse proxy with its own
    // public authority policy.
    if !options.expose_control {
        app = app.layer(axum::middleware::from_fn(loopback_host_only));
    }

    app.layer(axum::middleware::map_response(security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(track_http_connection))
}

/// Refuse non-loopback HTTP authorities on the unauthenticated control plane.
///
/// Browser requests to this HTTP/1 backend carry `Host`. Missing `Host` remains
/// accepted for HTTP/1.0 and in-process/non-browser clients; a DNS-rebinding
/// browser cannot exploit that exception because script cannot suppress or
/// rewrite the authority derived from its URL. HTTP/2, when desired, belongs at
/// the deployment proxy unless this backend is explicitly upgraded and its
/// multiplexing limits are qualified.
async fn loopback_host_only(request: Request, next: Next) -> Response {
    if request
        .headers()
        .get(header::HOST)
        .is_some_and(|host| !is_loopback_authority(host))
    {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            Json(serde_json::json!({
                "error": "non-loopback Host refused on the unauthenticated control plane; \
                          use localhost/127.0.0.1, or put an authenticating proxy in front of \
                          `dag serve --expose-control`"
            })),
        )
            .into_response();
    }
    next.run(request).await
}

fn is_loopback_authority(value: &HeaderValue) -> bool {
    let Ok(authority) = value.to_str() else {
        return false;
    };
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        let suffix = &bracketed[close + 1..];
        if !valid_port_suffix(suffix) {
            return false;
        }
        &bracketed[..close]
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.is_empty() || port.parse::<u16>().is_err() {
            return false;
        }
        host
    } else {
        authority
    };

    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn valid_port_suffix(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}

/// Baseline headers on every response, console and API alike.
///
/// `nosniff` is the one that matters for stored content: `routes::files`
/// serves anything it does not recognise as `application/octet-stream`, and
/// that is only inert if the browser is told not to second-guess it.
async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // `frame-ancestors` in the CSP supersedes this for current browsers; both
    // are sent because the header costs nothing and the overlap is not total.
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    // CIDs travel in query strings; there is no reason to leak them onward.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Refuse an API request that the browser itself reports as coming from
/// another site.
///
/// `Sec-Fetch-Site` is set by the browser and is unforgeable by page script,
/// so it cleanly separates "the console calling its own API" from "some other
/// page reaching in". Clients that are not browsers — curl, `dag` itself, any
/// HTTP library — never send it and are untouched.
///
/// The check is an allow-list, not a deny-list, because this is the only guard
/// in front of an unauthenticated API and it must fail closed. A request passes
/// without an explicit origin grant only when its `Sec-Fetch-Site` is one we
/// affirmatively trust:
///
/// * **absent** — a non-browser client, provided it did not also send an
///   explicit foreign `Origin`;
/// * **`same-origin`** — the console calling its own API;
/// * **`none`** — a user typing the URL or following a bookmark.
///
/// Everything else is treated as another origin reaching in and must match an
/// allow-listed origin. That is deliberately wider than "cross-site": a
/// **`same-site`** request is a different origin on the same registrable domain
/// — on a shared localhost, a sibling dev server on another port — which is not
/// the console and gets no unauthenticated write access by default. And an
/// **unrecognised** value is refused rather than waved through, since a browser
/// only ever sends one of the four defined tokens, so a deny-list's blind spot
/// buys nothing and costs the fail-closed property.
///
/// The allow-list is consulted so that an origin granted CORS above can
/// actually use it.
async fn same_site_only(
    State(allowed): State<Arc<Vec<HeaderValue>>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request.headers().get(header::ORIGIN);
    let explicitly_granted = origin.is_some_and(|value| allowed.iter().any(|a| a == value));
    let trusted_without_grant = match request.headers().get("sec-fetch-site") {
        // Curl and the CLI send neither header. A browser/agent that omits
        // Fetch Metadata but does disclose Origin must still prove it is this
        // request's HTTP authority; otherwise an explicit foreign origin
        // turns header absence into a guard bypass.
        None => origin.is_none_or(|value| origin_matches_http_authority(&request, value)),
        // Present: only same-origin navigation/fetch values pass. Note the
        // `Ok(..)` — a header that is present but not readable as text is not
        // the same as one that is absent, and folding the two together (which
        // `.to_str().ok()` did) let a caller opt out of the guard by sending
        // bytes instead of a value.
        Some(value) => matches!(value.to_str(), Ok("same-origin") | Ok("none")),
    };
    if !trusted_without_grant && !explicitly_granted {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "cross-origin request refused: dag serve has no authentication, \
                          so it grants no origin but its own. Start it with \
                          `--allow-origin <ORIGIN>` if another origin must reach this API."
            })),
        )
            .into_response();
    }

    next.run(request).await
}

/// Whether `Origin` names the same plain-HTTP authority as this request.
///
/// `dag serve` itself is HTTP; TLS termination belongs to the proxy posture,
/// where a non-HTTP external origin must be granted explicitly. Default ports
/// are normalized so `Origin: http://localhost` matches `Host: localhost:80`.
fn origin_matches_http_authority(request: &Request, origin: &HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Ok(origin) = origin.parse::<Uri>() else {
        return false;
    };
    if origin.scheme_str() != Some("http") || origin.query().is_some() {
        return false;
    }
    let Some(origin_authority) = origin.authority() else {
        return false;
    };

    let request_authority = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<axum::http::uri::Authority>().ok())
        .or_else(|| request.uri().authority().cloned());
    let Some(request_authority) = request_authority else {
        return false;
    };

    origin_authority
        .host()
        .eq_ignore_ascii_case(request_authority.host())
        && origin_authority.port_u16().unwrap_or(80) == request_authority.port_u16().unwrap_or(80)
}

/// How often the background integrity scan re-hashes the store.
const INTEGRITY_SCAN_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
struct HttpConnectionActivity {
    inner: Arc<HttpConnectionActivityInner>,
}

struct HttpConnectionActivityInner {
    setup_complete: AtomicBool,
    active_requests: AtomicUsize,
    generation: AtomicU64,
    idle_since: Mutex<Option<tokio::time::Instant>>,
    notify: Arc<tokio::sync::Notify>,
}

impl Default for HttpConnectionActivity {
    fn default() -> Self {
        Self {
            inner: Arc::new(HttpConnectionActivityInner {
                setup_complete: AtomicBool::new(false),
                active_requests: AtomicUsize::new(0),
                generation: AtomicU64::new(0),
                idle_since: Mutex::new(None),
                notify: Arc::new(tokio::sync::Notify::new()),
            }),
        }
    }
}

impl HttpConnectionActivity {
    fn begin(&self) -> HttpRequestLease {
        let previous = self.inner.active_requests.fetch_add(1, Ordering::AcqRel);
        if previous == 0 {
            *self
                .inner
                .idle_since
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        self.inner.setup_complete.store(true, Ordering::Release);
        self.changed();
        HttpRequestLease {
            activity: self.clone(),
        }
    }

    fn finish(&self) {
        let previous = self.inner.active_requests.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "HTTP request activity underflow");
        if previous == 1 {
            *self
                .inner
                .idle_since
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(tokio::time::Instant::now());
            self.changed();
        }
    }

    fn changed(&self) {
        self.inner.generation.fetch_add(1, Ordering::AcqRel);
        self.inner.notify.notify_waiters();
    }

    fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    fn setup_complete(&self) -> bool {
        self.inner.setup_complete.load(Ordering::Acquire)
    }

    fn active_requests(&self) -> usize {
        self.inner.active_requests.load(Ordering::Acquire)
    }

    fn idle_since(&self) -> Option<tokio::time::Instant> {
        *self
            .inner
            .idle_since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let notify = Arc::clone(&self.inner.notify);
        Box::pin(async move { notify.notified().await })
    }
}

struct HttpRequestLease {
    activity: HttpConnectionActivity,
}

impl Drop for HttpRequestLease {
    fn drop(&mut self) {
        self.activity.finish();
    }
}

struct TrackedResponseBody {
    inner: Body,
    lease: Option<HttpRequestLease>,
}

impl axum::body::HttpBody for TrackedResponseBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None)) {
            self.lease.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Clone)]
struct HttpConnectionInfo {
    activity: HttpConnectionActivity,
}

async fn track_http_connection(request: Request, next: Next) -> Response {
    let lease = request
        .extensions()
        .get::<axum::extract::ConnectInfo<HttpConnectionInfo>>()
        .map(|info| info.0.activity.begin());
    let response = next.run(request).await;
    match lease {
        Some(lease) => response.map(|inner| {
            Body::new(TrackedResponseBody {
                inner,
                lease: Some(lease),
            })
        }),
        None => response,
    }
}

struct HttpConnectionLimiter {
    slots: Arc<tokio::sync::Semaphore>,
    max_per_source: usize,
    by_source: Mutex<HashMap<IpAddr, usize>>,
}

impl HttpConnectionLimiter {
    fn new(limits: HttpConnectionLimits) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(tokio::sync::Semaphore::new(limits.total)),
            max_per_source: limits.per_source,
            by_source: Mutex::new(HashMap::new()),
        })
    }

    fn try_admit(self: &Arc<Self>, source: IpAddr) -> Result<HttpConnectionPermit, std::io::Error> {
        let global = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "HTTP connection limit reached",
                ),
                tokio::sync::TryAcquireError::Closed => {
                    std::io::Error::other("HTTP connection admission closed")
                }
            })?;
        let mut by_source = self
            .by_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = by_source.entry(source).or_default();
        if *active >= self.max_per_source {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "too many HTTP connections from this source",
            ));
        }
        *active += 1;
        drop(by_source);
        Ok(HttpConnectionPermit {
            _global: global,
            limiter: Arc::clone(self),
            source,
        })
    }
}

struct HttpConnectionPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    limiter: Arc<HttpConnectionLimiter>,
    source: IpAddr,
}

impl Drop for HttpConnectionPermit {
    fn drop(&mut self) {
        let mut by_source = self
            .limiter
            .by_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(active) = by_source.get_mut(&self.source) {
            *active -= 1;
            if *active == 0 {
                by_source.remove(&self.source);
            }
        }
    }
}

struct HttpShutdownState {
    fired: AtomicBool,
    notify: Arc<tokio::sync::Notify>,
}

impl HttpShutdownState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            fired: AtomicBool::new(false),
            notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    fn trigger(&self) {
        if !self.fired.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    fn is_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }

    fn wait(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let notify = Arc::clone(&self.notify);
        Box::pin(async move { notify.notified().await })
    }
}

/// Socket wrapper enforcing admission, absolute request setup, quiescent
/// keep-alive expiry, and force-close shutdown. Active handlers and response
/// bodies are exempt from the idle timer.
struct GuardedIo<T> {
    io: T,
    _permit: HttpConnectionPermit,
    activity: HttpConnectionActivity,
    setup_deadline: Pin<Box<tokio::time::Sleep>>,
    idle_timeout: Duration,
    idle: Option<Pin<Box<tokio::time::Sleep>>>,
    activity_generation: u64,
    activity_wait: Pin<Box<dyn Future<Output = ()> + Send>>,
    shutdown: Arc<HttpShutdownState>,
    shutdown_wait: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl<T> GuardedIo<T> {
    fn with_timeouts(
        io: T,
        permit: HttpConnectionPermit,
        shutdown: Arc<HttpShutdownState>,
        setup_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        let activity = HttpConnectionActivity::default();
        let activity_wait = activity.wait();
        let shutdown_wait = shutdown.wait();
        Self {
            io,
            _permit: permit,
            activity,
            setup_deadline: Box::pin(tokio::time::sleep(setup_timeout)),
            idle_timeout,
            idle: None,
            activity_generation: u64::MAX,
            activity_wait,
            shutdown,
            shutdown_wait,
        }
    }

    fn sync_activity(&mut self) {
        let generation = self.activity.generation();
        if generation == self.activity_generation {
            return;
        }
        self.activity_generation = generation;
        self.idle = if self.activity.setup_complete() && self.activity.active_requests() == 0 {
            self.activity
                .idle_since()
                .map(|since| Box::pin(tokio::time::sleep_until(since + self.idle_timeout)))
        } else {
            None
        };
    }

    fn poll_guards(&mut self, cx: &mut TaskContext<'_>) -> std::io::Result<()> {
        // Always poll a replacement waiter before returning to the wrapped
        // socket. `Notify::notify_waiters` does not retain a permit for an
        // unpolled future: replacing a ready waiter and immediately returning
        // would leave a narrow gap in which a handler can finish without a
        // registered transport waker, so its new idle deadline never fires.
        loop {
            self.sync_activity();
            if self.activity_wait.as_mut().poll(cx).is_pending() {
                break;
            }
            self.activity_wait = self.activity.wait();
        }
        self.sync_activity();

        if self.shutdown.is_fired() || self.shutdown_wait.as_mut().poll(cx).is_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "HTTP server is shutting down",
            ));
        }
        if self.shutdown.is_fired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "HTTP server is shutting down",
            ));
        }
        if !self.activity.setup_complete() && self.setup_deadline.as_mut().poll(cx).is_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP request setup timed out",
            ));
        }
        if let Some(idle) = &mut self.idle {
            if idle.as_mut().poll(cx).is_ready() && self.activity.active_requests() == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP keep-alive connection was idle for too long",
                ));
            }
        }
        Ok(())
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for GuardedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_guards(cx)?;
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for GuardedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_guards(cx)?;
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.poll_guards(cx)?;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_guards(cx)?;
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
}

struct GuardedListener {
    inner: tokio::net::TcpListener,
    limiter: Arc<HttpConnectionLimiter>,
    shutdown: Arc<HttpShutdownState>,
    setup_timeout: Duration,
    idle_timeout: Duration,
}

impl GuardedListener {
    fn with_timeouts(
        inner: tokio::net::TcpListener,
        limits: HttpConnectionLimits,
        shutdown: Arc<HttpShutdownState>,
        setup_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            limiter: HttpConnectionLimiter::new(limits),
            shutdown,
            setup_timeout,
            idle_timeout,
        }
    }
}

impl axum::serve::Listener for GuardedListener {
    type Io = GuardedIo<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (io, address) = axum::serve::Listener::accept(&mut self.inner).await;
            match self.limiter.try_admit(address.ip()) {
                Ok(permit) => {
                    return (
                        GuardedIo::with_timeouts(
                            io,
                            permit,
                            Arc::clone(&self.shutdown),
                            self.setup_timeout,
                            self.idle_timeout,
                        ),
                        address,
                    );
                }
                Err(error) => {
                    tracing::debug!(source = %address.ip(), %error, "refusing HTTP connection");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, GuardedListener>>
    for HttpConnectionInfo
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, GuardedListener>) -> Self {
        Self {
            activity: stream.io().activity.clone(),
        }
    }
}

struct HttpShutdownOnDrop(Arc<HttpShutdownState>);

impl Drop for HttpShutdownOnDrop {
    fn drop(&mut self) {
        self.0.trigger();
    }
}

/// Axum owns the graceful-shutdown future in a detached task. Tell that task
/// to drop the caller's signal future if the outer serve future is cancelled
/// or errors before the signal resolves.
struct SignalCancellationOnDrop(tokio::sync::watch::Sender<bool>);

impl Drop for SignalCancellationOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

struct TaskAbortOnDrop(tokio::task::AbortHandle);

impl Drop for TaskAbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Bind and serve until the process is interrupted, granting no origin but
/// this server's own.
pub async fn serve(control: Arc<Control>, addr: SocketAddr) -> Result<()> {
    serve_with(control, addr, ServerOptions::new()).await
}

/// Bind the read-only content plane (ADR-006).
///
/// It exposes no mutation routes. TLS and distributed rate controls still
/// belong at the deployment proxy for an Internet-facing address.
pub async fn serve_content(
    control: Arc<Control>,
    addr: SocketAddr,
    options: ServerOptions,
) -> Result<()> {
    serve_content_until(control, addr, options, shutdown_signal()).await
}

/// Bind the read-only content plane until `signal` resolves.
pub async fn serve_content_until<F>(
    control: Arc<Control>,
    addr: SocketAddr,
    options: ServerOptions,
    signal: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    validate_http_connection_limits(options.connection_limits)?;
    if !options.allowed_origins.is_empty() {
        let origins: Vec<&str> = options
            .allowed_origins
            .iter()
            .filter_map(|o| o.to_str().ok())
            .collect();
        tracing::info!(origins = ?origins, "content plane granting read-only cross-origin access");
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {}", addr))?;
    let bound = listener.local_addr()?;
    tracing::info!(address = %bound, "dag content plane listening");
    println!("dag content plane listening on http://{}", bound);

    run_http_until(
        listener,
        content_router_with(control, &options),
        options.connection_limits,
        signal,
    )
    .await
}

/// Bind and serve the console until the process is interrupted.
///
/// The server has **no authentication**. Binding anywhere other than loopback
/// without [`ServerOptions::expose_control`] is a hard refusal (ADR-006): a
/// warning is not a control, and `POST /api/gc/run` deletes data. Granting a
/// cross-origin allow-list is warned about because it hands those origins
/// the same unauthenticated API.
pub async fn serve_with(
    control: Arc<Control>,
    addr: SocketAddr,
    options: ServerOptions,
) -> Result<()> {
    serve_with_until(control, addr, options, shutdown_signal()).await
}

/// Bind the console until `signal` resolves, force-closing long-lived
/// transports so shutdown cannot be pinned by SSE or a slow response body.
pub async fn serve_with_until<F>(
    control: Arc<Control>,
    addr: SocketAddr,
    options: ServerOptions,
    signal: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    validate_http_connection_limits(options.connection_limits)?;
    if !addr.ip().is_loopback() && !options.expose_control {
        return Err(ControlPlaneBindRefused { addr }.into());
    }

    if !options.allowed_origins.is_empty() {
        let origins: Vec<&str> = options
            .allowed_origins
            .iter()
            .filter_map(|o| o.to_str().ok())
            .collect();
        tracing::warn!(
            origins = ?origins,
            "granting cross-origin access to an API with no authentication"
        );
        eprintln!(
            "warning: pages on {} may call this API directly. dag serve has no \
             authentication, so those origins get everything the console has.",
            origins.join(", ")
        );
    }

    if !addr.ip().is_loopback() {
        tracing::warn!(
            address = %addr,
            "binding a non-loopback address with --expose-control: this server \
             has no authentication, and POST /api/gc/run deletes data"
        );
        eprintln!(
            "warning: {} is not loopback and --expose-control is set. dag serve \
             has no authentication — anyone who can reach this port can delete \
             data. Put a proxy in front of it.",
            addr
        );
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {}", addr))?;

    let bound = listener.local_addr()?;
    tracing::info!(address = %bound, "dag console listening");
    println!("dag console listening on http://{}", bound);

    // Owned here so the scan stops when the server does, rather than outliving
    // it as a detached task.
    let scan = integrity::spawn_integrity_scan(Arc::clone(&control), INTEGRITY_SCAN_INTERVAL);
    let _scan_abort_on_drop = TaskAbortOnDrop(scan.abort_handle());

    // Trigger policies are operational promises, not labels. The same
    // long-lived process that owns the data-directory lock drains the durable
    // trigger queue and executes leased Pending runs. It grants no optional
    // capabilities, so an `exec` spec remains unreachable from this
    // unauthenticated HTTP surface.
    let (worker_stop, mut worker_stopped) = tokio::sync::watch::channel(false);
    let worker_control = Arc::clone(&control);
    let worker = tokio::spawn(async move {
        dag_jobs::run_worker_until(
            worker_control,
            dag_jobs::WorkerOptions::default(),
            dag_jobs::Capabilities::none(),
            async move {
                while !*worker_stopped.borrow() {
                    if worker_stopped.changed().await.is_err() {
                        break;
                    }
                }
            },
        )
        .await
    });

    let stop_on_signal = worker_stop.clone();
    let graceful = async move {
        signal.await;
        let _ = stop_on_signal.send(true);
    };

    let result = run_http_until(
        listener,
        router_with(control, &options),
        options.connection_limits,
        graceful,
    )
    .await;

    scan.abort();
    let _ = worker_stop.send(true);
    match worker.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(%error, "background job worker stopped"),
        Err(error) if error.is_cancelled() => {}
        Err(error) => tracing::error!(%error, "background job worker task failed"),
    }
    result
}

async fn run_http_until<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    limits: HttpConnectionLimits,
    signal: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    run_http_until_with_timeouts(
        listener,
        app,
        limits,
        HTTP_CONNECTION_SETUP_TIMEOUT,
        HTTP_CONNECTION_IDLE_TIMEOUT,
        signal,
    )
    .await
}

async fn run_http_until_with_timeouts<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    limits: HttpConnectionLimits,
    setup_timeout: Duration,
    idle_timeout: Duration,
    signal: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    validate_http_connection_limits(limits)?;
    let shutdown = HttpShutdownState::new();
    let _shutdown_on_drop = HttpShutdownOnDrop(Arc::clone(&shutdown));
    let (signal_cancel, mut signal_cancelled) = tokio::sync::watch::channel(false);
    let _signal_cancellation_on_drop = SignalCancellationOnDrop(signal_cancel);
    let graceful_shutdown = Arc::clone(&shutdown);
    let listener =
        GuardedListener::with_timeouts(listener, limits, shutdown, setup_timeout, idle_timeout);
    let app = app.into_make_service_with_connect_info::<HttpConnectionInfo>();

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                () = signal => graceful_shutdown.trigger(),
                () = async move {
                    while !*signal_cancelled.borrow() {
                        if signal_cancelled.changed().await.is_err() {
                            break;
                        }
                    }
                } => {}
            }
        })
        .await
        .context("server error")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

/// `GET /health`: process liveness only.
async fn liveness() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "check": "liveness",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// `GET /api/health`: readiness, including bounded control/store reads.
async fn readiness(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> error::ApiResult<Json<serde_json::Value>> {
    blocking::on_blocking_pool(&state, |control| {
        let stats = control.stats()?;
        Ok(Json(serde_json::json!({
            "status": "ok",
            "check": "readiness",
            "version": env!("CARGO_PKG_VERSION"),
            "recovered": stats.recovered,
        })))
    })
    .await
}

/// `GET /api/stats`
async fn stats(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> error::ApiResult<Json<dag_control::ControlStats>> {
    // Reads the maintained index/table counters rather than scanning content.
    blocking::on_blocking_pool(&state, |control| Ok(Json(control.stats()?))).await
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start_http(
        app: Router,
        limits: HttpConnectionLimits,
        setup_timeout: Duration,
        idle_timeout: Duration,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(run_http_until_with_timeouts(
            listener,
            app,
            limits,
            setup_timeout,
            idle_timeout,
            async move {
                let _ = shutdown_rx.await;
            },
        ));
        (address, shutdown_tx, server)
    }

    async fn request_to_end(address: SocketAddr, path: &str) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .expect("HTTP response did not finish")
            .unwrap();
        response
    }

    async fn read_headers(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !response.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buffer = [0u8; 512];
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0, "connection closed before response headers");
                response.extend_from_slice(&buffer[..read]);
                assert!(response.len() <= 16 * 1024, "response headers too large");
            }
        })
        .await
        .expect("response headers did not arrive");
        response
    }

    #[tokio::test]
    async fn admitted_content_body_holds_its_permit_and_frames_bytes() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().acquire_owned().await.unwrap();
        let bytes = Bytes::from(vec![7u8; CONTENT_RESPONSE_FRAME_BYTES * 2 + 1]);
        let mut body = admitted_bytes_body(bytes, permit);
        assert_eq!(slots.available_permits(), 0);

        let first = body
            .frame()
            .await
            .expect("one body frame")
            .expect("valid body frame")
            .into_data()
            .expect("data frame");
        assert_eq!(first.len(), CONTENT_RESPONSE_FRAME_BYTES);
        assert_eq!(slots.available_permits(), 0);

        drop(body);
        assert_eq!(slots.available_permits(), 1);
    }

    async fn guarded_io(
        setup_timeout: Duration,
        idle_timeout: Duration,
    ) -> (
        GuardedIo<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Arc<HttpConnectionLimiter>,
        Arc<HttpShutdownState>,
    ) {
        let limiter = HttpConnectionLimiter::new(HttpConnectionLimits {
            total: 1,
            per_source: 1,
        });
        let permit = limiter.try_admit("127.0.0.1".parse().unwrap()).unwrap();
        let shutdown = HttpShutdownState::new();
        let (io, peer) = tokio::io::duplex(64);
        (
            GuardedIo::with_timeouts(
                io,
                permit,
                Arc::clone(&shutdown),
                setup_timeout,
                idle_timeout,
            ),
            peer,
            limiter,
            shutdown,
        )
    }

    struct FinishLeaseOnRead {
        lease: Option<HttpRequestLease>,
    }

    impl tokio::io::AsyncRead for FinishLeaseOnRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.lease.take();
            Poll::Pending
        }
    }

    struct WakeCounter(AtomicUsize);

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct DropSignalSentinel(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignalSentinel {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn replacement_activity_waiter_is_armed_before_polling_the_socket() {
        let limiter = HttpConnectionLimiter::new(HttpConnectionLimits {
            total: 1,
            per_source: 1,
        });
        let permit = limiter.try_admit("127.0.0.1".parse().unwrap()).unwrap();
        let shutdown = HttpShutdownState::new();
        let mut guarded = GuardedIo::with_timeouts(
            FinishLeaseOnRead { lease: None },
            permit,
            shutdown,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let wakes = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut cx = TaskContext::from_waker(&waker);
        let mut byte = [0u8; 1];
        let mut buffer = tokio::io::ReadBuf::new(&mut byte);

        // First poll registers the original activity waiter.
        assert!(
            tokio::io::AsyncRead::poll_read(Pin::new(&mut guarded), &mut cx, &mut buffer,)
                .is_pending()
        );

        // `begin` makes that waiter ready. During the next underlying socket
        // poll, dropping the lease sends a second notification. The newly
        // installed waiter must already be registered to observe it.
        let lease = guarded.activity.begin();
        wakes.0.store(0, Ordering::Relaxed);
        guarded.io.lease = Some(lease);
        let mut buffer = tokio::io::ReadBuf::new(&mut byte);
        assert!(
            tokio::io::AsyncRead::poll_read(Pin::new(&mut guarded), &mut cx, &mut buffer,)
                .is_pending()
        );
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn pending_header_read_is_woken_by_absolute_setup_deadline() {
        let (mut guarded, _peer, limiter, _shutdown) =
            guarded_io(Duration::from_millis(10), Duration::from_secs(60)).await;
        let mut byte = [0u8; 1];
        let error = tokio::time::timeout(Duration::from_millis(100), guarded.read(&mut byte))
            .await
            .expect("setup deadline must wake a pending read")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(limiter.slots.available_permits(), 0);
        drop(guarded);
        assert_eq!(limiter.slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn active_request_is_not_cut_off_but_quiescent_keepalive_expires() {
        use tokio::io::AsyncWriteExt;

        let (mut guarded, mut peer, _limiter, _shutdown) =
            guarded_io(Duration::from_millis(10), Duration::from_millis(10)).await;
        let lease = guarded.activity.begin();
        tokio::time::sleep(Duration::from_millis(30)).await;
        peer.write_all(b"x").await.unwrap();
        let mut byte = [0u8; 1];
        guarded.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");

        drop(lease);
        let error = tokio::time::timeout(Duration::from_millis(100), guarded.read(&mut byte))
            .await
            .expect("idle deadline must wake a quiescent read")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn shutdown_wakes_an_active_transport() {
        let (mut guarded, _peer, _limiter, shutdown) =
            guarded_io(Duration::from_secs(60), Duration::from_secs(60)).await;
        let _lease = guarded.activity.begin();
        let trigger = Arc::clone(&shutdown);
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            trigger.trigger();
        });
        let mut byte = [0u8; 1];
        let error = tokio::time::timeout(Duration::from_millis(100), guarded.read(&mut byte))
            .await
            .expect("shutdown must wake a pending active transport")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn aborting_server_drops_the_detached_graceful_signal_future() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(track_http_connection));
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let sentinel = DropSignalSentinel(Some(dropped_tx));
        let signal = async move {
            let _sentinel = sentinel;
            std::future::pending::<()>().await;
        };
        let server = tokio::spawn(run_http_until_with_timeouts(
            listener,
            app,
            HttpConnectionLimits {
                total: 2,
                per_source: 2,
            },
            Duration::from_secs(5),
            Duration::from_secs(60),
            signal,
        ));

        let response = request_to_end(address, "/health").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("detached graceful signal survived outer cancellation")
            .expect("signal sentinel sender was dropped without notification");
    }

    #[tokio::test]
    async fn aborting_console_releases_background_control_ownership() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);

        let directory = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(directory.path()).unwrap());
        let weak_control = Arc::downgrade(&control);
        let server_control = Arc::clone(&control);
        let server = tokio::spawn(serve_with_until(
            server_control,
            address,
            ServerOptions::new(),
            std::future::pending(),
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match tokio::net::TcpStream::connect(address).await {
                    Ok(stream) => {
                        drop(stream);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("connecting to test console: {error}"),
                }
            }
        })
        .await
        .expect("test console did not start");

        drop(control);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while weak_control.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled console left a background task holding the Control");
    }

    #[tokio::test]
    async fn one_http_source_cannot_consume_global_admission() {
        let limiter = HttpConnectionLimiter::new(HttpConnectionLimits {
            total: 2,
            per_source: 1,
        });
        let first = limiter.try_admit("192.0.2.1".parse().unwrap()).unwrap();
        let refused = match limiter.try_admit("192.0.2.1".parse().unwrap()) {
            Ok(_) => panic!("one source exceeded its HTTP connection share"),
            Err(error) => error,
        };
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        let other = limiter.try_admit("192.0.2.2".parse().unwrap()).unwrap();
        drop((first, other));
        assert_eq!(limiter.slots.available_permits(), 2);
    }

    #[test]
    fn invalid_http_limits_cannot_panic_the_semaphore() {
        for limits in [
            HttpConnectionLimits {
                total: 0,
                per_source: 0,
            },
            HttpConnectionLimits {
                total: 4,
                per_source: 5,
            },
            HttpConnectionLimits {
                total: tokio::sync::Semaphore::MAX_PERMITS + 1,
                per_source: 1,
            },
        ] {
            assert!(validate_http_connection_limits(limits).is_err());
        }
    }

    #[tokio::test]
    async fn real_listener_refuses_slow_headers_but_keeps_serving() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(track_http_connection));
        let limits = HttpConnectionLimits {
            total: 4,
            per_source: 2,
        };
        let (address, shutdown, server) = start_http(
            app,
            limits,
            Duration::from_millis(30),
            Duration::from_secs(60),
        )
        .await;

        let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
        slow.write_all(b"G").await.unwrap();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(500), slow.read(&mut byte))
            .await
            .expect("absolute setup deadline did not close a slow header");
        assert!(matches!(closed, Ok(0) | Err(_)));

        let response = request_to_end(address, "/health").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn real_listener_preserves_slow_active_handler() {
        let app = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    "finished"
                }),
            )
            .layer(axum::middleware::from_fn(track_http_connection));
        let (address, shutdown, server) = start_http(
            app,
            HttpConnectionLimits {
                total: 2,
                per_source: 2,
            },
            Duration::from_millis(20),
            Duration::from_millis(20),
        )
        .await;

        let response = request_to_end(address, "/slow").await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected response: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"finished"));
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn real_listener_per_source_refusal_does_not_stop_accepting() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(track_http_connection));
        let (address, shutdown, server) = start_http(
            app,
            HttpConnectionLimits {
                total: 3,
                per_source: 2,
            },
            Duration::from_secs(5),
            Duration::from_secs(60),
        )
        .await;
        let first = tokio::net::TcpStream::connect(address).await.unwrap();
        let second = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut refused = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(500), refused.read(&mut byte))
            .await
            .expect("per-source overflow was not refused");
        assert!(matches!(closed, Ok(0) | Err(_)));

        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let response = request_to_end(address, "/health").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        drop(second);
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn real_listener_refuses_aggregate_overflow_without_queuing_a_socket() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(track_http_connection));
        let (address, shutdown, server) = start_http(
            app,
            HttpConnectionLimits {
                total: 1,
                per_source: 1,
            },
            Duration::from_secs(5),
            Duration::from_secs(60),
        )
        .await;
        let first = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut refused = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_millis(500), refused.read(&mut byte))
            .await
            .expect("aggregate overflow was queued instead of refused");
        assert!(matches!(closed, Ok(0) | Err(_)));

        drop(first);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let response = request_to_end(address, "/health").await;
        assert!(response.starts_with(b"HTTP/1.1 200"));
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn real_listener_shutdown_closes_an_active_sse_body() {
        let directory = tempfile::tempdir().unwrap();
        let control = Arc::new(Control::open(directory.path()).unwrap());
        let (address, shutdown, server) = start_http(
            router(control),
            HttpConnectionLimits {
                total: 4,
                per_source: 4,
            },
            Duration::from_secs(5),
            Duration::from_secs(60),
        )
        .await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /api/events/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let headers = read_headers(&mut stream).await;
        assert!(headers.starts_with(b"HTTP/1.1 200"));

        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("active SSE prevented bounded shutdown")
            .unwrap()
            .unwrap();
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut remaining))
            .await
            .expect("SSE transport remained open after server shutdown")
            .unwrap();
    }
}
