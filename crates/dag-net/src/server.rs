//! The node server: one process, one data directory, one authenticated port.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use dag_control::Control;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::auth::{AuthScope, ConnectionSetup, CredentialSet, RequireToken};
use crate::error::NetError;
use crate::events_service::EventsService;
use crate::pointer_service::PointersService;
use crate::proto;
use crate::proto::events_server::EventsServer;
use crate::proto::node_server::{Node, NodeServer};
use crate::proto::pointers_server::PointersServer;
use crate::proto::sync_server::SyncServer;
use crate::sync_service::SyncService;

/// Process-wide admission for synchronous node-protocol work.
///
/// Tokio's blocking pool is intentionally large. A credentialed peer must not
/// be able to fill it with Missing, Stat, probe, import or finalize calls and
/// starve unrelated filesystem users in this process.
const MAX_BLOCKING_OPERATIONS: usize = 32;
/// Process-wide ceiling on accepted node-protocol connections.
const DEFAULT_MAX_CONNECTIONS: usize = 128;
/// One source address cannot consume the whole process-wide connection pool.
const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 16;
/// HTTP/2 streams one peer connection may keep active concurrently.
const MAX_STREAMS_PER_CONNECTION: u32 = 64;
/// Tower-level requests admitted concurrently on one connection.
const MAX_REQUESTS_PER_CONNECTION: usize = 32;
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// TLS, the HTTP/2 preface, authentication and the first authorized request
/// share a short, non-resettable setup budget.
const CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LIVE_EVENT_STREAMS: usize = 32;
static BLOCKING_SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

fn blocking_slots() -> Arc<tokio::sync::Semaphore> {
    BLOCKING_SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_OPERATIONS)))
        .clone()
}

struct ConnectionLimiter {
    slots: Arc<tokio::sync::Semaphore>,
    max_per_source: usize,
    by_source: Mutex<HashMap<IpAddr, usize>>,
}

impl ConnectionLimiter {
    fn new(max_connections: usize, max_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(tokio::sync::Semaphore::new(max_connections)),
            max_per_source,
            by_source: Mutex::new(HashMap::new()),
        })
    }

    async fn admit(self: &Arc<Self>, source: IpAddr) -> std::io::Result<ConnectionPermit> {
        let global = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("node connection admission closed"))?;
        let mut by_source = self
            .by_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = by_source.entry(source).or_default();
        if *active >= self.max_per_source {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "too many node connections from this source",
            ));
        }
        *active += 1;
        drop(by_source);
        Ok(ConnectionPermit {
            _global: global,
            limiter: Arc::clone(self),
            source,
        })
    }

    fn close(&self) {
        self.slots.close();
    }
}

struct ConnectionPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    limiter: Arc<ConnectionLimiter>,
    source: IpAddr,
}

impl Drop for ConnectionPermit {
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

struct ShutdownState {
    fired: AtomicBool,
    notify: Arc<tokio::sync::Notify>,
    connections: Arc<ConnectionLimiter>,
}

impl ShutdownState {
    fn new(connections: Arc<ConnectionLimiter>) -> Arc<Self> {
        Arc::new(Self {
            fired: AtomicBool::new(false),
            notify: Arc::new(tokio::sync::Notify::new()),
            connections,
        })
    }

    fn trigger(&self) {
        if !self.fired.swap(true, Ordering::AcqRel) {
            self.connections.close();
            self.notify.notify_waiters();
        }
    }

    fn is_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }

    fn wait(self: &Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let state = Arc::clone(self);
        Box::pin(async move {
            loop {
                let notified = state.notify.notified();
                if state.is_fired() {
                    return;
                }
                notified.await;
                if state.is_fired() {
                    return;
                }
            }
        })
    }
}

/// An accepted transport that returns its global and per-source connection
/// slots only when the entire HTTP/2 connection is gone.
struct AdmittedIo<T> {
    io: T,
    _permit: ConnectionPermit,
    setup: ConnectionSetup,
    setup_deadline: Pin<Box<tokio::time::Sleep>>,
    shutdown: Arc<ShutdownState>,
    shutdown_wait: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl<T> AdmittedIo<T> {
    fn new(io: T, permit: ConnectionPermit, shutdown: Arc<ShutdownState>) -> Self {
        Self::with_setup_timeout(io, permit, shutdown, CONNECTION_SETUP_TIMEOUT)
    }

    fn with_setup_timeout(
        io: T,
        permit: ConnectionPermit,
        shutdown: Arc<ShutdownState>,
        setup_timeout: Duration,
    ) -> Self {
        let shutdown_wait = shutdown.wait();
        Self {
            io,
            _permit: permit,
            setup: ConnectionSetup::default(),
            setup_deadline: Box::pin(tokio::time::sleep(setup_timeout)),
            shutdown,
            shutdown_wait,
        }
    }

    fn poll_guards(&mut self, cx: &mut TaskContext<'_>) -> std::io::Result<()> {
        if self.shutdown.is_fired() || self.shutdown_wait.as_mut().poll(cx).is_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "node server is shutting down",
            ));
        }
        // Close the small race between checking the atomic flag and
        // registering the notification future's waker.
        if self.shutdown.is_fired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "node server is shutting down",
            ));
        }
        if !self.setup.is_complete() && self.setup_deadline.as_mut().poll(cx).is_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "node connection setup timed out",
            ));
        }
        Ok(())
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for AdmittedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_guards(cx)?;
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for AdmittedIo<T> {
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

impl<T> tonic::transport::server::Connected for AdmittedIo<T> {
    type ConnectInfo = ConnectionSetup;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.setup.clone()
    }
}

/// How the node port should be served.
#[derive(Debug, Clone, Default)]
pub struct ServeOptions {
    /// Current and optional previous scoped bearer credentials.
    ///
    /// Optional only for loopback binds; [`bind`] refuses a non-loopback
    /// address without credentials, before any socket opens.
    pub credentials: CredentialSet,
    /// Serve TLS from this certificate and key.
    ///
    /// Without it the port is plaintext HTTP/2 and is restricted to loopback
    /// unless [`Self::allow_insecure_transport`] is explicitly set.
    pub tls: Option<TlsIdentity>,
    /// Permit a non-loopback plaintext listener for remote development.
    ///
    /// This is intentionally separate from authentication: a bearer token
    /// does not encrypt its own transport.
    pub allow_insecure_transport: bool,
    /// Aggregate and per-source TCP connection admission.
    ///
    /// Tune the per-source share when a trusted L4 proxy makes many clients
    /// appear under one peer address.
    pub connection_limits: ConnectionLimits,
}

/// Node-port TCP admission limits.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// Total established and handshaking connections.
    pub total: usize,
    /// Connections attributed to one `peer_addr()` IP.
    pub per_source: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            total: DEFAULT_MAX_CONNECTIONS,
            per_source: DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
        }
    }
}

/// A PEM certificate chain and private key for the server side of TLS.
#[derive(Clone)]
pub struct TlsIdentity {
    /// PEM-encoded certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key.
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key stays out of Debug output on purpose.
        f.debug_struct("TlsIdentity")
            .field("cert_pem", &format_args!("[{} bytes]", self.cert_pem.len()))
            .field("key_pem", &format_args!("[redacted]"))
            .finish()
    }
}

/// A bound but not yet running node server.
///
/// Splitting bind from serve is what makes the port knowable: tests (and
/// `--listen 127.0.0.1:0`) learn the actual address before the accept loop
/// starts.
pub struct Bound {
    /// The address actually bound — the resolved port when `:0` was asked for.
    pub local_addr: SocketAddr,
    driver: Pin<Box<dyn Future<Output = Result<(), NetError>> + Send>>,
    shutdown: Option<ShutdownOnDrop>,
}

impl Bound {
    /// Run the accept loop until the process ends or the transport fails.
    /// Dropping this future also force-closes established connections.
    pub async fn serve(mut self) -> Result<(), NetError> {
        let _shutdown = self.shutdown.take().expect("bound server shutdown guard");
        self.driver.await
    }

    /// Run until `signal` resolves, then stop admission and close every
    /// established connection before returning.
    pub async fn serve_until<F>(mut self, signal: F) -> Result<(), NetError>
    where
        F: Future<Output = ()>,
    {
        let mut shutdown = self.shutdown.take().expect("bound server shutdown guard");
        let mut driver = self.driver;
        tokio::pin!(signal);
        tokio::select! {
            result = &mut driver => result,
            () = &mut signal => {
                shutdown.trigger();
                driver.await
            }
        }
    }
}

struct ShutdownOnDrop {
    state: Arc<ShutdownState>,
    tonic: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ShutdownOnDrop {
    fn trigger(&mut self) {
        self.state.trigger();
        if let Some(tonic) = self.tonic.take() {
            let _ = tonic.send(());
        }
    }
}

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.trigger();
    }
}

/// Bind the node protocol on `addr` and return the running-ready server.
///
/// Refuses both unauthenticated and plaintext non-loopback binds by default.
/// The node protocol can write chunks and file history, so neither posture is
/// reachable by accident.
pub async fn bind(
    control: Arc<Control>,
    addr: SocketAddr,
    opts: ServeOptions,
) -> Result<Bound, NetError> {
    validate_connection_limits(opts.connection_limits)?;
    if !addr.ip().is_loopback() && opts.tls.is_none() && !opts.allow_insecure_transport {
        return Err(NetError::InsecureTransportRefused {
            destination: addr.to_string(),
        });
    }
    if !addr.ip().is_loopback() && opts.credentials.is_empty() {
        return Err(NetError::CredentialsRequired { addr });
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| NetError::io(format!("binding {addr}"), e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| NetError::io("resolving bound address", e))?;

    let mut builder = Server::builder()
        .max_concurrent_streams(Some(MAX_STREAMS_PER_CONNECTION))
        .concurrency_limit_per_connection(MAX_REQUESTS_PER_CONNECTION)
        .load_shed(true)
        .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(HTTP2_KEEPALIVE_TIMEOUT))
        .http2_max_pending_accept_reset_streams(Some(MAX_STREAMS_PER_CONNECTION as usize))
        .http2_max_header_list_size(Some(16 * 1024));
    if let Some(identity) = &opts.tls {
        let identity = tonic::transport::Identity::from_pem(&identity.cert_pem, &identity.key_pem);
        builder = builder
            .tls_config(
                tonic::transport::ServerTlsConfig::new()
                    .identity(identity)
                    .timeout(CONNECTION_SETUP_TIMEOUT),
            )
            .map_err(NetError::Transport)?;
    }

    let read_auth = RequireToken::new(opts.credentials.clone(), AuthScope::Read);
    let sync_auth = RequireToken::new(opts.credentials.clone(), AuthScope::Sync);
    let pointer_auth = RequireToken::new(opts.credentials.clone(), AuthScope::Pointer);
    let events_auth = RequireToken::new(opts.credentials, AuthScope::Events);
    let node = NodeService {
        control: control.clone(),
    };

    let staging = Arc::new(
        control
            .staging_store()
            .map_err(|e| NetError::io("opening staging store", std::io::Error::other(e)))?,
    );
    let sync = SyncService {
        control: control.clone(),
        staging,
        enumerate_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        get_chunk_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        put_chunk_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        import_sessions: Arc::new(crate::sync_service::ImportSessions::default()),
    };
    let pointers = PointersService {
        control: control.clone(),
    };
    let events = EventsService {
        control: control.clone(),
        replay_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        stream_slots: Arc::new(tokio::sync::Semaphore::new(MAX_LIVE_EVENT_STREAMS)),
    };

    let router = builder
        .add_service(NodeServer::with_interceptor(node, read_auth))
        .add_service(SyncServer::with_interceptor(sync, sync_auth))
        .add_service(PointersServer::with_interceptor(pointers, pointer_auth))
        .add_service(tonic::service::interceptor::InterceptedService::new(
            EventsServer::new(events)
                .max_decoding_message_size(crate::events_service::MAX_SUBSCRIBE_REQUEST_BYTES)
                .max_encoding_message_size(crate::events_service::MAX_EVENT_RESPONSE_BYTES),
            events_auth,
        ));

    let connections = ConnectionLimiter::new(
        opts.connection_limits.total,
        opts.connection_limits.per_source,
    );
    let shutdown_state = ShutdownState::new(Arc::clone(&connections));
    let incoming_shutdown = Arc::clone(&shutdown_state);
    let incoming = TcpListenerStream::new(listener)
        .then(move |accepted| {
            let connections = Arc::clone(&connections);
            let shutdown_state = Arc::clone(&incoming_shutdown);
            async move {
                let io = match accepted {
                    Ok(io) => io,
                    Err(error) => return Some(Err(error)),
                };
                let source = match io.peer_addr() {
                    Ok(address) => address.ip(),
                    Err(error) => {
                        tracing::debug!(%error, "dropping node connection without a peer address");
                        return None;
                    }
                };
                match connections.admit(source).await {
                    Ok(permit) => Some(Ok::<_, std::io::Error>(AdmittedIo::new(
                        io,
                        permit,
                        shutdown_state,
                    ))),
                    Err(error) => {
                        // Admission refusal belongs to this socket. Yielding it
                        // as an incoming error would make Tonic terminate the
                        // entire listener for several ordinary error kinds.
                        tracing::debug!(%source, %error, "refusing node connection");
                        None
                    }
                }
            }
        })
        .filter_map(std::convert::identity);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let driver = Box::pin(async move {
        router
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .map_err(NetError::Transport)
    });

    Ok(Bound {
        local_addr,
        driver,
        shutdown: Some(ShutdownOnDrop {
            state: shutdown_state,
            tonic: Some(shutdown_tx),
        }),
    })
}

fn validate_connection_limits(limits: ConnectionLimits) -> Result<(), NetError> {
    if limits.total == 0
        || limits.per_source == 0
        || limits.per_source > limits.total
        || limits.total > tokio::sync::Semaphore::MAX_PERMITS
    {
        return Err(NetError::InvalidServerConfig {
            reason: format!(
                "connection limits require 1 <= per_source ({}) <= total ({}) <= {}",
                limits.per_source,
                limits.total,
                tokio::sync::Semaphore::MAX_PERMITS
            ),
        });
    }
    Ok(())
}

/// Bind and run in one call — the `dag node serve` entry point.
pub async fn serve(
    control: Arc<Control>,
    addr: SocketAddr,
    opts: ServeOptions,
) -> Result<(), NetError> {
    let bound = bind(control, addr, opts).await?;
    tracing::info!(addr = %bound.local_addr, "node protocol listening");
    bound.serve().await
}

/// Bind and run until `signal` resolves, force-closing established RPCs.
pub async fn serve_until<F>(
    control: Arc<Control>,
    addr: SocketAddr,
    opts: ServeOptions,
    signal: F,
) -> Result<(), NetError>
where
    F: Future<Output = ()>,
{
    let bound = bind(control, addr, opts).await?;
    tracing::info!(addr = %bound.local_addr, "node protocol listening");
    bound.serve_until(signal).await
}

/// Run admitted blocking work off the async worker.
pub(crate) async fn on_blocking<T, F>(work: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Status> + Send + 'static,
{
    on_blocking_with(blocking_slots(), work).await
}

async fn on_blocking_with<T, F>(slots: Arc<tokio::sync::Semaphore>, work: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Status> + Send + 'static,
{
    let permit = slots.try_acquire_owned().map_err(|_| {
        Status::resource_exhausted("too many concurrent node operations; retry later")
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "node blocking worker failed");
        Status::internal("node worker failed")
    })?
}

/// Run a blocking control-plane closure off the async worker.
///
/// The node services wrap synchronous redb and filesystem work; holding a
/// tonic worker for the duration would stall every other stream on it — the
/// same defect the HTTP handlers had before `dag_api::blocking`. `Arc` makes
/// the `'static` bound of `spawn_blocking` free here, unlike the job runner's
/// borrowed case that forced `block_in_place` in `dag_control::blocking`.
pub(crate) async fn on_control<T, F>(control: &Arc<Control>, work: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce(&Control) -> Result<T, Status> + Send + 'static,
{
    let control = control.clone();
    on_blocking(move || work(&control)).await
}

#[derive(Clone)]
struct NodeService {
    control: Arc<Control>,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn info(
        &self,
        _request: Request<proto::InfoRequest>,
    ) -> Result<Response<proto::InfoResponse>, Status> {
        let stats = on_control(&self.control, |control| {
            control.stats().map_err(|error| {
                tracing::error!(%error, "reading node statistics failed");
                Status::internal("node statistics are unavailable")
            })
        })
        .await?;

        Ok(Response::new(proto::InfoResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: dag_control::SCHEMA_VERSION,
            chunks: stats.chunks as u64,
            bytes: stats.bytes,
            pointers: stats.pointers as u64,
            pins: stats.pins as u64,
            recovered: stats.recovered,
            protocol_major: crate::PROTOCOL_MAJOR,
            protocol_minor: crate::PROTOCOL_MINOR,
            capabilities: crate::protocol_capabilities(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocking_admission_refuses_saturation_and_recovers() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let held = slots.clone().try_acquire_owned().unwrap();

        let refused = on_blocking_with(slots.clone(), || Ok::<_, Status>(7)).await;
        assert_eq!(refused.unwrap_err().code(), tonic::Code::ResourceExhausted);

        drop(held);
        assert_eq!(
            on_blocking_with(slots, || Ok::<_, Status>(7))
                .await
                .unwrap(),
            7
        );
    }

    #[test]
    fn connection_limit_validation_prevents_semaphore_panics() {
        assert!(validate_connection_limits(ConnectionLimits::default()).is_ok());
        for limits in [
            ConnectionLimits {
                total: 0,
                per_source: 0,
            },
            ConnectionLimits {
                total: 4,
                per_source: 5,
            },
            ConnectionLimits {
                total: tokio::sync::Semaphore::MAX_PERMITS + 1,
                per_source: 1,
            },
        ] {
            assert!(matches!(
                validate_connection_limits(limits),
                Err(NetError::InvalidServerConfig { .. })
            ));
        }
    }

    #[tokio::test]
    async fn connection_admission_lives_with_the_io() {
        let connections = ConnectionLimiter::new(1, 1);
        let shutdown = ShutdownState::new(Arc::clone(&connections));
        let permit = connections
            .admit("127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let (io, _peer) = tokio::io::duplex(64);
        let admitted = AdmittedIo::new(io, permit, shutdown);
        assert_eq!(connections.slots.available_permits(), 0);
        drop(admitted);
        assert_eq!(connections.slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn pending_setup_read_is_woken_by_its_deadline_and_releases_its_slot() {
        use tokio::io::AsyncReadExt;

        let connections = ConnectionLimiter::new(1, 1);
        let shutdown = ShutdownState::new(Arc::clone(&connections));
        let permit = connections
            .admit("127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let (io, _peer) = tokio::io::duplex(64);
        let mut admitted =
            AdmittedIo::with_setup_timeout(io, permit, shutdown, Duration::from_millis(10));
        let error = tokio::time::timeout(Duration::from_millis(100), admitted.read(&mut [0u8; 1]))
            .await
            .expect("the setup timer must wake a pending read")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(connections.slots.available_permits(), 0);
        drop(admitted);
        assert_eq!(connections.slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn authorized_setup_disarms_the_non_resettable_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let connections = ConnectionLimiter::new(1, 1);
        let shutdown = ShutdownState::new(Arc::clone(&connections));
        let permit = connections
            .admit("127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let (io, mut peer) = tokio::io::duplex(64);
        let mut admitted =
            AdmittedIo::with_setup_timeout(io, permit, shutdown, Duration::from_millis(10));
        admitted.setup.complete();
        tokio::time::sleep(Duration::from_millis(30)).await;
        peer.write_all(b"x").await.unwrap();
        let mut byte = [0u8; 1];
        admitted.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
    }

    #[tokio::test]
    async fn shutdown_wakes_established_io_and_closes_admission() {
        use tokio::io::AsyncReadExt;

        let connections = ConnectionLimiter::new(1, 1);
        let shutdown = ShutdownState::new(Arc::clone(&connections));
        let permit = connections
            .admit("127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let (io, _peer) = tokio::io::duplex(64);
        let mut admitted = AdmittedIo::new(io, permit, Arc::clone(&shutdown));
        admitted.setup.complete();

        let trigger = Arc::clone(&shutdown);
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            trigger.trigger();
        });
        let error = tokio::time::timeout(Duration::from_millis(100), admitted.read(&mut [0u8; 1]))
            .await
            .expect("shutdown must wake a pending read")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(connections
            .admit("127.0.0.2".parse().unwrap())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn one_source_cannot_consume_the_global_connection_pool() {
        let connections =
            ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS_PER_SOURCE);
        let source = "192.0.2.1".parse().unwrap();
        let mut held = Vec::new();
        for _ in 0..DEFAULT_MAX_CONNECTIONS_PER_SOURCE {
            held.push(connections.admit(source).await.unwrap());
        }
        let refused = match connections.admit(source).await {
            Ok(_) => panic!("one source consumed more than its connection share"),
            Err(error) => error,
        };
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        held.push(
            connections
                .admit("192.0.2.2".parse().unwrap())
                .await
                .unwrap(),
        );
    }
}
