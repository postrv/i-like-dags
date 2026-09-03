//! # dag-net — the authenticated node protocol (ADR-005)
//!
//! gRPC between dag nodes: replication (the ADR-002 sync engine over a
//! network), pointer reads and compare-and-set updates, and the event
//! stream. This is the surface *other nodes* talk to; the HTTP API in
//! `dag-api` remains the surface humans and the console talk to, and the
//! two do not know about each other.
//!
//! Two rules carried over from the rest of the system:
//!
//! - **The destination validates.** Atomic event publication runs the same
//!   incremental history, closure, and derived-index checks as directory sync,
//!   in the destination's own process. The wire carries offers, never authority.
//! - **Deny by default.** No job/spec management, direct execution, GC, or
//!   trust operations are exposed. A pointer update can enqueue an existing
//!   destination-configured subscription only when its credential has both
//!   `pointer` and `trigger`; executing an `exec` job additionally requires the
//!   destination operator's local worker capability.
//!   Sync does not enqueue jobs, but Commit also needs `trigger` when its
//!   atomic plan advances an actively subscribed pointer.
//!
//! Non-loopback serving requires TLS and scoped bearer credentials by default;
//! see [`ServeOptions`].

pub mod auth;
mod client;
mod error;
mod events_service;
mod pointer_service;
pub mod proto;
mod server;
pub mod sync;
mod sync_service;

pub use auth::{AuthScope, CredentialSet, ServerCredential};
pub use client::{ConnectOptions, RemoteEventPage, RemoteNode};
pub use error::NetError;
pub use server::{bind, serve, serve_until, Bound, ConnectionLimits, ServeOptions, TlsIdentity};
pub use sync_service::CHUNK_FRAME_BYTES;

/// Default and maximum number of events materialized for one remote replay.
/// A request using the implicit (`0`) limit ends with an explicit gRPC error
/// if older matching events were omitted by this ceiling.
pub const MAX_REMOTE_EVENT_REPLAY_EVENTS: usize = 500;

/// Wire compatibility negotiated before any replication bytes move.
pub const PROTOCOL_MAJOR: u32 = 3;
/// Backwards-compatible revision within [`PROTOCOL_MAJOR`].
pub const PROTOCOL_MINOR: u32 = 0;
/// Commit marker proving the caller implements candidate-aware publication.
pub const ATOMIC_SYNC_INDEX_CAPABILITY: &str = "atomic-sync-index-candidates-v1";
/// Event pages distinguish wanted-only historical targets from required
/// event/signature evidence.
pub const HISTORICAL_TARGET_HINTS_CAPABILITY: &str = "historical-target-hints-v1";
/// Features a protocol-v3 replication peer must provide.
pub const REQUIRED_SYNC_CAPABILITIES: &[&str] = &[
    "atomic-sync-publication-v1",
    "event-import-sessions-v1",
    ATOMIC_SYNC_INDEX_CAPABILITY,
    "stable-event-pagination-v1",
    HISTORICAL_TARGET_HINTS_CAPABILITY,
];

pub(crate) fn protocol_capabilities() -> Vec<String> {
    REQUIRED_SYNC_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_string())
        .collect()
}
