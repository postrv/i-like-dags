//! Non-production Rust models supporting the Cloudflare Edge implementation.
//!
//! The deployable implementation is `worker/` (TypeScript, R2 and Durable
//! Objects). This crate is deliberately `publish = false`. Its optional
//! `test-harness` feature exposes a small native transport fixture for client
//! smoke tests; that fixture is not protocol-parity or deployment evidence.

#[cfg(feature = "test-harness")]
#[doc(hidden)]
pub mod auth;
#[cfg(feature = "test-harness")]
#[doc(hidden)]
pub mod http;
pub mod r2;

#[cfg(feature = "test-harness")]
use std::sync::Arc;

#[cfg(feature = "test-harness")]
use dag_core::{Cid, ReplicaLog};

#[cfg(feature = "test-harness")]
use crate::r2::{MemoryObjects, R2Store};

/// Minimal process-local fixture for exercising an HTTP client.
///
/// This is hidden behind `test-harness`; it does not model Durable Object
/// sessions, recovery, quotas, or the Worker's atomic publication protocol.
#[cfg(feature = "test-harness")]
#[doc(hidden)]
pub struct EdgeReplica {
    pub(crate) log: ReplicaLog<R2Store<MemoryObjects>>,
    token: String,
}

#[cfg(feature = "test-harness")]
impl EdgeReplica {
    /// Empty replica that accepts `token` on every write.
    pub fn memory(token: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            log: ReplicaLog::new(R2Store::new(MemoryObjects::new())),
            token: token.into(),
        })
    }

    /// The bearer token writes must present.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Object store (re-hashes on get).
    pub fn store(&self) -> &R2Store<MemoryObjects> {
        self.log.store()
    }

    /// Rebuild heads from filed events.
    pub fn finalize(&self) -> (u32, u32) {
        self.log.finalize()
    }

    /// Resolve a pointer after [`Self::finalize`].
    pub fn resolve(&self, id: &str) -> Option<Cid> {
        self.log.resolve_pointer(id)
    }
}
