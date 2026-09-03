//! Remote replication: the ADR-002 engine with one side across the network.
//!
//! [`RemoteSource`] and [`RemoteDestination`] implement the sync traits by
//! calling the remote's RPCs, so [`dag_control::sync::replicate`] runs
//! unchanged — same ordering, same per-chunk failure isolation, same report.
//! The destination's validation runs wherever the destination lives: in the
//! remote server for a push, in this process for a pull.

use std::sync::Arc;

use dag_control::sync::{
    replicate, EventBatchOutcome, EventConflict, RebuildCounts, SyncDestination, SyncEnumeration,
    SyncOptions, SyncReport, SyncSource,
};
use dag_control::{Control, ControlError};
use dag_core::Cid;

use crate::client::RemoteNode;
use crate::error::NetError;

/// Push everything the local directory has that the remote node lacks.
pub async fn push(
    local: Arc<Control>,
    remote: &RemoteNode,
    opts: &SyncOptions,
) -> Result<SyncReport, ControlError> {
    remote.require_sync_protocol().await.map_err(remote_err)?;
    let destination = RemoteDestination::new(remote.clone());
    let opts = opts.clone();
    run_engine(move || replicate(local.as_ref(), &destination, &opts)).await
}

/// Pull everything the remote node has that the local directory lacks.
pub async fn pull(
    local: Arc<Control>,
    remote: &RemoteNode,
    opts: &SyncOptions,
) -> Result<SyncReport, ControlError> {
    remote.require_sync_protocol().await.map_err(remote_err)?;
    let source = RemoteSource::new(remote.clone());
    let opts = opts.clone();
    run_engine(move || replicate(&source, local.as_ref(), &opts)).await
}

/// Run the synchronous engine off the async workers.
///
/// The engine blocks on redb, the filesystem, and (through the adapters) the
/// network; a blocking-pool thread is the right home for all three. The
/// adapters inside re-enter the runtime with `Handle::block_on`, which is
/// legal from a blocking-pool thread and would deadlock a worker.
async fn run_engine<F>(work: F) -> Result<SyncReport, ControlError>
where
    F: FnOnce() -> Result<SyncReport, ControlError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| ControlError::Remote(format!("sync task failed: {e}")))?
}

fn remote_err(e: NetError) -> ControlError {
    ControlError::Remote(e.to_string())
}

/// A remote node in the source role: where a pull reads from.
pub struct RemoteSource {
    node: RemoteNode,
    handle: tokio::runtime::Handle,
}

impl RemoteSource {
    /// Wrap a connected node. Must be called on a runtime; the handle taken
    /// here is what the synchronous trait methods later block on.
    pub fn new(node: RemoteNode) -> Self {
        Self {
            node,
            handle: tokio::runtime::Handle::current(),
        }
    }
}

impl SyncSource for RemoteSource {
    fn enumerate(&self, opts: &SyncOptions) -> Result<SyncEnumeration, ControlError> {
        self.handle
            .block_on(self.node.enumerate_for(opts.max_walk, &opts.source_node_id))
            .map_err(remote_err)
    }

    fn chunk_len(&self, cid: &Cid) -> Result<usize, ControlError> {
        match self.handle.block_on(self.node.chunk_len(cid)) {
            Ok(Some(len)) => Ok(len as usize),
            // Absent at the source: the engine files it under
            // missing_at_source, exactly as the directory case does.
            Ok(None) => Err(ControlError::Core(dag_core::CoreError::ChunkNotFound(
                cid.to_hex(),
            ))),
            Err(e) => Err(remote_err(e)),
        }
    }

    fn fetch_chunk(&self, cid: &Cid) -> Result<Vec<u8>, ControlError> {
        self.handle
            .block_on(self.node.fetch_chunk(cid))
            .map_err(|e| match &e {
                crate::NetError::Status(status) if status.code() == tonic::Code::NotFound => {
                    ControlError::Core(dag_core::CoreError::ChunkNotFound(cid.to_hex()))
                }
                _ => remote_err(e),
            })
    }
}

/// A remote node in the destination role: where a push writes to.
///
/// Every import travels to the remote and is validated *there* — this
/// adapter cannot bypass the destination's refusals, only relay them.
pub struct RemoteDestination {
    node: RemoteNode,
    handle: tokio::runtime::Handle,
}

impl RemoteDestination {
    /// Wrap a connected node. Must be called on a runtime; the handle taken
    /// here is what the synchronous trait methods later block on.
    pub fn new(node: RemoteNode) -> Self {
        Self {
            node,
            handle: tokio::runtime::Handle::current(),
        }
    }
}

impl SyncDestination for RemoteDestination {
    fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>, ControlError> {
        self.handle
            .block_on(self.node.missing(cids))
            .map_err(remote_err)
    }

    fn store_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<(), ControlError> {
        self.handle
            .block_on(self.node.put_chunk(cid, bytes))
            .map_err(remote_err)
    }

    fn flush(&self) -> Result<(), ControlError> {
        self.handle.block_on(self.node.flush()).map_err(remote_err)
    }

    fn probe_pointer_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>, ControlError> {
        self.handle
            .block_on(self.node.probe_pointer_events(events))
            .map(Some)
            .map_err(remote_err)
    }

    fn probe_pin_events(
        &self,
        events: &[(String, u64, Cid)],
    ) -> Result<Option<Vec<EventConflict>>, ControlError> {
        self.handle
            .block_on(self.node.probe_pin_events(events))
            .map(Some)
            .map_err(remote_err)
    }

    fn import_pointer_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool, ControlError> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "remote event publication requires a complete atomic batch".into(),
        ))
    }

    fn import_pin_event(&self, id: &str, seq: u64, cid: &Cid) -> Result<bool, ControlError> {
        let _ = (id, seq, cid);
        Err(ControlError::Invalid(
            "remote event publication requires a complete atomic batch".into(),
        ))
    }

    fn import_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
    ) -> Result<EventBatchOutcome, ControlError> {
        self.handle
            .block_on(self.node.import_event_batch(pointer_events, pin_events))
            .map_err(remote_err)
    }

    fn publish_event_batch(
        &self,
        pointer_events: &[(String, u64, Cid)],
        pin_events: &[(String, u64, Cid)],
        index_candidates: &[Cid],
    ) -> Result<(EventBatchOutcome, RebuildCounts), ControlError> {
        self.handle
            .block_on(
                self.node
                    .publish_event_batch(pointer_events, pin_events, index_candidates),
            )
            .map_err(remote_err)
    }

    fn finalize(&self) -> Result<RebuildCounts, ControlError> {
        Err(ControlError::Invalid(
            "remote Finalize was removed in node protocol 3; publish a candidate-bound event batch"
                .into(),
        ))
    }
}
