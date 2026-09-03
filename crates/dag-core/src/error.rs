use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Chunk size {size} exceeds maximum allowed size {max_size}")]
    ChunkTooLarge { size: usize, max_size: usize },

    /// A whole-file operation crossed one of its explicit resource budgets.
    ///
    /// This is distinct from `ChunkTooLarge`: chunks retain the protocol's
    /// fixed 4 MiB invariant, while a manifest walk has several independently
    /// bounded logical resources (bytes, chunks, nodes, links and fetches).
    #[error("File {resource} {value} exceeds maximum allowed {limit}")]
    FileLimitExceeded {
        resource: &'static str,
        value: u64,
        limit: u64,
    },

    /// An ordinary collection refused before deleting anything because the
    /// store inventory exceeded its finite work/memory ceiling.
    #[error(
        "garbage-collection inventory exceeds the finite {limit}-chunk ceiling; no chunks were deleted. Use an explicitly unbounded offline collection only after sizing the store"
    )]
    GcInventoryLimit { limit: usize },

    /// The complete inventory fit the object-count ceiling but its aggregate
    /// bytes did not fit the ordinary pass's I/O/allocation budget.
    #[error(
        "garbage-collection inventory needs to examine {required} bytes, above the finite {limit}-byte ceiling; no chunks were deleted. Use an explicitly sized offline collection to raise or remove the ceiling"
    )]
    GcInventoryBytesLimit { limit: u64, required: u64 },

    /// Collection's filesystem snapshot and the derived chunk index disagree.
    ///
    /// This is a destructive-operation interlock, not a lookup failure. An
    /// older `control.redb` restored over newer `data/` can otherwise carry a
    /// stale recovery verdict and omit the newer pointer/pin events whose
    /// targets collection is about to delete.
    #[error(
        "garbage collection refused because the filesystem inventory ({filesystem} chunks) and chunk index ({indexed} rows) disagree: {detail}. No chunks were deleted; run `dag index reindex`, then `dag recover` while the server is stopped"
    )]
    GcIndexMismatch {
        filesystem: usize,
        indexed: usize,
        detail: String,
    },

    #[error("Chunk not found: {0}")]
    ChunkNotFound(String),

    #[error("Invalid CID format: {0}")]
    InvalidCid(String),

    /// Stored bytes no longer hash to the CID that names them.
    ///
    /// Distinct from [`CoreError::InvalidCid`] on purpose: that variant
    /// describes a malformed CID *string*, this one rotted or tampered
    /// *content*. Labelling corruption as a format problem pointed an
    /// operator at CID syntax when the finding was their data.
    #[error("CID mismatch: expected {expected}, computed {computed}")]
    CidMismatch {
        expected: crate::Cid,
        computed: crate::Cid,
    },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),

    /// The storage backend (index database, on-disk catalogue) failed.
    ///
    /// Distinct from [`CoreError::Io`]: the bytes may be intact and only the
    /// bookkeeping around them is broken, which is a different operator
    /// response — and a different exit code — from a failed read or write.
    #[error("storage backend error: {0}")]
    Backend(String),
}
