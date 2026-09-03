//! # dag-core
//!
//! The data model every other crate in the workspace shares: content
//! identifiers, immutable DAG entries, file chunking, and signing.
//!
//! This crate is pure data and traits — it never touches a disk. Storage lives
//! behind the [`ContentStore`] trait, which [`dag-storage`] implements.
//!
//! ## Content identifiers
//!
//! A [`Cid`] is the SHA-256 digest of the canonical bytes of a payload.
//! Identical bytes always produce the same CID, and the bytes behind a CID
//! never change (invariant I1). One chunk holds at most [`MAX_CHUNK_SIZE`]
//! (4 MiB, invariant I2).
//!
//! ```
//! use dag_core::Cid;
//!
//! let cid = Cid::compute(b"hello");
//! assert_eq!(cid, Cid::compute(b"hello"));
//! assert_ne!(cid, Cid::compute(b"hello!"));
//!
//! // A CID is a plain SHA-256 digest, which is why it round-trips through hex
//! // and drops straight into external tooling that speaks `sha256:` digests.
//! assert_eq!(Cid::from_hex(&cid.to_hex()).unwrap(), cid);
//! ```
//!
//! ## Entries and links
//!
//! An [`Entry`] is a payload plus [`Link`]s to other CIDs. Links point only at
//! CIDs, never at mutable names, so a published entry's graph can never change
//! underneath a reader (invariant I3).
//!
//! ```
//! use dag_core::{Cid, Entry, Link};
//!
//! let data = Cid::compute(b"the artifact");
//! let entry = Entry {
//!     payload: b"a release record".to_vec(),
//!     links: vec![Link { name: Some("artifact".into()), target: data }],
//!     meta: None,
//! };
//!
//! // Entries round-trip through CBOR; the encoding is deterministic, so the
//! // same entry always lands on the same CID.
//! let bytes = entry.to_bytes_cbor().unwrap();
//! assert_eq!(Entry::from_bytes_cbor(&bytes).unwrap().links.len(), 1);
//! ```
//!
//! ## Files larger than a chunk
//!
//! [`file::store_auto`] splits anything over the chunk limit with FastCDC and
//! records the pieces in a `file/v1` manifest, so appending to a large file
//! re-stores only the chunks that actually changed. See [`mod@file`].
//!
//! ## Signing
//!
//! [`signing`] produces Ed25519 signatures over DSSE envelopes carrying
//! in-toto v1 statements. Because a CID *is* a SHA-256 digest, it drops
//! straight into `subject.digest.sha256`, and external supply-chain tooling
//! can verify the envelopes without knowing anything about this system.
//!
//! [`dag-storage`]: https://docs.rs/dag-storage

mod cbor;
pub mod cid;
pub mod entry;
pub mod error;
pub mod file;
mod identifier;
pub mod job;
pub mod memory;
pub mod metrics;
pub mod offer;
pub mod pin;
pub mod pointer;
pub mod replica;
pub mod signing;
pub mod traits;

pub use cbor::decode_cbor_exact;
pub use cid::{Cid, CID_LEN};
pub use entry::{Entry, Link};
pub use error::CoreError;
pub use file::{ChunkerConfig, FileInfo, FileLimits, SplitReport, StoredContent};
pub use identifier::validate_identifier_text;
pub use job::{
    validate_job_id, validate_job_spec, CachePolicy, Determinism, EffectKey, InputManifest,
    JobError, JobId, JobInput, JobPolicy, JobRevision, JobRun, JobSpec, ResolvedPointer, RunId,
    RunOrigin, RunStatus, TriggerPolicy, MAX_JOB_CODE_REF_BYTES, MAX_JOB_CONFIG_BYTES,
    MAX_JOB_CONFIG_DEPTH, MAX_JOB_CONFIG_NODES, MAX_JOB_DECLARED_OUTPUTS, MAX_JOB_NAME_BYTES,
    MAX_JOB_PLACEMENT_BYTES, MAX_JOB_POINTER_INPUTS, MAX_JOB_STATIC_INPUTS,
};
pub use memory::MemoryStore;
pub use metrics::Metrics;
pub use offer::{offer_pin_event, offer_pointer_event, OfferError, OfferOutcome};
pub use pin::{validate_pin_id, PinError, PinEvent, PinHead, PinId, PinScope, PinState, PinTarget};
pub use pointer::{PointerEvent, PointerId};
pub use replica::{ReplicaError, ReplicaLog};
pub use traits::{CollectedChunk, ContentStore, GcReport, IntegrityReport, MetaHint};

/// Largest payload addressable by a single [`Cid`] (invariant I2).
///
/// Content above this is split by [`file::store_auto`] into chunks recorded in
/// a `file/v1` manifest; storing an oversized chunk directly is a hard error
/// rather than a silent truncation.
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[cfg(test)]
mod profile_tests {
    /// Release builds must check arithmetic like every other build does.
    ///
    /// This is trivially true under `cargo test`, which is the point: it is a
    /// guard on the workspace's `[profile.release] overflow-checks = true`,
    /// which is the only reason `cargo test --release` agrees with `cargo
    /// test`. Deleting that profile setting is what let the pin-TTL overflow
    /// panic in debug and wrap silently in the binary that actually ships.
    /// `cfg(overflow_checks)` is still unstable, so this asks the arithmetic
    /// itself. `black_box` keeps the addition out of const evaluation, which
    /// would otherwise refuse to compile it.
    #[test]
    fn arithmetic_is_checked_in_every_profile() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(|| std::hint::black_box(i64::MAX) + 1);
        std::panic::set_hook(previous);

        assert!(
            outcome.is_err(),
            "this profile wraps on overflow instead of trapping; see \
             [profile.release] in the workspace Cargo.toml"
        );
    }
}
