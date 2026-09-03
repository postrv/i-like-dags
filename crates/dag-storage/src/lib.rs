//! # dag-storage
//!
//! The storage node: chunk bytes on a filesystem, a redb index mapping CID to
//! location, integrity scanning, and garbage collection.
//!
//! ## Chunks, not graphs
//!
//! Everything here works at the chunk level and never parses an [`Entry`]
//! (invariant I9). A storage node knows that a CID names some bytes; it does
//! not know whether those bytes are a release manifest or a JPEG, and it never
//! follows a link. DAG traversal belongs to [`dag-control`], which sits above
//! this crate.
//!
//! That split is what lets collection be safe: [`GarbageCollector`] is handed
//! a pre-computed protected set and deletes only what is not in it, so it
//! needs no opinion about what the graph means.
//!
//! ```
//! use dag_core::{Cid, ContentStore};
//! use dag_storage::FsStore;
//!
//! let dir = tempfile::tempdir().unwrap();
//! let store = FsStore::new(dir.path()).unwrap();
//!
//! let cid = store.put_chunk(b"hello", None).unwrap();
//! assert_eq!(store.get_chunk(&cid).unwrap(), b"hello");
//!
//! // Storing the same bytes again is the same CID and no new object.
//! assert_eq!(store.put_chunk(b"hello", None).unwrap(), cid);
//! assert_eq!(cid, Cid::compute(b"hello"));
//! ```
//!
//! ## Layout
//!
//! Chunks live under the data directory sharded by the first byte of their hex
//! CID (`<data_dir>/ab/cdef…`). [`FsStore::chunk_path`] is public so operators
//! and integrity tools can reach a chunk's bytes without re-deriving that rule
//! — a second copy of it that drifts would fail silently.
//!
//! ## Index
//!
//! [`ChunkIndex`] is a redb table. In a full deployment it shares one database
//! file with the control plane's logs; [`FsStore::with_index`] opens a
//! standalone one for tools that need a store on its own.
//!
//! ## Durability
//!
//! The index and the bytes it names must not disagree after a power cut, and
//! only one direction of disagreement is survivable. A chunk file with no
//! index entry is garbage that [`FsStore::reindex`] or the next collection
//! sweeps up; an index entry naming a file that is absent or half-written is
//! corruption that nothing repairs, and it reads exactly like data loss.
//!
//! So the store fsyncs the chunk and the directory that names it *before* the
//! index learns it exists, and on the way out clears the index entry *before*
//! unlinking the bytes. That safety is not free — an fsync costs milliseconds,
//! which is most of what a small write costs — so [`DurabilityPolicy`] can
//! defer it to an explicit [`ContentStore::sync`](dag_core::ContentStore::sync)
//! for writers that can replay their input. The default is durable.
//!
//! [`Entry`]: dag_core::Entry
//! [`dag-control`]: https://docs.rs/dag-control

pub mod fs_store;
pub mod gc;
pub mod index;
pub mod integrity;

pub use fs_store::{
    DurabilityCoordination, DurabilityPolicy, DurabilityStats, FsStore, InFlightRegistry,
};
pub use gc::{
    GarbageCollector, GcCapableStore, GcConfig, GcReport, SystemDataPolicy,
    DEFAULT_GC_MAX_BYTES_EXAMINED, DEFAULT_GC_MAX_DELETIONS, DEFAULT_GC_MAX_EXAMINED,
};
pub use index::{ChunkIndex, ChunkLocation};
pub use integrity::{IntegrityScanner, ScanResult};
