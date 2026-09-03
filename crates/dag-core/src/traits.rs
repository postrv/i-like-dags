use crate::{Cid, CoreError, Entry, Link};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetaHint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

pub trait ContentStore: Send + Sync {
    fn put_chunk(&self, bytes: &[u8], meta: Option<MetaHint>) -> Result<Cid, CoreError>;
    fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError>;
    fn has_chunk(&self, cid: &Cid) -> Result<bool, CoreError>;

    /// Flush any writes this store has deferred. A no-op for stores that are
    /// already durable per write.
    ///
    /// Defaulted so no implementor breaks, and so a bulk writer can call it
    /// unconditionally: whoever is about to hand out a CID as a promise —
    /// `dag_core::file::split` returning a manifest root, an ingest returning
    /// to its caller — should call this first, without having to know which
    /// store it was given.
    fn sync(&self) -> Result<(), CoreError> {
        Ok(())
    }

    /// An in-progress ingest is about to reference `cid`; stores that track
    /// in-flight writes should protect it as if it were just written.
    ///
    /// A validator or publisher can reference chunks already on disk without
    /// writing them. Such a chunk is still one the in-progress operation
    /// depends on: the pointer/pin/manifest that names it may not be committed
    /// yet, and the reused file may carry an ancient mtime. Without this call,
    /// a concurrent garbage collection could see it as unreferenced, unpinned
    /// and old, and take it out from under live publication.
    ///
    /// Defaulted to a no-op: a store with no notion of in-flight writes (an
    /// in-memory test double, a store never collected concurrently) owes
    /// nothing here.
    fn note_reference(&self, _cid: &Cid) {}

    /// Put an Entry, encoding it as CBOR and storing as a chunk
    fn put_entry(&self, entry: &Entry) -> Result<Cid, CoreError> {
        let cbor_bytes = entry.to_bytes_cbor()?;
        self.put_chunk(&cbor_bytes, None)
    }

    /// Get links from a stored Entry by CID
    fn get_links(&self, cid: &Cid) -> Result<Vec<Link>, CoreError> {
        let bytes = self.get_chunk(cid)?;
        let entry = Entry::from_bytes_cbor(&bytes)?;
        Ok(entry.links)
    }

    /// Get a full Entry by CID
    fn get_entry(&self, cid: &Cid) -> Result<Entry, CoreError> {
        let bytes = self.get_chunk(cid)?;
        Entry::from_bytes_cbor(&bytes)
    }
}

/// Outcome of verifying one chunk's bytes against its CID.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    pub cid: Cid,
    pub node_id: String,
    pub is_valid: bool,
    pub error_message: Option<String>,
}

/// One chunk collected (or, in a dry run, judged collectable), recorded so the
/// run leaves a disposition record rather than a count.
///
/// A count cannot answer "prove the routine cleanup could not have touched
/// this" after the fact, because the bytes it refers to are gone.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollectedChunk {
    pub cid: Cid,
    /// Size of the chunk that was freed.
    pub bytes: usize,
    /// Age of the chunk at the moment it was judged, in seconds. Together
    /// with the report's `collection_epoch` this pins down when it was
    /// written, which is the other half of a disposition record.
    pub age_secs: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GcReport {
    pub node_id: Option<String>,
    pub collection_epoch: i64,
    pub total_chunks_examined: usize,
    pub chunks_deleted: usize,
    pub bytes_freed: usize,
    pub errors: Vec<String>,
    /// True when additional per-chunk diagnostics were omitted to bound the
    /// report. Collection counters remain exact.
    #[serde(default)]
    pub errors_truncated: bool,
    /// Chunks the caller's retention snapshot named.
    ///
    /// Named `_by_pins` for the JSON consumers that already read it, but the
    /// snapshot covers everything the control plane treats as a root — pins,
    /// live pointer heads, and the control plane's own event log.
    pub protected_by_pins: usize,
    /// Chunks the collector's own backstop recognised as control-plane data
    /// that the snapshot had not already named. Normally zero.
    pub protected_by_system: usize,
    pub skipped_too_young: usize,
    pub dry_run: bool,
    /// Every chunk this run collected, in the order it was collected, when
    /// the caller requested disposition details.
    ///
    /// Detailed dry runs populate it too. Summary callers may leave it empty
    /// while the counters remain exact; such a report cannot be filed as a
    /// full disposition record.
    #[serde(default)]
    pub collected: Vec<CollectedChunk>,
    /// True when `max_deletions` cut the pass short, so the counters above
    /// describe a prefix of the store rather than all of it.
    #[serde(default)]
    pub truncated_by_max_deletions: bool,
}
