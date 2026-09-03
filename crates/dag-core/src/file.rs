//! Files larger than one chunk.
//!
//! I2 caps a chunk at 4 MiB, which is a limit on *chunks*, not on content.
//! This module stores content larger than one chunk as a **manifest**: an
//! [`Entry`] whose ordered links name the file's chunks, produced by FastCDC
//! content-defined chunking. Reassembly is concatenation in link order; every
//! byte is re-hashed against its CID on the way out. All operations run under
//! explicit [`FileLimits`]; the compatibility helpers use a 64 GiB ceiling.
//!
//! ## Why content-defined boundaries
//!
//! Fixed-size chunking shifts every boundary when a byte is inserted, so two
//! revisions of a file share almost nothing. FastCDC picks boundaries from the
//! content itself, so an edit disturbs only the chunks it touches and revision
//! N+1 of a large artefact stores only what actually changed — the same
//! content-addressing dividend the rest of the system is built on, extended
//! inside files.
//!
//! ## Manifest format
//!
//! The manifest payload is human-readable JSON (like the worked example's
//! dataset cards), and its links carry the structure:
//!
//! ```text
//! Entry {
//!   payload: {"kind":"file/v1","size":N,"chunks":M,"depth":D,"chunking":"…"},
//!   links:   [chunk CIDs in order]                          // depth == 1
//!            [part CIDs, each a "file-part/v1" entry]       // depth > 1
//! }
//! ```
//!
//! A manifest's links must fit inside one 4 MiB entry, which caps direct links
//! per manifest. Beyond that the chunk list is split into `file-part/v1`
//! entries and the manifest links those instead — `depth` says how many levels
//! of indirection stand between the root and the data, so readers never have
//! to guess whether a link is data or structure. One level of parts already
//! covers exabytes; further levels exist so there is no practical cliff, up to
//! [`MAX_MANIFEST_DEPTH`] — a ceiling far above any manifest that can describe
//! a real file, and the difference between a rejected read and an unkillable
//! stack overflow. See that constant for the derivation.
//!
//! Manifests contain no timestamps: splitting the same bytes with the same
//! configuration yields the same root CID, which is what makes a chunked file
//! usable as a deterministic job input (J1).

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::{Cid, ContentStore, CoreError, Entry, Link, MetaHint, MAX_CHUNK_SIZE};

/// Payload `kind` for a file manifest root.
pub const FILE_KIND: &str = "file/v1";
/// Payload `kind` for one part of an oversized chunk list.
pub const FILE_PART_KIND: &str = "file-part/v1";
/// `MetaHint::content_type` recorded on manifest and part entries.
pub const MANIFEST_CONTENT_TYPE: &str = "application/vnd.dag.file+json";

/// Largest direct link list a v1 manifest node may carry.
///
/// This is a reader-side protocol and writer-memory ceiling. The encoded 4 MiB
/// entry limit can bind first (especially when links have names); accepting an
/// arbitrary caller-selected fan-out would nevertheless let `split` retain an
/// arbitrary `Vec<Link>` before serialization finally rejected it.
pub const MAX_LINKS_PER_MANIFEST: usize = 65_536;
/// Conservative writer fan-out that leaves room for CBOR framing and payload.
pub const DEFAULT_LINKS_PER_MANIFEST: usize = 55_000;

/// Default whole-file byte ceiling for local/core operations (64 GiB).
///
/// Network services and job adapters should normally select a smaller policy
/// with [`FileLimits`]. This ceiling keeps the convenient legacy helpers
/// bounded while leaving ample room for large local artefacts.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024;
/// Default maximum number of logical data chunks in one file.
pub const DEFAULT_MAX_FILE_CHUNKS: u64 = 1_048_576;
/// Default maximum manifest-node visits, including the root.
pub const DEFAULT_MAX_MANIFEST_NODES: u64 = 65_536;
/// Default maximum link occurrences inspected across the manifest tree.
pub const DEFAULT_MAX_MANIFEST_LINKS: u64 = 2_097_152;
/// Default maximum store fetches, including the root and repeated references.
pub const DEFAULT_MAX_FILE_FETCHES: u64 = DEFAULT_MAX_MANIFEST_LINKS + 1;

/// Resource policy for splitting, inspecting, verifying and joining a file.
///
/// Every counter is logical rather than unique-by-CID: if a hostile manifest
/// names the same part or leaf 10,000 times, it spends 10,000 units. This is
/// essential because each occurrence otherwise causes work and, for leaves,
/// output bytes even though the content address is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileLimits {
    /// Maximum declared or ingested file bytes.
    pub max_file_size: u64,
    /// Maximum logical data-chunk occurrences.
    pub max_chunks: u64,
    /// Maximum manifest-node visits, including repeated nodes and the root.
    pub max_manifest_nodes: u64,
    /// Maximum direct-link occurrences inspected across all visited nodes.
    pub max_links: u64,
    /// Maximum store reads, including the root, parts and data chunks.
    pub max_fetches: u64,
}

impl Default for FileLimits {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_chunks: DEFAULT_MAX_FILE_CHUNKS,
            max_manifest_nodes: DEFAULT_MAX_MANIFEST_NODES,
            max_links: DEFAULT_MAX_MANIFEST_LINKS,
            max_fetches: DEFAULT_MAX_FILE_FETCHES,
        }
    }
}

impl FileLimits {
    fn check(&self, resource: &'static str, value: u64, limit: u64) -> Result<(), CoreError> {
        if value > limit {
            return Err(CoreError::FileLimitExceeded {
                resource,
                value,
                limit,
            });
        }
        Ok(())
    }
}

/// Hard ceiling on a manifest's declared levels of indirection.
///
/// `depth` is read from the manifest payload, which is content anyone with
/// write access to the store — including `POST /api/chunks` on an
/// unauthenticated `dag serve` — can author. Reassembly descends one stack
/// frame per level, and a stack overflow in Rust is a `fatal runtime error`
/// that aborts the process: not a catchable panic, so it cannot be contained
/// by running the read in its own task. The bound therefore has to be a check
/// before the descent, not a rescue after it.
///
/// 64 is not a compromise between safety and capability, because no reachable
/// manifest comes near it. Taking the loosest configuration
/// `ChunkerConfig::validate` permits — `links_per_manifest` at its minimum of
/// 2, and chunks at fastcdc's 64-byte floor — a file occupying the entire
/// `u64` size range holds at most 2^58 chunks, and a binary tree over 2^58
/// leaves is 58 levels deep. With the defaults (65 536 links per manifest,
/// megabyte chunks) two levels already span more than 2^64 bytes. Sixty-four
/// stack frames cost nothing.
pub const MAX_MANIFEST_DEPTH: u32 = 64;

/// Chunking parameters.
///
/// Defaults follow common CDC practice (min = avg/4, max = 4×avg) with the
/// maximum pinned to [`MAX_CHUNK_SIZE`] so no produced chunk can violate I2.
#[derive(Debug, Clone)]
pub struct ChunkerConfig {
    /// No chunk smaller than this, except the final one.
    pub min_size: usize,
    /// Target average chunk size.
    pub avg_size: usize,
    /// Hard upper bound per chunk; must not exceed [`MAX_CHUNK_SIZE`].
    pub max_size: usize,
    /// Direct links per manifest or part entry before a level of parts is
    /// introduced. The default keeps a full entry comfortably inside the
    /// 4 MiB entry limit.
    pub links_per_manifest: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            min_size: 256 * 1024,
            avg_size: 1024 * 1024,
            max_size: MAX_CHUNK_SIZE,
            links_per_manifest: DEFAULT_LINKS_PER_MANIFEST,
        }
    }
}

impl ChunkerConfig {
    fn validate(&self) -> Result<(), CoreError> {
        // 64 is fastcdc's own lower bound on min_size; checking here turns a
        // would-be panic in the chunker into an error.
        if self.min_size < 64 || self.min_size >= self.avg_size || self.avg_size >= self.max_size {
            return Err(CoreError::PreconditionFailed(format!(
                "invalid chunker config: need 64 <= min ({}) < avg ({}) < max ({})",
                self.min_size, self.avg_size, self.max_size
            )));
        }
        if self.max_size > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: self.max_size,
                max_size: MAX_CHUNK_SIZE,
            });
        }
        if self.links_per_manifest < 2 {
            return Err(CoreError::PreconditionFailed(
                "links_per_manifest must be at least 2".to_string(),
            ));
        }
        if self.links_per_manifest > MAX_LINKS_PER_MANIFEST {
            return Err(CoreError::PreconditionFailed(format!(
                "links_per_manifest {} exceeds the safe maximum {}",
                self.links_per_manifest, MAX_LINKS_PER_MANIFEST
            )));
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!(
            "fastcdc-2020/{}-{}-{}",
            self.min_size, self.avg_size, self.max_size
        )
    }
}

/// The manifest / part payload as stored.
#[derive(Debug, Serialize, Deserialize)]
struct ManifestPayload {
    kind: String,
    /// Total file bytes. Present on the root only.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// Total data chunks under the root. Present on the root only.
    #[serde(skip_serializing_if = "Option::is_none")]
    chunks: Option<u64>,
    /// Levels of indirection below this entry; 1 means links are data chunks.
    depth: u32,
    /// Direct links carried by this entry (root and parts alike).
    links: u64,
    /// Chunking parameters, for provenance. Root only.
    #[serde(skip_serializing_if = "Option::is_none")]
    chunking: Option<String>,
    /// Declared content type of the *original file*, if the caller gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

/// What [`split`] stored.
#[derive(Debug, Clone, Serialize)]
pub struct SplitReport {
    /// CID of the manifest root.
    pub cid: Cid,
    /// Total bytes read from the input.
    pub size: u64,
    /// Data chunks the file was split into.
    pub chunks: u64,
    /// Chunks whose canonical path was not already present — the dedup ratio
    /// is visible as `chunks - new_chunks` shared with earlier content.
    ///
    /// Presence is deliberately only an accounting hint. Every chunk still
    /// passes through [`ContentStore::put_chunk`], which may repair corrupt
    /// bytes or adopt a crash-orphaned file; such repairs are not counted as
    /// new chunks because the store API does not expose that distinction.
    pub new_chunks: u64,
    /// Levels of indirection in the manifest tree (1 = flat).
    pub depth: u32,
}

/// What a manifest describes, per [`file_info`] / [`join`].
#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    /// Total file bytes.
    pub size: u64,
    /// Data chunk count.
    pub chunks: u64,
    /// Levels of indirection in the manifest tree.
    pub depth: u32,
    /// Declared content type of the original file, if recorded.
    pub content_type: Option<String>,
}

fn encode_payload(payload: &ManifestPayload) -> Result<Vec<u8>, CoreError> {
    serde_json::to_vec(payload)
        .map_err(|e| CoreError::Serialization(format!("manifest payload: {}", e)))
}

fn manifest_meta() -> Option<MetaHint> {
    Some(MetaHint {
        content_type: Some(MANIFEST_CONTENT_TYPE.to_string()),
        encoding: None,
    })
}

/// How [`store_auto`] stored the content.
#[derive(Debug, Clone)]
pub enum StoredContent {
    /// Fit in one chunk; stored exactly as `put_chunk` always has.
    Chunk {
        /// The chunk's CID.
        cid: Cid,
        /// Its length in bytes.
        size: u64,
    },
    /// Larger than one chunk (or chunking was forced): a file manifest.
    File(SplitReport),
}

/// Store a stream of unknown length, chunking only when it doesn't fit.
///
/// Reads one chunk's worth plus a byte to learn which side of the limit the
/// content falls on: at or under [`MAX_CHUNK_SIZE`] it becomes a single plain
/// chunk — byte-for-byte the behaviour `put_chunk` callers have always had —
/// and anything larger is [`split`] behind a manifest without rewinding the
/// stream. `force_chunked` produces the manifest form regardless of size,
/// which keeps CIDs stable for content that starts small and grows.
///
/// This is the shared implementation behind `dag put` and `POST /api/files`,
/// so the CLI and the HTTP API cannot drift apart on what a store means.
pub fn store_auto<S, R>(
    store: &S,
    reader: R,
    content_type: Option<String>,
    force_chunked: bool,
    config: &ChunkerConfig,
) -> Result<StoredContent, CoreError>
where
    S: ContentStore + ?Sized,
    R: Read,
{
    store_auto_with_limits(
        store,
        reader,
        content_type,
        force_chunked,
        config,
        &FileLimits::default(),
    )
}

/// [`store_auto`] with an explicit whole-file resource policy.
pub fn store_auto_with_limits<S, R>(
    store: &S,
    mut reader: R,
    content_type: Option<String>,
    force_chunked: bool,
    config: &ChunkerConfig,
    limits: &FileLimits,
) -> Result<StoredContent, CoreError>
where
    S: ContentStore + ?Sized,
    R: Read,
{
    if force_chunked {
        return split_with_limits(store, reader, content_type, config, limits)
            .map(StoredContent::File);
    }

    let mut head = Vec::new();
    (&mut reader)
        .take(MAX_CHUNK_SIZE as u64 + 1)
        .read_to_end(&mut head)?;

    limits.check("bytes", head.len() as u64, limits.max_file_size)?;

    if head.len() <= MAX_CHUNK_SIZE {
        let meta = content_type.map(|ct| MetaHint {
            content_type: Some(ct),
            encoding: None,
        });
        let size = head.len() as u64;
        let cid = store.put_chunk(&head, meta)?;
        // The caller is about to be handed this CID as a promise that the
        // bytes are stored; a store that batches its writes has to settle up
        // before that promise is made. See `split` for the same rule where
        // ordering also matters.
        store.sync()?;
        return Ok(StoredContent::Chunk { cid, size });
    }

    let full = std::io::Cursor::new(head).chain(reader);
    split_with_limits(store, full, content_type, config, limits).map(StoredContent::File)
}

/// Split `reader` into content-defined chunks and store a manifest for them.
///
/// Streams: memory use is bounded by `config.max_size`, not the input size.
/// Chunks already present in the store are recognised for the dedup report.
/// They are still offered through the idempotent `put_chunk` gate: a presence
/// check alone cannot distinguish an intact chunk from a torn/corrupt object,
/// and skipping that gate once let a rerun publish a manifest over bytes a
/// crashed deferred ingest had left short at the final path.
pub fn split<S, R>(
    store: &S,
    reader: R,
    content_type: Option<String>,
    config: &ChunkerConfig,
) -> Result<SplitReport, CoreError>
where
    S: ContentStore + ?Sized,
    R: Read,
{
    split_with_limits(store, reader, content_type, config, &FileLimits::default())
}

/// [`split`] with an explicit whole-file resource policy.
///
/// Manifest construction uses one incomplete group per level. Its memory is
/// therefore `O(links_per_manifest * depth)`, independent of the total chunk
/// count; older code retained every data link until EOF.
pub fn split_with_limits<S, R>(
    store: &S,
    reader: R,
    content_type: Option<String>,
    config: &ChunkerConfig,
    limits: &FileLimits,
) -> Result<SplitReport, CoreError>
where
    S: ContentStore + ?Sized,
    R: Read,
{
    config.validate()?;

    let chunker =
        fastcdc::v2020::StreamCDC::new(reader, config.min_size, config.avg_size, config.max_size);

    let mut total: u64 = 0;
    let mut data_chunks: u64 = 0;
    let mut new_chunks: u64 = 0;
    let mut builder = ManifestBuilder::new(store, config.links_per_manifest, limits);

    for item in chunker {
        let chunk = item
            .map_err(|e| CoreError::Io(std::io::Error::other(format!("chunking failed: {}", e))))?;
        let chunk_len = u64::try_from(chunk.data.len()).map_err(|_| {
            CoreError::PreconditionFailed("chunk length does not fit u64".to_string())
        })?;
        total = total.checked_add(chunk_len).ok_or_else(|| {
            CoreError::PreconditionFailed("file byte counter overflowed".to_string())
        })?;
        limits.check("bytes", total, limits.max_file_size)?;
        data_chunks = data_chunks.checked_add(1).ok_or_else(|| {
            CoreError::PreconditionFailed("file chunk counter overflowed".to_string())
        })?;
        limits.check("chunks", data_chunks, limits.max_chunks)?;

        let cid = Cid::compute(&chunk.data);
        // `has_chunk` is deliberately only the accounting hint: for a
        // filesystem it is a stat, and for an object store it may be a HEAD.
        // `put_chunk` remains the integrity/durability gate even on a hit.
        // Implementations are idempotent and may adopt an intact existing
        // object cheaply; FsStore also repairs a mismatched one and indexes a
        // valid orphan from an interrupted deferred ingest.
        let already_present = store.has_chunk(&cid)?;
        let stored = store.put_chunk(&chunk.data, None)?;
        if stored != cid {
            return Err(CoreError::PreconditionFailed(format!(
                "content store returned CID {stored} after being offered {cid}"
            )));
        }
        if !already_present {
            new_chunks = new_chunks.checked_add(1).ok_or_else(|| {
                CoreError::PreconditionFailed("new-chunk counter overflowed".to_string())
            })?;
        } else {
            // Preserve the trait-level in-flight contract for stores whose
            // idempotent put path does not itself record an existing object.
            // FsStore already does; noting it twice is harmless and keeps
            // split correct for other implementations.
            store.note_reference(&cid);
        }
        builder.push_data(Link::unnamed(cid))?;
    }

    // Settle the final incomplete descendant groups. Full groups were settled
    // immediately before their parent part was written; either way, the root
    // can never become durable before something it names.
    store.sync()?;
    let (links, depth) = builder.finish()?;
    // `finish` can emit the final partial part after the sync above. Settle it
    // before publishing the root that names it.
    store.sync()?;

    let payload = ManifestPayload {
        kind: FILE_KIND.to_string(),
        size: Some(total),
        chunks: Some(data_chunks),
        depth,
        links: links.len() as u64,
        chunking: Some(config.describe()),
        content_type,
    };
    let entry = Entry::new(encode_payload(&payload)?, links, manifest_meta());
    let cid = store.put_entry(&entry)?;

    // The root is written last and is the only thing the caller is given, so
    // it is made durable last. Returning a CID the store has not committed to
    // is the one thing this function must not do.
    store.sync()?;

    Ok(SplitReport {
        cid,
        size: total,
        chunks: data_chunks,
        new_chunks,
        depth,
    })
}

#[derive(Debug)]
struct ManifestLevel {
    links: Vec<Link>,
    next_part: u64,
}

impl ManifestLevel {
    fn new(capacity: usize) -> Self {
        Self {
            links: Vec::with_capacity(capacity),
            next_part: 0,
        }
    }
}

/// Incremental carry tree used by [`split_with_limits`].
struct ManifestBuilder<'a, S: ContentStore + ?Sized> {
    store: &'a S,
    fanout: usize,
    limits: &'a FileLimits,
    levels: Vec<ManifestLevel>,
    manifest_nodes: u64,
    manifest_links: u64,
}

impl<'a, S: ContentStore + ?Sized> ManifestBuilder<'a, S> {
    fn new(store: &'a S, fanout: usize, limits: &'a FileLimits) -> Self {
        Self {
            store,
            fanout,
            limits,
            levels: vec![ManifestLevel::new(fanout)],
            manifest_nodes: 0,
            manifest_links: 0,
        }
    }

    fn push_data(&mut self, link: Link) -> Result<(), CoreError> {
        self.push_at(0, link)
    }

    fn ensure_level(&mut self, level: usize) -> Result<(), CoreError> {
        if level >= MAX_MANIFEST_DEPTH as usize {
            return Err(CoreError::FileLimitExceeded {
                resource: "manifest depth",
                value: level as u64 + 1,
                limit: MAX_MANIFEST_DEPTH as u64,
            });
        }
        while self.levels.len() <= level {
            self.levels.push(ManifestLevel::new(self.fanout));
        }
        Ok(())
    }

    /// Push while retaining a full group until a following link proves that
    /// it cannot itself be the root. This is what preserves the old flat-root
    /// CID for exactly-`fanout` files.
    fn push_at(&mut self, level: usize, link: Link) -> Result<(), CoreError> {
        self.ensure_level(level)?;
        if self.levels[level].links.len() == self.fanout {
            let parent = self.flush_part(level)?;
            self.push_at(level + 1, parent)?;
        }
        self.levels[level].links.push(link);
        Ok(())
    }

    fn record_manifest(&mut self, direct_links: usize) -> Result<(), CoreError> {
        let direct_links = u64::try_from(direct_links).map_err(|_| {
            CoreError::PreconditionFailed("manifest link count does not fit u64".to_string())
        })?;
        self.manifest_nodes = self.manifest_nodes.checked_add(1).ok_or_else(|| {
            CoreError::PreconditionFailed("manifest-node counter overflowed".to_string())
        })?;
        self.limits.check(
            "manifest nodes",
            self.manifest_nodes,
            self.limits.max_manifest_nodes,
        )?;
        self.manifest_links = self
            .manifest_links
            .checked_add(direct_links)
            .ok_or_else(|| {
                CoreError::PreconditionFailed("manifest-link counter overflowed".to_string())
            })?;
        self.limits
            .check("manifest links", self.manifest_links, self.limits.max_links)?;
        let fetches = self.manifest_links.checked_add(1).ok_or_else(|| {
            CoreError::PreconditionFailed("file-fetch counter overflowed".to_string())
        })?;
        self.limits
            .check("fetches", fetches, self.limits.max_fetches)
    }

    fn flush_part(&mut self, level: usize) -> Result<Link, CoreError> {
        let group = std::mem::replace(
            &mut self.levels[level].links,
            Vec::with_capacity(self.fanout),
        );
        if group.is_empty() {
            return Err(CoreError::PreconditionFailed(
                "cannot create an empty file-part/v1 node".to_string(),
            ));
        }
        self.record_manifest(group.len())?;
        let depth = u32::try_from(level + 1).map_err(|_| {
            CoreError::PreconditionFailed("manifest depth does not fit u32".to_string())
        })?;
        let payload = ManifestPayload {
            kind: FILE_PART_KIND.to_string(),
            size: None,
            chunks: None,
            depth,
            links: group.len() as u64,
            chunking: None,
            content_type: None,
        };

        // All children must be durable before the part that names them.
        self.store.sync()?;
        let entry = Entry::new(encode_payload(&payload)?, group, manifest_meta());
        let cid = self.store.put_entry(&entry)?;
        let part = self.levels[level].next_part;
        self.levels[level].next_part = part.checked_add(1).ok_or_else(|| {
            CoreError::PreconditionFailed("manifest part counter overflowed".to_string())
        })?;
        Ok(Link::named(cid, format!("part-{part}")))
    }

    fn finish(mut self) -> Result<(Vec<Link>, u32), CoreError> {
        loop {
            let highest = self
                .levels
                .iter()
                .rposition(|level| !level.links.is_empty())
                .unwrap_or(0);
            let Some(lower) = (0..highest).find(|&level| !self.levels[level].links.is_empty())
            else {
                let links = std::mem::take(&mut self.levels[highest].links);
                self.record_manifest(links.len())?;
                let depth = u32::try_from(highest + 1).map_err(|_| {
                    CoreError::PreconditionFailed("manifest depth does not fit u32".to_string())
                })?;
                return Ok((links, depth));
            };

            let parent = self.flush_part(lower)?;
            self.push_at(lower + 1, parent)?;
        }
    }
}

/// Fetch a chunk and require that its bytes still hash to its CID.
fn get_verified<S: ContentStore + ?Sized>(store: &S, cid: &Cid) -> Result<Vec<u8>, CoreError> {
    let bytes = store.get_chunk(cid)?;
    let computed = Cid::compute(&bytes);
    if computed != *cid {
        return Err(CoreError::CidMismatch {
            expected: cid.clone(),
            computed,
        });
    }
    Ok(bytes)
}

/// Verify content all the way down, and report what was checked.
///
/// `get_chunk` re-hashes what it reads, so verifying a *plain* chunk is
/// already complete. A `file/v1` manifest is different: its own bytes
/// hashing correctly proves only that the list of parts is intact, and says
/// nothing about whether the parts are there. Anything that treats those
/// two cases alike reports a file as verified when its data is gone —
/// which is exactly what `dag verify` did, and what the J7 adoption gate
/// did, for every artefact large enough to be chunked.
///
/// Returns `Ok(None)` when `cid` is not a manifest (nothing deeper exists),
/// and `Ok(Some(info))` when the whole file was walked and every part
/// re-hashed. Errors are the usual [`CoreError::ChunkNotFound`] and
/// [`CoreError::CidMismatch`], naming the part that failed rather than the
/// root that named it.
///
/// The cost is a full read of the content, discarded. That is what
/// verification *is* — a check that reads less than everything is a check
/// of less than everything — but it means callers on a hot path should
/// think about when they run it.
pub fn verify_deep<S: ContentStore + ?Sized>(
    store: &S,
    cid: &Cid,
) -> Result<Option<FileInfo>, CoreError> {
    verify_deep_with_limits(store, cid, &FileLimits::default())
}

/// [`verify_deep`] with an explicit whole-file resource policy.
pub fn verify_deep_with_limits<S: ContentStore + ?Sized>(
    store: &S,
    cid: &Cid,
    limits: &FileLimits,
) -> Result<Option<FileInfo>, CoreError> {
    let bytes = get_verified(store, cid)?;
    match parse_manifest_candidate(&bytes)? {
        Some((payload, _)) if payload.kind == FILE_KIND => {
            let info = join_verified_root(store, cid, &bytes, &mut std::io::sink(), limits)?;
            Ok(Some(info))
        }
        // Not a manifest: the re-hash above is the whole check.
        _ => Ok(None),
    }
}

/// Decode bytes that explicitly claim a file-manifest kind.
///
/// Ordinary content returns `Ok(None)`. Once an entry claims `file/v1` or
/// `file-part/v1`, malformed/missing fields are corruption rather than a cue
/// to reinterpret the CBOR bytes as an ordinary file.
fn parse_manifest_candidate(bytes: &[u8]) -> Result<Option<(ManifestPayload, Entry)>, CoreError> {
    let Ok(entry) = Entry::from_bytes_cbor(bytes) else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&entry.payload) else {
        return Ok(None);
    };
    let Some(kind) = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    else {
        return Ok(None);
    };
    if kind != FILE_KIND && kind != FILE_PART_KIND {
        return Ok(None);
    }
    let payload = serde_json::from_value(value).map_err(|error| {
        CoreError::InvalidCid(format!("malformed {kind} manifest payload: {error}"))
    })?;
    Ok(Some((payload, entry)))
}

/// Describe `cid` if it is a file manifest; `Ok(None)` if it is ordinary
/// content. Errors only for store failures (missing chunk, I/O).
pub fn file_info<S: ContentStore + ?Sized>(
    store: &S,
    cid: &Cid,
) -> Result<Option<FileInfo>, CoreError> {
    file_info_with_limits(store, cid, &FileLimits::default())
}

/// [`file_info`] with an explicit whole-file resource policy.
pub fn file_info_with_limits<S: ContentStore + ?Sized>(
    store: &S,
    cid: &Cid,
    limits: &FileLimits,
) -> Result<Option<FileInfo>, CoreError> {
    let bytes = get_verified(store, cid)?;
    inspect_from_bytes_with_limits(&bytes, limits)
}

/// [`file_info`] over bytes the caller already fetched.
pub fn info_from_bytes(bytes: &[u8]) -> Option<FileInfo> {
    inspect_from_bytes(bytes).ok().flatten()
}

/// Fallible form of [`info_from_bytes`] that distinguishes ordinary content
/// from a malformed or over-budget `file/v1` claim.
pub fn inspect_from_bytes(bytes: &[u8]) -> Result<Option<FileInfo>, CoreError> {
    inspect_from_bytes_with_limits(bytes, &FileLimits::default())
}

/// [`inspect_from_bytes`] with an explicit whole-file resource policy.
pub fn inspect_from_bytes_with_limits(
    bytes: &[u8],
    limits: &FileLimits,
) -> Result<Option<FileInfo>, CoreError> {
    let Some((payload, entry)) = parse_manifest_candidate(bytes)? else {
        return Ok(None);
    };
    if payload.kind != FILE_KIND {
        return Ok(None);
    }
    validate_root(&payload, &entry, limits).map(Some)
}

/// Reassemble the file behind `cid`, writing its bytes to `writer`.
///
/// Every chunk — data, part, and the root itself — is re-hashed against its
/// CID as it is read, and the total size and chunk count are checked against
/// what the manifest declares. An error names the first node that fails.
pub fn join<S, W>(store: &S, cid: &Cid, writer: &mut W) -> Result<FileInfo, CoreError>
where
    S: ContentStore + ?Sized,
    W: Write,
{
    join_with_limits(store, cid, writer, &FileLimits::default())
}

/// [`join`] with an explicit whole-file resource policy.
pub fn join_with_limits<S, W>(
    store: &S,
    cid: &Cid,
    writer: &mut W,
    limits: &FileLimits,
) -> Result<FileInfo, CoreError>
where
    S: ContentStore + ?Sized,
    W: Write,
{
    let bytes = get_verified(store, cid)?;
    join_verified_root(store, cid, &bytes, writer, limits)
}

fn join_verified_root<S, W>(
    store: &S,
    cid: &Cid,
    bytes: &[u8],
    writer: &mut W,
    limits: &FileLimits,
) -> Result<FileInfo, CoreError>
where
    S: ContentStore + ?Sized,
    W: Write,
{
    let (payload, entry) = parse_manifest_candidate(bytes)?
        .ok_or_else(|| CoreError::PreconditionFailed(format!("{} is not a file manifest", cid)))?;
    if payload.kind != FILE_KIND {
        return Err(CoreError::PreconditionFailed(format!(
            "{} is not a file manifest (kind {:?})",
            cid, payload.kind
        )));
    }

    let info = validate_root(&payload, &entry, limits)?;
    let mut budget = WalkBudget::new(limits, info.size, info.chunks)?;
    budget.charge_node()?;
    budget.charge_links(entry.links.len())?;
    walk(store, &entry.links, info.depth, writer, &mut budget)?;

    if budget.written != info.size {
        return Err(CoreError::InvalidCid(format!(
            "file size mismatch: manifest {} declares {} bytes, chunks total {}",
            cid, info.size, budget.written
        )));
    }
    if budget.chunks != info.chunks {
        return Err(CoreError::InvalidCid(format!(
            "file chunk-count mismatch: manifest {} declares {}, found {}",
            cid, info.chunks, budget.chunks
        )));
    }

    Ok(info)
}

fn validate_root(
    payload: &ManifestPayload,
    entry: &Entry,
    limits: &FileLimits,
) -> Result<FileInfo, CoreError> {
    if payload.depth == 0 || payload.depth > MAX_MANIFEST_DEPTH {
        return Err(CoreError::PreconditionFailed(format!(
            "manifest declares depth {}, outside the legal range 1..={}",
            payload.depth, MAX_MANIFEST_DEPTH
        )));
    }
    validate_direct_links("root manifest", payload.links, entry.links.len())?;

    let size = payload.size.ok_or_else(|| {
        CoreError::InvalidCid("file/v1 root is missing mandatory `size`".to_string())
    })?;
    let chunks = payload.chunks.ok_or_else(|| {
        CoreError::InvalidCid("file/v1 root is missing mandatory `chunks`".to_string())
    })?;
    limits.check("bytes", size, limits.max_file_size)?;
    limits.check("chunks", chunks, limits.max_chunks)?;
    limits.check("manifest links", payload.links, limits.max_links)?;

    if chunks == 0 {
        if size != 0 || !entry.links.is_empty() || payload.depth != 1 {
            return Err(CoreError::InvalidCid(
                "an empty file/v1 root must have size 0, chunks 0, depth 1 and no links"
                    .to_string(),
            ));
        }
    } else {
        if size == 0 || entry.links.is_empty() {
            return Err(CoreError::InvalidCid(
                "a non-empty file/v1 root must declare positive size and carry links".to_string(),
            ));
        }
        if chunks > size {
            return Err(CoreError::InvalidCid(format!(
                "file/v1 declares {chunks} non-empty chunks for only {size} bytes"
            )));
        }
        if payload.links > chunks {
            return Err(CoreError::InvalidCid(format!(
                "file/v1 root carries {} branches but declares only {chunks} chunks",
                payload.links
            )));
        }
        if payload.depth == 1 && payload.links != chunks {
            return Err(CoreError::InvalidCid(format!(
                "flat file/v1 root carries {} links but declares {chunks} chunks",
                payload.links
            )));
        }
    }

    Ok(FileInfo {
        size,
        chunks,
        depth: payload.depth,
        content_type: payload.content_type.clone(),
    })
}

fn validate_direct_links(label: &str, declared: u64, actual: usize) -> Result<(), CoreError> {
    if actual > MAX_LINKS_PER_MANIFEST {
        return Err(CoreError::FileLimitExceeded {
            resource: "links in one manifest node",
            value: actual as u64,
            limit: MAX_LINKS_PER_MANIFEST as u64,
        });
    }
    if declared != actual as u64 {
        return Err(CoreError::InvalidCid(format!(
            "{label} declares {declared} links but carries {actual}"
        )));
    }
    Ok(())
}

struct WalkBudget<'a> {
    limits: &'a FileLimits,
    declared_size: u64,
    declared_chunks: u64,
    written: u64,
    chunks: u64,
    manifest_nodes: u64,
    links: u64,
    fetches: u64,
}

impl<'a> WalkBudget<'a> {
    fn new(
        limits: &'a FileLimits,
        declared_size: u64,
        declared_chunks: u64,
    ) -> Result<Self, CoreError> {
        limits.check("fetches", 1, limits.max_fetches)?;
        Ok(Self {
            limits,
            declared_size,
            declared_chunks,
            written: 0,
            chunks: 0,
            manifest_nodes: 0,
            links: 0,
            fetches: 1,
        })
    }

    fn charge_node(&mut self) -> Result<(), CoreError> {
        self.manifest_nodes = checked_counter("manifest-node", self.manifest_nodes, 1)?;
        self.limits.check(
            "manifest nodes",
            self.manifest_nodes,
            self.limits.max_manifest_nodes,
        )
    }

    fn charge_links(&mut self, direct_links: usize) -> Result<(), CoreError> {
        self.links = checked_counter("manifest-link", self.links, direct_links as u64)?;
        self.limits
            .check("manifest links", self.links, self.limits.max_links)
    }

    fn charge_fetch(&mut self) -> Result<(), CoreError> {
        self.fetches = checked_counter("file-fetch", self.fetches, 1)?;
        self.limits
            .check("fetches", self.fetches, self.limits.max_fetches)
    }

    fn require_leaf_capacity(&self, links: usize) -> Result<(), CoreError> {
        let remaining = self
            .declared_chunks
            .checked_sub(self.chunks)
            .ok_or_else(|| CoreError::InvalidCid("file chunk counter exceeded its total".into()))?;
        if links as u64 > remaining {
            return Err(CoreError::InvalidCid(format!(
                "manifest branch needs at least {links} chunks but only {remaining} remain declared"
            )));
        }
        Ok(())
    }
}

fn checked_counter(label: &str, current: u64, add: u64) -> Result<u64, CoreError> {
    current
        .checked_add(add)
        .ok_or_else(|| CoreError::InvalidCid(format!("{label} counter overflowed")))
}

fn walk<S, W>(
    store: &S,
    links: &[Link],
    depth: u32,
    writer: &mut W,
    budget: &mut WalkBudget<'_>,
) -> Result<(), CoreError>
where
    S: ContentStore + ?Sized,
    W: Write,
{
    // Every non-empty descendant branch must eventually produce at least one
    // non-empty leaf. This lower-bound check catches lying totals before a
    // wide branch performs any leaf fetches.
    budget.require_leaf_capacity(links.len())?;

    if depth == 1 {
        // Links are data chunks.
        for link in links {
            budget.chunks = checked_counter("file chunk", budget.chunks, 1)?;
            if budget.chunks > budget.declared_chunks {
                return Err(CoreError::InvalidCid(format!(
                    "file exposes more than its declared {} chunks",
                    budget.declared_chunks
                )));
            }
            budget.charge_fetch()?;
            let bytes = get_verified(store, &link.target)?;
            if bytes.is_empty() {
                return Err(CoreError::InvalidCid(format!(
                    "file data link {} names an empty chunk",
                    link.target
                )));
            }
            let next = checked_counter("file byte", budget.written, bytes.len() as u64)?;
            if next > budget.declared_size {
                return Err(CoreError::InvalidCid(format!(
                    "file bytes exceed the declared size {} before output",
                    budget.declared_size
                )));
            }
            budget
                .limits
                .check("bytes", next, budget.limits.max_file_size)?;
            writer.write_all(&bytes)?;
            budget.written = next;
        }
        return Ok(());
    }

    // Links are part entries one level down. Depth comes from the parent, so
    // a raw chunk that happens to decode as CBOR can never be mistaken for
    // structure — the tree's shape is declared, not sniffed.
    for link in links {
        // A repeated part is a repeated logical node even when its CID is the
        // same. Spend that budget before the store read so an exhausted walk
        // performs no additional attacker-amplified I/O.
        budget.charge_node()?;
        budget.charge_fetch()?;
        let bytes = get_verified(store, &link.target)?;
        let (payload, entry) = parse_manifest_candidate(&bytes)?.ok_or_else(|| {
            CoreError::InvalidCid(format!("{} is not a file part entry", link.target))
        })?;
        if payload.kind != FILE_PART_KIND || payload.depth != depth - 1 {
            return Err(CoreError::InvalidCid(format!(
                "part {} has kind {:?} depth {}, expected {:?} depth {}",
                link.target,
                payload.kind,
                payload.depth,
                FILE_PART_KIND,
                depth - 1
            )));
        }
        if payload.size.is_some()
            || payload.chunks.is_some()
            || payload.chunking.is_some()
            || payload.content_type.is_some()
        {
            return Err(CoreError::InvalidCid(format!(
                "part {} carries root-only file metadata",
                link.target
            )));
        }
        if entry.links.is_empty() {
            return Err(CoreError::InvalidCid(format!(
                "part {} carries no links",
                link.target
            )));
        }
        validate_direct_links(
            &format!("part {}", link.target),
            payload.links,
            entry.links.len(),
        )?;
        budget.charge_links(entry.links.len())?;
        walk(store, &entry.links, depth - 1, writer, budget)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    /// Minimal in-memory store. dag-storage depends on dag-core, so these
    /// tests cannot use FsStore; content addressing makes the double trivial.
    ///
    /// It also models the one thing a real deferred store has that a HashMap
    /// does not: a write becomes *durable* only when [`ContentStore::sync`]
    /// says so. Each sync is a numbered round, and every chunk written since
    /// the last one is stamped with it, so a test can ask which of two CIDs
    /// reached the disk first.
    #[derive(Default)]
    struct MemStore {
        chunks: Mutex<HashMap<Cid, Vec<u8>>>,
        unsynced: Mutex<Vec<Cid>>,
        /// CID → the sync round that made it durable.
        durable_in: Mutex<HashMap<Cid, usize>>,
        round: Mutex<usize>,
        gets: Mutex<HashMap<Cid, u64>>,
    }

    impl MemStore {
        /// Which sync round made `cid` durable; `None` if it never was.
        fn durable_round(&self, cid: &Cid) -> Option<usize> {
            self.durable_in.lock().unwrap().get(cid).copied()
        }
    }

    impl MemStore {
        fn corrupt(&self, cid: &Cid, bytes: &[u8]) {
            self.chunks
                .lock()
                .unwrap()
                .insert(cid.clone(), bytes.to_vec());
        }

        fn remove(&self, cid: &Cid) {
            self.chunks.lock().unwrap().remove(cid);
        }

        fn len(&self) -> usize {
            self.chunks.lock().unwrap().len()
        }

        fn get_count(&self, cid: &Cid) -> u64 {
            self.gets.lock().unwrap().get(cid).copied().unwrap_or(0)
        }
    }

    impl ContentStore for MemStore {
        fn put_chunk(&self, bytes: &[u8], _meta: Option<MetaHint>) -> Result<Cid, CoreError> {
            if bytes.len() > MAX_CHUNK_SIZE {
                return Err(CoreError::ChunkTooLarge {
                    size: bytes.len(),
                    max_size: MAX_CHUNK_SIZE,
                });
            }
            let cid = Cid::compute(bytes);
            self.chunks
                .lock()
                .unwrap()
                .insert(cid.clone(), bytes.to_vec());
            self.unsynced.lock().unwrap().push(cid.clone());
            Ok(cid)
        }

        fn sync(&self) -> Result<(), CoreError> {
            let mut round = self.round.lock().unwrap();
            *round += 1;
            let mut durable = self.durable_in.lock().unwrap();
            for cid in self.unsynced.lock().unwrap().drain(..) {
                durable.entry(cid).or_insert(*round);
            }
            Ok(())
        }

        fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError> {
            *self.gets.lock().unwrap().entry(cid.clone()).or_default() += 1;
            self.chunks
                .lock()
                .unwrap()
                .get(cid)
                .cloned()
                .ok_or_else(|| CoreError::ChunkNotFound(cid.to_hex()))
        }

        fn has_chunk(&self, cid: &Cid) -> Result<bool, CoreError> {
            Ok(self.chunks.lock().unwrap().contains_key(cid))
        }
    }

    /// Deterministic pseudorandom bytes (xorshift64*), so tests never depend
    /// on an RNG crate and chunk boundaries are reproducible.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let word = state.wrapping_mul(0x2545F4914F6CDD1D);
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Small chunks so multi-chunk behaviour appears without megabytes.
    fn small_config() -> ChunkerConfig {
        ChunkerConfig {
            min_size: 1024,
            avg_size: 4096,
            max_size: 16384,
            links_per_manifest: 65_536,
        }
    }

    fn round_trip(data: &[u8], config: &ChunkerConfig) -> (MemStore, SplitReport, Vec<u8>) {
        let store = MemStore::default();
        let report = split(&store, Cursor::new(data.to_vec()), None, config).unwrap();

        let mut out = Vec::new();
        let info = join(&store, &report.cid, &mut out).unwrap();

        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.chunks, report.chunks);
        (store, report, out)
    }

    #[test]
    fn multi_chunk_round_trip_is_byte_identical() {
        let data = noise(200 * 1024, 42);
        let (_store, report, out) = round_trip(&data, &small_config());

        assert_eq!(out, data, "reassembly must be byte-identical");
        assert!(
            report.chunks > 5,
            "should have split: {} chunks",
            report.chunks
        );
        assert_eq!(
            report.new_chunks, report.chunks,
            "fresh store: all chunks new"
        );
        assert_eq!(report.depth, 1);
    }

    #[test]
    fn splitting_is_deterministic() {
        let data = noise(100 * 1024, 7);
        let store = MemStore::default();
        let cfg = small_config();

        let a = split(&store, Cursor::new(data.clone()), None, &cfg).unwrap();
        let b = split(&store, Cursor::new(data), None, &cfg).unwrap();

        assert_eq!(a.cid, b.cid, "same bytes, same config, same manifest CID");
        assert_eq!(b.new_chunks, 0, "second split stores nothing new");
    }

    #[test]
    fn incremental_construction_preserves_the_previous_manifest_cid() {
        let data = noise(300 * 1024, 0x51A7);
        let store = MemStore::default();
        let cfg = ChunkerConfig {
            links_per_manifest: 3,
            ..small_config()
        };
        let report = split(&store, Cursor::new(data.clone()), None, &cfg).unwrap();

        // Reference implementation of the original all-links-in-memory fold.
        // Keeping it in a regression test pins the compatibility promise while
        // production uses the incremental carry tree.
        let mut links = fastcdc::v2020::StreamCDC::new(
            Cursor::new(data.clone()),
            cfg.min_size,
            cfg.avg_size,
            cfg.max_size,
        )
        .map(|chunk| Link::unnamed(Cid::compute(&chunk.unwrap().data)))
        .collect::<Vec<_>>();
        let chunks = links.len() as u64;
        let mut depth = 1u32;
        while links.len() > cfg.links_per_manifest {
            let mut parents = Vec::new();
            for (index, group) in links.chunks(cfg.links_per_manifest).enumerate() {
                let payload = ManifestPayload {
                    kind: FILE_PART_KIND.to_string(),
                    size: None,
                    chunks: None,
                    depth,
                    links: group.len() as u64,
                    chunking: None,
                    content_type: None,
                };
                let entry = Entry::new(
                    encode_payload(&payload).unwrap(),
                    group.to_vec(),
                    manifest_meta(),
                );
                parents.push(Link::named(
                    store.put_entry(&entry).unwrap(),
                    format!("part-{index}"),
                ));
            }
            links = parents;
            depth += 1;
        }
        let payload = ManifestPayload {
            kind: FILE_KIND.to_string(),
            size: Some(data.len() as u64),
            chunks: Some(chunks),
            depth,
            links: links.len() as u64,
            chunking: Some(cfg.describe()),
            content_type: None,
        };
        let old_root = store
            .put_entry(&Entry::new(
                encode_payload(&payload).unwrap(),
                links,
                manifest_meta(),
            ))
            .unwrap();

        assert_eq!(report.cid, old_root);
        assert_eq!(report.depth, depth);
        assert_eq!(report.chunks, chunks);
    }

    #[test]
    fn repeating_a_split_repairs_a_present_but_corrupt_data_chunk() {
        let data = noise(100 * 1024, 0xC0FFEE);
        let store = MemStore::default();
        let cfg = small_config();

        let first = split(&store, Cursor::new(data.clone()), None, &cfg).unwrap();
        assert_eq!(first.depth, 1, "test needs direct data links");
        let links = store.get_links(&first.cid).unwrap();
        let victim = links[links.len() / 2].target.clone();

        store.corrupt(&victim, b"short crash residue");
        assert!(store.has_chunk(&victim).unwrap(), "presence is the trap");
        assert!(
            join(&store, &first.cid, &mut Vec::new()).is_err(),
            "precondition: the manifest must detect the corrupt data chunk"
        );

        let repeated = split(&store, Cursor::new(data.clone()), None, &cfg).unwrap();
        assert_eq!(repeated.cid, first.cid, "repair must not change identity");
        assert_eq!(
            repeated.new_chunks, 0,
            "the corrupt canonical path was present, even though put repaired it"
        );

        let mut joined = Vec::new();
        join(&store, &repeated.cid, &mut joined).unwrap();
        assert_eq!(joined, data, "the repeated ingest must repair the victim");
    }

    /// The reason CDC exists: appending to a file must not re-store its body.
    #[test]
    fn appending_shares_almost_every_chunk() {
        let base = noise(150 * 1024, 99);
        let mut extended = base.clone();
        extended.extend_from_slice(&noise(20 * 1024, 100));

        let store = MemStore::default();
        let cfg = small_config();

        let first = split(&store, Cursor::new(base), None, &cfg).unwrap();
        let second = split(&store, Cursor::new(extended), None, &cfg).unwrap();

        assert!(
            second.new_chunks < second.chunks / 2,
            "an append should reuse most chunks: {} new of {}",
            second.new_chunks,
            second.chunks
        );
        assert_ne!(first.cid, second.cid);
    }

    #[test]
    fn empty_and_tiny_inputs_round_trip() {
        let (_s, report, out) = round_trip(&[], &small_config());
        assert_eq!(report.chunks, 0);
        assert!(out.is_empty());

        let (_s, report, out) = round_trip(b"x", &small_config());
        assert_eq!(report.chunks, 1);
        assert_eq!(out, b"x");
    }

    #[test]
    fn deep_manifests_round_trip() {
        // Force parts: 3 links per manifest over ~40 chunks -> depth 3.
        let cfg = ChunkerConfig {
            links_per_manifest: 3,
            ..small_config()
        };
        let data = noise(160 * 1024, 5);
        let (_store, report, out) = round_trip(&data, &cfg);

        assert!(
            report.depth >= 2,
            "should have needed parts: depth {}",
            report.depth
        );
        assert_eq!(out, data);
    }

    #[test]
    fn a_tampered_chunk_is_named_on_join() {
        let data = noise(100 * 1024, 11);
        let store = MemStore::default();
        let report = split(&store, Cursor::new(data), None, &small_config()).unwrap();

        // Corrupt one data chunk in place.
        let links = store.get_links(&report.cid).unwrap();
        let victim = &links[links.len() / 2].target;
        store.corrupt(victim, b"tampered");

        let err = join(&store, &report.cid, &mut Vec::new()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("CID mismatch"),
            "tampering must surface as a hash mismatch, got: {}",
            msg
        );
    }

    #[test]
    fn a_missing_chunk_fails_join() {
        let data = noise(64 * 1024, 13);
        let store = MemStore::default();
        let report = split(&store, Cursor::new(data), None, &small_config()).unwrap();

        let links = store.get_links(&report.cid).unwrap();
        store.remove(&links[0].target);

        let err = join(&store, &report.cid, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, CoreError::ChunkNotFound(_)), "got: {}", err);
    }

    #[test]
    fn ordinary_content_is_not_a_manifest() {
        let store = MemStore::default();
        let cid = store.put_chunk(b"just some bytes", None).unwrap();

        assert!(file_info(&store, &cid).unwrap().is_none());
        let err = join(&store, &cid, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(err, CoreError::PreconditionFailed(_)),
            "got: {}",
            err
        );
    }

    #[test]
    fn file_info_reports_the_manifest() {
        let data = noise(50 * 1024, 3);
        let store = MemStore::default();
        let report = split(
            &store,
            Cursor::new(data.clone()),
            Some("application/octet-stream".to_string()),
            &small_config(),
        )
        .unwrap();

        let info = file_info(&store, &report.cid).unwrap().unwrap();
        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.chunks, report.chunks);
        assert_eq!(
            info.content_type,
            Some("application/octet-stream".to_string())
        );
    }

    /// The auto path must sit exactly on the boundary: MAX_CHUNK_SIZE bytes
    /// is one plain chunk, one byte more is a manifest.
    #[test]
    fn store_auto_switches_exactly_at_the_chunk_limit() {
        let store = MemStore::default();
        let cfg = ChunkerConfig::default();

        let at_limit = noise(MAX_CHUNK_SIZE, 1);
        match store_auto(&store, Cursor::new(at_limit.clone()), None, false, &cfg).unwrap() {
            StoredContent::Chunk { cid, size } => {
                assert_eq!(size, MAX_CHUNK_SIZE as u64);
                assert_eq!(cid, Cid::compute(&at_limit), "plain chunk CID unchanged");
            }
            StoredContent::File(_) => panic!("content at the limit must stay a plain chunk"),
        }

        let over = noise(MAX_CHUNK_SIZE + 1, 2);
        match store_auto(&store, Cursor::new(over.clone()), None, false, &cfg).unwrap() {
            StoredContent::File(report) => {
                assert_eq!(report.size, over.len() as u64);
                // And it reassembles: the head buffer and the stream tail must
                // have been stitched back together without losing a byte.
                let mut out = Vec::new();
                join(&store, &report.cid, &mut out).unwrap();
                assert_eq!(out, over);
            }
            StoredContent::Chunk { .. } => panic!("oversized content must be chunked"),
        }
    }

    #[test]
    fn store_auto_forced_chunking_covers_small_content() {
        let store = MemStore::default();
        match store_auto(
            &store,
            Cursor::new(b"tiny".to_vec()),
            None,
            true,
            &small_config(),
        )
        .unwrap()
        {
            StoredContent::File(report) => assert_eq!(report.chunks, 1),
            StoredContent::Chunk { .. } => panic!("force_chunked must produce a manifest"),
        }
    }

    #[test]
    fn invalid_configs_are_refused() {
        let store = MemStore::default();
        let bad =
            |cfg: ChunkerConfig| split(&store, Cursor::new(vec![0u8; 10]), None, &cfg).unwrap_err();

        // min >= avg
        let e = bad(ChunkerConfig {
            min_size: 4096,
            avg_size: 4096,
            max_size: 16384,
            links_per_manifest: 10,
        });
        assert!(matches!(e, CoreError::PreconditionFailed(_)));

        // max beyond the chunk limit
        let e = bad(ChunkerConfig {
            min_size: 1024,
            avg_size: 4096,
            max_size: MAX_CHUNK_SIZE + 1,
            links_per_manifest: 10,
        });
        assert!(matches!(e, CoreError::ChunkTooLarge { .. }));

        let e = bad(ChunkerConfig {
            min_size: 1024,
            avg_size: 4096,
            max_size: 16384,
            links_per_manifest: MAX_LINKS_PER_MANIFEST + 1,
        });
        assert!(matches!(e, CoreError::PreconditionFailed(_)));
    }

    #[test]
    fn default_fanout_leaves_room_inside_the_entry_ceiling() {
        let leaf = Cid::compute(b"leaf");
        let links = (0..DEFAULT_LINKS_PER_MANIFEST)
            .map(|_| Link::unnamed(leaf.clone()))
            .collect::<Vec<_>>();
        let payload = ManifestPayload {
            kind: FILE_KIND.to_string(),
            size: Some(DEFAULT_LINKS_PER_MANIFEST as u64),
            chunks: Some(DEFAULT_LINKS_PER_MANIFEST as u64),
            depth: 1,
            links: DEFAULT_LINKS_PER_MANIFEST as u64,
            chunking: Some(ChunkerConfig::default().describe()),
            content_type: None,
        };
        let encoded = Entry::new(encode_payload(&payload).unwrap(), links, manifest_meta())
            .to_bytes_cbor()
            .unwrap();
        assert!(encoded.len() < MAX_CHUNK_SIZE);
    }

    /// Build a manifest entry by hand, so tests can declare shapes `split`
    /// would never produce — which is exactly what a hostile uploader does.
    fn forge(
        store: &MemStore,
        kind: &str,
        depth: u32,
        links: Vec<Link>,
        size: Option<u64>,
        chunks: Option<u64>,
    ) -> Cid {
        let payload = ManifestPayload {
            kind: kind.to_string(),
            size,
            chunks,
            depth,
            links: links.len() as u64,
            chunking: None,
            content_type: None,
        };
        let entry = Entry::new(encode_payload(&payload).unwrap(), links, manifest_meta());
        store.put_entry(&entry).unwrap()
    }

    fn forge_json(store: &MemStore, payload: serde_json::Value, links: Vec<Link>) -> Cid {
        let entry = Entry::new(
            serde_json::to_vec(&payload).unwrap(),
            links,
            manifest_meta(),
        );
        store.put_entry(&entry).unwrap()
    }

    #[test]
    fn roots_require_honest_mandatory_totals_and_direct_link_count() {
        let store = MemStore::default();
        let leaf = store.put_chunk(b"data", None).unwrap();

        for payload in [
            serde_json::json!({
                "kind": FILE_KIND,
                "depth": 1,
                "links": 1,
                "chunks": 1
            }),
            serde_json::json!({
                "kind": FILE_KIND,
                "depth": 1,
                "links": 1,
                "size": 4
            }),
            serde_json::json!({
                "kind": FILE_KIND,
                "depth": 1,
                "links": 2,
                "size": 4,
                "chunks": 1
            }),
            serde_json::json!({
                "kind": FILE_KIND,
                "depth": 1,
                "links": 1,
                "size": 3,
                "chunks": 1
            }),
            serde_json::json!({
                "kind": FILE_KIND,
                "depth": 1,
                "links": 1,
                "size": 4,
                "chunks": 2
            }),
        ] {
            let root = forge_json(&store, payload, vec![Link::unnamed(leaf.clone())]);
            let err = join(&store, &root, &mut Vec::new()).unwrap_err();
            assert!(
                matches!(err, CoreError::InvalidCid(_)),
                "malformed root must fail closed, got: {err}"
            );
        }
    }

    /// This is the compact amplification primitive from the review: one
    /// 4 MiB object named 65,536 times asks a naive sink verifier to process
    /// 256 GiB. The mandatory root total is checked against policy before the
    /// first repeated leaf fetch.
    #[test]
    fn sixty_five_thousand_repeated_four_mib_leaves_are_rejected_pre_fetch() {
        let store = MemStore::default();
        let leaf = store.put_chunk(&vec![7; MAX_CHUNK_SIZE], None).unwrap();
        let count = 65_536u64;
        let size = count.checked_mul(MAX_CHUNK_SIZE as u64).unwrap();
        // A flat 65,536-link Entry is itself slightly over 4 MiB once CBOR
        // overhead is included, so express the same logical amplification as
        // two references to one 32,768-link part.
        let part = forge(
            &store,
            FILE_PART_KIND,
            1,
            (0..count / 2)
                .map(|_| Link::unnamed(leaf.clone()))
                .collect(),
            None,
            None,
        );
        let root = forge(
            &store,
            FILE_KIND,
            2,
            vec![Link::unnamed(part.clone()), Link::unnamed(part.clone())],
            Some(size),
            Some(count),
        );

        let err = join(&store, &root, &mut std::io::sink()).unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::FileLimitExceeded {
                    resource: "bytes",
                    ..
                }
            ),
            "got: {err}"
        );
        assert_eq!(
            store.get_count(&leaf),
            0,
            "declared over-limit output must fail before fetching a repeated leaf"
        );
        assert_eq!(
            store.get_count(&part),
            0,
            "declared over-limit output must fail before fetching a repeated part"
        );
    }

    /// Sharing a part CID does not share its logical work. Each occurrence is
    /// charged before fetch/descent, so a depth-two repeated subtree cannot
    /// evade the node budget by hashing to one object.
    #[test]
    fn depth_two_repeated_subtrees_spend_budget_per_occurrence() {
        let store = MemStore::default();
        let leaf = store.put_chunk(b"x", None).unwrap();
        let part = forge(
            &store,
            FILE_PART_KIND,
            1,
            vec![Link::unnamed(leaf.clone()), Link::unnamed(leaf)],
            None,
            None,
        );
        let repeated = 1_000u64;
        let root = forge(
            &store,
            FILE_KIND,
            2,
            (0..repeated).map(|_| Link::unnamed(part.clone())).collect(),
            Some(repeated * 2),
            Some(repeated * 2),
        );
        let limits = FileLimits {
            max_file_size: repeated * 2,
            max_chunks: repeated * 2,
            max_manifest_nodes: 2, // root plus exactly one part visit
            max_links: 10_000,
            max_fetches: 10_000,
        };

        let mut output = Vec::new();
        let err = join_with_limits(&store, &root, &mut output, &limits).unwrap_err();
        assert!(
            matches!(
                err,
                CoreError::FileLimitExceeded {
                    resource: "manifest nodes",
                    value: 3,
                    limit: 2
                }
            ),
            "got: {err}"
        );
        assert_eq!(output, b"xx");
        assert_eq!(
            store.get_count(&part),
            1,
            "the second logical visit must be refused before another store fetch"
        );
    }

    #[test]
    fn split_stops_at_the_byte_and_chunk_budgets_without_publishing_a_root() {
        let store = MemStore::default();
        let limits = FileLimits {
            max_file_size: 8 * 1024,
            max_chunks: 1,
            max_manifest_nodes: 16,
            max_links: 16,
            max_fetches: 17,
        };
        let err = split_with_limits(
            &store,
            Cursor::new(noise(64 * 1024, 44)),
            None,
            &small_config(),
            &limits,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::FileLimitExceeded { .. }));
        assert!(
            store
                .chunks
                .lock()
                .unwrap()
                .values()
                .all(|bytes| parse_manifest_candidate(bytes).unwrap().is_none()),
            "an over-limit ingest may leave orphan data chunks but never a published manifest"
        );
    }

    #[test]
    fn all_file_walk_counters_fail_closed_on_overflow() {
        assert!(checked_counter("test", u64::MAX, 1).is_err());

        let limits = FileLimits {
            max_file_size: u64::MAX,
            max_chunks: u64::MAX,
            max_manifest_nodes: u64::MAX,
            max_links: u64::MAX,
            max_fetches: u64::MAX,
        };
        let mut budget = WalkBudget {
            limits: &limits,
            declared_size: u64::MAX,
            declared_chunks: u64::MAX,
            written: 0,
            chunks: 0,
            manifest_nodes: u64::MAX,
            links: u64::MAX,
            fetches: u64::MAX,
        };
        assert!(budget.charge_node().is_err());
        assert!(budget.charge_links(1).is_err());
        assert!(budget.charge_fetch().is_err());
    }

    #[test]
    fn incremental_builder_never_retains_the_whole_large_link_list() {
        let store = MemStore::default();
        let limits = FileLimits::default();
        let fanout = 64usize;
        let mut builder = ManifestBuilder::new(&store, fanout, &limits);
        let leaf = Cid::compute(b"same logical leaf");
        for _ in 0..100_000 {
            builder.push_data(Link::unnamed(leaf.clone())).unwrap();
            let buffered: usize = builder.levels.iter().map(|level| level.links.len()).sum();
            assert!(
                buffered <= fanout * builder.levels.len(),
                "only one bounded incomplete group may be retained per level"
            );
        }
        let (root_links, depth) = builder.finish().unwrap();
        assert!(root_links.len() <= fanout);
        assert!(depth > 1);
    }

    /// `depth` is an attacker-authored `u32`, and `walk` used to recurse once
    /// per declared level. ~30 000 levels costs under 4 MB of chunks and
    /// overflowed the stack — a `fatal runtime error` Rust cannot catch, so no
    /// amount of task isolation helps. The ceiling has to be a check.
    #[test]
    fn an_absurd_declared_depth_is_refused_before_recursing() {
        let store = MemStore::default();
        let leaf = store.put_chunk(b"data", None).unwrap();
        let root = forge(
            &store,
            FILE_KIND,
            30_000,
            vec![Link::unnamed(leaf)],
            Some(4),
            Some(1),
        );

        let err = join(&store, &root, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(err, CoreError::PreconditionFailed(_)),
            "got: {}",
            err
        );
        assert!(
            err.to_string().contains(&MAX_MANIFEST_DEPTH.to_string()),
            "the error should name the ceiling, got: {}",
            err
        );
    }

    /// Depth 0 with links is not merely nonsense: `depth - 1` underflowed,
    /// which panics in debug and produces `u32::MAX` in release.
    #[test]
    fn depth_zero_is_refused_rather_than_underflowing() {
        let store = MemStore::default();
        let leaf = store.put_chunk(b"data", None).unwrap();
        let root = forge(
            &store,
            FILE_KIND,
            0,
            vec![Link::unnamed(leaf)],
            Some(4),
            Some(1),
        );

        let err = join(&store, &root, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(err, CoreError::PreconditionFailed(_)),
            "got: {}",
            err
        );
    }

    /// The ceiling must be above anything legitimate, so check the boundary
    /// itself still reassembles — a chain of single-link parts exactly
    /// `MAX_MANIFEST_DEPTH` levels tall.
    #[test]
    fn a_manifest_at_the_depth_ceiling_still_joins() {
        let store = MemStore::default();
        let leaf = store.put_chunk(b"payload", None).unwrap();

        // Levels 1..MAX are part entries; the root sits at MAX.
        let mut child = Link::unnamed(leaf);
        for depth in 1..MAX_MANIFEST_DEPTH {
            let cid = forge(&store, FILE_PART_KIND, depth, vec![child], None, None);
            child = Link::named(cid, format!("part-{}", depth));
        }
        let root = forge(
            &store,
            FILE_KIND,
            MAX_MANIFEST_DEPTH,
            vec![child],
            Some(7),
            Some(1),
        );

        let mut out = Vec::new();
        let info = join(&store, &root, &mut out).unwrap();
        assert_eq!(out, b"payload");
        assert_eq!(info.depth, MAX_MANIFEST_DEPTH);
    }

    /// A manifest must not reach the disk before the chunks it names.
    ///
    /// A store that batches its fsyncs makes bulk ingest affordable, but the
    /// batching is only safe if `split` settles each level before writing the
    /// one above it. Get that wrong and a crash mid-flush leaves a durable
    /// root CID naming content that never landed — an unreadable file whose
    /// name says otherwise, which is precisely the failure content addressing
    /// is meant to rule out.
    #[test]
    fn a_manifest_is_made_durable_only_after_its_chunks() {
        let data = noise(120 * 1024, 77);
        let store = MemStore::default();
        let report = split(&store, Cursor::new(data), None, &small_config()).unwrap();

        let root_round = store
            .durable_round(&report.cid)
            .expect("split must make the root it returns durable");

        let links = store.get_links(&report.cid).unwrap();
        assert!(links.len() > 5, "need a multi-chunk file to say anything");
        for link in &links {
            let chunk_round = store
                .durable_round(&link.target)
                .expect("split must make every chunk durable");
            assert!(
                chunk_round < root_round,
                "chunk {} became durable in round {} but the manifest naming it \
                 was already durable in round {}",
                link.target,
                chunk_round,
                root_round
            );
        }
    }

    /// The same rule at every level of a deep manifest: a part entry names the
    /// level below it, so it may not outrun it either.
    #[test]
    fn every_level_of_a_deep_manifest_is_ordered_by_durability() {
        let cfg = ChunkerConfig {
            links_per_manifest: 3,
            ..small_config()
        };
        let data = noise(160 * 1024, 23);
        let store = MemStore::default();
        let report = split(&store, Cursor::new(data), None, &cfg).unwrap();
        assert!(report.depth >= 2, "need parts: depth {}", report.depth);

        // Walk down from the root; every child must be durable strictly
        // earlier than the entry that names it.
        let mut queue = vec![(report.cid.clone(), report.depth)];
        let mut checked = 0;
        while let Some((cid, depth)) = queue.pop() {
            let parent_round = store.durable_round(&cid).expect("durable");
            for link in store.get_links(&cid).unwrap() {
                let child_round = store.durable_round(&link.target).expect("durable");
                assert!(
                    child_round < parent_round,
                    "{} (round {}) names {} (round {})",
                    cid,
                    parent_round,
                    link.target,
                    child_round
                );
                checked += 1;
                if depth > 1 {
                    queue.push((link.target, depth - 1));
                }
            }
        }
        assert!(checked > 0);
    }

    /// A single chunk that never reaches the manifest path is still a promise,
    /// so `store_auto` has to settle it too.
    #[test]
    fn store_auto_makes_a_plain_chunk_durable_before_returning() {
        let store = MemStore::default();
        match store_auto(
            &store,
            Cursor::new(b"small enough for one chunk".to_vec()),
            None,
            false,
            &ChunkerConfig::default(),
        )
        .unwrap()
        {
            StoredContent::Chunk { cid, .. } => {
                assert!(
                    store.durable_round(&cid).is_some(),
                    "store_auto returned a CID it had not made durable"
                );
            }
            StoredContent::File(_) => panic!("small content must stay a plain chunk"),
        }
    }

    /// Every stored chunk in a deep manifest is reachable from the root by
    /// link traversal — this is what lets one subtree pin retain a whole
    /// file, and GC collect it once unpinned.
    #[test]
    fn every_stored_chunk_is_reachable_from_the_root() {
        let cfg = ChunkerConfig {
            links_per_manifest: 4,
            ..small_config()
        };
        let data = noise(120 * 1024, 21);
        let store = MemStore::default();
        let report = split(&store, Cursor::new(data), None, &cfg).unwrap();

        let mut reachable = std::collections::HashSet::new();
        let mut queue = vec![report.cid.clone()];
        while let Some(cid) = queue.pop() {
            if !reachable.insert(cid.clone()) {
                continue;
            }
            if let Ok(links) = store.get_links(&cid) {
                queue.extend(links.into_iter().map(|l| l.target));
            }
        }

        assert_eq!(
            reachable.len(),
            store.len(),
            "orphaned chunks would leak past subtree pins and GC"
        );
    }
}
