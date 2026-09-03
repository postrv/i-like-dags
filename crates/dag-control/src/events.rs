//! # Event Bus for Observability
//!
//! This module implements a lightweight in-process event bus for unified observability
//! across the DAG orchestrator. Events are emitted by pointer, pin, and job logs and
//! can be subscribed to for monitoring and debugging.
//!
//! ## Event Types
//!
//! - **PointerUpdate**: Emitted when a pointer is created or updated
//! - **PinEvent**: Emitted when a pin is created or deactivated
//! - **JobRun**: Emitted when a job run state changes
//! - **StorageHealth**: Emitted during storage integrity checks
//!
//! ## Usage
//!
//! ```rust
//! use dag_control::events::{Event, EventBus};
//! use dag_core::Cid;
//!
//! let bus = EventBus::new(16);
//! let mut subscriber = bus.subscribe();
//!
//! bus.emit(Event::PointerUpdate {
//!     id: "models/production".into(),
//!     new: Cid::compute(b"payload"),
//!     ts: 0,
//! });
//!
//! let envelope = subscriber.try_recv().expect("event was emitted");
//! assert_eq!(envelope.seq, 0);
//! ```
//!
//! ## Journal retention
//!
//! The journal shares `control.redb` with every primary log, so an unbounded
//! journal is not merely untidy — it inflates the file that holds the pointer,
//! pin and job history. A long-running `dag serve` writes a `StorageHealth`
//! row every fifteen minutes forever, so "an operator will compact it" is not
//! a retention policy.
//!
//! The journal therefore trims itself to [`DEFAULT_JOURNAL_RETENTION`] events.
//! Raise or disable the cap with the `DAG_EVENT_JOURNAL_KEEP` environment
//! variable (`0` disables trimming), or, when embedding, with
//! [`EventBus::with_journal_retention`].
//!
//! Trimming frees pages inside the file; redb reuses them, so a bounded
//! journal reaches a plateau rather than growing. It does not hand pages back
//! to the filesystem — only [`reclaim_control_db`] does that, and it needs the
//! database to itself.

use crate::error::{ControlError, Result};
use dag_core::{Cid, RunStatus};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

const EVENT_JOURNAL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("event_journal");

/// How many events the journal keeps before trimming itself.
///
/// At roughly 200 bytes of JSON per row this is tens of megabytes — large
/// enough that ordinary operation never notices the cap, small enough that an
/// unattended server has a ceiling. Matches the default of
/// `dag events compact --keep-last`, so the automatic and manual levers agree.
pub const DEFAULT_JOURNAL_RETENTION: u64 = 100_000;

/// Environment override for [`DEFAULT_JOURNAL_RETENTION`]; `0` disables trimming.
pub const JOURNAL_RETENTION_ENV: &str = "DAG_EVENT_JOURNAL_KEEP";

/// Largest encoded [`EventEnvelope`] accepted by the durable journal.
///
/// The journal is replayed through public observability surfaces. Bounding a
/// row before JSON decoding makes both retained disk use and the allocation
/// caused by any one corrupt or hostile legacy row finite.
pub const MAX_EVENT_ENVELOPE_BYTES: usize = 64 * 1024;

/// Rows removed per write transaction when trimming.
///
/// redb is copy-on-write: a transaction that touches every page of a table has
/// to allocate a whole second copy of it before it can commit. Deleting a large
/// journal in one transaction is what made compaction *grow* `control.redb` by
/// eight times. Bounded batches keep the peak page count flat.
const TRIM_BATCH: usize = 512;

/// Fraction of the cap allowed to accumulate above it before a trim runs.
///
/// Without slack every event past the cap would pay for a write transaction.
const TRIM_HYSTERESIS_DIVISOR: u64 = 8;

fn db_err(e: impl std::fmt::Display) -> ControlError {
    ControlError::db("event journal", e)
}

/// A JSON sink that never grows beyond the durable envelope ceiling.
struct EnvelopeWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl EnvelopeWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(1024),
            exceeded: false,
        }
    }
}

impl Write for EnvelopeWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("event envelope size overflow"));
        };
        if next_len > MAX_EVENT_ENVELOPE_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("event envelope exceeds limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_envelope(envelope: &EventEnvelope) -> Result<Vec<u8>> {
    let mut writer = EnvelopeWriter::new();
    match serde_json::to_writer(&mut writer, envelope) {
        Ok(()) => Ok(writer.bytes),
        Err(_) if writer.exceeded => Err(ControlError::Invalid(format!(
            "event envelope exceeds the {MAX_EVENT_ENVELOPE_BYTES}-byte journal limit"
        ))),
        Err(error) => Err(error.into()),
    }
}

fn decode_envelope(value: &[u8]) -> Result<EventEnvelope> {
    if value.len() > MAX_EVENT_ENVELOPE_BYTES {
        return Err(ControlError::Codec(format!(
            "event journal envelope is {} bytes, exceeding the {}-byte limit",
            value.len(),
            MAX_EVENT_ENVELOPE_BYTES
        )));
    }
    Ok(serde_json::from_slice(value)?)
}

fn seq_of(key: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = key
        .try_into()
        .map_err(|_| db_err(format!("journal key is {} bytes, expected 8", key.len())))?;
    Ok(u64::from_be_bytes(bytes))
}

/// Retention cap from the environment, falling back to the default.
///
/// An unparseable value is ignored rather than fatal: a typo in a unit file
/// should not stop the control plane from opening.
fn retention_from_env() -> Option<u64> {
    match std::env::var(JOURNAL_RETENTION_ENV) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT_JOURNAL_RETENTION),
        },
        Err(_) => Some(DEFAULT_JOURNAL_RETENTION),
    }
}

/// Result from event journal compaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CompactionReport {
    /// Number of events deleted — a count, not a sequence number.
    pub events_deleted: u64,
    /// Sequence number cutoff (events < cutoff were deleted)
    pub cutoff_seq: u64,
    /// Current (latest) sequence number
    pub current_seq: u64,
    /// Number of events still held afterwards.
    pub events_kept: u64,
    /// Oldest sequence number the journal still holds afterwards.
    pub earliest_seq: u64,
    /// True when nothing was written — see [`EventBus::plan_compaction`].
    pub dry_run: bool,
}

/// A bounded window of the event journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Replay {
    /// Matching envelopes, oldest first.
    pub events: Vec<EventEnvelope>,
    /// Oldest sequence number the journal still holds.
    pub earliest_seq: u64,
    /// Set when the requested start is older than anything that survives.
    pub truncated: Option<Truncated>,
    /// Number of journal rows inspected to build this response.
    pub scanned: u64,
    /// True when an explicit scan budget stopped the replay before every
    /// candidate row could be inspected.
    pub scan_truncated: bool,
}

/// The part of a replay request the journal could not answer.
///
/// Retention trims the *front* of the journal, so a caller asking for full
/// history gets a partial answer. Without this it looks complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Truncated {
    /// The sequence number the caller asked to start from.
    pub requested_seq: u64,
    /// The oldest sequence number that survives.
    pub earliest_seq: u64,
    /// How many sequence numbers were dropped before the surviving prefix.
    pub missing: u64,
}

/// Files below this are not worth copying to find out: redb's per-region
/// overhead and its close-time pre-allocation dominate a small database, which
/// is exactly the regime where compaction comes back *larger*.
const MIN_RECLAIMABLE_BYTES: u64 = 256 * 1024;

/// Suffix of the working copy compaction is attempted on.
const COMPACTING_SUFFIX: &str = "compacting";

/// Result from returning free pages to the filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReclaimReport {
    /// Size of `control.redb` before.
    pub bytes_before: u64,
    /// Size of `control.redb` after.
    pub bytes_after: u64,
    /// Difference, saturating at zero.
    pub bytes_reclaimed: u64,
    /// Bytes of keys, values and index metadata the database actually holds.
    pub live_bytes: u64,
    /// Whether the file was rewritten. False when it was already lean enough
    /// that rewriting it would have made it bigger.
    pub compacted: bool,
}

/// Return free pages in a control database to the filesystem.
///
/// Deleting rows — by [`EventBus::compact_keep_last`] or by the journal's own
/// trimming — frees pages *inside* the file, which redb reuses. The file itself
/// only shrinks when redb rewrites it, and
/// [`redb::Database::compact`] takes `&mut Database`: it must be the only
/// handle, with no live read transaction. An open [`Control`](crate::Control)
/// shares one `Arc<Database>` across the chunk index and every log, so this
/// cannot be done from inside a running control plane. Drop it first.
///
/// Compaction is attempted on a **copy**, and the copy replaces the original
/// only if it came out smaller. That is not caution for its own sake: redb
/// pre-allocates room as it closes, so compacting a database that is already
/// lean returns a *larger* file — measured, a 425,984-byte control database
/// came back 651,264, while a 4,153,344-byte one came back 2,785,280. Nothing
/// cheap distinguishes the two cases beforehand (both sat at about twice their
/// live bytes), so the honest way to find out is to try. A command called
/// "reclaim" must never cost disk.
///
/// Needs room for a second copy of the database while it runs.
///
/// Returns [`ControlError::DatabaseLocked`] if the directory is still open,
/// here or in another process.
pub fn reclaim_control_db(data_dir: &Path) -> Result<ReclaimReport> {
    let path = data_dir.join(crate::CONTROL_DB_FILE);
    let scratch = path.with_extension(COMPACTING_SUFFIX);

    let size = |p: &Path| -> Result<u64> {
        Ok(std::fs::metadata(p)
            .map_err(|e| ControlError::io(format!("failed to stat {}", p.display()), e))?
            .len())
    };
    let io = |what: String| move |e| ControlError::io(what.clone(), e);

    let bytes_before = size(&path)?;

    // Hold the original open for the whole operation. redb's file lock is what
    // stops another process opening the directory underneath us, and it is also
    // the check that this is safe to do at all.
    let original = Database::open(&path).map_err(|e| match e {
        redb::DatabaseError::DatabaseAlreadyOpen => ControlError::DatabaseLocked {
            path: data_dir.display().to_string(),
        },
        other => ControlError::db("opening control database for reclaim", other),
    })?;

    // `stats` lives on a write transaction; abort it, nothing is being changed.
    let live_bytes = {
        let txn = original.begin_write().map_err(db_err)?;
        let stats = txn.stats().map_err(db_err)?;
        let live = stats.stored_bytes() + stats.metadata_bytes();
        txn.abort().map_err(db_err)?;
        live
    };

    // Every size in the report is taken with no handle open. redb resizes the
    // file as it closes, so a measurement taken while `original` is alive
    // disagrees with what the caller sees a moment later.
    let unchanged = |bytes_after| ReclaimReport {
        bytes_before,
        bytes_after,
        bytes_reclaimed: 0,
        live_bytes,
        compacted: false,
    };

    // While `original` is held the file on disk still measures exactly
    // `bytes_before`; redb re-settles it — by up to a page — only when the
    // handle drops. So copy the pristine bytes now and install *that* copy
    // whenever we are not installing a deliberately smaller one. Renaming it
    // into place before the drop (as the compaction branch below already does)
    // leaves the drop to re-settle the discarded inode rather than the live
    // file — the reason reclaim could otherwise cost a page on a database it
    // only inspected.
    let copy_to_scratch = || -> Result<()> {
        let mut source = std::fs::File::open(&path)
            .map_err(io(format!("failed to open {} for copying", path.display())))?;
        let permissions = source
            .metadata()
            .map_err(io(format!("failed to stat {}", path.display())))?
            .permissions();

        // No truncation and no symlink following at the destination. A stale
        // `.compacting` file is evidence for an operator to inspect, not a
        // pathname this run may overwrite (or follow somewhere else).
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut target = options.open(&scratch).map_err(io(format!(
            "failed to create exclusive compaction copy {}",
            scratch.display()
        )))?;

        let copied = (|| -> std::io::Result<()> {
            std::io::copy(&mut source, &mut target)?;
            target.set_permissions(permissions)?;
            target.sync_all()
        })();
        if let Err(error) = copied {
            // We created this exact file with create_new above, so cleanup
            // cannot remove pre-existing user data.
            drop(target);
            let _ = std::fs::remove_file(&scratch);
            return Err(ControlError::io(
                format!("failed to copy {} to {}", path.display(), scratch.display()),
                error,
            ));
        }
        Ok(())
    };

    let sync_publication = || -> Result<()> {
        #[cfg(unix)]
        std::fs::File::open(data_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(io(format!("failed to sync {}", data_dir.display())))?;
        Ok(())
    };

    if bytes_before < MIN_RECLAIMABLE_BYTES {
        copy_to_scratch()?;
        std::fs::rename(&scratch, &path)
            .map_err(io(format!("failed to restore {}", path.display())))?;
        sync_publication()?;
        drop(original);
        return Ok(unchanged(size(&path)?));
    }

    copy_to_scratch()?;

    // Compact the copy, and make sure a failure never strands the scratch file.
    let compacted_size = (|| -> Result<u64> {
        let mut candidate = Database::open(&scratch)
            .map_err(|e| ControlError::db("opening the compaction copy", e))?;
        candidate.compact().map_err(db_err)?;
        drop(candidate);
        std::fs::File::open(&scratch)
            .and_then(|file| file.sync_all())
            .map_err(io(format!(
                "failed to make compacted copy {} durable",
                scratch.display()
            )))?;
        size(&scratch)
    })();

    let compacted_size = match compacted_size {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&scratch);
            return Err(e);
        }
    };

    if compacted_size >= bytes_before {
        // Compaction did not win. Discard it and restore the pristine bytes, so
        // the file is byte-for-byte what it was rather than redb's re-settled,
        // larger copy of the original inode.
        std::fs::remove_file(&scratch)
            .map_err(io(format!("failed to remove {}", scratch.display())))?;
        copy_to_scratch()?;
        std::fs::rename(&scratch, &path)
            .map_err(io(format!("failed to restore {}", path.display())))?;
        sync_publication()?;
        drop(original);
        return Ok(unchanged(size(&path)?));
    }

    // Same directory, so this is atomic: readers see either file, never neither.
    // `original` still holds the old inode, which keeps the lock held until this
    // function returns; nothing is written through it.
    std::fs::rename(&scratch, &path).map_err(io(format!(
        "failed to replace {} with the compacted copy",
        path.display()
    )))?;
    sync_publication()?;
    drop(original);

    let bytes_after = size(&path)?;

    Ok(ReclaimReport {
        bytes_before,
        bytes_after,
        bytes_reclaimed: bytes_before.saturating_sub(bytes_after),
        live_bytes,
        compacted: true,
    })
}

/// Envelope schema version emitted today.
///
/// Rows journaled before the field existed deserialize to this same value,
/// because they *are* this schema — the field arrived before any change.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

fn envelope_schema_version() -> u32 {
    ENVELOPE_SCHEMA_VERSION
}

/// Event envelope for persistent event journal
///
/// Wraps events with sequence number and timestamp for replay and gap detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Envelope schema version — present so external consumers can dispatch
    /// on it *before* the shape ever needs to change (see
    /// [`ENVELOPE_SCHEMA_VERSION`]).
    #[serde(default = "envelope_schema_version")]
    pub v: u32,
    /// Monotonic sequence number for ordering and replay
    pub seq: u64,
    /// Unix timestamp when event was emitted (envelope level)
    pub envelope_ts: i64,
    /// The actual event payload
    pub event: Event,
}

/// Unified event type for observability across the DAG system
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Event {
    /// Pointer was created or updated
    PointerUpdate { id: String, new: Cid, ts: i64 },
    /// Pin was created or deactivated
    PinEvent { id: String, action: String, ts: i64 },
    /// Job run state changed
    JobRun {
        job: String,
        run: String,
        status: RunStatus,
        ts: i64,
    },
    /// Storage health check completed
    StorageHealth { check: String, ok: bool, ts: i64 },
}

impl Event {
    /// The stream kind an event belongs to — the vocabulary every filter
    /// surface shares (`--filter` on the CLI, `?filter=` on the API, `types`
    /// on the node protocol). One definition, so the surfaces cannot drift.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::PointerUpdate { .. } => "pointer",
            Event::PinEvent { .. } => "pin",
            Event::JobRun { .. } => "job",
            Event::StorageHealth { .. } => "storage",
        }
    }
}

/// Event bus for broadcasting events to subscribers
///
/// Uses tokio::sync::broadcast for efficient multi-subscriber support.
/// Events are emitted without blocking on subscribers - if no subscribers
/// exist or all subscribers are lagging, events are dropped.
///
/// When configured with a journal, events are persisted to the shared database for replay.
/// Broadcasts EventEnvelope (with seq + ts) for uniform output in tail/follow modes.
#[derive(Clone)]
pub struct EventBus {
    sender: Arc<broadcast::Sender<EventEnvelope>>,
    journal: Option<Arc<EventJournal>>,
    /// Optional registry bumped on every emission — the cheapest complete
    /// tap on system activity, since every log already reports here.
    metrics: Option<Arc<dag_core::Metrics>>,
}

/// Persistent event journal for replay and gap detection
struct EventJournal {
    db: Arc<Database>,
    next_seq: Arc<Mutex<u64>>,
    earliest_seq: Arc<Mutex<u64>>,
    /// Events to keep; `None` means keep everything.
    retention: Option<u64>,
    /// Held for the duration of a trim so concurrent emitters do not pile up
    /// redundant delete transactions behind one another.
    trimming: Mutex<()>,
}

impl EventJournal {
    fn new(db: Arc<Database>, retention: Option<u64>) -> Result<Self> {
        // Create the table, then load the sequence bounds from it.
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(EVENT_JOURNAL).map_err(db_err)?;
        txn.commit().map_err(db_err)?;

        let (next_seq, earliest_seq) = {
            let txn = db.begin_read().map_err(db_err)?;
            let table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;

            let next = table
                .last()
                .map_err(db_err)?
                .map(|(key, _)| {
                    seq_of(key.value())?
                        .checked_add(1)
                        .ok_or_else(|| db_err("journal sequence space is exhausted at u64::MAX"))
                })
                .transpose()?
                .unwrap_or(0);

            let earliest = table
                .first()
                .map_err(db_err)?
                .map(|(key, _)| seq_of(key.value()))
                .transpose()?
                .unwrap_or(0);

            (next, earliest)
        };

        Ok(Self {
            db,
            next_seq: Arc::new(Mutex::new(next_seq)),
            earliest_seq: Arc::new(Mutex::new(earliest_seq)),
            retention,
            trimming: Mutex::new(()),
        })
    }

    fn persist(&self, event: &Event, envelope_ts: i64) -> Result<u64> {
        // Serialize allocation through commit. Advancing before a failed
        // transaction manufactured a permanent gap, while releasing this
        // mutex before commit allowed later sequences to become durable first.
        let mut next = self
            .next_seq
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let seq = *next;
        let successor = seq
            .checked_add(1)
            .ok_or_else(|| db_err("journal sequence space is exhausted at u64::MAX"))?;

        let envelope = EventEnvelope {
            v: ENVELOPE_SCHEMA_VERSION,
            seq,
            envelope_ts,
            event: event.clone(),
        };

        let key = seq.to_be_bytes();
        let value = encode_envelope(&envelope)?;

        // A committed redb transaction is durable — this replaces the explicit
        // per-event flush the sled journal needed.
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        *next = successor;
        drop(next);

        // Keep the journal inside its cap. Best-effort: a failed trim must not
        // fail the write that has already committed, and the next event past
        // the threshold tries again.
        if let Some(cap) = self.retention {
            let held = seq.saturating_add(1).saturating_sub(self.earliest_seq());
            if held > cap.saturating_add((cap / TRIM_HYSTERESIS_DIVISOR).max(1)) {
                let _ = self.compact(cap);
            }
        }

        Ok(seq)
    }

    /// Count rows and find the oldest surviving sequence number.
    fn survey(&self) -> Result<(u64, Option<u64>)> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;
        let count = table.len().map_err(db_err)?;
        let first = table
            .first()
            .map_err(db_err)?
            .map(|(key, _)| seq_of(key.value()))
            .transpose()?;
        Ok((count, first))
    }

    /// Rows strictly below `cutoff`, without deleting any.
    fn count_below(&self, cutoff: u64) -> Result<u64> {
        let cutoff_key = cutoff.to_be_bytes();
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;
        let mut n = 0u64;
        for item in table.range(..cutoff_key.as_slice()).map_err(db_err)? {
            item.map_err(db_err)?;
            n = n
                .checked_add(1)
                .ok_or_else(|| db_err("journal row count exceeds u64::MAX"))?;
        }
        Ok(n)
    }

    /// Delete every row below `cutoff`, in bounded transactions.
    fn trim_below(&self, cutoff: u64) -> Result<u64> {
        let cutoff_key = cutoff.to_be_bytes();
        let mut deleted = 0u64;

        loop {
            let txn = self.db.begin_write().map_err(db_err)?;
            let batch = {
                let mut table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;

                // Collect first, then remove: `range` borrows the table
                // immutably and `remove` needs it mutably.
                let keys: Vec<[u8; 8]> = {
                    let mut keys = Vec::with_capacity(TRIM_BATCH);
                    for item in table.range(..cutoff_key.as_slice()).map_err(db_err)? {
                        let (key, _) = item.map_err(db_err)?;
                        keys.push(seq_of(key.value())?.to_be_bytes());
                        if keys.len() >= TRIM_BATCH {
                            break;
                        }
                    }
                    keys
                };

                for key in &keys {
                    table.remove(key.as_slice()).map_err(db_err)?;
                }
                keys.len()
            };
            txn.commit().map_err(db_err)?;

            deleted = deleted
                .checked_add(batch as u64)
                .ok_or_else(|| db_err("journal deletion count exceeds u64::MAX"))?;
            if batch < TRIM_BATCH {
                break;
            }
        }

        Ok(deleted)
    }

    fn replay(
        &self,
        since_seq: u64,
        limit: Option<usize>,
        scan_limit: Option<usize>,
        matches: &dyn Fn(&Event) -> bool,
    ) -> Result<Replay> {
        let start_key = since_seq.to_be_bytes();

        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;

        let mut events = Vec::new();
        let mut scanned = 0u64;
        let mut scan_truncated = false;
        match limit {
            // Walk backwards from the newest and stop at the limit, so the cost
            // is the size of the answer rather than the size of the journal.
            Some(n) => {
                let mut range = table.range(start_key.as_slice()..).map_err(db_err)?;
                while events.len() < n {
                    let Some(item) = range.next_back() else { break };
                    if scan_limit.is_some_and(|max| scanned >= max as u64) {
                        scan_truncated = true;
                        break;
                    }
                    scanned = scanned
                        .checked_add(1)
                        .ok_or_else(|| db_err("journal replay scan count exceeds u64::MAX"))?;
                    let (_key, value) = item.map_err(db_err)?;
                    let envelope = decode_envelope(value.value())?;
                    if matches(&envelope.event) {
                        events.push(envelope);
                    }
                }
                events.reverse();
            }
            None => {
                for item in table.range(start_key.as_slice()..).map_err(db_err)? {
                    if scan_limit.is_some_and(|max| scanned >= max as u64) {
                        scan_truncated = true;
                        break;
                    }
                    scanned = scanned
                        .checked_add(1)
                        .ok_or_else(|| db_err("journal replay scan count exceeds u64::MAX"))?;
                    let (_key, value) = item.map_err(db_err)?;
                    let envelope = decode_envelope(value.value())?;
                    if matches(&envelope.event) {
                        events.push(envelope);
                    }
                }
            }
        }

        let earliest = self.earliest_seq();
        // `then`, not `then_some`: the latter evaluates the subtraction even
        // when the condition is false, which underflows for any ordinary
        // request past the start of the journal.
        let truncated = (since_seq < earliest).then(|| Truncated {
            requested_seq: since_seq,
            earliest_seq: earliest,
            missing: earliest - since_seq,
        });

        Ok(Replay {
            events,
            earliest_seq: earliest,
            truncated,
            scanned,
            scan_truncated,
        })
    }

    /// First sequence number whose envelope timestamp is at or after `ts`.
    ///
    /// A linear scan in sequence order, bounded by the retention cap. Wall
    /// clocks can step backwards between rows, so this answers "the first
    /// moment the journal *claims* to be past `ts`" — the honest reading of
    /// timestamps it merely recorded.
    fn seq_at_or_after(&self, ts: i64) -> Result<Option<u64>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(EVENT_JOURNAL).map_err(db_err)?;
        for item in table.iter().map_err(db_err)? {
            let (_key, value) = item.map_err(db_err)?;
            let envelope = decode_envelope(value.value())?;
            if envelope.envelope_ts >= ts {
                return Ok(Some(envelope.seq));
            }
        }
        Ok(None)
    }

    fn current_seq(&self) -> u64 {
        *self
            .next_seq
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn earliest_seq(&self) -> u64 {
        *self
            .earliest_seq
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// What [`Self::compact`] would do, without writing anything.
    fn plan(&self, keep_last: u64) -> Result<CompactionReport> {
        let current = self.current_seq();
        let cutoff = current.saturating_sub(keep_last);
        let (held, first) = self.survey()?;
        let doomed = self.count_below(cutoff)?;

        Ok(CompactionReport {
            events_deleted: doomed,
            cutoff_seq: cutoff,
            current_seq: current,
            events_kept: held.saturating_sub(doomed),
            earliest_seq: first.map(|f| f.max(cutoff)).unwrap_or(cutoff),
            dry_run: true,
        })
    }

    /// Compact journal by keeping only the last N events.
    ///
    /// Deletes events with seq < (current_seq - keep_last) in bounded
    /// transactions, then updates `earliest_seq` to what actually survives.
    fn compact(&self, keep_last: u64) -> Result<CompactionReport> {
        // One trimmer at a time. A caller who arrives mid-trim would otherwise
        // race the same rows; skipping is correct because the trim in flight is
        // already doing the work.
        let _guard = match self.trimming.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                let current = self.current_seq();
                let (held, first) = self.survey()?;
                return Ok(CompactionReport {
                    events_deleted: 0,
                    cutoff_seq: current.saturating_sub(keep_last),
                    current_seq: current,
                    events_kept: held,
                    earliest_seq: first.unwrap_or(current),
                    dry_run: false,
                });
            }
        };

        let current = self.current_seq();
        let cutoff = current.saturating_sub(keep_last);

        let deleted = self.trim_below(cutoff)?;

        // Report what survives rather than what the arithmetic implies: a
        // journal that already held fewer events than `keep_last` keeps fewer.
        let (kept, first) = self.survey()?;
        let earliest = first.unwrap_or(current);
        *self
            .earliest_seq
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = earliest;

        Ok(CompactionReport {
            events_deleted: deleted,
            cutoff_seq: cutoff,
            current_seq: current,
            events_kept: kept,
            earliest_seq: earliest,
            dry_run: false,
        })
    }
}

impl EventBus {
    /// Create a new event bus with the given channel capacity
    ///
    /// Capacity determines how many events can be buffered per subscriber.
    /// When a subscriber lags behind by more than capacity events, older
    /// events are dropped (lagged error).
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender: Arc::new(sender),
            journal: None,
            metrics: None,
        }
    }

    /// Count emissions into `metrics`: `dag_events_total{kind=…}` always, and
    /// `dag_job_runs_total{status=…}` for job-run transitions. Riding the bus
    /// instead of instrumenting each log means one tap covers every emitter.
    pub fn with_metrics(mut self, metrics: Arc<dag_core::Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Create a new event bus with default capacity (100 events)
    pub fn new_default() -> Self {
        Self::new(100)
    }

    /// Create a new event bus with persistent journal
    ///
    /// Events are persisted to the shared database for replay and gap
    /// detection, and the journal trims itself to
    /// [`DEFAULT_JOURNAL_RETENTION`] events — or to whatever
    /// `DAG_EVENT_JOURNAL_KEEP` says, including `0` for no cap at all.
    pub fn with_journal(capacity: usize, db: Arc<Database>) -> Result<Self> {
        Self::with_journal_retention(capacity, db, retention_from_env())
    }

    /// Create a new event bus with a persistent journal and an explicit cap.
    ///
    /// `keep_last` of `None` keeps every event, which is only appropriate when
    /// something else bounds the lifetime of the database.
    pub fn with_journal_retention(
        capacity: usize,
        db: Arc<Database>,
        keep_last: Option<u64>,
    ) -> Result<Self> {
        let (sender, _) = broadcast::channel(capacity);
        let journal = EventJournal::new(db, keep_last)?;

        Ok(Self {
            sender: Arc::new(sender),
            journal: Some(Arc::new(journal)),
            metrics: None,
        })
    }

    /// Emit an event to all subscribers
    ///
    /// This is a non-blocking operation. If no subscribers exist,
    /// the event is silently dropped. If a journal is configured,
    /// the event is persisted before broadcasting.
    ///
    /// Broadcasts EventEnvelope with seq + ts for uniform output.
    pub fn emit(&self, event: Event) {
        let ts = chrono::Utc::now().timestamp();

        if let Some(metrics) = &self.metrics {
            if let Some(counter) = metrics.event_counter(event.kind()) {
                counter.inc();
            }
            if let Event::JobRun { status, .. } = &event {
                let status = match status {
                    RunStatus::Pending => "pending",
                    RunStatus::Running => "running",
                    RunStatus::Succeeded => "succeeded",
                    RunStatus::Failed { .. } => "failed",
                };
                if let Some(counter) = metrics.job_status_counter(status) {
                    counter.inc();
                }
            }
        }

        // Persist to journal if configured and get seq
        let seq = if let Some(ref journal) = self.journal {
            match journal.persist(&event, ts) {
                Ok(seq) => seq,
                Err(error) => {
                    // The public contract is journal-before-broadcast. A
                    // fabricated sequence 0 makes subscribers believe this
                    // event is replayable when it is not and can conceal a
                    // real gap. Preserve the primary mutation, but refuse the
                    // misleading live notification and leave an operator-
                    // visible error.
                    tracing::error!(
                        target: "dag::events",
                        error = %error,
                        event_kind = event.kind(),
                        "event journal write failed; live notification suppressed"
                    );
                    return;
                }
            }
        } else {
            // No journal: use 0 as placeholder (best-effort)
            0
        };

        // Wrap in envelope and broadcast to subscribers
        let envelope = EventEnvelope {
            v: ENVELOPE_SCHEMA_VERSION,
            seq,
            envelope_ts: ts,
            event,
        };

        // Broadcast to subscribers (ignore errors if no subscribers)
        let _ = self.sender.send(envelope);
    }

    /// Subscribe to events
    ///
    /// Returns a receiver that will receive all event envelopes emitted after
    /// this subscription is created. Events emitted before subscription
    /// are not received.
    ///
    /// Envelopes include seq + ts for uniform output in tail/follow modes.
    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.sender.subscribe()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Replay every event from the journal at or after `since_seq`.
    ///
    /// Unbounded: prefer [`Self::replay`] anywhere the answer is going to a
    /// client, which stops reading at the limit and reports a trimmed prefix.
    /// Requires a journal to be configured, otherwise returns empty vec.
    pub fn replay_from(&self, since_seq: u64) -> Result<Vec<EventEnvelope>> {
        Ok(self.replay(since_seq, None, &|_| true)?.events)
    }

    /// Replay a bounded window of the journal.
    ///
    /// `limit` selects the **newest** matching events at or after `since_seq`,
    /// returned oldest first, and bounds the read itself rather than trimming
    /// afterwards. `matches` is applied before the limit is counted, so a
    /// filtered request returns a full window of the kind asked for.
    ///
    /// [`Replay::truncated`] is set when `since_seq` is older than anything the
    /// journal still holds — the case where a caller asking for full history
    /// would otherwise get a partial answer that looks complete.
    pub fn replay(
        &self,
        since_seq: u64,
        limit: Option<usize>,
        matches: &dyn Fn(&Event) -> bool,
    ) -> Result<Replay> {
        self.replay_with_scan_limit(since_seq, limit, None, matches)
    }

    /// Replay a window while inspecting no more than `scan_limit` journal rows.
    ///
    /// A selective predicate may need to inspect many non-matching rows before
    /// it fills a small answer. Network-facing callers must bound that work and
    /// check [`Replay::scan_truncated`] rather than treating a short answer as
    /// proof that no older matching events exist. `None` preserves the local,
    /// operator-controlled replay behaviour.
    pub fn replay_with_scan_limit(
        &self,
        since_seq: u64,
        limit: Option<usize>,
        scan_limit: Option<usize>,
        matches: &dyn Fn(&Event) -> bool,
    ) -> Result<Replay> {
        match &self.journal {
            Some(journal) => journal.replay(since_seq, limit, scan_limit, matches),
            None => Ok(Replay {
                events: Vec::new(),
                earliest_seq: 0,
                truncated: None,
                scanned: 0,
                scan_truncated: false,
            }),
        }
    }

    /// First journal sequence number stamped at or after `ts` (unix
    /// seconds), or `None` when the journal holds nothing that recent —
    /// what `events tail --since <time>` resolves before replaying.
    ///
    /// Returns `None` with no journal configured.
    pub fn seq_at_or_after(&self, ts: i64) -> Result<Option<u64>> {
        match &self.journal {
            Some(journal) => journal.seq_at_or_after(ts),
            None => Ok(None),
        }
    }

    /// Get the current sequence number
    ///
    /// Returns 0 if no journal is configured.
    pub fn current_seq(&self) -> u64 {
        match &self.journal {
            Some(journal) => journal.current_seq(),
            None => 0,
        }
    }

    /// Get the earliest sequence number available in the journal
    ///
    /// Returns 0 if no journal is configured or journal is empty.
    pub fn earliest_seq(&self) -> u64 {
        match &self.journal {
            Some(journal) => journal.earliest_seq(),
            None => 0,
        }
    }

    /// Compact the event journal, keeping only the last N events.
    ///
    /// Deletes events older than (current_seq - keep_last) in bounded
    /// transactions. Freed pages stay in the file for redb to reuse; call
    /// [`reclaim_control_db`] on a closed database to hand them back to the
    /// filesystem.
    ///
    /// Requires a journal to be configured, otherwise returns error.
    pub fn compact_keep_last(&self, keep_last: u64) -> Result<CompactionReport> {
        match &self.journal {
            Some(journal) => journal.compact(keep_last),
            None => Err(ControlError::NoJournal),
        }
    }

    /// What [`Self::compact_keep_last`] would do, without writing anything.
    ///
    /// The counts are measured against the journal as it stands, so a second
    /// preview after a compaction reports that there is nothing left to drop.
    pub fn plan_compaction(&self, keep_last: u64) -> Result<CompactionReport> {
        match &self.journal {
            Some(journal) => journal.plan(keep_last),
            None => Err(ControlError::NoJournal),
        }
    }

    /// The standing retention cap, if the journal trims itself.
    pub fn journal_retention(&self) -> Option<u64> {
        self.journal.as_ref().and_then(|j| j.retention)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // Tests that need to wait for an event use
    // `dag_control::test_utils::TestControl::wait_for_event`, which does the
    // same polling with a proper `Result` instead of a panic.

    #[test]
    fn test_event_bus_emit_and_receive() {
        let bus = EventBus::new_default();
        let mut sub = bus.subscribe();

        let event = Event::PointerUpdate {
            id: "test-ptr".to_string(),
            new: Cid::compute(b"one"),
            ts: Utc::now().timestamp(),
        };

        bus.emit(event.clone());

        match sub.try_recv() {
            Ok(envelope) => match (&envelope.event, &event) {
                (Event::PointerUpdate { id: id1, .. }, Event::PointerUpdate { id: id2, .. }) => {
                    assert_eq!(id1, id2);
                }
                _ => panic!("Event type mismatch"),
            },
            Err(e) => panic!("Failed to receive event: {:?}", e),
        }
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new_default();
        let mut sub1 = bus.subscribe();
        let mut sub2 = bus.subscribe();

        assert_eq!(bus.subscriber_count(), 2);

        let event = Event::PinEvent {
            id: "test-pin".to_string(),
            action: "created".to_string(),
            ts: Utc::now().timestamp(),
        };

        bus.emit(event);

        // Both subscribers should receive the event
        assert!(sub1.try_recv().is_ok());
        assert!(sub2.try_recv().is_ok());
    }

    #[test]
    fn test_no_subscribers_doesnt_block() {
        let bus = EventBus::new_default();

        let event = Event::StorageHealth {
            check: "integrity".to_string(),
            ok: true,
            ts: Utc::now().timestamp(),
        };

        // Should not panic or block
        bus.emit(event);
    }

    #[test]
    fn test_events_before_subscription_not_received() {
        let bus = EventBus::new_default();

        let event1 = Event::PointerUpdate {
            id: "ptr1".to_string(),
            new: Cid::compute(b"one"),
            ts: Utc::now().timestamp(),
        };

        bus.emit(event1);

        // Subscribe after emission
        let mut sub = bus.subscribe();

        // Should not receive the event emitted before subscription
        assert!(sub.try_recv().is_err());

        // But should receive events after subscription
        let event2 = Event::PointerUpdate {
            id: "ptr2".to_string(),
            new: Cid::compute(b"two"),
            ts: Utc::now().timestamp(),
        };

        bus.emit(event2);
        assert!(sub.try_recv().is_ok());
    }

    #[test]
    fn test_event_serialization() {
        let event = Event::JobRun {
            job: "test-job".to_string(),
            run: "run-123".to_string(),
            status: RunStatus::Succeeded,
            ts: 1234567890,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: Event = serde_json::from_str(&json).unwrap();

        match (event, deserialized) {
            (
                Event::JobRun {
                    job: j1, run: r1, ..
                },
                Event::JobRun {
                    job: j2, run: r2, ..
                },
            ) => {
                assert_eq!(j1, j2);
                assert_eq!(r1, r2);
            }
            _ => panic!("Event type mismatch"),
        }
    }

    #[test]
    fn test_event_journal_persist_and_replay() {
        use tempfile::tempdir;

        let temp = tempdir().unwrap();
        let db = Arc::new(Database::create(temp.path().join("events.redb")).unwrap());

        let bus = EventBus::with_journal(100, db).unwrap();

        // Emit some events. Commits are durable; no flushing required.
        bus.emit(Event::PointerUpdate {
            id: "ptr1".to_string(),
            new: Cid::compute(b"one"),
            ts: Utc::now().timestamp(),
        });

        bus.emit(Event::PinEvent {
            id: "pin1".to_string(),
            action: "created".to_string(),
            ts: Utc::now().timestamp(),
        });

        bus.emit(Event::JobRun {
            job: "job1".to_string(),
            run: "1".to_string(),
            status: RunStatus::Pending,
            ts: Utc::now().timestamp(),
        });

        // Verify current seq
        assert_eq!(bus.current_seq(), 3);

        // Replay all events
        let envelopes = bus.replay_from(0).unwrap();
        assert_eq!(envelopes.len(), 3);
        assert_eq!(envelopes[0].seq, 0);
        assert_eq!(envelopes[1].seq, 1);
        assert_eq!(envelopes[2].seq, 2);

        // Replay from seq 1
        let envelopes = bus.replay_from(1).unwrap();
        assert_eq!(envelopes.len(), 2);
        assert_eq!(envelopes[0].seq, 1);
        assert_eq!(envelopes[1].seq, 2);
    }

    #[test]
    fn oversized_envelope_is_refused_before_it_reaches_the_journal() {
        let temp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(temp.path().join("events.redb")).unwrap());
        let journal = EventJournal::new(db, Some(100)).unwrap();

        let error = journal
            .persist(
                &Event::StorageHealth {
                    check: "x".repeat(MAX_EVENT_ENVELOPE_BYTES),
                    ok: true,
                    ts: 0,
                },
                0,
            )
            .unwrap_err();

        assert!(matches!(error, ControlError::Invalid(_)), "{error}");
        assert!(error.to_string().contains("65536-byte journal limit"));
        assert_eq!(journal.current_seq(), 0);
        assert_eq!(journal.survey().unwrap(), (0, None));
    }

    #[test]
    fn oversized_raw_journal_row_is_refused_before_json_decode() {
        let temp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(temp.path().join("events.redb")).unwrap());
        let bus = EventBus::with_journal_retention(16, db.clone(), Some(100)).unwrap();

        let oversized = vec![b'{'; MAX_EVENT_ENVELOPE_BYTES + 1];
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(EVENT_JOURNAL).unwrap();
            table
                .insert(0u64.to_be_bytes().as_slice(), oversized.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        for error in [
            bus.replay(0, Some(1), &|_| true).unwrap_err(),
            bus.seq_at_or_after(0).unwrap_err(),
        ] {
            assert!(matches!(error, ControlError::Codec(_)), "{error}");
            let message = error.to_string();
            assert!(message.contains("65537 bytes"), "{message}");
            assert!(message.contains("65536-byte limit"), "{message}");
            assert!(!message.contains("expected value"), "{message}");
        }
    }

    #[test]
    fn test_event_journal_persists_across_restarts() {
        use tempfile::tempdir;

        let temp = tempdir().unwrap();
        let db_path = temp.path().join("events.redb");

        // First session: emit events
        {
            let db = Arc::new(Database::create(&db_path).unwrap());
            let bus = EventBus::with_journal(100, db).unwrap();

            bus.emit(Event::PointerUpdate {
                id: "ptr1".to_string(),
                new: Cid::compute(b"one"),
                ts: Utc::now().timestamp(),
            });

            assert_eq!(bus.current_seq(), 1);
        }

        // Second session: verify events persisted
        {
            let db = Arc::new(Database::create(&db_path).unwrap());
            let bus = EventBus::with_journal(100, db).unwrap();

            assert_eq!(bus.current_seq(), 1);

            let envelopes = bus.replay_from(0).unwrap();
            assert_eq!(envelopes.len(), 1);
            assert_eq!(envelopes[0].seq, 0);

            // Emit more events
            bus.emit(Event::PinEvent {
                id: "pin1".to_string(),
                action: "created".to_string(),
                ts: Utc::now().timestamp(),
            });

            assert_eq!(bus.current_seq(), 2);
        }
    }

    fn journal_open_error_for_raw_key(key: &[u8]) -> String {
        let temp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(temp.path().join("events.redb")).unwrap());
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(EVENT_JOURNAL).unwrap();
            table.insert(key, b"{}".as_slice()).unwrap();
        }
        txn.commit().unwrap();

        match EventBus::with_journal_retention(16, db, Some(100)) {
            Ok(_) => panic!("malformed journal key was accepted"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn malformed_journal_keys_are_typed_open_errors_not_panics() {
        for key in [vec![0u8; 7], vec![0u8; 9]] {
            let error = journal_open_error_for_raw_key(&key);
            assert!(error.contains("journal key is"), "{error}");
            assert!(error.contains("expected 8"), "{error}");
        }
    }

    #[test]
    fn exhausted_journal_sequence_is_a_typed_open_error() {
        let error = journal_open_error_for_raw_key(&u64::MAX.to_be_bytes());
        assert!(error.contains("sequence space is exhausted"), "{error}");
    }

    #[test]
    fn test_envelope_serialization() {
        let envelope = EventEnvelope {
            v: ENVELOPE_SCHEMA_VERSION,
            seq: 42,
            envelope_ts: 1234567890,
            event: Event::PointerUpdate {
                id: "test".to_string(),
                new: Cid::compute(b"one"),
                ts: 1234567890,
            },
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: EventEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(envelope.seq, deserialized.seq);
        assert_eq!(envelope.envelope_ts, deserialized.envelope_ts);
    }

    #[test]
    fn test_gap_detection() {
        // Gap detection helper for CLI
        fn detect_gap(envelopes: &[EventEnvelope]) -> Option<(u64, u64)> {
            for window in envelopes.windows(2) {
                let expected_next = window[0].seq + 1;
                if window[1].seq != expected_next {
                    return Some((window[0].seq, window[1].seq));
                }
            }
            None
        }

        let envelopes = vec![
            EventEnvelope {
                v: ENVELOPE_SCHEMA_VERSION,
                seq: 0,
                envelope_ts: 100,
                event: Event::StorageHealth {
                    check: "test".to_string(),
                    ok: true,
                    ts: 100,
                },
            },
            EventEnvelope {
                v: ENVELOPE_SCHEMA_VERSION,
                seq: 1,
                envelope_ts: 101,
                event: Event::StorageHealth {
                    check: "test".to_string(),
                    ok: true,
                    ts: 101,
                },
            },
            EventEnvelope {
                v: ENVELOPE_SCHEMA_VERSION,
                seq: 3, // Gap! Missing seq 2
                envelope_ts: 103,
                event: Event::StorageHealth {
                    check: "test".to_string(),
                    ok: true,
                    ts: 103,
                },
            },
        ];

        let gap = detect_gap(&envelopes);
        assert_eq!(gap, Some((1, 3)));
    }
}
