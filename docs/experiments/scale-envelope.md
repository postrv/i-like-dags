# Scale envelope: what a million chunks actually costs

> Measured, not estimated. Re-run
> [`crates/dag-control/examples/scale_envelope.rs`](../../crates/dag-control/examples/scale_envelope.rs)
> whenever retention, collection, sync or the store change shape, and update
> this file — a performance claim nobody has re-measured is a rumour.

## Why this exists

The 2026-07 review's lesson was that the test suite had two structural blind
spots — **time** and **scale** — and every defect living in them was
invisible. Time was addressed then (`filetime`, aged-chunk tests). This
closes scale: the store, the retention snapshot and the collector all hold
collections in memory and walk them, and nothing had ever run against a
corpus big enough to notice.

It found three defects, and the adversarial review of the fixes found four
more — two of them introduced by those fixes. All are fixed; the numbers
below are post-fix except where marked. The review's findings are recorded
with the adversarial review of those fixes; the short version is that holding a lock across a batch made
one race deterministic rather than closing it, and deferring durability at
a sync destination created a torn-file state that presence checks could
never see.

## The setup

| | |
|---|---|
| Machine | Apple M1 Max, 32 GB, APFS on internal SSD |
| OS / toolchain | macOS 26.5.2, rustc 1.95.0, `--release` |
| Corpus | 1,000,000 loose 1 KiB chunks + 100,000 chunks under one `:full` subtree pin |
| Graph | fan-out-1000 entry tree over the pinned leaves (101 interior entries) — the shape `file/v1` manifests produce |
| Names | 1,000 pointers |
| Total | 1,101,102 chunks, 1.13 GB |

Three scale dimensions are exercised separately on purpose: **store size**
(the loose million — ingest, collection scan, stats), **protected-set size**
(the pinned 100k — retention expansion, the GC protected set), and
**referenced-set size** (what sync actually moves).

Run it in two phases so each fits a bounded shell:

```bash
cargo build --release --example scale_envelope -p dag-control
./target/release/examples/scale_envelope seed    /tmp/scale 1000000 100000
./target/release/examples/scale_envelope measure /tmp/scale 1000000 100000
```

## Results

### Ingest (seed phase)

| Phase | Seconds | Rate |
|---|---|---|
| 1,000,000 loose chunks, bulk/deferred | 557 | ~1,800 chunks/s |
| 100,000 tree leaves, bulk/deferred | 65 | ~1,500 chunks/s |
| Build the entry tree (101 entries) | 1.8 | |
| Create 1,000 pointers | 28 | ~35 pointers/s |
| Pin the subtree (`:full`) | 0.03 | |

**Ingest is bound by durability, not hashing.** 1 KiB chunks are the worst
case for this — the fixed per-chunk cost dominates completely, and a real
corpus of megabyte-scale files moves far more bytes per chunk. Bulk paths
already defer their fsyncs (see below); the residue is the index commit.

**Pointer writes are ~28 ms each**, and that is inherent rather than
incidental: each is a durable event entry (content write) *plus* a redb
transaction commit — several fsyncs, serialized by the per-log write mutex.
Irrelevant for a deploy hook; a real constraint if something wants thousands
of pointer updates a second, which this is not built for.

### Read and maintenance (measure phase)

| Phase | Seconds | Detail |
|---|---|---|
| Rebuild pointer + pin heads (recovery gate) | 0.12 | 1,000 pointers, 1 pin |
| `stats()` (filesystem walk, pre-fix) | 228 | 1,101,102 chunks |
| Metrics render | <0.01 | 4.4 KB of exposition text |
| Retention refresh (R4 subtree walk) | 13.1 | 100k-object expansion |
| Sync push, referenced set | 91 | 101,102 chunks, 110 MB, 1,000 pointer events |
| Sync push, repeat (warm) | 53 | 101,102 already present |
| GC dry run | 468 | 1,101,102 examined, 1,000,000 eligible |
| GC real run | 1,041 | 1,000,000 deleted, 1.02 GB freed, 101,102 protected |
| `stats()` after collection | 2.0 | 101,102 chunks remain |
| Replica spot verify | 1.4 | 1,000 leaves re-hashed on the replica |

**Whole measure phase: 31.6 minutes wall, 293 MB peak RSS.** That RSS number
is the one to watch: the protected set, the collection candidate list and the
sync wanted-set are all in-memory collections, and a 1.1M-chunk store with a
100k-object subtree pin still fits in under 300 MB. Memory is not the
constraint at this scale; durability is.

Collection deletes at **~960 chunks/s** end to end (1,000,000 in 1,041 s),
including the scan.

## The three defects it found

### 1. Collection paid one fsync per deleted chunk

Each deletion committed its own redb index transaction — **5.6 ms each**,
which is 90 minutes for a million chunks, and the cost is invisible at test
scale where a collection deletes five.

Fixed by batching: `GcCapableStore::delete_chunks` takes up to
`GC_DELETE_BATCH` (512) chunks and clears their index entries in one
transaction (`ChunkIndex::remove_batch`). Measured at 20k chunks: **112.5 s →
3.45 s, 33x.**

The ordering invariant is unchanged — index entries cleared durably, *then*
files unlinked — so a crash mid-batch leaves unindexed files (the artifact
`reindex` already sweeps), never an index naming deleted bytes.

### 2. The sync destination fsynced every received chunk

A transfer is replayable by construction: if it is interrupted, you re-run
it. Paying per-chunk durability for it bought nothing. The destination now
writes through a deferred staging store and the engine flushes **once**, at
an explicit durability barrier between the chunk phase and the event phase
(`SyncDestination::flush`; a `Flush` RPC on the wire). Imports and finalize
settle defensively first, so even a misordered client cannot file an event
over unflushed bytes.

Measured at 20k chunks: **99.2 s → 14.0 s, 7x.** Raising the staging store's
self-flush threshold to 65,536 (from the 1,024 default, which still cost
roughly one fsync per chunk) gave a further **3.7x on bulk ingest**.

### 3. `stats()` walked the filesystem — on the metrics path

`Control::stats` enumerated every chunk file and issued a `stat` per chunk:
**228 seconds at 1.1M chunks**. `GET /metrics` calls it on every scrape, so a
Prometheus job against a large store would take minutes per scrape and hold
a blocking thread throughout.

It now reads `ChunkIndex::summary()` — one sequential read transaction over
data the index already records.

**Be careful about why this is right, because the obvious reason does not
survive measurement.** Running both paths against the same directory:

| Store | Filesystem walk | Index scan | Ratio |
|---|---|---|---|
| 101,102 chunks, cache warm | 0.85 s | 0.81 s | 1.0x |
| 1,002,002 chunks | 251.8 s | 6.6 s | **38.4x** |

Both rows matter, and the first is the one that would have been missed by
asserting the obvious. At small, cache-warm sizes **the two are the same
speed** — the index scan pays a CBOR decode per entry, which cancels the
walk's saved syscalls. The advantage is entirely a scaling effect: the walk
degrades non-linearly (8 us per chunk at 101k, 251 us per chunk at 1M) as a
million-entry directory tree exhausts the OS metadata caches, while a
sequential read of one file stays flat (8.0 us against 6.5 us per chunk).

So the justification, honestly ordered: **(1) semantics** —
`ControlStats::chunks` is documented as "chunks tracked in the index", and
the walk counted orphan files `reindex` has not adopted, overstating what
the deployment holds; **(2)** it removes a pathological cliff from the
scrape path, where a Prometheus job would otherwise spend four minutes per
scrape holding a blocking thread; **(3)** speed, decisively at scale and
not at all when small. The first reason would justify the change alone; the
third would not have justified it at the size most deployments are.

Compare the two paths against any directory with:

```bash
cargo build --release --example stats_paths -p dag-control
./target/release/examples/stats_paths /tmp/scale/primary
```

## What the shapes mean operationally

- **Collection cost tracks the whole store**, not the garbage in it — every
  chunk is examined. Schedule it; never put it in a request path.
- **Replication cost tracks the *referenced* set**, not the store: the
  million loose chunks correctly did not travel, because unreferenced
  content is exactly what collection is free to delete (ADR-002).
- **A warm sync still costs a presence check per referenced chunk** (53 s
  for 101k). That check is a filesystem `exists`, deliberately: the index
  saying "present" while the file is gone would make sync skip a chunk the
  replica does not have.
- **Retention expansion is linear and fast** (13 s for a 100k-object
  subtree) — the ceiling exists to bound a hostile graph, not because the
  walk is expensive.
- **Scrapes are O(index scan)** and independent of everything else.

## Known headroom, not yet taken

Quantified so the next person can decide, rather than rediscover:

- **The GC scan issues two `stat`s per chunk** — one for age, one for size
  (`get_chunk_age` then `get_chunk_size`). One `metadata()` call yields
  both, which should roughly halve the 468 s scan. Not taken here because it
  changes the `GcCapableStore` interface, and a maintenance path that runs
  on a schedule did not justify the churn mid-review.
- **1 KiB chunks are the pathological case.** Every per-chunk cost is
  amortised over 1 KiB of payload. A corpus of realistic files moves one to
  three orders of magnitude more bytes for the same per-chunk overhead.
- **The deletion batch stalls every writer process-wide** for as long as it
  holds the in-flight registry lock — measured at ~32 ms per 512-chunk
  batch. That is the price of making the name-versus-sweep race
  unwinnable, and it is a convoy, not a deadlock; a smaller
  `GC_DELETE_BATCH` trades throughput for shorter stalls if a workload ever
  cares.
- **Nothing here is parallel.** Ingest, scan and sync are single-threaded;
  the fsync-bound phases would benefit most, and the in-flight registry lock
  taken across a deletion batch is the one place where parallelism would
  need care.
