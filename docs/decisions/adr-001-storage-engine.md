# ADR-001: Replace sled with redb for control-plane storage

Status: **accepted / implemented** · Date: 2026-07-26

## Context

All control-plane metadata sits in sled 0.34.7: the CID→location index
(dag-storage) and the pointer/pin/job logs, event journal, and recovery flags
(dag-control), spread across five separate sled databases per data directory.
Chunk bytes never touch sled — they live on the filesystem under `FsStore`.

sled's last release was 2021. Its 1.0 rewrite has been in alpha for years, the
on-disk format is documented as unstable ahead of 1.0, and it is the sole
source of one (now patched) RUSTSEC advisory in our tree. Staying means
building a durability-critical product on an engine that is, in practice,
frozen.

What we actually use of sled, measured (`grep` over the workspace):

| Operation | Sites | Notes |
|---|---|---|
| get/insert/remove/contains | ~107 | plain KV |
| iter / first / last | ~73 | head lookups, listings |
| open_tree | 30 | namespaces |
| flush | 32 | explicit durability |
| **multi-tree transactions** | **5** | events+heads atomicity, with retry loops up to 10 attempts |
| scan_prefix / range | 4 | binary-key history reads |
| merge operators / watch_prefix / compare_and_swap | 0 | — |

The workload is a **metadata control plane**: small values (32-byte CIDs,
CBOR-encoded heads and event references), append-heavy logs keyed for
lexicographic range scans, modest volume. It is not a data plane.

## Options considered

**redb** (pure Rust, copy-on-write B-tree, ~4.7k stars). Stable, maintained,
explicitly stable file format with a committed upgrade path. ACID with MVCC:
one writer, non-blocking readers, savepoints, multiple tables per transaction.
Compiles in seconds.

**fjall** (pure Rust LSM, 3.0 released with a rewritten forward-compatible
format). Benchmarks ahead of redb and at/above RocksDB on write-heavy
workloads; both single-writer and serializable-snapshot-isolation transaction
modes. Author states feature development "will mostly wind down going into
2026" — a stabilisation phase, not abandonment, but the 3.0 format is brand
new. Its LSM strengths target write volumes this control plane does not have.

**RocksDB** (via rust-rocksdb). Battle-tested at scale — and mis-matched here
on every axis that matters to us: C++ toolchain dependency, ~40 s compile vs
seconds, large binary, deep tuning surface, and its advantages only appear at
data volumes the control plane will never see. It would also directly damage
the "SQLite of DAGs" positioning: an embeddable provenance tool that takes
minutes to `cargo install` is not embeddable.

**SurrealDB.** Category error for this slot, considered honestly because it
keeps coming up: it is a full document-graph database (query language, server
modes, its own versioning) that itself sits on a pluggable KV layer — RocksDB
or its beta pure-Rust engine surrealkv. Adopting it would replace a KV library
with an entire database engine, move invariant enforcement (append-only logs,
sequence contiguity) out of our Rust code and behind a query language, and
pull in an enormous dependency tree. Its graph features would not even apply:
our graph lives in content-addressed entries on the filesystem, not in the KV
store. If a future product layer wants rich queries *over* provenance, that
is a read-model built from the event journal — not a storage engine swap.

**heed/LMDB.** Production-proven under Meilisearch, but a C dependency with
mmap semantics and key-size caveats, and no advantage over redb for this
workload. **canopydb**: author's own README says do not trust it with
production data. **sled 1.0**: still alpha, still requires a format migration
to get to — the cost of migrating without the benefit of leaving.

## Decision

Adopt **redb**. Two structural changes ride along:

1. **One database, many tables.** The five sled DBs collapse into a single
   redb file with one table per current tree. Cross-log atomicity —
   impossible across separate sled databases — becomes a plain multi-table
   transaction (e.g. recovery flags and rebuilt heads commit together).
2. **Retry loops become straight-line code.** redb's single-writer
   serializable transactions replace the optimistic-concurrency retry loops
   (10-attempt) in `pointer.rs`, `pin.rs`, and `job.rs`. This deletes the
   most delicate concurrency code in the workspace, which is the largest
   real win of the migration.

fjall is the fallback if the control plane ever becomes write-bound; the
storage layer should be shaped so that swap stays cheap (no redb types in
public APIs).

## Migration path

The system is event-sourced with a recovery gate built on exactly the premise
"derived state may be stale — rebuild before trusting it". A store migration
is the ultimate stale cache, and the machinery already exists:

- **Primary data (copied):** pointer events, pin events, job events + runs +
  effect cache + pointer subscriptions, event journal. Chunk bytes are on the
  filesystem and untouched.
- **Derived data (rebuilt, not copied):** pointer heads
  (`rebuild_from_events`), pin heads and retention (`PinLog::rebuild`), the
  CID index (`FsStore::reindex`), and job heads (`JobLog::rebuild`).

`dag migrate` is an offline transaction rather than a sequence of in-place
writes. Historical `Control::open` created all six sled databases, so migration
requires the complete canonical six-source set and refuses a partial legacy
directory. It preflights every source and backup destination, locks the live
sled databases through validation and publication, and copies into a private
same-filesystem staging file. The known default-tree rows in `index` and
`recovery.db` are rebuild-only inputs; they are not copied, but remain covered
by the whole-source snapshot and drift checks. Any other nonempty unmapped tree
is refused. Migration verifies copied row counts and bytes, then opens the stage
through the current schema and standard chunk/pointer/pin/job rebuild paths.
Only a fully recovered stage is published with no replacement. The original
names are still intact at that point and are subsequently renamed one-by-one to
`*.sled.bak`; every renamed database is reopened and matched to the durable
source digest before its phase is committed. A private durable phase directory
makes every retirement idempotently resumable and is renamed to a permanent
completion receipt.

`Control::open` refuses a sled-format directory, any active marker or orphaned
stage, and any unmarked layout containing both `control.redb` and live sled
sources. If `control.redb` is missing, a completion receipt or any
`*.sled.bak` path also blocks empty reinitialisation. There is no silent
auto-migration and no window in which a partial publication is accepted as
authoritative.

Those crash-atomic/no-replace claims are the Linux/macOS local-filesystem
contract. Other targets and filesystems need an independently tested equivalent
for sled locking, no-replace rename and durable directory fsync; absent that,
the operator must rely on a stopped volume snapshot rather than this proof.

## Consequences

- The live control plane and every server request path use redb. The released
  `dag` CLI temporarily retains sled solely for the explicit, offline
  `dag migrate` compatibility path, because removing it would strand
  pre-redb directories. `deny.toml` confines sled to that one direct wrapper
  and records its two unmaintained (not vulnerability) transitive advisories;
  sled and that subtree leave after the documented migration window.
- On-disk format changes; `dag migrate` is a one-way door with an explicit
  backup, and README must document it.
- The `Arc<Db>`-lifetime and `flush()` idioms map 1:1 (redb `Database` /
  `WriteTransaction::commit` with `Durability::Immediate`).
- ~11 files change: all five logs, recovery, the index, and their tests.
