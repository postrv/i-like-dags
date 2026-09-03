# ADR-002: Replication between data directories (`dag sync`)

**Status**: Accepted
**Date**: 2026-07-26
**Supersedes**: the `StorageNodeAdmin::replicate` sketch, deleted in the typed-error refactor

## Context

Everything lives on one disk. Content addressing makes replication unusually
cheap — every transfer is incremental by construction, because the receiver
already knows the name of every byte it holds — but nothing used that.

The gap this closes is "durable" versus "survives the laptop".

## Decision 1: replicate directory-to-directory, not over HTTP

`dag sync push <path>` and `dag sync pull <path>` take a filesystem path to a
second data directory. That directory can be an external disk, a mounted
share, or something a backup tool then ships onward.

HTTP was the alternative. It is rejected for now on three counts:

1. **`dag serve` has no authentication, by decision.** Pushing *to* a remote
   over an unauthenticated API means anyone else can push to it too. Sync
   would be building on a surface that is deliberately trusted-network-only.
2. **The API cannot answer the question sync asks.** There is no batch "which
   of these CIDs do you already have" endpoint, so a push would need one
   request per chunk. The single most valuable property of content-addressed
   replication — cheap difference detection — is the thing the current API is
   least able to serve.
3. **No event-import endpoint exists**, and adding one that accepts
   pre-existing pointer events over an unauthenticated surface would let any
   caller graft history onto a pointer.

The engine is written as one `transfer(from, to)` over two open `Control`s,
with `push`/`pull` differing only in argument order. Adding an HTTP remote
later means implementing that same source/destination pair against a client,
not reworking the algorithm.

## Decision 2: transfer events, never replay them

The tempting implementation is to read the source's pointer history and call
`create`/`update` on the destination. It is wrong.

`PointerLog::create` and `update` stamp `chrono::Utc::now()` into the event
and derive `seq` from the local head. Replaying that way produces events whose
bytes differ from the originals, so **every replayed event lands on a
different CID**. For a system whose entire claim is that a CID names exactly
one sequence of bytes forever, a replica whose provenance log has different
identifiers is not a replica. It would also invalidate any signature made over
an event.

So sync moves the event *entries* — they are ordinary content-addressed chunks
— together with the `(id, seq) → event_cid` mappings from the log's redb
table. The destination ends up byte-identical, CID for CID.

This requires two new primitives on each log:

```rust
fn event_cids(&self) -> Result<Vec<(String, u64, Cid)>>   // enumerate
fn import_event(&self, id: &str, seq: u64, cid: &Cid)     // insert one mapping
```

`import_event` is the trust boundary and validates before writing:

- the CID resolves to an entry that is already in the local store;
- the entry decodes to an event of the right type;
- the event's own `id` and `seq` match the key it is being filed under — so a
  sender cannot file event *A* under pointer *B*'s sequence;
- for pointers, `prev` matches the `new` of `seq - 1`, and `seq == 1` is a
  create with no `prev` (P1, P2);
- an existing mapping at that `(id, seq)` must already name the same CID.
  Divergent history is refused rather than overwritten.

That last rule is what makes the operation safe to repeat and safe to run
against a directory that has its own writes: sync can add history, never
rewrite it.

## Decision 3: verify on receipt, and let one bad chunk fail alone

Every received chunk is re-hashed. `FsStore::put_chunk` already computes the
CID of what it is given, so the check is to compare that against the CID the
sender claimed — a mismatch means the chunk is dropped and counted, and the
sync continues.

The alternative, aborting the whole transfer, is worse for the case that
actually happens: one corrupt chunk on a failing source disk should not stop
the other 99.9% from reaching safety. The report names what failed, and a
subsequent run retries exactly those chunks because they are still missing.

Chunks that did arrive are flushed and kept as resumable progress, but **no
event-derived heads or indexes are published while any attempted chunk
failed**. Publication is one barrier after a complete content phase; a
partial copy is never presented as a complete replica.

The graph walk has a configurable safety ceiling. Reaching it is represented
by structured truncation metadata (`visited`, `limit`, and the remaining
frontier), makes the report incomplete, and blocks atomic event/index
publication. It is not a successful short walk. Hitting the ceiling exactly
with an empty frontier is complete.

## Decision 4: what moves, and what does not

**Moves**: chunk bytes; pointer events; pin events; signature entries (found
through the source's `sig_by_target` index, since nothing links *to* a
signature — the link points the other way); and everything reachable by
walking entry links from current pointer heads and effective pin targets.
Every readable pointer event also contributes its direct target as a bounded,
wanted-only provenance hint. Superseded hints are not recursively walked and
are not required-live: if the source has collected one, sync records it in
`missing_at_source` without blocking publication of an otherwise intact
current state. Signature discovery covers the current live closure and event
entries, including event signatures and counter-signatures; a direct
historical hint does not start recursive content or signature discovery.

Pin event history always moves as provenance. A pin roots content only when it
is active, unexpired, and its scope applies at the source: global pins apply;
`Local { node_id }` applies only when it matches `SyncOptions.source_node_id`
(`local` by compatibility default and configurable with `dag sync --node-id`).
A direct pin offers exactly its target. A subtree pin follows links only to its
recorded depth. The scope is not rewritten for the destination: operators must
run destination GC under the destination's own node identity.

**Does not move**:

- **Trusted keys.** Trust is a local operational decision (that is the rule
  the signing layer is built on). Copying a keyring would let a source decide
  what its replica trusts. Signatures arrive; whether they are *trusted* is
  answered by the receiving machine's own keyring.
- **Job specs, runs and the effect cache.** A replica is a copy of data and
  its provenance, not of a scheduler. Syncing an effect cache would also mean
  a side-effecting job could be considered "already run" on a machine where
  it never ran. Deferred deliberately.
- **The event journal and recovery flags.** Both describe the local
  deployment's own history and state.

### What rooted content excludes

Recursive roots are current pointer heads and effective pin targets. Direct
targets named by pointer history are also offered, but **content with no
current pointer, historical pointer target, or effective pin is not
replicated**. A bare `dag put` followed by `dag sync push` does not back that
content up.

That is deliberate and consistent rather than an oversight: unreferenced
content is exactly what garbage collection is free to delete, so treating it as
worth replicating would be claiming a durability the local directory does not
offer either. Anything worth keeping is worth pinning, and the pin is the
statement that makes it so.

It is still a sharp edge, so `dag sync` reports the chunk count it moved and
the CLI documents it. If a future version grows an `--all` flag that sweeps the
whole store, it should be opt-in for this reason.

## Decision 5: derived state is validated and merged at atomic publication

After a complete transfer the destination validates only the offered refs and
affected pointer/pin IDs against its authoritative event mappings. It derives
the affected heads and reverse-pin membership, classifies the bounded
signature/effect candidates supplied by the source, and publishes all exact
event inserts and derived merges in one transaction. It does not copy a source
head table, scan unrelated destination history, or inventory the whole local
store. Publication may preserve an existing complete recovery verdict, but it
cannot certify an unrecovered deployment.

Any chunk failure, walk truncation, malformed event, missing closure, or
divergent event blocks that publication and leaves previously visible mappings,
heads, and indexes unchanged. Dry-run performs read-only event-position probes
where the destination supports them, so local and gRPC plans report divergence
without writing.

## Consequences

- A replica passes the same `dag usecase verify` the original does. That is
  the acceptance test.
- Re-running a sync transfers only what changed; an interrupted one resumes
  by re-running, with no journal or resume token, because "what is missing"
  is always recomputable from content addresses.
- Sync is one-directional per invocation. There is no merge and no conflict
  resolution: divergent pointer history is reported, not reconciled. Multi-
  writer convergence (CRDT pointers) remains a Phase-4 question.
- The destination must not be open in another process — redb locks its
  database file to one handle.
