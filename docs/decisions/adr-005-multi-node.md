# ADR-005: Multi-node replication over gRPC

**Status**: Accepted
**Date**: 2026-08-04
**Protocol-3 amendment**: 2026-08-24
**Builds on**: ADR-002 (directory sync), which this extends across a network
without moving its trust boundary

## Context

ADR-002 gave the system replication between two directories on one machine.
The remaining gap is two *machines*: a primary that takes writes and a replica
that follows it, with the same guarantees the directory transfer already
makes — byte-identical event logs, verification on receipt, divergence refused
rather than merged.

ADR-002 rejected a network remote at the time, for three named reasons:

1. `dag serve` has no authentication, and an event-import endpoint on an
   unauthenticated surface would let anyone graft pointer history;
2. the HTTP API could not answer "which of these CIDs do you already have"
   in batch, so difference detection — the whole advantage of
   content-addressed replication — degenerated to a request per chunk;
3. no event-import endpoint existed at all.

These are objections to *that surface*, not to networked replication. A
dedicated node protocol answers all three by construction.

## Decision 1: a separate, authenticated node protocol — not the HTTP API

`dag node serve` is a new listener, distinct from `dag serve`:

- **`dag serve` (HTTP) is unchanged**: unauthenticated by decision, loopback
  by default, for humans and the console. Nothing in this ADR touches its
  posture.
- **`dag node serve` (gRPC) is for other nodes.** It authenticates every call
  with a scoped bearer credential. The server hashes tokens at load time,
  compares fixed-size digests in constant time, and accepts a `current` plus
  optional `previous` credential for staged rotation. Missing/wrong tokens
  return one generic `Unauthenticated` response; a valid credential without
  the service scope gets one generic `PermissionDenied` response.
- Tokens are 32–256 characters from the padding-free base64url alphabet
  (`A-Z`, `a-z`, `0-9`, `_`, `-`). Server config and clients reject non-ASCII,
  controls, whitespace and other punctuation before binding or connecting;
  validation errors never echo the supplied secret.
- Non-loopback serving requires both credentials and TLS. A bearer token does
  not encrypt itself. Plaintext is allowed on loopback for tests and local
  development; `--allow-insecure-transport` is an explicit two-sided escape
  hatch for remote development only. Clients refuse before connecting, so a
  token is never silently offered to a remote `grpc://` destination.

gRPC over tonic, because the protocol needs typed messages, streaming in both
directions (chunk transfer up and down, event subscription), deadlines, and a
contract file a third party can implement against.

**Codegen has no external toolchain.** The `.proto` is compiled by `protox`
(a pure-Rust protobuf compiler) inside `build.rs` — no `protoc` binary, so
`cargo build` still works from a bare checkout, the same property the
committed web console `dist/` preserves.

## Decision 2: the sync engine is abstracted; the trust boundary is not moved

The ADR-002 engine was one `transfer(from, to)` over two open `Control`s. It
is now `transfer` over two traits; the simplified canonical native shape is:

```rust
trait SyncSource { enumerate(); chunk_len(); fetch_chunk(); }
trait SyncDestination {
    missing(); store_chunk(); flush(); probe_pointer_events(); probe_pin_events();
    publish_event_batch(pointer_events, pin_events, index_candidates);
}
```

The concrete trait retains staging/finalize compatibility hooks for the
separate Edge HTTP session protocol. Native directory and gRPC destinations
leave per-event hooks fail-closed and override candidate-aware atomic
publication; their sessionless finalize hook is disabled.

`Control` implements both (the directory case, unchanged behaviour); the gRPC
client implements both against a remote node. Push is a local source driving a
remote destination; pull is a remote source driving the local destination.
This is the extension ADR-002 predicted: "implementing that same
source/destination pair against a client, not reworking the algorithm."

### Protocol-v3 scale, atomicity, and compatibility boundary

Replication compatibility is negotiated before enumeration or transfer.
`Node.Info` exposes the node-protocol major/minor and capability names for
operators; the sync-scoped `Sync.Negotiate` RPC exposes the same contract to a
client that is not authorised for `Node.Info`. A major mismatch, an older
required minor, or a missing required capability fails before either peer
enumerates, uploads, or publishes anything.

Event history is independent of the bounded content walk. A source keeps an
authoritative event generation in redb and increments it in the same
transaction as every pointer or pin event-log mutation. Protocol v3 reads
pointer and pin mappings in 4,096-ref cursor pages and binds every page plus a
content-only enumeration to that generation. A concurrent mutation returns
`Aborted` and the client restarts; continuation pages are O(page), not a scan
of the already-returned prefix. Event entries and their covering signatures
are added explicitly to both the transfer set and required-live set, so a
destination that has none of the event chunks still receives them before
publication. Pointer pages separately expose direct targets decoded from
readable, matching event entries. Those targets enter only the wanted set:
missing superseded content is reported as collected history and does not block
publication. Raw event-entry bytes are charged before decoding against the
64 MiB aggregate client budget, and the negotiated
`historical-target-hints-v1` capability prevents a current client from silently
using a server that omits this classification data.

A destination stages event refs in a private resumable session. Pages are
idempotent by `(session_id, page_index)`, the session ID is stable for the
complete offer, and the final marker binds page count, pointer/pin counts, and
a digest of the ordered offer. Sessions expire after 30 idle minutes, can be
inspected or explicitly aborted, and retain an idempotent commit receipt until
expiry. The server admits at most four active sessions, 65,536 refs and 256 MiB
per session, and 512 MiB in aggregate; completed receipts have a separate
finite admission bound. Offers beyond those quotas are refused rather than
grown without a limit. The same 65,536-record ceiling applies to strict
signature/effect candidates, whose decoded classification work has a separate
256 MiB aggregate limit.

Commit first makes every received chunk durable. It validates the offered refs
and affected IDs against the authoritative destination mappings, validates the
affected pointer and destination-applicable pin closures, and classifies the
bounded signature/effect candidates. It then publishes exact event inserts,
affected heads, reverse-pin membership, signature/claim merges, and the new
event generation in one redb transaction. Publication may preserve an existing
complete recovery verdict, but cannot mint one for an unrecovered deployment.
Staged refs are never visible. A disconnect before the marker leaves no public
prefix; a disconnect during publication cannot cancel the publication worker,
and a retry observes either the stored receipt or the still-active staged
offer. A completely empty offer is a cheap idempotent publication receipt, not
a request to scan or rebuild the destination.

The destination identity is the system's current default, `local`: Global and
`Local { node_id: "local" }` pins are closure-validated publication roots;
other Local pin heads replicate as provenance metadata but neither require
their target bytes nor enter local GC retention. `source_node_id` remains only
the source-side root selector and is never inferred to be the remote
destination identity. Making destination identity configurable/persistent is
deferred until node identity itself becomes deployment state.

Protocol 3 is deliberately a breaking boundary because the older publication
shapes cannot bind signature/effect candidates to the event offer. A v3 client
rejects a v1/v2 server during negotiation before transfer. A v3 server rejects
v1/v2 negotiation and retains the legacy streaming/unary import and `Finalize`
method numbers only to return an immediate `FailedPrecondition`; those methods
never read a stream, stage a mapping, or publish state. `BeginEventImport`,
`StageEventImport`, and candidate-aware `CommitEventImport` are the only native
event-publication path.

Mixed protocol majors therefore fail closed rather than interoperate. Operators
must stop replication and coordinate the major upgrade; upgrading servers first
then clients is operationally convenient, but old clients will not replicate
during the interval. This is not a zero-downtime rolling-compatibility promise.

**Validation runs in the destination process, always.** The incremental
chain-integrity, right-id-right-seq, predecessor/successor, closure, and
divergence-refused checks execute on whichever side is being written to: the
server during a push, the local process during a pull. A remote peer can never
make a destination file an event its own validation would refuse. Every
hostile-history test the directory engine has (grafted deactivations, divergent
chains, gap injection) holds over the wire because it is the same code on the
same side.

`Missing` is the batch has-CID endpoint whose absence was ADR-002's second
objection: the client offers CIDs in bounded batches, the server answers with
the subset it lacks, and only those chunks travel. Every received chunk is
re-hashed by the receiving store exactly as before; a mismatch fails that
chunk alone.

Chunks stream in bounded frames (256 KiB) rather than single messages, so the
protocol's message-size limit stays small and a 4 MiB chunk neither inflates
it nor fragments the API.

## Decision 3: primary/replica, not multi-master

"Consensus for pointer updates" is scoped to what the data model already
makes true: a pointer's history is a single chain, so there must be exactly
one serialization point per pointer. In this version that point is one node —
the primary — and the protocol makes remote writes safe rather than making
concurrent masters converge:

- `Pointers.Resolve` / `List` give replicas and clients reads.
- `Pointers.Update` carries `expect_seq`, a compare-and-set: the primary's
  per-log mutex serializes writers, and an update whose expectation is stale
  is refused with the current head so the caller re-reads and retries.
  `expect_seq = 0` means create. Two concurrent remote writers cannot lose an
  update — one wins, one is told exactly why it did not.

Raft (or CRDT pointers) is deferred, on reasoning worth recording: consensus
buys the ability for writes to survive the loss of the primary, at the price
of a quorum dependency, membership management, and a much larger correctness
surface. No deployment of this system needs that yet. What ADR-002 already
guarantees — divergence is *refused loudly*, never merged silently — means a
failed-over replica that took independent writes cannot corrupt a recovered
primary; reconciliation is a human decision, reported per event. That is the
honest failure mode until real demand pays for quorum.

## Decision 4: what is reachable over the wire — and what is not

Reachable: `Node.Info` (version, schema version, store stats), the `Sync`
service (negotiate / enumerate / missing / chunk transfer / bounded staged
event publication),
`Pointers` (resolve, list, CAS update), `Events.Subscribe` (journal replay
from a sequence number, then live tail — the same semantics as
`dag events tail --since-seq --follow`).

Deliberately absent, each for the same reason it is absent from the HTTP API:

- **No job/spec or direct-execution API.** Jobs and commands do not appear in
  the protocol. A pointer update may enqueue an existing destination-local
  `OnPointerUpdate` subscription only when its credential has both `pointer`
  and `trigger`; an exec-backed job additionally requires the destination
  operator's local `--allow-exec-jobs` capability. Thus a peer can activate
  only automation the destination explicitly configured, and neither remote
  trigger authority nor the local process grant is sufficient by itself.
- **No GC.** Deletion stays a local operator decision at the console of the
  node that owns the disk. "Federated GC" in this version is the scope
  semantics the pin model already has: a node's collector honours its own
  pins and pointers; `PinScope::Local { node_id }` pins on *other* nodes do
  not protect content here, and nothing remote can trigger a sweep.
  Coordinated cross-fleet deletion is deferred alongside consensus.
- **No trust operations.** The keyring is not readable or writable remotely,
  and sync continues not to move it (ADR-002): a source must not decide what
  its replica trusts.
- **No migrate, reclaim, or recovery flags** — all local-deployment state.

## Decision 5: operational shape

- `dag node serve --data-dir D --listen ADDR --auth-file F --tls-cert C
  --tls-key K [--allow-exec-jobs]` — one process per data directory, same redb single-handle
  rule as ever. The JSON file contains `current` and optional `previous`
  objects, each with `token` and `scopes`. The colocated durable job worker
  starts with no capabilities; `--allow-exec-jobs` is the explicit local
  process-execution grant and does not add a job-management or direct-exec RPC.
- Scopes follow service boundaries: `read` for `Node.Info`, `sync` for the
  complete replication service, `pointer` for pointer reads/CAS updates, and
  `events` for subscriptions. `trigger` is a conditional second authority: a
  `pointer`-only CAS remains valid when it would enqueue no active local job,
  while a subscribed update atomically refuses unless the same credential also
  has `trigger`. `trigger` alone does not reach the Pointers service. `admin` is
  an explicit wildcard. The old `--token`/`--token-file` route remains for safe
  cutovers, grants `admin` (including trigger), cannot overlap `--auth-file`,
  and is still subject to TLS/plaintext policy. Existing `pointer` auth files
  remain valid for unsubscribed pointers; add `trigger` during rotation before
  using them for subscribed updates. No-auth loopback retains historical
  all-scopes behavior.
- Atomic `Sync` publication files replicated pointer history and derived heads
  but does not enqueue destination-local pointer jobs. It nevertheless requires
  `trigger` when the same publication transaction would advance a pointer with
  an active destination `OnPointerUpdate` subscription; `sync` alone remains
  sufficient for pins and unsubscribed/idempotent pointer offers. The check is
  made before any event, head, generation, or index row changes. Already queued
  pointer intents carry enqueue-time job-revision and input-manifest snapshots,
  so a later sync or job update cannot steer their execution material.
- `dag sync push|pull --remote grpc://host:port` (or `grpcs://` with
  `--ca-cert`) joins the existing `--remote <path>` form; the report and exit
  behaviour are identical to the directory case, including per-chunk failure
  isolation and non-zero exit on partial transfer. Enumeration ends with a
  mandatory completeness marker carrying any walk truncation, and dry-run
  conflict probes are read-only RPCs. `--node-id` is sent to the source to
  select which local-scoped pins root content; it does not rewrite their scope
  for the destination.
- `dag events tail --remote grpc://…` tails a remote node's journal.
- `dag node info --remote grpc://…` is the operational ping.
- Every remote client command accepts `--allow-insecure-transport`, but only
  as an explicit opt-in for non-loopback `grpc://`. `grpcs://` is the
  production form. The same rule applies to the HTTP sync client: remote
  `http://` is refused and redirects are never followed.
- `--ca-cert` augments native platform roots rather than replacing them.
  Native unary calls carry deadlines. PutChunk also has frame-idle/total
  bounds and aggregate upload/download admission; event replay and pointer
  listing are capped/paginated without putting a deadline on live streams.
- `Missing` reads and hashes at most 16 purportedly held chunks per call.
  Neither a filesystem path nor an index receipt alone can hide indexed
  corruption from a later replication.

## Consequences

- A replica on another machine passes `dag usecase verify` with event logs
  byte-identical to the primary's — the ADR-002 acceptance test, now over a
  network.
- Re-running an interrupted remote sync recomputes missing content from content
  addresses and resumes event publication through the bounded, digest-derived
  server session and its idempotent receipt. There is no unbounded client-side
  transfer journal to corrupt.
- The workspace gains one crate (`dag-net`) and the dependency direction
  gains one edge: `cli → net → control`. The HTTP API and the node protocol
  do not know about each other.
- A node exposes two listeners with two postures: an unauthenticated local
  HTTP console and an encrypted, scoped-auth node port. The asymmetry is deliberate
  and documented; collapsing them would either put auth on the console
  (rejected in ADR-002's context) or node operations on an open port
  (rejected here).
