# ADR-007: Distribution runtime — wasm verifier and Edge replica

**Status**: Accepted
**Date**: 2026-08-21
**Builds on**: ADR-002 (sync engine as source/destination traits),
ADR-005 (authenticated destination-side import), ADR-006 (public
content plane), the `ContentStore` trait in `dag-core`

## Context

The kernel is a single-writer directory. That is the form factor, and
it is finished. What was missing is a second place for the bytes to
live that is not another laptop directory, and a verifier that is not
another `dag` binary.

ADR-002 rejected HTTP sync on three named grounds: no authentication
on `dag serve`, no batch "which CIDs do you have," and no event-import
endpoint that would be safe on an unauthenticated surface. ADR-005
answered those over gRPC for node-to-node. This ADR answers them over
HTTP for two new runtimes: a **browser verifier** (wasm32 `dag-core`)
and a **Cloudflare replica** (R2 + Durable Objects).

The three objections close because this surface is not `dag serve`:

1. Writes and imports require a bearer token (constant-time compare),
   the same model as `dag node serve`.
2. `POST /sync/missing` is the batch has-CID endpoint.
3. Import validation runs in the **destination** — the Worker —
   using the same `offer_pointer_event` / `offer_pin_event` functions
   the laptop `import_event` uses. A peer cannot file history the
   destination itself would refuse.

## Decision 1: the kernel compiles to wasm32

`dag-core` stays a `std` library. An optional `wasm` feature wires
`getrandom` for the wasm32 target. The portable surface is:

- `Cid::compute`, `from_hex`, `from_bytes`
- `Entry` encode/decode
- `file::{join, verify_deep, info_from_bytes}`
- `signing::{verify_envelope, record_from_bytes}`
- `offer_pointer_event` / `offer_pin_event` (chain rules, no I/O)
- `MemoryStore` — first-class `ContentStore`, no longer `#[cfg(test)]`

`FsStore`, redb, tokio, tonic do **not** go on wasm32. `dag-wasm` is
a thin `wasm-bindgen` crate over that surface. A committed verify
page fetches chunks from a content plane (ADR-006) or an Edge Worker
and paints the same 7-of-7 walk `dag usecase verify` prints.

`ContentStore` keeps `Send + Sync`. wasm32-unknown-unknown accepts
the bound on a single-threaded target.

## Decision 2: stores are the runtime, not forks of the engine

| Store | Runtime | Durability |
|---|---|---|
| `FsStore` | laptop | fsync + redb index |
| `MemoryStore` | tests, wasm tab | process lifetime |
| `R2Store` | Cloudflare Worker | R2 object = CID hex |

`R2Store::put_chunk` re-hashes and refuses a mismatch. `missing`
treats an object that is absent **or** size 0 as missing — the
torn-upload analogue of `Control::missing` requiring indexed *and*
present. A lying or partial PUT cannot become a permanent hole.

## Decision 3: one Durable Object per pointer is the Edge primary

A pointer's history is a single chain, so there is exactly one
serialization point per pointer (ADR-005). On the laptop that point
is the per-log mutex plus a redb transaction. On the Edge it is a
Durable Object addressed by `idFromName(pointer_id)`, with the event
map in DO SQLite.

`expect_seq` CAS is the same primitive as `PointerLog::update_cas`.
Divergent history is refused, never merged. No CRDT. Pin events use
the same shape (one DO class, or a dedicated pins object).

The Worker is a **replica** when the laptop pushes, and an Edge
**primary** for names whose CAS updates originate there. A laptop
accepting DO-originated writes is out of scope for this pass (the
existing gRPC CAS client would be the path). Trust still does not
travel: the Worker has no `trusted_keys` table.

## Decision 4: the HTTP sync contract

Authenticated (token) unless noted:

| Method | Path | Role |
|---|---|---|
| GET | `/c/:cid` | public; name is the hash |
| POST | `/sync/missing` | destination; batch has-CID |
| PUT | `/c/:cid` | destination; re-hash, 4 MiB cap |
| POST | `/sync/flush` | destination; durability barrier |
| POST | `/sync/probe/{pointer,pin}` | sessionless read-only conflict check |
| POST | `/sync/import/pointer` | destination; `offer_pointer_event` |
| POST | `/sync/import/pin` | destination; `offer_pin_event` |
| POST | `/sync/finalize` | destination; rebuild heads |
| POST | `/sync/abort` | best-effort discard after definitive import refusal |
| POST | `/pointers` | CAS update, `expect_seq`, token |

Limits copy the node port: never `Vec::with_capacity(declared)`,
`MAX_CHUNK_SIZE` refused before buffering past 4 MiB, missing-batch
capped. Frame/idle budgets apply where the Worker streams; a single
PUT of one chunk does not need the gRPC frame loop.

`dag sync push --remote https://… --token-file` drives
`HttpDestination`, which implements the existing `SyncDestination`
trait. The laptop engine does not change. `http://` is accepted only for
loopback unless the caller explicitly passes `--allow-insecure-transport` for
remote development. Redirects are not followed, including downgrade
redirects, because replaying `Authorization` to a peer-selected destination
would cross the authentication boundary.

Each push lazily generates one UUIDv4 `X-Dag-Sync-Session`, attached only to
pointer/pin imports, finalize, and abort. Chunks, missing, flush, and dry-run
probes are sessionless. A destination that has imported nothing returns a
zero-count finalize receipt locally and sends no request. The Worker refuses an
unknown UUID instead of synthesizing an empty session. It retains bounded exact
receipts for completion, abort, expiry, and validation refusal, so replay is
stable while a receipt is retained and remains fail-closed as
`sync_session_unknown` after eviction.

An upgraded Catalog revalidates a legacy `publishing` snapshot that has no
durable validation witness. A failure terminalizes and removes only that exact
unwitnessed owner/revision; witnessed publication and changed revisions are
never cleared. Readiness requires the publishing witness to equal its revision:
it remains false while legacy revalidation is pending and also fails closed on
a corrupt, mismatched non-null witness, which recovery never silently clears.

A definitive structured import refusal is abortable. Structured
`sync_busy`, `coordination_recovered`, `sync_context_changed`,
`sync_revision_changed`, publication-pending/unavailable, rate-limit, and
internal-error responses retain the exact UUID for a bounded same-session
retry. Validation, capacity, authentication, and invalid-request failures are
terminal for that attempt. Malformed or truncated error bodies never authorize
abort or session rotation, and finalize uncertainty never aborts a session
which may already be publishing. Response JSON is capped at 128 KiB and error
diagnostics are read only through a 512-byte cap.

## Decision 5: what the Worker will not do

No job execution. No garbage collection. No keyring. No migrate. No
recovery flags. Each is absent for the same reason it is absent from
the gRPC proto (ADR-005). Exec on a Worker would be the HTTP RCE
problem with extra steps.

No IPLD, no libp2p, no SourceHub, no CRDT pointer heads. See
[ECOSYSTEM.md](../ECOSYSTEM.md).

## Consequences

- A browser can verify a release without an account and without
  trusting the host, provided it walks CIDs. That is the product
  thesis made literal.
- HTTP sync is no longer deferred. The three ADR-002 objections are
  answered on this surface, not on `dag serve`.
- Import validation has one contract, with native and Worker-specific
  implementations tested against the same canonical fixtures. Worker
  acceptance comes from the TypeScript unit and Workerd runtime suites. The
  Rust crate's opt-in in-process HTTP harness is only a native-client transport
  smoke fixture: it deliberately lacks the Worker's staged-session protocol
  and must not be cited as parity or Worker security evidence. Live account
  deployment remains separate evidence.

## Not decided here

WASM job adapters (the honest sandbox exec cannot claim). OPFS as a
persistent browser store. A laptop following an Edge-primary pointer.
mTLS. Sigstore. Those stay backlog.
