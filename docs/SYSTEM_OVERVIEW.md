# The system, explained

> One document covering what has been built, why it is shaped the way it is,
> and the roadmap as currently understood — including the choices still open.
> Companion documents: [USE_CASE.md](USE_CASE.md) (the runnable worked
> example), [ALL_USE_CASES.md](ALL_USE_CASES.md) (the application survey),
> [ECOSYSTEM.md](ECOSYSTEM.md) (Grok Bot, agent VMs, Source Network),
> `decisions/` (the ADRs), and [runbooks/operations.md](runbooks/operations.md).

## The thesis

An embeddable, single-directory content-addressed DAG store — "the SQLite of
DAGs" — where provenance is the product, not a feature. Content addressing
proves *what*, attestation jobs record *how*, pins prove *still there*,
signatures prove *who*, and replication produces a copy that proves all of it
again somewhere else. Every claim is checkable by someone holding nothing but
the bytes: no account, no API access, no trust in the operator.

The form factor is the strategy. Everything below runs from `cargo add` and a
directory on disk; there is no server to deploy. `dag serve` is a loopback
viewer. `dag content serve` (ADR-006) is the public read-only plane a
browser verifier can hit. An Edge replica (ADR-007) is a second
`ContentStore`, not a second product.

## The data model — five nouns and a signature

**Chunks.** The unit of storage: at most 4 MiB of bytes, named by the SHA-256
of those bytes. The name *is* the hash (a CID), so a chunk cannot change
under its identifier (invariant I1), storing the same bytes twice is a no-op,
and verification is re-hashing. CIDs are exactly 32 bytes, enforced at every
boundary — parser, deserializer, store — because a shorter one once reached
the filesystem sharding code and panicked a server.

**Entries.** A payload plus named links to other CIDs, CBOR-encoded, stored
as an ordinary chunk. Links live inside the entry's bytes, so they are
covered by its CID: you cannot change what an entry points at without
changing what the entry *is* (I3). Entries linking entries form the DAG.

**Files.** Content larger than 4 MiB is split by FastCDC content-defined
chunking (256 KiB / 1 MiB / 4 MiB) behind a `file/v1` manifest — an entry
linking the pieces in order. Chunk boundaries follow content, so a revision
that inserts a row re-uses almost every chunk of the previous version. The
manifest is timestamp-free; the same bytes always produce the same root CID.
V1 roots must carry exact byte, chunk and direct-link totals. Readers charge
repeated references against checked byte/chunk/node/link/fetch budgets before
descent; local helpers default to 64 GiB and the HTTP/job policies to 1 GiB.
Split builds the manifest incrementally, retaining only one bounded link group
per tree level rather than every chunk link until EOF.

**Pointers.** The one mutable thing: a name that resolves to a CID today and
may resolve to a different one tomorrow. Updates append to an event log —
each event itself a content-addressed entry — so history is complete,
ordered, and tamper-evident (I4, P1–P4). "What did `models/production` mean
in March?" is a lookup, not an investigation.

**Pins.** Retention as data. A pin protects a CID — or, as a subtree pin,
everything transitively reachable from it — with a scope and optionally a
TTL. Garbage collection honours effective retention (I6), never
runs before the derived state has been rebuilt from the logs (the recovery
gate), and when uncertain, retains (R6). Unpinned, unreferenced content is
collectable — which makes the posture *tamper-evident but erasable*, a
combination blockchains cannot offer.

**Signatures.** Ed25519 over DSSE envelopes carrying in-toto v1 statements —
the formats the supply-chain ecosystem already verifies. A signature is
stored as an entry with a `signs` link to its target: walkable, pinnable,
collectable like everything else. Trust is a local keyring populated by
explicit `dag key trust` decisions, and a *trusted* verdict is only ever
computed against the keyring's copy of the key — never the key embedded in
the record, or anyone could claim any key ID.

On top of the nouns sits one verb worth naming: **jobs**. Queue admission
binds both the exact filed job-event revision and the then-resolved static and
pointer inputs into an immutable run manifest (J3). Claims and execution load
that revision, never the mutable job head, so an update after enqueue cannot
change code, configuration, adapter, declared outputs or inputs underneath
queued work. Deterministic jobs are
reproducible from their manifest (J1). Side-effecting jobs are memoized: the
effect key is the configuration plus the input manifest, so identical work is
never repeated (J2) — which is build-cache semantics, verified live at three
requests to one invocation. The `exec` adapter runs real commands over
materialised inputs under that regime. Manual and worker execution use the
same durable lease/token lifecycle; only the token holder can start,
heartbeat or complete a run.

## Architecture

Seven library crates plus two distribution crates, strictly one-way:

```
dag-cli → dag-api → dag-jobs → dag-control → dag-storage → dag-core
        → dag-net ─────────────↗
dag-wasm ───────────────────────────────────────────────→ dag-core
dag-edge ───────────────────────────────────────────────→ dag-core
```

- **dag-core** — the data model: CIDs, entries, the chunker, signing, traits,
  typed `CoreError`, first-class `MemoryStore`, pointer/pin offer validation.
  No I/O policy of its own. Compiles to wasm32 behind the `wasm` feature.
- **dag-storage** — the storage node: filesystem chunk store sharded by CID
  prefix, redb index, integrity scan, garbage collector. Operates at chunk
  level only; it never parses the DAG (I9).
- **dag-control** — the orchestrator: pointer log, pin log, retention index,
  job log, signature log, event bus, recovery state, replication engine,
  `HttpDestination`, and `Control::open(dir)` — the single entry point that
  owns one on-disk layout.
- **dag-jobs** — adapters, the runner, effect caching, the capability system,
  `RunError` (the extension point for third-party adapters).
- **dag-api** — axum HTTP API split into a content plane and a control plane
  (ADR-006), SSE, streaming file transfer, the embedded TypeScript console
  (`tsc` alone, `dist/` committed), and the seeded scenario behind
  `dag usecase`.
- **dag-net** — authenticated gRPC node protocol (ADR-005).
- **dag-cli** — every operation as a command, JSON output, BSD-sysexits exit
  codes derived by matching the typed errors through the causal chain.
- **dag-wasm** — `wasm-bindgen` surface over dag-core for a browser verifier.
- **dag-edge** — the deployable Cloudflare Worker lives in `dag-edge/worker/`
  and uses R2 plus Durable Objects for the token-gated sync destination
  (ADR-007). The Rust crate contains storage models and an explicit,
  non-default `test-harness` transport fixture; that fixture is not the Worker
  protocol implementation or Worker acceptance evidence.

One data directory holds everything:

```
<data_dir>/
  data/          chunk bytes, sharded by CID hex prefix
  control.redb   one database: index, all logs, journal, recovery flags
  keys/          Ed25519 secret keys, mode 0600, untouched by store or GC
```

redb is single-writer by design (ADR-001): a per-log mutex plus one write
transaction replaced the retry loops sled required. A directory written by a
pre-redb release is refused with a message naming `dag migrate`, which
converts it losslessly — verified against a real sled-built directory,
identical CIDs after migration.

## The decisions that make it what it is

These are load-bearing; each is written down where it was made.

1. **History is transferred, never replayed** (ADR-002). `dag sync
   push|pull` moves pointer and pin *event entries* — ordinary chunks —
   rather than re-issuing creates and updates, because replaying would stamp
   new timestamps and give every event a different CID. A replica is
   byte-identical, CID for CID, and a signature made over an event survives
   replication. `import_event` is the trust boundary: it validates the
   entry, its claimed position, chain integrity, and refuses divergent
   history rather than overwriting it.

2. **Sync replicates from roots.** Pointer history is preserved; current
   pointer heads and active, non-expired, scope-matching pins define live
   content. Direct/subtree depth semantics match retention. Content with
   neither is exactly what collection is free to delete. Walk truncation and
   transfer/import failures block publication of new destination heads.

3. **The capability gate is the security boundary, not the cargo feature.**
   Cargo unifies features across a workspace, so `dag-api` links a `dag-jobs`
   with exec compiled in. What keeps an unauthenticated HTTP endpoint from
   being drive-by RCE is `Capabilities` — deny-by-default,
   granted only by the CLI's per-run `--allow-exec` or the node worker's
   explicit `--allow-exec-jobs`, never by the API path or a stored job spec.
   A test runs with the feature ON and proves the API still cannot execute,
   and a companion proves the same job runs when granted, so the first cannot
   pass for the wrong reason.

   The native node port exposes no job/spec or direct-execution RPC. A remote
   pointer mutation can enqueue an existing local subscription only with both
   `pointer` and `trigger` scopes; an exec-backed subscription then also needs
   the local worker capability above. Pointer authorization and the active-job
   lookup share the pointer publication transaction. Sync publication does not
   enqueue local jobs, but advancing an actively subscribed pointer still
   requires `sync` + `trigger` in the same atomic Commit transaction. Trigger
   intents freeze their exact job revision and input manifest at pointer
   publication; GC retains those full input closures through pending/running
   execution.

   Runnable jobs are indexed by adapter and enqueue order. A worker scans only
   the adapters it advertises, while queue admission and every trigger path
   share the same 100,000-pending-run transaction limit. This prevents an
   unsupported-adapter backlog from turning capability filtering into an
   unbounded global scan.

4. **`dag serve` has no authentication on loopback, by decision.** A
   non-loopback bind without `--expose-control` is a hard refusal
   (ADR-006), the same fail-closed shape as `dag node serve` without TLS and
   scoped credentials. The
   public listener is `dag content serve`: GET-by-CID, no writes, no
   console. Auth on the human console still belongs to a proxy.

5. **Trust does not travel.** A sync deliberately does not copy the keyring:
   a source must not decide what its replica trusts. Signatures arrive
   *valid*; they become *trusted* only when the receiving machine trusts the
   key itself.

6. **Typed errors end to end.** No `anyhow` in any library crate's public
   API. `CoreError`, `PointerError`, `PinError`, `JobError`, `ControlError`,
   `RunError` — and both binaries *derive* their behaviour from them: the CLI
   maps the causal chain to sysexits (65 data error, 69 unavailable adapter,
   75 timeout, 77 capability not granted…), the API maps the same types to
   HTTP statuses (413 too large, 409 not recovered, 403 withheld, 501 not
   found, 504 timeout). Adding a variant upstream surfaces as a
   non-exhaustive-match warning, not a silent 500.

7. **Blocking work stays off the async runtime.** `dag_control::blocking::
   offload` wraps `block_in_place` (not `spawn_blocking`, whose `'static`
   bound the job runner cannot meet while borrowing `&Control`), with a
   runtime-flavour check so current-thread tests run inline. Fully
   synchronous handlers use `dag_api::blocking::on_blocking_pool`. A
   regression test proves a ticker keeps ticking on a two-worker runtime
   while a job run and a scenario seed are in flight.

## Quality posture

- Unit, integration, doctest and live-CLI coverage run without intentionally
  ignored tests. `#[ignore]` is banned by policy: an ignored test is a test
  nobody runs, and the historical hangs it papered over were real defects
  (fixed by the in-process `TestControl` harness).
- Configured CI runs formatting, workspace/all-target/all-feature Clippy, the
  Rust 1.89 MSRV check, native and browser WASM builds, both npm projects,
  dependency policy/audits, and the runnable end-to-end demo. Rustdoc with
  warnings denied and secret scanning were part of an earlier local matrix,
  not configured CI gates; both must be repeated for the frozen release
  revision. Production Rust contains no `unsafe` blocks; the only current
  blocks serialize process-environment mutation in an `exec` adapter test.
- Security claims have executable regression coverage: capability denial with
  `exec` compiled in, exact leased-run ownership, immutable queued revisions,
  corrupt-chunk repair, atomic publication, authenticated and bounded native
  sessions, backup verification, and edge authentication/quotas.
- Dated review notes in [PRODUCTION_READINESS_REVIEW.md](PRODUCTION_READINESS_REVIEW.md)
  and [REVIEW_BRIEF.md](REVIEW_BRIEF.md) are finding provenance, not current
  status. Residual operational boundaries live in
  [runbooks/operations.md](runbooks/operations.md). A configured CI workflow
  is a repeatable gate, not evidence that a particular commit passed unless
  its run is checked.

Fixed defects are kept as regression tests rather than as a separate ledger:
each one records a case the tests at the time could not see — mocked seams,
feature-unified builds, cached publish artifacts — because the pattern is
worth more than the patch.

## Where it stands today

This is Apache-2.0 preview software, not a validated production release.
There is no project-operated public replica: an Edge Worker is whatever
hostname an operator deploys from `crates/dag-edge`. Configured policy
gates become evidence only after every required input is tracked and the
complete matrix passes on one frozen revision. The publishable crates
carry Apache-2.0 metadata and `rust-version = "1.89"`; a fresh
package/dry-run gate must pass on the final tree before any crates.io
upload. Uploading is deliberately manual:

```bash
cargo publish --workspace   # then tag v0.1.0
```

CI is defined in `.github/workflows/ci.yml` with least-privilege permissions,
pinned actions and toolchains, lockfile-only installs and explicit security
policy gates. Consult the hosting service for the status of a remote run; the
repository alone cannot prove that the workflow is enabled or has succeeded.

---

# The roadmap

Three horizons, from committed to speculative.

## Horizon 1 — finishing moves (small, decided, mostly the user's call)

1. **Finish and retain the release evidence** for this exact tree, including
   the independent security review, local verification matrix and a green
   hosted CI run.
2. **Deploy the reviewed Edge build deliberately**, with production secrets,
   routes and observability checked against the operations runbook; then
   perform the documented live smoke tests. Deployment is separate from code
   review and requires explicit operator authorization.
3. **Publish to crates.io and tag v0.1.0** only after a fresh package/dry-run
   gate. A second `cargo publish --dry-run` against unpublished `0.1.0` crates
   can compile the previous dry-run's cached tarball from `~/.cargo/registry`
   rather than this tree; clear that cache before trusting a dry-run that
   follows a source change.
4. **Backlog items**, unprioritised and not represented as shipped: transparent zstd
   compression (CID computed over *uncompressed* bytes, preserving I1);
   dropping sled and `dag migrate` after a deprecation window. (`events
   tail --since` and event-schema versioning have shipped.)

## Horizon 2 — the wedge (a choice, not a queue)

The application survey ([ALL_USE_CASES.md](ALL_USE_CASES.md)) ranks the
domains; three stand out as wedges, and they imply different next builds.
These are options to choose between, not a list to complete.

**Option A — build and compute caching.** The exec adapter already has the
semantics; what's missing is porcelain and proof. Build: a second worked
example (`dag usecase` -style) showing a real multi-step build memoized
across runs and seeded across machines with `dag sync`; possibly a thin
`dag build` verb or a separate task-runner crate consuming `dag-jobs`.
Longer-term option: Remote Execution API compatibility, which would slot
this store under existing Bazel/Buck2 clients. *Cheapest path to visible
value; proven market.*

**Option B — agent provenance.** Near-zero new core code: the publishable
crates *are* the SDK. Build: a worked example attesting an agent's tool
calls (manifest per action, attestation chain, orchestrator signature); an
LLM-call adapter whose effect key is prompt + model + parameters —
side-effecting, and network-touching, so it belongs behind its own
capability exactly as exec does; optionally an MCP server exposing put /
attest / verify to agent frameworks (the narsil-mcp analysis-caching case is
this shape). *No incumbent; the market is forming now.* The sharpest
concrete instance is the vcot proof-certificate corpus analysed in
[PROOF_ARTIFACTS.md](PROOF_ARTIFACTS.md): dual-checker verdicts as signed
attestations, memoized Lean shard builds, and a measured
incremental-reverification story.

**Option C — legal hold and compliance retention.** Mostly porcelain and
positioning over existing primitives: `hold create|release` verbs mapping
onto pins with the legal vocabulary (matter scope = subtree, schedule =
TTL — note there is no precedence primitive: retention is a union, and the
inert `importance` field was removed in schema 2, so ranked holds would need
a quota mechanism built first); a defensible-disposition report generated from
the GC report and pin history; a document mapping the system onto the
regulatory language (WORM posture, custody chains). *Most exact primitive
fit and most defensible position; slowest market.*

The honest sequencing observation: A and B share almost all machinery, and C
is largely documentation. **B is the launch narrative** — and the
agent-gets-a-computer products (Grok Bot and kin; see
[ECOSYSTEM.md](ECOSYSTEM.md)) made that urgent rather than speculative.
The distribution runtime (Horizon 3) is how B becomes visible: the
ledger leaves the VM, a tab verifies it.

## Horizon 3 — distribution runtime (ADR-006, ADR-007)

The kernel needed a second `ContentStore` and a public content plane,
not Raft.

- **`dag content serve`** — read-only HTTP. GET-by-CID is
  self-authenticating. Non-loopback `dag serve` without
  `--expose-control` is a hard refusal.
- **wasm32 `dag-core`** + `dag-wasm` — a browser re-hashes every byte
  against a content plane. No account.
- **Edge replica** — Cloudflare Worker, `R2Store`, one Durable Object
  per pointer (the ADR-005 serialization point, at the edge).
  Authenticated `HttpDestination` answers the three objections ADR-002
  had to HTTP sync: a token, batch `Missing`, import validation in the
  destination. It requires HTTPS off-loopback and never follows redirects,
  so a bearer token cannot be silently sent over plaintext or replayed to a
  redirected origin.

Still deferred, with the same reasons as ADR-005:

- Multi-writer / CRDT pointers (refuse-divergence is the product)
- Federated GC
- Key distribution (Sigstore vs a key-manifest convention)
- WASM job adapters (the honest sandbox; a new capability, not this pass)
- A laptop following an Edge-primary pointer

## Open questions, with the options as currently understood

| Question | Options | Current lean |
|---|---|---|
| Auth on the human console | (a) stay proxy-only; (b) bearer tokens in `dag serve`; (c) mTLS | (a) — ADR-006 split the public plane off instead |
| The wedge | A build cache / B agent provenance / C legal hold | B; agent VMs made it product-shaped. See ECOSYSTEM.md |
| Compression | zstd at the store layer, CID over uncompressed bytes | Do it; load-bearing the moment chunks leave the laptop |
| IPLD / Source interop | ignore / CIDv1 export of raw SHA-256 | export later if asked; no format change |
| Commercial shape | open core → enterprise (multi-node, RBAC) → managed Edge replica | nothing before v0.1.0 is public |

## What it is deliberately not

Worth restating, because the refusals are design decisions with the same
standing as the features: not an OLTP database (single-writer, hashing on
every write); not a blockchain or consensus system (trust is a local
keyring); not planet-scale distribution (single node plus directory sync);
not tamper-*proof* (an attacker with write access can delete — what they
cannot do is alter content while keeping its CID); and not a sandbox (exec
isolation belongs to containers, and claiming it in-process would be
theatre).
