# Production-readiness review, 2026-07-30

> **Historical snapshot.** This review is retained as finding provenance for
> commit `56134da`. Its readiness verdict and point-in-time gap list are
> not current status. Operational limits that still apply are in
> [runbooks/operations.md](runbooks/operations.md).

An adversarial review across four fronts — durability and scale, security,
operability and embeddability, and the claims in
[ALL_USE_CASES.md](ALL_USE_CASES.md) — against the tree at commit `56134da`.
Every finding below was reproduced against the built binary or the real
library types, or read at the cited line. Nothing is inferred from the docs.

**Verdict as reviewed: not production-ready.**

> **Status, 2026-08-03.** Nearly all of Class A–E below has since been fixed,
> in commits `99f5532`..`17e289b`; the mapping is in
> [What was fixed](#what-was-fixed-and-what-was-not) at the end, along with
> the findings deliberately left alone and the two places where the fix
> changed behaviour rather than restoring it. This document is kept as the
> record of what was found and why — these failure scenarios are the reason
> the tests that now exist look the way they do.

That is not a comment on the design, which is largely sound and in several
places genuinely excellent (see [What holds](#what-holds)). It is a comment
on the gap between a system that is *correct* and a system that is
*deployable*, and the gap is currently wide enough that three separate
defects silently destroy data the operator explicitly asked to keep.

---

## Why the green test suite is not evidence

563 test attributes pass. They cannot reach where the critical defects live,
and the reason is structural rather than accidental:

- **Time.** `grep -rn "set_file_times\|filetime\|utimes\|mtime" crates/`
  returns nothing. No test ever ages a chunk. So neither the 24-hour
  control-log protection gate nor the 60-second minimum chunk age is ever
  exercised — every GC test collects milliseconds after writing, where both
  comparisons are trivially true.
- **Scale.** No test approaches the 10,000-node subtree expansion cap. The
  closest, `a_subtree_pin_retains_a_whole_chunked_file`, uses a 200 KiB file
  — roughly 50 chunks against a cap of 10,000.

This is the same species as ledger defects 13 and 14, where the effect key
covered a timestamp and a sequence number: invisible at the level the tests
were written at. Any fix for the items below must add a time-manipulating
test and a cap-approaching test, or the defect regresses unseen.

---

## Class A — silent destruction of retained data

These need no attacker. They fire during normal operation, under stock
configuration, and every one of them reports success.

### A0. A pointer protects nothing, so the simplest possible workflow loses data

This is the most immediate defect in the system: it needs no aging, no
scale, no concurrency and no attacker. Four commands:

```
$ dag put --data "production config v7: db=prod-01 replicas=3"
4a79cac8...
$ dag pointer create --id deploy/prod/config --cid 4a79cac8...
created deploy/prod/config @1 -> 4a79cac8…fcd2
$ dag gc run --min-age-secs 0
{ "deleted": 1, "bytes_freed": 43, "protected_by_pins": 0, ... }
$ dag pointer resolve --id deploy/prod/config
4a79cac8...                                   # still resolves
$ dag get --cid 4a79cac8... --raw
Error: Chunk not found: 4a79cac8...
```

`RetentionIndex::protected_set` (`crates/dag-control/src/retention.rs:206`)
is built from pins and system-protected CIDs only; GC's test is a bare
`protected_cids.contains(&cid)` (`crates/dag-storage/src/gc.rs:136`). No
pointer head is ever a root. The result is a dangling pointer with no error
and no warning.

Nothing in README or docs states that a pointer protects
nothing. ALL_USE_CASES.md §8 says the integration is "two CLI calls in a
deploy hook"; §5 says "a pointer per dataset name gives current". Both
produce data the next `dag gc run` deletes.

Either make live pointer heads an implicit GC root, or — if pins really are
meant to be the only root — have `pointer create`/`update` warn when the
target is unpinned, and say so wherever a pointer is recommended.

### A1. A subtree pin protects only the first 10,000 nodes

`crates/dag-control/src/retention.rs:359` breaks out of the BFS at
`hard_cap` and returns the truncated set as though it were the whole
subtree. The cap is `DEFAULT_MAX_SUBTREE_EXPANSION = 10_000`
(`crates/dag-control/src/lib.rs:87`). GC then collects everything past it.

Reproduced independently by two reviewers; one measured
`examined=10052 deleted=51 protected_by_pins=10000` against a 10,051-node
graph, destroying 51 leaves of an active pin, and the other lost most of a
19,279-chunk file and got `Chunk not found` on read-back.

At the shipped 1 MiB average chunk size this is any pinned artifact over
roughly 10 GB — and `dag pin create <cid>:full` is exactly what the docs
recommend. It breaks invariant I6 by default.

The alarm exists and is not wired up: `SubtreeExpansionReport`, whose
`limited_by_max_expansion` field is precisely this signal, is declared at
`retention.rs:97` and re-exported at `lib.rs:49` but **constructed
nowhere**. `expand_subtree_static` returns a bare `HashSet`.

### A2. GC deletes the append-only history after 24 hours

`crates/dag-storage/src/gc.rs:201-206` protects control-plane entries only
while `chunk_age < policy.control_logs_min_age`, and `Control` hardcodes
that to 24 hours (`crates/dag-control/src/lib.rs:500`). Nothing pins
pointer or pin events, so they are ordinary collectable chunks.

Reproduced end to end: after aging chunks two days, a default `dag gc run`
reported `deleted 4 … protected 1 by pins / 0 by system`, and afterwards
`pointer resolve` still worked from the cached head while `pointer history`,
`pointer rebuild`, `pin history` and `pin rebuild` all failed with
`Chunk not found`. The control plane looks healthy while its entire history
and its own recovery path are gone; the M6 recovery gate becomes
permanently unsatisfiable.

Two aggravating details. Detection of control-plane data is a heuristic
that CBOR-parses each chunk hunting for field names like `pin_id`
(`gc.rs:215` onward), so durability of the audit log rests on fuzzy
matching. And `SystemDataPolicy::default()` at `gc.rs:53` says 30 days —
a value no caller ever uses, so anyone reading the library to understand
retention reads the wrong number.

### A3. `dag sync pull` can switch off a local pin

`PinLog::import_event` (`crates/dag-control/src/pin.rs:414-468`) refuses to
*replace* an existing `(pin_id, seq)` mapping but happily *appends* a new
one, and its own doc comment concedes "Pin events carry no `prev`, so there
is no chain to check." A remote can therefore file a Deactivate at seq 2
against your local pin; `rebuild` takes max-seq as head, and the pin reads
Deactivated with the sync reporting zero failures and exit 0. The same
`transfer` then sets the recovery flags, arming GC to act on it.

`PointerLog::import_event` defends against exactly this with four gates and
has a test for it. Pins — the retention primitive the entire legal-hold
case rests on — have no equivalent.

### A4. GC concurrent with a large put deletes the chunks mid-write

`crates/dag-core/src/file.rs:262-312` writes N chunks then the manifest,
never re-verifying; the chunks are unreferenced and unpinned throughout.
Reproduced: `split` returned `Ok` with a 38,606-chunk root that could not
be read back. The `min_chunk_age` default of 60 s only covers puts that
finish inside a minute, and `POST /api/gc/run` accepts `min_age_secs: 0`
unauthenticated. The dedup path is worse — `file.rs:271` skips `put_chunk`
when the chunk already exists, so reused chunks keep their old mtime and
have no age protection at all.

### A5. Nothing is ever fsynced, and the ordering is inverted

`grep -rn "sync_all\|sync_data\|fsync" crates/` returns nothing.
`crates/dag-storage/src/fs_store.rs:246-254` writes to a temp file and
renames, with no `sync_all` and no parent-directory fsync. Meanwhile redb
commits with `Immediate` durability. So `put_chunk` produces a
non-durable file and a durable index entry; `PointerLog::create` produces a
non-durable event entry and a durable log entry. After power loss you get
exactly the state A2 produces, arrived at by crash instead of by policy.
`delete_chunk` has the same inversion in reverse, leaving stale index
entries nothing repairs.

---

## Class B — there is no recovery story

### B1. `dag index verify` validates the wrong directory

`ChunkLocation.path` is an **absolute** path (`index.rs:18`, written at
`fs_store.rs:136`), and `crates/dag-storage/src/integrity.rs:57` does
`fs::read(&location.path)` rather than deriving the path from the store's
own `data_dir`. Both failure directions were measured on a `cp -R` copy:
with the original still present the copy was declared `20/20 chunks valid`
while the scanner re-hashed the *original's* files; with the original moved
away, a byte-perfect copy was declared 100% corrupt.

So the only whole-directory checker in the system gives a green light to an
unverified restore and condemns a good backup. `chunk_path()` derives the
path correctly and every read path uses it — integrity is the sole outlier,
and the fix is one line.

Compounding it, `IndexCmd::Verify` (`crates/dag-cli/src/commands/content.rs:274-307`)
emits its report and returns `Ok(())` unconditionally, so the command can
never fail a cron check no matter how many chunks are invalid.

### B2. `control.redb` is an unrecoverable single point of failure

Delete it, keep `data/` intact, and every documented recovery command
recovers nothing: `pointer rebuild` → 0 pointers, `pin rebuild` → 0 pins,
`status` → "recovered yes", `usecase verify` → pointer not found.

The cause is an asymmetry the codebase already knows how to avoid.
`PointerLog::rebuild_from_events` (`pointer.rs:645`), `PinLog::rebuild`
(`pin.rs:498`) and `JobLog::rebuild` (`job.rs:570`) rebuild heads by
iterating the redb **events table**; they need that table to know which
CIDs the events are. `SignatureLog::rebuild` (`signatures.rs:409`) and
`Control::rebuild_effect_claims` (`lib.rs:392`) do it properly, by
`store.list_all_cids()`. The three load-bearing logs are the three that
cannot recover from primary data.

This also means `control.redb` is *primary* state, not derived — which
makes the absence of any backup procedure in README or docs a gap rather
than an omission. `grep -rn -i "backup\|restore\|snapshot\|fsck" README.md docs/`
finds only a `sync push --remote /Volumes/backup/dag` example.

### B3. A truncated `control.redb` panics

Truncating the file to half its length produces a Rust panic inside redb's
page manager with exit 101 — a code the CLI's own sysexits table does not
define. A half-written database is the expected artifact of an interrupted
copy, a full disk, or a killed process. (Garbage over the header, by
contrast, is handled cleanly.)

### B4. There is no schema version anywhere

Not in `control.redb`, not in `Entry`, not in key files. All 16 redb tables
are `TableDefinition<&[u8], &[u8]>`, so redb's own type check can never
fire. `PointerEvent`, `PinEvent` and `JobEvent` carry no `#[serde(default)]`,
and nine stored enums are bare derives — so adding a required field or a
variant is a permanent break on immutable content-addressed entries that
(per B2) have no rebuild path. An interrupted `dag migrate` is a dead end:
re-running refuses while `Control::open` succeeds, serving truncated
history.

---

## Class C — attack surface

`dag serve` has no authentication by decision, which is defensible for a
loopback tool. The problem is what sits behind that decision.

- **Permissive CORS plus no auth** (`crates/dag-api/src/lib.rs:126`,
  applied to the whole router). Demonstrated live from a foreign origin:
  preflight approved, a production pointer repointed, and the response read
  back. With no authentication, CORS is the only remaining control, and
  `*` upgrades blind CSRF into full read-write API access — including
  `POST /api/gc/run`.
- **Stored XSS on the console's own origin** — `routes/files.rs:143-149`
  echoes the uploader's `Content-Type` verbatim, so a stored `<script>`
  serves as `text/html`. No CSP, no `X-Content-Type-Options`, no
  `X-Frame-Options` anywhere.
- **Remote process abort** — `crates/dag-core/src/file.rs:471` recurses once
  per declared indirection level with no ceiling, `depth` being a `u32` read
  from an attacker-authored payload. 30,000 levels costs under 4 MB and
  aborts the process. A Rust stack overflow is not catchable, so no amount
  of task isolation helps.
- **Small-order key forgery** — `crates/dag-core/src/signing.rs:190` uses
  non-strict `verify` and never calls `is_weak()`. 5 of 8 small-order keys
  accepted a forged signature over an arbitrary statement. `verify_strict`
  rejects all of them; two one-line fixes.
- **`--min-trusted N` counts signatures, not distinct keys**
  (`crates/dag-cli/src/commands/sign.rs:63`). One key signing twice with
  different notes satisfies `--min-trusted 2`. The doc comment three lines
  above states the guarantee it fails to provide — and that guarantee,
  two independent checkers held to agreement, is the whole point of the
  vdw33 attestation work.
- **Adoption has no domain separation** — any signature by an adopt-trusted
  key over the claim CID authorizes adoption; `_type`/`payloadType` are
  never checked.
- **No `[profile.release]` in the workspace manifest**, so release builds
  have overflow checks off. The unvalidated `now_unix() + ttl` at
  `routes/pins.rs:133` therefore wraps silently in release rather than
  panicking: the API returns 200, the pin reports Active, and GC reports it
  unprotected.

---

## Class D — the wedge does not currently hold

[ALL_USE_CASES.md](ALL_USE_CASES.md) ranks build and compute caching first,
as "the use case where 'the SQLite of DAGs' is decisive rather than
incidental". Three findings bear directly on that.

**D1. Single-writer versus the analogy.** SQLite's defining operational
property is multi-process concurrency — file locking with `busy_timeout` and
retry. redb is single-handle exclusive. Eight concurrent `dag put` against
one directory: **seven failed**, with `Database already open. Cannot acquire
lock.` and exit 70, which `main.rs:325` defines as "an internal error: a bug,
or a corrupt database". There is no lock-wait, no `--lock-timeout`, no
backoff, and README never mentions the constraint. A build tool is precisely
the workload that exposes it, and each invocation also pays ~113 ms of
database open/close. The one process-sharing mechanism that exists,
`dag serve`, is deliberately barred from the exec adapter.

**D2. Third-party adapters cannot record provenance.** `execute_once`,
`execute_once_with` and `execute_once_hooked` all construct their runner
internally with a hardcoded adapter set (`crates/dag-jobs/src/execution.rs:59-93`);
there is no injection point. The escape hatch — `JobRunner::new` plus
`register_adapter` — produces correct output but records no `JobRun`, no
manifest and no status. So the users the doc targets, people building a
hermetic task runner, get either provenance or their own adapters, never
both. The fix is small: let `execute_once_hooked` take a caller-supplied
runner.

**D3. A phantom feature costing an unmaintained dependency.**
`crates/dag-cli/Cargo.toml:23` hard-enables `dag-jobs` features
`["fetch", "exec"]`. No source file anywhere references `feature = "fetch"`,
yet it pulls `reqwest 0.11.27` into both the CLI and the API, dragging in
unmaintained `rustls-pemfile 1.0.4` (RUSTSEC-2025-0134). That advisory is
the *only* reason the last CI run (26 July) failed — every other job passed.
Deleting a feature nobody uses probably turns CI green.

It also makes the then-current "Cargo feature `exec`, off by default" claim
true of the library and false of the shipped binary. The capability gate is
still the real boundary, and it **holds** — verified with
the feature on: the CLI executes with `--allow-exec`, the identical job over
HTTP returns 403.

---

## Class E — operability

- **The event journal grows without bound, and compaction makes the file
  bigger.** Measured: 600 events → 1,011,712 bytes; after compacting to keep
  100 → 6,574,080 bytes, 6.5× larger. `redb::Database::compact()` is called
  nowhere in the workspace. `dag serve` never schedules compaction, and the
  periodic integrity scan writes a `StorageHealth` row every 15 minutes, so
  the file holding all the primary logs grows monotonically forever.
- **"What happened last Tuesday" is not answerable.** Only `--since-seq`
  exists, replay materialises every row from the cursor before the caller
  trims, and front-truncation is invisible — `EventBus::earliest_seq()` is
  public and never consulted, so a request for full history returns a
  partial answer that looks complete.
- **The SSE stream drops lagged events silently.** `routes/events.rs:109`
  turns `Lagged(n)` into `None` via `.ok()?`. The CLI path handles the same
  condition correctly and prints `# lagged, missed n events`. The doc
  comment claims the gap is visible as a sequence jump, which is false
  whenever a filter is active — and the web console always filters.
- **No metrics at all**, and logs use the human formatter with ANSI escapes
  and no `--log-format`. `GET /api/stats` is the nearest substitute and is
  genuinely good; it would adapt into a Prometheus exposition cheaply.
- **The SPA fallback returns HTTP 200 and console HTML for every unmatched
  path**, including `/health` and `/healthz` — the default probe paths for
  Kubernetes, ALB and Consul. A liveness probe configured against them can
  never fail.
- **`gc run` reports counts, not contents.** `GcReport`
  (`crates/dag-core/src/traits.rs:46-57`) carries `chunks_deleted` and
  `bytes_freed` but no list of collected CIDs. ALL_USE_CASES.md §4 claims
  "the GC report names what was collected and why it was free" as the
  defensible-disposition row; it does not, and since GC deletes the bytes,
  the record is gone for good.
- **Pin `importance` is inert.** 58 mentions across the tree, all plumbing
  and display; nothing makes a decision on it. The CLI help says "higher
  wins when quotas force a choice", and there are no quotas. §4's
  "hold precedence over retention schedules → pin importance" row is
  aspirational.
- **Exit codes mislead on three routine conditions.** Database locked,
  missing signing key and divergent sync all report 70 ("a bug"). The
  locked case should be 75 (`TEMPFAIL`, which already exists and is already
  used for job timeouts); `redb::DatabaseError::DatabaseAlreadyOpen` is
  flattened into a `String` at `lib.rs:216`, so embedders cannot match on it
  either. Corrupt content on disk is reported as `Invalid CID format`, which
  sends the operator to check their CID rather than their storage.
- **The then-current non-exhaustive-match claim is false.** Both `ControlError`
  and `RunError` are `#[non_exhaustive]`, which *forces* downstream wildcard
  arms — and `main.rs:375` and `main.rs:392` both have one. A new variant
  becomes exit 70 silently, with no warning. The two claimed properties are
  mutually exclusive.

---

## The use cases, graded

Each claim in [ALL_USE_CASES.md](ALL_USE_CASES.md) was traced to the code
that would deliver it and, where feasible, run end to end.

| § | Use case | Grade |
|---|---|---|
| 1 | Model-release provenance | **Partial** |
| 2 | Build and compute caching | **Partial** |
| 3 | AI agent provenance | **Aspirational** |
| 4 | Legal hold / chain of custody | **Aspirational** |
| 5 | Data and ML lineage | **Partial** (the dedup claim itself is delivered) |
| 6 | Air-gapped and field operation | **Delivered**, two papercuts |
| 7 | Software supply chain | **Partial** |
| 8 | Deployment forensics | **Aspirational** |

**§1 model release.** The flagship works: `dag usecase seed && dag usecase
verify` reproduces the documented output byte for byte, and tampering a leaf
gives `6 of 7` and exit 65. Three unstated caveats. Tampering an *interior*
node truncates the walk, so the report silently drops the subtree beneath it
and reports `3 of 4` — failure is still detected, but an auditor comparing
runs must know the expected node count out of band. You cannot verify a
historical release: `scenario::verify` resolves the current head only, and
`usecase verify` takes `--pointer` and nothing else, so the regulator's
actual question has no command. And the hand-it-to-a-regulator story stops
one step short — content verifies self-contained at a synced replica
(`7 of 7`, exit 0), but signatures degrade to `valid, UNTRUSTED key` with no
signer name, because the key and its owner's identity do not travel. §6's
"verification needs no network at any point" is true for bytes and false for
*who*.

**§2 build caching.** The action cache is real; verified with an observable
side effect (a command writing a nanosecond timestamp, three run requests,
one invocation, identical output CID). What "cargo add, not infrastructure"
does not include, and the doc does not say: no task graph — `Scheduler`
exposes only `resolve_inputs` and `trigger_jobs_for_pointer`, with no
job→job dependency and no topological order. The 339-module Lean result the
doc cites is powered by 355 lines of *experiment* code (`parse_imports`,
`closures`, `levels` in `docs/experiments/vdw33-build-cache/main.rs`) that
an adopter must rewrite, and that is the majority of what a build tool is.
Also no parallelism (see D1), no file watching, and the exec `JobSpec` /
`ExecConfig` schema is documented only in a rustdoc comment — with
externally-tagged enum JSON (`"cache_outputs": {"Pin": {...}}`) that is
undiscoverable without reading the source. This is a correct action cache,
roughly Bazel's CAS+AC layer. It is not yet a build tool.

**§3 agent provenance — the weakest section.** `grep -rni
"agent\|llm\|prompt\|openai\|anthropic" crates/*/src/` returns zero hits.
"Agent memory as a DAG" is backed by no code, and "effect-cached LLM calls"
has no substrate because there is no HTTP adapter of any kind — the `fetch`
feature compiles in `reqwest` that nothing references (see D3). Worse,
`fake_fetch` is registered in the default runner with hardcoded
`b"fake data"`, advertised by `dag job adapters`, and shipped as
`examples/job.fetch-url.json` under the name "fetch-homepage": a job using
it silently produces the string `fake data` regardless of any URL. The
generic claim — an agent run has the shape of a release — is fair, and
`AttestAdapter` does link every resolved input. But "the attest adapter
needs almost nothing new" describes the easy half, and
`docs/SYSTEM_OVERVIEW.md` is more honest, listing the LLM adapter as a thing
to build.

**§4 legal hold — the mapping table is the least accurate thing in the
document.** Of its seven rows, three are false and one is inert. "Hold over
everything a matter touches" is false beyond 10,000 nodes (A1); an operator
sees `pin info` reporting Active, `gc status` on the root reporting
PROTECTED, and 501 chunks inside the hold queued for deletion. "Record that
the hold existed" is false once the events age out (A2) — `pin history`
errors out entirely. "Disposition cannot destroy held material" is false via
A0, A1 and A2. "Hold precedence via pin importance" is an inert field: it
never enters any decision, surviving only as display in `gc status`, and the
CLI help promises "higher wins when quotas force a choice" when there are no
quotas anywhere. "Defensible disposition — the GC report names what was
collected and why it was free" is false: `GcReport`
(`crates/dag-core/src/traits.rs:46-57`) is eight counters and an error list,
with no CID list and no per-chunk reason. The loop at `gc.rs:158-169`
already has both values in hand.

**§5 lineage.** The dedup claim is exactly right, measured on a 38 MB CSV:
34 chunks for v1; changing one row in the middle costs **1** new chunk;
appending a row costs **2**. Three revisions of a 38 MB file occupy 39 MB.
The caveats: a dataset at or above ~11 GB silently under-protects under a
subtree pin (A1) against a doc whose headline example is 10 GB; the pointer
holding "current" protects nothing (A0); there is no `dag cat`, so piping a
revision into a notebook needs a temp file; and **entry payloads cost ~1.9×
on disk** because `Entry.payload` is a plain `Vec<u8>`
(`crates/dag-core/src/entry.rs:14`) with no `serde_bytes`, so ciborium
encodes it as a CBOR array of integers. A 1 MiB payload occupies 1,998,693
bytes, which makes the real limit for `put-entry` about **2.09 MiB, not
4 MiB** — and the resulting error names a size the user never supplied.
Fixing it changes every entry CID, so it is a pre-1.0 decision that should
be made now.

**§6 air-gapped — delivered.** Resume is genuinely real: deleting 5,000 of
10,502 chunks from a replica and re-running sent exactly the missing set
(`chunks_sent: 5000, chunks_skipped: 5502, failures: []`) with no journal
and no resume token. Trust correctly does not travel. Papercuts: the remote
directory must be created by hand first, and there is no "is this replica
complete?" check for a pin-rooted hold — an interrupted sync leaves an index
containing only what arrived, so `index verify` reports 100% valid on an
incomplete replica (and see B1, which makes it worse).

**§7 supply chain.** The crypto is right: PAE is golden-tested against the
DSSE spec example and the statement shape matches in-toto v1. But "the
format existing supply-chain verifiers consume" is not consumable today.
There is **no export path** — the envelope is buried in a CBOR entry, `dag
get --raw` returns raw CBOR, and `GET /api/signatures` returns verdicts
without the envelope. The rustdoc calls the envelope "extractable for
external tooling"; nothing extracts it. A `dag signature show --cid --json`
printing the envelope verbatim is roughly 20 lines and converts §7 from a
claim into a demo. Separately, `predicateType` is hardcoded to the project's
own URI (`signing.rs:105`), so you cannot emit SLSA Provenance — and
`predicateType` is exactly what external verifiers dispatch on.

**§8 deployment forensics.** "Reconstructing the exact deployed state at
time T becomes a resolve at a sequence number" — there is no such command.
`pointer resolve` takes `--id` and nothing else; `pointer history --from
--to` plus `jq` is the actual path. No timestamp lookup, no multi-pointer
"state as of T", no way to verify a historical root. And "integration cost
is nearly zero: two CLI calls in a deploy hook" is wrong given A0 — two
calls buy a flight recorder the next GC erases. The HTTP API also cannot
*write* pointers (`crates/dag-api/src/lib.rs:94-95` exposes resolve and
history only), so deploy hooks must shell out to the CLI, one process per
call, against the single-handle lock. `dag pointer resolve --id P [--at-seq
N | --as-of <ISO8601>]` is porcelain over a range scan that already exists,
and it is the single change that turns §8 from a story into a feature.

### On "Where it does not fit"

The four entries listed are all true, but the section omits every limit an
adopter hits on day one: single-process-per-directory; pins as the only
retention root; the 10,000-node subtree ceiling; the 24-hour control-plane
retention floor; the ~2.09 MiB effective entry payload limit; and no pointer
writes over HTTP. The "erasure as a strength" framing is also the one I'd
challenge — erasure works, but the same mechanism is what makes A0, A1 and
A2 destructive, and presenting collectability purely as a compliance
strength in a document that elsewhere promises "will the evidence still be
there" is arguing both sides.

### On the wedge ranking

Keep build caching at #1 — it is the only ranked use case whose core
mechanism verifies working end to end today, and crucially the one *least*
damaged by A0/A1/A2: a build cache's outputs are ephemeral by nature, and
cache entries are small enough not to reach the expansion cap. Its gap is a
missing task-graph layer, which is additive work in a new crate rather than
a fix to existing semantics.

Swap the other two. Legal hold needs three bug fixes and one report
enrichment, all small and all things worth doing anyway; agent provenance
needs an HTTP adapter, a memory model and a framework integration, none of
which exist as a line of code. "Near-zero new code" is the least accurate
sentence in the document, and it is load-bearing for the current ranking.
The market-timing argument for agent provenance is real and worth making —
but on market terms, not on a false claim about implementation cost.

One note on the thesis itself. "The proof must be checkable without access
to your systems" is the right frame, and the replica test passes it for
content. The trust half does not travel: a third party gets `valid,
UNTRUSTED key` with no signer name and no way to learn who a key ID belongs
to. Until there is a key-distribution story — even just "publish your
fingerprint on your website" — every use case stops one step short of the
promise in its own thesis.

---

## What holds

Worth stating plainly, because it calibrates everything above and several of
these are better than the norm:

- **Pointer sequence integrity under concurrency is genuinely sound.** Every
  path was traced for a duplicate or skipped `seq`; the per-log mutex really
  does cover the read-head → put-event → commit window, and the 16-thread
  test is real rather than decorative.
- **`PointerLog::import_event`'s four validation gates all hold** — no way
  to graft an event onto another pointer, file out of order, overwrite
  divergent history, or file an event whose chunk is absent.
- **Content addressing catches corruption on read, always** — `get_chunk`
  re-hashes, and `file::join` re-hashes every node including parts. A hostile
  remote cannot substitute bytes under a CID, including through a symlink.
- **The exec capability gate is the boundary the capability-gate docs say it is**, proven
  with the feature compiled in.
- **The library crates' dependency footprint is clean**: no axum, hyper,
  tower, openssl or sled in any of dag-core/storage/control/jobs, and
  `anyhow` really is confined to `test-utils`. `Control::open` → job →
  results works from a third-party crate with no `test-utils`, and `Control`
  drove correctly from four threads.
- **`skip_serializing_if` on optional `Entry`/`MetaHint` fields makes
  optional-field addition CID-preserving** — verified byte-identical. That
  is the single most important compatibility property in the system, and it
  holds today, untested and undocumented.
- **`TrustedKey.purposes` (ADR-004) is a textbook schema migration** —
  `serde(default)`, documented legacy semantics, inert unknown values,
  deliberate non-grandfathering. It is the template the rest of the on-disk
  format needs.
- **Eager table creation in every constructor** means new-binary-on-old-database
  already works by construction; it silently carried the ADR-003 and ADR-004
  table additions.
- **The withheld-adapter message is exemplary** — it names the adapter, why
  it was withheld, that the API never grants it, and the exact CLI flag. It
  is the standard the rest of the error surface should meet, as are the
  not-recovered, legacy-directory and divergent-sync messages.
- **The defect-5 fix is real**: `run_gc` refreshing retention before
  collecting genuinely closes the cache-TTL window, with a real regression
  test.
- **CID length validation holds end to end** — traversal, short and non-hex
  inputs all clean 400s.

---

## Suggested order of work

Sequenced by risk removed per unit of effort, not by severity alone.

**Before anything else — stop the bleeding (each is small):**

1. A0: decide whether a live pointer head is a GC root. If yes, add heads to
   `protected_set`. If no, warn on `pointer create`/`update` against an
   unpinned target and correct §5, §8 and the USE_CASE narrative. Either
   way, four commands should not silently lose data.
2. A1: return and honour `SubtreeExpansionReport`; refuse to *create* a pin
   whose subtree exceeds the cap rather than silently truncating, and make
   GC treat a truncated retention snapshot as "retain everything".
3. A2: make pointer/pin/job event entries unconditionally protected, not
   age-gated. Retention of the audit log should not be a heuristic with a
   timer.
4. B1: use `chunk_path()` at `integrity.rs:57`; exit non-zero when
   `invalid_chunks > 0`.
5. C: `verify_strict` plus `is_weak()`; count distinct keys in
   `--min-trusted`; validate the TTL addition; add `[profile.release]` with
   `overflow-checks = true`.
6. D3: delete the `fetch` feature. While there, either remove `fake_fetch`
   from the default runner or rename it and the shipped
   `examples/job.fetch-url.json` so nothing advertises a fetcher that
   returns the literal string `fake data`.

**Then — make it recoverable:**

6. B2: give pointer, pin and job logs a store-scan rebuild, the way
   signatures and effect claims already have. This converts `control.redb`
   from primary state into derived state, which is what the docs already
   claim it is.
7. A5: fsync the chunk file before rename and the parent directory after;
   order the index insert after the durable write.
8. A3: give pin import the same divergence refusal pointers have.
9. B4: add a `schema` table with a version, checked in `Control::open`.

**Then — make it operable:**

10. `ControlError::DatabaseLocked` → exit 75, plus `--lock-timeout` with
    backoff. This is also the minimum for D1.
11. Journal retention that actually shrinks the file; consult
    `earliest_seq` in both replay paths; emit a gap marker on SSE `Lagged`.
12. Itemise `GcReport` (collected CIDs and the reason each was free) — this
    is what makes §4 defensible disposition true rather than aspirational.
13. A real `/health` outside the SPA fallback; `/metrics`; `--log-format json`.

**Cheap features that convert an aspirational claim into a demo.** Each is
small, and each is the single thing standing between a use case and its
promise:

14. `dag pointer resolve --id P --at-seq N | --as-of <ISO8601>` — porcelain
    over an existing range scan. Turns §8 into a feature.
15. `dag signature show --cid <sig> --json` printing the DSSE envelope
    verbatim, plus a `--predicate-type` flag. ~20 lines and a plumbing
    change; turns §7 into something cosign can consume.
16. `dag usecase verify --cid <root>`, so a historical release can be
    verified at all, and report unreachable children as *unverified* rather
    than omitting them from the denominator.
17. Decide on `#[serde(with = "serde_bytes")]` for `Entry.payload`. It
    recovers ~1.9× on entry storage and makes the documented 4 MiB limit
    true — but it changes every entry CID, so it is now or never.

**Then — reopen the positioning question.** D1 is not a bug so much as a
mismatch between the storage engine and the analogy used to sell it. Either
add lock-wait and retry so concurrent invocations queue rather than fail,
or move the wedge to a use case where one writer is natural (legal hold and
release provenance both are), or state the constraint next to the claim.
Choosing deliberately is the point; the current docs choose implicitly, in
favour of the one workload that breaks it.

---

## Documentation corrections needed regardless

- The then-current "Cargo feature `exec`, off by default" claim — true of
  the library, false of the shipped binary.
- The then-current non-exhaustive-match claim — contradicted by
  `#[non_exhaustive]` plus the wildcard arms it forces.
- The then-current "Max Chunk Size: 4 MiB per CID (hard limit)" claim —
  true for chunks, ~2.09 MiB for entry payloads.
- ALL_USE_CASES.md §4 — the GC report does not name what it collected, and
  pin importance is not consulted by anything.
- ALL_USE_CASES.md §3 — "the attest adapter needs almost nothing new"
  understates by an adapter, a memory model and an integration surface.
- README — the one-process-per-directory constraint is documented in
  ADR-002, and was not where an operator would look. Nor is the
  fact that a pointer is not a retention root.
- The "Remaining Priorities → Priority 1: publish" framing should not stand
  while Class A is open.

---

## What was fixed, and what was not

All of it landed between `99f5532` and `17e289b`. The table maps findings to
commits; the two entries below it are the deliberate exceptions.

| Finding | Commit |
|---|---|
| A0 pointer is not a retention root; A1 silent expansion truncation; A2 history collectable after a day; E1 report is only counters | `763cb37` |
| C small-order key forgery; `--min-trusted` counts signatures | `99f5532` |
| D3 phantom `fetch` feature and its unmaintained dependency; `fake_fetch` advertised as real | `738b1c5` |
| Locked directory reported as an internal error (exit 70) | `153c0bd` |
| B1 `index verify` validates the wrong directory and cannot fail | `fd99c07` |
| A5 nothing fsynced; durability ordering inverted | `75e6497` |
| C CORS, stored XSS, unbounded manifest recursion, TTL overflow, missing release profile | `9440424` |
| B2 `control.redb` unrecoverable; A3 sync can deactivate a local pin | `42eb5ba` |
| §7 DSSE envelopes unreachable; `predicateType` hardcoded | `a43d559` |
| §8 no resolve-at-a-sequence; §1 no historical verify | `725d095` |
| Bulk ingest latency-bound after the durability fix | `9d91441` |
| E2 journal unbounded, compaction grew the file, SSE dropped events silently | `17e289b` |
| A4 collection racing a concurrent ingest | `b277995` |
| B4 no on-disk schema version; truncated control.redb panicked | `HEAD` |

One defect was found *by* the fixes rather than by the review: the web
console's live feed had never worked. It registered `source.onmessage`,
while the server names every SSE message after its kind, and a named message
is never dispatched to `onmessage`. Nothing in the review caught it because
the review tested the API, not the browser.

### Accepted, not fixed

**Pin importance remains inert.** It is stored, reported by `gc status`, and
consulted by nothing, because there is no quota mechanism for it to arbitrate.
Implementing quota-driven eviction is a feature, not a bug fix, and inventing
one to justify an existing field would be the wrong order. The `§4` mapping
table and the CLI help no longer claim otherwise.

**One process per data directory stands.** redb locks the database file.
`--lock-timeout` turns the collision into a queue and the exit code now says
"transient" rather than "bug", but genuine write parallelism against one
directory is not what this is. That is now stated in `ALL_USE_CASES.md` next
to the build-caching claim, which is the use case most likely to want it.

### Two things the fixes changed rather than restored

**A pointer's superseded versions are still collectable.** Making live heads
retention roots fixes the dangling-name defect, but only for the *current*
head; the history entry naming an older CID is permanent while its bytes are
not. That is deliberate — protecting every version a pointer ever had would
mean nothing is ever collectable — so `pointer resolve --at-seq` reports
`content_present`, and `§8` now says a flight recorder is three calls (put,
update, pin), not two.

**`dag put --fast` is opt-in.** Batched durability roughly doubles ingest, but
deduplication tests a chunk's presence rather than its hash, so a crash
mid-ingest can leave a short file that a later run adopts. The default stays
durable, where the fsync precedes the rename and the hazard cannot arise.
