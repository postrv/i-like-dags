# Review brief: the 2026-08 hardening pass

> **Historical review input.** This brief describes the scope reviewers were
> asked to attack at that checkpoint; it is not a current readiness result.
> Residual operational boundaries that still apply are in
> [runbooks/operations.md](runbooks/operations.md).

You are reviewing sixteen commits (`56134da..f025b2e`, 87 files, ~10.5k lines
added) that responded to
[PRODUCTION_READINESS_REVIEW.md](PRODUCTION_READINESS_REVIEW.md). That
document lists the original findings and maps each to the commit that closed
it; read it first, because this brief assumes it.

The work was done fast, in parallel, by several contributors who could not
see each other's trees. Treat that as the prior: the individual fixes were
each tested, but the *interactions* between them had far less scrutiny than
the fixes themselves. Where I would look hardest is listed below.

**Please try to break this rather than confirm it.** Findings that say "this
is fine" are much less useful than one reproducible failure. Assume every
claim below is a claim, not a fact, including the ones about test coverage.

---

## Orientation

Six crates, strict one-way dependency: `cli → api → jobs → control → storage
→ core`. `Control::open(dir)` is the single entry point and owns one on-disk
layout: `<data_dir>/data/` for chunk bytes, `<data_dir>/control.redb` for the
chunk index, the append-only pointer/pin/job logs, the event journal, the
signature index and the recovery flags.

```bash
cargo test --workspace --all-features        # 483 tests, expect 0 failures
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The suite is now I/O bound rather than CPU bound, because chunk writes fsync.
If it seems slow, that is why, and it is worth confirming rather than
assuming.

A quick end-to-end sanity path, which should stay true after anything you do:

```bash
dag --data-dir /tmp/x usecase seed
dag --data-dir /tmp/x usecase verify              # 7 of 7 nodes intact
dag --data-dir /tmp/x recover --max-objects 100000 --max-bytes 1073741824
dag --data-dir /tmp/x gc run --min-age-secs 0
dag --data-dir /tmp/x usecase verify              # still 7 of 7
```

---

## What changed, and the seam I would push on in each

### 1. Retention became much broader (`763cb37`, `b277995`)

Collection now treats as roots: pins, **the transitive closure of every live
pointer head**, the control plane's own event entries (enumerated exactly
from the logs), and chunks this process wrote within the caller's minimum-age
window.

The interesting question is whether it is now *too* broad — whether anything
is unreachable by collection that should not be. A store that only ever grows
is its own kind of failure, and none of the new tests assert an upper bound on
what survives. Specifically worth attacking:

- Pointer-head closure is computed per pointer with no memoisation across
  pointers. What does that cost with 10,000 pointers over a shared graph?
- The in-flight write registry (`FsStore::recent_writes`) is an in-memory
  `HashMap<Cid, Instant>` pruned only when read. A long-lived `dag serve` that
  writes constantly and collects rarely — does it bound?
- `run_gc` refuses entirely when any pin's expansion hits the ceiling. One
  oversized pin therefore blocks collection for the whole directory. Is that
  the right failure mode, or should it collect what it can prove is free?

### 2. Durability and its opt-out (`75e6497`, `9d91441`)

Writes are now: temp file → fsync → rename → fsync parent → index insert.
Deletion clears the index entry first. `DurabilityPolicy::Deferred` batches
the fsyncs *and* the index inserts, exposed as `Control::bulk_ingest` and
`dag put --fast`.

- The ordering claim is the whole point. Verify it independently rather than
  trusting `crates/dag-storage/tests/durability.rs` — that test asserts the
  ordering it was written alongside.
- `--fast` has a documented hazard: `split` deduplicates on a chunk's
  *presence*, not its hash, so a crash mid-ingest can leave a short file a
  later run adopts. Is the hazard actually confined to `--fast`, or can the
  durable path reach it too?
- `Deferred` self-flushes at 1024 pending chunks. What happens on the
  threshold boundary, and on a panic between threshold and flush?

### 3. The logs became recoverable, and pin history gained a chain (`42eb5ba`)

The explicit offline `dag recover --max-objects … --max-bytes …` protocol scans
a preflight-bounded content inventory and reconstructs pointer, pin and job
logs, the chunk index, and the signature/effect-claim indexes. Its durable
in-progress marker keeps GC closed across every later failure or restart. The
default path refuses strict-decoding pointer/pin/job records that exist in the
store but are absent from the filed tables. Recovering a lost/truncated database
therefore requires an explicit, offline
`--trust-unfiled-control-events` decision after verifying store-writer
provenance. Partial log rebuild commands default to filed tables; their store
scans require `--from-store --trust-unfiled-control-events`, default to the same
100,000-object/1 GiB preflight, and expose `--max-objects`/`--max-bytes` only for
that explicit scan (`0` is the offline unbounded opt-out). They do not complete
the full gate.

`PinEvent` gained `prev: Option<Cid>`; import requires contiguity and, for
seq > 1, a `prev` naming the event already filed at N−1.

- Event entries are identified by strict CBOR decode into the event struct.
  Confirm the default recovery refuses any unfiled candidate before adoption,
  and that the explicit trust flag cannot bypass chain/fork validation or select
  only convenient candidates.
- Recovery reconciles a partially populated table against the same bounded
  store inventory rather than triggering only on a zero count. Check that a
  forged or divergent candidate fails closed without replacing a filed event.
- The `prev` addition is claimed CID-preserving via `skip_serializing_if`,
  with a golden test. Check the golden value is genuinely a pre-change
  capture and not a value regenerated after the fact.
- Pre-`prev` deactivations cannot replicate, by design. Confirm the failure is
  the safe direction (destination over-retains) and is reported, not silent.

### 4. The HTTP surface (`9440424`)

No CORS layer by default; an opt-in `--allow-origin` allow-list; a
`Sec-Fetch-Site` check on browser-facing mutations including `/api/gc/run`; an
inert content-type allow-list plus `Content-Disposition: attachment`; baseline
security headers with a CSP; a depth ceiling of 64 on `file/v1` recursion;
checked TTL arithmetic; `[profile.release] overflow-checks = true`. Recovery is
offline-only and has no HTTP route. HTTP GC is finite, cannot disable system
protection, and is safe to expose only behind the documented authentication/TLS
perimeter.

- `Sec-Fetch-Site` is browser-set and unforgeable by page script, which is the
  argument for relying on it. Is that true of every browser the console
  supports, and what happens on one that omits the header?
- The CSP was written against what `assets.rs` actually serves. Load the
  console and check the browser console is clean — a CSP that breaks the app
  will be turned off by the next person, which is worse than none.
- The depth ceiling is derived from what the loosest permitted
  `ChunkerConfig` needs. Re-derive it; if the derivation is wrong, either
  legitimate manifests break or the ceiling does not bind.
- `dag serve` still has **no authentication**, deliberately. Everything above
  narrows what can reach it; none of it makes the API safe to expose.

### 5. Signing (`99f5532`, `a43d559`)

`verify_strict` plus `is_weak()` rejection at key-parse time; `--min-trusted`
counts distinct trusted key IDs; `dag signatures --cid` exports standalone
DSSE envelopes; `dag sign --predicate-type` sets the field external verifiers
dispatch on.

- The small-order forgery test uses a table of eight canonical points. Are
  they the right eight, and does rejecting at parse time actually cover every
  path a key can enter the keyring by?
- Distinct-key counting was applied to `valid` as well as `trusted`. Check the
  adoption path (`Control::adopt_attested`) — it uses `any(|s| s.trusted)`, a
  threshold of one, so counting does not matter there. Confirm that reasoning
  holds.
- Take an exported `.dsse.json` to a real external verifier if you can. The
  claim is that it is consumable; nobody has proved that against actual
  `cosign` or `slsa-verifier`.

### 6. Journal, SSE and the console (`17e289b`)

Bounded journal with reclaim-on-compaction; replay reports front-truncation;
SSE emits a `lagged` message. A separate defect surfaced here: the console
registered `source.onmessage` while the server names every SSE message, so
the live feed had **never** worked.

- That console bug is the most interesting thing in this pass, because it
  says the browser path is under-tested generally. What else in `web/` is
  wired to an API shape it does not actually receive?
- Reclaim compacts a copy and keeps it only if smaller. What happens when the
  disk cannot hold the copy?
- `web/dist/` is committed and must match `web/src/`. Run `npm run build` in
  `crates/dag-api/web` and check nothing changes.

### 7. Schema version (`22e9a98`)

`control.redb` carries a `schema` table read before any subsystem opens a
table. Unversioned directories are adopted as version 1 and stamped. A
truncated database is caught (redb panics; the panic unwinds) and reported.

- The "refuses without writing" property is the one that matters. Verify it
  by inspection of ordering, not just by the test.
- `catch_unwind` around `Database::create` assumes the panic unwinds.
  `[profile.release] panic = "unwind"` is set explicitly with a rationale, and
  the schema tests do pass under `--release`, so it holds today — but it is an
  undeclared coupling between an error path and a profile setting. Nothing
  fails loudly if someone sets `abort` later; a reviewer might reasonably ask
  for a test that would.
- Is version 1 actually a single format? Directories written across this
  pass's own commits differ (pin events with and without `prev`). They are
  intended to be read-compatible; confirm that.

---

## Known-weak areas, stated plainly

These are not hidden. Confirming them is low value; finding that they are
*worse* than described is high value.

- **Pin `importance` is inert.** Recorded, displayed by `gc status`, consulted
  by no decision. There is no quota mechanism for it to arbitrate.
- **One process per data directory.** `--lock-timeout` makes it a queue.
  Genuine write parallelism against one directory does not exist.
- **Third-party job adapters cannot record provenance.** `execute_once*`
  builds its runner internally; the escape hatch produces output but no
  `JobRun`. This undercuts the embedding story in `ALL_USE_CASES.md` §2.
- **No metrics, no structured logging, no real `/health`** — the SPA fallback
  returns 200 with HTML for every unmatched path, so a liveness probe pointed
  at `/health` can never fail.
- **Entry payloads cost ~1.9x on disk**, so `put-entry` tops out near 2.09 MiB
  despite the documented 4 MiB limit. Fixing it changes every entry CID.
- **`#[non_exhaustive]` on `ControlError` and `RunError`** forces wildcard
  match arms downstream, so a new variant silently becomes exit 70 / HTTP 500.
  Both matches must be edited by hand.

---

## The test suite, and how to distrust it

The original review's central finding was not any single defect but that 563
passing tests could not reach where the defects lived: no test had ever aged a
chunk on disk, and none approached the subtree-expansion ceiling. Time and
scale were blind spots.

Those levers now exist — `filetime` is a dev-dependency, and
`gc_retention_roots.rs` drives the ceiling — but the same question applies to
this pass's own tests. The useful thing you can do is ask, for each new test
file, *what would still pass if the fix were reverted*. Several were verified
against the pre-fix code by their authors; several were not. The new files:

```
crates/dag-control/tests/{gc_retention_roots,gc_write_race,rebuild_from_store,
  schema_version,concurrent_open,bulk_ingest,event_journal_bounded,
  event_journal_replay_window}.rs
crates/dag-storage/tests/durability.rs
crates/dag-api/tests/{browser_safety,events_observability}.rs
crates/dag-cli/tests/{cli_index_verify,cli_recover_lost_database,
  pointer_as_of,signature_export}.rs
```

Dimensions still not exercised anywhere, which is where I would write new
tests rather than read existing ones:

- **Crash.** Nothing kills a process mid-write and reopens. Every durability
  claim rests on reading the ordering, not on observing a survivor.
- **Scale.** Nothing runs against a store of millions of chunks. Several code
  paths materialise whole-store `Vec`s and `HashSet`s.
- **Multi-process.** One test opens a directory twice in-process. Nothing runs
  two `dag` binaries against one directory.
- **The browser.** No test drives the console; the SSE defect above went
  unnoticed for that reason.
- **Long-running.** No test runs `dag serve` for long enough to see the
  journal grow, the integrity scan fire, or memory settle.

---

## Ground rules for that review pass

Engineering rules the review was run against:

- TDD: the failing test comes first, and is watched failing.
- No `#[allow(...)]` of any kind, no `todo!()`, no `unimplemented!()`, no
  `// TODO` in merged code. Fix it or leave it out.
- `cargo clippy --all-targets --all-features -- -D warnings` must be clean,
  and `cargo fmt` applied.
- Publishing to crates.io and changing hosted-CI enablement were out of
  scope for that pass.
- Nothing in this pass had been pushed to any remote.
