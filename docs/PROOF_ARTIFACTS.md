# Proof certificates as provenance: the vcot fit, measured

> **Status: options analysis, plus the decisive experiment — now run.** The
> build-cache experiment proposed below was executed on 2026-07-28; results
> are in [The experiment, run](#the-experiment-run-2026-07-28). It produced
> the headline number and surfaced two effect-key defects (later numbered
> 13 and 14), both fixed. This document informs the Horizon-2 wedge choice
> in [SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md) — it is the concrete instance
> of "Option B — agent provenance", examined against a real artifact corpus.
>
> The subject matter is the vcot / Avent's Razor body of work (three papers:
> *Avent's Razor*, *Verified Chain-of-Thought for Finite-Domain Constraint
> Reasoning*, and *A Proof-Assistant-Checked Determination of W(3,3)*), whose
> artifacts ship as `vdw33-certificates.zip`. A separate working session
> measured this store's chunking parameters against that corpus; this
> document reviews those findings, re-verifies what could be re-verified
> locally, and lays out the options.

## Evidence discipline

The papers tag every claim by evidence class; this document owes them the
same courtesy.

| Tag | Meaning |
|---|---|
| **[V]** | verified in the session that wrote this document (commands re-run here) |
| **[R]** | reported by the other measuring session; consistent with [V] checks but not reproduced here |
| **[P]** | published in the papers themselves |
| **[A]** | arithmetic over [V]/[P] quantities, not an end-to-end measurement |

## The two systems, briefly

**vcot** is a verified chain-of-thought loop for finite-domain constraint
reasoning: untrusted proposers (language models or a deterministic solver)
emit typed steps; an 18-rule kernel *computes* every conclusion (proposers
can never state one); completed derivations are re-checked from bytes by two
independent checkers (Python, and a zero-dependency Rust verifier held to
exact agreement by differential fuzzing); each accepted chain compiles to
Lean 4, where every step is re-proved from exactly its cited premises. Its
flagship artifact is a Lean-kernel-checked determination of the van der
Waerden number W(3,3) = 27: a 382,964-step derivation covering the entire
21,048-node search, compiled to 336 Lean shard modules plus a master and a
combined theorem whose human audit surface is two three-line definitions.

**This store** is a content-addressed DAG with pointers, pins, effect-cached
jobs, Ed25519/DSSE/in-toto signing, and directory replication — provenance
as the product.

## Why this is an identity, not an analogy

Avent's Razor, Definition 2.6: *a reasoning trace is a DAG whose nodes are
propositions and whose edges are rule instances; it is valid iff every node
is an axiom or the conclusion computed by its rule from its cited premises.
A valid trace is a certificate: its acceptability depends on its bytes, not
the process that produced it.*

That is this system's entry model stated in another vocabulary. A derivation
step is `rule + premise references -> conclusion` — a CBOR payload plus
named links, covered by the entry's own CID. "Acceptability depends on its
bytes" is invariant I1 wearing a different hat. Two proofs sharing a lemma
share that lemma's CID by construction. And the papers already live this way
by hand: they publish SHA-256 tables, ship a hand-rolled `SHA256SUMS.txt`,
and designate the proof JSON "the canonical anchor" precisely because the
compiled `.lean` bytes are not canonical. The store is the systematization
of a practice the papers already follow manually.

The value of the pairing is **semantic identity and keying — not
compression**. The next section is why that sentence has to be said.

## What was measured

### Claims re-verified in this session [V]

- `vdw33-certificates.zip` matches the SHA-256 the paper publishes
  (`6a7097b59cde7139cb88f27c4676bbdca33160cd628cab383e1c7ae272b5ffd0`), so
  everything below is measured against exactly the artifact set the paper
  describes.
- The corpus: 345 files, 137,703,869 bytes uncompressed; the proof object
  `vdw_3_3_27.proof.json` is 30,167,150 bytes; the 339 Lean modules total
  107,506,833 bytes.
- **The import graph is a ternary tree.** Max out-degree 3; in-degree
  exactly 1 for 337 of 339 modules; the two roots (never imported) are
  `Vdw33Combined` and the standalone witness `Vdw33Lower`; 157 leaves.
- **Invalidation is shallow.** Reverse reachability over that graph: editing
  any single module invalidates at most 7 other modules, median 6 — not 338.
- **There is no cross-file redundancy.** `gzip -9` over the concatenation of
  all 339 modules: 10,619,610 bytes. Per-file `gzip -9`, summed: 10,648,097
  bytes. If the shards shared material across file boundaries, concatenated
  compression would beat per-file compression; it is 0.3% better over 107.5
  MB. The repetition is token-level, where a compressor reaches it and a
  chunker cannot.
- `RESULT.md` in the artifact package twice states the master theorem
  "imports all shards". It imports three (`Vdw33S1`, `Vdw33S113`,
  `Vdw33S225`) and reaches the rest transitively. See the corrections
  ledger at the end.

### Claims reported by the measuring session [R]

Consistent with everything above but not re-run here:

- FastCDC at this store's defaults (256 KiB / 1 MiB / 4 MiB) over the 339
  modules: 344 chunks, all distinct — **0.00% dedup**. Pushing parameters
  down two orders of magnitude (16K/64K/256K, then 2K/8K/32K): still 0.00%.
- A one-character edit mid-file in one shard leaves 343 of 344 chunks
  unchanged (99.71%) — write amplification on a proof revision is already
  near-optimal at default parameters, from content addressing alone.

### Published quantities the options below lean on [P]

- Shard build: 12,076 s wall on 2 cores for 336 shards (mean ~36 s each);
  master 57 s; combined bridge ~222 s; full Lean re-check ~3.4 h.
- Checkers: Python 9 s, Rust 2.1 s over the full 383k-step certificate.
- The proof object is the canonical anchor; recompiling reproduces today's
  `.lean` bytes, but compiler evolution would change their hashes while
  proving the same statements.

## The pitch that is dead: storage efficiency

The store does not compress, so it would hold 107.5 MB of shards where the
shipped zip holds 15.2 MB — a 9x give-up [V] — and deduplication recovers
nothing at any chunking scale [R], because there is nothing cross-file to
recover [V]. **If this system is pitched as storage efficiency for proof
artifacts, it surrenders 9x and gains zero.** That framing is retired, not
defended. (It does put a concrete motivating dataset behind the
transparent-zstd backlog item — CID over uncompressed bytes, invariant I1
preserved — which would close most of the gap invisibly. A backlog
tailwind, not a pitch.)

## The live options, ranked by defensibility

### 1. Verification verdicts as signed attestations

The strongest option, and the one to lead with. The vcot papers' central
discipline is redundant independent checking: two checkers sharing no code,
held to exact agreement; then the Lean kernel as final oracle. Today, "both
checkers accepted and Lean accepted" is a sentence in a PDF — trustworthy
because the reader trusts the author. As stored attestations it becomes a
fact a stranger can check:

- The proof object goes in via `store_auto` — a `file/v1` manifest over ~30
  chunks; its root CID *is* a sha256 digest, so it drops directly into
  `subject.digest.sha256` of an in-toto v1 statement, the format the signing
  layer already emits and external supply-chain tooling already verifies.
- Each checker's verdict is a DSSE envelope over that subject, signed by
  **that checker's own key**: predicate carries the checker's name, its
  binary's CID (the Rust verifier is zero-dependency, so content-addressing
  the checker itself is meaningful), the verdict, the step count, and the
  toolchain. Two envelopes, two keys. "Held to exact agreement" becomes
  two independently signed statements over the same CID.
- Lean acceptance is a third attestation whose predicate names the Lean
  toolchain version (and ideally the toolchain archive's CID) — "Lean
  4.10.0, no `sorry`, no `axiom`" as a checkable predicate instead of prose.
- Stored via the existing `sign_cid` pattern: each signature is an entry
  with a `signs` link to its target — walkable, pinnable, replicable. A
  subtree pin from the corpus root retains the entire evidence set; a
  pointer (`vdw33/proof`) names the current certification, and pointer
  history records re-certifications.

The existing trust rule fits without modification: a *trusted* verdict is
only computed against the keyring's copy of a key, trust does not travel
with `dag sync`, so a consumer decides for themselves which checkers they
believe — which is exactly the papers' own posture that checker agreement
is evidence, not proof. Today `dag verify` requires intact content plus at
least one trusted signature; a "2-of-2 distinct keys" threshold is a CLI
flag's worth of porcelain, not a core change.

**Cost: near-zero new core code.** This is a worked example and a document,
which is why it doubles as the launch narrative for the crates.io
publication.

**Since run** (2026-07-28): the example exists with real CIDs and genuinely
produced verdicts — both vcot v0.2.1 checkers and Lean 4.10.0 ran here and
accepted the `fable_zebra` certificate, each verdict signed under its own
key with a predicate naming the checker implementation by CID, and
`dag verify --min-trusted 2` gates on their exact agreement. See
[experiments/vdw33-attestation/](experiments/vdw33-attestation/README.md),
including its honest-scope note on why the W(3,3) certificate's own
checker verdicts require the vdw33-era engine.

### 2. Memoized shard builds (the build cache pointed at Lean)

Each shard build is a job: config = compiler invocation + toolchain CID,
inputs = the proof object (or per-shard slice) and the imported modules'
artifacts. The effect key already covers config + input manifest, so this
is build-cache semantics with no new machinery, and `dag sync` seeds another
machine's cache — the receiving side already knows the name of every byte
it holds.

There is a real ecosystem gap here: Lake has no general content-addressed
remote build cache; mathlib's `lake exe cache get` is bespoke tooling for
that one project, keyed on git revision rather than content [R — checked
against Lake docs by the measuring session].

This option also **resolves the paper's own "non-canonical shard bytes"
caveat structurally**: the `.lean`/`.olean` files are derived artifacts —
cache values keyed by (compiler, proof object), not anchors. Derived
artifacts don't need stable identity; the attestation names the compiler
that produced them, and the proof object stays the one canonical anchor.

### 3. Incremental re-verification

The same machinery as option 2, read from the verification side, and the
tree measurement makes it concrete: a one-module revision invalidates at
most 7 modules [V]. This document originally carried "roughly 25x" as
arithmetic over the paper's per-shard times; the experiment has since
**measured it** — 10.1x wall-clock for the worst-case revision, 31x for a
byte-level one, 209x for a no-change re-verification, with the hit/miss
pattern matching the dependency structure exactly. See
[The experiment, run](#the-experiment-run-2026-07-28). Re-certification
then republishes attestations for exactly the invalidated shards, and
pointer history records what changed and when.

### 4. Cross-proof lemma sharing

Two certified directions (upper bound, witness) could in principle share
lemma entries by CID. Given the dedup result, expect this to be weak;
measure it only if it falls out of other work for free. Not a pitch.

**A footnote, deliberately:** kappa = log2(|P|/|P_C|), the razor's
constraint capacity, connects to this store only in that a stored search
trace would let kappa be *computed from an artifact* rather than derived
analytically. One sentence, no numbers — the razor paper's own discipline
for unbuilt directions applies here too.

## Granularity: the shard is the unit

Step-level entries would mean 382,964 tiny objects for this one
certificate. The redb index would cope; a filesystem chunk store would not,
and nothing needs it — checkers consume the certificate whole, and Lean
consumes shards. The right units are the ones the pipeline already uses:
the proof object (one `file/v1` DAG), and the shard (339 entries whose
links mirror the import tree, max out-degree 3 [V]). Conveniently,
sync-from-roots then does the right thing: point a pointer at the corpus
root and the whole evidence set replicates; nothing dangling, nothing
over-promised.

## Overclaims to refuse

Stated once, bluntly, so no later document has to walk anything back:

1. **A CID proves bytes, not validity.** Content addressing says the
   certificate is the one everyone means; only the kernel says the
   inference is sound. The store adds provenance and incrementality; the
   trusted base remains the Lean kernel plus the axiom list. Conflating
   these would be exactly the overclaim the papers were built to refuse.
2. **Caching verdicts grows the trusted base.** A cached verdict adds the
   effect-key computation and the store's integrity to what must be
   trusted. Caching must therefore be defeasible: a `--no-cache` path
   re-derives everything from source, and a cached verdict is never the
   sole evidence for a claim.
3. **No storage-efficiency claims.** Measured dead, above.
4. **No soundness claims for the attestations themselves.** An attestation
   records that a named checker accepted named bytes. Checker agreement is
   evidence of implementation correctness, not proof — the papers say this
   about their own checkers, and the stored form must not say more.

## What this does to the roadmap

The Horizon-2 question is A (build cache) versus B (agent provenance). This
corpus is the sharpest available instance of B, for a reason worth stating
precisely: **formal verification is the one provenance domain where "did
the agent do the right thing" is machine-decidable.** Everywhere else,
attestation records what happened and a human still judges whether it
should have. Here the attestation records that the result was *correct*,
and a third party can re-derive that judgement from the artifacts alone.
That is a stronger sentence than anyone else in the agent-provenance space
can write — and options 2 and 3 are simultaneously a working instance of A,
so the "A and B share almost all machinery" observation from the overview
stops being an observation and becomes one artifact set.

### Recommended sequence

1. **This document** — done; it is the review-and-options step.
2. **The decisive experiment** — run on 2026-07-28; see
   [The experiment, run](#the-experiment-run-2026-07-28). The prediction of
   roughly 331/339 hits was exact; the wall-clock saving is measured at 10x
   for the worst-case revision, 31x for a byte-level one, and 209x for a
   no-change re-verification. The memoization story ships.
3. **The worked example** (`dag usecase`-shaped): seed the corpus — proof
   object, shard entries mirroring the import tree, dual-checker
   attestations under two keys, Lean-oracle attestation, subtree pin,
   pointer — and a verify walk that checks all of it from the bytes alone.
   The full corpus is 137 MB, so the seeded scenario likely uses a trimmed
   subset with the real corpus as a documented walkthrough.
4. **Write-ups follow the artifacts**, with the evidence-class discipline
   the papers use; the incremental-verification number stays labeled
   arithmetic until step 2 measures it.

## The experiment, run (2026-07-28)

Everything in this section was measured in this repository's working
session, on one machine: Apple Silicon, 10 cores, 32 GB, Lean 4.10.0 (the
paper's exact toolchain, installed via elan), 8 concurrent build jobs.
Single runs, no confidence intervals — the same discipline the papers use
for their own single-machine numbers.

**Harness.** A ~250-line driver *outside* this repository, consuming
dag-control and dag-jobs as libraries — the embedding shape the use-case
survey describes, granting the exec capability in its own process; the HTTP
API path was never involved. One exec job per module (`vdw33/<module>`),
whose inputs are a `src/<module>` pointer plus `olean/<dep>` pointers for
the *transitive* import closure — the honest input set, because Lean loads
transitive imports. The job's command materialises those pointers as files,
renames them into a `deps/` directory, and invokes the toolchain's `lean`
by absolute path with `LEAN_PATH` — empty environment, no shell tricks,
outputs collected through `store_auto`. Modules execute in level order
(leaves first), and an output pointer is only updated when the produced
CID actually changed.

**The experiment's first product was two defects**, both of the same
species — the effect key named the coordinates of a resolution rather than
the inputs — and both invisible to every existing test because runner tests
reuse a single manifest value:

- **Defect 13:** `resolved_at_unix` fed the effect key, so the cache could
  only hit when two triggers resolved in the same wall-clock second. The
  historical "three run requests, one invocation" verification had passed
  by timing luck.
- **Defect 14:** each pointer's `log_seq` fed the key, so reverting a
  pointer to bytes that were built before produced a fresh key — measured
  live as a 280 s full-chain rebuild of content the cache already held.

Both are fixed (the key now covers static CIDs and pointer (id, head CID)
pairs; timestamp and seq stay in the run record for replay). Worth stating
plainly: **the experiment paid for itself before
the first measurement**, and this is precisely what the papers' evidence
discipline predicts — claims verified by execution find what claims
verified by inspection cannot.

**The measured matrix:**

| Pass | Misses | Hits | Wall | vs cold |
|---|---|---|---|---|
| Cold build, all 339 modules | 339 | 0 | 44.3 min | 1x |
| No-change re-run | 0 | 339 | 12.7 s | 209x |
| Comment-only edit, deepest leaf (S299) | 1 | 338 | 86 s | 31x |
| Semantic rename in S299 | 8 | 331 | 4.4 min | 10.1x |
| Revert of that rename, before defect-14 fix | 8 | 331 | 4.7 min | rebuild |
| Revert, after the fix (micro-demo) | 0 | 1 | 28 ms/job | hit |
| Full pass on a `cp -R` copy of the store | 0 | 339 | 13.1 s | 204x |
| Sample jobs on a `dag sync` replica | all | 0 | — | miss |

Cold-pass distribution: 2.7 s min, 61.3 s median, 198.6 s max per shard;
the combined theorem alone is 110 s; 5.4 core-hours total, consistent with
the paper's 3.4 h on its 2-core machine.

**Findings, in order of weight:**

1. **The prediction was exact.** The options analysis predicted roughly
   331/339 hits for a one-module revision; the semantic revision measured
   exactly 331/339, with the misses being precisely the edited leaf and its
   7-module ancestor chain, in level order. The import-tree measurement and
   the cache behaved as one model.

2. **Early cutoff falls out of content addressing, undesigned.** The
   comment-only edit rebuilt one module, its olean came back byte-identical,
   the output pointer therefore did not move, and all seven ancestors hit
   the cache. That is Bazel-grade incremental behaviour — change detection
   by output content, not timestamps — from nothing but CIDs and the
   skip-no-op-pointer-update rule.

3. **Rebuilds converge.** In the semantic pass, all seven rebuilt ancestors
   produced oleans byte-identical to their previous ones — Lean 4.10.0 is
   deterministic on this corpus, across fresh temp dirs and across the two
   data directories. The store absorbs converged outputs as no-op puts, so
   a revision's blast radius in *storage* is one module even when its blast
   radius in *compute* is eight.

4. **Re-verification is cheap at exactly the granularity claimed.** The
   options analysis carried "roughly 25x" as arithmetic over the paper's
   hardware; measured on one machine against its own 8-way cold build, the
   worst-case single-lemma revision is 10.1x by wall clock (59x by CPU
   time — the chain is serial, which caps wall-clock gains), a byte-level
   revision is 31x, and the no-change case — "is this corpus still
   verified?" — is 209x. Those are the honest numbers, and they supersede
   the arithmetic.

5. **`dag sync` replicates the evidence, not the effort.** The replica got
   all 678 pointers and 743 MB of content in 26 s, and every sampled job on
   it re-executed: effect-cache entries are job state, which ADR-002
   deliberately keeps local. A plain directory copy carries both (339/339
   hits, 13.1 s). So today: copy the directory to seed a builder, sync to
   seed a verifier. If cross-machine *compute* seeding is ever wanted over
   sync, the principled route is already on this document's list: a signed
   effect-cache entry is exactly a verdict attestation — "this key produced
   these outputs, says this builder" — which the receiver trusts or ignores
   by keyring policy, not by blind import. That would unify option 1 and
   option 2 rather than bolting a cache protocol onto sync. **Since built
   and tested: ADR-003.** `--attest-key` publishes signed claims that sync
   carries; `--adopt-attested` on a replica adopts them on a miss, but only
   from a keyring-trusted key with every output present and intact (J7).

### The ADR-003 legs (2026-07-28, same machine)

After attested effect claims landed, the sync gap was re-measured with the
trust edge in place. The builder ran a fresh cold build with `--attest`
(each completed shard published a signed, pinned claim); the run was
interrupted externally after 222 of 339 modules and later resumed to
completion — incrementally, as the cache design implies: 222 hits, 117
executions, no work repeated. The numbers below say what each leg covers.

| Leg | Result |
|---|---|
| `dag sync` to a fresh replica | 638.7 MiB, 222 claims indexed at destination, 25 s |
| Replica, key **trusted**: all 157 leaf jobs, `--adopt` | **157 adopted, 0 executed, 11.3 s** |
| Replica, key **not trusted**: same claims present | 0 adopted; executed (7.4 s for the probe module) and converged on the identical olean CID |
| After the builder run completed (339 claims): full pass on the replica | **157 cache hits + 182 adopted + 0 executed, 13.0 s** — the whole 44-minute corpus reproduced without one Lean invocation |

The trusted replica satisfied roughly 1.7 core-hours of leaf compute in
11.3 seconds from claims alone, with Lean never invoked; the untrusted
replica, holding byte-identical claims and content, quietly did the work
itself and produced the same CID — the failure mode of a missing trust
edge is *wasted compute*, never *wrong outputs*. Sync now seeds a builder
too, but only across an explicit `dag key trust`.

**Caveats.** The comment edit is a byte-level proxy for revision; the
rename is a real source change that preserves the proof. A revision that
changes a lemma's *statement* would land in the same 8-miss shape (its
olean necessarily changes). Timings are single runs on one machine; the
driver's 12.7 s no-change floor is dominated by 339 sequential-ish job
resolutions and could be batched. None of the caveats touch the shape of
the result: hit/miss behaviour matched the dependency structure exactly in
every pass.

## Corrections ledger (upstream)

- `RESULT.md` in `vdw33-certificates.zip` states (twice: lines 61 and 101)
  that the master theorem "imports all shards". Verified false [V]:
  `Vdw33Main.lean` imports exactly `Vdw33S1`, `Vdw33S113`, `Vdw33S225` and
  reaches the rest transitively through the ternary tree. The fix belongs
  in the vcot repository, and it matters because the tree structure is
  precisely what makes the incremental story above work.
- A small provenance lesson rides along: `RESULT.md`'s hash is pinned in
  the package's own `SHA256SUMS.txt`, so correcting it means republishing
  the zip under a new hash — a mutable document pinned by content hash.
  A pointer with history is the primitive that problem was asking for.
