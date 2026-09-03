# Use cases: where a content-addressed DAG earns its keep

> The fully worked, runnable example is [USE_CASE.md](USE_CASE.md) — a
> model-release provenance ledger, seeded by `dag usecase seed` and checked by
> `dag usecase verify`. This document maps the same primitives onto every
> other domain where they are genuinely useful, in rough order of fit, and is
> honest about where they are not.

## The lens

The system answers seven distinct questions, each with one primitive:

| Question | Primitive |
|---|---|
| Prove what this is | CID — the identifier *is* the hash of the bytes |
| Prove what it depended on | links, immutable inside the entry they belong to |
| What did this name mean at time T? | pointers, with total append-only history |
| Will the evidence still be there? | pins — retention as data, honoured by GC |
| Don't redo work whose inputs haven't changed | effect cache keyed on content |
| Who vouched for it? | Ed25519 over DSSE envelopes, local keyring |
| Give me a copy I can verify independently | `dag sync` — byte-identical, CID for CID |

The test for a genuine application is stricter than "integrity matters".
Plenty of systems hash things. Content addressing pays for itself where
**verification by a third party who distrusts you is the point** — where the
claim has to travel, and has to be checkable with nothing but the bytes, no
access to the system that produced them. Every use case below passes that
test; the last section lists the ones that don't.

---

## 1. Model-release provenance (the worked example)

> Which exact dataset, configuration and code produced the model that was
> live in production on 12 March? Prove none of it has been altered since.

The flagship, built and runnable today — see [USE_CASE.md](USE_CASE.md) for
the full walkthrough. Artefacts become chunks; dataset cards wrap them with
links; pointers name the moving parts; a deterministic attest job publishes
an entry linking every input it resolved; a subtree pin retains the whole
release's evidence; a signature says who approved it. `dag usecase verify`
walks from the name to every byte the release depended on and re-hashes each
one, consulting nothing outside the data directory.

The same shape transfers to any regulated model deployment: the regulator
changes, the question does not.

---

## 2. Build and compute caching

> Why was this rebuilt? And why should I trust the cached artefact I got
> instead of a rebuild?

**The mapping.** The exec adapter already *is* an action cache. Its effect
key is the job's config plus the resolved input manifest, so an identical
command over identical inputs is a cache hit by construction — measured at
scale in [PROOF_ARTIFACTS.md](PROOF_ARTIFACTS.md): a 339-module Lean corpus
rebuilt cold in 44 minutes, re-verified unchanged in 13 seconds, with a
one-module revision re-running exactly the modules the dependency structure
requires. Inputs materialise from content addresses; outputs go through
`store_auto`, so large artefacts chunk and dedup. Seeding another machine
is two different promises, and the same experiment measured both: copying
the data directory carries the effect cache (a full pass on the copy is
all hits), while `dag sync` deliberately carries content and provenance but
not job state (ADR-002), so a synced replica re-executes and converges on
byte-identical outputs — sync seeds a *verifier*, a copy seeds a *builder*.
Attested effect claims (ADR-003) bridge the two across an explicit trust
edge: a builder running with `--attest-key` publishes signed claims that
sync carries, and a replica that has run `dag key trust --for adopt` on
that builder's key can `--adopt-attested` them on a miss instead of
re-executing. The grant is purpose-scoped (ADR-004): a key trusted only
for release verification never becomes a build source by accident.

**Who does this today.** Bazel's Action Cache + CAS, Nix, sccache,
Turborepo's remote cache. All of them are servers, or assume one.

**Why embedded wins.** Nobody wants to operate a remote-cache deployment for
a ten-person team. A hermetic task runner built on `dag-jobs` gets correct
incremental execution from a library — `cargo add`, not infrastructure. This
is the use case where "the SQLite of DAGs" is decisive rather than
incidental.

**The embedder's own adapters go through the same lifecycle.**
`Execution::new(control).adapter(mine).run(&job)` runs a caller-supplied
`JobAdapter` with the full trigger → resolve → record → effect-cache → pin
path, so a build tool gets *both* its own execution model and the run
records that make the cache auditable. Until this existed, building a
`JobRunner` by hand skipped the run record entirely — the provenance half —
which is exactly the half this system is for. Built-in `code_ref` names
cannot be shadowed, so no embedder silently changes what `hash` means for
every spec already in the directory.

**The standing constraint carries over.** Exec runs only where the
capability is granted — the CLI behind `--allow-exec`, never the HTTP API.
A build tool embedding the runner grants the capability in its own process;
nothing about this use case loosens the gate.

---

## 3. AI agent provenance and memoized pipelines

> What did the agent read before it did that? And who — which orchestrator,
> which policy — let it?

**The mapping.** An agent run has exactly the shape of a release: inputs
resolved into a manifest (J3), work done, outputs published, an attestation
linking everything it touched, signed by the orchestrator's key. "Show me
the evidence chain for this agent action" is the regulator question from the
worked example with the nouns changed, and organisations deploying agents
are beginning to be asked it. The attest adapter needs almost nothing new.

Two further fits, both native rather than bolted on:

- **Effect-cached LLM calls.** A model call is a side-effecting job whose
  effect key is prompt + model + parameters. An identical pipeline step is a
  cache hit — no API spend — and because the cache is content-addressed it
  *cannot* be stale (J2). The model adapter is the embedder's to write, and
  `Execution` (see §2) gives it the run records without asking it to
  reimplement them.
- **Agent memory as a DAG.** Memory entries with links make "this conclusion
  derived from these observations" a walkable, immutable edge; pins are
  memory-retention policy; pointer history is what the agent believed at
  time T.

**Who does this today.** Tracing products (LangSmith and kin) — mutable SaaS
logs, verifiable only by trusting the vendor's database.

**Why embedded wins.** The ledger lives with the agent: works offline,
survives vendor churn, and its claims are checkable by an auditor who has no
account with anyone. There is no incumbent here; the market is forming now.

**The sharpest instance** is formal proof certificates — the one provenance
domain where "did the agent do the right thing" is machine-decidable, so an
attestation can record that the result was *correct*, not just that it
happened. Measured against a real Lean certificate corpus in
[PROOF_ARTIFACTS.md](PROOF_ARTIFACTS.md).

**Agent VMs made this urgent.** Grok Bot (August 2026) and the same-season
Claude Cowork / ChatGPT Work products give a named agent a persistent
cloud computer. Official Grok Bot docs are explicit that every bot on
one account shares that computer — files, cookies, credentials — and
that separate bots are not a security boundary. Approvals gate proposed
actions; they do not reconstruct what already ran; the VM is not
self-hosted. The ledger that *leaves* the VM, verified in a tab that
has no vendor account, is the answer this kernel already had. See
[ECOSYSTEM.md](ECOSYSTEM.md). Do not integrate with the VM operator:
that would undo the claim.

---

## 4. Legal hold, chain of custody, compliance retention

> Prove this evidence was preserved, unaltered, from the moment the hold was
> issued — and prove the routine cleanup could not have touched it.

**The mapping** is the most exact in this document: a litigation hold is a
pin, feature for feature.

| Legal concept | Primitive |
|---|---|
| Hold over everything a matter touches | subtree pin — transitive by walking links |
| The retention schedule itself | pin TTL, absolute epoch semantics (R5) |
| Record that the hold existed, and when it lifted | append-only pin history, which collection never touches |
| Disposition cannot destroy held material | GC honours effective retention, behind the recovery gate (I6, R6) |
| Chain of custody | each handler signs the CID; signatures are walkable entries |
| Defensible disposition | `gc run --record` stores the report *in the ledger*: every collected CID with size and age, chained under `system/gc/dispositions`, signable and replicable |

The disposition record is worth dwelling on, because it is what makes
deletion *defensible* rather than merely correct: the report is content, so
it can be signed by whoever authorised the disposition, and the chain
retains itself — each record links its predecessor, and a live pointer head
is a transitive retention root, so the trail cannot be collected by the same
mechanism it documents.

Two honest qualifications remain, both from the 2026-08 review
([PRODUCTION_READINESS_REVIEW.md](PRODUCTION_READINESS_REVIEW.md)):

- **There is no way to rank retention.** Pins are all-or-nothing: retention
  is a union, so a pin either protects content or it does not. The inert
  `importance` field was removed in schema 2 rather than left implying a
  precedence the collector could not act on. Ranked holds need a quota
  mechanism — a budget that breaks pins under a size target — which does not
  exist.
- **Subtree expansion has a ceiling**, and reaching it now *refuses to
  collect* rather than protecting a prefix and deleting the rest. Raise it
  with `--max-subtree-expansion` when a hold genuinely covers more.

And one this system deliberately does not solve: **signature timestamps are
self-asserted**. A signature says who, not when — there is no trusted
timestamping authority, so "preserved *since* T" rests on the pin's own
event time, which the holder wrote. Where an adversary might backdate,
counter-sign into an external transparency log; this system feeds one
rather than replacing it.

**Who does this today.** WORM storage appliances and e-discovery suites —
expensive, server-shaped, and verified by trusting the appliance.

**Why embedded wins.** "Tamper-evident, retention-enforced, independently
checkable" as a library has no competitor shaped like a library. The buyers
are regulated and slow, which makes this the most defensible fit long-term
rather than the fastest.

---

## 5. Data and ML lineage

> Which data trained this model — and what exactly did last quarter's
> revision change?

**The mapping.** The FastCDC chunker means a 10 GB dataset that gained a row
costs one new chunk plus a manifest — revisions dedup at the chunk level,
automatically. Dataset cards with `supersedes` links (already in the worked
example) are the lineage model practitioners hand-roll in YAML. A pointer
per dataset name gives "current", pointer history gives "as of March", and
an attestation per training run records what was actually read.

**Who does this today.** DVC — content-addressed file storage using git as
its pointer layer; Pachyderm — the same shape at Kubernetes scale; LakeFS —
needs a server. This system does the data half *and* the pointer half
natively, plus retention and attestation, embedded.

**Why embedded wins.** The store is a directory next to the notebook. No
daemon, no git plumbing repurposed for data, no cluster.

---

## 6. Air-gapped and field operation

> How does evidence cross a boundary that packets must not?

**The mapping.** ADR-002 chose directory-to-directory sync and rejected
HTTP. For most users that is an implementation choice; for this use case it
is the product. A data directory travels on a disk; `dag sync` at the far
side is incremental (only missing CIDs move), verifying (every received
chunk is re-hashed), and refuses divergent history rather than merging it.
Verification needs no network at any point — `dag usecase verify` consults
nothing outside the directory.

**Where that matters.** Classified and defense networks, ships and remote
sites, hospitals, field research, election systems — and evidence gathered
by journalists and human-rights documenters in hostile environments, where
the archive must outlive and out-credibility its holder (the shape Starling
Lab pioneered).

**Why this system.** Almost no provenance tooling works fully disconnected.
This one does by construction, and the trust model fits: trusted keys
deliberately do not travel with a sync, so a source cannot decide what its
replica trusts.

---

## 7. Software supply chain

> The attestation ecosystem assumes the attestations live somewhere. Where?

**The mapping.** The signing layer already speaks DSSE envelopes carrying
in-toto v1 statements — the format existing supply-chain verifiers consume.
A CID is a sha256 digest, so it drops straight into `subject.digest.sha256`.
SBOMs, provenance statements and the artefacts they describe are ordinary
entries: walkable, pinnable per supported release, replicable with sync.

`dag signatures --cid <C> [--out-dir <D>]` writes each covering signature as
a standalone `.dsse.json`, and `dag sign --predicate-type <uri>` sets the
`predicateType` external verifiers dispatch on — so a statement can be SLSA
Provenance rather than only this project's own predicate. Together those are
what make the format claim usable rather than merely structural.

Interop runs both ways: `dag signatures --import <dsse.json>` accepts an
envelope minted elsewhere — a CI signer, another deployment — as an ordinary
signature entry, provided it verifies against a key the importer names or
already trusts, names exactly one sha256 subject, and that subject's bytes
are present and intact locally. So an attestation produced by the build
system can be filed against the artefact *here*, and `dag verify` treats it
identically to a locally-made one. Ed25519 only; an ECDSA envelope (cosign's
default) fails verification and is refused rather than stored.

A private registry falls out of the same parts: a pointer per
`package@channel`, versions as immutable entries, publisher signatures
checked against a keyring the *consumer* controls. The "registry quietly
mutated a published version" attack class closes structurally, not by
policy.

**Who does this today.** Sigstore and Rekor — which are complements, not
competitors. This is the local store the big public infrastructure assumes
exists at each org and doesn't provide.

---

## 8. Deployment forensics

> What configuration was live at the moment of the incident?

**The mapping.** Pointer history answers this verbatim. A deploy hook does
`dag put` + `pointer update` per change; an attestation links config → code
→ approver; `dag sync` ships the directory to an evidence store the
production environment cannot rewrite. Reconstructing the exact deployed
state at time T becomes a resolve at a sequence number, tamper-evident.

**The caveat that decides whether this actually works.** A pointer's
*current* head is a retention root, so a deploy hook's two calls are enough
to keep the live config alive. Superseded versions are not: the history
entry recording that CID is permanent, but the bytes it names become
collectable once the pointer moves on. That is deliberate — otherwise
nothing would ever be collectable — but it means **reconstructing an old
deployment requires pinning it, not merely having named it**.

`pointer update --pin-history <ttl>` is that pin, folded into the update:
one flag adds a subtree pin `history/<id>/<seq>` over the version just
superseded, expiring after the review window. So the deploy hook really is
two calls — `dag put`, then `dag pointer update --pin-history 2592000` for a
thirty-day flight recorder — and the retention is explicit rather than
hoped for.

**Who consumes it.** Incident review and SOC 2 auditors — both currently
served by screenshots of dashboards and trust in whoever operates them.

**Why this system.** Integration cost is nearly zero: two CLI calls in a
deploy hook buys a flight recorder.

---

## Briefer treatments

The same shapes, compressed:

- **Scientific reproducibility.** Journals increasingly require artifact
  evaluation. An attestation per figure — data, code, environment, result —
  is checkable by a reviewer with no access to the lab. Deterministic re-runs
  (J1) verify claims; the effect cache memoizes expensive simulations so
  verification doesn't mean recomputation.
- **Clinical trials and regulated data.** The flagship use case with a
  different regulator (21 CFR Part 11 territory): trial data immutability,
  amendment history via `supersedes` links, retention for the mandated
  period via TTL pins.
- **Backup tooling.** restic and borg are content-addressed backup; the
  chunker, `file/v1` manifests and sync already are one, as a library.
  Dedup across snapshots is the chunker doing its job.
- **Audit-grade event sourcing.** The pointer log *is* an event-sourced
  system whose events are content-addressed and signable. Where an audit
  log's consumers don't trust its operator, this is the stronger substrate.

---

## Where it does not fit

Claiming everything would discredit the rest, so, plainly:

- **Hot transactional data.** redb is single-writer and every write hashes
  its payload. This is a provenance store, not an OLTP database; put the
  ledger next to the database, not under it.
- **Multi-party Byzantine trust.** Trust is a local keyring by design.
  Where mutually distrusting parties need consensus on ordering, that is a
  transparency log or blockchain problem — this system can feed one, not
  replace one.
- **Planet-scale distribution.** Single node plus directory / gRPC /
  authenticated-HTTP replica. IPFS occupies the other end of that
  spectrum. A Cloudflare Worker with R2 is a replica, not a DHT.
- **Multi-writer document databases.** [Source Network](https://source.network/)
  / DefraDB is the closest cousin — Merkle DAG, CIDs, WASM, offline —
  and is a CRDT document store with IPLD CIDs, DIDs, and a BSL licence.
  They solved distribution and merge. This kernel solved provenance
  plus erasable retention. Becoming them would undo ADR-002/005. See
  [ECOSYSTEM.md](ECOSYSTEM.md).
- **Erasure — a strength, and the edge it cuts both ways.** Unlike a
  blockchain, unpinned content is collectable, so the system offers
  tamper-*evidence* together with the ability to genuinely erase.
  "Tamper-evident but erasable" is a compliance posture most immutable
  systems cannot offer, and it matters wherever a right to erasure applies.
  The same mechanism is why retention has to be got right: what is not a
  root is, by design, free. Roots are pins, live pointer heads, and the
  control plane's own history — everything else is collectable.
- **One process per data directory.** redb locks the database file, so
  concurrent `dag` invocations against one directory queue rather than run.
  `--lock-timeout` makes that a wait instead of a failure, but a workload
  that wants genuine write parallelism against a single directory is not
  what this is. It matters most for §2, where a build tool is exactly the
  shape that would want it.
- **Entry payloads are not chunks.** `Entry.payload` is CBOR-encoded as an
  array of integers, costing roughly 1.9x on disk, so the 4 MiB limit is
  about 2.09 MiB of actual payload for `put-entry`. `dag put` is unaffected —
  it chunks — and this is the path most content takes.

---

## Choosing a wedge

The common thread across every strong fit: **someone who does not trust you
will later ask you to prove what happened, and the proof must be checkable
without access to your systems.** The general market is audits answered by
mathematics instead of by access.

Ranked by where the embedded, no-server form factor is *decisive* rather
than merely pleasant:

1. **Build and compute caching** — proven demand, and the adapter already
   ships.
2. **Agent provenance** — no incumbent; agent VMs (Grok Bot and kin)
   made the market product-shaped. Near-zero new core; the
   distribution runtime is what makes a claim checkable outside the VM.
3. **Legal hold** — the most exact primitive mapping and the most defensible
   position, sold into the slowest market.

Everything else follows one of those three shapes.
