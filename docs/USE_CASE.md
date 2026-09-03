# Use case: a model-release provenance ledger

> Run it: `dag usecase seed && dag usecase verify`, or `./scripts/demo.sh`.
> Browse it: `dag serve`.

## The problem

A team ships a fraud-detection model. Six months later, a regulator asks:

> Which exact dataset, configuration and code produced the model that was live
> in production on 12 March? Prove none of it has been altered since.

Answering that from a conventional stack means trusting a chain of mutable
things: a row in a metadata database, a path in object storage, a tag in a
model registry. Each can be edited, and an edit leaves no trace that anyone
outside the system can check. "Prove" becomes "trust our audit table".

## The shape of the answer

Content addressing turns that inside out. If an artefact's identifier *is* the
hash of its bytes, then:

- a reference to it cannot silently start meaning something else;
- anyone holding the bytes can check them, with no access to the system that
  produced them;
- and "what did this depend on" can be recorded as immutable links rather than
  as foreign keys into a mutable table.

What content addressing does *not* give you is a way to say "the current
production model", or a way to stop a cleanup job deleting last year's
evidence. That is what the rest of the system is for.

## Building it

Each step below is what `dag usecase seed` does.

### ① Artefacts become chunks

```bash
dag put --file customers-2026-Q1.csv --content-type text/csv
# 6e23af8c...57f5
```

The CID is the SHA-256 of the bytes. Storing the same file twice is a no-op:
same bytes, same address.

### ② A dataset card wraps the raw data

```bash
dag put-entry --payload '{"kind":"dataset-card/v1","revision":"2026-Q1","rows":2}' \
              --link 6e23af8c...57f5:rows.csv
```

An **entry** is a payload plus named **links** to other CIDs. The payload here
is human-readable metadata; the link is what makes the raw CSV reachable by
traversal. Links are part of the entry's bytes, so they are covered by its CID:
you cannot change what a card points at without changing the card's identity.

### ③ Pointers give the moving parts names

```bash
dag pointer create --id datasets/customer-transactions --cid <card>
dag pointer create --id configs/fraud-detector        --cid <config>
dag pointer create --id code/fraud-detector           --cid <code>
```

A **pointer** is the one mutable thing in the system: a name that resolves to a
CID today and may resolve to a different one tomorrow. Updates append to a log
rather than overwriting, so `dag pointer history` is a complete record of what
the name has ever meant.

### ④ A job attests to what it read

```bash
dag job create --spec attest-release.json
dag job subscribe-pointer --job-id attest-release --pointer-id datasets/customer-transactions
```

The `attest` adapter is deterministic and does one thing: publish an entry that
**links every input it resolved**. Its output is a function of its inputs
alone — no timestamp — so re-attesting unchanged inputs produces the same CID
rather than a near-duplicate.

The job's policy is `CachePolicy::Pin { ttl: None }`. An audit trail
nobody retains is one that garbage collection is free to erase.

### ⑤ Release, revise, release again

```bash
dag job run-once --job-id attest-release
dag pointer update --id models/fraud-detector/production --cid <attestation>
```

Then the dataset gains a row. A new card is published linking both the new CSV
and — via a `supersedes` link — the previous card. The pointer moves. The job
runs again and produces a *different* attestation, because its inputs differ.

Two releases now exist, each with its own attestation, each independently
verifiable.

### ⑥ Retention makes the lineage durable

```bash
dag pin create --id release/fraud-detector/v2 --target <attestation>:full
```

A **subtree pin** on the attestation transitively protects everything the
attestation links: the dataset card, the raw CSV, the config, the code, and the
superseded card behind them. One pin, expressed against one CID, retains an
entire release's evidence — and it does so by walking the links, so it stays
correct as the graph grows.

Compare the scratch pin the example also creates, with a TTL: retention that
expires on its own.

### ⑦ Collection refuses to guess

```bash
dag gc run --dry-run
# Error: recovery not complete; stop the server and run `dag recover` first
dag recover --max-objects 100000 --max-bytes 1073741824
dag gc run --dry-run
```

Pointer/pin/job heads and the chunk, signature and effect-claim indexes are
derived state. A stale or partial view could make collection delete retained
data, so the gate opens only after the complete bounded offline recovery has
reconciled all of them against one verified inventory. Partial pointer/pin
rebuilds cannot certify that state, and there is no remote recovery route. The
ordinary command refuses unsigned pointer/pin/job-shaped store records that are
not already filed. A genuinely lost/truncated database needs an additional
offline `--trust-unfiled-control-events` only after every store writer's
provenance has been verified. Explicit partial `--from-store` rebuilds use the
same 100,000-object/1 GiB defaults and accept `--max-objects`/`--max-bytes`; zero
removes a dimension only for a deliberately sized offline pass.

## Answering the question

```bash
$ dag usecase verify
provenance for models/fraud-detector/production
  root c73d19ee4ff0b7a02da606ef1db9095670e395c82c43b1541c541d1825223b6f
  ✓ c73d19ee…3b6f (root)
    ✓ a8fce5a8…64ce datasets/customer-transactions
    ✓ af7d3032…d3fe configs/fraud-detector
    ✓ 40fde5be…e436 code/fraud-detector
      ✓ 6e23af8c…57f5 rows.csv
      ✓ 88ab0377…d4e0 supersedes
        ✓ b15d8321…562f rows.csv

7 of 7 nodes intact, 2451 bytes, retention: protected
```

The public HTTP form of this walk is fail-closed and finite: at most 500 nodes,
64 MiB of hash-verified bytes, 2,000 examined links and depth 64. It refuses an
oversized lineage instead of returning a partial result that could be mistaken
for complete verification.

Starting from a name, it walks to every byte that release depended on and
re-hashes each one. Nothing outside the data directory is consulted — no
manifest, no database, no index that could disagree with the content.

Corrupt one chunk and the walk says so, exits non-zero, and names the node:

```bash
$ printf 'tampered' > .dag/data/af/7d3032...
$ dag usecase verify
    ✗ af7d3032…d3fe configs/fraud-detector  [CID mismatch: expected af7d…, computed d121…]
6 of 7 nodes intact
$ echo $?
65
```

That is the whole claim: detection needs the bytes and the CID, and nothing
else. A regulator can run it. So can a customer, an auditor, or a future
maintainer who does not trust the current one.

## Which invariant does what

| Question | Mechanism | Invariant |
|---|---|---|
| Can an artefact change under its identifier? | CID is the digest of the bytes | I1 |
| Can a dependency edge be rewritten? | links live inside the entry, covered by its CID | I3 |
| What did this name mean last March? | append-only pointer log | I4, P1–P4 |
| What exactly did that run read? | input manifest recorded at run start | J3 |
| Does re-running give the same answer? | deterministic adapters, no clock in the output | J1 |
| Will the evidence still be there? | subtree pin over the attestation | I5, R3 |
| Could cleanup delete it anyway? | GC honours effective retention, behind a recovery gate | I6, R6 |
| Who did what, when? | one ordered event journal | — |

## Adding *who* to *what*

Content addressing proves the bytes; signatures prove who vouched for them:

```bash
dag key generate --id release-manager --trust
dag sign --cid <attestation> --key release-manager --note "approved for production"
dag verify --cid <attestation>
# ✓ c73d19ee…3b6f
#   ✓ 7ef41a7dba6db7ce  trusted  (release-manager)
```

Signatures are Ed25519 over [DSSE] envelopes carrying [in-toto] statements —
the format the supply-chain ecosystem already verifies — and they are stored
as ordinary entries linking the content they sign, so they are walkable,
pinnable, and collectable like everything else. `dag verify` exits non-zero
unless the content is intact *and* at least one signature verifies against a
key you have explicitly trusted with `dag key trust`.

[DSSE]: https://github.com/secure-systems-lab/dsse
[in-toto]: https://in-toto.io

## What this is not

- **Not a PKI.** Trust is a local keyring populated by explicit `dag key
  trust` decisions. Nothing distributes keys, nothing expires them, and there
  is no transparency log; whose keys you trust is an operational decision the
  system records but does not make.
- **Not tamper-proof storage.** An attacker with write access can delete a
  chunk, or rewrite a pointer log. What they cannot do is change content while
  keeping its CID, so alteration becomes detectable rather than prevented.
- **Not a multi-writer cluster.** Primary/replica replication exists
  (`dag sync`, `dag node serve`; ADR-005). Divergent pointer histories are
  refused, not merged; there is no consensus or CRDT.

## Adapting it

The scenario lives in `crates/dag-api/src/scenario.rs` and is about 200 lines.
The same shape fits anything with the same question underneath it:

- **Security evidence** — pin a subtree per investigation; the attestation is
  the chain of custody.
- **Build provenance** — pointers for `sources/*`, an attestation per release,
  a pin per supported version.
- **Analysis caching** — a pointer per source file CID resolving to its analysis
  output; unchanged input means unchanged CID means a cache hit that cannot be
  stale.

A broader survey — eight domains in order of fit, plus the ones the system is
deliberately *not* for — is in [ALL_USE_CASES.md](ALL_USE_CASES.md).
