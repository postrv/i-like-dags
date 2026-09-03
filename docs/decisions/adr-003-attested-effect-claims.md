# ADR-003: Attested effect claims

**Status**: accepted, implemented (2026-07)

## Context

ADR-002 deliberately keeps job state — including the effect cache — out of
`dag sync`: a source must not write into a replica's private state. The
build-cache experiment (docs/PROOF_ARTIFACTS.md) measured the consequence
precisely: a synced replica holds every output byte yet re-executes every
job, because the key→outputs mappings live in `control.redb` and stay home.
Copying the directory carries the cache; sync does not. So today sync seeds
a *verifier*, and only a physical copy seeds a *builder*.

The gap could be closed by making sync copy the effect-cache table. That is
rejected here, twice over: it violates ADR-002's boundary, and it makes the
receiver *execute on the strength of* mappings whose author it never chose
to believe. A cache entry is a claim — "this effect key produced these
outputs" — and claims from elsewhere are exactly what the signing layer
already knows how to handle.

## Decision

**A shareable cache entry is a signed claim, and adopting one is a trust
decision.**

1. **An effect claim is an ordinary entry** (`effect-claim/v1`): payload =
   the binary effect key plus (name, output CID) pairs; named links to the
   outputs. Deterministic encoding, so the same fact always has the same
   CID and re-attesting is a no-op everywhere (entry, index, signature —
   Ed25519 is deterministic).
2. **Signed with the existing machinery** — a DSSE envelope over the claim
   CID via `SignatureLog::sign`, nothing bespoke — and **pinned as a
   subtree**, which makes the claim *and its outputs* roots for sync and
   GC. Claims therefore travel exactly like any other provenance: no new
   transport, no new tables in flight.
3. **A lookup index** (`effect_claims`: key bytes → claim CIDs) is derived
   state, rebuilt by store scan like the signature index; sync rebuilds it
   at the destination. The index is an accelerator, never an authority.
4. **Adoption is gated four ways** (invariant J7). Outputs are adopted only
   when: the claim decodes and names *exactly* the requested key; a
   signature over the claim verifies against the **keyring's** copy of a
   trusted key — never the key embedded in the record; and every claimed
   output is present with bytes hashing to its CID. Any failed gate
   degrades to "execute normally", silently and safely.
5. **Everything is opt-in per invocation.** `execute_once_hooked` takes
   explicit hooks; the plain paths pass none. The CLI exposes
   `--attest-key <id>` (publish claims) and `--adopt-attested` (consult
   them); the HTTP API exposes neither, mirroring the exec capability
   pattern. With no trusted keys or no flag, behaviour is byte-identical
   to before this ADR.

A claim asserts "this key vouches that this effect key resolves to these
outputs" — vouching, not necessarily executing: a node may re-attest a fact
it verified (a cache hit, or an adoption it validated). Who executed lives
in run records, which remain local.

## Consequences

- `dag sync` can now seed builders, not just verifiers — but only across
  an explicit trust edge: trust the builder's key and its cache entries
  become usable; revoke it (`dag key untrust`) and they instantly are not.
- Trusting a key for adoption means trusting it for *build outputs you
  will consume*. At the time of this ADR the keyring had no per-purpose
  scoping — a key trusted for release signatures was also trusted for
  adoption — which this ADR named as its main known limitation.
  **Resolved by ADR-004**: adoption now requires a grant made with
  `dag key trust --for adopt`, and is never implied.
- Adoption grows the local trusted base (builder key + local store
  integrity), exactly as docs/PROOF_ARTIFACTS.md's refusals section says a
  cache must admit. It stays defeasible: run without `--adopt-attested`
  and everything re-derives from source.
- ADR-002 stands untouched: job state still does not travel. What travels
  is content that happens to be a claim, under the same rules as all
  content.

## Alternatives rejected

- **Sync the effect-cache table**: crosses the ADR-002 boundary and imports
  unattributed claims. No trust story at all.
- **Unsigned claim entries, trusted by reachability**: "it synced from a
  directory I read" is provenance-by-adjacency — the exact laundering the
  signing layer exists to prevent.
- **A separate cache-transport protocol** (Bazel-style remote cache API):
  real machinery for a different product; and it would still need the
  trust story this ADR supplies with parts that already exist.
