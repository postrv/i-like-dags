# ADR-004: Purpose-scoped trust

**Status**: accepted, implemented (2026-07)

## Context

The keyring is flat. `dag key trust` makes a key trusted, and two different
code paths then honour it:

1. **Verification** — `dag verify`, the signatures API: signatures by the
   key earn the *trusted* verdict.
2. **Adoption** (ADR-003) — `--adopt-attested`: effect claims signed by the
   key can substitute outputs for execution.

These grants have different blast radii. Trusting an auditor's key to mean
"their release approvals count" should not also mean "their build outputs
run here", and trusting a CI builder for cache adoption should not add a
vote to a `--min-trusted 2` release gate. ADR-003 named this conflation as
its main known limitation; the at-scale demo made it concrete — the same
`key trust` that made checker verdicts count would also have made those
keys adoptable-from.

The forcing observation: **a trust grant is an authorization, and
authorizations without stated scope grow to their maximum interpretation.**
Every precedent in this space scopes key trust — SSH `authorized_keys`
options, X.509 extended key usage, PGP usage flags. A flat keyring was
fine while there was one consumer; ADR-003 added a second, and the third
will not announce itself in advance.

## Decision

**A trust entry records what it grants, and every consumer asks for the
purpose it needs.**

1. **Purposes name enforcement points, not vocabularies.** A purpose is a
   code path that grants something on the strength of trust. Today there
   are exactly two: `verify` and `adopt`. Predicate-type patterns
   ("trusted for vcot-verdict/v1") are deliberately not purposes — they
   scope *statements*, not *powers*, and a pattern language is a standing
   invitation to matching bugs. If a predicate-level policy is ever
   needed, it composes on top of `verify` rather than replacing it.
2. **The entry stores strings; the code asks with an enum.** `TrustedKey`
   gains `purposes: Vec<String>`; consumers ask `grants(TrustPurpose)`.
   An unrecognized stored string is *inert*, not an error — it matches no
   purpose the code can ask for, so a keyring written by a newer version
   degrades to deny-by-default in an older one instead of failing to read.
3. **Granting defaults to `verify`.** `dag key trust --for verify,adopt`
   spells out wider grants; bare `dag key trust` means what it always
   meant. Adoption — the power to substitute someone's outputs for local
   execution — is never implied.
4. **Legacy entries mean `verify` only.** An empty `purposes` list marks
   an entry written before this ADR — written when trust *meant*
   verification, before ADR-003 silently widened it. Reading legacy
   entries as verify-only restores their original meaning rather than
   grandfathering the over-grant; operators who relied on adoption re-run
   `dag key trust --for verify,adopt` once, making the wider grant an
   explicit decision on record. Grandfathering as all-purposes was
   considered and refused: it would preserve the hole for exactly the
   keys granted while the hole existed.
5. **Re-granting replaces.** The keyring holds one entry per key ID; the
   latest explicit decision wins. No merge semantics to reason about.
6. **Verdicts are purpose-relative.** `SignatureLog::verify_for(cid,
   purpose)` is the primitive; `verify(cid)` keeps its meaning as
   `verify_for(cid, Verify)`. `SignatureStatus.trusted` answers the
   purpose that was asked; the status also carries the entry's effective
   purposes so displays can show the whole grant. Adoption (J7) now
   requires a signature trusted **for `adopt`** — the fourth gate's
   wording tightens from "a trusted key" to "a key trusted for this".

## Consequences

- The ADR-003 demo's replica needs one `dag key trust --for verify,adopt`
  re-grant for its builder key; nothing else changes for it. Checker keys
  from the attestation example keep working untouched — verification was
  always their meaning.
- The keyring's serialization is forward- and backward-compatible: the
  field defaults to empty on old records, and unknown purpose strings are
  inert on old binaries.
- Trust still does not travel (ADR-002); purposes travel with nothing
  because the entries they annotate travel with nothing.
- A future purpose (say, `schedule` for distributed job placement) is one
  enum variant, one enforcement point asking for it, and one line of CLI
  parsing — with old keyrings denying it by construction.

## Alternatives rejected

- **Separate keyrings per purpose** (verify_keys, adopt_keys): two tables,
  two CLI surfaces, and every future purpose doubles the plumbing; a
  purposes field is the same model with one table.
- **Predicate-pattern scoping**: maximum granularity, but it scopes the
  wrong thing (statements, not powers) and imports a pattern language.
  Rejected as a purpose; possible someday as policy layered above.
- **Grandfather legacy entries as all-purposes**: preserves behaviour for
  existing directories at the cost of preserving the exact over-grant
  this ADR exists to close, permanently, for the least-audited entries.
