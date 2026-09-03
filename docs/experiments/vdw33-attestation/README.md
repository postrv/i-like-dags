# The dual-checker attestation example, run

> The worked example from docs/PROOF_ARTIFACTS.md option 1, executed
> 2026-07-28 against the same data directory that holds the W(3,3) shard
> corpus and its effect claims. Every CID below is real; every verdict was
> produced by actually running the oracle named. One directory now holds
> sources, built artifacts, effect claims, certificates, and verdicts —
> and a stranger with a copy can check all of it from the bytes.

## What was attested, and by what

The subject is `fable_zebra.proof.json` — the 193-step vcot certificate
authored by Claude Fable 5 through the typed gate (the papers' flagship
LLM artifact) — plus its compiled Lean form and its unedited transcript.
Three oracles ran here, for real:

| Oracle | Invocation | Verdict |
|---|---|---|
| `vcot-check` (Rust, zero-dep, built natively arm64) | 193 steps in 0.002 s | accepted |
| `checker.py` (vcot v0.2.1, CPython) | same conclusion, byte-identical rendering | accepted |
| Lean 4.10.0 (core toolchain) | `lean fable_zebra.lean`, 14.2 s | accepted |

## The store contents

Single-chunk artifacts have CID = SHA-256 of their bytes, so for them the
store's name *is* the paper's published hash:

```
fable_zebra.proof.json   a1c3473a09925e92b7c0bb7cb425e1f4afc25d2d058ef66890443d3f9d9e0988
fable_zebra.lean         1089c442b746a51a4327dfcb60bd8be86ce3b6ac7e6b442ec8f8d20730ed7f1d
fable_zebra transcript   e17d4525281ae4813eccd1bcd8e8a044d17b30bccceb5e17c235546f1af8b830
vcot v0.2.1 source zip   12570a58f9d64da9c40ab478d6a2c372b3022a9f2c56da072a407b699aab2c02
vcot-check binary        8bee26e42dad1dc944581ca28254c9b8ca21d72634f3acd68170dfa4c9921505
vdw_3_3_27.proof.json    0c15443f4d774e624b43a091240f023cfbbed564af3c1527168fc1ee9a1ca0f0  (file/v1 root; 30 MB, chunked)
vdw_3_3_26.witness.json  0795bd0afad96710de2ca266169f7e1a01eb86f4d9e7c360fde29548df30889e  (= the hash in the paper's table)
```

The witness CID equals the published SHA-256 verbatim. The 30 MB W(3,3)
proof is chunked, so its root is a manifest CID; reassembly reproduces the
published flat digest `c86cc8c8…694b1`, which the corpus card records.

Two certificate cards tie the artifacts together (entries with named
links), each behind a pointer and a full-subtree pin:

```
vcot/fable-zebra -> 534b29b5a2fd1e05d350417de01cd7d890a3dfb1bcf361ba2f98f982c3aedf96
                    links: proof, lean, transcript, checker-source, checker-binary
vdw33/corpus     -> e6d2954c9cd3ec376b40665fcecc69eac130000d9450d7ae9a437234a97082b8
                    links: proof, witness
```

## The attestations

Each oracle has its own Ed25519 key (`dag key generate`), and signs with a
structured predicate (`dag sign --predicate`) rather than prose. The
checker predicates name the checker implementation *by CID* — the source
zip, and for the Rust checker its zero-dependency binary — so "verified by
vcot-check" bottoms out in content addresses, not names:

```bash
dag sign --cid a1c3473a… --key checker-rust --predicate '{
  "type":"vcot-verdict/v1","checker":"vcot-check",
  "implementation":{"source_zip":"12570a58…","binary":"8bee26e4…","platform":"arm64-apple-darwin"},
  "calculus":"vcot v0.2.1","verdict":"accepted","steps":193,"wall_s":0.002}'
dag sign --cid a1c3473a… --key checker-python --predicate '{…"checker":"checker.py"…}'
dag sign --cid 1089c442… --key lean-oracle    --predicate '{"type":"lean-accept/v1","toolchain":"leanprover/lean4:v4.10.0",…}'
dag sign --cid e6d2954c… --key lean-oracle    --predicate '{"type":"lean-accept/v1","scope":"all 339 W(3,3) modules…","evidence":"effect claims under builder key 91a28a0b…"}'
```

## The gate

"Two independent checkers held to exact agreement" is now one exit code:

```
$ dag verify --cid a1c3473a… --min-trusted 2
✓ a1c3473a…0988
  ✓ d13a4eb8fc32ab1a  trusted  (checker-rust)
  ✓ 78ddafd4e098bdb9  trusted  (checker-python)
2 signature(s): 2 trusted, 2 valid        exit 0

$ dag verify --cid a1c3473a… --min-trusted 3   # more agreement than exists
                                          exit 65
```

## Trust does not travel — shown live

`dag sync` carried the cards, the artifacts, and all four attestations to
the replica (which already trusted only the *builder* key from the
build-cache experiment). Verification there, before and after the
operator's own trust decisions:

```
replica$ dag verify --cid a1c3473a… --min-trusted 2
2 signature(s): 0 trusted, 2 valid        exit 65   # arrived valid, vouched by nobody
replica$ dag key trust --public-key 788438b4… --comment "python checker"
replica$ dag key trust --public-key a3e21f9a… --comment "rust checker"
replica$ dag verify --cid a1c3473a… --min-trusted 2
2 signature(s): 2 trusted, 2 valid        exit 0
```

## Honest scope

The W(3,3) certificate itself is *not* dual-checker attested here: it uses
the clause rules (`OR_UNIT`/`OR_CONFLICT`) added in the vdw33-era engine,
and every checker snapshot on this machine (v0.1, v0.2.1) rejects it with
`unknown rule 'OR_UNIT'` — both checkers agreeing exactly, on the
rejection. Its checker verdicts belong to whoever runs the vdw33-era
artifact package. What is genuinely attested here is its load-bearing
oracle: Lean 4.10.0 elaborated all 339 modules on this machine as this
directory's shard-build jobs, and the lean-oracle attestation over the
corpus card names the effect claims as evidence. The papers' own trust
model says the in-loop checkers are redundant and Lean is the guarantee;
the attestation set mirrors that structure exactly.
