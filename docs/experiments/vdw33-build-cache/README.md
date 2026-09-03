# The vdw33 build-cache experiment

The harness and raw results behind the measured section of
[../../PROOF_ARTIFACTS.md](../../PROOF_ARTIFACTS.md). Run on 2026-07-28:
Apple Silicon, 10 cores, 32 GB, Lean 4.10.0, 8 build jobs.

`main.rs` is the ~250-line driver: one exec job per Lean module of the
W(3,3) certificate corpus, inputs declared as a `src/<module>` pointer plus
the transitive import closure as `olean/<dep>` pointers, executed in level
order through `dag_jobs::execute_once_with` with the exec capability
granted in-process. It probes the effect cache with the runner's own key
before each run, so hit/miss in the reports is exact rather than inferred
from timing. It is deliberately not a workspace member: it is an archived
experiment, not shipped code. To rerun it, copy `main.rs` to `src/main.rs`
beside the `Cargo.toml` here, `cargo build --release`, and point it at an
extracted `lean_pkg/` from `vdw33-certificates.zip` (SHA-256
`6a7097b59cde7139cb88f27c4676bbdca33160cd628cab383e1c7ae272b5ffd0`):

```bash
vdw33-exp --data-dir <fresh-dir> --pkg <lean_pkg> --jobs 8   # cold build
vdw33-exp --data-dir <same-dir>  --pkg <lean_pkg> --jobs 8   # warm: all hits
# edit a module, run again: exactly the invalidated chain misses

# ADR-003 legs: builder attests, replica adopts across a trust edge
# (the grant must carry the adopt purpose — ADR-004; bare `key trust`
# grants verification only)
vdw33-exp --data-dir <builder> --pkg <lean_pkg> --jobs 8 --attest
dag --data-dir <builder> sync push --remote <replica>
dag --data-dir <replica> key trust --for verify,adopt --public-key <builder-key-hex>
vdw33-exp --data-dir <replica> --pkg <lean_pkg> --jobs 8 --adopt
```

Each report line's `source` says how the outputs were obtained: `cache`
(local effect-cache hit), `adopted` (satisfied by a keyring-trusted claim,
no execution), or `executed`. The builder key is a fixed demo seed printed
at startup; a real deployment uses `dag key generate` and `--attest-key`.

`results/` holds one JSON line per executed module plus a summary line
(the four archived passes predate the `source` field and say
`"cached": bool` instead):

| File | Pass | Summary |
|---|---|---|
| `cold.jsonl` | cold build, 339 modules | 339 misses, 2,657 s wall |
| `warm.jsonl` | no changes | 339 hits, 12.7 s |
| `passA.jsonl` | comment-only edit of `Vdw33S299` | 1 miss, 86 s |
| `passB.jsonl` | private-theorem rename in `Vdw33S299` | 8 misses (the exact ancestor chain), 263 s |
| `adopt.jsonl` | ADR-003: all 157 leaves on a synced, trusting replica | 157 adopted, 0 executed, 11.3 s |

The sync-replica, directory-copy and revert legs were run interactively;
their summary numbers are in PROOF_ARTIFACTS.md. Note the two effect-key
defects the experiment surfaced (later numbered 13 and 14) are fixed as of
this commit; rerunning against older revisions will measure the defects
instead of the cache.
