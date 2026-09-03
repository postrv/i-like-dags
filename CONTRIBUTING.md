# Contributing

Copyright 2026 Laurence Avent. Contributions are accepted under the Apache
License, Version 2.0 (see [LICENSE](LICENSE)).

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`), certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

Use the identity you intend to appear in git history. There is no CLA.

## Security

Vulnerabilities go to [SECURITY.md](SECURITY.md), not the public issue
tracker.

## Checks

From the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

Console TypeScript (after `npm ci` in `crates/dag-api/web`):

```bash
cd crates/dag-api/web && npm run check && npm run build
```

Prefer `dag_control::test_utils::TestControl` (feature `test-utils`) over
shelling out to the CLI. Do not add `#[ignore]`. Do not add `todo!()`,
`unimplemented!()`, or `#[allow(...)]` in merged code.

## Documentation

Public behaviour belongs in the README, ADRs under `docs/decisions/`, or
`docs/runbooks/operations.md`. Do not introduce a parallel status or
architecture file.
