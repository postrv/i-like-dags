# Supply-chain policy

This repository treats a dependency change as a production-code change. A
release revision must commit its Rust and npm lockfiles; CI checks those exact
files, permits only reviewed sources and licenses, fails on
moderate-or-higher npm advisories, and evaluates the full Rust feature graph
against the RustSec database.

## Enforced gates

The `Dependency policy and advisories` CI job installs exact versions of
`cargo-deny` and `cargo-audit` through a commit-pinned installer action.
`cargo deny --locked check` enforces [`deny.toml`](../deny.toml):

- dependencies may come only from crates.io; unknown registries and every Git
  dependency fail;
- licenses must be on the narrow permissive allowlist, including workspace
  crates; a new license requires a reviewed policy change;
- wildcard requirements fail, and the platform OpenSSL/native-tls stacks are
  banned because the system standardizes on rustls;
- RustSec findings fail unless their exact advisory ID and rationale appear in
  the policy; and
- duplicate crate versions are reported for convergence work but do not fail a
  release by themselves. Semver-major crypto transitions and target-specific
  support crates make a blanket duplicate ban impractical; vulnerabilities and
  source/license violations remain hard failures.

The console and edge jobs install exactly their committed npm lockfiles with
dependency lifecycle scripts disabled. A dependency-free lock-policy check
requires npm lockfile v3, sha512 integrity, the official HTTPS npm registry,
and reviewed licenses. MPL/LGPL allowances are confined to named, development-
only lightningcss/sharp binary packages rather than accepted for arbitrary
runtime dependencies. CI then runs explicit build/test steps and
`npm audit --audit-level=moderate`. Pull requests also fail dependency review
at moderate severity. Production installs should use the same lockfiles and
should not replace `npm ci` with an unconstrained install.

The source checkout and the history reachable from the candidate HEAD are
scanned with the Gitleaks 8.18.4 default detection rules. CI verifies the exact
Linux scanner archive, downloads and verifies the exact official generated rule
configuration, removes its sole root global allowlist with one deterministic
transform, and byte-compares the result with the vendored history policy. The
source configuration extends that exact rule policy and adds one reviewed
non-release-path allowlist.

CI then requires an unallowed token-shaped detector probe to fail with the
finding exit code under both checked-in configurations. A paired copy under an
explicitly allowlisted dependency path must return clean under the source
configuration and remain a finding under the history configuration. This
catches scanner, configuration-grammar, extension, and inherited-default drift.
These apparently redundant self-tests are intentional: the Gitleaks 8.30.1
binary available during this review silently accepted the first probe; the upstream regression is documented in
[gitleaks/gitleaks#2170](https://github.com/gitleaks/gitleaks/issues/2170).
Do not update the scanner until the new binary passes the self-tests.

The reviewed `.gitleaks.toml` suppresses findings only for dependency caches,
compiler output, local Cloudflare state, fuzz outputs, and editor/agent state;
it does not waive source fixtures. Gitleaks 8.18.4 still walks and reads those
allowlisted paths. CI therefore scans in a dedicated pristine full-history
checkout before dependency installation, builds, or repository-controlled
commands. A local `--source .` scan can still traverse ignored caches and should
be run from a clean candidate checkout. A secret-like source fixture must be
replaced with a clearly non-secret value or receive a narrowly justified
finding-level exception.

The history scan uses `.gitleaks-history.toml`, which retains every official
8.18.4 detection rule and rule-local exception but deliberately has no global
path or extension allowlist. This keeps a secret in a formerly tracked
build/cache-like path or lockfile from being suppressed. CI also rejects current
tracked files under every source-scan allowlisted path, so a source artifact
cannot be hidden there. Exact upstream and transformed hashes, the transform,
and the upstream MIT license are recorded in
[the third-party notices](../THIRD_PARTY_NOTICES.md).

Secret scanning is a signature/entropy control, not proof that no credential
exists. Release still requires an inventory of CI, Worker, proxy, sync, signing,
and backup secrets plus rotation/revocation procedures outside the repository.

GitHub Actions are referenced by commit SHA. Node, Rust, MSRV, wasm-bindgen,
cargo-deny, cargo-audit, and gitleaks versions are exact in the workflow.
Updating any of those pins is a deliberate artifact/toolchain review, not
routine floating CI maintenance. Dependabot proposes weekly Cargo, npm, and
GitHub Actions updates; every proposal still passes the same lockfile and
policy gates.

## Release boundary

CI has repository read permission only. It does not publish crates, create
GitHub releases, or deploy the Cloudflare Worker, so an untrusted pull request
cannot turn a passing build into a release. Deployment credentials and release
permissions must remain in a separate, protected workflow or operator process.

Before distributing a binary or Worker bundle, release from a clean tagged
commit whose complete CI matrix passed, use the committed lockfiles and pinned
toolchains, record artifact SHA-256 digests, and attach a signed provenance
attestation/SBOM in the release system. The configured workflow is intended to
establish a reproducible, policy-checked candidate only after every required
input is tracked and the complete matrix passes on one frozen revision. This
working tree makes no such claim. The publishing, signing, and provenance
system is not present in this repository today.

Dependabot maintains package and action pins weekly. Exact Node/Rust and audit-
tool pins need an explicit review after upstream security releases (and at
least monthly while shipping), because Dependabot does not manage every value
embedded in workflow inputs.

## The legacy sled exception

The current storage and control planes use redb. `sled 0.34.7` remains as one
direct dependency of `dag-cli` solely so an operator with a pre-redb data
directory can run `dag migrate`. The command runs before normal control-plane
startup and only on an explicitly selected local directory; sled is not called
by the HTTP API, node protocol, worker/daemon request paths, or edge runtime.

RustSec marks two sled transitives as unmaintained:

- `RUSTSEC-2025-0057`, `fxhash 0.2.1`; and
- `RUSTSEC-2024-0384`, `instant 0.1.13`.

These are maintenance-status warnings, not known vulnerabilities. They are
ignored by exact ID in `deny.toml`, and the bans policy permits sled only when
directly wrapped by `dag-cli`. A vulnerability in sled or either transitive is
not covered by those exceptions and fails CI.

Moving migration behind a default-off feature would make ordinary release
binaries unable to follow the documented recovery path. Leaving that feature
on by default would not reduce the shipped graph. A separate migrator binary or
package would change installation and recovery UX and could strand operators
who upgrade in place. The production choice for the compatibility window is
therefore the explicit scoped exception, not a cosmetic feature split.

Remove sled, both advisory exceptions, and the wrapper allowance together once
supported installations no longer need the pre-redb format. Until then the
residual risk is limited but real: unmaintained sled code is linked into the CLI
and processes an operator-supplied legacy database when migration is invoked.
Run migration offline, from a verified backup, and retire the `*.sled.bak`
copies only after validation.

## Local verification

Run the same policy before merging a dependency or toolchain change:

```bash
cargo deny --locked check --hide-inclusion-graph
cargo audit --no-fetch                 # use `cargo audit` when network is available
# Use the checksum-pinned Gitleaks 8.18.4 binary and run all CI canaries first.
gitleaks detect --no-git --source . --config .gitleaks.toml --redact --no-banner
gitleaks detect --source . --config .gitleaks-history.toml --redact --no-banner

cd crates/dag-api/web
npm ci --ignore-scripts --no-audit --no-fund
node ../../../scripts/check-npm-lock-policy.mjs package-lock.json
npm audit --audit-level=moderate

cd ../../dag-edge/worker
npm ci --ignore-scripts --no-audit --no-fund
node ../../../scripts/check-npm-lock-policy.mjs package-lock.json
npm audit --audit-level=moderate
```

Review the lockfile diff as code. Do not add a broader license, registry,
organization-wide Git source, advisory range, or dependency wrapper merely to
make the gate green; record why the specific dependency is required and how it
will be removed or updated.
