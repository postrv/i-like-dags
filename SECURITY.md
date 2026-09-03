# Security

Please **do not** open a public issue for a vulnerability.

Report privately through GitHub Security Advisories:

https://github.com/postrv/i-like-dags/security/advisories/new

Include the affected crate or command, a reproduction, and the impact. We will
acknowledge the report and coordinate a fix before any disclosure.

## By design (not vulnerabilities)

These are standing product decisions, documented in the README and ADRs.
Please do not report them as bugs:

- `dag serve` has **no authentication** on loopback. A non-loopback bind
  without `--expose-control` is refused. Put a proxy in front if the control
  plane must be reachable from elsewhere.
- `POST /api/chunks` is unauthenticated by design on that loopback control
  plane. The public listener is `dag content serve` (GET-by-CID, no writes).
- The `exec` adapter is **not a sandbox**. It is deny-by-default, never
  granted by the HTTP API, and requires an explicit CLI capability
  (`--allow-exec` / `--allow-exec-jobs`). Hostile programs still have the
  host user's authority unless you run the worker in a VM or container.
- Public content serving provides **integrity, not confidentiality**. A CID
  is not an access-control token. Encrypt sensitive payloads before ingest
  or place authorization in front of the content plane.
- Native replication is primary/replica, not consensus or a complete backup.
  Trust keys do not travel with sync.

## Scope

This policy covers the crates in this repository (`dag-core`, `dag-storage`,
`dag-control`, `dag-jobs`, `dag-api`, `dag-net`, `dag-cli`, `dag-wasm`,
`dag-edge`) and their committed tests, Worker source, and console assets.
