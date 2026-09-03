# ADR-006: Two HTTP postures — console vs content plane

**Status**: Accepted
**Date**: 2026-08-21
**Builds on**: the unauthenticated-`dag serve` decision (SYSTEM_OVERVIEW §4),
ADR-002 (no event-import on the human API), ADR-005 (node port is the
authenticated write surface)

## Context

`dag serve` is a human console. It has no authentication, by decision:
loopback by default, same-origin by default, `Sec-Fetch-Site` refusing
cross-site browser POSTs because `POST /api/gc/run` is CORS-simple. That
posture is correct for a viewer on `127.0.0.1`.

It is not correct for anything a browser on another origin, a CDN, or a
wasm verifier should be allowed to reach. Until this ADR the only
control on a non-loopback bind was a warning. The warning does not stop
`curl` from deleting data.

A second need appeared with the wasm verifier and the Edge replica
(ADR-007): **GET-by-CID is self-authenticating**. Serving chunks and
file reassembly to the public internet does not require trusting the
server, because the client re-hashes. Serving GC, pointer writes, job
run, and recovery on the same port does.

## Decision 1: split the routers

`dag-api` exposes two routers, composed from the same handlers:

- **Content plane** — GET health, metrics, stats, chunks, files, entries,
  graph, pointer resolve / history / list, pin list / info / history,
  signatures, usecase verify, events replay. No PUT, no POST that
  mutates the store or the logs.
- **Control plane** — everything that writes, deletes, runs a job, seeds
  a scenario, or rebuilds recovery state. Plus the console SPA.

`PUT /api/chunks` and `POST /api/files` stay off the content plane.
Ingest is the CLI, the authenticated node port, or a Worker that
holds a token (ADR-007). A public upload surface is a different
product.

## Decision 2: `dag serve` refuses non-loopback control

`dag serve` mounts the control router only when the listen address is
loopback **or** the operator passed `--expose-control`.

A non-loopback bind without that flag is a **hard refusal** — the
process exits before the listener is created. This is the same shape
`dag node serve` uses for non-loopback transport without TLS and scoped
credentials.
A warning that operators learn to ignore is not a control.

Loopback behaviour is unchanged: the console still has no
authentication, still binds `127.0.0.1:8080` by default, still refuses
cross-site browser POSTs.

`--expose-control` is an explicit, loud, documented escape hatch for
the operator who has put a proxy in front of the port and accepts
that this process will delete data for anyone who can reach it. It
does not add authentication. That remains a proxy's job.

## Decision 3: `dag content serve` is the public listener

```bash
dag content serve --addr 0.0.0.0:8081
```

Content router only. Safe to bind a public address. No console SPA.
Pointer resolve is served because a verifier that starts from a *name*
needs it, and is documented as **untrusted convenience**: the bytes
behind a CID are self-authenticating; the claim that a name currently
resolves to that CID is not, unless the client walks the pointer-event
chain (each event is an ordinary chunk) or trusts the operator of the
plane. A lying content plane cannot forge chunk bytes. It can lie
about heads. The ADR-007 verify page walks CIDs; it does not take
resolve as gospel.

## Consequences

- The human console and the public content plane can no longer be
  confused for each other. A deployment that wants both runs both.
- ADR-002's objection to "event-import on the human API" is unchanged.
  Import lives on the node port (ADR-005) and on the authenticated
  Worker surface (ADR-007), never here.
- Tests pin the refusal: non-loopback `dag serve` without the flag
  fails before bind; `dag content serve` returns 404/405 on GC and
  pointer POST; loopback `dag serve` still seeds and verifies.

## Not decided here

Authentication on the console. Bearer tokens on `dag serve`. Those
remain proxy-only, as before. The flag is a bind policy, not an auth
system.
