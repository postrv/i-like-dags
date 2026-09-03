# dag-edge — Cloudflare replica (ADR-007)

Authenticated HTTP destination for `dag sync push --remote https://…`.
Production chunks live in R2. Each pointer and pin has one canonical SQLite
Durable Object. One fixed Catalog object stages replication transactions,
coordinates CAS, accounts retained storage, and caches only atomically
committed public heads. There are no crons, queues, or bucket listings. The
Catalog uses one bounded, persisted alarm solely to reconcile expired R2
upload reservations.

## Deploy a replica

This directory is Worker source, not a hosted service. Deploy your own
Worker from the configuration below and verify `/health` and `/ready` on
**that** hostname. There is no project-operated public replica; a
`workers.dev` preview belongs to whoever deployed it and is not a
canonical endpoint.

A deployed Worker serves a console in the browser: a graph of the resolved
DAG, re-hashed in the tab by a pinned local WASM verifier (capped at 16
nodes and 16 MiB, click-started only). The page does not persist
credentials or graph data.

`GET /c/:cid` and `GET /p/:id` stay public. Writes need
`Authorization: Bearer`.

```bash
curl -s https://<your-worker>/health
curl -s https://<your-worker>/p/models/fraud-detector/production
curl -s https://<your-worker>/c/<cid> | sha256sum
```

A **new** `usecase seed` is a new event log. Pointer events carry a wall-clock
`ts`, so two seeds of the same story produce different event CIDs. A replica
that already has the first seed's history refuses a second seed's push at
those `(id, seq)` positions (HTTP 409, no overwrite, no CRDT). Content CIDs
still match — public resolve and re-hash keep working.

Re-pushing is idempotent only when this directory's *event CIDs* are
the ones already filed (`AlreadyFiled`). A different seed from the one that
first filled the Worker will keep reporting divergent events even after
every content chunk is already on R2. Do not expect the histories to merge.

## Deploy

Run commands from the **repo root**. `wrangler whoami` must show the intended
account. The Worker package pins the tested Wrangler version.

```bash
cd crates/dag-edge/worker
npm ci

# once per account — skip if the bucket already exists
npx wrangler r2 bucket create dag-chunks

# prompted secret; use 32–256 random padding-free base64url characters
# (never put the value in config, shell history, or the command line)
npx wrangler secret put INGEST_TOKEN_CURRENT -c ../wrangler.r2.jsonc

# after the custom route, WAF/rate rules, account budgets, and alerts exist,
# enter exactly: custom-domain-waf-account-limits-v1
npx wrangler secret put DAG_EDGE_PERIMETER_CONFIRMED -c ../wrangler.r2.jsonc

npm run check:deploy
npx wrangler deploy -c ../wrangler.r2.jsonc
```

The R2 binding name in config is `CHUNKS` (what the Worker reads), not
`dag_chunks`. The bucket name is `dag-chunks`. Set the two rate-limit namespace
IDs in `wrangler.r2.jsonc` to positive integers unique within the Cloudflare
account before deployment.

### Credential rotation

`INGEST_TOKEN_CURRENT` is the production ingest credential. For a
zero-downtime rotation, set `INGEST_TOKEN_PREVIOUS` to the old value, set
`INGEST_TOKEN_CURRENT` to the new value, move every client, then delete
`INGEST_TOKEN_PREVIOUS`.
`DAG_INGEST_TOKEN_CURRENT`, `DAG_INGEST_TOKEN_PREVIOUS`, and `DAG_NODE_TOKEN`
are accepted only as one-release compatibility aliases in demo/test mode. In
`production-r2`, a legacy-only configuration or any legacy alias alongside the
scoped names reports `production_ready=false` and authenticated operations
fail with HTTP 503 until only the scoped current/previous names remain. Every
configured active token value must be distinct, including current/previous and
legacy slots; duplicates fail closed as `weak_configuration`.
Tokens must be 32 to 256 padding-free base64url characters
(`[A-Za-z0-9_-]`); missing, non-ASCII, punctuation-bearing, too-short, or
oversized configured or offered tokens fail closed. Well-formed token
comparisons use fixed-size SHA-256 digests, and tokens and their
fingerprints are never logged or returned.

The ingest credential is one full-mutation operator scope: it authorizes chunk
uploads, pointer and pin imports, and every sync mutation. It is not a
per-operation or read-only credential; rotate and distribute it accordingly.

### Production bindings

| Binding | Purpose |
|---|---|
| `CHUNKS` | Private R2 bucket; objects are keyed by SHA-256 CID |
| `POINTERS`, `PINS` | Per-name SQLite Durable Objects |
| `CATALOG` | Fixed committed-name registry and crash-recovery leases |
| `ASSETS` | Exact allowlist source for the pinned verifier JS and WASM |
| `INGEST_RATE_LIMITER` | Per-credential, per-operation write quota |
| `PUBLIC_READ_RATE_LIMITER` | Anonymous read quota |
| `DAG_EDGE_MODE=production-r2` | Makes storage and quota misconfiguration fail closed |
| `DAG_RETAINED_BYTES_LIMIT` | Hard logical ceiling for bytes admitted through this Worker |
| `DAG_RETAINED_OBJECTS_LIMIT` | Hard logical ceiling for distinct admitted CIDs |
| `DAG_EDGE_PERIMETER_CONFIRMED` | Attests that custom-domain, WAF, account budgets, and alerts are active |

`GET /health` is minimal liveness and returns HTTP 200 with
`{"ok":true,"status":"live"}` when the Worker can execute. `GET /ready` is
fail-closed readiness: it returns HTTP 200 only when R2 production mode, a
current scoped credential, both rate bindings, both retained-storage budgets,
Catalog access, and the exact perimeter attestation are present and valid.
It also requires `legacy_heads_pending=0`: registry rows imported from the old
name-only schema are not production-ready until the canonical child head event
has been hash-read, strictly decoded, matched to its derived metadata, and its
live content closure validated. Every other state returns HTTP 503 with
`production_ready=false`. Readiness
exposes aggregate retained bytes, objects, and conservative pending
reservations. It also reports and refuses any publishing snapshot without an
exact validation witness for its revision, never exposing CIDs, names,
sessions, credentials, or exception text. A null witness is the recoverable
legacy shape; a mismatched non-null witness is corruption and stays fail-closed.
Production authenticated operations also enforce the static readiness posture:
current scoped authentication without legacy aliases, R2 and Durable Object
bindings, both rate-limit bindings, both retained budgets, and the exact
perimeter attestation. `/ready` additionally probes Catalog availability; it is
still the deployment/orchestrator health signal rather than a substitute for
real account-side inspection.

The retained ledger reserves capacity before an R2 write and commits it after
the write completes. A CID already in the ledger is never charged twice;
re-uploading it repairs/overwrites the same R2 key. New writes first create a
hidden zero-byte R2 reservation marker, re-confirm Catalog ownership, and then
conditionally replace that exact marker ETag with provider-SHA-256-verified
bytes. An interrupted or ambiguous write remains charged.

The Catalog alarm claims at most 16 reservations per invocation after their
60-second ownership lease expires. Strongly consistent R2 HEAD metadata then
decides the transition: checksum-and-size-valid objects commit; invalid or
ambiguous objects remain charged; stale markers are conditionally replaced by
a random nonempty fence with a different ETag before deletion. Absence starts
a second 60-second grace and is checked again before capacity is released.
This fences a late application writer holding the old marker ETag. Remaining
rows are selected from persisted `reserved_at` order and rescheduled, so no
volatile cursor or unbounded scan is required. Alarm failures keep charges and
schedule a retry. Aborted syncs can still leave immutable, unreferenced chunks,
and those chunks remain charged.

The bucket must be exclusive to this Worker. The conditional fence and fresh
Catalog lease exclude application writers during the final HEAD/delete window;
an administrator or second writer using the bucket API can bypass that
coordination. Restrict bucket credentials and never attach another writer.

This checkout has no destructive GC endpoint. Do **not** apply a blanket R2
TTL: historical events and live DAGs may still name old objects. Operators who
need reclamation must inventory reachability outside the request path, retain
unreferenced candidates for an agreed quarantine window, and delete only
confirmed orphans while reconciling the Catalog ledger. Until that audited
reachability reconciler exists, budgets are the fail-stop and storage is
append-only. The reservation alarm above recovers upload accounting only; it
never decides reachability or deletes content objects. Set R2
usage/spend alerts below the account limit. When upgrading an existing R2
bucket, either deploy against a new empty bucket or seed/reconcile every
existing object into the ledger first; `/ready` cannot infer pre-existing R2
inventory and must not be treated as proof that this migration was performed.

The production config disables `workers.dev` and intentionally declares no
route. Attach an explicitly managed custom domain or zone route before
cutover, enable zone-level **Always Use HTTPS**, and keep the alternate
`*.workers.dev` origin disabled. Keep the route fail-closed, configure
WAF/account-level abuse controls and spend alerts, and monitor Worker errors,
409/429/507 responses, R2
operations, retained-budget usage, and authenticated `/sync/status` phase and
staged counts. The in-Worker rate counters are deliberately
approximate and per Cloudflare location; they complement rather than replace
account-level controls. The production CPU and subrequest ceilings assume a
paid Workers plan.

For an operator-owned R2 preview whose Durable Object heads already
reference objects in `dag-chunks`, use `wrangler.demo-r2.jsonc`. It keeps
the Cloudflare `workers.dev` origin,
uses the bounded demo rate policy, and sets `DAG_EDGE_MODE=demo-r2`; therefore
`/ready` remains HTTP 503 and can never be mistaken for production readiness.
Unlike the KV profile, it preserves consistency between existing heads and
their chunk bytes. Its admitted-write budget is capped at 256 MiB and 10,000
objects, independent of pre-existing legacy objects awaiting reconciliation.

```bash
cd crates/dag-edge/worker
npx wrangler deploy -c ../wrangler.demo-r2.jsonc --strict
```

Temporary Cloudflare accounts cannot create R2. `wrangler.jsonc` deploys a
separately named `dag-edge-kv-demo` Worker and binds KV as `CHUNKS_KV`. KV use
is refused unless `DAG_EDGE_MODE=demo-kv`. The demo config carries approximate
ingest and public-read limiter bindings, but `/ready` always returns HTTP 503
because cross-location reads are eventually consistent and the R2 fencing and
reconciliation protocol is unavailable. Interrupted KV reservations remain
conservatively charged until the same CID is retried. Treat Worker rate limits
as local abuse damping only; temporary-account spend caps and platform
protections remain the operational boundary.

```bash
cd crates/dag-edge/worker
npx wrangler deploy --temporary -c ../wrangler.jsonc
```

## Usage caps (deliberate)

| Cap | Value | Why |
|---|---|---|
| Chunk | 4 MiB | I2 |
| `/sync/missing` request | 4096 | production protocol ceiling; duplicate CIDs are removed |
| Free/demo unique CIDs | 900 | server/client cap below the 1000 internal-subrequest ceiling |
| Events per pointer/pin | 10 000 | one DO cannot grow without bound |
| Catalog names | 4096 | finalize counts names; never `R2.list()` |
| Events staged per sync | 4096 | keeps resumable publication below the 5000-subrequest fail-stop |
| Distinct pointer/pin groups | 700 demo / 4096 production | leaves request budget for Catalog, child DO, R2, and response work |
| Prepublication lease | 5 minutes sliding | abandoned staging is discarded; publishing never expires |
| R2 upload lease / absence grace | 60 seconds / 60 seconds | fences stale writers before releasing missing reservations |
| Reservation reconciliation | 16 reservations per alarm | bounded R2 retries, persisted ordering; failures stay charged |
| Entry links parsed | 100 000 | schema-aware hard work ceiling; excess returns HTTP 422 |
| Inspection links retained | 256 | prevents `/i/:cid` memory/JSON amplification; total count/truncation are reported |
| Inspection link name | 256 UTF-8 bytes | larger labels are omitted from output |
| Retained production bytes | 10 GiB in example config | operator-selected hard logical budget |
| Retained production objects | 100 000 in example config | distinct-CID budget; repeated CIDs do not charge again |
| Object-store concurrency | 6 | matches the per-invocation open-connection ceiling |
| Production subrequests | 5000 | explicit per-invocation fail-stop below the paid default |

Flush is a 204 no-op (a completed R2/KV PUT is the durability barrier). Request
bodies are counted while streaming and canceled at the limit. Reads reject
oversized or hash-invalid stored objects. Entry inspection validates every link
without materializing more than the 256-link result prefix; inputs beyond its
structural ceiling return `inspection_limit_exceeded`. The Worker does not
retry, call itself, or run jobs or GC.

## Atomic HTTP sync contract

The HTTP client generates one UUIDv4 per push and sends it as
`X-Dag-Sync-Session` on each `POST /sync/import/pointer`,
`POST /sync/import/pin`, and `POST /sync/finalize`. Imports keep their existing
JSON body (`{"id":…,"seq":…,"cid":…}`) and return `{"filed":true|false}`,
but they write only hidden Catalog staging. Public resolve continues to read
the old committed Catalog head, and canonical child logs are untouched.

Finalize has an empty body. It validates the complete closure of every final
pointer and applicable active, unexpired pin before freezing the exact session
revision. `Global` pins and `Local { node_id: "local" }` pins are applicable;
other local-node pins are an explicit capability boundary and do not retain
content in this Edge deployment. Pointer event payloads are capped at 4 KiB;
historical pin payloads retain native's enclosing-chunk (4 MiB) compatibility
boundary. Control event Entries must be payload-only, without links or
metadata. The Worker then idempotently copies each name to its child DO in
bounded waves, durably records per-child progress, and flips all Catalog
heads/membership in one SQLite transaction. A crash can
therefore leave copied child rows, but they are not public. Publishing has no
expiry and cannot be aborted; a later authenticated client, even with another
UUID, can resume the frozen snapshot. Before freeze, `POST /sync/abort` with
the same header and an empty body discards staging. Another live session or CAS
returns structured HTTP 409 `sync_busy` with `Retry-After`. Staging expires
after five idle minutes. The Catalog retains a bounded 1024-session terminal
receipt table: a lost successful finalize replays the exact prior counts;
validation failures, aborts, and expiries replay their exact typed refusal;
and retained terminal UUIDs cannot be restaged. After receipt eviction, a
stale finalize remains fail-closed as `sync_session_unknown`; only a new
authenticated import may explicitly start staging with that UUID. Chunk PUT,
missing, and flush remain sessionless: immutable orphan chunks are safe and
still count against retained budgets.

A legacy `publishing` snapshot without a durable validation witness is
revalidated before any child publication resumes. If that exact owner/revision
fails validation, the Catalog atomically records the typed terminal refusal and
deletes its hidden staging; it never clears a witnessed publication or a newer
revision. `/ready` stays false while this recovery is pending and also for a
non-null witness that does not exactly match the publishing revision; that
corrupt state is reported unavailable rather than automatically discarded.

Authenticated dry-run support is sessionless and read-only:

- `POST /sync/probe/pointer` or `/sync/probe/pin` accepts
  `{"events":[{"id":…,"seq":…,"cid":…}]}` and returns divergent committed
  mappings as `{"conflicts":[{"id", "seq", "offered", "existing"}]}`.
- `GET /sync/status` returns only aggregate phase/count data.

Probes take a short read lease, are capped at 4096 offers, 700 distinct names,
and 512 KiB, skip unknown Catalog names without instantiating child DOs, and
return `sync_busy` rather than race a mutation.

## Tests

```bash
cd crates/dag-edge/worker
npm ci --ignore-scripts --no-audit --no-fund
node ../../../scripts/check-npm-lock-policy.mjs package-lock.json
npm run typecheck
npm test
npm run types:check
npm run check:deploy
```

The runtime suite executes the Worker, R2, static assets, and SQLite Durable
Objects under Cloudflare's workerd-based Vitest pool. Its test-only
compatibility date is one day behind production because the pinned pool's
bundled workerd currently supports dates through 2026-08-22.
`worker/wrangler.test.jsonc` has no credential or public route and disables
`workers.dev` and preview URLs; the fixed non-secret test credential is
injected only into the local Miniflare process by `worker/vitest.config.ts`.
The same local-only injection supplies the R2 harness sentinel: a mistaken
deployment of the test config cannot open its bucket and fails closed. Do not
attach that test Worker through a service binding; delete any accidental
deployment rather than trying to make it usable.

The verifier assets are served through two exact pathname routes with
digest/SRI-versioned query strings and immutable caching. Regenerate the
browser manifest and committed assets together on upgrade; the pinned JS/WASM
integrity checks fail closed if HTML and cached assets do not match.
