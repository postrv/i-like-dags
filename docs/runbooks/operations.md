# Operations runbook

How to run a dag deployment in anger: serving, watching, backing up,
collecting, and recovering. Every command here is real; where a behaviour is
a deliberate decision rather than an accident, the reason is stated inline.

## The shape of a deployment

One data directory, one owning process at a time:

```
<data_dir>/
  data/          chunk bytes, sharded by CID hex prefix
  control.redb   chunk index, pointer/pin/job logs, event journal, recovery flags
  keys/          local signing keys (directory 0700, files 0600; never replicated)
```

redb locks `control.redb` to a single process. A CLI command run while
`dag serve` holds the directory fails fast with exit 75; pass
`--lock-timeout <secs>` to queue instead. This is a feature: two writers on
one directory is the corruption you were going to page about later.

Fresh Unix deployments are created owner-only (`0700`) and a fresh
`control.redb` is `0600`, independent of the service umask. Existing paths
are not silently chmodded because group-shared installations can be
intentional; startup logs a `dag::permissions` warning when either grants
group/world access. For a single-service-account deployment, remediate with:

```bash
chmod 0700 /var/lib/dag /var/lib/dag/keys
chmod 0600 /var/lib/dag/control.redb /var/lib/dag/keys/*.json
```

Stored chunks and job configuration may themselves be sensitive. Use a
dedicated account, keep the parent directory private, and apply equivalent
ACLs on non-Unix platforms.

The chunk tree accepts only real two-lowercase-hex shard directories and
regular chunk files at their canonical names. Symlinks and special files at a
shard or chunk position are refused by reads, writes, inventory and collection;
they are never treated as chunks. On Unix, descendant operations are anchored
to an open `data/` directory descriptor, so replacing a shard with a symlink
cannot redirect a read, rename or unlink outside the store. Treat any such
refusal as evidence that the data directory was modified outside `dag` and
investigate before retrying.

Signing-key reads are deliberately strict. A key must be a regular file no
larger than 4 KiB; duplicate or unknown JSON fields are rejected, and its
stored name, public key and key ID must all match the public identity derived
from its secret seed. On Unix, key and directory symlinks and special files
are never followed, key files with any group/world permission are refused,
and a group/world-writable `keys/` directory is refused. Owner-only read-only
secret mounts are supported (`keys/` mode `0500`, key mode `0400`); a
different file owner or a directory that exposes key names produces an
operator warning rather than requiring the mount to be writable.

`dag key list` is also an integrity check: an unreadable, malformed or
inconsistent `*.json` key makes the command fail instead of silently hiding
that identity. Investigate such a file offline and restore it from a protected
backup; do not hand-edit the public metadata independently of the seed.

## Serving

Two listeners, two postures — deliberately different:

| | `dag serve` | `dag node serve` |
|---|---|---|
| Protocol | HTTP + web console + SSE | gRPC (dagnet.v1) |
| Audience | humans, dashboards, scrapers | other dag nodes |
| Auth | none, by decision | scoped current + previous bearer credentials |
| Default bind | `127.0.0.1:8080` | `127.0.0.1:7411` |
| Off-loopback | **refused** unless `--expose-control` | **refused** without TLS and credentials; scoped `--auth-file` is the production posture |
| TLS | put a proxy in front | `--tls-cert` / `--tls-key` |

```bash
# Human/console surface, loopback only
dag serve --addr 127.0.0.1:8080

# Node port for replication, authenticated + TLS
dag node serve --listen 0.0.0.0:7411 \
  --auth-file /etc/dag/node-auth.json \
  --tls-cert /etc/dag/node.crt --tls-key /etc/dag/node.key
```

The node process runs the durable job worker. Its default capabilities are
empty. Add `--allow-exec-jobs` only on a host intentionally allowed to run
command-backed jobs; this is a local worker grant, not a node-RPC scope. A
remote pointer update can activate an existing local subscription only when
its credential separately has both `pointer` and `trigger`.

`/etc/dag/node-auth.json` should be readable only by the service account:

```json
{
  "current": { "token": "CURRENT_BASE64URL_SECRET_AT_LEAST_32_BYTES", "scopes": ["read", "sync"] },
  "previous": { "token": "PREVIOUS_BASE64URL_SECRET_AT_LEAST_32_BYTES", "scopes": ["read", "sync"] }
}
```

Generate random tokens of 32–256 padding-free base64url characters (`A-Z`,
`a-z`, `0-9`, `_`, `-`). Grant only the services that client uses: `read`,
`sync`, `pointer`, and/or `events`. Add `trigger` only to a pointer writer that
may activate destination-local `OnPointerUpdate` jobs; `trigger` by itself
cannot call the Pointers service. `admin` is a wildcard, not a routine default.
To rotate, place the
old current credential in `previous`, add the new current credential and
restart; move clients to the new token; then remove `previous` and restart.
The two rotation slots must contain different plaintext tokens; reusing one
token with different scope lists is refused because the effective grant would
otherwise be the union of both lists. The server stores only token digests
after parsing the file.

Transport input reads are finite: token files are at most 4 KiB, the auth JSON
64 KiB, a TLS private key 256 KiB, and a certificate chain or additional CA
2 MiB. The final path component must be a regular file and cannot be a
symbolic link; directories, devices, FIFOs and sockets are refused before a
read. Point the command at a resolved file when certificate tooling publishes
through symlinks. On Unix, token files, auth JSON and TLS private keys must
grant no world access and must not be group-writable. Group-readable
`root:service` files (for example mode 0640) and files owned by root are
accepted for normal service-manager operation, but group access or an
unexpected non-root owner produces a warning; prefer owner-only mode 0600.
Use equivalent service-identity ACLs on non-Unix platforms. CA certificates
and public certificate chains are not secrets, but receive the same file-type
and size checks.

The legacy `--token`/`--token-file` server route remains for compatibility and
grants `admin`, including trigger authority; migrate it rather than treating it
as the steady state. All
remote client commands resolve a token in this order: `--token`,
`--token-file`, then `DAG_NODE_TOKEN`. With no `--auth-file`, `node serve`
also retains `DAG_NODE_TOKEN` as part of the legacy `admin` route; remove that
environment variable after migrating the server to scoped credentials. The
32–256-character base64url rule is enforced at resolution time for all three
client sources, before any network connection is attempted. A token file may
carry one trailing LF or CRLF; other whitespace is refused rather than trimmed.

Existing auth files with `pointer` remain valid for pointers with no active
subscriptions. Before using that credential to mutate a subscribed pointer,
rotate it to `scopes: ["pointer", "trigger"]`. Pointer publication checks the
active job policy and trigger scope in the same database transaction; refusal
leaves event mappings, head, sync generation, and trigger queue unchanged.
An advisory read rejects the steady-state unauthorized case before storing an
immutable pointer-event object. If a subscription commits in the narrow window
between that read and the definitive transaction, the transaction still rolls
back every mutable row; at most one unfiled, GC-eligible event object can remain.
Legacy admin and no-auth loopback retain their all-scopes compatibility
behavior. Replicated pointer heads published through `Sync` do not enqueue
local jobs, but Commit still needs `trigger` when it advances an actively
subscribed pointer. A sync-only credential remains sufficient for pins and
unsubscribed or idempotent pointer offers.

Plaintext is loopback-only by default on clients and servers. For a remote
development network that cannot use TLS, both ends must explicitly pass
`--allow-insecure-transport`; this sends the bearer token and data in clear
text and is not a production configuration. HTTP sync also refuses redirects,
including HTTPS-to-HTTP downgrade redirects.

`--ca-cert` on a `grpcs://` client augments the platform native trust roots;
it does not pin or replace them. Omit it for publicly issued certificates.
Unary/read/write RPCs have finite deadlines, PutChunk has a 30-second frame
idle and 120-second total bound, and chunk upload/download concurrency is
admitted in aggregate. Event follow streams remain long-lived, but replay
returns at most the newest 500 matching entries after scanning at most 50,000
rows. The server admits one materialized replay and 32 response streams at a
time; an implicit replay that omits older matches ends with `OUT_OF_RANGE`.
Pointer lists are fetched in pages.

The node port defaults to 128 total TCP connections and 16 per source IP.
`--max-connections` and `--max-connections-per-source` tune those ceilings.
The source is the socket's direct `peer_addr()`: behind a trusted L4 proxy,
budget the proxy address explicitly and enforce the real-client policy at the
proxy rather than treating the backend peer address as end-user identity.

If the HTTP API must be reachable beyond the machine, put an authenticating
proxy in front of it and pass `--expose-control` explicitly. Without that
flag a non-loopback bind is a hard refusal. In the default loopback posture,
requests carrying a non-loopback `Host` authority are also refused; this
prevents a browser from reaching the unauthenticated API through DNS
rebinding. The proxy owns authority validation when `--expose-control` is set.
`POST /api/gc/run` deletes data, which is why this opt-in is deliberately
loud.

Both HTTP listeners default to 256 total connections and 32 per direct peer
IP. Tune them with `--max-connections` and
`--max-connections-per-source`; behind an L4 proxy the direct source is the
proxy, so enforce real-client limits there. The backend is HTTP/1. Initial
request headers must complete within the fixed 10-second setup budget;
subsequent keep-alive headers share the 60-second quiescent deadline measured
from the preceding response. The quiescent timer is paused for active handlers,
downloads and SSE. Shutdown force-closes established transports so SSE cannot
retain the process or data-directory lock indefinitely. The application
listener is plaintext; terminate TLS, provide HTTP/2 if required, and enforce
distributed rate/connection policy at the deployment proxy.

An accepted synchronous storage operation is not cancelled when its HTTP
client disconnects. In particular, an admitted GC request may complete durably
after the caller loses the response. Check status/readiness and reconcile the
result before retrying a mutation. Recovery has no HTTP route: stop the server
and run the bounded local `dag recover` command described below.

## Probes

Use **`/health` for liveness**: it only proves the process and HTTP runtime can
answer. Use **`/api/health` for readiness**: it performs bounded reads across
the maintained content index and control tables and returns 503 if that work
cannot be admitted or read. Both return JSON and identify their check type;
readiness also reports whether retention recovery is complete. Every other
unmatched path returns the console's HTML, which a probe would happily call
200, so do not probe `/`.

## Metrics

`GET /metrics` (or `/api/metrics`) serves Prometheus text format:

- `dag_store_put_seconds` / `dag_store_get_seconds` histograms, plus totals
  and bytes — ingest and read latency at the store boundary.
- `dag_gc_runs_total` and **`dag_gc_refused_total`** — a refusal is the
  recovery gate or retention-completeness check holding the line, counted
  apart from failures on purpose. A climbing refusal count means investigate
  the named cause and, when the recovery gate is open, run the complete offline
  recovery below rather than a partial table rebuild.
- `dag_sync_events_refused_total` — a nonzero value is the replication
  trust boundary rejecting divergent or forged history. Investigate the
  *peer*, not this node.
- `dag_http_requests_total{method,route,status}` — labels are matched route
  patterns, so cardinality is bounded.
- `dag_job_runs_pending`, `dag_job_runs_running` and
  `dag_job_trigger_queue` — pending work should drain while a server owns the
  directory. `dag_job_trigger_dead_letters > 0` always needs investigation.
- Gauges (`dag_store_chunks`, `dag_store_bytes`, `dag_pointers`, `dag_pins`,
  `dag_event_seq`, `dag_recovered`) are read from the index at scrape time.

Counters are per-process (they reset on restart); gauges are on-disk truth.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: dag
    static_configs: [{ targets: ["127.0.0.1:8080"] }]
```

## Logs

Diagnostics go to stderr; stdout is always the command's own output.
`RUST_LOG` tunes verbosity. For a log shipper:

```bash
dag serve --log-format json          # or DAG_LOG_FORMAT=json
```

Structured completion lines: target `dag::gc` (chunks examined/deleted,
bytes freed, `duration_ms`) and `dag::sync` (chunks/bytes sent, events,
failures, `duration_ms`).

## Durable job queue maintenance

Pointer-trigger intents, pending runs, active leases, completion receipts and
dead letters are durable. Each pointer-trigger intent freezes the filed job
revision and every static/pointer input in the pointer-publication transaction;
legacy unsnapshotted intents are dead-lettered rather than resolved from current
state. Each admitted run carries that immutable revision and manifest, so a
later job, pointer, or sync update cannot alter already authorized work. Workers select the oldest row
from per-adapter indexes, and the pending queue has a hard 100,000-row cap
checked in the same transaction for direct, on-create and pointer triggers.
Admission fails with backpressure instead of growing the database without a
bound.

Because `control.redb` has exclusive process ownership, every `Running` row at
startup belongs to a dead prior process. Startup fails those rows immediately
even if their recorded lease had not yet expired, avoiding an unsafe automatic
repeat of a side effect. Pending rows keep their immutable revision and are
made claimable again; rows without a revision are never executed. Manual
`run-once` and HTTP admission use the same exact-run lease, heartbeat and token
completion protocol as the background worker. The default node worker has no
execution capabilities, so an `exec` job remains queued until a node is
started with `--allow-exec-jobs`.

```bash
dag job dead-letters --limit 100
dag job compact-dead-letters --dry-run --max-delete 1000
dag job compact-dead-letters --max-delete 1000       # after review

dag job compact-runs --job-id <JOB> --keep-terminal 1000 \
  --max-delete 1000 --dry-run
dag job compact-runs --job-id <JOB> --keep-terminal 1000 \
  --max-delete 1000

dag job unsubscribe-pointer --job-id <JOB> --pointer-id <POINTER>
```

Dead letters are permanent refusals, not retry backlog; inspect their recorded
reason before bounded deletion. Run compaction advances a per-job watermark,
so deleted run IDs are never reused and stale receipts cannot alias a future
run. Watch `dag_job_trigger_dead_letters`, `dag_job_runs_pending` and
`dag_job_runs_running`; a rising pending gauge with no running work usually
means no worker has the capability required by the stored jobs.

Successful completion must return exactly the declared output names in their
declared order. Failed runs store no outputs, and retained failure text is
truncated on a UTF-8 boundary at 16 KiB. Run-history APIs are newest-first,
cursor-paged (maximum 1,000 rows and 2 MiB of encoded items per response).
For a failed `exec` command, the newest 20 lines of stderr are surfaced within
that 16 KiB ceiling and may therefore appear in the durable run record, API
responses and operator logs. Commands must not print tokens, credentials or
other secrets to stderr; protect those records and logs as sensitive data.

## Backup and replication

**Replication is not a complete backup.** It deliberately omits local trust,
private keys, job-run history, subscriptions and the event journal. Use the
snapshot command for disaster recovery:

```bash
# Stop the process that owns /var/lib/dag, then hold its redb lock while every
# immutable object and the complete control database are copied and hashed.
dag --data-dir /var/lib/dag backup create \
  --out /mnt/offline/dag-$(date +%Y-%m-%d)

# Verification checks the exact file set, byte counts and every SHA-256.
dag backup verify --source /mnt/offline/dag-2026-08-23

# Restore is intentionally never in-place. Cut over only after validation;
# the old directory remains the rollback.
dag --data-dir /var/lib/dag-restored backup restore \
  --source /mnt/offline/dag-2026-08-23
dag --data-dir /var/lib/dag-restored index verify
dag --data-dir /var/lib/dag-restored status
```

`backup create` refuses an existing destination, symlinks and special files,
stages beside the destination, fsyncs it, then publishes by atomic rename.
The output/destination parent must already exist. `backup restore` verifies
before copying, validates staged `control.redb` through a read-only redb handle
without creating, repairing, stamping, upgrading, or reconciling it, and
likewise refuses an existing target. The manifest must contain that database
and may not contain an active migration marker, staging file or live sled
database. A completed migration receipt and `*.sled.bak` provenance directories
are copied with the deployment. Verify and restore reject a manifest declaring
more than 1 TiB before hashing deployment files and enforce the same aggregate
ceiling against bytes actually read and copied. Size a larger deployment and
pass a finite `--max-bytes`; reserve `--max-bytes 0` for a deliberately
unbounded offline operation with separately monitored capacity. A backup
contains `keys/`: preserve its
restrictive permissions, encrypt the backup volume, and control it like the
production signing host. The manifest detects corruption or modification
relative to that manifest; keep a copy of its digest in an independent system
if the backup location itself is outside your trust boundary.

The fully durable no-clobber publication contract requires a local filesystem
that implements the requested primitives: Linux, Android and Apple targets use
an OS-level atomic no-replace rename, and Unix targets fsync directory entries.
Other targets use a final existence check plus the platform rename and cannot
portably fsync directories; treat that as a weaker compatibility mode and keep
an independently protected copy until a restore drill succeeds.

Run a restore drill on a schedule. A backup you have not restored is a hope,
not a recovery plan.

Content addressing makes *replication* incremental and every re-run a resume
— there is no transfer journal to corrupt:

```bash
# To a mounted disk (ADR-002)
dag sync push --remote /Volumes/backup/dag

# To another node (ADR-005)
dag sync push --remote grpcs://replica.internal:7411 \
  --token-file /etc/dag/node-token --ca-cert /etc/dag/replica-ca.pem
```

What travels: chunks, pointer/pin history (byte-identical, CID for CID),
signatures, effect claims. What deliberately does not: **trusted keys** (a
source must not decide what its replica trusts), job state, the event
journal, recovery flags, `keys/`.

A partial transfer exits non-zero and names what failed; re-running retries
exactly the missing pieces. Divergent history is refused per event, never
merged — if a push reports refusals, the two sides genuinely disagree and a
human should look.

HTTP Edge pushes use a generated UUIDv4 staging session for pointer/pin
imports and finalize. If no import was attempted, finalize is a local
zero-count result and no UUID or request is created. A definitive structured
import refusal triggers best-effort abort. Busy, recovered/context-changed,
transport, malformed-body, and publication/finalize uncertainty retain the
exact session for bounded idempotent retry; finalize uncertainty is never
aborted. Validation, conflict, capacity, authentication, and invalid-request
codes are terminal for that attempt. The Worker refuses an unknown UUID and
keeps bounded exact receipts for completion, abort, expiry, and validation
refusal. Dry-run conflict probes are authenticated but sessionless.

Two report lines mean different things and deserve different reactions:

- **failures** — a chunk could not be read, sent or accepted. Re-run;
  investigate the disk or the peer if it persists. Exits non-zero.
- **absent at source** — the source's *history* names a chunk the source
  no longer holds, because a collection took the superseded bytes. The
  provenance log still transfers whole; those particular bytes are simply
  gone upstream. Not a failure, and not a reason to exit non-zero — before
  this was distinguished, one routine collection made every later sync fail
  for ever. If you need those versions to survive, pin them
  (`--pin-history` at update time).

**Verify a replica like you mean it:** `dag usecase verify` on the replica,
or `dag verify --cid …` for specific content.

## Garbage collection

```bash
dag gc run --dry-run     # what would go
dag gc run               # collect
dag gc run --record      # collect, and file the report in the ledger
dag gc status --cid <C>  # why is this retained?
```

Each ordinary pass has a default 10,000-deletion ceiling and a complete
inventory ceiling of 100,000 objects and 1 GiB. If the CLI or API reports
deletion `truncated`, repeat the pass until it is false; every pass recomputes
the retention snapshot before deleting. If either inventory ceiling is
exceeded, the pass refuses before any deletion instead of operating on a
prefix. Size the store, estimate the full scan window, take and verify a backup,
stop other writers, and run the explicit offline override only when that
unbounded work is acceptable. Use `--max-delete N` to choose a smaller
reviewable deletion batch. Zero removes the deletion, object and byte ceilings
and is accepted only by the local CLI; HTTP refuses it and `--record` refuses it
so neither a request nor a disposition constructs unbounded state. The HTTP
summary and ordinary human output keep exact counters without retaining an
itemised row per deletion; `--json`, `--show-collected`, and `--record` request
bounded details.

`--record` is for deployments where deletion must be *defensible*: the
report (every collected CID, with size and age) is stored as content behind
a `gc-disposition/v1` entry, chained to previous records under the pointer
`system/gc/dispositions`. Because a live pointer head is a transitive
retention root, the chain retains itself — no pin to remember, and the trail
cannot be collected by the mechanism it documents. Sign it (`dag sign --cid
<record>`) if the disposition needs an authoriser's name on it; replicas get
it with the pointer history.

Default retention is the union of: active pins (with TTL and scope), live
pointer heads (transitively), full DAG closures named by unadmitted trigger
snapshots and pending/running run manifests, filed control-plane history, the
bounded signature index covering protected content, conservative unfiled
control witnesses/roots, and chunks written in the last `--min-age-secs`
(default 60). Active-work rows are pre-decode and aggregate-byte bounded;
the aggregate encoded-snapshot ceiling is 256 MiB, and immutable revision/input
root references must fit the remaining shared GC expansion budget before the
root list grows. Legacy, corrupt, or over-budget active material refuses
collection before deletion. The signature
index retains at most 4,096 entries per target and follows counter-signatures;
recovery deterministically prefers locally trusted and internally valid
evidence. Any overflow signature that must survive collection needs its own
pin.
Unfiled candidate records are not authority: their event/root witnesses remain
protected, but descendants receive protection only after a bounded, complete
closure proof. An unreadable candidate closure or exhausted shared work budget
emits a warning and leaves unproved descendants unprotected; it does not grant
retention to unrelated inventory or stop all collection. Repair or investigate
such candidates before relying on their targets as retained data.
Superseded pointer versions stay *named* in history while their bytes become
collectable — reconstructing an old state needs a pin, not merely a name.
`dag pointer update --pin-history <secs>` adds that pin as part of the
update, which is what a deploy hook wanting a flight recorder should use.

The local/offline `--no-system-protection` option deliberately permits filed
audit-log objects themselves to become collectable. Take and verify a backup
and accept the loss of that history/recovery evidence before using it. The
option does not disable live pointer/pin roots or conservative witnesses for
plausible unfiled events, and the HTTP route cannot request it.

Collection fails closed for authoritative filed roots/state and the complete
inventory: before full recovery is certified, when the inventory exceeds the
object or byte ceiling, and when a filed pointer/pin closure exceeds the
expansion ceiling (`--max-subtree-expansion` raises it). The bounded unfiled-
candidate policy above deliberately does not turn non-authoritative content
into a global stop. The node replication protocol has no GC surface, but the
native control HTTP API does expose `POST /api/gc/run`. The control listener is
loopback-only by default; exposing it requires the documented authenticated/TLS
perimeter. HTTP accepts only finite collection and cannot disable system-data
protection. There is no remote recovery route.

## What it costs at scale

Measured on one machine, recorded in
[`docs/experiments/scale-envelope.md`](../experiments/scale-envelope.md) —
re-run the experiment there rather than trusting these to be current.

The shapes worth planning around:

- **Ingest and collection are I/O-bound on durability**, not CPU. Bulk
  paths (`dag put` of a large file, `dag sync`) defer and batch their
  fsyncs; per-chunk durable writes are roughly an order of magnitude
  slower, which is the price of a chunk being individually crash-safe.
- **Collection cost tracks the whole store**, not the garbage in it: a complete
  pass examines every chunk. Ordinary passes refuse before deleting when more
  than 100,000 objects or 1 GiB would be inventoried. Run collection on a
  schedule, not in a request path, and treat the uncapped CLI mode as an offline
  maintenance operation.
- **`stats()` / `GET /metrics` reads the index**, so a scrape is cheap
  regardless of store size. Nothing else on the scrape path touches the
  filesystem.
- **Replication cost tracks the *referenced* set** — pointers, pins and
  what they reach — not the store. Unreferenced content is not replicated
  at all (ADR-002).

## Recovery

After restoring `control.redb` from backup, after replacing/reindexing the chunk
catalogue, or when the recovery gate refuses collection, stop `dag serve` and
run one complete recovery against a sized inventory:

```bash
dag recover --max-objects 100000 --max-bytes 1073741824
dag index verify           # optional independent full integrity report
```

The defaults cap both store objects/control rows and aggregate store bytes.
Raise a ceiling only after sizing the deployment. Setting one to zero removes
that dimension's limit and is appropriate only in an explicitly sized offline
maintenance window. Recovery first preflights both ceilings, then persists an
in-progress marker before it hashes the complete inventory, atomically replaces
the chunk index, and reconciles pointer, pin, job, signature and effect-claim
state. Any later error or crash leaves that marker in place, so GC stays closed
across restart until a complete retry succeeds.

Ordinary recovery treats the filed pointer, pin and job tables as authority. It
fails closed if the store also contains strict-decoding control records that are
absent from those tables: these legacy records are unsigned ordinary content,
so shape alone cannot grant mutable-name, retention, or job authority. On a
healthy or completely restored database, do not add an override. When the
database was lost or truncated and a verified backup is unavailable, first
establish the provenance of every content-store writer, then make the explicit
whole-inventory trust decision:

```bash
dag recover --max-objects 100000 --max-bytes 1073741824 \
  --trust-unfiled-control-events
```

The flag considers every qualifying pointer, pin and job record in the bounded
inventory; it does not cherry-pick candidates. Malformed, incomplete or forked
histories still make recovery fail, and the durable in-progress marker keeps GC
closed after that failure. Preserve the original directory and prefer restoring
a verified complete backup when writer provenance is uncertain.

`dag index reindex` remains a lower-level repair tool. It validates and hashes a
complete filesystem inventory, then replaces the chunk index in one database
transaction. Because that replacement changes the index generation and
invalidates the recovery verdict, finish such a repair with `dag recover`; do
not substitute independent pointer/pin rebuilds for the complete command.

A **truncated** `control.redb` (interrupted copy, full disk) is caught at open
with a message naming the remedy. Restore the database from a verified backup,
or preserve/move the unreadable file aside and run the complete offline
recovery so every recoverable log and derived safety index is rebuilt from the
content-addressed files in `data/`, using the explicit trust flag above only
after the provenance check. Partial pointer/pin/job commands default to their
filed tables; their store scans require
`--from-store --trust-unfiled-control-events`, preflight the same default
100,000-object and 1 GiB inventory ceilings, and accept
`--max-objects`/`--max-bytes` only with that store-scan mode. Set a dimension to
zero only as an explicit, measured offline opt-out. The partial commands do not
close the full recovery gate.

If `dag` refuses a directory saying the schema is too new: run the newer
binary. Nothing is wrong with the data.

## Upgrades

Stop the process, swap the binary, start. The schema version in
`control.redb` is checked before anything writes; older binaries refuse
newer directories cleanly. Pre-redb (sled) directories from early releases
convert with `dag migrate` — originals are renamed `*.sled.bak`, never
deleted. Treat this as an offline operation:

1. Stop every process that can use the data directory and take a verified,
   independently protected filesystem or volume snapshot of the entire legacy
   directory. `dag backup create` is deliberately a redb-deployment command and
   cannot create this pre-migration safety copy.
2. Run `dag migrate --dry-run`. It preflights every legacy source and every
   possible `*.sled.bak` destination; any existing destination is an error.
   Sled exposes no read-only opener, so dry-run creates no migration artifacts
   but may perform sled's own crash recovery while opening a source.
3. Run `dag migrate`. It locks all live sled databases through validation and
   publication, copies into a private same-filesystem staging file, verifies
   source/stage rows and counts, and runs current schema initialization plus
   chunk/pointer/pin/job recovery before publication. Each renamed backup is
   reopened and checked against the durable source digest before its retirement
   phase is committed.
4. If the command or host stops while the active marker exists, do not move or
   delete the stage, marker, `control.redb`, sources, or backups. Rerun the
   identical command. Normal `Control::open` calls refuse the active marker,
   and retirement of each source is durably journaled and idempotent. If the
   active marker has already become `.control-redb-migration-v1.complete`, the
   transaction committed; use normal `dag status` even if the process lost its
   final success output.
5. After success, verify the deployment normally. Keep the `*.sled.bak`
   directories until the rollback/provenance retention period expires. The
   permanent `.control-redb-migration-v1.complete` directory is the phase
   receipt and should remain with the deployment.

The full crash-consistency proof assumes an access-controlled local filesystem
on Linux or macOS: those targets provide both sled's exclusive process lock,
atomic no-replace rename and directory fsync. Windows cannot portably fsync
directory entries, and the sled/no-replace guarantees are weaker on other Unix
targets; do not claim crash-atomic migration there without a stopped volume
snapshot and a tested platform-specific recovery procedure. Network and FUSE
filesystems must independently guarantee redb-compatible locking, atomic rename
and durable fsync semantics before use.

Schema 5 is the first schema with immutable queued-job revisions and adapter
queue indexes. Upgrading schema 1–4 is one-way: any pre-upgrade Pending or
Running row is terminalised fail-closed because its intended historical job
revision cannot be inferred safely. Schema-1 databases may contain the old
`Updated` event shape without `prev`; the upgrade records a per-job cutoff
derived only from rows already filed in `job_events`, in the same transaction
as the schema stamp. Only those filed sequences receive the compatibility
exception. A future missing-`prev` event is refused, and a database rebuilt
from content alone cannot infer the cutoff, so it reports that legacy chain
for operator recovery rather than accepting it.

Schema 4 introduced atomic sync-generation updates for pointer and pin event
mutations; schema 5 preserves that guarantee. Older binaries refuse a schema-5
directory rather than partially interpreting the new queue and migration
tables, so retain a verified pre-upgrade backup for rollback instead of trying
to downgrade the database in place.

## Security posture, in one place

- HTTP API: unauthenticated by decision, loopback by default. Proxy for
  anything else.
- Public content plane: provides no confidentiality. Chunk/file bytes,
  pointer and pin names/history, signature predicates, event metadata,
  aggregate stats and metrics are readable to any network client. Failed-job
  details are redacted from HTTP replay, but identifiers remain visible. Do
  not bind it publicly for a deployment whose content or namespace is secret;
  put authentication in front of it or keep it private.
- Node port: token always off-loopback and TLS available. The wire exposes no
  job/spec or direct-exec method, GC, or trust-keyring operation. A
  `pointer` + `trigger` credential can activate only a preconfigured local
  pointer subscription; exec also requires the host's local capability grant.
- Exec adapter: deny-by-default capability. Direct CLI execution requires
  `--allow-exec`; the durable node worker separately requires
  `--allow-exec-jobs`. The HTTP API can never execute, even with the feature
  compiled in — there is a test that proves it.
- Trust: `dag key trust` is local and purpose-scoped (`--for verify,adopt`);
  nothing ever imports trust from a peer.
