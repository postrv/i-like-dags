# i-like-dags

Content-addressed storage with first-class versioning, retention and jobs.
Single binary, single data directory, no daemon required.

Content addressing alone gives you immutability. This adds the parts you need
to build something on top of it: **pointers** (mutable names with an
append-only history), **pins** (retention expressed as data), **jobs** (which
record exactly what they read), and **one ordered event journal** over all of
it.

```bash
cargo build --release

# Load a worked example and prove its lineage
./target/release/dag usecase seed
./target/release/dag usecase verify

# Or browse it
./target/release/dag serve      # http://127.0.0.1:8080
```

## Model

| Concept | What it is | Mutable? |
|---|---|---|
| **Chunk** | Bytes, ≤ 4 MiB, addressed by their SHA-256 | never |
| **Entry** | A payload plus named links to other CIDs (CBOR) | never |
| **File** | A bounded manifest entry over content-defined chunks | never |
| **Pointer** | A name resolving to a CID, with full history | yes, append-only |
| **Pin** | Retention over a CID or its subtree, with scope and TTL | via events |
| **Job** | An adapter over resolved inputs, recorded per run | — |
| **Event** | One journal of every change above | append-only |

The 4 MiB limit is per *chunk*, not per file. `dag put` on anything larger
splits it with FastCDC content-defined chunking behind a `file/v1` manifest;
`dag get` reassembles and re-hashes every byte on the way out. Because chunk
boundaries come from the content, revision N+1 of a large artefact stores only
what changed — appending 2 MB to a 50 MB model stores ~2 MB. One subtree pin
(`--target <manifest>:full`) retains the whole file.

Signatures add *who* to the *what*: `dag sign` stores an Ed25519 signature —
a [DSSE](https://github.com/secure-systems-lab/dsse) envelope over an
[in-toto](https://in-toto.io) statement, verifiable by external supply-chain
tooling — as an ordinary entry linking the signed CID. Trust is a local
keyring (`dag key trust`); `dag verify` demands intact content plus at least
one trusted signature. Secret keys live under `<data_dir>/keys/` (directory
mode 0700, files 0600 on Unix) and never travel with replication.

Everything lives under one data directory (default `.dag`):

```
.dag/
  data/          chunk bytes, sharded by CID prefix
  control.redb   everything else: CID index, pointer/pin/job logs,
                 event journal, recovery flags — one table each
```

Upgrading from a pre-redb release? Stop every process using the directory and
take a verified filesystem/volume snapshot of the whole legacy directory first
(`dag backup create` intentionally requires an existing redb deployment). Then
run `dag migrate --dry-run` followed by `dag migrate`. The command stages a
mode-0600 redb file on the same filesystem, checks every copied row, runs schema
validation and the normal rebuild/recovery path, and only then publishes it.
The originals are not renamed or deleted until publication and are retained as
`*.sled.bak`; an interrupted run with an active marker blocks normal opens and
resumes by rerunning the same command. It never overwrites an existing backup.
A successful run preserves its phase journal in
`.control-redb-migration-v1.complete`.

## Worked example

[`docs/USE_CASE.md`](docs/USE_CASE.md) builds a **model-release provenance
ledger**: datasets, configs and code as content; pointers naming each; a
deterministic job that attests to what it read; a subtree pin retaining the
whole lineage; and a verification pass that walks a release back to every byte
it depended on and re-hashes each one.

```
$ dag usecase verify
provenance for models/fraud-detector/production
  ✓ c73d19ee…3b6f (root)
    ✓ a8fce5a8…64ce datasets/customer-transactions
    ✓ af7d3032…d3fe configs/fraud-detector
    ✓ 40fde5be…e436 code/fraud-detector
      ✓ 6e23af8c…57f5 rows.csv
      ✓ 88ab0377…d4e0 supersedes
        ✓ b15d8321…562f rows.csv

7 of 7 nodes intact, 2451 bytes, retention: protected
```

`./scripts/demo.sh` runs the whole story end to end, including tampering with a
chunk on disk and watching verification catch it.

For the full picture — what is built, why it is shaped the way it is, and the
roadmap with its open choices — see
[`docs/SYSTEM_OVERVIEW.md`](docs/SYSTEM_OVERVIEW.md).
[`docs/ALL_USE_CASES.md`](docs/ALL_USE_CASES.md) surveys the other domains the
same primitives fit, and the ones they deliberately do not.
[`docs/ECOSYSTEM.md`](docs/ECOSYSTEM.md) places the kernel next to agent VMs
(Grok Bot and kin) and Source Network.

## Web console

`dag serve` starts an HTTP API and a web console on the same port.

- **Overview** — live stats, activity feed, collection dry-runs, verification
- **Explorer** — walk the link graph from any CID or pointer; every node is
  re-hashed as it is read, and retention is shown inline
- **Pointers** — resolve, and read the history of what a name has meant
- **Pins** — what is retained, by what, until when
- **Jobs** — specs, runs, and the exact input revisions each run resolved
- **Events** — the journal, live over server-sent events

The console is TypeScript compiled by `tsc` (no bundler, no runtime
dependencies) and embedded in the binary, so there is nothing to deploy
alongside it. To work on it:

```bash
cd crates/dag-api/web
npm install && npm run watch   # then rebuild the Rust crate to re-embed
```

The compiled output in `web/dist/` is committed, so `cargo build` never needs
Node. CI recompiles it and fails if the checked-in output has drifted.

### HTTP collection bounds

Collection reads are cursor-paged; they never mean "materialise the whole
deployment". `GET /api/pointers`, `/api/pins`, and `/api/jobs` return:

```json
{"items": [], "next_cursor": null, "truncated": false}
```

Pass the opaque `next_cursor` back as `cursor`. `limit` defaults to 100 and
must be in `1..=200`; an out-of-range limit is a 400, never silently clamped.
`truncated` is true exactly when `next_cursor` is present. Pointer and pin
histories use the same envelope; `from` is inclusive, `to` is exclusive, and
a cursor cannot be combined with a non-default `from`. Resend the same `to`
with each cursor to preserve a caller-selected upper bound; when `to` is
omitted, each request reads only as far as the head it observes. Signature
pages retain their `signatures` field and add `next_cursor`, `truncated`, and
`trusted_complete`; `trusted` is a safe distinct-key lower bound on partial
pages and is exact only when `trusted_complete` is true.

`GET /api/jobs/runs` uses the same page envelope. Its numeric `cursor` is the
exclusive run sequence below which to continue (newest first), and `limit`
must be in `1..=1000`; zero, malformed cursors and larger values are rejected
instead of silently clamped. Every schema-5 run exposes the immutable filed
job-event revision selected when it entered the queue.

A page also has a 2 MiB encoded-item budget. Reaching it returns a continuation
after the last included record. If one oversized legacy record cannot fit by
itself, the endpoint returns 413 with a repair/removal message, ensuring a
client cannot become stuck in a cursor loop that never advances. Graph reads
return at most 500 nodes and 2,000 edges; pointer annotations inspect at most
200 heads and set `pointer_labels_truncated` when labels are partial.
The public worked-example verifier runs on the finite blocking-work pool and
refuses rather than truncates at 500 nodes, 64 MiB of hash-verified bytes,
2,000 examined links, or depth 64; internal filesystem errors are logged but
not returned to anonymous callers.

Public `GET /api/events` replay returns at most 500 envelopes, scans at most
50,000 durable rows for selective filters, and refuses an encoded response
larger than 4 MiB with 413. Only one materialised replay is admitted at a time,
with that slot held until its body is consumed or dropped. Journal envelopes
are limited to 64 KiB before persistence and checked at that same bound before
decoding. Replay responses retain `scanned` and `scan_truncated`, so a filtered
short page is not mistaken for proof that no older match exists.

> The console (`dag serve`) has **no authentication** on loopback,
> deliberately. A non-loopback bind without `--expose-control` is refused
> outright (ADR-006), because `POST /api/gc/run` deletes data. The public
> listener is `dag content serve`: GET-by-CID, no writes, no console. If
> the control plane must be reachable from elsewhere, put a proxy in
> front of `--expose-control`.
>
> That decision is why the browser-side controls are not optional. No origin
> but the server's own is granted anything: there is no
> `Access-Control-Allow-Origin`, and an API request a browser reports as
> cross-site (`Sec-Fetch-Site`) is refused outright — otherwise any page you
> visited could `POST /api/gc/run` on your localhost. `--allow-origin
> <ORIGIN>` grants specific origins if you genuinely embed the API elsewhere;
> `*` is not accepted. Non-browser clients (curl, `dag` itself) are unaffected.
> Downloads from `/api/files` are served `attachment` with `nosniff` and an
> inert content type, so stored content cannot execute as the console.
>
> `POST /api/chunks` is capped at 4 MiB (`MAX_CHUNK_SIZE`), the JSON
> endpoints at 256 KiB, and whole-file HTTP transfers at 1 GiB. Larger local
> file operations use a 64 GiB default ceiling. Files stream through
> `/api/files` without whole-body buffering:
>
> ```bash
> curl -X POST -T model.safetensors 'http://127.0.0.1:8080/api/files?content_type=application/x-model'
> curl -o model.safetensors 'http://127.0.0.1:8080/api/files?cid=<CID>'
> ```
>
> Upload streams through the chunker without buffering; download streams the
> reassembly, re-hashing every chunk, with `Content-Length` set from the
> manifest — a verification failure aborts the stream short, so corruption is
> detectable as truncation, never silently delivered. Upload bodies also have
> a 30-second idle timeout and 30-minute overall deadline, and share the
> server's finite blocking-work admission pool.

## CLI

```bash
dag put --data "hello"                    # or --file / --stdin
dag get --cid <CID> --out ./out.bin
dag put-entry --payload '{}' --link <CID>:name
dag get-links --cid <CID>

dag pointer create|update|resolve|head|history|list|rebuild
dag pointer update --id <P> --cid <C> --pin-history 2592000   # flight recorder
dag pin     create|deactivate|list|info|history|rebuild
dag job     create|update|trigger|run-once|runs|list|subscribe-pointer|unsubscribe-pointer|adapters
dag job     dead-letters|compact-dead-letters|compact-runs
dag gc      run|status
dag events  tail --follow --since 2026-08-04T09:00:00Z --filter pointer,pin,job
dag index   stats|verify|reindex

dag key     generate|list|trust|untrust      # signing identities + keyring
dag sign    --cid <CID> --key <name>         # Ed25519 over a DSSE envelope
dag verify  --cid <CID>                      # intact + trusted signature, or exit 65
dag signatures --cid <CID> --out-dir <D>     # export envelopes for external verifiers
dag signatures --import <dsse.json>          # accept one minted elsewhere

dag job run-once --job-id <J> --allow-exec   # run a command-backed job

dag sync    push|pull --remote <dir|grpcs://host:port|https://edge>  # replicate either way

dag node serve --listen 127.0.0.1:7411    # the authenticated port other nodes talk to
dag node info  --remote grpc://host:7411  # ping another node
dag pointer resolve|update --remote …     # read, or compare-and-set, on another node
dag events tail --remote grpc://…         # follow another node's journal

dag status                                # summarise the deployment
dag usecase seed|verify
dag serve --addr 127.0.0.1:8080           # console; non-loopback needs --expose-control
dag content serve --addr 0.0.0.0:8081     # read-only content plane (ADR-006)
dag backup create|verify|restore           # complete offline snapshots
dag migrate [--dry-run]                   # convert a pre-redb data directory
```

Add `--json` (or `--pretty`) to any command for machine-readable output on
stdout; logs and progress always go to stderr. Exit codes follow BSD sysexits:
`66` not found, `65` bad data or failed verification, `69` unavailable (a
remote node unreached, or an adapter this build lacks), `74` I/O, `75` a
timeout, `77` a capability not granted (add `--allow-exec`), `78` recovery
incomplete, `70` otherwise.

Ready-made job specs live in `crates/dag-cli/examples/`. `dag job adapters`
lists what this binary can run; anything it marks `SIMULATED` is a test double
that fabricates its output. Only `fake_fetch` is — it exists so the
side-effecting caching paths are demonstrable without a network. **There is no
HTTP adapter**; fetching a URL means running one through `exec`, below.

## Running real work: the `exec` adapter

Jobs can run a local command over their resolved inputs, which is what turns
provenance tracking into a pipeline. Inputs are materialised as files (a
chunked file arrives reassembled), declared outputs are read back as content,
and the run records exactly which pointer revisions were read:

```jsonc
// crates/dag-cli/examples/job.exec-wordcount.json
"code_ref": "exec",
"config": {
  "command": "sh",
  "args": ["-c", "wc -lwc < 'inputs/datasets~customer-transactions' > outputs/report.txt"],
  "outputs": { "report": "outputs/report.txt" },
  "capture_stdout": true,
  "timeout_secs": 60
}
```

```bash
dag job create --spec crates/dag-cli/examples/job.exec-wordcount.json
dag job run-once --job-id wordcount --allow-exec
```

Because exec is side-effecting, its effect key covers the command, arguments,
environment *and* the resolved inputs — so re-running the same command over
unchanged inputs serves the cached outputs instead of re-executing, giving
build-cache semantics. `CachePolicy::None` does not change that; drop the
effect cache entry or change the inputs to force a re-run.

> **`exec` runs arbitrary commands with no sandbox.** The library feature is
> off by default; the shipped CLI compiles it in but grants no execution
> capability unless `--allow-exec` is passed for a one-shot run or
> `--allow-exec-jobs` is passed to an intentional worker host. It is **never
> reachable through the HTTP API** — `dag serve` has no built-in
> authentication, so browser-origin controls cannot be process-execution
> authority. The child gets an empty environment plus a minimal
> `PATH` (so parent secrets are not inherited), a fresh temp working
> directory, no shell interpretation of arguments, and a wall-clock timeout.
> Filesystem, memory, CPU and network isolation are **not** provided — run
> `dag` in a container if you need them. Full threat model in
> `crates/dag-jobs/src/exec.rs`.

## Garbage collection and the recovery gate

Pointer, pin and job heads plus the chunk, signature and effect-claim indexes
are derived state. Collection refuses to run until one complete recovery has
reconciled all of them against the same verified store inventory and recorded
the current chunk-index generation. Stop the server and run the bounded offline
command; the ordinary limits are 100,000 objects/control rows and 1 GiB:

```bash
dag gc run                 # Error: recovery not complete  (exit 78)
dag recover --max-objects 100000 --max-bytes 1073741824
dag gc run --dry-run       # now permitted
```

Raise either recovery ceiling only after sizing the deployment. Zero removes
that dimension's ceiling and is intended only for an explicitly sized offline
maintenance window. By default recovery refuses to promote unsigned
pointer/pin/job-shaped content that is not already filed in the database. A
lost or truncated `control.redb` therefore requires a separate provenance
decision: after verifying that every store writer was authorised to create
control history, rerun the same offline command with
`--trust-unfiled-control-events`. That flag considers every qualifying record
in the bounded inventory; it is not selective. Partial pointer/pin/job rebuilds
are diagnostics and repair tools. Their store scans likewise require
`--from-store --trust-unfiled-control-events`, default to the same 100,000-object
and 1 GiB inventory ceilings, and accept `--max-objects`/`--max-bytes` only with
that explicit store scan. Zero is the clearly named offline opt-out for a
measured maintenance window. These partial commands do not certify every
GC-safety index or complete the gate. There is no HTTP recovery route.

### What collection keeps

Default roots are **pins**, **the current head of every live pointer**
(transitively — what a name resolves to, and everything it links to), and the
control plane's filed event history. The bounded signature index retains up to
4,096 signatures covering each retained target (and their counter-signatures),
preferring locally trusted and internally valid evidence during recovery.
Recent/in-flight writes, full input closures named by unadmitted trigger
snapshots and pending/running runs, and conservative witnesses for plausible
unfiled control events are additional safety layers. Active-work rows are
bounded before decode, aggregate encoded snapshots stop at 256 MiB, and their
immutable revision/input roots share collection's finite expansion budget.
Corrupt, legacy, or over-budget active work makes collection fail closed before
deletion. A signature omitted by that
per-target ceiling is ordinary unpinned content and needs its own pin if it must
survive collection. Other content becomes eligible only after the configured
age and deletion gates permit it.

Unfiled control-shaped records are not authority. Collection keeps each
plausible event and named root, but protects descendants only after their
closure validates within the shared bound. Unreadable or budget-exhausted
candidates warn and leave unproved descendants unprotected instead of granting
whole-inventory retention; investigate them before relying on their targets.

The local/offline `--no-system-protection` escape hatch allows filed audit-log
objects themselves to become collectable; use it only after a verified backup
and an explicit decision to discard that recovery/history evidence. It does
not disable root correctness or collection's conservative unfiled witnesses,
and HTTP cannot request it.

Two consequences worth knowing before you rely on either:

- **Only the *current* head is a root.** A pointer's history is permanent, but
  the bytes an older version named become collectable once the pointer moves
  on. `dag pointer resolve --id P --at-seq N` reports `content_present` so a
  historical answer never quietly names content that has gone. If you need to
  reconstruct old states — incident review, a deploy flight recorder — pin
  them; naming them is not enough.
- **A pin over a very large subtree can refuse rather than under-protect.**
  Expansion is bounded; reaching that bound stops collection with
  `RetentionIncomplete` naming the pin, instead of protecting a prefix and
  deleting the rest. Raise it with `--max-subtree-expansion`.

`dag gc run` lists every collected CID with its size and age (`--show-collected`
in text output, always in `--json`), so a run leaves a disposition record
rather than a count. `--record` goes further and stores that report *in the
ledger*: a `gc-disposition/v1` entry linking the full report, chained to its
predecessors under the pointer `system/gc/dispositions`. The chain retains
itself — a live pointer head is a transitive retention root — so the record
of what was deleted cannot be deleted by the mechanism it documents, and it
can be signed and replicated like any other content.

A pass deletes and itemises at most 10,000 chunks by default and inventories at
most 100,000 store objects totalling at most 1 GiB. This bounds the exclusive
collection window, I/O and report memory. A deletion-truncated result is an
instruction to run another pass; an object- or byte-inventory error refuses
before deleting anything and requires the operator to size the store and choose
an offline maintenance window. `--max-delete 0` is the explicit local/offline
override that removes all three ceilings. It is unavailable through HTTP, and
`--record` refuses it because a defensible itemised record must have a finite
construction bound.

The native control API does expose finite `POST /api/gc/run` requests. That
listener is loopback-only by default; an explicitly exposed listener must sit
behind the documented authentication/TLS perimeter. HTTP refuses unbounded
deletion/inventory work and refuses disabling system-data protection. It does
not expose recovery.

### Keeping a superseded version

Only a pointer's *current* head is a retention root, so the bytes behind an
older version become collectable as soon as the pointer moves on. When you
need to reconstruct old states — incident review, a deploy flight recorder —
say so at update time:

```bash
dag pointer update --id configs/prod --cid <NEW> --pin-history 2592000
```

That adds a subtree pin `history/configs/prod/<seq>` over the version being
superseded, expiring after thirty days. Without it the history still *names*
that version for ever; with it, the version can still be *read*.

## One process per data directory

redb locks the control database to a single handle, so one process owns a data
directory at a time. A second `dag` command while `dag serve` is running — or
two CI steps sharing a directory — fails with `DatabaseLocked` and exit 75
(`EX_TEMPFAIL`, i.e. retrying may work) rather than an error suggesting a bug.

```bash
dag --lock-timeout 30 put --file big.bin   # queue instead of failing
```

If you need genuine write parallelism against one directory, this is not the
tool for it.

## Complete backups

Replication copies the referenced graph, not local operational state. A
disaster-recovery snapshot includes the content store, `control.redb` (run
history, subscriptions and journal), and `keys/`:

```bash
dag --data-dir /var/lib/dag backup create --out /mnt/offline/dag-2026-08-23
dag backup verify --source /mnt/offline/dag-2026-08-23
dag --data-dir /var/lib/dag-restored backup restore \
  --source /mnt/offline/dag-2026-08-23
```

Creation holds redb's exclusion through a read-only database handle while it
copies the deployment, then publishes an fsynced, per-file SHA-256 manifest by
atomic rename. Restore verifies first and refuses to overwrite any existing
directory; its destination parent must already exist. Verify and restore admit
at most 1 TiB of declared and observed deployment files by default. Set
`--max-bytes` to a measured finite ceiling for larger snapshots; `--max-bytes
0` is an explicit, unbounded offline opt-out. Validate the new path, then cut
over while the old one remains your rollback. The manifest detects
changes relative to itself; it is not a signature or independent proof of
authenticity, so anchor its digest outside an untrusted backup location.
Backups contain private signing keys, so encrypt and access-control them
accordingly. The full procedure and restore drill are in
[`docs/runbooks/operations.md`](docs/runbooks/operations.md).

The snapshot format requires a real `control.redb`. Active migration markers,
staging files and live sled paths are rejected; a completed migration receipt
and its `*.sled.bak` provenance directories are preserved alongside the
required redb database.

## Replication

```bash
dag sync push --remote /Volumes/backup/dag     # send what the remote lacks
dag sync pull --remote /Volumes/backup/dag     # fetch what this directory lacks
dag sync push --remote /path --dry-run         # report without writing
dag sync push --remote /path --node-id node-a  # honour node-a local pins
```

Every transfer is incremental by construction: the destination already knows
the name of every byte it holds, so "what is missing" is a set difference over
CIDs. There is no journal and no resume token — an interrupted sync is
completed by running it again, and a second run of a finished one transfers
nothing.

History is moved, not replayed. `create`/`update` would stamp the local clock
into each event and so give every one a different CID; sync copies the event
entries themselves, and a replica is byte-identical, CID for CID. Events are
validated as they are filed: divergent history is refused rather than
overwritten, so sync can add to a directory that has its own writes but never
rewrite it. A dry run performs read-only conflict checks rather than waiting
until a real import to reveal an already divergent destination.

Replication preserves immutable pointer events, offers each readable event's
direct target, and recursively follows current pointer content. A superseded
target already collected at the source is reported but does not block current
state publication; superseded targets are not recursively walked. Pin content
follows effective-retention semantics: active, unexpired, scope-matching direct
pins name one CID, while subtree pins honour their depth. All pin events still
travel as provenance. Content with no current pointer, historical pointer
target, or effective pin is **not** copied — a bare `dag put` followed by
`dag sync push` does not back it up. Pin what you mean to keep.

The graph walk is bounded. If it reaches `--max-walk`, sync reports explicit
truncation, exits non-zero, keeps the verified chunks that arrived for the next
run, and leaves destination heads/indexes unpublished. Chunk or event failures
have the same publication barrier: partial bytes are resumable progress, never
a complete-looking replica.

Trusted keys deliberately do not travel. A signature arrives valid but
untrusted until the receiving machine's own keyring vouches for the key —
trust is a local decision, and a source must not get to make it for its
replica. See `docs/decisions/adr-002-sync.md`.

### Across machines

The same engine runs against another *node* instead of another directory:

```bash
# On the replica: /etc/dag/node-auth.json holds a current scoped credential
# and, during rotation only, the immediately previous credential.
dag node serve --listen 0.0.0.0:7411 --auth-file /etc/dag/node-auth.json \
  --tls-cert node.crt --tls-key node.key

# On the primary
dag sync push --remote grpcs://replica.internal:7411 \
  --token-file /etc/dag/node-token --ca-cert replica-ca.pem
```

`--ca-cert` adds a private CA to the platform native roots; it is not
certificate pinning. Use native roots alone for a publicly issued
certificate. The node process also runs the durable job worker, but command
execution stays disabled unless the local operator explicitly adds
`--allow-exec-jobs`; node RPCs expose no job/spec or direct-execution method.
A remote pointer mutation can activate an existing local `OnPointerUpdate`
subscription only when that credential carries both `pointer` and `trigger`.
An `exec` subscription still needs the separate local worker grant, so neither
authority is sufficient on its own.

The auth file is JSON; keep it mode 0600 and out of logs and source control:

```json
{
  "current": { "token": "CURRENT_BASE64URL_SECRET_AT_LEAST_32_BYTES", "scopes": ["read", "sync"] },
  "previous": { "token": "PREVIOUS_BASE64URL_SECRET_AT_LEAST_32_BYTES", "scopes": ["read", "sync"] }
}
```

Scopes are `read` (`Node.Info`), `sync`, `pointer`, `trigger`, and `events`;
`admin` is an explicit wildcard. `pointer` permits reads and CAS updates only
when the update would enqueue no active local subscription; add `trigger` to
authorize that side effect. A `trigger`-only token cannot call the Pointers
service. Tokens must be 32–256 characters from the padding-free base64url
alphabet (`A-Z`, `a-z`, `0-9`, `_`, `-`); generate them randomly rather than
using the placeholders above. Rotate by
installing old current as `previous` plus a new `current`, restarting, moving
clients to the new token, then deleting `previous` and restarting again.
Rotation slots using the same token are refused, even when their scope lists
differ. The historical `--token`/`--token-file`
server flags remain as a compatibility route, grant `admin`, and cannot be
combined with `--auth-file`. `DAG_NODE_TOKEN` is the client fallback and,
when no auth file is supplied, remains a legacy server-token fallback; remove
it from the server environment after the scoped cutover.

Existing scoped auth files remain valid. A historical `pointer` credential
continues to resolve, list, create and update pointers that have no active
`OnPointerUpdate` work. Add `trigger` during rotation before using it against a
subscribed pointer. Legacy single-token/admin authentication and no-auth
loopback serving retain their all-scopes compatibility behavior.

`Sync` never synthesizes destination-local job intents, but a Commit that
advances an actively subscribed pointer still requires both `sync` and
`trigger`; sync-only remains valid for pins and unsubscribed or idempotent
pointer offers. Pointer-trigger intents freeze their exact job revision and
input manifest in the pointer transaction, so later job, pointer, or sync
changes cannot rewrite already authorized work.

Credential and TLS inputs must be regular files; final-component symlinks and
special files are refused. Reads are bounded to 4 KiB for a token file, 64
KiB for auth JSON, 256 KiB for a TLS private key, and 2 MiB for a certificate
chain or additional CA. On Unix, secret inputs refuse world access and group
write access; a deliberate group-readable service file is accepted with a
warning, though mode 0600 is preferred. Apply equivalent ACLs elsewhere.

Same guarantees over the wire: byte-identical event logs, per-chunk receipt
hashing, divergence refused — validation always runs in the *destination's*
process, so a hostile peer cannot file history the destination itself would
refuse. Non-loopback serving requires TLS and credentials. Clients likewise
refuse plaintext `grpc://` and `http://` beyond loopback before sending a
bearer token. `--allow-insecure-transport` is a deliberately noisy opt-in on
both ends for remote development only; it sends credentials and data in the
clear. HTTP replication never follows redirects, so authentication cannot be
replayed to a redirected or downgraded destination. The wire cannot configure
jobs or commands, directly invoke exec, run garbage collection, or alter the
trust keyring. A `pointer` + `trigger` credential may activate only an existing
destination-local pointer subscription; an exec-backed subscription also
requires that host's explicit `--allow-exec-jobs` grant.

Remote integrity and memory work are bounded: missing checks hash-verify at
most 16 chunks per native call, concurrent chunk uploads/downloads have
aggregate admission, event replay returns at most the newest 500 matching
entries after scanning at most 50,000 rows, admits one materialized replay and
32 response streams at a time, and pointer listing is paginated. An implicit
replay that omits older matches ends with `OUT_OF_RANGE`, not a clean EOF.
Unary calls carry deadlines; uploads additionally enforce per-frame idle and
total deadlines, while intentionally long-lived event streams do not.

The node listener admits 128 TCP connections by default and at most 16 from
one `peer_addr()` IP. Both limits are configurable with
`--max-connections` and `--max-connections-per-source`; when a trusted L4
proxy represents many clients under one backend address, size the per-source
share for that topology and enforce the external client policy at the proxy.

Both HTTP listeners default to 256 connections in total and 32 per direct
peer IP; the same `--max-connections` and
`--max-connections-per-source` flags tune them. This backend is HTTP/1. Its
initial request headers have a non-resettable 10-second setup budget;
subsequent keep-alive headers must reach the router within the 60-second
quiescent deadline measured from the preceding response. That timer is paused
while a handler or response body is active, so slow integrity/GC work, large
downloads and SSE are not mistaken for idle sockets. Shutdown actively closes
established transports, including SSE. Internet deployments still put TLS,
HTTP/2 when wanted, and distributed connection/rate controls at the proxy.
Once accepted, synchronous storage mutations run to completion even if the
HTTP client disconnects; callers must reconcile the durable result before
retrying.

Remote writes are compare-and-set: `dag pointer update --remote … --expect-seq N`
applies only if the node's head is exactly `N` (0 creates), and a stale
expectation is refused *naming the actual head*, so two concurrent writers
cannot silently lose an update. `dag events tail --remote` follows another
node's journal live. See `docs/decisions/adr-005-multi-node.md` for what is
deliberately deferred (multi-master consensus, coordinated deletion) and why.

## Observability

`GET /metrics` serves Prometheus text format: store put/get latency
histograms and byte counters, collection shape (with *refusals* counted
separately — a refused collection is the safety gate working), replication
receipts and trust-boundary refusals, events by kind, job runs by status,
and HTTP requests by matched route. Gauges for the store's current shape are
read from the index at scrape time. Use `/health` for process liveness and
`/api/health` for bounded storage/control readiness.

`--log-format json` (or `DAG_LOG_FORMAT=json`) turns stderr diagnostics into
one JSON object per line; stdout always remains the command's own output.
GC and sync completions carry structured fields (`duration_ms`, counts).

[`docs/runbooks/operations.md`](docs/runbooks/operations.md) is the
operator's guide: serving postures, probes, scrape config, what each refusal
metric means, backup verification, recovery, upgrades. There is no
project-operated public replica.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for sign-off and review rules.

```bash
cargo test --locked --workspace --all-features
RUSTFLAGS='-D warnings' cargo clippy --locked --workspace --all-targets --all-features
cargo fmt --all -- --check

cd crates/dag-api/web && npm run check   # typecheck the console
```

Prefer `Control` over subprocesses in tests: `dag_control::test_utils::TestControl`
(behind the `test-utils` feature) gives an isolated data directory with the
event bus wired up.

## Crates

```
dag-core      data model: CIDs, entries, pointers, pins, job types, MemoryStore
dag-storage   filesystem store, redb index, integrity scan, collector
dag-control   pointers, pins, retention, jobs, recovery, events, HTTP sync dest
dag-jobs      adapters and the run lifecycle
dag-api       HTTP API (content + control planes), SSE, embedded web console
dag-net       the authenticated gRPC node protocol (replication, CAS, events)
dag-cli       the `dag` binary
dag-wasm      wasm-bindgen verifier over dag-core
dag-edge      Worker source plus Rust storage models/non-production test harness
```

## Status

M0–M7 complete — content, entries, pointers, pins and GC, jobs with effect
caching, the recovery gate, observability — plus signing (Ed25519/DSSE),
the exec adapter behind a deny-by-default capability, Prometheus metrics,
primary/replica multi-node over an authenticated gRPC port (ADR-005), a
read-only content plane (ADR-006), and a wasm / Edge distribution runtime
(ADR-007). What is built, why, and the open choices are in
[`docs/SYSTEM_OVERVIEW.md`](docs/SYSTEM_OVERVIEW.md). How to run a node is in
[`docs/runbooks/operations.md`](docs/runbooks/operations.md).

## License

Copyright 2026 Laurence Avent.

This project is licensed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE). Contributions are accepted under the same terms; see
[`CONTRIBUTING.md`](CONTRIBUTING.md). To report a vulnerability, see
[`SECURITY.md`](SECURITY.md).

## Invariants

- **I1** content for a CID never changes
- **I2** chunks are ≤ 4 MiB
- **I3** an entry's links are immutable once published
- **I4** pointers mutate only by appending to their log
- **I5** retention is data, not configuration
- **I6** collection honours effective retention
- **R6** when collection is uncertain, retain
- **I7** deterministic jobs reproduce their outputs
- **I8** side-effecting jobs reuse first-run artefacts
- **I9** storage nodes operate on chunks and never parse the DAG
- **I10** the external interface is CIDs and pointers; dereferencing is opt-in
