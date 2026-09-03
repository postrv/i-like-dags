# Adjacent systems: agent VMs and Source Network

> Why these two came up, what they are, and what this kernel does *not*
> become because of them. Companion to [ALL_USE_CASES.md](ALL_USE_CASES.md)
> §3 and the Horizon-2 wedge in [SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md).

## Grok Bot and the agent-gets-a-computer trend

[Grok Bot](https://x.ai/news/introducing-grok-bot) (August 2026) is the
clearest public instance of a shape that several vendors arrived at in the
same season: a named agent that is not a chat window but a **persistent
cloud VM** with a browser, a filesystem, a terminal, and connectors. Work
continues when the operator's laptop is closed. Claude Cowork, ChatGPT
Work, and Microsoft Copilot Cowork are the same idea with different
nouns.

Official Grok Bot docs are explicit about the security boundary, and it
is smaller than the marketing:

- Every bot on one account shares **one** computer. Files, browser
  cookies, and CLI credentials are visible to the whole roster.
- Separate bots are **not** separate sandboxes. The product itself calls
  this a blast radius.
- There is no self-host. The VM is xAI/Cursor-managed.
- Approvals gate *proposed* actions. They do not reconstruct what already
  ran, and they do not travel with the artefact.

That is the hole this kernel fills. The VM operator is a third party.
"Trust the cloud computer" is not a provenance answer. Shared-computer
siblings can see each other's files, so one bot's *outputs* become
checkable only if they leave as content-addressed, signed claims a
keyring the *auditor* controls will vouch for. When a bot is deleted,
shared-computer files and sessions may remain; a `.dag` directory (or a
sync to an Edge replica) is what an auditor can still re-hash.

The fit is Option B from the application survey, now product-shaped
rather than speculative:

- Embed `Control` / `dag_jobs::Execution` in the agent runtime. A
  manifest per action, an attestation chain, an orchestrator signature.
- Sync the ledger *out* of the VM. The VM is ephemeral evidence; the
  replica is not.
- A wasm32 verifier in a tab is how a human checks the work without an
  account on the vendor that ran the VM.

Do **not** add a Grok Bot connector, scrape the VM, or treat Cursor
auth as a trust root. The ledger's claim is that someone who distrusts
the operator can still verify. Integrating with the operator would
undo that.

An MCP server exposing put / attest / verify is a later porcelain
item, not a core change. The content plane (ADR-006) and the wasm
verifier (ADR-007) are what make the claim checkable *outside* the VM.

## Source Network / DefraDB — complement, not a rewrite

[Source](https://source.network/) and DefraDB are the closest cousin in
the wild: edge-first, Merkle DAG, CIDs, WASM builds, offline-first,
"verifiable." They are not this product.

| | This kernel | DefraDB / Source |
|---|---|---|
| CID | raw 32-byte SHA-256 | IPLD CIDv0/v1 (multicodec / multihash) |
| Mutation | refuse divergent pointer history | Merkle-CRDT merge, multi-write-master |
| Trust | local keyring; trust does not travel | DIDs, SourceHub ACP, threshold keys, proxy re-encryption |
| Jobs / effect cache / pins-as-GC | first-class | not the product |
| License | Apache-2.0 | BSL (non-production grant) |
| Form factor | single-writer directory, "SQLite of DAGs" | P2P libp2p document DB + GraphQL |

They solved **distribution and multi-writer documents**. This kernel
solved **provenance you can verify without trusting the operator**, plus
retention that can actually erase. Taking their CRDT / P2P / DID stack
would undo [ADR-002](decisions/adr-002-sync.md) and
[ADR-005](decisions/adr-005-multi-node.md) and the
tamper-evident-but-erasable posture.

Written non-goals for this pass (and the default thereafter):

- no IPLD CID wrap in the on-disk format
- no libp2p
- no SourceHub access-control policies
- no CRDT pointer heads

A later optional *export* of a raw SHA-256 as CIDv1 (codec = raw, hash =
sha2-256) is one function if someone asks for interop. It is not a
rewrite of `Cid`.

What *is* worth taking as a requirement: they already compile one engine
to native + WASM + JS and swap IndexedDB / SQLite / filesystem behind
it. That is the `ContentStore` endgame [ADR-007](decisions/adr-007-edge-runtime.md)
is building — MemoryStore, FsStore, R2Store — without becoming a
document database.
