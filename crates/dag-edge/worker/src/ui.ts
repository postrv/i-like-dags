import {
  DAG_WASM_JS_SHA256_SRI,
  DAG_WASM_SHA256_HEX,
} from "../../../dag-wasm/web/browser-kernel.mjs";

/** Same-origin console. No polling. Graph walk is click-started and capped. */
export function consolePage(nonce: string): string {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
    throw new Error("console CSP nonce must be 16-128 base64url characters");
  }
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dag-edge — a replica you can re-hash</title>
<style nonce="${nonce}">
:root {
  --paper: #f3eee4;
  --paper-2: #ebe4d7;
  --ink: #1b1814;
  --muted: #6b6458;
  --faint: #948c80;
  --line: #d9d0c2;
  --accent: #8d5724;
  --brass: #c9a36a;
  --ok: #2c6a4a;
  --bad: #a13a32;
  --well: #14110e;
  --well-line: #2c2822;
  --shadow: 0 18px 50px rgba(27, 24, 20, .08);
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--paper); color: var(--ink); }
body {
  font: 17px/1.55 "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
  min-height: 100vh;
}
.ui { font-family: Inter, "Segoe UI", ui-sans-serif, system-ui, sans-serif; }
.mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
a { color: var(--accent); text-underline-offset: .15em; }
.page { max-width: 74rem; margin: 0 auto; padding: 0 1.5rem 5rem; }
header.top {
  display: flex; justify-content: space-between; align-items: center;
  gap: 1rem; padding: 1.15rem 0 1.05rem; border-bottom: 1px solid var(--line);
}
.brand { display: flex; align-items: center; gap: .7rem; }
.brand svg { display: block; }
.mark {
  letter-spacing: .2em; text-transform: uppercase; font-size: .68rem;
  color: var(--accent); font-weight: 600;
}
#health { font-size: .72rem; color: var(--faint); letter-spacing: .04em; }
.hero { padding: 2.6rem 0 1.6rem; max-width: 38rem; }
.kicker {
  font-size: .7rem; letter-spacing: .18em; text-transform: uppercase;
  color: var(--accent); margin: 0 0 .75rem; font-weight: 600;
}
.hero h1 {
  font-size: clamp(2.15rem, 5vw, 3.4rem);
  line-height: 1.06; font-weight: 500; letter-spacing: -.03em;
  margin: 0 0 1rem;
}
.lede { font-size: 1.18rem; color: var(--muted); margin: 0 0 1.6rem; }
.row { display: flex; flex-wrap: wrap; gap: .55rem; align-items: center; }
input, textarea, button { font: inherit; }
input[type=text], input[type=password], textarea {
  width: 100%; background: #fffdf8; color: var(--ink);
  border: 1px solid var(--line); border-radius: 10px; padding: .7rem .85rem;
}
textarea { min-height: 6rem; font-size: .85rem; }
button {
  background: transparent; color: var(--ink); border: 1px solid var(--line);
  border-radius: 999px; padding: .55rem 1.05rem; cursor: pointer;
}
button:hover { border-color: var(--accent); color: var(--accent); }
button.primary {
  background: var(--ink); color: var(--paper); border-color: var(--ink);
}
button.primary:hover { background: var(--accent); border-color: var(--accent); color: #fff; }
.chip {
  border: 1px solid var(--line); border-radius: 999px; padding: .38rem .8rem;
  font-size: .78rem; color: var(--muted); background: transparent; cursor: pointer;
}
.chip:hover, .chip.on { border-color: var(--accent); color: var(--accent); background: #fff; }
.stage {
  background: #fffdf8; border: 1px solid var(--line); border-radius: 22px;
  padding: 1rem 1rem 1.2rem; box-shadow: var(--shadow); margin: 0 0 2.6rem;
}
.stage-top {
  display: flex; justify-content: space-between; align-items: baseline;
  gap: 1rem; padding: .35rem .4rem .75rem;
}
.score { font-size: 1.05rem; letter-spacing: -.01em; }
.score.ok { color: var(--ok); } .score.bad { color: var(--bad); }
.graph-wrap { position: relative; }
#graph {
  width: 100%; height: 520px; display: block; border-radius: 14px;
  touch-action: none; cursor: grab; user-select: none;
  background:
    radial-gradient(700px 280px at 50% -10%, rgba(201,163,106,.09), transparent 60%),
    linear-gradient(180deg, #1a1713, var(--well));
}
#graph.panning { cursor: grabbing; }
.graph-tools { position: absolute; top: .7rem; right: .7rem; display: flex; gap: .4rem; }
.graph-tools button {
  background: rgba(20, 17, 14, .78); color: #f3efe6; border-color: #3a342c;
  padding: .32rem .75rem; font-size: .74rem;
}
.graph-tools button:hover { color: var(--brass); border-color: var(--brass); }
.vnode:focus { outline: none; }
.vnode:focus rect { stroke: var(--brass); stroke-width: 2.4px; }
.legend {
  display: flex; flex-wrap: wrap; gap: .4rem 1.15rem;
  font-size: .72rem; color: var(--faint); margin: .75rem .4rem 0;
}
.swatch {
  display: inline-block; width: .5rem; height: .5rem; border-radius: 99px;
  margin-right: .35rem; vertical-align: middle;
}
.read { color: var(--muted); font-size: .98rem; margin: .85rem .4rem 0; max-width: 46rem; }
.grid { display: grid; grid-template-columns: 1.05fr .95fr; gap: 1rem; margin: 1rem .15rem 0; }
@media (max-width: 860px) {
  .grid { grid-template-columns: 1fr; }
  #graph { height: 400px; }
  .hero { padding-top: 1.8rem; }
}
.panel {
  background: var(--paper); border: 1px solid var(--line);
  border-radius: 14px; padding: 1.05rem 1.1rem; min-height: 9rem;
}
.panel h3 { margin: 0 0 .4rem; font-size: 1.2rem; font-weight: 500; }
.cid { font-size: .74rem; color: var(--muted); word-break: break-all; margin-top: .15rem; }
.badge {
  display: inline-block; font-size: .66rem; letter-spacing: .08em;
  text-transform: uppercase; border: 1px solid var(--line);
  border-radius: 999px; padding: .15rem .5rem; margin: 0 .3rem .35rem 0;
  color: var(--muted); font-weight: 600;
}
.badge.ok { color: var(--ok); border-color: #b9d2c4; }
.badge.bad { color: var(--bad); border-color: #e3b6b2; }
.preview {
  margin: .7rem 0 0; padding: .65rem .7rem; background: #fff;
  border: 1px solid var(--line); border-radius: 8px;
  font-size: .75rem; color: var(--muted); white-space: pre-wrap;
  max-height: 8rem; overflow: auto;
}
.nouns {
  display: grid; grid-template-columns: repeat(5, 1fr); gap: .7rem;
  margin: 0 0 2.4rem;
}
@media (max-width: 860px) { .nouns { grid-template-columns: 1fr 1fr; } }
.noun {
  background: #fffdf8; border: 1px solid var(--line); border-radius: 14px;
  padding: .9rem .95rem 1rem;
}
.noun .n { font-size: .68rem; letter-spacing: .16em; text-transform: uppercase; color: var(--accent); font-weight: 600; margin: 0 0 .35rem; }
.noun h3 { margin: 0 0 .35rem; font-size: 1.15rem; font-weight: 500; }
.noun p { margin: 0; color: var(--muted); font-size: .92rem; }
.essay { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.6rem; padding: .2rem 0 2rem; }
@media (max-width: 860px) { .essay { grid-template-columns: 1fr; } }
.essay h2 { font-size: 1.35rem; font-weight: 500; margin: 0 0 .55rem; letter-spacing: -.02em; }
.essay p, .essay li { color: var(--muted); font-size: 1rem; }
.essay ol { margin: .35rem 0 0; padding-left: 1.15rem; }
.essay li { margin: .4rem 0; }
.notes {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.4rem;
  border-top: 1px solid var(--line); padding: 1.6rem 0 2rem;
}
@media (max-width: 860px) { .notes { grid-template-columns: 1fr; } }
.notes h2 { font-size: 1.15rem; font-weight: 500; margin: 0 0 .45rem; }
.notes p { color: var(--muted); margin: 0; font-size: .98rem; }
details.write { border-top: 1px solid var(--line); padding-top: 1.2rem; color: var(--muted); }
details.write summary {
  cursor: pointer; color: var(--faint); font-size: .78rem;
  letter-spacing: .1em; text-transform: uppercase; font-weight: 600;
}
details.write label { display: block; margin: .9rem 0 .35rem; font-size: .8rem; color: var(--faint); }
.security-note { max-width: 48rem; }
.security-note.bad { color: var(--bad); }
footer.colophon {
  margin-top: 2.2rem; padding-top: 1rem; border-top: 1px solid var(--line);
  color: var(--faint); font-size: .8rem;
}
</style>
</head>
<body>
<div class="page">
  <header class="top ui">
    <div class="brand">
      <svg width="28" height="22" viewBox="0 0 28 22" aria-hidden="true">
        <circle cx="14" cy="4" r="3" fill="none" stroke="#8d5724" stroke-width="1.4"/>
        <circle cx="5" cy="18" r="3" fill="none" stroke="#8d5724" stroke-width="1.4"/>
        <circle cx="23" cy="18" r="3" fill="none" stroke="#8d5724" stroke-width="1.4"/>
        <path d="M12.2 6.6 L6.8 15.2" fill="none" stroke="#c9a36a" stroke-width="1.1"/>
        <path d="M15.8 6.6 L21.2 15.2" fill="none" stroke="#c9a36a" stroke-width="1.1"/>
      </svg>
      <div class="mark">dag-edge · content plane</div>
    </div>
    <div id="health">connecting</div>
  </header>

  <section class="hero">
    <p class="kicker ui">A replica whose content bytes this tab can re-check</p>
    <h1>The name is the hash. Everything else is a story you can re-check.</h1>
    <p class="lede">This page re-hashes every fetched chunk and uses a pinned Rust <span class="mono">dag-core</span> WebAssembly decoder to derive links from those verified bytes. That detects corrupt or substituted content. Because the page, pointer response, and verifier share one origin, independent verification still requires a separately pinned verifier and root or signed checkpoint.</p>
    <div class="row ui" style="margin-bottom:.7rem" id="chips"></div>
    <div class="row ui">
      <input id="pointer" type="text" value="models/fraud-detector/production" spellcheck="false" aria-label="Pointer name" style="flex:1;min-width:16rem">
      <button class="primary" id="open" type="button">Open this release</button>
    </div>
  </section>

  <section class="stage" id="stage">
    <div class="stage-top ui">
      <div>
        <div class="kicker">The graph</div>
        <div id="score" class="score" role="status" aria-live="polite">Nothing walked yet. Open a release — this tab fetches, hashes, and locally decodes each CID.</div>
        <div id="engine" class="cid mono">Rust verifier loading…</div>
      </div>
    </div>
    <div class="graph-wrap">
      <svg id="graph" viewBox="0 0 1000 460" preserveAspectRatio="xMidYMid meet" role="group" tabindex="0" aria-label="DAG of the resolved release. Tab to individual nodes; use arrow keys to pan, plus and minus to zoom, and zero to fit." aria-describedby="graph-help"></svg>
      <div class="graph-tools ui">
        <button type="button" id="fit" title="Fit every node in view">Fit</button>
      </div>
    </div>
    <div class="legend ui">
      <span><i class="swatch" style="background:var(--ok)"></i>intact — SHA-256 in this tab matches the CID</span>
      <span><i class="swatch" style="background:var(--brass)"></i>selected</span>
      <span><i class="swatch" style="background:var(--faint)"></i>drag to pan · scroll to zoom</span>
    </div>
    <p class="read" id="graph-help">Each box is an immutable CID. An arrow is a named link decoded in this tab from its verified parent entry — never from server-supplied graph metadata. Click or keyboard-activate a box to read it. Drag the well to pan; scroll to zoom. A pointer is only the mutable name resolved to obtain the root.</p>
    <div class="grid">
      <div class="panel" id="inspect-out">
        <h3>Select a node</h3>
        <p style="color:var(--muted);margin:0">The graph is empty until you open a name. Then every node is fetched, re-hashed, and decoded in this browser. Green means the fetched bytes match that CID; it is not a signature or freshness verdict.</p>
      </div>
      <div class="panel" id="reading">
        <h3>What you are looking at</h3>
        <p style="color:var(--muted);margin:0 0 .7rem">A model-release ledger. The live name <span class="mono" style="color:var(--ink)">models/fraud-detector/production</span> points at an attestation. That entry links a dataset, a config, and code. The dataset card links the CSV and the revision it supersedes.</p>
        <p style="color:var(--muted);margin:0">A pointer is the only mutable noun. Its history is an append-only log of content-addressed events. This replica already has one history for that name. A second seed with a new timestamp is a different log — refused, not merged.</p>
      </div>
    </div>
  </section>

  <section class="nouns ui">
    <article class="noun">
      <p class="n">01</p>
      <h3>Chunk</h3>
      <p>≤4&nbsp;MiB of bytes. The CID is the SHA-256 of those bytes. Same bytes, same name.</p>
    </article>
    <article class="noun">
      <p class="n">02</p>
      <h3>Entry</h3>
      <p>A payload plus named links, stored as an ordinary chunk. Retarget a link and the CID changes.</p>
    </article>
    <article class="noun">
      <p class="n">03</p>
      <h3>Pointer</h3>
      <p>A mutable name over an immutable log. Updates append. History is ordered and tamper-evident.</p>
    </article>
    <article class="noun">
      <p class="n">04</p>
      <h3>Pin</h3>
      <p>Retention as data. Collection honours pins. When uncertain, it retains.</p>
    </article>
    <article class="noun">
      <p class="n">05</p>
      <h3>Signature</h3>
      <p>Ed25519 over DSSE / in-toto. Trust is a local keyring, never the key in the record.</p>
    </article>
  </section>

  <section class="essay">
    <article>
      <h2>Why it exists</h2>
      <p>Agents now get a computer: a vendor VM with a filesystem, a browser, and your credentials. Approvals gate what is <em>proposed</em>. They do not reconstruct what already ran, and they do not travel with the artefact.</p>
      <p>When the operator is a third party, “trust the cloud computer” is not a provenance answer. Shared-computer siblings can see each other’s files. The only checkable residue is content-addressed, signed, and held somewhere the auditor chose — a directory on disk, or a replica like this one.</p>
    </article>
    <article>
      <h2>How it works</h2>
      <p>You publish bytes. The store names them by hash. You assemble those names into entries. You hang a pointer on the root you care about, and a pin if it must survive collection. A job is just another writer of entries. Replay is re-hashing, not asking the operator what happened.</p>
      <p>This page does the smallest honest demo of that: resolve a name, walk links decoded by the shared Rust kernel, and hash every node in your browser. A complete green graph means this origin served bytes matching those CIDs. It does not prove pointer freshness, signatures, or non-equivocation.</p>
    </article>
    <article>
      <h2>What is novel</h2>
      <p>This is not IPLD, not a blockchain, and not a CRDT. Divergent pointer history is refused. Browser entry decoding here is compiled from the same <span class="mono">dag-core</span> implementation as the laptop; pointer and pin event imports are validated by the Edge control plane.</p>
      <p>The form factor is the strategy: a single-writer directory, “the SQLite of DAGs.” This Worker is a second <span class="mono">ContentStore</span> — R2 for durable deployments or isolated KV for ephemeral demos, with one Durable Object per name — not a second product. Jobs, trust, and deletion do not travel. You can still re-hash every byte without an account.</p>
    </article>
  </section>

  <section class="notes">
    <article>
      <h2>This surface</h2>
      <p><span class="mono">GET /c/:cid</span> is public. <span class="mono">GET /p/:id</span> is an untrusted, freshly fetched resolve. Writes need a bearer token. There is no job execution, no garbage collection, and no listing of the bucket. A walk happens only when you ask, and stops at explicit node, byte, depth, link, and edge limits.</p>
    </article>
    <article>
      <h2>The 409 you may have seen</h2>
      <p>Two <span class="mono">usecase seed</span> runs produce the same content CIDs and different event CIDs — events carry a wall-clock <span class="mono">ts</span>. The replica keeps the first chain. That refuse is the product working.</p>
    </article>
    <article>
      <h2>What this is not</h2>
      <p>Not consensus. Not multi-master. Not a place to run <span class="mono">exec</span>. Those belong to a laptop, a container, or an ADR that has not been accepted. Honesty about the boundary is part of the claim.</p>
    </article>
  </section>

  <details class="write ui">
    <summary>Write to this replica</summary>
    <p class="security-note" id="write-security">Use a short-lived, least-privilege token. This page keeps it only in the password field, never in browser storage, and sends it only in the <span class="mono">Authorization</span> header to this origin. Network writes are enabled only on HTTPS, plus loopback development. Any script running on this origin could still read it.</p>
    <label for="token">Bearer token</label>
    <input id="token" type="password" autocomplete="new-password" autocapitalize="none" spellcheck="false">
    <button id="forget-token" type="button" style="margin-top:.55rem">Forget token</button>
    <label for="payload">Text to store as a chunk</label>
    <textarea id="payload" spellcheck="false">hello from the console</textarea>
    <div class="row" style="margin:.7rem 0">
      <button class="primary" id="put" type="button">Put and re-hash</button>
    </div>
    <label for="point-id">Point a name at the current CID</label>
    <input id="point-id" type="text" spellcheck="false" placeholder="demo/note">
    <button id="point" type="button">Compare-and-set pointer</button>
    <div id="write-out" class="panel" role="status" aria-live="polite" hidden style="margin-top:1rem"></div>
  </details>

  <footer class="colophon ui">A single-writer directory, replicated. This page never lists the bucket, never polls, and never runs a job.</footer>
</div>
<script type="module" nonce="${nonce}">
(function () {
  var KNOWN = [
    "models/fraud-detector/production",
    "datasets/customer-transactions",
    "configs/fraud-detector",
    "code/fraud-detector"
  ];
  var MAX_WALK = 16;
  var MAX_DEPTH = 8;
  var MAX_NODE_BYTES = 4 * 1024 * 1024;
  var MAX_TOTAL_BYTES = 16 * 1024 * 1024;
  var MAX_LINKS = 256;
  var MAX_EDGES = 256;
  var MAX_CACHE_NODES = 64;
  var MAX_CACHE_BYTES = 16 * 1024 * 1024;
  var MAX_CONTROL_BYTES = 64 * 1024;
  var WALK_CONCUR = 4;
  var WASM_SHA256 = "${DAG_WASM_SHA256_HEX}";
  var WASM_JS_INTEGRITY = "${DAG_WASM_JS_SHA256_SRI}";
  var NW = 168;
  var NH = 58;
  var VIEW_W = 1000;
  var VIEW_H = 460;
  var graph = { nodes: [], edges: [] };
  var selected = null;
  var hovered = null;
  var walkGen = 0;
  var inspectGen = 0;
  var activeWalkController = null;
  var inspectController = null;
  var nodeCache = new Map();
  var nodeCacheBytes = 0;
  var graphCache = new Map();
  var cam = { x: 0, y: 0, w: VIEW_W, h: VIEW_H };
  var camLocked = false;
  var suppressClick = false;
  var $ = function (id) { return document.getElementById(id); };
  var chips = $("chips");
  KNOWN.forEach(function (id) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "chip";
    b.textContent = id.split("/").slice(-2).join("/");
    b.title = id;
    b.addEventListener("click", function () {
      $("pointer").value = id;
      Array.prototype.forEach.call(chips.children, function (c) { c.classList.remove("on"); });
      b.classList.add("on");
      openRelease();
    });
    chips.appendChild(b);
  });
  if (chips.firstChild) chips.firstChild.classList.add("on");

  var tokenInput = $("token");
  var secureWriteContext = location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1";
  if (!secureWriteContext) {
    $("write-security").textContent = "Writes are disabled because this page is not using HTTPS. Never send a bearer token over plaintext HTTP.";
    $("write-security").className = "security-note bad";
    tokenInput.disabled = true;
    $("put").disabled = true;
    $("point").disabled = true;
  }
  $("forget-token").addEventListener("click", function () {
    tokenInput.value = "";
    tokenInput.focus();
    $("write-out").hidden = false;
    $("write-out").textContent = "Token forgotten.";
  });
  window.addEventListener("pagehide", function () {
    tokenInput.value = "";
    if (activeWalkController) activeWalkController.abort();
    if (inspectController) inspectController.abort();
  });

  fetch("/ready", { cache: "no-store", credentials: "same-origin" }).then(function (response) {
    if (response.status !== 200 && response.status !== 503) {
      throw new Error("readiness returned HTTP " + response.status);
    }
    return readJsonBounded(response, MAX_CONTROL_BYTES, "readiness response");
  }).then(function (h) {
    if (!strictObject(h) || typeof h.production_ready !== "boolean" || !strictObject(h.limits) || !Number.isSafeInteger(h.limits.max_chunk_size)) {
      throw new Error("readiness returned an invalid response");
    }
    var readiness = h.production_ready ? "production ready" : "demo / not production ready";
    $("health").textContent = (typeof h.store === "string" ? h.store : "store") + " · cap " + (h.limits.max_chunk_size / 1048576) + " MiB · " + readiness + " · no list · no cron";
  }).catch(function () { $("health").textContent = "unreachable"; });

  function sha256hex(bytes) {
    return crypto.subtle.digest("SHA-256", bytes).then(function (d) {
      return Array.prototype.map.call(new Uint8Array(d), function (b) {
        return b.toString(16).padStart(2, "0");
      }).join("");
    });
  }
  function strictObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }
  function validCid(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  }
  function localRawInfo(bytes) {
    var preview = null;
    try {
      var text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      var chars = text[Symbol.iterator]();
      var pieces = [];
      for (var index = 0; index < 1024; index += 1) {
        var next = chars.next();
        if (next.done) break;
        pieces.push(next.value);
      }
      preview = pieces.join("");
      if (!chars.next().done) preview += "…";
    } catch (_) {}
    return { kind: "bytes", links: [], linksTotal: 0, preview: preview };
  }
  function validateEntryInfo(json) {
    var value = JSON.parse(json);
    if (!strictObject(value) || (value.kind !== "entry" && value.kind !== "bytes") || !Array.isArray(value.links) || value.links.length > MAX_LINKS ||
        !Number.isSafeInteger(value.links_total) || value.links_total < value.links.length ||
        !Number.isSafeInteger(value.payload_len) || value.payload_len < 0 ||
        (value.preview !== null && (typeof value.preview !== "string" || value.preview.length > 2050))) {
      throw new Error("Rust verifier returned an invalid entry record");
    }
    var links = value.links.map(function (link) {
      if (!strictObject(link) || !validCid(link.target) ||
          (link.name !== null && (typeof link.name !== "string" || link.name.length > 514))) {
        throw new Error("Rust verifier returned an invalid link record");
      }
      return { name: link.name, target: link.target };
    });
    if (value.kind === "bytes" && (links.length !== 0 || value.links_total !== 0)) {
      throw new Error("Rust verifier classified opaque bytes with links");
    }
    return {
      kind: value.kind,
      links: links,
      linksTotal: value.links_total,
      preview: value.preview,
      payloadSize: value.payload_len
    };
  }
  function readBounded(response, limit, label) {
    label = label || "response";
    var stated = response.headers.get("Content-Length");
    if (stated !== null && (!/^\\d+$/.test(stated) || Number(stated) > limit)) {
      return Promise.reject(new Error(label + " exceeds this verifier's remaining byte budget"));
    }
    if (!response.body || !response.body.getReader) {
      return response.arrayBuffer().then(function (buffer) {
        if (buffer.byteLength > limit) throw new Error(label + " exceeds this verifier's remaining byte budget");
        return new Uint8Array(buffer);
      });
    }
    var reader = response.body.getReader();
    var chunks = [];
    var total = 0;
    function next() {
      return reader.read().then(function (part) {
        if (part.done) {
          var bytes = new Uint8Array(total);
          var offset = 0;
          chunks.forEach(function (chunk) { bytes.set(chunk, offset); offset += chunk.length; });
          return bytes;
        }
        total += part.value.byteLength;
        if (total > limit) {
          return reader.cancel().then(function () {
            throw new Error(label + " exceeds this verifier's remaining byte budget");
          });
        }
        chunks.push(part.value);
        return next();
      });
    }
    return next().finally(function () { reader.releaseLock(); });
  }
  function readTextBounded(response, limit, label) {
    return readBounded(response, limit, label).then(function (bytes) {
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    });
  }
  function readJsonBounded(response, limit, label) {
    return readTextBounded(response, limit, label).then(function (text) {
      try { return JSON.parse(text); }
      catch (_) { throw new Error(label + " was not valid JSON"); }
    });
  }

  function loadVerifierScript() {
    return new Promise(function (resolve, reject) {
      var script = document.createElement("script");
      script.src = "/assets/dag_wasm.js?v=" + encodeURIComponent(WASM_JS_INTEGRITY);
      script.integrity = WASM_JS_INTEGRITY;
      script.crossOrigin = "anonymous";
      script.onload = function () { resolve(); };
      script.onerror = function () { reject(new Error("WASM verifier script failed its integrity or load check")); };
      document.head.appendChild(script);
    });
  }

  var kernelReady = Promise.all([
    fetch("/assets/dag_wasm_bg.wasm?v=" + WASM_SHA256, { cache: "force-cache", credentials: "same-origin" })
    .then(function (response) {
      if (!response.ok) throw new Error("WASM asset returned HTTP " + response.status);
      return readBounded(response, 1024 * 1024, "WASM asset");
    }),
    loadVerifierScript()
  ]).then(function (values) {
      var bytes = values[0];
      return sha256hex(bytes).then(function (digest) {
        if (digest !== WASM_SHA256) throw new Error("WASM asset digest mismatch");
        var module = window.DagWasm;
        if (typeof module !== "function" || typeof module.inspect_chunk !== "function") {
          throw new Error("WASM verifier exports are incomplete");
        }
        return module({ module_or_path: bytes }).then(function () {
          $("engine").textContent = "dag-core/WASM verifier · pinned " + short(WASM_SHA256);
          return module;
        });
      });
    }).catch(function (error) {
      $("engine").textContent = "verifier unavailable · " + String(error && error.message || error);
      $("engine").style.color = "var(--bad)";
      throw error;
    });
  kernelReady.catch(function () {});
  function short(cid) { return cid && cid.length > 12 ? cid.slice(0, 8) + "…" + cid.slice(-4) : (cid || ""); }
  function applyCam() {
    $("graph").setAttribute("viewBox", cam.x + " " + cam.y + " " + cam.w + " " + cam.h);
  }
  function contentBounds() {
    var pad = 40;
    if (!graph.nodes.length) return { x: 0, y: 0, w: VIEW_W, h: VIEW_H };
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    graph.nodes.forEach(function (n) {
      minX = Math.min(minX, n.x);
      minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x + NW);
      maxY = Math.max(maxY, n.y + NH);
    });
    return { x: minX - pad, y: minY - pad, w: Math.max(NW, maxX - minX) + pad * 2, h: Math.max(NH, maxY - minY) + pad * 2 };
  }
  function fitCam() {
    var b = contentBounds();
    var aspect = VIEW_W / VIEW_H;
    if (b.w / b.h > aspect) {
      var h = b.w / aspect;
      b.y -= (h - b.h) / 2;
      b.h = h;
    } else {
      var w = b.h * aspect;
      b.x -= (w - b.w) / 2;
      b.w = w;
    }
    cam = b;
    camLocked = false;
    applyCam();
  }
  function evictNodeCache(protectCid) {
    while (nodeCache.size > MAX_CACHE_NODES || nodeCacheBytes > MAX_CACHE_BYTES) {
      var oldest = nodeCache.keys().next().value;
      if (oldest === undefined) break;
      var entry = nodeCache.get(oldest);
      nodeCache.delete(oldest);
      if (entry && entry.ready) nodeCacheBytes -= entry.ready.size;
      if (oldest === protectCid && nodeCache.size) {
        nodeCache.set(oldest, entry);
        if (entry && entry.ready) nodeCacheBytes += entry.ready.size;
      }
    }
  }
  function dropPendingNodeCache() {
    nodeCache.forEach(function (entry, cid) {
      if (!entry.ready) nodeCache.delete(cid);
    });
  }
  function loadNode(cid, byteLimit, signal) {
    if (!validCid(cid)) return Promise.reject(new Error("invalid CID returned by the graph"));
    var cached = nodeCache.get(cid);
    if (cached && cached.ready && cached.ready.size > byteLimit) {
      return Promise.reject(new Error("chunk exceeds this verifier's remaining byte budget"));
    }
    if (cached) {
      nodeCache.delete(cid);
      nodeCache.set(cid, cached);
      return cached.promise.then(function (record) {
        if (record.size > byteLimit) throw new Error("chunk exceeds this verifier's remaining byte budget");
        return record;
      });
    }
    var cacheEntry = { promise: null, ready: null };
    cacheEntry.promise = kernelReady.then(function (kernel) {
      return fetch("/c/" + encodeURIComponent(cid), {
        cache: "force-cache",
        credentials: "same-origin",
        signal: signal
      })
        .then(function (response) {
          if (!response.ok) throw new Error("chunk returned HTTP " + response.status);
          return readBounded(response, Math.min(MAX_NODE_BYTES, byteLimit), "chunk");
        }).then(function (bytes) {
          return sha256hex(bytes).then(function (digest) {
            var intact = digest === cid;
            var info = localRawInfo(bytes);
            if (intact) info = validateEntryInfo(kernel.inspect_chunk(bytes));
            var rec = { cid: cid, size: bytes.length, digest: digest, intact: intact, info: info };
            cacheEntry.ready = rec;
            if (!intact && nodeCache.get(cid) === cacheEntry) {
              nodeCache.delete(cid);
            } else if (nodeCache.get(cid) === cacheEntry) {
              nodeCacheBytes += rec.size;
              evictNodeCache(cid);
            }
            return rec;
          });
        });
    }).catch(function (error) {
      if (nodeCache.get(cid) === cacheEntry) nodeCache.delete(cid);
      throw error;
    });
    nodeCache.set(cid, cacheEntry);
    evictNodeCache(cid);
    return cacheEntry.promise;
  }
  function resolvePointer(id, signal) {
    if (!id) return Promise.reject(new Error("Pointer name required."));
    return fetch("/p/" + encodeURIComponent(id), {
      cache: "no-store",
      credentials: "same-origin",
      headers: { "Cache-Control": "no-cache", Accept: "application/json" },
      signal: signal
    }).then(function (response) {
      if (!response.ok) throw new Error("pointer resolve returned HTTP " + response.status);
      return readJsonBounded(response, MAX_CONTROL_BYTES, "pointer response").then(function (head) {
        if (!strictObject(head) || !validCid(head.cid) || !Number.isSafeInteger(head.seq) || head.seq < 1) {
          throw new Error("pointer resolve returned an invalid head");
        }
        return head;
      });
    });
  }
  function svgEl(name, attrs) {
    var el = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }
  function prettyName(name) {
    if (!name) return "(node)";
    var parts = String(name).split("/");
    return parts[parts.length - 1];
  }
  function whyNode(n) {
    var name = (n && n.name) || "";
    if (name.indexOf("models/") === 0 || name.indexOf("production") >= 0) {
      return "The live release. An attestation entry: payload plus named links to the inputs that produced it.";
    }
    if (name.indexOf("datasets/") === 0 || name === "customer-transactions") {
      return "A dataset card. Human metadata in the payload; the CSV is a link, not embedded bytes.";
    }
    if (name === "supersedes") {
      return "The previous card. Revision history lives in the DAG, so you can walk it without trusting the pointer log.";
    }
    if (name === "rows.csv") {
      return "Raw bytes. No links. The CID is the SHA-256 of this CSV and nothing else.";
    }
    if (name.indexOf("configs/") === 0 || name.indexOf("config") >= 0) {
      return "Training configuration, stored as a chunk and named by a pointer of its own.";
    }
    if (name.indexOf("code/") === 0) {
      return "The code that was attested. A later pointer move does not rewrite this CID.";
    }
    if (n && n.kind === "entry") {
      return "An entry: a payload and a frozen list of named links. Changing either changes the CID.";
    }
    return "A content-addressed chunk. If the badge says intact, the bytes fetched from this replica hashed to this name in your browser.";
  }

  function emptyGraph(svg, W, H) {
    var hint = [
      { x: 421, y: 46, w: 158, label: "release" },
      { x: 148, y: 186, w: 168, label: "dataset" },
      { x: 416, y: 186, w: 148, label: "config" },
      { x: 684, y: 186, w: 148, label: "code" },
      { x: 86, y: 326, w: 130, label: "rows.csv" },
      { x: 248, y: 326, w: 148, label: "supersedes" }
    ];
    function mid(a) { return { x: a.x + a.w / 2, y: a.y + 24 }; }
    var edges = [[0,1],[0,2],[0,3],[1,4],[1,5]];
    edges.forEach(function (pair) {
      var a = mid(hint[pair[0]]), b = mid(hint[pair[1]]);
      var path = svgEl("path", {
        d: "M " + a.x + " " + (hint[pair[0]].y + 48) + " C " + a.x + " " + (a.y + 70) + ", " + b.x + " " + (b.y - 40) + ", " + b.x + " " + hint[pair[1]].y,
        fill: "none", stroke: "#3a342c", "stroke-width": "1.1", "stroke-dasharray": "4 5"
      });
      svg.appendChild(path);
    });
    hint.forEach(function (box) {
      svg.appendChild(svgEl("rect", {
        x: box.x, y: box.y, width: box.w, height: "48", rx: "10",
        fill: "#1c1915", stroke: "#3a342c", "stroke-dasharray": "4 4"
      }));
      var t = svgEl("text", {
        x: box.x + box.w / 2, y: box.y + 29, fill: "#8a8276",
        "text-anchor": "middle", "font-size": "13",
        "font-family": "Segoe UI, ui-sans-serif, system-ui, sans-serif"
      });
      t.textContent = box.label;
      svg.appendChild(t);
    });
    var caption = svgEl("text", {
      x: W / 2, y: H - 28, fill: "#6d675c", "text-anchor": "middle",
      "font-size": "14", "font-family": "Iowan Old Style, Palatino, serif"
    });
    caption.textContent = "A model release looks like this. Open it to re-hash the real one.";
    svg.appendChild(caption);
  }

  function draw(opts) {
    var svg = $("graph");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var nodes = graph.nodes;
    if (!nodes.length) {
      cam = { x: 0, y: 0, w: VIEW_W, h: VIEW_H };
      applyCam();
      emptyGraph(svg, VIEW_W, VIEW_H);
      return;
    }
    var byD = {};
    var maxD = 0;
    nodes.forEach(function (n) {
      maxD = Math.max(maxD, n.depth);
      (byD[n.depth] || (byD[n.depth] = [])).push(n);
    });
    var hgap = 36, vgap = 92, pad = 48;
    var worldW = VIEW_W;
    for (var m = 0; m <= maxD; m++) {
      var layerW = (byD[m] || []).length * NW + Math.max(0, (byD[m] || []).length - 1) * hgap;
      worldW = Math.max(worldW, layerW + pad * 2);
    }
    for (var d = 0; d <= maxD; d++) {
      var layer = byD[d] || [];
      var total = layer.length * NW + Math.max(0, layer.length - 1) * hgap;
      var x = (worldW - total) / 2;
      layer.forEach(function (n) {
        n.x = x; n.y = pad + d * (NH + vgap);
        x += NW + hgap;
      });
    }
    var defs = svgEl("defs", {});
    var marker = svgEl("marker", {
      id: "arrow", viewBox: "0 0 10 10", refX: "8", refY: "5",
      markerWidth: "7", markerHeight: "7", orient: "auto"
    });
    marker.appendChild(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#6a6256" }));
    defs.appendChild(marker);
    svg.appendChild(defs);

    var pos = {};
    nodes.forEach(function (n) { pos[n.cid] = n; });
    graph.edges.forEach(function (e) {
      var a = pos[e.from], b = pos[e.to];
      if (!a || !b) return;
      var x1 = a.x + NW / 2, y1 = a.y + NH;
      var x2 = b.x + NW / 2, y2 = b.y;
      var mid = (y1 + y2) / 2;
      var path = svgEl("path", {
        d: "M " + x1 + " " + y1 + " C " + x1 + " " + mid + ", " + x2 + " " + mid + ", " + x2 + " " + y2,
        fill: "none",
        stroke: "#8a7b5c",
        "stroke-width": "1.35",
        "data-from": e.from,
        "data-to": e.to,
        class: "edge"
      });
      svg.appendChild(path);
      if (e.name) {
        var lab = svgEl("text", {
          x: (x1 + x2) / 2, y: mid - 4, fill: "#a89878",
          "text-anchor": "middle", "font-size": "10",
          "font-family": "SFMono-Regular, Consolas, ui-monospace, monospace",
          "data-from": e.from,
          "data-to": e.to,
          class: "elabel"
        });
        lab.textContent = e.name;
        svg.appendChild(lab);
      }
    });
    nodes.forEach(function (n) {
      var nodeLabel = prettyName(n.name) + ", " + (n.kind === "loading" ? "loading" : (n.intact ? "CID verified" : "CID not verified")) + ", " + short(n.cid);
      var g = svgEl("g", {
        style: "cursor:pointer",
        "data-cid": n.cid,
        class: "vnode",
        role: "button",
        tabindex: "0",
        focusable: "true",
        "aria-label": nodeLabel
      });
      var on = selected === n.cid;
      var loading = n.kind === "loading";
      var fill = loading ? "#181614" : (n.intact ? "#1d211c" : "#2a1614");
      var stroke = on ? "#c9a36a" : (loading ? "#5c564c" : (n.intact ? "#4a5c48" : "#7a3d38"));
      var rect = svgEl("rect", {
        x: n.x, y: n.y, width: NW, height: NH, rx: "11",
        fill: fill, stroke: stroke, "stroke-width": on ? "1.9" : "1.1"
      });
      if (loading) rect.setAttribute("stroke-dasharray", "4 4");
      g.appendChild(rect);
      var label = svgEl("text", {
        x: n.x + 12, y: n.y + 22,
        fill: loading ? "#8a8276" : (n.intact ? "#f3efe6" : "#d9847c"),
        "font-size": "13", "font-family": "Segoe UI, ui-sans-serif, system-ui, sans-serif"
      });
      var name = prettyName(n.name);
      label.textContent = name.length > 20 ? name.slice(0, 19) + "…" : name;
      var sub = svgEl("text", {
        x: n.x + 12, y: n.y + 42, fill: "#8a8680",
        "font-size": "11", "font-family": "SFMono-Regular, Consolas, ui-monospace, monospace"
      });
      sub.textContent = loading ? "fetching…" : (short(n.cid) + " · " + n.size + " B");
      g.appendChild(label);
      g.appendChild(sub);
      function activateNode() {
        if (suppressClick) return;
        selected = n.cid;
        paintSelection();
        showInspect(n);
      }
      g.addEventListener("click", activateNode);
      g.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activateNode();
        }
      });
      g.addEventListener("focus", function () { hovered = n.cid; highlight(); });
      g.addEventListener("blur", function () { hovered = null; highlight(); });
      g.addEventListener("mouseenter", function () { hovered = n.cid; highlight(); });
      g.addEventListener("mouseleave", function () { hovered = null; highlight(); });
      svg.appendChild(g);
    });
    highlight();
    if (!camLocked || (opts && opts.fit && !camLocked)) fitCam();
    else applyCam();
  }

  function paintSelection() {
    var svg = $("graph");
    Array.prototype.forEach.call(svg.querySelectorAll(".vnode"), function (el) {
      var cid = el.getAttribute("data-cid");
      var rec = graph.nodes.filter(function (n) { return n.cid === cid; })[0];
      var rect = el.querySelector("rect");
      if (!rect || !rec) return;
      var on = selected === cid;
      var loading = rec.kind === "loading";
      rect.setAttribute("stroke", on ? "#c9a36a" : (loading ? "#5c564c" : (rec.intact ? "#4a5c48" : "#7a3d38")));
      rect.setAttribute("stroke-width", on ? "1.9" : "1.1");
    });
    highlight();
  }

  function highlight() {
    var svg = $("graph");
    var focus = hovered || selected;
    var related = {};
    if (focus) {
      related[focus] = true;
      graph.edges.forEach(function (e) {
        if (e.from === focus || e.to === focus) {
          related[e.from] = true;
          related[e.to] = true;
        }
      });
    }
    Array.prototype.forEach.call(svg.querySelectorAll(".edge, .elabel"), function (el) {
      var on = !focus || el.getAttribute("data-from") === focus || el.getAttribute("data-to") === focus;
      el.setAttribute("opacity", on ? "1" : ".28");
      if (el.classList.contains("edge")) {
        el.setAttribute("stroke", on ? "#8a7b5c" : "#2c2822");
        if (on) el.setAttribute("marker-end", "url(#arrow)");
        else el.removeAttribute("marker-end");
      }
    });
    Array.prototype.forEach.call(svg.querySelectorAll(".vnode"), function (el) {
      var cid = el.getAttribute("data-cid");
      el.setAttribute("opacity", !focus || related[cid] ? "1" : ".4");
    });
  }

  function setInspect(n, info, intact, err) {
    var box = $("inspect-out");
    box.replaceChildren();
    var h = document.createElement("h3");
    h.textContent = err ? "Could not read" : (prettyName(n && n.name) || "Node");
    box.append(h);
    if (n && n.cid) {
      var c = document.createElement("div");
      c.className = "cid mono";
      c.textContent = n.cid;
      box.append(c);
    }
    if (!err) {
      var bar = document.createElement("div");
      bar.style.marginTop = ".65rem";
      function badge(text, cls) {
        var s = document.createElement("span");
        s.className = "badge ui" + (cls ? " " + cls : "");
        s.textContent = text;
        bar.append(s);
      }
      badge(intact ? "intact" : "mismatch", intact ? "ok" : "bad");
      badge((info && info.kind) || (n && n.kind) || "chunk");
      if (info && info.linksTotal > info.links.length) badge("links truncated", "bad");
      box.append(bar);
    }
    var p = document.createElement("p");
    p.style.margin = ".7rem 0 0";
    p.style.color = "var(--muted)";
    p.textContent = err ? String(err) : whyNode(n);
    box.append(p);
    if (info && info.preview) {
      var pre = document.createElement("pre");
      pre.className = "preview mono";
      pre.textContent = info.preview;
      box.append(pre);
    }
    (info && info.links || []).forEach(function (link) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      b.style.margin = ".55rem .35rem 0 0";
      b.textContent = (link.name || "link") + " →";
      b.addEventListener("click", function () {
        selected = link.target;
        var target = graph.nodes.filter(function (x) { return x.cid === link.target; })[0];
        paintSelection();
        if (target) showInspect(target);
        else showInspect({ cid: link.target, name: link.name, kind: "chunk" });
      });
      box.append(b);
    });
  }

  function showInspect(n) {
    if (typeof n === "string") n = { cid: n, name: n };
    if (n.cid === "pending") return;
    inspectGen += 1;
    var requestGen = inspectGen;
    if (inspectController) inspectController.abort();
    inspectController = new AbortController();
    var controller = inspectController;
    function isCurrent() {
      return requestGen === inspectGen && selected === n.cid;
    }
    function apply(res) {
      if (!isCurrent()) return;
      n.intact = res.intact;
      n.size = res.size;
      n.kind = (res.info && res.info.kind) || n.kind;
      n.info = res.info;
      setInspect(n, res.info, res.intact, null);
    }
    if (n.info) {
      setInspect(n, n.info, n.intact, null);
      return;
    }
    var cached = nodeCache.get(n.cid);
    if (cached && cached.ready) {
      apply(cached.ready);
      return;
    }
    setInspect(n, null, n.intact, null);
    var heading = $("inspect-out").querySelector("h3");
    if (heading) heading.textContent = "Reading…";
    loadNode(n.cid, MAX_NODE_BYTES, controller.signal).then(apply).catch(function (e) {
      if (isCurrent() && e && e.name !== "AbortError") setInspect(n, null, false, e);
    });
  }

  function writeReading(rootName, result) {
    var box = $("reading");
    box.replaceChildren();
    var h = document.createElement("h3");
    h.textContent = "How to read this DAG";
    var p1 = document.createElement("p");
    p1.style.color = "var(--muted)";
    p1.style.margin = "0 0 .7rem";
    var resolution = result.seq ? (" at sequence " + result.seq + " on " + result.resolvedAt) : "";
    p1.textContent = rootName + (result.seq ? " was freshly resolved" : "") + resolution + ". This tab followed only links decoded by dag-core/WASM after each parent passed its CID check. " + result.intact + " of " + result.total + " fetched nodes re-hashed to their names, using " + result.totalBytes + " bytes.";
    var p2 = document.createElement("p");
    p2.style.color = "var(--muted)";
    p2.style.margin = "0 0 .7rem";
    p2.textContent = (result.complete ? "The bounded walk completed. " : "The walk is incomplete: " + result.reason + ". ") + "Top row is the head. Each row below is one link deeper. Hover or focus a node to see only its edges. Arrow labels came from the verified parent bytes; changing one changes that parent CID.";
    var p3 = document.createElement("p");
    p3.style.color = "var(--muted)";
    p3.style.margin = "0";
    p3.textContent = "The pointer is not part of this graph. Its response is mutable and untrusted, so it is fetched without caching each time. This same-origin page does not prove freshness or prevent the origin from changing both the claimed root and verifier; use an independently pinned root, checkpoint, CLI, or verifier for that threat model.";
    box.append(h, p1, p2, p3);
  }

  function revealStage() {
    var r = $("stage").getBoundingClientRect();
    if (r.top < 0 || r.bottom > window.innerHeight) {
      $("stage").scrollIntoView({ behavior: "auto", block: "nearest" });
    }
  }

  function scoreResult(result, fromCache) {
    var suffix = result.complete ? " · complete bounded walk" : " · incomplete: " + result.reason;
    if (fromCache) suffix += " · immutable graph cache";
    $("score").textContent = result.intact + " of " + result.total + " intact" + suffix;
    $("score").className = "score " + (result.complete && result.intact === result.total && result.total ? "ok" : "bad");
  }

  function cacheGraph(root, snapshot) {
    if (graphCache.has(root)) graphCache.delete(root);
    graphCache.set(root, snapshot);
    while (graphCache.size > 16) graphCache.delete(graphCache.keys().next().value);
  }

  function showCachedGraph(id, head, resolvedAt, snap) {
    graph = {
      nodes: snap.nodes.map(function (node) {
        return Object.assign({}, node, node.cid === head.cid ? { name: id } : null);
      }),
      edges: snap.edges.map(function (edge) { return Object.assign({}, edge); })
    };
    selected = snap.root;
    camLocked = false;
    var result = Object.assign({}, snap.result, { seq: head.seq, resolvedAt: resolvedAt });
    scoreResult(result, true);
    writeReading(id, result);
    draw({ fit: true });
    var sel = graph.nodes.filter(function (x) { return x.cid === selected; })[0];
    if (sel) showInspect(sel);
  }

  function openRelease() {
    var id = $("pointer").value.trim();
    revealStage();
    if (activeWalkController) activeWalkController.abort();
    if (inspectController) inspectController.abort();
    dropPendingNodeCache();
    activeWalkController = new AbortController();
    var controller = activeWalkController;
    inspectGen += 1;
    walkGen += 1;
    var gen = walkGen;
    $("score").textContent = "Resolving " + id + "…";
    $("score").className = "score";
    graph = { nodes: [{ cid: "pending", name: id, depth: 0, size: 0, intact: null, kind: "loading" }], edges: [] };
    selected = "pending";
    camLocked = false;
    draw({ fit: true });
    Promise.all([kernelReady, resolvePointer(id, controller.signal)]).then(function (values) {
      var head = values[1];
      if (gen !== walkGen) return;
      selected = head.cid;
      var resolvedAt = new Date().toISOString();
      $("score").textContent = id + " · freshly resolved seq " + head.seq;
      var cachedGraph = graphCache.get(head.cid);
      if (cachedGraph) {
        if (activeWalkController === controller) activeWalkController = null;
        showCachedGraph(id, head, resolvedAt, cachedGraph);
        return;
      }
      return walk(head.cid, id, head.seq, resolvedAt, gen, controller);
    }).catch(function (e) {
      if (gen !== walkGen) return;
      if (activeWalkController === controller) activeWalkController = null;
      $("score").textContent = e instanceof Error ? e.message : String(e);
      $("score").className = "score bad";
    });
  }

  function walk(root, rootName, sequence, resolvedAt, gen, controller) {
    graph = { nodes: [], edges: [] };
    var discovered = new Set([root]);
    var pending = [{ cid: root, name: rootName || "(root)", depth: 0 }];
    var inflight = 0;
    var intact = 0;
    var totalBytes = 0;
    var reservedBytes = 0;
    var linksRead = 0;
    var incompleteReason = null;
    var paintFrame = null;
    var done = false;

    function markIncomplete(reason) {
      if (!incompleteReason) incompleteReason = reason;
    }

    function paint() {
      if (paintFrame !== null || done) return;
      paintFrame = requestAnimationFrame(function () {
        paintFrame = null;
        if (done || gen !== walkGen) return;
        var n = graph.nodes.length;
        var ready = graph.nodes.filter(function (x) { return x.kind !== "loading"; }).length;
        $("score").textContent = intact + " of " + n + " intact" + (ready < n ? " · loading" : "") + " · " + totalBytes + " bytes";
        $("score").className = "score";
        draw({ fit: true });
      });
    }

    function enqueue(job, reservation) {
      var rec = { cid: job.cid, name: job.name, depth: job.depth, size: 0, intact: null, kind: "loading" };
      graph.nodes.push(rec);
      inflight += 1;
      reservedBytes += reservation;
      paint();
      loadNode(job.cid, reservation, controller.signal).then(function (res) {
        if (gen !== walkGen) return;
        reservedBytes -= reservation;
        totalBytes += res.size;
        rec.size = res.size;
        rec.intact = res.intact;
        rec.kind = (res.info && res.info.kind) || "bytes";
        rec.info = res.info;
        if (res.intact) intact += 1;
        var links = res.info && res.info.links || [];
        if (res.intact && res.info && res.info.linksTotal > links.length) {
          markIncomplete("an entry exceeded the " + MAX_LINKS + "-link local decode limit");
        }
        if (res.intact && links.length && job.depth >= MAX_DEPTH) {
          markIncomplete("the walk reached its depth limit of " + MAX_DEPTH);
        } else if (res.intact) {
          for (var linkIndex = 0; linkIndex < links.length; linkIndex += 1) {
            var link = links[linkIndex];
            if (linksRead >= MAX_LINKS) {
              markIncomplete("the walk reached its total link limit of " + MAX_LINKS);
              break;
            }
            linksRead += 1;
            if (graph.edges.length >= MAX_EDGES) {
              markIncomplete("the walk reached its edge limit of " + MAX_EDGES);
              break;
            }
            graph.edges.push({ from: job.cid, to: link.target, name: link.name });
            if (!discovered.has(link.target)) {
              if (discovered.size >= MAX_WALK) {
                markIncomplete("the walk reached its node limit of " + MAX_WALK);
                continue;
              }
              discovered.add(link.target);
              pending.push({ cid: link.target, name: link.name || "(link)", depth: job.depth + 1 });
            }
          }
        }
        inflight -= 1;
        pump();
        paint();
        maybeFinish();
      }).catch(function (error) {
        if (gen !== walkGen) return;
        reservedBytes -= reservation;
        rec.kind = "error";
        rec.intact = false;
        rec.error = error instanceof Error ? error.message : String(error);
        markIncomplete(rec.error.indexOf("byte budget") >= 0 ? "the walk reached its " + MAX_TOTAL_BYTES + "-byte total limit" : "at least one discovered node could not be verified");
        inflight -= 1;
        pump();
        paint();
        maybeFinish();
      });
    }

    function pump() {
      if (gen !== walkGen) return;
      while (pending.length && inflight < WALK_CONCUR) {
        var remaining = MAX_TOTAL_BYTES - totalBytes - reservedBytes;
        if (remaining <= 0) {
          markIncomplete("the walk reached its " + MAX_TOTAL_BYTES + "-byte total limit");
          pending.length = 0;
          break;
        }
        enqueue(pending.shift(), Math.min(MAX_NODE_BYTES, remaining));
      }
      if (pending.length && graph.nodes.length >= MAX_WALK) {
        pending.length = 0;
        markIncomplete("the walk reached its node limit of " + MAX_WALK);
      }
    }

    function maybeFinish() {
      if (done || inflight || pending.length) return;
      done = true;
      finish();
    }

    function finish() {
      if (gen !== walkGen) return;
      if (activeWalkController === controller) activeWalkController = null;
      if (paintFrame !== null) {
        cancelAnimationFrame(paintFrame);
        paintFrame = null;
      }
      var n = graph.nodes.length;
      var result = {
        intact: intact,
        total: n,
        totalBytes: totalBytes,
        complete: incompleteReason === null && intact === n && n > 0,
        reason: incompleteReason || (intact === n ? "" : "one or more CID checks failed"),
        seq: sequence,
        resolvedAt: resolvedAt
      };
      scoreResult(result, false);
      writeReading(rootName, result);
      camLocked = false;
      draw({ fit: true });
      if (result.complete) {
        cacheGraph(root, { nodes: graph.nodes, edges: graph.edges, root: root, result: result });
      }
      var sel = graph.nodes.filter(function (x) { return x.cid === selected; })[0] || graph.nodes[0];
      if (sel) showInspect(sel);
    }

    pump();
    maybeFinish();
  }

  function put() {
    var token = tokenInput.value;
    var out = $("write-out");
    out.hidden = false;
    if (!secureWriteContext) { out.textContent = "Writes require HTTPS."; return; }
    if (!token) { out.textContent = "Token required."; return; }
    var bytes = new TextEncoder().encode($("payload").value);
    if (bytes.length > MAX_NODE_BYTES) { out.textContent = "Payload exceeds the 4 MiB chunk limit."; return; }
    sha256hex(bytes).then(function (cid) {
      return fetch("/c/" + cid, {
        method: "PUT",
        headers: { Authorization: "Bearer " + token, "Content-Type": "application/octet-stream" },
        body: bytes
      }).then(function (r) {
        if (!r.ok) return readTextBounded(r, MAX_CONTROL_BYTES, "write response").then(function (t) { throw new Error("write returned HTTP " + r.status + (t ? ": " + t.slice(0, 300) : "")); });
        out.textContent = "Stored " + cid;
        selected = cid;
        var info = localRawInfo(bytes);
        graph.nodes = [{ cid: cid, name: "new chunk", depth: 0, size: bytes.length, intact: true, kind: info.kind, info: info }];
        graph.edges = [];
        var result = { intact: 1, total: 1, totalBytes: bytes.length, complete: true, reason: "", seq: null, resolvedAt: new Date().toISOString() };
        scoreResult(result, false);
        writeReading("new chunk", result);
        camLocked = false;
        draw({ fit: true });
        showInspect(graph.nodes[0]);
      });
    }).catch(function (e) { out.textContent = e instanceof Error ? e.message : String(e); });
  }

  function currentSequence(id) {
    return fetch("/p/" + encodeURIComponent(id), {
      cache: "no-store",
      credentials: "same-origin",
      headers: { "Cache-Control": "no-cache", Accept: "application/json" }
    }).then(function (response) {
      if (response.status === 404) return 0;
      if (!response.ok) throw new Error("pointer precondition read returned HTTP " + response.status);
      return readJsonBounded(response, MAX_CONTROL_BYTES, "pointer precondition response").then(function (head) {
        if (!strictObject(head) || !Number.isSafeInteger(head.seq) || head.seq < 1 || !validCid(head.cid)) {
          throw new Error("pointer precondition read returned an invalid head");
        }
        return head.seq;
      });
    });
  }

  function point() {
    var token = tokenInput.value;
    var id = $("point-id").value.trim();
    var cid = selected;
    var out = $("write-out");
    out.hidden = false;
    if (!secureWriteContext) { out.textContent = "Writes require HTTPS."; return; }
    if (!token || !id || !cid) { out.textContent = "Token, name, and a selected CID required."; return; }
    var selectedNode = graph.nodes.filter(function (node) { return node.cid === cid; })[0];
    if (!validCid(cid) || !selectedNode || selectedNode.intact !== true) {
      out.textContent = "Select a CID that this tab has verified before moving a pointer.";
      return;
    }
    currentSequence(id).then(function (expect) {
      return fetch("/pointers", {
        method: "POST",
        credentials: "same-origin",
        headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
        body: JSON.stringify({ id: id, cid: cid, expect_seq: expect })
      });
    }).then(function (r) {
      return readTextBounded(r, MAX_CONTROL_BYTES, "pointer update response").then(function (t) {
        if (!r.ok) throw new Error("pointer update returned HTTP " + r.status + (t ? ": " + t.slice(0, 300) : ""));
        out.textContent = "Pointer " + id + " now names " + cid;
        walkGen += 1;
        if ($("pointer").value.trim() === id) openRelease();
      });
    }).catch(function (e) { out.textContent = e instanceof Error ? e.message : String(e); });
  }

  function bindCamera() {
    var svg = $("graph");
    var drag = null;
    var pts = {};
    var pinch = null;
    svg.addEventListener("pointerdown", function (ev) {
      if (ev.pointerType === "mouse" && ev.button !== 0) return;
      pts[ev.pointerId] = { x: ev.clientX, y: ev.clientY };
      var ids = Object.keys(pts);
      if (ids.length === 2) {
        var a = pts[ids[0]], b = pts[ids[1]];
        var dx = a.x - b.x, dy = a.y - b.y;
        pinch = { d: Math.sqrt(dx * dx + dy * dy) || 1, w: cam.w, h: cam.h, x: cam.x, y: cam.y };
        drag = null;
        return;
      }
      drag = { id: ev.pointerId, x: ev.clientX, y: ev.clientY, vx: cam.x, vy: cam.y, moved: false };
      svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener("pointermove", function (ev) {
      if (pts[ev.pointerId]) pts[ev.pointerId] = { x: ev.clientX, y: ev.clientY };
      var ids = Object.keys(pts);
      if (pinch && ids.length >= 2) {
        var a = pts[ids[0]], b = pts[ids[1]];
        var dx = a.x - b.x, dy = a.y - b.y;
        var d = Math.sqrt(dx * dx + dy * dy) || 1;
        var nw = Math.max(180, Math.min(3600, pinch.w * (pinch.d / d)));
        var nh = nw * (VIEW_H / VIEW_W);
        var rect = svg.getBoundingClientRect();
        var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        var px = (mx - rect.left) / rect.width;
        var py = (my - rect.top) / rect.height;
        var wx = pinch.x + px * pinch.w;
        var wy = pinch.y + py * pinch.h;
        cam.w = nw; cam.h = nh;
        cam.x = wx - px * nw;
        cam.y = wy - py * nh;
        camLocked = true;
        suppressClick = true;
        applyCam();
        return;
      }
      if (!drag || ev.pointerId !== drag.id) return;
      var rect = svg.getBoundingClientRect();
      var pdx = ev.clientX - drag.x;
      var pdy = ev.clientY - drag.y;
      if (Math.abs(pdx) + Math.abs(pdy) > 3) {
        drag.moved = true;
        suppressClick = true;
        svg.classList.add("panning");
      }
      if (!drag.moved) return;
      ev.preventDefault();
      cam.x = drag.vx - pdx * (cam.w / rect.width);
      cam.y = drag.vy - pdy * (cam.h / rect.height);
      camLocked = true;
      applyCam();
    });
    function endPtr(ev) {
      delete pts[ev.pointerId];
      if (drag && ev.pointerId === drag.id) {
        drag = null;
        svg.classList.remove("panning");
      }
      if (Object.keys(pts).length < 2) pinch = null;
      setTimeout(function () { suppressClick = false; }, 0);
    }
    svg.addEventListener("pointerup", endPtr);
    svg.addEventListener("pointercancel", endPtr);
    svg.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var rect = svg.getBoundingClientRect();
      var px = (ev.clientX - rect.left) / rect.width;
      var py = (ev.clientY - rect.top) / rect.height;
      var mx = cam.x + px * cam.w;
      var my = cam.y + py * cam.h;
      var factor = ev.deltaY < 0 ? 0.88 : 1.12;
      var nw = Math.max(180, Math.min(3600, cam.w * factor));
      var nh = nw * (VIEW_H / VIEW_W);
      cam.x = mx - px * nw;
      cam.y = my - py * nh;
      cam.w = nw;
      cam.h = nh;
      camLocked = true;
      applyCam();
    }, { passive: false });
    svg.addEventListener("keydown", function (ev) {
      var handled = true;
      var stepX = cam.w * 0.08;
      var stepY = cam.h * 0.08;
      if (ev.key === "ArrowLeft") cam.x -= stepX;
      else if (ev.key === "ArrowRight") cam.x += stepX;
      else if (ev.key === "ArrowUp") cam.y -= stepY;
      else if (ev.key === "ArrowDown") cam.y += stepY;
      else if (ev.key === "+" || ev.key === "=") {
        cam.x += cam.w * 0.06; cam.y += cam.h * 0.06;
        cam.w *= 0.88; cam.h *= 0.88;
      } else if (ev.key === "-" || ev.key === "_") {
        cam.x -= cam.w * 0.06; cam.y -= cam.h * 0.06;
        cam.w *= 1.12; cam.h *= 1.12;
      } else if (ev.key === "0" || ev.key === "Home") {
        fitCam();
        ev.preventDefault();
        return;
      } else handled = false;
      if (!handled) return;
      ev.preventDefault();
      cam.w = Math.max(180, Math.min(3600, cam.w));
      cam.h = cam.w * (VIEW_H / VIEW_W);
      camLocked = true;
      applyCam();
    });
  }

  $("fit").addEventListener("click", function () {
    camLocked = false;
    if (graph.nodes.length) fitCam();
  });
  $("open").addEventListener("click", openRelease);
  $("pointer").addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") openRelease();
  });
  $("put").addEventListener("click", put);
  $("point").addEventListener("click", point);
  bindCamera();
  draw();
})();
</script>
</body>
</html>`;
}
