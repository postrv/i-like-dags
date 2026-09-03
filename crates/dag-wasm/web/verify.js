import {
  DAG_WASM_JS_SHA256_SRI,
  DAG_WASM_SHA256_HEX,
} from "./browser-kernel.mjs";

const MAX_NODES = 64;
const MAX_NODE_BYTES = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES = 16 * 1024 * 1024;
const MAX_DEPTH = 8;
const MAX_LINKS = 256;
const MAX_CONTROL_BYTES = 64 * 1024;
const CID = /^[0-9a-f]{64}$/;
const $ = (id) => document.getElementById(id);
let runGeneration = 0;
let activeController = null;

function sha256hex(bytes) {
  return crypto.subtle.digest("SHA-256", bytes).then((digest) =>
    [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  );
}

async function readBounded(response, limit) {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
    throw new Error("response exceeds the remaining byte budget");
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > limit) throw new Error("response exceeds the remaining byte budget");
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > limit) {
        await reader.cancel();
        throw new Error("response exceeds the remaining byte budget");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

async function readJsonBounded(response, limit, label) {
  const bytes = await readBounded(response, limit);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error(`${label} was not valid JSON`);
  }
}

function loadVerifierScript() {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = `./dist/dag_wasm.js?v=${encodeURIComponent(DAG_WASM_JS_SHA256_SRI)}`;
    script.integrity = DAG_WASM_JS_SHA256_SRI;
    script.crossOrigin = "anonymous";
    script.onload = resolve;
    script.onerror = () => reject(new Error("verifier JavaScript failed its integrity or load check"));
    document.head.appendChild(script);
  });
}

const kernelReady = Promise.all([
  fetch(`./dist/dag_wasm_bg.wasm?v=${DAG_WASM_SHA256_HEX}`, { cache: "force-cache" }).then((response) => {
    if (!response.ok) throw new Error(`WASM returned HTTP ${response.status}`);
    return readBounded(response, 1024 * 1024);
  }),
  loadVerifierScript(),
]).then(async ([bytes]) => {
  if (await sha256hex(bytes) !== DAG_WASM_SHA256_HEX) {
    throw new Error("verifier WASM digest mismatch");
  }
  if (typeof window.DagWasm !== "function" || typeof window.DagWasm.inspect_chunk !== "function") {
    throw new Error("verifier exports are incomplete");
  }
  await window.DagWasm({ module_or_path: bytes });
  $("engine").textContent = `kernel: dag-core/WASM · pinned ${DAG_WASM_SHA256_HEX.slice(0, 12)}…`;
  return window.DagWasm;
}).catch((error) => {
  $("engine").textContent = `kernel unavailable: ${error.message || String(error)}`;
  $("engine").className = "bad";
  throw error;
});
kernelReady.catch(() => {});

function validateInspection(text) {
  const value = JSON.parse(text);
  if (!value || (value.kind !== "entry" && value.kind !== "bytes") ||
      !Array.isArray(value.links) || value.links.length > MAX_LINKS ||
      !Number.isSafeInteger(value.links_total) || value.links_total < value.links.length ||
      !Number.isSafeInteger(value.payload_len) || value.payload_len < 0 ||
      (value.preview !== null && (typeof value.preview !== "string" || value.preview.length > 2050))) {
    throw new Error("verifier returned an invalid inspection record");
  }
  for (const link of value.links) {
    if (!link || !CID.test(link.target) ||
        (link.name !== null && (typeof link.name !== "string" || link.name.length > 514))) {
      throw new Error("verifier returned an invalid link");
    }
  }
  return value;
}

async function resolveRoot(base, signal) {
  const supplied = $("root").value.trim();
  if (supplied) {
    if (!CID.test(supplied)) throw new Error("trusted root must be 64 lowercase hexadecimal characters");
    return { cid: supplied, source: "supplied out-of-band root" };
  }
  const pointer = $("pointer").value.trim();
  if (!pointer) throw new Error("pointer or trusted root required");
  const response = await fetch(`${base}/api/pointers/resolve?id=${encodeURIComponent(pointer)}`, {
    cache: "no-store",
    headers: { "Cache-Control": "no-cache", Accept: "application/json" },
    signal,
  });
  if (!response.ok) throw new Error(`pointer resolve returned HTTP ${response.status}`);
  const body = await readJsonBounded(response, MAX_CONTROL_BYTES, "pointer response");
  const cid = body.cid || body.current_cid || body;
  const root = typeof cid === "string" ? cid : cid?.cid;
  if (!CID.test(root)) throw new Error("pointer resolve returned an invalid CID");
  return { cid: root, source: `untrusted pointer ${pointer}` };
}

async function getChunk(base, cid, remaining, signal) {
  const response = await fetch(`${base}/api/chunks?cid=${encodeURIComponent(cid)}`, {
    cache: "force-cache",
    signal,
  });
  if (!response.ok) throw new Error(`chunk ${cid.slice(0, 12)}… returned HTTP ${response.status}`);
  return readBounded(response, Math.min(MAX_NODE_BYTES, remaining));
}

async function verify(generation, controller) {
  $("err").hidden = true;
  $("nodes").replaceChildren();
  $("score").hidden = true;
  const kernel = await kernelReady;
  const base = $("base").value.trim().replace(/\/$/, "");
  if (!/^https?:\/\//.test(base)) throw new Error("content plane base must be an HTTP(S) URL");
  const root = await resolveRoot(base, controller.signal);
  if (generation !== runGeneration) return;
  const pending = [{ cid: root.cid, depth: 0, name: root.source }];
  const seen = new Set([root.cid]);
  let intact = 0;
  let totalBytes = 0;
  let linksRead = 0;
  let incomplete = null;

  while (pending.length) {
    if (seen.size > MAX_NODES) { incomplete ||= `node limit ${MAX_NODES}`; break; }
    const node = pending.shift();
    const remaining = MAX_TOTAL_BYTES - totalBytes;
    if (remaining <= 0) { incomplete ||= `byte limit ${MAX_TOTAL_BYTES}`; break; }
    const bytes = await getChunk(base, node.cid, remaining, controller.signal);
    if (generation !== runGeneration) return;
    totalBytes += bytes.length;
    const ok = await sha256hex(bytes) === node.cid;
    let inspection = { kind: "unverified", links: [], links_total: 0 };
    if (ok) {
      intact += 1;
      inspection = validateInspection(kernel.inspect_chunk(bytes));
    }
    const li = document.createElement("li");
    li.className = ok ? "ok" : "bad";
    li.textContent = `${ok ? "intact" : "corrupt"}  ${node.name || "node"}  ${node.cid.slice(0, 12)}…  ${bytes.length} bytes  ${inspection.kind}`;
    $("nodes").appendChild(li);
    if (!ok) continue;
    if (inspection.links_total > inspection.links.length) incomplete ||= "per-entry link decode limit";
    if (node.depth >= MAX_DEPTH && inspection.links.length) {
      incomplete ||= `depth limit ${MAX_DEPTH}`;
      continue;
    }
    for (const link of inspection.links) {
      if (linksRead >= MAX_LINKS) { incomplete ||= `link limit ${MAX_LINKS}`; break; }
      linksRead += 1;
      if (!seen.has(link.target)) {
        if (seen.size >= MAX_NODES) { incomplete ||= `node limit ${MAX_NODES}`; continue; }
        seen.add(link.target);
        pending.push({ cid: link.target, depth: node.depth + 1, name: link.name || "link" });
      }
    }
  }

  const total = $("nodes").children.length;
  const complete = !incomplete && intact === total && total > 0 && pending.length === 0;
  $("score").hidden = false;
  $("score").className = `score ${complete ? "ok" : "bad"}`;
  $("score").textContent = `${intact} of ${total} · ${complete ? "complete bounded walk" : `incomplete${incomplete ? `: ${incomplete}` : ""}`}`;
}

$("run").addEventListener("click", () => {
  if (activeController) activeController.abort();
  activeController = new AbortController();
  runGeneration += 1;
  const generation = runGeneration;
  const controller = activeController;
  verify(generation, controller).catch((error) => {
    if (generation !== runGeneration || error?.name === "AbortError") return;
    $("err").hidden = false;
    $("err").textContent = String(error?.message || error).slice(0, 300);
  });
});

for (const input of [$("base"), $("pointer"), $("root")]) {
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("run").click();
  });
}
window.addEventListener("pagehide", () => activeController?.abort());
