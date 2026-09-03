import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import {
  DAG_WASM_JS_SHA256_SRI,
  DAG_WASM_SHA256_HEX,
} from "../../../dag-wasm/web/browser-kernel.mjs";
import { consolePage } from "../src/ui.ts";

const NONCE = "0123456789abcdef0123456789abcdef";

describe("consolePage", () => {
  it("ships a nonce-bound, locally decoded, explicitly bounded verifier", () => {
    const html = consolePage(NONCE);
    assert.match(html, /id="graph"/);
    assert.match(html, /Open this release/);
    assert.match(html, /Why it exists/);
    assert.match(html, /How it works/);
    assert.match(html, /What is novel/);
    assert.match(html, new RegExp(`<style nonce="${NONCE}">`));
    assert.match(html, new RegExp(`<script type="module" nonce="${NONCE}">`));
    assert.match(html, /script\.src = "\/assets\/dag_wasm\.js\?v=" \+ encodeURIComponent\(WASM_JS_INTEGRITY\)/);
    assert.match(html, /dag_wasm_bg\.wasm\?v=" \+ WASM_SHA256/);
    assert.match(html, /script\.integrity = WASM_JS_INTEGRITY/);
    assert.match(html, /kernel\.inspect_chunk\(bytes\)/);
    assert.match(html, new RegExp(`WASM_SHA256 = "${DAG_WASM_SHA256_HEX}"`));
    assert.match(html, /nodeCache = new Map\(\)/);
    assert.match(html, /graphCache = new Map\(\)/);
    assert.match(html, /cache: "no-store"/);
    assert.match(html, /fetch\("\/ready"/);
    assert.match(html, /response\.status !== 200 && response\.status !== 503/);
    assert.match(html, /demo \/ not production ready/);
    assert.match(html, /R2 for durable deployments or isolated KV for ephemeral demos/);
    assert.match(html, /bytes fetched from this replica hashed to this name in your browser/);
    assert.doesNotMatch(html, /bytes in R2 hashed to this name in your browser/);
    assert.doesNotMatch(html, /fetch\("\/health"/);
    assert.match(html, /encodeURIComponent\(id\)/);
    assert.match(html, /MAX_WALK = 16/);
    assert.match(html, /MAX_TOTAL_BYTES = 16 \* 1024 \* 1024/);
    assert.match(html, /MAX_LINKS = 256/);
    assert.match(html, /MAX_EDGES = 256/);
    assert.match(html, /MAX_CONTROL_BYTES = 64 \* 1024/);
    assert.match(html, /WALK_CONCUR = 4/);
    assert.match(html, /activeWalkController\.abort\(\)/);
    assert.match(html, /dropPendingNodeCache\(\)/);
    assert.match(html, /cancelAnimationFrame\(paintFrame\)/);
    assert.match(html, /role: "button"/);
    assert.match(html, /tabindex: "0"/);
    assert.match(html, /event\.key === "Enter" \|\| event\.key === " "/);
    assert.match(html, /same-origin page does not prove freshness/);
    assert.doesNotMatch(html, /\/i\//);
    assert.doesNotMatch(html, /headCache/);
    assert.doesNotMatch(html, /sessionStorage|localStorage/);
    assert.doesNotMatch(html, /encodeURI\(/);
    assert.doesNotMatch(html, /fonts\.googleapis|fonts\.gstatic/);
    assert.doesNotMatch(html, /setInterval|EventSource/);
    assert.doesNotMatch(html, /\$\{/);
  });

  it("emits syntactically valid controller JavaScript", () => {
    const html = consolePage(NONCE);
    const script = html.match(/<script type="module"[^>]*>([\s\S]*)<\/script>/)?.[1];
    assert.ok(script);
    assert.doesNotThrow(() => new Function(script));
    assert.match(script, /\/\^\\d\+\$\//, "Content-Length validation keeps its digit escape");
  });

  it("rejects a missing or injectable CSP nonce", () => {
    assert.throws(() => consolePage(""), /CSP nonce/);
    assert.throws(() => consolePage('safe"><script>alert(1)<\/script>'), /CSP nonce/);
  });
});

describe("committed browser kernel", () => {
  it("matches the pinned WASM and JavaScript digests", () => {
    const wasm = readFileSync(new URL("../public/dag_wasm_bg.wasm", import.meta.url));
    const js = readFileSync(new URL("../public/dag_wasm.js", import.meta.url));
    assert.equal(wasm.subarray(0, 4).toString("hex"), "0061736d");
    assert.equal(createHash("sha256").update(wasm).digest("hex"), DAG_WASM_SHA256_HEX);
    assert.equal(
      `sha256-${createHash("sha256").update(js).digest("base64")}`,
      DAG_WASM_JS_SHA256_SRI,
    );
    assert.match(js.toString("utf8"), /__exports\.inspect_chunk/);
  });

  it("keeps the standalone verifier on the same artifacts and local topology", () => {
    const workerWasm = readFileSync(new URL("../public/dag_wasm_bg.wasm", import.meta.url));
    const workerJs = readFileSync(new URL("../public/dag_wasm.js", import.meta.url));
    const standaloneWasm = readFileSync(
      new URL("../../../dag-wasm/web/dist/dag_wasm_bg.wasm", import.meta.url),
    );
    const standaloneJs = readFileSync(
      new URL("../../../dag-wasm/web/dist/dag_wasm.js", import.meta.url),
    );
    const verifier = readFileSync(
      new URL("../../../dag-wasm/web/verify.js", import.meta.url),
      "utf8",
    );
    assert.deepEqual(standaloneWasm, workerWasm);
    assert.deepEqual(standaloneJs, workerJs);
    assert.match(verifier, /kernel\.inspect_chunk\(bytes\)/);
    assert.match(verifier, /cache: "no-store"/);
    assert.match(verifier, /activeController\.abort\(\)/);
    assert.doesNotMatch(verifier, /\/api\/graph/);
  });
});
