import {
  env,
  evictDurableObject,
  listDurableObjectIds,
  runDurableObjectAlarm,
  runInDurableObject,
  SELF,
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  ensureR2ReservationMarker,
  inspectR2BudgetObject,
  openStore,
  type ChunkStore,
  writeR2ReservedChunk,
} from "../../src/chunks.ts";
import { cidToIntArray, computeCidHex } from "../../src/cid.ts";
import { encodeCbor } from "../../src/cbor.ts";
import {
  ReferenceClosureError,
  validatePublicationClosure,
  type ClosureBudgets,
} from "../../src/closure.ts";
import { encodeEntry, encodePointerEvent } from "../../src/dag.ts";
import edgeWorker from "../../src/index.ts";
import {
  DEMO_MAX_PUBLICATION_GROUPS,
  INSPECT_LINK_LIMIT,
  MAX_CATALOG_NAMES,
  MAX_CHUNK_SIZE,
  MAX_ENTRY_LINKS,
  MAX_POINTER_EVENT_PAYLOAD,
  MAX_TERMINAL_SYNC_SESSIONS,
  OPERATION_LEASE_SECONDS,
  RESERVATION_RECONCILE_BATCH,
  SYNC_SESSION_SECONDS,
} from "../../src/limits.ts";
import type { EdgeEnv } from "../../src/types.ts";

const TOKEN = "test-ingest-token-00000000000000000000000000000000";
let SESSION_A = "00000000-0000-4000-8000-00000000000a";
let SESSION_B = "00000000-0000-4000-8000-00000000000b";

function authHeaders(contentType?: string, session?: string): Headers {
  const headers = new Headers({ authorization: `Bearer ${TOKEN}` });
  if (contentType) headers.set("content-type", contentType);
  if (session) headers.set("x-dag-sync-session", session);
  return headers;
}

async function putBytes(bytes: Uint8Array): Promise<string> {
  const cid = await computeCidHex(bytes);
  const response = await SELF.fetch(`https://example.test/c/${cid}`, {
    method: "PUT",
    headers: authHeaders("application/octet-stream"),
    body: bytes,
  });
  expect(response.status).toBe(204);
  return cid;
}

function pinEntry(pinId: string, target: string, ts: number): Uint8Array {
  return pinEventEntry(pinId, target, 1, null, ts);
}

function pinEventEntry(
  pinId: string,
  target: string,
  seq: number,
  prev: string | null,
  ts = seq,
): Uint8Array {
  return encodeEntry(
    encodeCbor({
      seq,
      pin_id: pinId,
      target: { Direct: cidToIntArray(target) },
      scope: "Global",
      expires_at: null,
      state: "Active",
      ts,
      author: null,
      ...(prev === null ? {} : { prev: cidToIntArray(prev) }),
    }),
  );
}

async function pointerEntry(pointerId: string, target: string, seq = 1, prev: string | null = null): Promise<string> {
  return putBytes(
    encodeEntry(
      encodePointerEvent({ seq, pointerId, prev, new: target, ts: seq }),
    ),
  );
}

async function finalize(session = SESSION_A): Promise<Response> {
  return SELF.fetch("https://example.test/sync/finalize", {
    method: "POST",
    headers: authHeaders(undefined, session),
    body: "",
  });
}

function numberedSession(index: number): string {
  return `10000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function rustEntryPrefix(declaredLinks: number): Uint8Array {
  return new Uint8Array([
    0xa2,
    0x67, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
    0x80,
    0x65, 0x6c, 0x69, 0x6e, 0x6b, 0x73,
    0x9a,
    (declaredLinks >>> 24) & 0xff,
    (declaredLinks >>> 16) & 0xff,
    (declaredLinks >>> 8) & 0xff,
    declaredLinks & 0xff,
  ]);
}

function largeRustEntry(linkCount: number): Uint8Array {
  const prefix = rustEntryPrefix(linkCount);
  const link = new Uint8Array([
    0xa2,
    0x64, 0x6e, 0x61, 0x6d, 0x65,
    0x61, 0x61,
    0x66, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
    0x98, 0x20,
    ...new Uint8Array(32),
  ]);
  const bytes = new Uint8Array(prefix.byteLength + link.byteLength * linkCount);
  bytes.set(prefix);
  for (let i = 0; i < linkCount; i++) bytes.set(link, prefix.byteLength + i * link.byteLength);
  return bytes;
}

function linkedEntry(targets: string[], payload = new Uint8Array()): Uint8Array {
  return encodeCbor({
    payload: Array.from(payload),
    links: targets.map((target) => ({ name: null, target: cidToIntArray(target) })),
  });
}

async function memoryStore(bytes: Uint8Array[]): Promise<{ store: ChunkStore; cids: string[] }> {
  const objects = new Map<string, Uint8Array>();
  const cids: string[] = [];
  for (const value of bytes) {
    const cid = await computeCidHex(value);
    objects.set(cid, value);
    cids.push(cid);
  }
  const store: ChunkStore = {
    backend: "r2",
    async get(cid) {
      return objects.get(cid) ?? null;
    },
    async put(cid, value) {
      objects.set(cid, value);
    },
    async missing(cid) {
      return !objects.has(cid);
    },
  };
  return { store, cids };
}

const GENEROUS_TEST_CLOSURE_BUDGETS: ClosureBudgets = {
  maxObjects: 16,
  maxBytes: 1024 * 1024,
  maxLinks: 16,
  maxDepth: 16,
};

async function expectClosureError(
  promise: Promise<unknown>,
  code: ReferenceClosureError["code"],
): Promise<void> {
  try {
    await promise;
    throw new Error(`expected closure error ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(ReferenceClosureError);
    expect((error as ReferenceClosureError).code).toBe(code);
  }
}

describe("edge Worker runtime", () => {
  beforeEach(() => {
    SESSION_A = crypto.randomUUID();
    SESSION_B = crypto.randomUUID();
  });

  it("does not instantiate a per-name Durable Object for an unknown public pointer", async () => {
    const response = await SELF.fetch("https://example.test/p/arbitrary-public-probe");
    expect(response.status).toBe(404);
    expect(await listDurableObjectIds(env.POINTERS)).toHaveLength(0);
  });

  it("fails closed for unauthenticated writes and plaintext transport", async () => {
    const cid = "00".repeat(32);
    const unauthorized = await SELF.fetch(`https://example.test/c/${cid}`, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: new Uint8Array(),
    });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("www-authenticate")).toContain("Bearer");

    const plaintext = await SELF.fetch(`http://example.test/c/${cid}`, {
      method: "PUT",
      headers: authHeaders("application/octet-stream"),
      body: new Uint8Array(),
    });
    expect(plaintext.status).toBe(400);

    const redirected = await SELF.fetch("http://example.test/health", { redirect: "manual" });
    expect(redirected.status).toBe(308);
    expect(redirected.headers.get("location")).toBe("https://example.test/health");

    const loopback = await SELF.fetch("http://127.0.0.1:8788/health");
    expect(loopback.status).toBe(200);
  });

  it("separates liveness from fail-closed production readiness", async () => {
    const health = await SELF.fetch("https://example.test/health");
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true, status: "live" });

    const ready = await SELF.fetch("https://example.test/ready");
    expect(ready.status).toBe(503);
    expect(await ready.json()).toMatchObject({
      ok: false,
      status: "not_ready",
      production_ready: false,
      mode: "test",
      perimeter_confirmed: false,
    });
    expect((await SELF.fetch("https://example.test/ready", { method: "HEAD" })).status).toBe(503);

    const limiter: RateLimit = {
      async limit() {
        return { success: true };
      },
    };
    const productionEnv: EdgeEnv = {
      ...env,
      DAG_EDGE_MODE: "production-r2",
      DAG_EDGE_PERIMETER_CONFIRMED: "custom-domain-waf-account-limits-v1",
      INGEST_TOKEN_CURRENT: TOKEN,
      INGEST_RATE_LIMITER: limiter,
      PUBLIC_READ_RATE_LIMITER: limiter,
    };
    const productionReady = await edgeWorker.fetch(
      new Request("https://example.test/ready"),
      productionEnv,
    );
    expect(productionReady.status).toBe(200);
    expect(await productionReady.json()).toMatchObject({
      ok: true,
      status: "ready",
      production_ready: true,
      perimeter_confirmed: true,
    });

    const nonportableSecret = await edgeWorker.fetch(
      new Request("https://example.test/ready"),
      { ...productionEnv, INGEST_TOKEN_CURRENT: ".".repeat(32) },
    );
    expect(nonportableSecret.status).toBe(503);
    expect(await nonportableSecret.json()).toMatchObject({
      production_ready: false,
      ingest_auth: "weak_configuration",
    });

    const catalog = env.CATALOG.getByName("catalog");
    await catalog.counts();
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        `INSERT INTO registry
          (kind, name, state, owner, reserved_at, head_seq, head_cid)
         VALUES ('pointer', 'readiness/legacy-pending', 'committed', NULL, NULL, NULL, NULL)`,
      );
      state.storage.sql.exec(
        "INSERT INTO names (kind, name) VALUES ('pointer', 'readiness/legacy-pending')",
      );
    });
    const legacyPending = await edgeWorker.fetch(
      new Request("https://example.test/ready"),
      productionEnv,
    );
    expect(legacyPending.status).toBe(503);
    expect(await legacyPending.json()).toMatchObject({
      production_ready: false,
      legacy_heads_pending: 1,
    });
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        "DELETE FROM registry WHERE kind = 'pointer' AND name = 'readiness/legacy-pending'",
      );
      state.storage.sql.exec(
        "DELETE FROM names WHERE kind = 'pointer' AND name = 'readiness/legacy-pending'",
      );
    });

    const flush = (testEnv: EdgeEnv) =>
      edgeWorker.fetch(
        new Request("https://example.test/sync/flush", {
          method: "POST",
          headers: authHeaders(),
        }),
        testEnv,
      );
    expect((await flush(productionEnv)).status).toBe(204);

    const { DAG_EDGE_PERIMETER_CONFIRMED: _perimeter, ...withoutPerimeter } = productionEnv;
    expect((await flush(withoutPerimeter)).status).toBe(503);

    const { INGEST_TOKEN_CURRENT: _current, ...withoutCurrent } = productionEnv;
    const legacyOnly: EdgeEnv = { ...withoutCurrent, DAG_NODE_TOKEN: TOKEN };
    expect((await flush(legacyOnly)).status).toBe(503);

    const demoR2: EdgeEnv = {
      ...legacyOnly,
      DAG_EDGE_MODE: "demo-r2",
      DAG_EDGE_PERIMETER_CONFIRMED: undefined,
    };
    const demoReady = await edgeWorker.fetch(
      new Request("https://example.test/ready"),
      demoR2,
    );
    expect(demoReady.status).toBe(503);
    expect(await demoReady.json()).toMatchObject({
      production_ready: false,
      store: "r2",
      mode: "demo-r2",
      ingest_auth: "legacy_only",
      perimeter_confirmed: false,
    });
    expect((await flush(demoR2)).status).toBe(204);
    const { INGEST_RATE_LIMITER: _demoLimiter, ...demoWithoutIngestLimiter } = demoR2;
    expect((await flush(demoWithoutIngestLimiter)).status).toBe(503);

    const { PUBLIC_READ_RATE_LIMITER: _publicLimiter, ...withoutPublicLimiter } = productionEnv;
    expect((await flush(withoutPublicLimiter)).status).toBe(503);

    expect(
      (
        await flush({
          ...productionEnv,
          DAG_RETAINED_BYTES_LIMIT: "0",
        })
      ).status,
    ).toBe(503);
  });

  it("requires a UUIDv4 session only on transactional event endpoints and bounds empty bodies", async () => {
    const missingSession = await SELF.fetch("https://example.test/sync/import/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "x", seq: 1, cid: "00".repeat(32) }),
    });
    expect(missingSession.status).toBe(400);
    expect((await missingSession.json<{ error: { code: string } }>()).error.code).toBe(
      "invalid_sync_session",
    );
    const oversizedFinalize = await SELF.fetch("https://example.test/sync/finalize", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_A),
      body: "x",
    });
    expect(oversizedFinalize.status).toBe(413);
    const status = await SELF.fetch("https://example.test/sync/status", {
      headers: authHeaders(),
    });
    expect(status.status).toBe(200);
    const statusText = status.clone().text();
    expect(await status.json()).toMatchObject({ phase: "idle", staged_events: 0 });
    expect(await statusText).not.toContain(SESSION_A);
  });

  it("streams and cancels request bodies once the canonical limit is crossed", async () => {
    const piece = new Uint8Array(1024 * 1024);
    let emitted = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (emitted < 4) {
          emitted++;
          controller.enqueue(piece);
        } else if (emitted === 4) {
          emitted++;
          controller.enqueue(new Uint8Array([1]));
        }
      },
      cancel() {
        cancelled = true;
      },
    });
    const response = await SELF.fetch(`https://example.test/c/${"00".repeat(32)}`, {
      method: "PUT",
      headers: authHeaders("application/octet-stream"),
      body,
    });
    expect(response.status).toBe(413);
    expect((await response.json<{ error: { code: string } }>()).error.code).toBe("body_too_large");
    // Workerd may not reflect a transferred stream's cancellation back into
    // this test isolate; the direct body-reader unit test asserts cancel().
    expect(emitted).toBe(5);
  });

  it("rejects oversized backend objects before buffering them", async () => {
    const cid = "ab".repeat(32);
    await env.CHUNKS!.put(cid, new Uint8Array(MAX_CHUNK_SIZE + 1));
    const response = await SELF.fetch(`https://example.test/c/${cid}`);
    expect(response.status).toBe(502);
    expect((await response.json<{ error: { code: string } }>()).error.code).toBe("chunk_unavailable");
  });

  it("reports a same-size backend CID mismatch as a generic 502", async () => {
    const cid = "ef".repeat(32);
    await env.CHUNKS!.put(cid, new TextEncoder().encode("corrupt backend value"));
    const response = await SELF.fetch(`https://example.test/c/${cid}`);
    expect(response.status).toBe(502);
    const text = await response.text();
    expect(text).toContain("stored chunk failed CID verification");
    expect(text).not.toContain(cid);
    expect(text).not.toContain(await computeCidHex(new TextEncoder().encode("corrupt backend value")));
  });

  it("serves verified immutable chunks with conditional, range, and security headers", async () => {
    const bytes = new TextEncoder().encode("content-addressed bytes");
    const cid = await putBytes(bytes);

    const response = await SELF.fetch(`https://example.test/c/${cid}`);
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
    expect(response.headers.get("cache-control")).toContain("immutable");
    expect(response.headers.get("etag")).toBe(`"${cid}"`);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("access-control-allow-origin")).toBe("*");

    const conditional = await SELF.fetch(`https://example.test/c/${cid}`, {
      headers: { "if-none-match": `"${cid}"` },
    });
    expect(conditional.status).toBe(304);

    const range = await SELF.fetch(`https://example.test/c/${cid}`, {
      headers: { range: "bytes=0-6" },
    });
    expect(range.status).toBe(206);
    expect(new TextDecoder().decode(await range.arrayBuffer())).toBe("content");
  });

  it("has no protocol operation that deletes a valid content-addressed object", async () => {
    const bytes = new TextEncoder().encode("immutable protocol object");
    const cid = await putBytes(bytes);
    const refused = await SELF.fetch(`https://example.test/c/${cid}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    expect(refused.status).toBe(405);
    expect(refused.headers.get("allow")).toContain("PUT");
    const stillPresent = await SELF.fetch(`https://example.test/c/${cid}`);
    expect(stillPresent.status).toBe(200);
    expect(new Uint8Array(await stillPresent.arrayBuffer())).toEqual(bytes);
  });

  it("deduplicates missing checks and trusts only hardened R2 object metadata", async () => {
    const present = await putBytes(new TextEncoder().encode("present"));
    const absent = "cd".repeat(32);
    const response = await SELF.fetch("https://example.test/sync/missing", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ cids: [present, absent, present, absent] }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ missing: [absent] });
  });

  it("refuses non-canonical and oversized pointer and pin event Entries", async () => {
    const target = await putBytes(new TextEncoder().encode("canonical-event-target"));
    const pointerId = "canonical/pointer";
    const pointerPayload = encodePointerEvent({
      seq: 1,
      pointerId,
      prev: null,
      new: target,
      ts: 1,
    });
    const oversizedPointerPayload = encodeCbor({
      seq: 1,
      pointer_id: pointerId,
      prev: null,
      new: cidToIntArray(target),
      ts: 1,
      extension: "x".repeat(MAX_POINTER_EVENT_PAYLOAD),
    });
    expect(oversizedPointerPayload.byteLength).toBeGreaterThan(MAX_POINTER_EVENT_PAYLOAD);

    const pinId = "canonical-pin";
    const pinPayload = encodeCbor({
      seq: 1,
      pin_id: pinId,
      target: { Direct: cidToIntArray(target) },
      scope: "Global",
      expires_at: null,
      state: "Active",
      ts: 1,
      author: null,
    });
    const oversizedPinPayload = encodeCbor({
      seq: 1,
      pin_id: pinId,
      target: { Direct: cidToIntArray(target) },
      scope: "Global",
      expires_at: null,
      state: "Active",
      ts: 1,
      author: null,
      extension: "x".repeat(MAX_POINTER_EVENT_PAYLOAD),
    });
    expect(oversizedPinPayload.byteLength).toBeGreaterThan(MAX_POINTER_EVENT_PAYLOAD);

    const nonCanonical = (payload: Uint8Array): Uint8Array[] => [
      linkedEntry([target], payload),
      encodeCbor({
        payload: Array.from(payload),
        links: [],
        meta: { content_type: "application/cbor", encoding: null },
      }),
    ];
    const pointerEntries = [...nonCanonical(pointerPayload), encodeEntry(oversizedPointerPayload)];
    for (const entry of pointerEntries) {
      const cid = await putBytes(entry);
      const response = await SELF.fetch("https://example.test/sync/import/pointer", {
        method: "POST",
        headers: authHeaders("application/json", SESSION_A),
        body: JSON.stringify({ id: pointerId, seq: 1, cid }),
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: "invalid_pointer_event" } });
    }
    const pinEntries = nonCanonical(pinPayload);
    for (const entry of pinEntries) {
      const cid = await putBytes(entry);
      const response = await SELF.fetch("https://example.test/sync/import/pin", {
        method: "POST",
        headers: authHeaders("application/json", SESSION_A),
        body: JSON.stringify({ id: pinId, seq: 1, cid }),
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: "invalid_pin_event" } });
    }
    const historicalPinCid = await putBytes(encodeEntry(oversizedPinPayload));
    const acceptedHistoricalPin = await SELF.fetch("https://example.test/sync/import/pin", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: pinId, seq: 1, cid: historicalPinCid }),
    });
    expect(acceptedHistoricalPin.status).toBe(200);
    expect(
      (
        await SELF.fetch("https://example.test/sync/abort", {
          method: "POST",
          headers: authHeaders(undefined, SESSION_A),
          body: "",
        })
      ).status,
    ).toBe(200);
  });

  it("keeps accepted imports hidden until finalize publishes the whole session", async () => {
    const target = await putBytes(new TextEncoder().encode("head"));
    const pointerBytes = encodeEntry(
      encodePointerEvent({
        seq: 1,
        pointerId: "release/production",
        prev: null,
        new: target,
        ts: 1,
      }),
    );
    const eventCid = await putBytes(pointerBytes);
    const imported = await SELF.fetch("https://example.test/sync/import/pointer", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: "release/production", seq: 1, cid: eventCid }),
    });
    expect(imported.status).toBe(200);
    expect(await imported.json()).toEqual({ filed: true });
    const pinCid = await putBytes(pinEntry("release-pin", target, 1));
    const pinImported = await SELF.fetch("https://example.test/sync/import/pin", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: "release-pin", seq: 1, cid: pinCid }),
    });
    expect(pinImported.status).toBe(200);

    expect((await SELF.fetch("https://example.test/p/release%2Fproduction")).status).toBe(404);
    expect((await env.POINTERS.getByName("pointer:release/production").head()).seq).toBe(0);
    expect((await env.PINS.getByName("pin:release-pin").head()).seq).toBe(0);

    const committed = await finalize();
    expect(committed.status).toBe(200);
    expect(await committed.json()).toMatchObject({ pointers: 1, pins: 1 });
    const resolved = await SELF.fetch("https://example.test/p/release%2Fproduction");
    expect(resolved.status).toBe(200);
    expect(await resolved.json()).toEqual({ id: "release/production", seq: 1, cid: target });
    expect(await env.CATALOG.getByName("catalog").counts()).toEqual({
      pointers: 1,
      pins: 1,
      staged: 0,
      phase: "idle",
    });
  });

  it("hash-verifies and strictly decodes every canonical pointer predecessor before staging", async () => {
    const target = await putBytes(new TextEncoder().encode("pointer-predecessor-target"));
    const alternate = await putBytes(new TextEncoder().encode("pointer-predecessor-alternate"));
    const successorTarget = await putBytes(new TextEncoder().encode("pointer-successor-target"));
    const cases = [
      { kind: "missing", code: "canonical_predecessor_unavailable", status: 502 },
      { kind: "hash", code: "canonical_predecessor_unavailable", status: 502 },
      { kind: "malformed", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-id", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-seq", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-new", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-link", code: "chain_broken", status: 409 },
    ] as const;
    const catalog = env.CATALOG.getByName("catalog");

    for (const [index, testCase] of cases.entries()) {
      const id = `predecessor/pointer/${testCase.kind}/${index}`;
      let predecessorBytes = encodeEntry(
        encodePointerEvent({ seq: 1, pointerId: id, prev: null, new: target, ts: 1 }),
      );
      if (testCase.kind === "malformed") predecessorBytes = new Uint8Array([0xff]);
      if (testCase.kind === "wrong-id") {
        predecessorBytes = encodeEntry(
          encodePointerEvent({ seq: 1, pointerId: `${id}/forged`, prev: null, new: target, ts: 1 }),
        );
      }
      if (testCase.kind === "wrong-seq") {
        predecessorBytes = encodeEntry(
          encodePointerEvent({ seq: 2, pointerId: id, prev: target, new: target, ts: 2 }),
        );
      }
      if (testCase.kind === "wrong-new") {
        predecessorBytes = encodeEntry(
          encodePointerEvent({ seq: 1, pointerId: id, prev: null, new: alternate, ts: 1 }),
        );
      }
      const predecessorCid = await computeCidHex(predecessorBytes);
      if (testCase.kind === "hash") {
        await env.CHUNKS!.put(predecessorCid, new TextEncoder().encode("wrong bytes"));
      } else if (testCase.kind !== "missing") {
        expect(await putBytes(predecessorBytes)).toBe(predecessorCid);
      }
      const child = env.POINTERS.getByName(`pointer:${id}`);
      expect(
        await child.importEvent(id, 1, predecessorCid, {
          seq: 1,
          pointerId: id,
          prev: null,
          new: target,
        }),
      ).toMatchObject({ ok: true });

      const successor = await pointerEntry(
        id,
        successorTarget,
        2,
        testCase.kind === "wrong-link" ? alternate : target,
      );
      const response = await SELF.fetch("https://example.test/sync/import/pointer", {
        method: "POST",
        headers: authHeaders("application/json", SESSION_A),
        body: JSON.stringify({ id, seq: 2, cid: successor }),
      });
      expect(response.status).toBe(testCase.status);
      expect(await response.json()).toMatchObject({ error: { code: testCase.code } });
      expect(await catalog.counts()).toMatchObject({ phase: "idle", staged: 0 });
      expect(await catalog.contains("pointer", id)).toBe(false);
      expect(await child.head()).toMatchObject({ seq: 1, cid: target, eventCid: predecessorCid });
      expect((await SELF.fetch(`https://example.test/p/${encodeURIComponent(id)}`)).status).toBe(404);
    }
  });

  it("hash-verifies pin predecessors and their exact event-CID linkage before staging", async () => {
    const target = await putBytes(new TextEncoder().encode("pin-predecessor-target"));
    const wrongLink = await putBytes(new TextEncoder().encode("pin-predecessor-wrong-link"));
    const cases = [
      { kind: "missing", code: "canonical_predecessor_unavailable", status: 502 },
      { kind: "hash", code: "canonical_predecessor_unavailable", status: 502 },
      { kind: "malformed", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-id", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-seq", code: "canonical_predecessor_invalid", status: 502 },
      { kind: "wrong-link", code: "chain_broken", status: 409 },
    ] as const;
    const catalog = env.CATALOG.getByName("catalog");

    for (const [index, testCase] of cases.entries()) {
      const id = `predecessor-pin-${testCase.kind}-${index}`;
      let predecessorBytes = pinEventEntry(id, target, 1, null);
      if (testCase.kind === "malformed") predecessorBytes = new Uint8Array([0xff]);
      if (testCase.kind === "wrong-id") {
        predecessorBytes = pinEventEntry(`${id}-forged`, target, 1, null);
      }
      if (testCase.kind === "wrong-seq") {
        predecessorBytes = pinEventEntry(id, target, 2, wrongLink);
      }
      const predecessorCid = await computeCidHex(predecessorBytes);
      if (testCase.kind === "hash") {
        await env.CHUNKS!.put(predecessorCid, new TextEncoder().encode("wrong pin bytes"));
      } else if (testCase.kind !== "missing") {
        expect(await putBytes(predecessorBytes)).toBe(predecessorCid);
      }
      const child = env.PINS.getByName(`pin:${id}`);
      expect(
        await child.importEvent(id, 1, predecessorCid, {
          seq: 1,
          pinId: id,
          prev: null,
        }),
      ).toMatchObject({ ok: true });

      const successor = await putBytes(
        pinEventEntry(
          id,
          target,
          2,
          testCase.kind === "wrong-link" ? wrongLink : predecessorCid,
        ),
      );
      const response = await SELF.fetch("https://example.test/sync/import/pin", {
        method: "POST",
        headers: authHeaders("application/json", SESSION_A),
        body: JSON.stringify({ id, seq: 2, cid: successor }),
      });
      expect(response.status).toBe(testCase.status);
      expect(await response.json()).toMatchObject({ error: { code: testCase.code } });
      expect(await catalog.counts()).toMatchObject({ phase: "idle", staged: 0 });
      expect(await catalog.contains("pin", id)).toBe(false);
      expect(await child.head()).toMatchObject({ seq: 1, eventCid: predecessorCid });
    }
  });

  it("rejects and cleans up an active pin whose direct target is absent", async () => {
    const missing = await computeCidHex(new TextEncoder().encode("missing-pin-target"));
    const eventCid = await putBytes(pinEntry("missing-direct", missing, 1));
    const imported = await SELF.fetch("https://example.test/sync/import/pin", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: "missing-direct", seq: 1, cid: eventCid }),
    });
    expect(imported.status).toBe(200);

    const refused = await finalize();
    expect(refused.status).toBe(409);
    const refusal = await refused.json();
    expect(refusal).toMatchObject({ error: { code: "reference_unavailable" } });
    expect(await env.PINS.getByName("pin:missing-direct").head()).toMatchObject({ seq: 0 });
    expect(await env.CATALOG.getByName("catalog").counts()).toMatchObject({
      staged: 0,
      phase: "idle",
    });
    for (let retry = 0; retry < 2; retry++) {
      const repeated = await finalize(SESSION_A);
      expect(repeated.status).toBe(409);
      expect(await repeated.json()).toEqual(refusal);
    }
    expect((await finalize(SESSION_B)).status).toBe(409);
  });

  it("rejects a missing descendant for both staged import and direct CAS", async () => {
    const missing = await computeCidHex(new TextEncoder().encode("missing-descendant"));
    const root = await putBytes(linkedEntry([missing]));
    const eventCid = await pointerEntry("closure/import", root);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "closure/import", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);

    const importRefused = await finalize();
    expect(importRefused.status).toBe(409);
    expect(await importRefused.json()).toMatchObject({ error: { code: "reference_unavailable" } });
    expect((await SELF.fetch("https://example.test/p/closure%2Fimport")).status).toBe(404);
    expect(await env.POINTERS.getByName("pointer:closure/import").head()).toMatchObject({ seq: 0 });

    const casRefused = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "closure/cas", expect_seq: 0, cid: root }),
    });
    expect(casRefused.status).toBe(409);
    expect(await casRefused.json()).toMatchObject({ error: { code: "reference_unavailable" } });
    expect((await SELF.fetch("https://example.test/p/closure%2Fcas")).status).toBe(404);
    expect(await env.POINTERS.getByName("pointer:closure/cas").head()).toMatchObject({ seq: 0 });
  });

  it("publishes a complete reachable closure", async () => {
    const leaf = await putBytes(new TextEncoder().encode("reachable-leaf"));
    const root = await putBytes(linkedEntry([leaf]));
    const eventCid = await pointerEntry("closure/complete", root);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "closure/complete", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);
    expect((await finalize()).status).toBe(200);
    expect(await (await SELF.fetch("https://example.test/p/closure%2Fcomplete")).json()).toMatchObject({
      cid: root,
    });
  });

  it("enforces independent object, byte, link, and graph-depth closure budgets", async () => {
    const leafBytes = new TextEncoder().encode("budget-leaf");
    const leafCid = await computeCidHex(leafBytes);
    const rootBytes = linkedEntry([leafCid]);
    const rootCid = await computeCidHex(rootBytes);
    const objectGraph = await memoryStore([rootBytes, leafBytes]);
    await expectClosureError(
      validatePublicationClosure(
        objectGraph.store,
        [{ kind: "pointer", name: "object-limit", cid: rootCid }],
        1,
        { ...GENEROUS_TEST_CLOSURE_BUDGETS, maxObjects: 1 },
      ),
      "reference_object_limit",
    );

    const byteGraph = await memoryStore([leafBytes]);
    await expectClosureError(
      validatePublicationClosure(
        byteGraph.store,
        [{ kind: "pointer", name: "byte-limit", cid: leafCid }],
        1,
        { ...GENEROUS_TEST_CLOSURE_BUDGETS, maxBytes: leafBytes.byteLength - 1 },
      ),
      "reference_byte_limit",
    );

    const twoLinkRoot = linkedEntry([leafCid, leafCid]);
    const twoLinkCid = await computeCidHex(twoLinkRoot);
    const linkGraph = await memoryStore([twoLinkRoot, leafBytes]);
    await expectClosureError(
      validatePublicationClosure(
        linkGraph.store,
        [{ kind: "pointer", name: "link-limit", cid: twoLinkCid }],
        1,
        { ...GENEROUS_TEST_CLOSURE_BUDGETS, maxLinks: 1 },
      ),
      "reference_link_limit",
    );

    const middleBytes = linkedEntry([leafCid]);
    const middleCid = await computeCidHex(middleBytes);
    const deepRootBytes = linkedEntry([middleCid]);
    const deepRootCid = await computeCidHex(deepRootBytes);
    const depthGraph = await memoryStore([deepRootBytes, middleBytes, leafBytes]);
    await expectClosureError(
      validatePublicationClosure(
        depthGraph.store,
        [{ kind: "pointer", name: "depth-limit", cid: deepRootCid }],
        1,
        { ...GENEROUS_TEST_CLOSURE_BUDGETS, maxDepth: 1 },
      ),
      "reference_depth_limit",
    );
  });

  it("matches native pin applicability, expiry, state, and subtree-depth semantics", async () => {
    const missing = await computeCidHex(new TextEncoder().encode("semantic-pin-missing"));
    const pinEvent = (
      id: string,
      target: Record<string, unknown>,
      scope: string | Record<string, unknown>,
      state = "Active",
      expiresAt: number | null = null,
    ) =>
      encodeEntry(
        encodeCbor({
          seq: 1,
          pin_id: id,
          target: target as never,
          scope: scope as never,
          expires_at: expiresAt,
          state,
          ts: 1,
          author: null,
        }),
      );

    const ignoredBytes = [
      pinEvent("pin-inactive", { Direct: cidToIntArray(missing) }, "Global", "Deactivated"),
      pinEvent("pin-expired", { Direct: cidToIntArray(missing) }, "Global", "Active", 9),
      pinEvent(
        "pin-other-node",
        { Direct: cidToIntArray(missing) },
        { Local: { node_id: "other" } },
      ),
    ];
    const ignored = await memoryStore(ignoredBytes);
    await expect(
      validatePublicationClosure(
        ignored.store,
        [
          { kind: "pin", name: "pin-inactive", eventCid: ignored.cids[0] },
          { kind: "pin", name: "pin-expired", eventCid: ignored.cids[1] },
          { kind: "pin", name: "pin-other-node", eventCid: ignored.cids[2] },
        ],
        10,
        GENEROUS_TEST_CLOSURE_BUDGETS,
      ),
    ).resolves.toMatchObject({ objects: 3 });

    const localBytes = pinEvent(
      "pin-local",
      { Direct: cidToIntArray(missing) },
      { Local: { node_id: "local" } },
    );
    const local = await memoryStore([localBytes]);
    await expectClosureError(
      validatePublicationClosure(
        local.store,
        [{ kind: "pin", name: "pin-local", eventCid: local.cids[0] }],
        10,
        GENEROUS_TEST_CLOSURE_BUDGETS,
      ),
      "reference_unavailable",
    );

    const rootBytes = linkedEntry([missing]);
    const rootCid = await computeCidHex(rootBytes);
    const depthZeroEvent = pinEvent(
      "pin-depth-zero",
      { Subtree: { root: cidToIntArray(rootCid), max_depth: 0 } },
      "Global",
    );
    const depthOneEvent = pinEvent(
      "pin-depth-one",
      { Subtree: { root: cidToIntArray(rootCid), max_depth: 1 } },
      "Global",
    );
    const subtree = await memoryStore([rootBytes, depthZeroEvent, depthOneEvent]);
    await expect(
      validatePublicationClosure(
        subtree.store,
        [{ kind: "pin", name: "pin-depth-zero", eventCid: subtree.cids[1] }],
        10,
        GENEROUS_TEST_CLOSURE_BUDGETS,
      ),
    ).resolves.toMatchObject({ objects: 2 });
    await expectClosureError(
      validatePublicationClosure(
        subtree.store,
        [{ kind: "pin", name: "pin-depth-one", eventCid: subtree.cids[2] }],
        10,
        GENEROUS_TEST_CLOSURE_BUDGETS,
      ),
      "reference_unavailable",
    );
  });

  it("aborts accepted staging after a later definite refusal without touching child logs", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const before = await catalog.counts();
    const acceptedTarget = await putBytes(new TextEncoder().encode("accepted-head"));
    const acceptedCid = await pointerEntry("accepted", acceptedTarget);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "accepted", seq: 1, cid: acceptedCid }),
        })
      ).status,
    ).toBe(200);

    const target = await putBytes(new TextEncoder().encode("other-head"));
    const forgedBytes = encodeEntry(
      encodePointerEvent({ seq: 1, pointerId: "actual", prev: null, new: target, ts: 1 }),
    );
    const eventCid = await putBytes(forgedBytes);
    const response = await SELF.fetch("https://example.test/sync/import/pointer", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: "offered", seq: 1, cid: eventCid }),
    });
    expect(response.status).toBe(409);
    const aborted = await SELF.fetch("https://example.test/sync/abort", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_A),
      body: "",
    });
    expect(aborted.status).toBe(200);
    expect(await aborted.json()).toEqual({ aborted: true });
    const repeatedAbort = await SELF.fetch("https://example.test/sync/abort", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_A),
      body: "",
    });
    expect(repeatedAbort.status).toBe(409);
    expect(await repeatedAbort.json()).toMatchObject({
      error: { code: "sync_session_aborted" },
    });
    const staleFinalize = await finalize(SESSION_A);
    expect(staleFinalize.status).toBe(409);
    expect(await staleFinalize.json()).toMatchObject({ error: { code: "sync_session_aborted" } });
    expect(await catalog.counts()).toEqual(before);
    expect((await SELF.fetch("https://example.test/p/offered")).status).toBe(404);
    expect((await SELF.fetch("https://example.test/p/accepted")).status).toBe(404);
    expect((await env.POINTERS.getByName("pointer:accepted").head()).seq).toBe(0);
  });

  it("serializes sessions, expires only prepublication staging, and blocks CAS", async () => {
    const target = await putBytes(new TextEncoder().encode("leased-head"));
    const eventCid = await pointerEntry("leased", target);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "leased", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);

    const contender = await SELF.fetch("https://example.test/sync/import/pointer", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_B),
      body: JSON.stringify({ id: "leased", seq: 1, cid: eventCid }),
    });
    expect(contender.status).toBe(409);
    expect(contender.headers.get("retry-after")).not.toBeNull();
    const cas = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "leased", expect_seq: 0, cid: target }),
    });
    expect(cas.status).toBe(409);

    const catalog = env.CATALOG.getByName("catalog");
    expect(
      await catalog.operationStatus(
        Math.floor(Date.now() / 1000) + SYNC_SESSION_SECONDS,
      ),
    ).toMatchObject({ phase: "idle", stagedEvents: 0 });
    for (let attempt = 0; attempt < 2; attempt++) {
      const expiredFinalize = await finalize(SESSION_A);
      expect(expiredFinalize.status).toBe(409);
      expect(
        (await expiredFinalize.json<{ error: { code: string } }>()).error.code,
      ).toBe("sync_session_expired");
    }
    const expiredAbort = await SELF.fetch("https://example.test/sync/abort", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_A),
      body: "",
    });
    expect(expiredAbort.status).toBe(409);
    expect(await expiredAbort.json()).toMatchObject({
      error: { code: "sync_session_expired" },
    });
    expect(
      await catalog.beginSession(
        SESSION_A,
        Math.floor(Date.now() / 1000) + SYNC_SESSION_SECONDS,
      ),
    ).toMatchObject({
      state: "terminal",
      outcome: "expired",
      code: "sync_session_expired",
      status: 409,
    });
    const takeover = await catalog.beginSession(
      SESSION_B,
      Math.floor(Date.now() / 1000) + SYNC_SESSION_SECONDS,
    );
    expect(takeover).toEqual({ state: "ready" });
    expect(await catalog.counts()).toMatchObject({ staged: 0, phase: "staging" });
    expect((await env.POINTERS.getByName("pointer:leased").head()).seq).toBe(0);
    expect(
      (
        await SELF.fetch("https://example.test/sync/abort", {
          method: "POST",
          headers: authHeaders(undefined, SESSION_B),
          body: "",
        })
      ).status,
    ).toBe(200);
  });

  it("refuses an unknown finalize UUID without creating an empty transfer", async () => {
    const response = await finalize(SESSION_A);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: { code: "sync_session_unknown" } });
    expect(await env.CATALOG.getByName("catalog").counts()).toMatchObject({
      phase: "idle",
      staged: 0,
    });
  });

  it("replays an exact completion receipt and refuses terminal UUID reuse", async () => {
    const targetA = await putBytes(new TextEncoder().encode("receipt-a"));
    const eventA = await pointerEntry("receipt/a", targetA);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "receipt/a", seq: 1, cid: eventA }),
        })
      ).status,
    ).toBe(200);
    const first = await finalize(SESSION_A);
    expect(first.status).toBe(200);
    const receipt = await first.json();
    expect(receipt).toMatchObject({ pointers: 1, pins: 0 });
    const replay = await finalize(SESSION_A);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(receipt);

    const reused = await SELF.fetch("https://example.test/sync/import/pointer", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: "receipt/a", seq: 1, cid: eventA }),
    });
    expect(reused.status).toBe(409);
    expect(await reused.json()).toMatchObject({ error: { code: "sync_session_complete" } });
    const completedAbort = await SELF.fetch("https://example.test/sync/abort", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_A),
      body: "",
    });
    expect(completedAbort.status).toBe(409);
    expect(await completedAbort.json()).toMatchObject({
      error: { code: "sync_session_complete" },
    });

    const targetB = await putBytes(new TextEncoder().encode("receipt-b"));
    const eventB = await pointerEntry("receipt/b", targetB);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_B),
          body: JSON.stringify({ id: "receipt/b", seq: 1, cid: eventB }),
        })
      ).status,
    ).toBe(200);
    expect((await finalize(SESSION_B)).status).toBe(200);
  });

  it("an unrelated finalize or abort cannot advance another witnessed publication", async () => {
    const target = await putBytes(new TextEncoder().encode("exact-owner"));
    const eventCid = await pointerEntry("session/exact", target);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "session/exact", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);
    const catalog = env.CATALOG.getByName("catalog");
    const snapshot = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(snapshot.state).toBe("validate");
    if (snapshot.state !== "validate") throw new Error("expected validation snapshot");
    await validatePublicationClosure(openStore(env as EdgeEnv), snapshot.heads, Math.floor(Date.now() / 1000));
    await catalog.freezePublication(snapshot.sessionId, snapshot.revision, Math.floor(Date.now() / 1000));

    const wrongFinalize = await finalize(SESSION_B);
    expect(wrongFinalize.status).toBe(409);
    expect(await wrongFinalize.json()).toMatchObject({ error: { code: "sync_session_unknown" } });
    const wrongAbort = await SELF.fetch("https://example.test/sync/abort", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_B),
      body: "",
    });
    expect(wrongAbort.status).toBe(409);
    expect(await wrongAbort.json()).toMatchObject({ error: { code: "sync_busy" } });
    expect((await catalog.publicationPlan()).state).toBe("publishing");
    expect(await env.POINTERS.getByName("pointer:session/exact").head()).toMatchObject({ seq: 0 });

    const exactAbort = await SELF.fetch("https://example.test/sync/abort", {
      method: "POST",
      headers: authHeaders(undefined, SESSION_A),
      body: "",
    });
    expect(exactAbort.status).toBe(200);
    expect(await exactAbort.json()).toEqual({ aborted: false, published: true });
    expect(await env.POINTERS.getByName("pointer:session/exact").head()).toMatchObject({ seq: 1 });
  });

  it("bounds exact receipts, fails closed after eviction, and requires explicit restaging", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    await catalog.counts();
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec("DELETE FROM terminal_sessions");
      for (let index = 0; index < MAX_TERMINAL_SYNC_SESSIONS; index++) {
        state.storage.sql.exec(
          `INSERT INTO terminal_sessions
            (session_id, outcome, terminal_at, pointers, pins)
           VALUES (?, 'aborted', ?, 0, 0)`,
          numberedSession(index),
          index,
        );
      }
    });
    const newest = numberedSession(MAX_TERMINAL_SYNC_SESSIONS);
    expect(await catalog.beginSession(newest, 2_000_000_000)).toEqual({ state: "ready" });
    expect(await catalog.abortSession(newest, 2_000_000_000)).toEqual({ state: "aborted" });
    const retained = await runInDurableObject(catalog, (_instance, state) =>
      state.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM terminal_sessions").one().n,
    );
    expect(retained).toBe(MAX_TERMINAL_SYNC_SESSIONS);
    expect(await catalog.beginFinalize(numberedSession(0), 2_000_000_001)).toEqual({
      state: "unknown",
    });
    expect(await catalog.beginFinalize(newest, 2_000_000_001)).toMatchObject({
      state: "terminal",
      outcome: "aborted",
      status: 409,
      code: "sync_session_aborted",
    });
    // The bounded table cannot remember an evicted UUID forever. Its stale
    // finalize is still refused as unknown; only a new authenticated import
    // path may explicitly acquire and restage that UUID.
    expect(await catalog.beginSession(numberedSession(0), 2_000_000_002)).toEqual({
      state: "ready",
    });
    expect(await catalog.abortSession(numberedSession(0), 2_000_000_002)).toEqual({
      state: "aborted",
    });
  });

  it("cannot resume publication after a crash before the durable validation witness", async () => {
    const leaf = await putBytes(new TextEncoder().encode("pre-witness-leaf"));
    const root = await putBytes(linkedEntry([leaf]));
    const eventCid = await pointerEntry("witness/pre", root);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "witness/pre", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);

    const catalog = env.CATALOG.getByName("catalog");
    const snapshot = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(snapshot.state).toBe("validate");
    if (snapshot.state !== "validate") throw new Error("expected validation snapshot");
    await validatePublicationClosure(
      openStore(env as EdgeEnv),
      snapshot.heads,
      Math.floor(Date.now() / 1000),
    );
    await evictDurableObject(catalog);

    const restarted = env.CATALOG.getByName("catalog");
    expect(await restarted.publicationPlan()).toEqual({ state: "idle" });
    expect(await env.POINTERS.getByName("pointer:witness/pre").head()).toMatchObject({ seq: 0 });
    expect((await SELF.fetch("https://example.test/p/witness%2Fpre")).status).toBe(404);
    expect((await finalize()).status).toBe(200);
  });

  it("revalidates an unwitnessed publication and fails readiness on a mismatched witness", async () => {
    const target = await putBytes(new TextEncoder().encode("legacy-witness-target"));
    const eventCid = await pointerEntry("witness/legacy", target);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "witness/legacy", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);
    const catalog = env.CATALOG.getByName("catalog");
    expect((await catalog.budgetStatus()).unvalidatedPublicationPending).toBe(false);
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE sync_session SET phase = 'publishing', validated_revision = NULL WHERE singleton = 1",
      );
    });
    expect(await catalog.publicationPlan()).toEqual({ state: "unvalidated" });
    expect((await catalog.budgetStatus()).unvalidatedPublicationPending).toBe(true);
    expect(await env.POINTERS.getByName("pointer:witness/legacy").head()).toMatchObject({ seq: 0 });

    const snapshot = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(snapshot.state).toBe("validate");
    if (snapshot.state !== "validate") throw new Error("expected validation snapshot");
    await validatePublicationClosure(
      openStore(env as EdgeEnv),
      snapshot.heads,
      Math.floor(Date.now() / 1000),
    );
    expect(
      await catalog.freezePublication(
        snapshot.sessionId,
        snapshot.revision,
        Math.floor(Date.now() / 1000),
      ),
    ).toEqual({ state: "publishing" });
    expect((await catalog.budgetStatus()).unvalidatedPublicationPending).toBe(false);

    // A non-NULL witness for some other revision is not a recoverable legacy
    // row. It must make readiness fail, while exact-session cleanup continues
    // to refuse to erase the corrupt/witnessed publication.
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE sync_session SET validated_revision = revision + 1 WHERE singleton = 1",
      );
    });
    expect((await catalog.budgetStatus()).unvalidatedPublicationPending).toBe(true);
    const limiter: RateLimit = {
      async limit() {
        return { success: true };
      },
    };
    const mismatched = await edgeWorker.fetch(
      new Request("https://example.test/ready"),
      {
        ...env,
        DAG_EDGE_MODE: "production-r2",
        DAG_EDGE_PERIMETER_CONFIRMED: "custom-domain-waf-account-limits-v1",
        INGEST_TOKEN_CURRENT: TOKEN,
        INGEST_RATE_LIMITER: limiter,
        PUBLIC_READ_RATE_LIMITER: limiter,
      },
    );
    expect(mismatched.status).toBe(503);
    expect(await mismatched.json()).toMatchObject({
      production_ready: false,
      unvalidated_publication_pending: true,
    });
    expect(
      await catalog.clearFailedValidation(
        snapshot.sessionId,
        snapshot.revision,
        Math.floor(Date.now() / 1000),
        409,
        "reference_unavailable",
        "referenced content is unavailable",
      ),
    ).toEqual({ cleared: false });
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE sync_session SET validated_revision = revision WHERE singleton = 1",
      );
    });
    expect((await catalog.budgetStatus()).unvalidatedPublicationPending).toBe(false);

    expect((await finalize(SESSION_A)).status).toBe(200);
    expect(await (await SELF.fetch("https://example.test/p/witness%2Flegacy")).json()).toMatchObject({
      cid: target,
    });
  });

  it("terminalizes an invalid unwitnessed publication and restores readiness for a fresh session", async () => {
    const limiter: RateLimit = {
      async limit() {
        return { success: true };
      },
    };
    const productionEnv: EdgeEnv = {
      ...env,
      DAG_EDGE_MODE: "production-r2",
      DAG_EDGE_PERIMETER_CONFIRMED: "custom-domain-waf-account-limits-v1",
      INGEST_TOKEN_CURRENT: TOKEN,
      INGEST_RATE_LIMITER: limiter,
      PUBLIC_READ_RATE_LIMITER: limiter,
    };
    const catalog = env.CATALOG.getByName("catalog");

    for (const failure of ["missing", "corrupt"] as const) {
      const session = crypto.randomUUID();
      const freshSession = crypto.randomUUID();
      const name = `witness/invalid-${failure}`;
      const targetBytes = new TextEncoder().encode(`unwitnessed-${failure}-target`);
      const target = await putBytes(targetBytes);
      const eventCid = await pointerEntry(name, target);
      const imported = await SELF.fetch("https://example.test/sync/import/pointer", {
        method: "POST",
        headers: authHeaders("application/json", session),
        body: JSON.stringify({ id: name, seq: 1, cid: eventCid }),
      });
      expect(imported.status).toBe(200);
      await runInDurableObject(catalog, (_instance, state) => {
        state.storage.sql.exec(
          "UPDATE sync_session SET phase = 'publishing', validated_revision = NULL WHERE singleton = 1",
        );
      });

      const recovering = await edgeWorker.fetch(
        new Request("https://example.test/ready"),
        productionEnv,
      );
      expect(recovering.status).toBe(503);
      expect(await recovering.json()).toMatchObject({
        production_ready: false,
        unvalidated_publication_pending: true,
      });

      if (failure === "missing") {
        await env.CHUNKS!.delete(target);
      } else {
        await env.CHUNKS!.put(target, new TextEncoder().encode("corrupt target bytes"));
      }
      const first = await finalize(session);
      const firstBody = await first.json();
      expect(first.status).toBe(failure === "missing" ? 409 : 502);
      expect(firstBody).toMatchObject({
        error: {
          code: failure === "missing" ? "reference_unavailable" : "reference_store_invalid",
        },
      });
      expect(await catalog.counts()).toMatchObject({ phase: "idle", staged: 0 });

      const replay = await finalize(session);
      expect(replay.status).toBe(first.status);
      expect(await replay.json()).toEqual(firstBody);

      const recovered = await edgeWorker.fetch(
        new Request("https://example.test/ready"),
        productionEnv,
      );
      expect(recovered.status).toBe(200);
      expect(await recovered.json()).toMatchObject({
        production_ready: true,
        unvalidated_publication_pending: false,
      });

      expect(await putBytes(targetBytes)).toBe(target);
      const reimported = await SELF.fetch("https://example.test/sync/import/pointer", {
        method: "POST",
        headers: authHeaders("application/json", freshSession),
        body: JSON.stringify({ id: name, seq: 1, cid: eventCid }),
      });
      expect(reimported.status).toBe(200);
      expect((await finalize(freshSession)).status).toBe(200);
      expect(
        await (
          await SELF.fetch(`https://example.test/p/${encodeURIComponent(name)}`)
        ).json(),
      ).toMatchObject({ id: name, seq: 1, cid: target });
    }
  });

  it("preserves a newer staging revision when an older validation fails or freezes", async () => {
    const firstTarget = await putBytes(new TextEncoder().encode("revision-first"));
    const secondTarget = await putBytes(new TextEncoder().encode("revision-second"));
    const firstEvent = await pointerEntry("revision/first", firstTarget);
    const secondEvent = await pointerEntry("revision/second", secondTarget);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "revision/first", seq: 1, cid: firstEvent }),
        })
      ).status,
    ).toBe(200);
    const catalog = env.CATALOG.getByName("catalog");
    const old = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(old.state).toBe("validate");
    if (old.state !== "validate") throw new Error("expected validation snapshot");

    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "revision/second", seq: 1, cid: secondEvent }),
        })
      ).status,
    ).toBe(200);
    expect(
      await catalog.clearFailedValidation(
        old.sessionId,
        old.revision,
        Math.floor(Date.now() / 1000),
        409,
        "reference_unavailable",
        "referenced content is unavailable",
      ),
    ).toEqual({ cleared: false });
    expect(
      await catalog.freezePublication(old.sessionId, old.revision, Math.floor(Date.now() / 1000)),
    ).toEqual({ state: "changed" });
    expect(await catalog.counts()).toMatchObject({ staged: 2, phase: "staging" });
    expect(await catalog.publicationPlan()).toEqual({ state: "idle" });
    expect(await env.POINTERS.getByName("pointer:revision/first").head()).toMatchObject({ seq: 0 });
    expect(await env.POINTERS.getByName("pointer:revision/second").head()).toMatchObject({ seq: 0 });
    expect(
      (
        await SELF.fetch("https://example.test/sync/abort", {
          method: "POST",
          headers: authHeaders(undefined, SESSION_A),
          body: "",
        })
      ).status,
    ).toBe(200);
  });

  it("classifies a validation cleanup revision race as retryable and preserves the session", async () => {
    const firstTarget = await putBytes(new TextEncoder().encode("revision-race-first"));
    const secondTarget = await putBytes(new TextEncoder().encode("revision-race-second"));
    const firstEvent = await pointerEntry("revision/race-first", firstTarget);
    const secondEvent = await pointerEntry("revision/race-second", secondTarget);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "revision/race-first", seq: 1, cid: firstEvent }),
        })
      ).status,
    ).toBe(200);

    let signalRead!: () => void;
    let releaseRead!: () => void;
    const readStarted = new Promise<void>((resolve) => { signalRead = resolve; });
    const readReleased = new Promise<void>((resolve) => { releaseRead = resolve; });
    const closureReads: string[] = [];
    const blockingKv = {
      async get(key: string, type: "stream") {
        expect(type).toBe("stream");
        closureReads.push(key);
        if (key === firstTarget) {
          signalRead();
          await readReleased;
        }
        return null;
      },
      async put() {},
    } as unknown as KVNamespace;
    const demoEnv: EdgeEnv = {
      ...env,
      CHUNKS: undefined,
      CHUNKS_KV: blockingKv,
      DAG_EDGE_MODE: "demo-kv",
    };
    const pendingFinalize = edgeWorker.fetch(
      new Request("https://example.test/sync/finalize", {
        method: "POST",
        headers: authHeaders(undefined, SESSION_A),
        body: "",
      }),
      demoEnv,
    );
    await readStarted;
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "revision/race-second", seq: 1, cid: secondEvent }),
        })
      ).status,
    ).toBe(200);
    releaseRead();

    const raced = await pendingFinalize;
    expect(raced.status).toBe(409);
    expect(raced.headers.get("retry-after")).toBe("1");
    expect(await raced.json()).toMatchObject({ error: { code: "sync_revision_changed" } });
    expect(closureReads).toEqual([firstTarget]);
    expect(await env.CATALOG.getByName("catalog").counts()).toMatchObject({
      phase: "staging",
      staged: 2,
    });
    expect((await finalize(SESSION_A)).status).toBe(200);
  });

  it("resumes a frozen publication under a new client UUID without exposing partial children", async () => {
    const targetA = await putBytes(new TextEncoder().encode("publication-a"));
    const targetB = await putBytes(new TextEncoder().encode("publication-b"));
    const cidA = await pointerEntry("publication/a", targetA);
    const cidB = await pointerEntry("publication/b", targetB);
    const catalog = env.CATALOG.getByName("catalog");
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        `INSERT INTO registry
          (kind, name, state, owner, reserved_at, head_seq, head_cid)
         VALUES ('pointer', 'publication/a', 'committed', NULL, NULL, NULL, NULL)`,
      );
      state.storage.sql.exec(
        "INSERT OR IGNORE INTO names (kind, name) VALUES ('pointer', 'publication/a')",
      );
    });
    for (const [id, cid] of [["publication/a", cidA], ["publication/b", cidB]]) {
      const response = await SELF.fetch("https://example.test/sync/import/pointer", {
        method: "POST",
        headers: authHeaders("application/json", SESSION_A),
        body: JSON.stringify({ id, seq: 1, cid }),
      });
      expect(response.status).toBe(200);
    }
    const validation = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(validation.state).toBe("validate");
    if (validation.state !== "validate") throw new Error("expected validation snapshot");
    await validatePublicationClosure(
      openStore(env as EdgeEnv),
      validation.heads,
      Math.floor(Date.now() / 1000),
    );
    expect(
      await catalog.freezePublication(
        validation.sessionId,
        validation.revision,
        Math.floor(Date.now() / 1000),
      ),
    ).toEqual({ state: "publishing" });
    const plan = await catalog.publicationPlan();
    expect(plan.state).toBe("publishing");
    if (plan.state !== "publishing") throw new Error("expected publication plan");
    const first = plan.groups[0];
    expect(first.kind).toBe("pointer");
    if (first.kind !== "pointer") throw new Error("expected pointer group");
    expect(
      await env.POINTERS.getByName(`pointer:${first.name}`).publishBatch(first.name, first.events),
    ).toMatchObject({ ok: true });
    const second = plan.groups[1];
    expect(second.kind).toBe("pointer");
    if (second.kind !== "pointer") throw new Error("expected pointer group");
    expect(
      await env.POINTERS.getByName(`pointer:${second.name}`).publishBatch(second.name, second.events),
    ).toMatchObject({ ok: true });
    await catalog.markPublishedBatch(plan.sessionId, [{ kind: second.kind, name: second.name }]);

    // The seeded legacy membership had an empty child and is safely pruned as
    // a phantom while the replacement remains hidden in frozen staging.
    expect((await SELF.fetch("https://example.test/p/publication%2Fa")).status).toBe(404);
    expect((await SELF.fetch("https://example.test/p/publication%2Fb")).status).toBe(404);
    const resumed = await finalize(SESSION_A);
    expect(resumed.status).toBe(200);
    expect(await resumed.json()).toMatchObject({ pointers: 2 });
    expect(await (await SELF.fetch("https://example.test/p/publication%2Fa")).json()).toMatchObject({ cid: targetA });
    expect(await (await SELF.fetch("https://example.test/p/publication%2Fb")).json()).toMatchObject({ cid: targetB });
  });

  it("discards pre-witness legacy staged sessions during schema migration", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    await catalog.counts();
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec("DROP TABLE sync_session");
      state.storage.sql.exec(`
        CREATE TABLE sync_session (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          session_id TEXT NOT NULL,
          phase TEXT NOT NULL CHECK (phase IN ('staging', 'publishing')),
          touched_at INTEGER NOT NULL
        )
      `);
      state.storage.sql.exec(
        `INSERT INTO sync_session (singleton, session_id, phase, touched_at)
         VALUES (1, ?, 'publishing', ?)`,
        SESSION_A,
        Math.floor(Date.now() / 1000),
      );
      state.storage.sql.exec(
        `INSERT INTO staged_events
          (session_id, kind, name, seq, event_cid, prev_cid, new_cid, child_published)
         VALUES (?, 'pointer', 'legacy/unwitnessed', 1, ?, NULL, ?, 1)`,
        SESSION_A,
        "11".repeat(32),
        "22".repeat(32),
      );
    });
    await evictDurableObject(catalog);

    const migrated = env.CATALOG.getByName("catalog");
    expect(await migrated.counts()).toMatchObject({ staged: 0, phase: "idle" });
    expect(await migrated.publicationPlan()).toEqual({ state: "idle" });
    expect((await SELF.fetch("https://example.test/p/legacy%2Funwitnessed")).status).toBe(404);
    const discarded = await finalize(SESSION_A);
    expect(discarded.status).toBe(409);
    expect(await discarded.json()).toMatchObject({
      error: { code: "sync_session_legacy_discarded" },
    });
  });

  it("never caches an unproved legacy head across resolve, import, or CAS", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const liveTarget = await putBytes(new TextEncoder().encode("legacy-proof-live"));

    const missingName = "legacy/proof-missing";
    const missingEventBytes = encodeEntry(
      encodePointerEvent({ seq: 1, pointerId: missingName, prev: null, new: liveTarget, ts: 1 }),
    );
    const missingEventCid = await computeCidHex(missingEventBytes);
    await env.POINTERS.getByName(`pointer:${missingName}`).importEvent(
      missingName,
      1,
      missingEventCid,
      { seq: 1, pointerId: missingName, prev: null, new: liveTarget },
    );

    const closureName = "legacy/proof-closure";
    const missingTarget = await computeCidHex(new TextEncoder().encode("legacy-missing-target"));
    const closureEventCid = await pointerEntry(closureName, missingTarget);
    await env.POINTERS.getByName(`pointer:${closureName}`).importEvent(
      closureName,
      1,
      closureEventCid,
      { seq: 1, pointerId: closureName, prev: null, new: missingTarget },
    );

    const pinName = "legacy-proof-corrupt-pin";
    const corruptPinBytes = pinEntry(pinName, liveTarget, 1);
    const corruptPinCid = await computeCidHex(corruptPinBytes);
    await env.CHUNKS!.put(corruptPinCid, new TextEncoder().encode("corrupt pin head"));
    await env.PINS.getByName(`pin:${pinName}`).importEvent(pinName, 1, corruptPinCid, {
      seq: 1,
      pinId: pinName,
      prev: null,
    });

    const casName = "legacy/proof-mismatch-cas";
    const mismatchedCasBytes = encodeEntry(
      encodePointerEvent({ seq: 1, pointerId: `${casName}/forged`, prev: null, new: liveTarget, ts: 1 }),
    );
    const mismatchedCasCid = await putBytes(mismatchedCasBytes);
    await env.POINTERS.getByName(`pointer:${casName}`).importEvent(
      casName,
      1,
      mismatchedCasCid,
      { seq: 1, pointerId: casName, prev: null, new: liveTarget },
    );

    await runInDurableObject(catalog, (_instance, state) => {
      for (const [kind, name] of [
        ["pointer", missingName],
        ["pointer", closureName],
        ["pin", pinName],
        ["pointer", casName],
      ] as const) {
        state.storage.sql.exec(
          `INSERT INTO registry
            (kind, name, state, owner, reserved_at, head_seq, head_cid)
           VALUES (?, ?, 'committed', NULL, NULL, NULL, NULL)`,
          kind,
          name,
        );
        state.storage.sql.exec("INSERT INTO names (kind, name) VALUES (?, ?)", kind, name);
      }
    });

    const missing = await SELF.fetch(`https://example.test/p/${encodeURIComponent(missingName)}`);
    expect(missing.status).toBe(502);
    expect(await missing.json()).toMatchObject({ error: { code: "legacy_head_unavailable" } });
    const closure = await SELF.fetch(`https://example.test/p/${encodeURIComponent(closureName)}`);
    expect(closure.status).toBe(409);
    expect(await closure.json()).toMatchObject({ error: { code: "reference_unavailable" } });

    const replacementPin = await putBytes(pinEntry(pinName, liveTarget, 2));
    const pinImport = await SELF.fetch("https://example.test/sync/import/pin", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: pinName, seq: 1, cid: replacementPin }),
    });
    expect(pinImport.status).toBe(502);
    expect(await pinImport.json()).toMatchObject({ error: { code: "legacy_head_unavailable" } });

    const cas = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: casName, expect_seq: 1, cid: liveTarget }),
    });
    expect(cas.status).toBe(502);
    expect(await cas.json()).toMatchObject({ error: { code: "legacy_head_invalid" } });
    expect(await catalog.operationStatus(Math.floor(Date.now() / 1000))).toMatchObject({
      phase: "idle",
      stagedEvents: 0,
    });
    for (const [kind, name] of [
      ["pointer", missingName],
      ["pointer", closureName],
      ["pin", pinName],
      ["pointer", casName],
    ] as const) {
      expect(await catalog.legacyHeadPending(kind, name)).toBe(true);
    }

    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        "DELETE FROM registry WHERE name IN (?, ?, ?, ?)",
        missingName,
        closureName,
        pinName,
        casName,
      );
      state.storage.sql.exec(
        "DELETE FROM names WHERE name IN (?, ?, ?, ?)",
        missingName,
        closureName,
        pinName,
        casName,
      );
    });
  });

  it("migrates confirmed legacy catalog rows lazily and prunes phantom membership", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const target = await putBytes(new TextEncoder().encode("legacy-head"));
    const eventCid = await pointerEntry("legacy/real", target);
    expect(
      await env.POINTERS.getByName("pointer:legacy/real").importEvent("legacy/real", 1, eventCid, {
        seq: 1,
        pointerId: "legacy/real",
        prev: null,
        new: target,
      }),
    ).toMatchObject({ ok: true });
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec("DROP TABLE registry");
      state.storage.sql.exec(`
        CREATE TABLE registry (
          kind TEXT NOT NULL CHECK (kind IN ('pointer', 'pin')),
          name TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('pending', 'committed')),
          owner TEXT,
          reserved_at INTEGER,
          PRIMARY KEY (kind, name),
          CHECK (
            (state = 'committed' AND owner IS NULL AND reserved_at IS NULL) OR
            (state = 'pending' AND owner IS NOT NULL AND reserved_at IS NOT NULL)
          )
        )
      `);
      state.storage.sql.exec(
        `INSERT INTO registry (kind, name, state, owner, reserved_at)
         VALUES ('pointer', 'legacy/pending', 'pending', ?, 1)`,
        SESSION_A,
      );
      state.storage.sql.exec("INSERT INTO names (kind, name) VALUES ('pointer', 'legacy/real')");
      state.storage.sql.exec("INSERT INTO names (kind, name) VALUES ('pointer', 'legacy/phantom')");
    });
    await evictDurableObject(catalog);

    expect(await (await SELF.fetch("https://example.test/p/legacy%2Freal")).json()).toMatchObject({
      seq: 1,
      cid: target,
    });
    expect((await SELF.fetch("https://example.test/p/legacy%2Fphantom")).status).toBe(404);
    expect(await env.CATALOG.getByName("catalog").contains("pointer", "legacy/phantom")).toBe(false);
    expect(await env.CATALOG.getByName("catalog").contains("pointer", "legacy/pending")).toBe(false);
  });

  it("anchors legacy membership to the canonical head before an older sync offer", async () => {
    const name = "legacy/non-regression";
    const first = await putBytes(new TextEncoder().encode("legacy-first"));
    const second = await putBytes(new TextEncoder().encode("legacy-second"));
    const firstEvent = await pointerEntry(name, first);
    const secondEvent = await pointerEntry(name, second, 2, first);
    const child = env.POINTERS.getByName(`pointer:${name}`);
    expect(
      await child.importEvent(name, 1, firstEvent, {
        seq: 1,
        pointerId: name,
        prev: null,
        new: first,
      }),
    ).toMatchObject({ ok: true });
    expect(
      await child.importEvent(name, 2, secondEvent, {
        seq: 2,
        pointerId: name,
        prev: first,
        new: second,
      }),
    ).toMatchObject({ ok: true });
    const catalog = env.CATALOG.getByName("catalog");
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        `INSERT INTO registry
          (kind, name, state, owner, reserved_at, head_seq, head_cid)
         VALUES ('pointer', ?, 'committed', NULL, NULL, NULL, NULL)`,
        name,
      );
      state.storage.sql.exec("INSERT INTO names (kind, name) VALUES ('pointer', ?)", name);
    });

    const offered = await SELF.fetch("https://example.test/sync/import/pointer", {
      method: "POST",
      headers: authHeaders("application/json", SESSION_A),
      body: JSON.stringify({ id: name, seq: 1, cid: firstEvent }),
    });
    expect(offered.status).toBe(200);
    expect(await offered.json()).toEqual({ filed: false });
    expect((await finalize()).status).toBe(200);
    expect(await (await SELF.fetch("https://example.test/p/legacy%2Fnon-regression")).json()).toMatchObject({
      seq: 2,
      cid: second,
    });
  });

  it("normalizes malformed percent encoding to a structured client error", async () => {
    const response = await SELF.fetch("https://example.test/p/%");
    expect(response.status).toBe(400);
    const body = await response.json<{ error: { code: string } }>();
    expect(body.error.code).toBe("invalid_path_encoding");
  });

  it("advertises safe public CORS response headers", async () => {
    const response = await SELF.fetch("https://example.test/c/example", { method: "OPTIONS" });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-methods")).toBe("GET, HEAD, OPTIONS");
    expect(response.headers.get("access-control-allow-headers")).toContain("Range");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("does not combine pointer CAS work with an existing sync publication", async () => {
    const syncTarget = await putBytes(new TextEncoder().encode("phase-split-sync"));
    const syncEvent = await pointerEntry("phase/sync", syncTarget);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "phase/sync", seq: 1, cid: syncEvent }),
        })
      ).status,
    ).toBe(200);
    const catalog = env.CATALOG.getByName("catalog");
    const snapshot = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(snapshot.state).toBe("validate");
    if (snapshot.state !== "validate") throw new Error("expected validation snapshot");
    await validatePublicationClosure(
      openStore(env as EdgeEnv),
      snapshot.heads,
      Math.floor(Date.now() / 1000),
    );
    expect(
      await catalog.freezePublication(
        snapshot.sessionId,
        snapshot.revision,
        Math.floor(Date.now() / 1000),
      ),
    ).toEqual({ state: "publishing" });

    const casTarget = await putBytes(new TextEncoder().encode("phase-split-cas"));
    const cas = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "phase/cas", expect_seq: 0, cid: casTarget }),
    });
    expect(cas.status).toBe(409);
    expect(await cas.json()).toMatchObject({ error: { code: "sync_publication_pending" } });
    expect((await catalog.publicationPlan()).state).toBe("publishing");
    expect(await env.POINTERS.getByName("pointer:phase/sync").head()).toMatchObject({ seq: 0 });
    expect(await env.POINTERS.getByName("pointer:phase/cas").head()).toMatchObject({ seq: 0 });
    expect((await finalize()).status).toBe(200);
  });

  it("publishes CAS immediately through the Catalog and refuses stale expectations", async () => {
    const first = await putBytes(new TextEncoder().encode("cas-first"));
    const created = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "cas/release", expect_seq: 0, cid: first }),
    });
    expect(created.status).toBe(200);
    expect(await (await SELF.fetch("https://example.test/p/cas%2Frelease")).json()).toMatchObject({
      seq: 1,
      cid: first,
    });

    const second = await putBytes(new TextEncoder().encode("cas-second"));
    const stale = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "cas/release", expect_seq: 0, cid: second }),
    });
    expect(stale.status).toBe(412);
    expect(await (await SELF.fetch("https://example.test/p/cas%2Frelease")).json()).toMatchObject({
      seq: 1,
      cid: first,
    });
  });

  it("refuses to extend a modern CAS history whose current event object was lost", async () => {
    const first = await putBytes(new TextEncoder().encode("cas-proof-first"));
    const created = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "cas/proof-current", expect_seq: 0, cid: first }),
    });
    expect(created.status).toBe(200);
    const receipt = await created.json<{ event_cid: string }>();
    await env.CHUNKS!.delete(receipt.event_cid);

    const second = await putBytes(new TextEncoder().encode("cas-proof-second"));
    const refused = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "cas/proof-current", expect_seq: 1, cid: second }),
    });
    expect(refused.status).toBe(502);
    expect(await refused.json()).toMatchObject({ error: { code: "legacy_head_unavailable" } });
    expect(await env.CATALOG.getByName("catalog").operationStatus(Math.floor(Date.now() / 1000))).toMatchObject({
      phase: "idle",
    });
    expect(await (await SELF.fetch("https://example.test/p/cas%2Fproof-current")).json()).toMatchObject({
      seq: 1,
      cid: first,
    });
  });

  it("never publishes a child-ahead CAS head without its event and live closure proof", async () => {
    for (const testCase of [
      { kind: "missing", code: "legacy_head_unavailable", status: 502 },
      { kind: "corrupt", code: "legacy_head_unavailable", status: 502 },
      { kind: "missing-closure", code: "reference_unavailable", status: 409 },
    ] as const) {
      const name = `cas/child-ahead-${testCase.kind}`;
      const firstTarget = await putBytes(new TextEncoder().encode(`${testCase.kind}-first`));
      const created = await SELF.fetch("https://example.test/pointers", {
        method: "POST",
        headers: authHeaders("application/json"),
        body: JSON.stringify({ id: name, expect_seq: 0, cid: firstTarget }),
      });
      expect(created.status).toBe(200);

      const missingTarget = await computeCidHex(
        new TextEncoder().encode(`${testCase.kind}-missing-target`),
      );
      const childTarget = testCase.kind === "missing-closure"
        ? missingTarget
        : await putBytes(new TextEncoder().encode(`${testCase.kind}-second`));
      const eventBytes = encodeEntry(
        encodePointerEvent({
          seq: 2,
          pointerId: name,
          prev: firstTarget,
          new: childTarget,
          ts: 2,
        }),
      );
      const childEventCid = await computeCidHex(eventBytes);
      if (testCase.kind === "corrupt") {
        await env.CHUNKS!.put(childEventCid, new TextEncoder().encode("corrupt child-ahead event"));
      } else if (testCase.kind === "missing-closure") {
        expect(await putBytes(eventBytes)).toBe(childEventCid);
      }
      expect(
        await env.POINTERS.getByName(`pointer:${name}`).importEvent(name, 2, childEventCid, {
          seq: 2,
          pointerId: name,
          prev: firstTarget,
          new: childTarget,
        }),
      ).toMatchObject({ ok: true });

      const proposed = await putBytes(new TextEncoder().encode(`${testCase.kind}-proposed`));
      const refused = await SELF.fetch("https://example.test/pointers", {
        method: "POST",
        headers: authHeaders("application/json"),
        body: JSON.stringify({ id: name, expect_seq: 1, cid: proposed }),
      });
      expect(refused.status).toBe(testCase.status);
      expect(await refused.json()).toMatchObject({ error: { code: testCase.code } });
      expect(await (await SELF.fetch(`https://example.test/p/${encodeURIComponent(name)}`)).json())
        .toMatchObject({ seq: 1, cid: firstTarget });
      expect(await env.CATALOG.getByName("catalog").operationStatus(Math.floor(Date.now() / 1000)))
        .toMatchObject({ phase: "idle" });
    }
  });

  it("applies the catalog name ceiling to direct pointer CAS", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        `WITH RECURSIVE sequence(n) AS (
           VALUES(0)
           UNION ALL SELECT n + 1 FROM sequence WHERE n + 1 < ?
         )
         INSERT INTO registry
           (kind, name, state, owner, reserved_at, head_seq, head_cid)
         SELECT 'pin', 'capacity/' || n, 'committed', NULL, NULL, 1, ?
         FROM sequence`,
        MAX_CATALOG_NAMES - 1,
        "11".repeat(32),
      );
      state.storage.sql.exec(
        `INSERT INTO registry
          (kind, name, state, owner, reserved_at, head_seq, head_cid)
         VALUES ('pointer', 'capacity/existing', 'committed', NULL, NULL, 1, ?)`,
        "22".repeat(32),
      );
    });

    const owner = "00000000-0000-4000-8000-0000000000cc";
    const now = Math.floor(Date.now() / 1000);
    expect(await catalog.beginCas(owner, "capacity/existing", now)).toEqual({ state: "ready" });
    expect(await catalog.cancelCas(owner)).toEqual({ released: true });
    expect(await catalog.beginCas(owner, "capacity/new", now)).toEqual({
      state: "catalog_full",
      limit: MAX_CATALOG_NAMES,
    });

    const target = await putBytes(new TextEncoder().encode("capacity-target"));
    const response = await SELF.fetch("https://example.test/pointers", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ id: "capacity/new", expect_seq: 0, cid: target }),
    });
    expect(response.status).toBe(507);
    expect(await response.json()).toMatchObject({ error: { code: "catalog_full" } });
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec("DELETE FROM registry WHERE name LIKE 'capacity/%'");
    });
  });

  it("recovers a CAS crash after the child write and never regresses the committed head", async () => {
    const name = "cas/crash";
    const target = await putBytes(new TextEncoder().encode("cas-crash-target"));
    const eventCid = await pointerEntry(name, target);
    const catalog = env.CATALOG.getByName("catalog");
    const ownerA = "00000000-0000-4000-8000-0000000000ca";
    const ownerB = "00000000-0000-4000-8000-0000000000cb";
    const startedAt = Math.floor(Date.now() / 1000);
    expect(await catalog.beginCas(ownerA, name, startedAt)).toEqual({ state: "ready" });
    const child = env.POINTERS.getByName(`pointer:${name}`);
    expect(
      await child.importEvent(name, 1, eventCid, {
        seq: 1,
        pointerId: name,
        prev: null,
        new: target,
      }),
    ).toMatchObject({ ok: true });
    expect((await SELF.fetch("https://example.test/p/cas%2Fcrash")).status).toBe(404);

    expect(
      await catalog.beginCas(ownerB, "cas/next", startedAt + OPERATION_LEASE_SECONDS),
    ).toEqual({ state: "recover_cas", owner: ownerB, name });
    expect(await catalog.publishRecoveredCas(ownerB, name, await child.head())).toEqual({
      ok: true,
      published: true,
    });
    expect(await (await SELF.fetch("https://example.test/p/cas%2Fcrash")).json()).toMatchObject({
      seq: 1,
      cid: target,
    });

    expect(await catalog.beginCas(ownerA, name, startedAt + OPERATION_LEASE_SECONDS + 1)).toEqual({
      state: "ready",
    });
    expect(
      await catalog.publishRecoveredCas(ownerA, name, { seq: 0, cid: null, eventCid: null }),
    ).toMatchObject({ ok: false });
    expect((await catalog.pointerState(name))).toEqual({ state: "ready", seq: 1, cid: target });
    await catalog.cancelCas(ownerA);
  });

  it("finishes a witnessed publication but defers probe work to a fresh request", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const before = await catalog.counts();
    const target = await putBytes(new TextEncoder().encode("probe-phase-target"));
    const eventCid = await pointerEntry("probe/phase-split", target);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "probe/phase-split", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);
    const snapshot = await catalog.beginFinalize(SESSION_A, Math.floor(Date.now() / 1000));
    expect(snapshot.state).toBe("validate");
    if (snapshot.state !== "validate") throw new Error("expected validation snapshot");
    await validatePublicationClosure(
      openStore(env as EdgeEnv),
      snapshot.heads,
      Math.floor(Date.now() / 1000),
    );
    await catalog.freezePublication(
      snapshot.sessionId,
      snapshot.revision,
      Math.floor(Date.now() / 1000),
    );

    const probe = await SELF.fetch("https://example.test/sync/probe/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ events: [] }),
    });
    expect(probe.status).toBe(409);
    expect(await probe.json()).toMatchObject({ error: { code: "coordination_recovered" } });
    expect(await catalog.counts()).toMatchObject({
      phase: "idle",
      staged: 0,
      pointers: before.pointers + 1,
    });
  });

  it("refuses demo probe fanout before acquiring a lease or calling child objects", async () => {
    const before = await listDurableObjectIds(env.POINTERS);
    const events = Array.from({ length: DEMO_MAX_PUBLICATION_GROUPS + 1 }, (_, index) => ({
      id: `demo-probe/${index}`,
      seq: 1,
      cid: "ab".repeat(32),
    }));
    const demoEnv: EdgeEnv = { ...env, DAG_EDGE_MODE: "demo-kv" };
    const response = await edgeWorker.fetch(
      new Request("https://example.test/sync/probe/pointer", {
        method: "POST",
        headers: authHeaders("application/json"),
        body: JSON.stringify({ events }),
      }),
      demoEnv,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: "probe_name_limit" } });
    expect(await env.CATALOG.getByName("catalog").counts()).toMatchObject({ phase: "idle" });
    expect(await listDurableObjectIds(env.POINTERS)).toHaveLength(before.length);
  });

  it("provides bounded, sessionless, read-only divergence probes", async () => {
    const target = await putBytes(new TextEncoder().encode("probe-head"));
    const eventCid = await pointerEntry("probe/known", target);
    expect(
      (
        await SELF.fetch("https://example.test/sync/import/pointer", {
          method: "POST",
          headers: authHeaders("application/json", SESSION_A),
          body: JSON.stringify({ id: "probe/known", seq: 1, cid: eventCid }),
        })
      ).status,
    ).toBe(200);
    expect((await finalize()).status).toBe(200);
    const before = await listDurableObjectIds(env.POINTERS);
    const offered = "ab".repeat(32);
    const response = await SELF.fetch("https://example.test/sync/probe/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({
        events: [
          { id: "probe/known", seq: 1, cid: eventCid },
          { id: "probe/known", seq: 1, cid: eventCid },
          { id: "probe/unknown", seq: 1, cid: offered },
        ],
      }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ conflicts: [] });
    expect(await listDurableObjectIds(env.POINTERS)).toHaveLength(before.length);

    const conflict = await SELF.fetch("https://example.test/sync/probe/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ events: [{ id: "probe/known", seq: 1, cid: offered }] }),
    });
    expect(await conflict.json()).toEqual({
      conflicts: [{ id: "probe/known", seq: 1, offered, existing: eventCid }],
    });
  });

  it("recovers an expired CAS lease before admitting a probe", async () => {
    const name = "probe/cas-recovery";
    const target = await putBytes(new TextEncoder().encode("probe-cas-recovery"));
    const eventCid = await pointerEntry(name, target);
    await env.POINTERS.getByName(`pointer:${name}`).importEvent(name, 1, eventCid, {
      seq: 1,
      pointerId: name,
      prev: null,
      new: target,
    });
    const catalog = env.CATALOG.getByName("catalog");
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        `INSERT OR REPLACE INTO cas_lease (singleton, owner, name, touched_at)
         VALUES (1, ?, ?, ?)`,
        "00000000-0000-4000-8000-0000000000da",
        name,
        Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS - 1,
      );
    });

    const recovered = await SELF.fetch("https://example.test/sync/probe/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ events: [{ id: name, seq: 1, cid: eventCid }] }),
    });
    expect(recovered.status).toBe(409);
    expect(await recovered.json()).toMatchObject({ error: { code: "coordination_recovered" } });
    const response = await SELF.fetch("https://example.test/sync/probe/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ events: [{ id: name, seq: 1, cid: eventCid }] }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ conflicts: [] });
    expect(await catalog.operationStatus(Math.floor(Date.now() / 1000))).toMatchObject({
      phase: "idle",
    });
  });

  it("does not publish CAS recovery when the child head event object is missing", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const name = "cas/recovery-missing-event";
    const owner = crypto.randomUUID();
    const startedAt = Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS;
    expect(await catalog.beginCas(owner, name, startedAt)).toEqual({ state: "ready" });
    const target = await putBytes(new TextEncoder().encode("recovery-missing-target"));
    const missingEvent = await computeCidHex(new TextEncoder().encode("missing-cas-event"));
    await env.POINTERS.getByName(`pointer:${name}`).importEvent(name, 1, missingEvent, {
      seq: 1,
      pointerId: name,
      prev: null,
      new: target,
    });

    const recovery = await SELF.fetch("https://example.test/sync/probe/pointer", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: JSON.stringify({ events: [] }),
    });
    expect(recovery.status).toBe(502);
    expect(await recovery.json()).toMatchObject({ error: { code: "legacy_head_unavailable" } });
    expect(await catalog.pointerState(name)).toEqual({ state: "absent" });
    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec("DELETE FROM cas_lease");
    });
  });

  it("enforces retained byte quota and never double-charges an existing CID", async () => {
    const baseline = await env.CATALOG.getByName("catalog").budgetStatus();
    const first = new Uint8Array(3 * 1024 * 1024);
    first[0] = 1;
    const firstCid = await computeCidHex(first);
    const putFirst = () =>
      SELF.fetch(`https://example.test/c/${firstCid}`, {
        method: "PUT",
        headers: authHeaders("application/octet-stream"),
        body: first,
      });
    expect((await putFirst()).status).toBe(204);
    const afterFirst = await env.CATALOG.getByName("catalog").budgetStatus();
    expect(afterFirst).toMatchObject({
      retainedBytes: baseline.retainedBytes + first.byteLength,
      retainedObjects: baseline.retainedObjects + 1,
    });
    expect((await putFirst()).status).toBe(204);
    expect(await env.CATALOG.getByName("catalog").budgetStatus()).toEqual(afterFirst);

    const second = new Uint8Array(3 * 1024 * 1024);
    second[0] = 2;
    const secondCid = await computeCidHex(second);
    const exhausted = await SELF.fetch(`https://example.test/c/${secondCid}`, {
      method: "PUT",
      headers: authHeaders("application/octet-stream"),
      body: second,
    });
    expect(exhausted.status).toBe(507);
    expect((await exhausted.json<{ error: { code: string } }>()).error.code).toBe(
      "retained_bytes_quota_exceeded",
    );
  });

  it("reserves object capacity atomically and refuses an over-budget object", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const baseline = await catalog.budgetStatus();
    const ownerA = "00000000-0000-4000-8000-0000000000ba";
    const ownerB = "00000000-0000-4000-8000-0000000000bb";
    const limit = baseline.retainedObjects + 1;
    expect(
      await catalog.reserveChunk(
        ownerA,
        "12".repeat(32),
        0,
        Math.floor(Date.now() / 1000),
        Number.MAX_SAFE_INTEGER,
        limit,
      ),
    ).toEqual({ state: "reserved" });
    expect(
      await catalog.reserveChunk(
        ownerB,
        "13".repeat(32),
        0,
        Math.floor(Date.now() / 1000),
        Number.MAX_SAFE_INTEGER,
        limit,
      ),
    ).toEqual({ state: "quota", resource: "objects" });
    await runInDurableObject(catalog, async (_instance, state) => {
      const expired = Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS - 1;
      state.storage.sql.exec(
        "UPDATE chunk_budget SET reserved_at = ?, absent_since = ? WHERE cid = ?",
        expired,
        expired,
        "12".repeat(32),
      );
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toEqual(baseline);
  });

  it("reconciles expired reservations only after a bounded confirmed-absence grace", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const baseline = await catalog.budgetStatus();
    const owner = "00000000-0000-4000-8000-0000000000e1";
    const cid = "31".repeat(32);
    const expired = Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS - 1;
    expect(
      await catalog.reserveChunk(
        owner,
        cid,
        17,
        expired,
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER,
      ),
    ).toEqual({ state: "reserved" });

    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toMatchObject({
      retainedBytes: baseline.retainedBytes + 17,
      retainedObjects: baseline.retainedObjects + 1,
      reservations: baseline.reservations + 1,
    });
    await runInDurableObject(catalog, async (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE chunk_budget SET reserved_at = ?, absent_since = ? WHERE cid = ?",
        expired,
        expired,
        cid,
      );
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toEqual(baseline);
  });

  it("reconciles expired reservations in persisted bounded alarm batches", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const expired = Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS - 1;
    const cids = Array.from({ length: RESERVATION_RECONCILE_BATCH + 1 }, (_, index) =>
      (0x80 + index).toString(16).padStart(64, "0"),
    );
    for (let index = 0; index < cids.length; index++) {
      const owner = `00000000-0000-4000-8000-${(0xf00 + index).toString(16).padStart(12, "0")}`;
      expect(
        await catalog.reserveChunk(
          owner,
          cids[index],
          0,
          expired,
          Number.MAX_SAFE_INTEGER,
          Number.MAX_SAFE_INTEGER,
        ),
      ).toEqual({ state: "reserved" });
    }

    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    const firstPass = await runInDurableObject(catalog, (_instance, state) =>
      state.storage.sql
        .exec<{ marked: number }>(
          `SELECT COUNT(*) AS marked FROM chunk_budget
           WHERE cid IN (${cids.map(() => "?").join(",")}) AND absent_since IS NOT NULL`,
          ...cids,
        )
        .one().marked,
    );
    expect(firstPass).toBe(RESERVATION_RECONCILE_BATCH);

    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    const secondPass = await runInDurableObject(catalog, (_instance, state) =>
      state.storage.sql
        .exec<{ marked: number }>(
          `SELECT COUNT(*) AS marked FROM chunk_budget
           WHERE cid IN (${cids.map(() => "?").join(",")}) AND absent_since IS NOT NULL`,
          ...cids,
        )
        .one().marked,
    );
    expect(secondPass).toBe(cids.length);

    await runInDurableObject(catalog, (_instance, state) => {
      state.storage.sql.exec(
        `DELETE FROM chunk_budget WHERE cid IN (${cids.map(() => "?").join(",")})`,
        ...cids,
      );
      state.storage.sql.exec(
        `UPDATE budget_totals SET
          retained_bytes = (SELECT COALESCE(SUM(size), 0) FROM chunk_budget),
          retained_objects = (SELECT COUNT(*) FROM chunk_budget)
         WHERE singleton = 1`,
      );
    });
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
  });

  it("commits a provider-verified R2 object found after an interrupted upload", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const baseline = await catalog.budgetStatus();
    const owner = "00000000-0000-4000-8000-0000000000e2";
    const bytes = new TextEncoder().encode("reservation-present");
    const cid = await computeCidHex(bytes);
    const expired = Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS - 1;
    expect(
      await catalog.reserveChunk(
        owner,
        cid,
        bytes.byteLength,
        expired,
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER,
      ),
    ).toEqual({ state: "reserved" });
    await env.CHUNKS!.put(cid, bytes, { sha256: cid });

    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toMatchObject({
      retainedBytes: baseline.retainedBytes + bytes.byteLength,
      retainedObjects: baseline.retainedObjects + 1,
      reservations: baseline.reservations,
    });
    expect(await inspectR2BudgetObject(env.CHUNKS!, cid, bytes.byteLength)).toEqual({
      state: "valid",
    });
  });

  it("fences an expired writer before releasing its absent reservation", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const baseline = await catalog.budgetStatus();
    const owner = "00000000-0000-4000-8000-0000000000e3";
    const bytes = new TextEncoder().encode("reservation-race");
    const cid = await computeCidHex(bytes);
    const now = Math.floor(Date.now() / 1000);
    expect(
      await catalog.reserveChunk(
        owner,
        cid,
        bytes.byteLength,
        now,
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER,
      ),
    ).toEqual({ state: "reserved" });
    const marker = await ensureR2ReservationMarker(env.CHUNKS!, cid, bytes.byteLength, owner);
    expect(marker.state).toBe("marker");
    if (marker.state !== "marker") throw new Error("reservation marker was not created");

    const expired = now - OPERATION_LEASE_SECONDS - 1;
    await runInDurableObject(catalog, async (_instance, state) => {
      state.storage.sql.exec("UPDATE chunk_budget SET reserved_at = ? WHERE cid = ?", expired, cid);
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.renewChunk(owner, cid, now + 1)).toEqual({ renewed: false });
    const late = await writeR2ReservedChunk(
      env.CHUNKS!,
      cid,
      bytes.byteLength,
      bytes,
      marker.etag,
    );
    expect(late).toMatchObject({ state: "changed", object: { state: "absent" } });
    expect(await inspectR2BudgetObject(env.CHUNKS!, cid, bytes.byteLength)).toEqual({
      state: "absent",
    });

    await runInDurableObject(catalog, async (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE chunk_budget SET reserved_at = ?, absent_since = ? WHERE cid = ?",
        expired,
        expired,
        cid,
      );
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toEqual(baseline);
  });

  it("keeps an invalid real object charged and commits it after a verified retry", async () => {
    const catalog = env.CATALOG.getByName("catalog");
    const baseline = await catalog.budgetStatus();
    const owner = "00000000-0000-4000-8000-0000000000e4";
    const bytes = new TextEncoder().encode("reservation-retry");
    const cid = await computeCidHex(bytes);
    const expired = Math.floor(Date.now() / 1000) - OPERATION_LEASE_SECONDS - 1;
    expect(
      await catalog.reserveChunk(
        owner,
        cid,
        bytes.byteLength,
        expired,
        Number.MAX_SAFE_INTEGER,
        Number.MAX_SAFE_INTEGER,
      ),
    ).toEqual({ state: "reserved" });
    await env.CHUNKS!.put(cid, new Uint8Array(bytes.byteLength));
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toMatchObject({
      retainedBytes: baseline.retainedBytes + bytes.byteLength,
      retainedObjects: baseline.retainedObjects + 1,
      reservations: baseline.reservations + 1,
    });

    await env.CHUNKS!.put(cid, bytes, { sha256: cid });
    await runInDurableObject(catalog, async (_instance, state) => {
      state.storage.sql.exec("UPDATE chunk_budget SET reserved_at = ? WHERE cid = ?", expired, cid);
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(catalog)).toBe(true);
    expect(await catalog.budgetStatus()).toMatchObject({
      retainedBytes: baseline.retainedBytes + bytes.byteLength,
      retainedObjects: baseline.retainedObjects + 1,
      reservations: baseline.reservations,
    });
  });

  it("caps inspection link output and omits oversized link labels", async () => {
    const target = "cd".repeat(32);
    const bytes = encodeCbor({
      payload: [],
      links: Array.from({ length: INSPECT_LINK_LIMIT + 7 }, (_, index) => ({
        name: index === 0 ? "x".repeat(1024) : `link-${index}`,
        target: cidToIntArray(target),
      })),
    });
    const cid = await putBytes(bytes);
    const response = await SELF.fetch(`https://example.test/i/${cid}`);
    expect(response.status).toBe(200);
    const responseText = response.clone().text();
    const inspected = await response.json<{
      links: Array<{ name: string | null; name_truncated?: boolean }>;
      link_count: number;
      links_truncated: boolean;
    }>();
    expect(inspected.links).toHaveLength(INSPECT_LINK_LIMIT);
    expect(inspected.link_count).toBe(INSPECT_LINK_LIMIT + 7);
    expect(inspected.links_truncated).toBe(true);
    expect(inspected.links[0]).toMatchObject({ name: null, name_truncated: true });
    expect((await responseText).length).toBeLessThan(100_000);
  });

  it("keeps concurrent near-limit inspections bounded and returns 422 at the structural ceiling", async () => {
    const bytes = largeRustEntry(80_000);
    expect(bytes.byteLength).toBe(3_920_021);
    expect(bytes.byteLength).toBeLessThan(MAX_CHUNK_SIZE);
    const cid = await computeCidHex(bytes);
    await env.CHUNKS!.put(cid, bytes);

    const responses = await Promise.all(
      Array.from({ length: 4 }, () => SELF.fetch(`https://example.test/i/${cid}`)),
    );
    for (const response of responses) {
      expect(response.status).toBe(200);
      const body = await response.json<{
        kind: string;
        link_count: number;
        links: unknown[];
        links_truncated: boolean;
      }>();
      expect(body).toMatchObject({
        kind: "entry",
        link_count: 80_000,
        links_truncated: true,
      });
      expect(body.links).toHaveLength(INSPECT_LINK_LIMIT);
    }

    const refusedBytes = rustEntryPrefix(MAX_ENTRY_LINKS + 1);
    const refusedCid = await computeCidHex(refusedBytes);
    await env.CHUNKS!.put(refusedCid, refusedBytes);
    const refused = await SELF.fetch(`https://example.test/i/${refusedCid}`);
    expect(refused.status).toBe(422);
    expect((await refused.json<{ error: { code: string } }>()).error.code).toBe(
      "inspection_limit_exceeded",
    );
  });

  it("rejects a JSON BOM instead of silently normalizing request bytes", async () => {
    const response = await SELF.fetch("https://example.test/sync/missing", {
      method: "POST",
      headers: authHeaders("application/json"),
      body: `\ufeff${JSON.stringify({ cids: [] })}`,
    });
    expect(response.status).toBe(400);
    expect((await response.json<{ error: { code: string } }>()).error.code).toBe("invalid_json");
  });

  it("serves only the two pinned verifier assets", async () => {
    const js = await SELF.fetch("https://example.test/assets/dag_wasm.js");
    expect(js.status).toBe(200);
    expect(js.headers.get("content-type")).toContain("text/javascript");
    expect(js.headers.get("cache-control")).toContain("immutable");

    const wasm = await SELF.fetch("https://example.test/assets/dag_wasm_bg.wasm");
    expect(wasm.status).toBe(200);
    expect(wasm.headers.get("content-type")).toBe("application/wasm");

    expect((await SELF.fetch("https://example.test/assets/../src/index.ts")).status).toBe(404);
    expect((await SELF.fetch("https://example.test/assets/not-allowed.js")).status).toBe(404);
  });
});
