import assert from "node:assert/strict";
import test from "node:test";
import {
  cancelR2ReservationMarker,
  ensureR2ReservationMarker,
  openStore,
  writeR2ReservedChunk,
  type R2BudgetBucket,
} from "../src/chunks.ts";

type FakeObject = {
  bytes: Uint8Array;
  etag: string;
  customMetadata?: Record<string, string>;
  checksums?: { sha256?: ArrayBuffer };
};

class ContentEtagBucket implements R2BudgetBucket {
  readonly writes: string[] = [];
  private readonly objects = new Map<string, FakeObject>();

  async head(key: string) {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      size: object.bytes.byteLength,
      etag: object.etag,
      customMetadata: object.customMetadata,
      checksums: object.checksums,
    };
  }

  async put(
    key: string,
    value: Uint8Array,
    options?: {
      onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } | Headers;
      httpMetadata?: { contentType?: string; cacheControl?: string };
      customMetadata?: Record<string, string>;
      sha256?: string;
    },
  ) {
    const current = this.objects.get(key);
    const condition = options?.onlyIf;
    if (condition instanceof Headers) {
      if (condition.get("if-none-match") === "*" && current) return null;
      const match = condition.get("if-match");
      if (match !== null && current?.etag !== match) return null;
    } else if (condition) {
      if (condition.etagMatches !== undefined && current?.etag !== condition.etagMatches) {
        return null;
      }
      if (
        condition.etagDoesNotMatch !== undefined &&
        current?.etag === condition.etagDoesNotMatch
      ) {
        return null;
      }
    }
    const bytes = new Uint8Array(value.byteLength);
    bytes.set(value);
    const etag = hex(await crypto.subtle.digest("SHA-256", bytes));
    this.writes.push(etag);
    this.objects.set(key, {
      bytes,
      etag,
      customMetadata: options?.customMetadata,
      checksums: options?.sha256 ? { sha256: fromHex(options.sha256) } : undefined,
    });
    return { etag };
  }

  async delete(key: string) {
    this.objects.delete(key);
  }
}

test("R2 test mode is usable only with the local Workerd harness binding", () => {
  const bucket = {} as R2Bucket;
  assert.throws(
    () => openStore({ CHUNKS: bucket, DAG_EDGE_MODE: "test" }),
    /requires DAG_EDGE_MODE=production-r2 or demo-r2/,
  );
  assert.equal(
    openStore({
      CHUNKS: bucket,
      DAG_EDGE_MODE: "test",
      DAG_EDGE_TEST_HARNESS: "workerd-local-only",
    }).backend,
    "r2",
  );
});

test("R2 and KV bindings fail closed outside their explicit deployment modes", () => {
  assert.equal(
    openStore({ CHUNKS: {} as R2Bucket, DAG_EDGE_MODE: "demo-r2" }).backend,
    "r2",
  );
  assert.throws(
    () => openStore({ CHUNKS: {} as R2Bucket, DAG_EDGE_MODE: "demo-kv" }),
    /requires DAG_EDGE_MODE=production-r2 or demo-r2/,
  );
  assert.throws(
    () => openStore({ CHUNKS_KV: {} as KVNamespace, DAG_EDGE_MODE: "production-r2" }),
    /disabled unless DAG_EDGE_MODE=demo-kv/,
  );
});

test("KV missing probes rehash non-empty objects so sync can repair corruption", async () => {
  const good = new TextEncoder().encode("expected bytes");
  const corrupt = new TextEncoder().encode("corrupt bytes");
  const cid = hex(await crypto.subtle.digest("SHA-256", good));
  let stored = corrupt;
  const kv = {
    async get(_key: string, type: string) {
      assert.equal(type, "stream");
      const copy = new Uint8Array(stored);
      return new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(copy);
          controller.close();
        },
      });
    },
    async put(_key: string, value: ArrayBuffer) {
      stored = new Uint8Array(value);
    },
  } as unknown as KVNamespace;
  const store = openStore({ CHUNKS_KV: kv, DAG_EDGE_MODE: "demo-kv" });

  assert.equal(await store.missing(cid), true);
  stored = good;
  assert.equal(await store.missing(cid), false);
});

test("a content-derived R2 ETag is changed before an expired writer is fenced", async () => {
  const bucket = new ContentEtagBucket();
  const cid = "ab".repeat(32);
  const owner = "00000000-0000-4000-8000-0000000000f1";
  const bytes = new TextEncoder().encode("late-writer");
  const marker = await ensureR2ReservationMarker(bucket, cid, bytes.byteLength, owner);
  assert.equal(marker.state, "marker");
  if (marker.state !== "marker") throw new Error("marker was not created");

  assert.equal(await cancelR2ReservationMarker(bucket, cid, marker.etag, owner), true);
  assert.notEqual(bucket.writes[1], marker.etag);
  assert.deepEqual(
    await writeR2ReservedChunk(bucket, cid, bytes.byteLength, bytes, marker.etag),
    { state: "changed", object: { state: "absent" } },
  );
});

function hex(buffer: ArrayBuffer): string {
  let out = "";
  for (const byte of new Uint8Array(buffer)) out += byte.toString(16).padStart(2, "0");
  return out;
}

function fromHex(value: string): ArrayBuffer {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return bytes.buffer;
}
