import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_BODY_STREAM_CHUNKS, readBodyBounded } from "../src/body.ts";

test("bounded body reader cancels the producer immediately on overflow", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2]));
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://example.test/upload", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  const result = await readBodyBounded(request, 1);
  assert(result instanceof Response);
  assert.equal(result.status, 413);
  assert.equal(cancelled, true);
});

test("bounded body reader cancels a body rejected by Content-Length", async () => {
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://example.test/upload", {
    method: "POST",
    headers: { "content-length": "2" },
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  const result = await readBodyBounded(request, 1);
  assert(result instanceof Response);
  assert.equal(result.status, 413);
  assert.equal(cancelled, true);
});

test("bounded body reader reassembles ordinary fragmentation without retaining frames", async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2]));
      controller.enqueue(new Uint8Array());
      controller.enqueue(new Uint8Array([3, 4, 5]));
      controller.close();
    },
  });
  const request = new Request("https://example.test/upload", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  const result = await readBodyBounded(request, 5);
  assert(result instanceof Uint8Array);
  assert.deepEqual([...result], [1, 2, 3, 4, 5]);
});

test("bounded body reader cancels excessive frame fragmentation before the byte limit", async () => {
  let emitted = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array([emitted & 0xff]));
      emitted += 1;
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://example.test/upload", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  const result = await readBodyBounded(request, MAX_BODY_STREAM_CHUNKS + 1);
  assert(result instanceof Response);
  assert.equal(result.status, 413);
  assert.equal(
    (await result.json() as { error: { code: string } }).error.code,
    "body_too_fragmented",
  );
  assert.equal(emitted, MAX_BODY_STREAM_CHUNKS + 1);
  assert.equal(cancelled, true);
});
