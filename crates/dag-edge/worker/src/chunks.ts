import { bytesToHex, computeCidHex, isTorn, parseCidHex } from "./cid.ts";
import { MAX_CHUNK_SIZE, MISSING_CONCURRENCY } from "./limits.ts";
import type { EdgeEnv } from "./types.ts";

export type ChunkBackend = "r2" | "kv";

export type ChunkStore = {
  backend: ChunkBackend;
  get(cidHex: string): Promise<Uint8Array | null>;
  put(cidHex: string, bytes: Uint8Array): Promise<void>;
  /** Absent or torn (size 0, not the empty digest) is missing. */
  missing(cidHex: string): Promise<boolean>;
};

export type R2BudgetObjectState =
  | { state: "absent" }
  | { state: "valid" }
  | { state: "marker"; etag: string }
  | { state: "invalid"; etag: string };

export type R2ReservedWriteResult =
  | { state: "written" }
  | { state: "changed"; object: R2BudgetObjectState };

const R2_STATE_KEY = "dagEdgeState";
const R2_OWNER_KEY = "dagEdgeOwner";
const R2_RESERVED = "reservation";
const R2_CANCELLED = "cancelled";

export type R2BudgetBucket = {
  head(key: string): Promise<{
    size: number;
    etag: string;
    checksums?: { sha256?: ArrayBuffer };
    customMetadata?: Record<string, string>;
  } | null>;
  put(
    key: string,
    value: Uint8Array,
    options?: {
      onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } | Headers;
      httpMetadata?: { contentType?: string; cacheControl?: string };
      customMetadata?: Record<string, string>;
      sha256?: string;
    },
  ): Promise<{ etag: string } | null>;
  delete(key: string): Promise<void>;
};

type R2Like = R2BudgetBucket & {
  get(key: string): Promise<{
    arrayBuffer(): Promise<ArrayBuffer>;
    size: number;
    customMetadata?: Record<string, string>;
  } | null>;
};

type KvLike = {
  get(key: string, type: "stream"): Promise<ReadableStream | null>;
  put(key: string, value: ArrayBuffer): Promise<void>;
};

class StoredChunkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoredChunkError";
  }
}

export function openStore(
  env: Pick<EdgeEnv, "CHUNKS" | "CHUNKS_KV" | "DAG_EDGE_MODE" | "DAG_EDGE_TEST_HARNESS">,
): ChunkStore {
  if (env.CHUNKS && env.CHUNKS_KV) {
    throw new Error("ambiguous chunk store bindings");
  }
  if (env.CHUNKS) {
    const localTest =
      env.DAG_EDGE_MODE === "test" && env.DAG_EDGE_TEST_HARNESS === "workerd-local-only";
    if (
      env.DAG_EDGE_MODE !== "production-r2" &&
      env.DAG_EDGE_MODE !== "demo-r2" &&
      !localTest
    ) {
      throw new Error("R2 chunk storage requires DAG_EDGE_MODE=production-r2 or demo-r2");
    }
    return r2Store(env.CHUNKS);
  }
  if (env.CHUNKS_KV && env.DAG_EDGE_MODE === "demo-kv") return kvStore(env.CHUNKS_KV);
  if (env.CHUNKS_KV) {
    throw new Error("KV chunk storage is disabled unless DAG_EDGE_MODE=demo-kv");
  }
  throw new Error("no chunk store binding (CHUNKS or CHUNKS_KV)");
}

function r2Store(bucket: R2Like): ChunkStore {
  return {
    backend: "r2",
    async get(cidHex) {
      const obj = await bucket.get(cidHex);
      if (!obj || isR2Marker(obj.customMetadata) || isTorn(obj.size, cidHex)) return null;
      if (obj.size > MAX_CHUNK_SIZE) {
        throw new StoredChunkError("stored chunk exceeds the configured chunk limit");
      }
      const bytes = new Uint8Array(await obj.arrayBuffer());
      if (bytes.byteLength !== obj.size || bytes.byteLength > MAX_CHUNK_SIZE) {
        throw new StoredChunkError("stored chunk changed while it was being read");
      }
      return bytes;
    },
    async put(cidHex, bytes) {
      await bucket.put(cidHex, bytes, {
        httpMetadata: {
          contentType: "application/octet-stream",
          cacheControl: "public, max-age=31536000, immutable",
        },
        customMetadata: { dagCid: cidHex },
        sha256: cidHex,
      });
    },
    async missing(cidHex) {
      const head = await bucket.head(cidHex);
      if (!head) return true;
      if (isR2Marker(head.customMetadata)) return true;
      if (isTorn(head.size, cidHex) || head.size > MAX_CHUNK_SIZE) return true;
      const checksum = head.checksums?.sha256;
      if (checksum) return bytesToHex(new Uint8Array(checksum)) !== cidHex;
      // Hardened writes always carry a provider-verified SHA-256. A legacy
      // object with only self-asserted metadata is missing until sync rewrites
      // it; size and custom metadata are not an integrity proof.
      return true;
    },
  };
}

/**
 * Inspect only provider-authenticated metadata. Self-asserted custom metadata
 * identifies fencing markers but never proves that an object is valid data.
 */
export async function inspectR2BudgetObject(
  bucket: R2BudgetBucket,
  cidHex: string,
  expectedSize: number,
): Promise<R2BudgetObjectState> {
  const head = await bucket.head(cidHex);
  if (!head) return { state: "absent" };
  if (isR2Marker(head.customMetadata)) return { state: "marker", etag: head.etag };
  const checksum = head.checksums?.sha256;
  if (
    head.size === expectedSize &&
    checksum &&
    bytesToHex(new Uint8Array(checksum)) === cidHex
  ) {
    return { state: "valid" };
  }
  return { state: "invalid", etag: head.etag };
}

/**
 * Create or adopt a zero-byte reservation marker. The final object is written
 * only if this exact ETag still exists, which lets recovery fence stale puts.
 */
export async function ensureR2ReservationMarker(
  bucket: R2BudgetBucket,
  cidHex: string,
  expectedSize: number,
  owner: string,
): Promise<R2BudgetObjectState> {
  const r2 = bucket;
  for (let attempt = 0; attempt < 3; attempt++) {
    const observed = await inspectR2BudgetObject(bucket, cidHex, expectedSize);
    if (observed.state !== "absent") return observed;
    try {
      const marker = await r2.put(cidHex, new Uint8Array(), {
        onlyIf: new Headers({ "if-none-match": "*" }),
        httpMetadata: { contentType: "application/octet-stream", cacheControl: "no-store" },
        customMetadata: { [R2_STATE_KEY]: R2_RESERVED, [R2_OWNER_KEY]: owner },
      });
      if (marker) return { state: "marker", etag: marker.etag };
    } catch (error) {
      const afterError = await inspectR2BudgetObject(bucket, cidHex, expectedSize);
      if (afterError.state !== "absent") return afterError;
      throw error;
    }
  }
  return inspectR2BudgetObject(bucket, cidHex, expectedSize);
}

/** Atomically replace one reservation marker with verified immutable bytes. */
export async function writeR2ReservedChunk(
  bucket: R2BudgetBucket,
  cidHex: string,
  expectedSize: number,
  bytes: Uint8Array,
  markerEtag: string,
): Promise<R2ReservedWriteResult> {
  const r2 = bucket;
  try {
    const written = await r2.put(cidHex, bytes, {
      onlyIf: { etagMatches: markerEtag },
      httpMetadata: {
        contentType: "application/octet-stream",
        cacheControl: "public, max-age=31536000, immutable",
      },
      customMetadata: { dagCid: cidHex },
      sha256: cidHex,
    });
    if (written) return { state: "written" };
  } catch (error) {
    const afterError = await inspectR2BudgetObject(bucket, cidHex, expectedSize);
    if (afterError.state === "valid") return { state: "written" };
    if (afterError.state !== "marker" || afterError.etag !== markerEtag) {
      return { state: "changed", object: afterError };
    }
    throw error;
  }
  return {
    state: "changed",
    object: await inspectR2BudgetObject(bucket, cidHex, expectedSize),
  };
}

/**
 * Replace a stale marker conditionally before deletion. Any writer holding the
 * old marker ETag is permanently fenced before the key becomes absent again.
 */
export async function cancelR2ReservationMarker(
  bucket: R2BudgetBucket,
  cidHex: string,
  markerEtag: string,
  owner: string,
): Promise<boolean> {
  const r2 = bucket;
  const fence = new Uint8Array(32);
  crypto.getRandomValues(fence);
  let cancelled: { etag: string } | null;
  try {
    cancelled = await r2.put(cidHex, fence, {
      onlyIf: { etagMatches: markerEtag },
      httpMetadata: { contentType: "application/octet-stream", cacheControl: "no-store" },
      customMetadata: { [R2_STATE_KEY]: R2_CANCELLED, [R2_OWNER_KEY]: owner },
    });
  } catch {
    return false;
  }
  // Ordinary single-part R2 ETags are content-derived. A second empty marker
  // would retain the stale writer's ETag and would not fence it at all.
  if (!cancelled || cancelled.etag === markerEtag) return false;
  const current = await r2.head(cidHex);
  if (
    !current ||
    current.etag !== cancelled.etag ||
    current.customMetadata?.[R2_STATE_KEY] !== R2_CANCELLED ||
    current.customMetadata?.[R2_OWNER_KEY] !== owner
  ) {
    return false;
  }
  await r2.delete(cidHex);
  return true;
}

function isR2Marker(metadata: Record<string, string> | undefined): boolean {
  const state = metadata?.[R2_STATE_KEY];
  return state === R2_RESERVED || state === R2_CANCELLED;
}

function kvStore(kv: KvLike): ChunkStore {
  return {
    backend: "kv",
    async get(cidHex) {
      const stream = await kv.get(cidHex, "stream");
      if (!stream) return null;
      const bytes = await readStoreStream(stream, MAX_CHUNK_SIZE);
      if (isTorn(bytes.byteLength, cidHex)) return null;
      return bytes;
    },
    async put(cidHex, bytes) {
      const copy = new Uint8Array(bytes.byteLength);
      copy.set(bytes);
      await kv.put(cidHex, copy.buffer);
    },
    async missing(cidHex) {
      const stream = await kv.get(cidHex, "stream");
      if (!stream) return true;
      try {
        const bytes = await readStoreStream(stream, MAX_CHUNK_SIZE);
        if (isTorn(bytes.byteLength, cidHex)) return true;
        // KV has no provider-authenticated checksum metadata. Recompute the
        // digest here so a non-empty corrupt legacy/demo object is offered for
        // repair instead of being reported present forever. Final reads still
        // pass through `getVerified`; this closes the repair loop as well.
        return (await computeCidHex(bytes)) !== cidHex;
      } catch (error) {
        if (error instanceof StoredChunkError) return true;
        throw error;
      }
    },
  };
}

export async function putVerified(
  store: ChunkStore,
  cidHex: string,
  bytes: Uint8Array,
): Promise<{ error: string; status: number } | null> {
  if (bytes.byteLength > MAX_CHUNK_SIZE) {
    return { status: 413, error: `chunk exceeds ${MAX_CHUNK_SIZE} bytes` };
  }
  let expected: string;
  try {
    expected = parseCidHex(cidHex);
  } catch (e) {
    return { status: 400, error: String(e).replace(/^Error: /, "") };
  }
  const computed = await computeCidHex(bytes);
  if (computed !== expected) {
    return {
      status: 502,
      error: "stored chunk failed CID verification",
    };
  }
  await store.put(expected, bytes);
  return null;
}

export async function getVerified(
  store: ChunkStore,
  cidHex: string,
): Promise<Uint8Array | { error: string; status: number }> {
  let expected: string;
  try {
    expected = parseCidHex(cidHex);
  } catch (e) {
    return { status: 400, error: String(e).replace(/^Error: /, "") };
  }
  let bytes: Uint8Array | null;
  try {
    bytes = await store.get(expected);
  } catch (error) {
    if (error instanceof StoredChunkError) {
      return { status: 502, error: "stored chunk is invalid" };
    }
    throw error;
  }
  if (!bytes) return { status: 404, error: "chunk not found" };
  const computed = await computeCidHex(bytes);
  if (computed !== expected) {
    return {
      status: 502,
      error: "stored chunk failed CID verification",
    };
  }
  return bytes;
}

/** HEAD/get in bounded parallel batches. No retries. */
export async function missingBatch(
  store: ChunkStore,
  cidHexes: string[],
): Promise<string[]> {
  const missing: string[] = [];
  const unique = [...new Set(cidHexes)];
  for (let i = 0; i < unique.length; i += MISSING_CONCURRENCY) {
    const slice = unique.slice(i, i + MISSING_CONCURRENCY);
    const flags = await Promise.all(slice.map((cid) => store.missing(cid)));
    for (let j = 0; j < slice.length; j++) {
      if (flags[j]) missing.push(slice[j]);
    }
  }
  return missing;
}

async function readStoreStream(stream: ReadableStream, limit: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        try {
          await reader.cancel("stored chunk limit exceeded");
        } catch {
          // The size violation is authoritative even if cancellation races.
        }
        throw new StoredChunkError("stored chunk exceeds the configured chunk limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
