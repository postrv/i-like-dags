import { errorResponse } from "./http.ts";

/** Maximum stream frames accepted for one bounded request body. */
export const MAX_BODY_STREAM_CHUNKS = 4096;

export async function readBodyBounded(
  request: Request,
  limit: number,
): Promise<Uint8Array | Response> {
  const declared = request.headers.get("content-length");
  let declaredSize: number | null = null;
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) {
      return errorResponse(400, "invalid_content_length", "invalid Content-Length header");
    }
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0) {
      return errorResponse(400, "invalid_content_length", "invalid Content-Length header");
    }
    if (size > limit) {
      if (request.body) {
        try {
          await request.body.cancel("declared request body limit exceeded");
        } catch {
          // The declared limit violation is authoritative even if the
          // producer has already closed or cancellation races with it.
        }
      }
      return errorResponse(413, "body_too_large", `body exceeds ${limit} bytes`);
    }
    declaredSize = size;
  }

  if (!request.body) return new Uint8Array();

  const reader = request.body.getReader();
  let body = new Uint8Array(declaredSize ?? 0);
  let total = 0;
  let chunks = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks += 1;
      if (chunks > MAX_BODY_STREAM_CHUNKS) {
        try {
          await reader.cancel("request body stream is too fragmented");
        } catch {
          // Limit enforcement must not depend on the producer accepting cancel().
        }
        return errorResponse(
          413,
          "body_too_fragmented",
          `body exceeds ${MAX_BODY_STREAM_CHUNKS} stream chunks`,
        );
      }
      const nextTotal = total + value.byteLength;
      if (!Number.isSafeInteger(nextTotal) || nextTotal > limit) {
        try {
          await reader.cancel("request body limit exceeded");
        } catch {
          // Limit enforcement must not depend on the producer accepting cancel().
        }
        return errorResponse(413, "body_too_large", `body exceeds ${limit} bytes`);
      }
      if (body.byteLength < nextTotal) {
        let capacity = Math.max(body.byteLength, Math.min(limit, 1024));
        while (capacity < nextTotal) capacity = Math.min(limit, Math.max(nextTotal, capacity * 2));
        const grown = new Uint8Array(capacity);
        grown.set(body.subarray(0, total));
        body = grown;
      }
      body.set(value, total);
      total = nextTotal;
    }
  } catch (error) {
    try {
      await reader.cancel(error);
    } catch {
      // The original stream error is the useful one.
    }
    throw error;
  } finally {
    reader.releaseLock();
  }

  if (declaredSize !== null && total !== declaredSize) {
    return errorResponse(
      400,
      "content_length_mismatch",
      "request body does not match Content-Length",
    );
  }
  return body.byteLength === total ? body : body.slice(0, total);
}

export async function readJsonBounded(
  request: Request,
  limit: number,
): Promise<unknown | Response> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    return errorResponse(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const bytes = await readBodyBounded(request, limit);
  if (bytes instanceof Response) return bytes;
  try {
    // Preserve a leading U+FEFF so JSON.parse rejects a non-JSON BOM instead
    // of silently normalizing bytes that Rust's parser would refuse.
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch {
    return errorResponse(400, "invalid_json", "request body is not valid UTF-8 JSON");
  }
}

export function asJsonObject(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}
