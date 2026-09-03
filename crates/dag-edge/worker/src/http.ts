export const CACHE_IMMUTABLE = "public, max-age=31536000, immutable";
export const CACHE_REVALIDATE = "no-cache";
export const CACHE_PRIVATE = "no-store";

type ResponseOptions = {
  status?: number;
  cache?: string;
  cors?: boolean;
  headers?: HeadersInit;
};

export function jsonResponse(body: unknown, options: ResponseOptions = {}): Response {
  const headers = responseHeaders(options);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), {
    status: options.status ?? 200,
    headers,
  });
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  requestId?: string,
  options: Omit<ResponseOptions, "status"> = {},
): Response {
  return jsonResponse(
    {
      error: { code, message },
      ...(requestId ? { request_id: requestId } : {}),
    },
    { ...options, status, cache: CACHE_PRIVATE },
  );
}

export function emptyResponse(status = 204, options: ResponseOptions = {}): Response {
  return new Response(null, {
    status,
    headers: responseHeaders({ ...options, status }),
  });
}

export function binaryResponse(bytes: Uint8Array, options: ResponseOptions = {}): Response {
  const headers = responseHeaders(options);
  headers.set("content-type", "application/octet-stream");
  headers.set("content-length", String(bytes.byteLength));
  return new Response(bytes, { status: options.status ?? 200, headers });
}

export function responseHeaders(options: ResponseOptions = {}): Headers {
  const headers = new Headers(options.headers);
  headers.set("cache-control", options.cache ?? CACHE_PRIVATE);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  headers.set("x-frame-options", "DENY");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.set("strict-transport-security", "max-age=31536000");
  if (options.cors) {
    headers.set("access-control-allow-origin", "*");
    headers.set(
      "access-control-expose-headers",
      "Accept-Ranges, Content-Length, Content-Range, ETag, X-Request-Id",
    );
    // Public content is not personalized, so shared caches need not vary by Origin.
    headers.delete("vary");
    headers.set("cross-origin-resource-policy", "cross-origin");
  }
  return headers;
}

export function withoutBody(response: Response): Response {
  return new Response(null, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export function requestId(request: Request): string {
  const ray = request.headers.get("cf-ray");
  return ray && /^[A-Za-z0-9-]{1,128}$/.test(ray) ? ray : crypto.randomUUID();
}

export function logRequestError(request: Request, id: string, error: unknown): void {
  const url = new URL(request.url);
  console.error(
    JSON.stringify({
      level: "error",
      event: "request_failed",
      request_id: id,
      method: request.method,
      path: url.pathname,
      error_type: error instanceof Error ? error.name : "NonError",
      // Never log request headers, bodies, credential hashes, or exception text.
    }),
  );
}
