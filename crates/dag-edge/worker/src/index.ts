import {
  authenticateIngest,
  ingestAuthConfiguration,
  type AuthenticatedIngest,
} from "./auth.ts";
import { asJsonObject, readBodyBounded, readJsonBounded } from "./body.ts";
import { retainedBudgetConfiguration } from "./budget.ts";
import {
  CatalogObject,
  type CatalogKind,
  type CatalogStart,
  type PublicationGroup,
  type TerminalSessionRefusal,
} from "./catalog.ts";
import {
  cancelR2ReservationMarker,
  ensureR2ReservationMarker,
  getVerified,
  inspectR2BudgetObject,
  missingBatch,
  openStore,
  writeR2ReservedChunk,
} from "./chunks.ts";
import { CborLimitError } from "./cbor.ts";
import { computeCidHex, parseCidHex } from "./cid.ts";
import {
  ReferenceClosureError,
  validatePublicationClosure,
  type PublicationValidationHead,
} from "./closure.ts";
import {
  decodePinEvent,
  decodePinEventEntry,
  decodePointerEvent,
  decodePointerEventEntry,
  encodeEntry,
  encodePointerEvent,
} from "./dag.ts";
import {
  CACHE_IMMUTABLE,
  CACHE_PRIVATE,
  binaryResponse,
  emptyResponse,
  errorResponse,
  jsonResponse,
  logRequestError,
  requestId,
  responseHeaders,
  withoutBody,
} from "./http.ts";
import { checkPinId, checkPointerId } from "./ids.ts";
import { inspectBytes } from "./inspect.ts";
import {
  CHUNK_BODY_LIMIT,
  DEMO_MAX_PUBLICATION_GROUPS,
  DEMO_MISSING_BATCH,
  DO_CONCURRENCY,
  JSON_BODY_LIMIT,
  MAX_CATALOG_NAMES,
  MAX_CHUNK_SIZE,
  MAX_EVENTS_PER_LOG,
  MAX_STAGED_EVENTS,
  MISSING_BATCH,
  OPERATION_LEASE_SECONDS,
} from "./limits.ts";
import { PinObject, type PinHeadView, type PinOfferContext } from "./pin.ts";
import { PointerObject, type PointerHeadView, type PointerOfferContext } from "./pointer.ts";
import { formatOfferError, offerPinEvent, offerPointerEvent, type PinEventView, type PointerEventView } from "./offer.ts";
import type { EdgeEnv } from "./types.ts";
import { consolePage } from "./ui.ts";

export { CatalogObject, PinObject, PointerObject };

const VERIFIER_ASSETS = new Map<string, { sourcePath: string; contentType: string }>([
  ["/assets/dag_wasm.js", { sourcePath: "/dag_wasm.js", contentType: "text/javascript; charset=utf-8" }],
  ["/assets/dag_wasm_bg.wasm", { sourcePath: "/dag_wasm_bg.wasm", contentType: "application/wasm" }],
]);
const REQUIRED_PERIMETER_ATTESTATION = "custom-domain-waf-account-limits-v1";

function isDemoMode(env: Pick<EdgeEnv, "DAG_EDGE_MODE">): boolean {
  return env.DAG_EDGE_MODE === "demo-kv" || env.DAG_EDGE_MODE === "demo-r2";
}

export default {
  async fetch(request: Request, env: EdgeEnv): Promise<Response> {
    const id = requestId(request);
    try {
      const response = await handle(request, env);
      const headers = new Headers(response.headers);
      headers.set("x-request-id", id);
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    } catch (error) {
      logRequestError(request, id, error);
      return errorResponse(500, "internal_error", "internal server error", id);
    }
  },
} satisfies ExportedHandler<EdgeEnv>;

async function handle(request: Request, env: EdgeEnv): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // Browsers treat loopback as a trustworthy local-development context and
  // Wrangler serves it over HTTP. Non-loopback traffic remains fail-closed.
  if (url.protocol !== "https:" && !isLoopbackHost(url.hostname)) {
    if (request.method === "GET" || request.method === "HEAD") {
      url.protocol = "https:";
      return new Response(null, {
        status: 308,
        headers: responseHeaders({ headers: { location: url.toString() } }),
      });
    }
    return errorResponse(400, "https_required", "authenticated requests require HTTPS");
  }

  if (VERIFIER_ASSETS.has(path)) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return methodNotAllowed("GET, HEAD");
    }
    return verifierAsset(request, env, path);
  }
  if (path.startsWith("/assets/")) return errorResponse(404, "not_found", "asset not found");

  if (request.method === "OPTIONS" && isPublicDataPath(path)) return corsPreflight();

  if (
    (request.method === "GET" || request.method === "HEAD") &&
    isPublicReadPath(path) &&
    path !== "/health"
  ) {
    const limited = await enforcePublicReadLimit(request, env, publicReadClass(path));
    if (limited) return limited;
  }

  if ((request.method === "GET" || request.method === "HEAD") && (path === "/" || path === "/ui")) {
    const response = htmlConsole();
    return request.method === "HEAD" ? withoutBody(response) : response;
  }
  if ((request.method === "GET" || request.method === "HEAD") && path === "/health") {
    const response = jsonResponse(
      { ok: true, status: "live" },
      { cors: true, cache: CACHE_PRIVATE },
    );
    return request.method === "HEAD" ? withoutBody(response) : response;
  }
  if ((request.method === "GET" || request.method === "HEAD") && path === "/ready") {
    const response = await readiness(env);
    return request.method === "HEAD" ? withoutBody(response) : response;
  }

  if ((request.method === "GET" || request.method === "HEAD") && path.startsWith("/c/")) {
    return getChunk(env, path.slice(3), request);
  }
  if ((request.method === "GET" || request.method === "HEAD") && path.startsWith("/i/")) {
    return inspectChunk(env, path.slice(3), request);
  }
  if (request.method === "PUT" && path.startsWith("/c/")) {
    const authorized = await requireIngest(request, env, "chunk-write");
    if (authorized instanceof Response) return authorized;
    return putChunk(env, path.slice(3), request);
  }

  if ((request.method === "GET" || request.method === "HEAD") && path.startsWith("/p/")) {
    const decoded = decodePath(path.slice(3), "pointer id");
    if (decoded instanceof Response) return decoded;
    const response = await resolvePointer(env, decoded);
    return request.method === "HEAD" ? withoutBody(response) : response;
  }

  if (path === "/sync/missing" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "missing");
    if (authorized instanceof Response) return authorized;
    return missing(env, request);
  }
  if (path === "/sync/flush" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "flush");
    if (authorized instanceof Response) return authorized;
    // A completed R2/KV put is the ADR-007 durability barrier. KV remains
    // explicitly demo-only because its cross-location reads are eventual.
    return emptyResponse(204, {
      headers: env.DAG_EDGE_MODE === "demo-kv" ? { warning: '299 dag-edge "KV demo is eventually consistent"' } : undefined,
    });
  }
  if (path === "/sync/import/pointer" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "pointer-import");
    if (authorized instanceof Response) return authorized;
    const session = requireSyncSession(request);
    if (session instanceof Response) return session;
    return importPointer(env, request, session);
  }
  if (path === "/sync/import/pin" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "pin-import");
    if (authorized instanceof Response) return authorized;
    const session = requireSyncSession(request);
    if (session instanceof Response) return session;
    return importPin(env, request, session);
  }
  if (path === "/sync/finalize" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "finalize");
    if (authorized instanceof Response) return authorized;
    const session = requireSyncSession(request);
    if (session instanceof Response) return session;
    return finalize(env, request, session);
  }
  if (path === "/sync/abort" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "abort");
    if (authorized instanceof Response) return authorized;
    const session = requireSyncSession(request);
    if (session instanceof Response) return session;
    return abortSync(env, request, session);
  }
  if ((path === "/sync/probe/pointer" || path === "/sync/probe/pin") && request.method === "POST") {
    const authorized = await requireIngest(request, env, "probe");
    if (authorized instanceof Response) return authorized;
    return probeEvents(env, request, path.endsWith("pointer") ? "pointer" : "pin");
  }
  if ((request.method === "GET" || request.method === "HEAD") && path === "/sync/status") {
    const authorized = await requireIngest(request, env, "status");
    if (authorized instanceof Response) return authorized;
    const response = await syncStatus(env);
    return request.method === "HEAD" ? withoutBody(response) : response;
  }
  if (path === "/pointers" && request.method === "POST") {
    const authorized = await requireIngest(request, env, "pointer-cas");
    if (authorized instanceof Response) return authorized;
    return casPointer(env, request);
  }

  if (knownPath(path)) return methodNotAllowed(allowedMethods(path));
  return errorResponse(404, "not_found", "not found");
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

async function verifierAsset(request: Request, env: EdgeEnv, path: string): Promise<Response> {
  const asset = VERIFIER_ASSETS.get(path);
  if (!asset) return errorResponse(404, "not_found", "asset not found");
  const sourceUrl = new URL(request.url);
  sourceUrl.pathname = asset.sourcePath;
  sourceUrl.search = "";
  const upstream = await env.ASSETS.fetch(new Request(sourceUrl, { method: "GET" }));
  if (!upstream.ok) {
    return errorResponse(503, "verifier_asset_unavailable", "verifier asset unavailable");
  }
  const headers = responseHeaders({ cache: CACHE_IMMUTABLE });
  headers.set("content-type", asset.contentType);
  const etag = upstream.headers.get("etag");
  if (etag) headers.set("etag", etag);
  const length = upstream.headers.get("content-length");
  if (length) headers.set("content-length", length);
  const response = new Response(request.method === "HEAD" ? null : upstream.body, {
    status: 200,
    headers,
  });
  return response;
}

function isPublicDataPath(path: string): boolean {
  return (
    path.startsWith("/c/") ||
    path.startsWith("/i/") ||
    path.startsWith("/p/") ||
    path === "/health" ||
    path === "/ready"
  );
}

function isPublicReadPath(path: string): boolean {
  return isPublicDataPath(path) || path === "/" || path === "/ui";
}

function publicReadClass(path: string): string {
  if (path.startsWith("/c/")) return "chunk";
  if (path.startsWith("/i/")) return "inspect";
  if (path.startsWith("/p/")) return "pointer";
  if (path === "/ready") return "readiness";
  return "site";
}

async function readiness(env: EdgeEnv): Promise<Response> {
  let backend: "r2" | "kv" | "unavailable" = "unavailable";
  try {
    backend = openStore(env).backend;
  } catch {
    // Readiness reports configuration state without exposing exception text.
  }
  const auth = ingestAuthConfiguration(env);
  const quotasConfigured = Boolean(env.INGEST_RATE_LIMITER && env.PUBLIC_READ_RATE_LIMITER);
  const perimeterConfirmed = env.DAG_EDGE_PERIMETER_CONFIRMED === REQUIRED_PERIMETER_ATTESTATION;
  const budget = retainedBudgetConfiguration(env);
  let budgetUsage: Awaited<ReturnType<CatalogObject["budgetStatus"]>> | null = null;
  let catalogAvailable = false;
  try {
    budgetUsage = await env.CATALOG.getByName("catalog").budgetStatus();
    catalogAvailable = true;
  } catch {
    // Report only the boolean health signal; never expose binding error text.
  }
  const ready =
    backend === "r2" &&
    env.DAG_EDGE_MODE === "production-r2" &&
    auth.productionReady &&
    quotasConfigured &&
    perimeterConfirmed &&
    budget.ok &&
    catalogAvailable &&
    budgetUsage?.legacyHeadsPending === 0 &&
    budgetUsage?.unvalidatedPublicationPending === false;
  return jsonResponse(
    {
      ok: ready,
      status: ready ? "ready" : "not_ready",
      store: backend,
      mode: env.DAG_EDGE_MODE ?? "unconfigured",
      production_ready: ready,
      ingest_auth: auth.kind,
      quotas_configured: quotasConfigured,
      perimeter_confirmed: perimeterConfirmed,
      catalog_available: catalogAvailable,
      legacy_heads_pending: budgetUsage?.legacyHeadsPending ?? null,
      unvalidated_publication_pending:
        budgetUsage?.unvalidatedPublicationPending ?? null,
      retained_budget: budget.ok
        ? {
            configured: true,
            bytes_limit: budget.bytes,
            objects_limit: budget.objects,
            retained_bytes: budgetUsage?.retainedBytes ?? 0,
            retained_objects: budgetUsage?.retainedObjects ?? 0,
            pending_reservations: budgetUsage?.reservations ?? 0,
          }
        : { configured: false, reason: budget.reason },
      limits: {
        max_chunk_size: MAX_CHUNK_SIZE,
        missing_batch: isDemoMode(env) ? DEMO_MISSING_BATCH : MISSING_BATCH,
        max_events_per_log: MAX_EVENTS_PER_LOG,
        max_catalog_names: MAX_CATALOG_NAMES,
      },
    },
    { status: ready ? 200 : 503, cors: true, cache: CACHE_PRIVATE },
  );
}

async function requireIngest(
  request: Request,
  env: EdgeEnv,
  operation: string,
): Promise<AuthenticatedIngest | Response> {
  const result = await authenticateIngest(request.headers.get("authorization"), env);
  if (!result.ok) {
    if (result.kind === "unconfigured" || result.kind === "weak_configuration") {
      console.error(
        JSON.stringify({
          level: "error",
          event: "ingest_auth_configuration_invalid",
          reason: result.kind,
        }),
      );
      return errorResponse(503, "ingest_auth_unavailable", "ingest authentication is unavailable");
    }
    const response = errorResponse(401, "unauthorized", "valid ingest credentials are required");
    response.headers.set("www-authenticate", 'Bearer realm="dag-edge", error="invalid_token"');
    return response;
  }

  if (env.DAG_EDGE_MODE === "production-r2") {
    const configurationError = productionIngestConfigurationError(env);
    if (configurationError) {
      console.error(
        JSON.stringify({
          level: "error",
          event: "production_ingest_configuration_invalid",
          reason: configurationError,
        }),
      );
      return errorResponse(
        503,
        "production_ingest_not_ready",
        "production ingest configuration is not ready",
      );
    }
  }

  if (env.INGEST_RATE_LIMITER) {
    const outcome = await env.INGEST_RATE_LIMITER.limit({
      key: `${result.auth.principalKey}:${operation}`,
    });
    if (!outcome.success) return rateLimited("ingest quota exceeded");
  } else if (env.DAG_EDGE_MODE === "production-r2" || env.DAG_EDGE_MODE === "demo-r2") {
    return errorResponse(503, "ingest_quota_unavailable", "ingest quota enforcement is unavailable");
  }
  return result.auth;
}

function productionIngestConfigurationError(env: EdgeEnv): string | null {
  if (!ingestAuthConfiguration(env).productionReady) return "ingest_auth";
  if (
    !env.INGEST_RATE_LIMITER ||
    !env.PUBLIC_READ_RATE_LIMITER ||
    !env.POINTERS ||
    !env.PINS ||
    !env.CATALOG
  ) {
    return "bindings";
  }
  if (env.DAG_EDGE_PERIMETER_CONFIRMED !== REQUIRED_PERIMETER_ATTESTATION) {
    return "perimeter";
  }
  if (!retainedBudgetConfiguration(env).ok) return "retained_budget";
  try {
    if (openStore(env).backend !== "r2") return "storage";
  } catch {
    return "storage";
  }
  return null;
}

async function enforcePublicReadLimit(
  request: Request,
  env: EdgeEnv,
  resource: string,
): Promise<Response | null> {
  if (!env.PUBLIC_READ_RATE_LIMITER) {
    // Readiness must be able to report that the binding is missing. Once the
    // binding exists it is rate-limited like every other non-liveness read.
    if (resource === "readiness") return null;
    return env.DAG_EDGE_MODE === "production-r2" || env.DAG_EDGE_MODE === "demo-r2"
      ? errorResponse(503, "public_quota_unavailable", "public quota enforcement is unavailable", undefined, {
          cors: true,
        })
      : null;
  }
  const offeredClient = request.headers.get("cf-connecting-ip");
  const client =
    offeredClient && /^[0-9a-f:.]{1,64}$/i.test(offeredClient)
      ? offeredClient.toLowerCase()
      : "unattributed";
  const outcome = await env.PUBLIC_READ_RATE_LIMITER.limit({ key: `${client}:${resource}` });
  return outcome.success ? null : rateLimited("public read quota exceeded", true);
}

function rateLimited(message: string, cors = false): Response {
  const response = errorResponse(429, "rate_limited", message, undefined, { cors });
  response.headers.set("retry-after", "60");
  return response;
}

async function inspectChunk(env: EdgeEnv, cidPath: string, request: Request): Promise<Response> {
  const result = await getVerified(openStore(env), cidPath);
  if (!(result instanceof Uint8Array)) {
    return errorResponse(result.status, "chunk_unavailable", result.error, undefined, { cors: true });
  }
  const cid = parseCidHex(cidPath);
  const etag = `"${cid}.inspect-v1"`;
  if (matchesEtag(request, etag)) return notModified(etag, true);
  let inspected: ReturnType<typeof inspectBytes>;
  try {
    inspected = inspectBytes(cid, result);
  } catch (error) {
    if (error instanceof CborLimitError) {
      return errorResponse(
        422,
        "inspection_limit_exceeded",
        "stored chunk exceeds safe structural inspection limits",
        undefined,
        { cors: true },
      );
    }
    throw error;
  }
  const response = jsonResponse(inspected, {
    cache: CACHE_IMMUTABLE,
    cors: true,
    headers: { etag },
  });
  return request.method === "HEAD" ? withoutBody(response) : response;
}

async function getChunk(env: EdgeEnv, cidPath: string, request: Request): Promise<Response> {
  const result = await getVerified(openStore(env), cidPath);
  if (!(result instanceof Uint8Array)) {
    return errorResponse(result.status, "chunk_unavailable", result.error, undefined, { cors: true });
  }
  const cid = parseCidHex(cidPath);
  const etag = `"${cid}"`;
  if (matchesEtag(request, etag)) return notModified(etag, true);

  const range = request.method === "GET" ? parseRange(request.headers.get("range"), result.byteLength) : null;
  if (range === "invalid") {
    return errorResponse(416, "range_not_satisfiable", "requested byte range is not satisfiable", undefined, {
      cors: true,
      headers: { "content-range": `bytes */${result.byteLength}` },
    });
  }
  const bytes = range ? result.subarray(range.start, range.end + 1) : result;
  const response = binaryResponse(bytes, {
    status: range ? 206 : 200,
    cache: CACHE_IMMUTABLE,
    cors: true,
    headers: {
      etag,
      "accept-ranges": "bytes",
      ...(range ? { "content-range": `bytes ${range.start}-${range.end}/${result.byteLength}` } : {}),
    },
  });
  return request.method === "HEAD" ? withoutBody(response) : response;
}

async function putChunk(env: EdgeEnv, cidPath: string, request: Request): Promise<Response> {
  try {
    parseCidHex(cidPath);
  } catch {
    return errorResponse(400, "invalid_cid", "CID must be 64 hexadecimal characters");
  }
  const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/octet-stream") {
    return errorResponse(415, "unsupported_media_type", "Content-Type must be application/octet-stream");
  }
  const bytes = await readBodyBounded(request, CHUNK_BODY_LIMIT);
  if (bytes instanceof Response) return bytes;
  const error = await putBudgeted(env, cidPath, bytes);
  if (error) {
    const response = errorResponse(error.status, error.code, error.error);
    if (error.retryAfterSeconds) response.headers.set("retry-after", String(error.retryAfterSeconds));
    return response;
  }
  return emptyResponse();
}

type BudgetedPutError = {
  status: number;
  code: string;
  error: string;
  retryAfterSeconds?: number;
};

async function putBudgeted(
  env: EdgeEnv,
  cidHex: string,
  bytes: Uint8Array,
): Promise<BudgetedPutError | null> {
  if (bytes.byteLength > MAX_CHUNK_SIZE) {
    return { status: 413, code: "chunk_too_large", error: `chunk exceeds ${MAX_CHUNK_SIZE} bytes` };
  }
  let expected: string;
  try {
    expected = parseCidHex(cidHex);
  } catch {
    return { status: 400, code: "invalid_cid", error: "CID must be 64 hexadecimal characters" };
  }
  if ((await computeCidHex(bytes)) !== expected) {
    return { status: 400, code: "cid_mismatch", error: "chunk bytes do not match the requested CID" };
  }
  const budget = retainedBudgetConfiguration(env);
  if (!budget.ok) {
    return {
      status: 503,
      code: "retained_budget_unavailable",
      error: "retained-storage quota enforcement is unavailable",
    };
  }
  const owner = crypto.randomUUID();
  const catalog = env.CATALOG.getByName("catalog");
  const lease = await catalog.reserveChunk(
    owner,
    expected,
    bytes.byteLength,
    nowSeconds(),
    budget.bytes,
    budget.objects,
  );
  if (lease.state === "busy") {
    return {
      status: 409,
      code: "chunk_busy",
      error: "another upload of this chunk is in progress",
      retryAfterSeconds: lease.retryAfterSeconds,
    };
  }
  if (lease.state === "quota") {
    return {
      status: 507,
      code: `retained_${lease.resource}_quota_exceeded`,
      error: "retained-storage quota is exhausted",
    };
  }
  const store = openStore(env);
  if (lease.state === "existing") {
    // The ledger is already charged. Rewriting identical verified bytes also
    // repairs an out-of-band deletion or corrupt legacy object safely.
    await store.put(expected, bytes);
    return null;
  }
  if (store.backend !== "r2" || !env.CHUNKS) {
    // KV is intentionally demo-only and has no conditional object writes.
    // Its interrupted reservations remain charged rather than being released
    // under an eventually-consistent absence observation.
    await store.put(expected, bytes);
    await catalog.commitChunk(owner, expected);
    return null;
  }

  try {
    for (let attempt = 0; attempt < 4; attempt++) {
      const prepared = await ensureR2ReservationMarker(
        env.CHUNKS,
        expected,
        bytes.byteLength,
        owner,
      );
      if (prepared.state === "valid") {
        await catalog.commitChunk(owner, expected);
        return null;
      }
      if (prepared.state === "invalid") {
        const fenced = await cancelR2ReservationMarker(
          env.CHUNKS,
          expected,
          prepared.etag,
          owner,
        );
        if (!fenced) continue;
        continue;
      }
      if (prepared.state === "absent") continue;

      // Confirm ledger ownership after marker creation. A late placeholder
      // from an expired writer can never be promoted after reconciliation.
      const renewed = await catalog.renewChunk(owner, expected, nowSeconds());
      if (!renewed.renewed) {
        await cancelR2ReservationMarker(env.CHUNKS, expected, prepared.etag, owner);
        return {
          status: 409,
          code: "chunk_busy",
          error: "the upload reservation changed during storage",
          retryAfterSeconds: 1,
        };
      }
      const written = await writeR2ReservedChunk(
        env.CHUNKS,
        expected,
        bytes.byteLength,
        bytes,
        prepared.etag,
      );
      if (written.state === "written" || written.object.state === "valid") {
        await catalog.commitChunk(owner, expected);
        return null;
      }
    }
  } catch {
    // R2 PUT failures can be ambiguous. Strong HEAD consistency is the only
    // basis for committing; otherwise leave the charged row for the alarm.
    try {
      const observed = await inspectR2BudgetObject(env.CHUNKS, expected, bytes.byteLength);
      if (observed.state === "valid") {
        await catalog.commitChunk(owner, expected);
        return null;
      }
    } catch {
      // The durable reservation remains the conservative source of truth.
    }
  }
  return {
    status: 503,
    code: "chunk_store_unavailable",
    error: "chunk storage could not be durably reconciled; retry this CID",
    retryAfterSeconds: OPERATION_LEASE_SECONDS,
  };
}

async function missing(env: EdgeEnv, request: Request): Promise<Response> {
  const parsed = await readJsonBounded(request, JSON_BODY_LIMIT);
  if (parsed instanceof Response) return parsed;
  const body = asJsonObject(parsed);
  if (!body || !Array.isArray(body.cids)) {
    return errorResponse(400, "invalid_request", "cids must be an array");
  }
  if (body.cids.length > MISSING_BATCH) {
    return errorResponse(400, "batch_too_large", `missing batch exceeds ${MISSING_BATCH}`);
  }
  const asked: string[] = [];
  const seen = new Set<string>();
  for (const hex of body.cids) {
    if (typeof hex !== "string") return errorResponse(400, "invalid_cid", "each cid must be hex");
    let cid: string;
    try {
      cid = parseCidHex(hex);
    } catch {
      return errorResponse(400, "invalid_cid", "each CID must be 64 hexadecimal characters");
    }
    if (!seen.has(cid)) {
      seen.add(cid);
      asked.push(cid);
    }
  }
  const storeBatchLimit = isDemoMode(env) ? DEMO_MISSING_BATCH : MISSING_BATCH;
  if (asked.length > storeBatchLimit) {
    return errorResponse(
      400,
      "batch_too_large",
      `unique missing batch exceeds ${storeBatchLimit} in ${env.DAG_EDGE_MODE ?? "unconfigured"} mode`,
    );
  }
  const missingCids = await missingBatch(openStore(env), asked);
  return jsonResponse({ missing: missingCids });
}

async function importPointer(env: EdgeEnv, request: Request, sessionId: string): Promise<Response> {
  const offer = await readOffer(request);
  if (offer instanceof Response) return offer;
  const idError = checkPointerId(offer.id);
  if (idError) return errorResponse(400, "invalid_pointer_id", idError);

  const got = await getVerified(openStore(env), offer.cid);
  if (!(got instanceof Uint8Array)) {
    return errorResponse(got.status, "event_unavailable", got.error);
  }

  let event;
  try {
    event = decodePointerEvent(decodePointerEventEntry(got));
  } catch {
    return errorResponse(400, "invalid_pointer_event", "chunk is not a valid pointer event entry");
  }
  const stub = env.POINTERS.getByName(`pointer:${offer.id}`);
  const observed = await stub.offerContext(offer.seq);
  const catalog = env.CATALOG.getByName("catalog");
  const legacyPending = await catalog.legacyHeadPending("pointer", offer.id);
  let provenLegacyHead: PointerHeadView | null = null;
  if (legacyPending) {
    const invalidLegacyHead = await validatePointerHeadIntegrity(
      env,
      offer.id,
      observed.head,
      nowSeconds(),
    );
    if (invalidLegacyHead) return invalidLegacyHead;
    provenLegacyHead = observed.head;
  }
  const invalidPredecessor = await validatePointerPredecessor(
    env,
    offer.id,
    offer.seq,
    observed,
  );
  if (invalidPredecessor) return invalidPredecessor;
  const refusedByCanonical = preflightPointerOffer(
    offer.id,
    offer.seq,
    offer.cid,
    event,
    observed,
  );
  if (refusedByCanonical) return refusedByCanonical;
  const prepared = await prepareSession(env, sessionId);
  if (prepared) return prepared;
  const canonical = await stub.offerContext(offer.seq);
  if (!samePointerContext(observed, canonical)) {
    await catalog.releaseEmptySession(sessionId);
    return syncContextChanged();
  }
  const result = await catalog.stagePointer(
    sessionId,
    offer.id,
    offer.seq,
    offer.cid,
    event,
    canonical,
    provenLegacyHead,
    nowSeconds(),
  );
  if (!result.ok) {
    await catalog.releaseEmptySession(sessionId);
  }
  return result.ok
    ? jsonResponse({ filed: result.filed })
    : errorResponse(result.status, result.kind, result.error);
}

async function importPin(env: EdgeEnv, request: Request, sessionId: string): Promise<Response> {
  const offer = await readOffer(request);
  if (offer instanceof Response) return offer;
  const idError = checkPinId(offer.id);
  if (idError) return errorResponse(400, "invalid_pin_id", idError);

  const got = await getVerified(openStore(env), offer.cid);
  if (!(got instanceof Uint8Array)) {
    return errorResponse(got.status, "event_unavailable", got.error);
  }

  let event;
  try {
    event = decodePinEvent(decodePinEventEntry(got));
  } catch {
    return errorResponse(400, "invalid_pin_event", "chunk is not a valid pin event entry");
  }
  const stub = env.PINS.getByName(`pin:${offer.id}`);
  const observed = await stub.offerContext(offer.seq);
  const catalog = env.CATALOG.getByName("catalog");
  const legacyPending = await catalog.legacyHeadPending("pin", offer.id);
  let provenLegacyHead: PinHeadView | null = null;
  if (legacyPending) {
    const invalidLegacyHead = await validateLegacyPinHead(
      env,
      offer.id,
      observed.head,
      nowSeconds(),
    );
    if (invalidLegacyHead) return invalidLegacyHead;
    provenLegacyHead = observed.head;
  }
  const invalidPredecessor = await validatePinPredecessor(
    env,
    offer.id,
    offer.seq,
    observed,
  );
  if (invalidPredecessor) return invalidPredecessor;
  const refusedByCanonical = preflightPinOffer(
    offer.id,
    offer.seq,
    offer.cid,
    { seq: event.seq, pinId: event.pinId, prev: event.prev },
    observed,
  );
  if (refusedByCanonical) return refusedByCanonical;
  const prepared = await prepareSession(env, sessionId);
  if (prepared) return prepared;
  const canonical = await stub.offerContext(offer.seq);
  if (!samePinContext(observed, canonical)) {
    await catalog.releaseEmptySession(sessionId);
    return syncContextChanged();
  }
  const result = await catalog.stagePin(
    sessionId,
    offer.id,
    offer.seq,
    offer.cid,
    { seq: event.seq, pinId: event.pinId, prev: event.prev },
    canonical,
    provenLegacyHead,
    nowSeconds(),
  );
  if (!result.ok) {
    await catalog.releaseEmptySession(sessionId);
  }
  return result.ok
    ? jsonResponse({ filed: result.filed })
    : errorResponse(result.status, result.kind, result.error);
}

async function validatePointerPredecessor(
  env: EdgeEnv,
  id: string,
  seq: number,
  canonical: PointerOfferContext,
): Promise<Response | null> {
  if (seq <= 1) return null;
  if (canonical.predecessorEventCid === null) {
    return canonical.predecessorNewCid === null ? null : invalidCanonicalPredecessor();
  }
  if (canonical.predecessorNewCid === null) return invalidCanonicalPredecessor();
  const got = await getVerified(openStore(env), canonical.predecessorEventCid);
  if (!(got instanceof Uint8Array)) return unavailableCanonicalPredecessor(got.error);
  try {
    const event = decodePointerEvent(decodePointerEventEntry(got));
    if (
      event.pointerId !== id ||
      event.seq !== seq - 1 ||
      event.new !== canonical.predecessorNewCid
    ) {
      return invalidCanonicalPredecessor();
    }
  } catch {
    return invalidCanonicalPredecessor();
  }
  return null;
}

async function validatePointerHeadIntegrity(
  env: EdgeEnv,
  id: string,
  head: PointerHeadView,
  validationTime: number,
): Promise<Response | null> {
  if (head.seq === 0 && head.cid === null && head.eventCid === null) return null;
  if (head.seq < 1 || head.cid === null || head.eventCid === null) {
    return invalidLegacyHead("pointer");
  }
  const got = await getVerified(openStore(env), head.eventCid);
  if (!(got instanceof Uint8Array)) return unavailableLegacyHead("pointer", got.error);
  try {
    const event = decodePointerEvent(decodePointerEventEntry(got));
    if (event.pointerId !== id || event.seq !== head.seq || event.new !== head.cid) {
      return invalidLegacyHead("pointer");
    }
  } catch {
    return invalidLegacyHead("pointer");
  }
  return validateLiveHeads(
    env,
    [{ kind: "pointer", name: id, cid: head.cid }],
    validationTime,
  );
}

async function validateLegacyPinHead(
  env: EdgeEnv,
  id: string,
  head: PinHeadView,
  validationTime: number,
): Promise<Response | null> {
  if (head.seq === 0 && head.eventCid === null) return null;
  if (head.seq < 1 || head.eventCid === null) return invalidLegacyHead("pin");
  const got = await getVerified(openStore(env), head.eventCid);
  if (!(got instanceof Uint8Array)) return unavailableLegacyHead("pin", got.error);
  try {
    const event = decodePinEvent(decodePinEventEntry(got));
    if (event.pinId !== id || event.seq !== head.seq) return invalidLegacyHead("pin");
  } catch {
    return invalidLegacyHead("pin");
  }
  return validateLiveHeads(
    env,
    [{ kind: "pin", name: id, eventCid: head.eventCid }],
    validationTime,
  );
}

async function validatePinPredecessor(
  env: EdgeEnv,
  id: string,
  seq: number,
  canonical: PinOfferContext,
): Promise<Response | null> {
  if (seq <= 1 || canonical.predecessorEventCid === null) return null;
  const got = await getVerified(openStore(env), canonical.predecessorEventCid);
  if (!(got instanceof Uint8Array)) return unavailableCanonicalPredecessor(got.error);
  try {
    const event = decodePinEvent(decodePinEventEntry(got));
    if (event.pinId !== id || event.seq !== seq - 1) {
      return invalidCanonicalPredecessor();
    }
  } catch {
    return invalidCanonicalPredecessor();
  }
  return null;
}

function preflightPointerOffer(
  id: string,
  seq: number,
  eventCid: string,
  event: PointerEventView,
  canonical: PointerOfferContext,
): Response | null {
  const predecessor =
    canonical.predecessorNewCid === null
      ? null
      : { seq: seq - 1, pointerId: id, prev: null, new: canonical.predecessorNewCid };
  const judged = offerPointerEvent(
    id,
    seq,
    eventCid,
    event,
    canonical.existingEventCid,
    predecessor,
  );
  if (!("err" in judged) || judged.err.kind === "missing_predecessor") return null;
  return errorResponse(409, judged.err.kind, formatOfferError(judged.err));
}

function preflightPinOffer(
  id: string,
  seq: number,
  eventCid: string,
  event: PinEventView,
  canonical: PinOfferContext,
): Response | null {
  const judged = offerPinEvent(
    id,
    seq,
    eventCid,
    event,
    canonical.existingEventCid,
    canonical.predecessorEventCid,
  );
  if (!("err" in judged) || judged.err.kind === "missing_predecessor") return null;
  return errorResponse(409, judged.err.kind, formatOfferError(judged.err));
}

function unavailableCanonicalPredecessor(detail: string): Response {
  return errorResponse(
    502,
    "canonical_predecessor_unavailable",
    `canonical predecessor content is unavailable: ${detail}`,
  );
}

function invalidCanonicalPredecessor(): Response {
  return errorResponse(
    502,
    "canonical_predecessor_invalid",
    "canonical predecessor metadata does not match its verified event",
  );
}

function unavailableLegacyHead(kind: "pointer" | "pin", detail: string): Response {
  return errorResponse(
    502,
    "legacy_head_unavailable",
    `legacy ${kind} head content is unavailable: ${detail}`,
  );
}

function invalidLegacyHead(kind: "pointer" | "pin"): Response {
  return errorResponse(
    502,
    "legacy_head_invalid",
    `legacy ${kind} head metadata does not match its verified event`,
  );
}

function samePointerContext(left: PointerOfferContext, right: PointerOfferContext): boolean {
  return (
    left.storedIdentity === right.storedIdentity &&
    left.existingEventCid === right.existingEventCid &&
    left.predecessorEventCid === right.predecessorEventCid &&
    left.predecessorNewCid === right.predecessorNewCid &&
    left.head.seq === right.head.seq &&
    left.head.cid === right.head.cid &&
    left.head.eventCid === right.head.eventCid
  );
}

function samePointerHeadView(left: PointerHeadView, right: PointerHeadView): boolean {
  return left.seq === right.seq && left.cid === right.cid && left.eventCid === right.eventCid;
}

function samePinContext(left: PinOfferContext, right: PinOfferContext): boolean {
  return (
    left.storedIdentity === right.storedIdentity &&
    left.existingEventCid === right.existingEventCid &&
    left.predecessorEventCid === right.predecessorEventCid &&
    left.head.seq === right.head.seq &&
    left.head.eventCid === right.head.eventCid
  );
}

function syncContextChanged(): Response {
  const response = errorResponse(
    409,
    "sync_context_changed",
    "canonical event context changed while replication coordination was acquired; retry",
  );
  response.headers.set("retry-after", "1");
  return response;
}

function syncRevisionChanged(): Response {
  const response = errorResponse(
    409,
    "sync_revision_changed",
    "replication session changed during closure validation; retry finalize",
  );
  response.headers.set("retry-after", "1");
  return response;
}

async function finalize(env: EdgeEnv, request: Request, sessionId: string): Promise<Response> {
  const body = await readBodyBounded(request, 0);
  if (body instanceof Response) return body;
  const finished = await finishStagedPublication(env, sessionId);
  if (finished instanceof Response) return finished;
  return finalizeResponse(finished);
}

async function finishStagedPublication(
  env: EdgeEnv,
  recoveryOwner: string,
  recoverExistingPublication = false,
): Promise<{ pointers: number; pins: number } | Response> {
  const catalog = env.CATALOG.getByName("catalog");
  // Exactly one closure validation may run in an invocation. A revision race
  // or recovered CAS ends this request so retry starts with a fresh platform
  // subrequest budget.
  const start = recoverExistingPublication
    ? await catalog.beginPublicationRecovery(nowSeconds())
    : await catalog.beginFinalize(recoveryOwner, nowSeconds());
  if (start.state === "complete") {
    return { pointers: start.pointers, pins: start.pins };
  }
  if (start.state === "terminal") return terminalSessionResponse(start);
  if (start.state === "unknown") {
    return errorResponse(
      409,
      "sync_session_unknown",
      "replication session was never started or its bounded receipt was evicted",
    );
  }
  if (start.state === "busy") return syncBusy(start.retryAfterSeconds);
  if (start.state === "recover_cas") {
    const recovered = await recoverCas(env, start.owner, start.name);
    if (recovered) return recovered;
    // CAS recovery may itself consume the complete closure-read allowance.
    // Publication resumes only in a fresh invocation with a fresh platform
    // subrequest budget.
    return retryAfterRecovery();
  }
  if (start.state === "validate") {
    const groupLimit = isDemoMode(env) ? DEMO_MAX_PUBLICATION_GROUPS : MAX_STAGED_EVENTS;
    if (start.heads.length > groupLimit) {
      const code = "reference_group_limit";
      const message = `replication publication exceeds ${groupLimit} final pointer/pin groups in this mode`;
      const cleanup = await catalog.clearFailedValidation(
        start.sessionId,
        start.revision,
        nowSeconds(),
        409,
        code,
        message,
      );
      if (!cleanup.cleared) return syncRevisionChanged();
      return errorResponse(409, code, message);
    }
    const invalid = await validateLiveHeads(env, start.heads, nowSeconds());
    if (invalid) {
      const failure = await errorResponseDetails(invalid);
      const cleanup = await catalog.clearFailedValidation(
        start.sessionId,
        start.revision,
        nowSeconds(),
        invalid.status,
        failure.code,
        failure.message,
      );
      if (!cleanup.cleared) return syncRevisionChanged();
      return invalid;
    }
    const frozen = await catalog.freezePublication(
      start.sessionId,
      start.revision,
      nowSeconds(),
    );
    if (frozen.state === "busy") return syncBusy(frozen.retryAfterSeconds);
    if (frozen.state === "missing") {
      return errorResponse(
        409,
        "sync_session_missing",
        "replication session changed during validation",
      );
    }
    if (frozen.state === "changed") {
      return syncRevisionChanged();
    }
  }
  return publishStaged(env);
}

async function validateLiveHeads(
  env: EdgeEnv,
  heads: PublicationValidationHead[],
  validationTime: number,
): Promise<Response | null> {
  try {
    await validatePublicationClosure(openStore(env), heads, validationTime);
    return null;
  } catch (error) {
    if (error instanceof ReferenceClosureError) {
      return errorResponse(error.status, error.code, error.message);
    }
    throw error;
  }
}

async function errorResponseDetails(response: Response): Promise<{ code: string; message: string }> {
  const body = await response.clone().json<unknown>();
  if (
    !body ||
    typeof body !== "object" ||
    !("error" in body) ||
    !body.error ||
    typeof body.error !== "object" ||
    !("code" in body.error) ||
    typeof body.error.code !== "string" ||
    !("message" in body.error) ||
    typeof body.error.message !== "string"
  ) {
    throw new Error("internal validation response is not a structured error");
  }
  return { code: body.error.code, message: body.error.message };
}

function finalizeResponse(counts: { pointers: number; pins: number }): Response {
  return jsonResponse({
    pointers: counts.pointers,
    pins: counts.pins,
    signatures: 0,
    claims: 0,
  });
}

async function abortSync(env: EdgeEnv, request: Request, sessionId: string): Promise<Response> {
  const body = await readBodyBounded(request, 0);
  if (body instanceof Response) return body;
  const result = await env.CATALOG.getByName("catalog").abortSession(
    sessionId,
    nowSeconds(),
  );
  if (result.state === "busy") return syncBusy(result.retryAfterSeconds);
  if (result.state === "terminal") return terminalSessionResponse(result);
  if (result.state === "publishing") {
    const published = await finishStagedPublication(env, sessionId);
    if (published instanceof Response) return published;
    return jsonResponse({ aborted: false, published: true });
  }
  return jsonResponse({ aborted: result.state === "aborted" });
}

async function resolvePointer(env: EdgeEnv, id: string): Promise<Response> {
  const idError = checkPointerId(id);
  if (idError) return errorResponse(400, "invalid_pointer_id", idError, undefined, { cors: true });

  const catalog = env.CATALOG.getByName("catalog");
  let state = await catalog.pointerState(id);
  if (state.state === "absent") {
    return errorResponse(404, "pointer_not_found", "pointer not found", undefined, { cors: true });
  }
  if (state.state === "blocked") {
    return errorResponse(503, "pointer_unavailable", "pointer is temporarily unavailable", undefined, {
      cors: true,
    });
  }
  // Only confirmed legacy membership may instantiate a child during lazy
  // migration. Arbitrary public names stop at the Catalog lookup above.
  if (state.state === "bootstrap") {
    const owner = crypto.randomUUID();
    const prepared = await prepareProbe(env, owner);
    if (prepared) return prepared;
    try {
      state = await catalog.pointerState(id);
      if (state.state === "bootstrap") {
        const child = env.POINTERS.getByName(`pointer:${id}`);
        const observed = await child.head();
        const invalid = await validatePointerHeadIntegrity(env, id, observed, nowSeconds());
        if (invalid) return invalid;
        const rechecked = await child.head();
        if (!samePointerHeadView(observed, rechecked)) return syncContextChanged();
        state = await catalog.cacheLegacyPointerForProbe(owner, id, rechecked);
      }
    } finally {
      await catalog.finishProbe(owner);
    }
    if (state.state === "absent") {
      return errorResponse(404, "pointer_not_found", "pointer not found", undefined, { cors: true });
    }
    if (state.state === "bootstrap" || state.state === "blocked") {
      return errorResponse(503, "pointer_unavailable", "pointer is temporarily unavailable", undefined, { cors: true });
    }
  }
  return jsonResponse(
    { id, seq: state.seq, cid: state.cid },
    { cors: true, cache: CACHE_PRIVATE },
  );
}

async function casPointer(env: EdgeEnv, request: Request): Promise<Response> {
  const parsed = await readJsonBounded(request, JSON_BODY_LIMIT);
  if (parsed instanceof Response) return parsed;
  const body = asJsonObject(parsed);
  if (
    !body ||
    typeof body.id !== "string" ||
    typeof body.cid !== "string" ||
    !Number.isSafeInteger(body.expect_seq) ||
    (body.expect_seq as number) < 0 ||
    (body.expect_seq as number) >= MAX_EVENTS_PER_LOG
  ) {
    return errorResponse(400, "invalid_request", "id, cid, and a valid expect_seq are required");
  }
  const id = body.id;
  const expectSeq = body.expect_seq as number;
  const idError = checkPointerId(id);
  if (idError) return errorResponse(400, "invalid_pointer_id", idError);
  let newCid: string;
  try {
    newCid = parseCidHex(body.cid);
  } catch {
    return errorResponse(400, "invalid_cid", "cid must be 64 hexadecimal characters");
  }

  const owner = crypto.randomUUID();
  const prepared = await prepareCas(env, owner, id);
  if (prepared) return prepared;
  const catalog = env.CATALOG.getByName("catalog");

  // CAS exposes this head immediately, so its complete closure must be proved
  // after acquiring the Catalog lease but before either the child log or a
  // public Catalog head is written. Imported historical targets may have been
  // collected; only their final live head is checked at finalize. Content-
  // addressed writes are immutable and there is no valid chunk delete
  // endpoint, closing the proof-to-publication window.
  const invalidTarget = await validateLiveHeads(
    env,
    [{ kind: "pointer", name: id, cid: newCid }],
    nowSeconds(),
  );
  if (invalidTarget) {
    await catalog.cancelCas(owner);
    return invalidTarget;
  }

  let committed = await catalog.pointerStateForCas(owner, id);
  const stub = env.POINTERS.getByName(`pointer:${id}`);
  if (committed.state === "bootstrap") {
    const observed = await stub.head();
    const invalidLegacyHead = await validatePointerHeadIntegrity(
      env,
      id,
      observed,
      nowSeconds(),
    );
    if (invalidLegacyHead) {
      await catalog.cancelCas(owner);
      return invalidLegacyHead;
    }
    const rechecked = await stub.head();
    if (!samePointerHeadView(observed, rechecked)) {
      await catalog.cancelCas(owner);
      return syncContextChanged();
    }
    committed = await catalog.cacheLegacyPointerForCas(owner, id, rechecked);
  }
  if (committed.state === "blocked") {
    await catalog.cancelCas(owner);
    return errorResponse(503, "pointer_unavailable", "pointer is temporarily unavailable");
  }
  const committedHead =
    committed.state === "ready"
      ? { seq: committed.seq, cid: committed.cid }
      : { seq: 0, cid: null };
  if (committedHead.seq !== expectSeq) {
    await catalog.cancelCas(owner);
    return casMismatch(id, expectSeq, committedHead);
  }

  const childHead = await stub.head();
  if (childHead.seq !== committedHead.seq || childHead.cid !== committedHead.cid) {
    if (childHead.seq > committedHead.seq) {
      const recovered = await publishVerifiedRecoveredCas(env, owner, id, childHead);
      if (recovered instanceof Response) return recovered;
      return casMismatch(id, expectSeq, recovered.head);
    } else {
      await catalog.cancelCas(owner);
    }
    return errorResponse(503, "pointer_unavailable", "pointer is temporarily unavailable");
  }
  if (childHead.seq > 0) {
    const invalidCurrentHead = await validatePointerHeadIntegrity(
      env,
      id,
      childHead,
      nowSeconds(),
    );
    if (invalidCurrentHead) {
      await catalog.cancelCas(owner);
      return invalidCurrentHead;
    }
    if (!samePointerHeadView(childHead, await stub.head())) {
      await catalog.cancelCas(owner);
      return syncContextChanged();
    }
  }

  const seq = expectSeq + 1;
  const event = {
    seq,
    pointerId: id,
    prev: expectSeq === 0 ? null : committedHead.cid,
    new: newCid,
    ts: Math.floor(Date.now() / 1000),
  };
  if (event.prev === null && expectSeq !== 0) {
    await catalog.cancelCas(owner);
    return errorResponse(503, "pointer_unavailable", "pointer is temporarily unavailable");
  }

  const entryBytes = encodeEntry(encodePointerEvent(event));
  const eventCid = await computeCidHex(entryBytes);
  const putError = await putBudgeted(env, eventCid, entryBytes);
  if (putError) {
    await catalog.cancelCas(owner);
    return errorResponse(putError.status, putError.code, putError.error);
  }
  const renewed = await catalog.renewCas(owner, id, nowSeconds());
  if (!renewed.renewed) {
    return syncBusy(1);
  }

  const imported = await stub.importEvent(id, seq, eventCid, {
    seq: event.seq,
    pointerId: event.pointerId,
    prev: event.prev,
    new: event.new,
  });
  if (!imported.ok) {
    const actual = await stub.head();
    const recovered = await publishVerifiedRecoveredCas(env, owner, id, actual);
    if (recovered instanceof Response) return recovered;
    if (imported.kind === "divergent") return casMismatch(id, expectSeq, recovered.head);
    return errorResponse(imported.status, imported.kind ?? "offer_refused", imported.error);
  }
  await catalog.publishCas(owner, id, expectSeq, seq, newCid);
  return jsonResponse({ seq, event_cid: eventCid });
}

function casMismatch(id: string, expected: number, head: { seq: number; cid: string | null }): Response {
  return errorResponse(
    412,
    "cas_mismatch",
    `pointer ${id} is at seq ${head.seq} (cid ${head.cid ?? "none"}), not ${expected}; re-read and retry`,
  );
}

async function prepareSession(env: EdgeEnv, sessionId: string): Promise<Response | null> {
  const catalog = env.CATALOG.getByName("catalog");
  for (let attempts = 0; attempts < 4; attempts++) {
    const start = await catalog.beginSession(sessionId, nowSeconds());
    const handled = await handleCatalogStart(env, start, sessionId);
    if (handled === null && start.state === "ready") return null;
    if (handled instanceof Response) return handled;
  }
  return errorResponse(503, "sync_unavailable", "replication coordination is temporarily unavailable");
}

async function prepareCas(env: EdgeEnv, owner: string, name: string): Promise<Response | null> {
  const catalog = env.CATALOG.getByName("catalog");
  const start = await catalog.beginCas(owner, name, nowSeconds());
  if (start.state === "ready") return null;
  if (start.state === "catalog_full") {
    return errorResponse(
      507,
      "catalog_full",
      `catalog is full (${start.limit} names)`,
    );
  }
  if (start.state === "busy") return syncBusy(start.retryAfterSeconds);
  if (start.state === "publishing") {
    const response = errorResponse(
      409,
      "sync_publication_pending",
      "replication publication must finish before pointer CAS; retry after finalize",
    );
    response.headers.set("retry-after", "1");
    return response;
  }
  const recovered = await recoverCas(env, start.owner, start.name);
  return recovered ?? retryAfterRecovery();
}

async function prepareProbe(env: EdgeEnv, owner: string): Promise<Response | null> {
  const catalog = env.CATALOG.getByName("catalog");
  for (let attempts = 0; attempts < 4; attempts++) {
    const start = await catalog.beginProbe(owner, nowSeconds());
    const handled = await handleCatalogStart(env, start, owner);
    if (handled === null && start.state === "ready") return null;
    if (handled instanceof Response) return handled;
  }
  return errorResponse(503, "sync_unavailable", "probe coordination is temporarily unavailable");
}

async function handleCatalogStart(
  env: EdgeEnv,
  start: CatalogStart,
  recoveryOwner: string,
): Promise<Response | "retry" | null> {
  if (start.state === "ready") return null;
  if (start.state === "busy") return syncBusy(start.retryAfterSeconds);
  if (start.state === "terminal") return terminalSessionResponse(start);
  if (start.state === "recover_cas") {
    const recovered = await recoverCas(env, start.owner, start.name);
    return recovered ?? retryAfterRecovery();
  }
  const published = await finishStagedPublication(env, recoveryOwner, true);
  return published instanceof Response ? published : retryAfterRecovery();
}

async function recoverCas(env: EdgeEnv, owner: string, name: string): Promise<Response | null> {
  const recovered = await publishVerifiedRecoveredCas(env, owner, name);
  return recovered instanceof Response ? recovered : null;
}

/**
 * A child head is only derived metadata until its immutable event object and
 * live target closure have been hash-verified. Every CAS recovery route uses
 * this helper so none can expose a child-ahead row by trusting SQLite alone.
 */
async function publishVerifiedRecoveredCas(
  env: EdgeEnv,
  owner: string,
  name: string,
  observedHead?: PointerHeadView,
): Promise<{ head: PointerHeadView; published: boolean } | Response> {
  const catalog = env.CATALOG.getByName("catalog");
  const child = env.POINTERS.getByName(`pointer:${name}`);
  const head = observedHead ?? await child.head();
  const invalid = await validatePointerHeadIntegrity(env, name, head, nowSeconds());
  if (invalid) {
    await catalog.cancelCas(owner);
    return invalid;
  }
  if (!samePointerHeadView(head, await child.head())) {
    await catalog.cancelCas(owner);
    return syncContextChanged();
  }
  const result = await catalog.publishRecoveredCas(owner, name, head);
  if (result.ok) return { head, published: result.published };
  await catalog.cancelCas(owner);
  console.error(JSON.stringify({ level: "error", event: "cas_recovery_inconsistent" }));
  return errorResponse(503, "pointer_unavailable", "pointer is temporarily unavailable");
}

async function publishStaged(env: EdgeEnv): Promise<{ pointers: number; pins: number } | Response> {
  const catalog = env.CATALOG.getByName("catalog");
  const plan = await catalog.publicationPlan();
  if (plan.state === "idle") {
    return errorResponse(409, "sync_session_missing", "no publication is in progress");
  }
  if (plan.state === "unvalidated") {
    return errorResponse(
      503,
      "sync_validation_required",
      "replication publication has no durable validation witness",
    );
  }
  for (let offset = 0; offset < plan.groups.length; offset += DO_CONCURRENCY) {
    const wave = plan.groups.slice(offset, offset + DO_CONCURRENCY);
    const settled = await Promise.allSettled(wave.map((group) => publishGroup(env, group)));
    const accepted: Array<{ kind: CatalogKind; name: string }> = [];
    let failed = false;
    for (let i = 0; i < settled.length; i++) {
      const outcome = settled[i];
      if (outcome.status === "fulfilled" && outcome.value.ok) {
        accepted.push({ kind: wave[i].kind, name: wave[i].name });
      } else {
        failed = true;
      }
    }
    if (accepted.length > 0) await catalog.markPublishedBatch(plan.sessionId, accepted);
    if (failed) {
      console.error(JSON.stringify({ level: "error", event: "sync_publication_group_failed" }));
      return errorResponse(503, "sync_publication_incomplete", "replication publication is incomplete; retry finalize");
    }
  }
  const complete = await catalog.completePublication(nowSeconds());
  if (complete.state !== "complete") {
    return errorResponse(503, "sync_publication_incomplete", "replication publication is incomplete; retry finalize");
  }
  return { pointers: complete.pointers, pins: complete.pins };
}

async function publishGroup(
  env: EdgeEnv,
  group: PublicationGroup,
): Promise<{ ok: boolean }> {
  if (group.kind === "pointer") {
    return env.POINTERS.getByName(`pointer:${group.name}`).publishBatch(group.name, group.events);
  }
  return env.PINS.getByName(`pin:${group.name}`).publishBatch(group.name, group.events);
}

function syncBusy(retryAfterSeconds: number): Response {
  const response = errorResponse(409, "sync_busy", "another coordinated operation is in progress");
  response.headers.set("retry-after", String(Math.max(1, Math.ceil(retryAfterSeconds))));
  return response;
}

function terminalSessionResponse(refusal: TerminalSessionRefusal): Response {
  return errorResponse(refusal.status, refusal.code, refusal.message);
}

function retryAfterRecovery(): Response {
  const response = errorResponse(
    409,
    "coordination_recovered",
    "a prior operation was recovered; retry in a fresh request",
  );
  response.headers.set("retry-after", "1");
  return response;
}

function requireSyncSession(request: Request): string | Response {
  const session = request.headers.get("x-dag-sync-session");
  if (
    !session ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(session)
  ) {
    return errorResponse(400, "invalid_sync_session", "X-Dag-Sync-Session must be a UUIDv4");
  }
  return session.toLowerCase();
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

type ProbeOffer = { id: string; seq: number; cid: string };

async function probeEvents(env: EdgeEnv, request: Request, kind: CatalogKind): Promise<Response> {
  const parsed = await readJsonBounded(request, JSON_BODY_LIMIT);
  if (parsed instanceof Response) return parsed;
  const body = asJsonObject(parsed);
  if (!body || !Array.isArray(body.events) || body.events.length > MAX_STAGED_EVENTS) {
    return errorResponse(400, "invalid_probe", `events must be an array of at most ${MAX_STAGED_EVENTS} offers`);
  }
  const offers: ProbeOffer[] = [];
  const positions = new Map<string, string>();
  for (const value of body.events) {
    const item = asJsonObject(value);
    if (
      !item ||
      typeof item.id !== "string" ||
      !Number.isSafeInteger(item.seq) ||
      (item.seq as number) < 1 ||
      (item.seq as number) > MAX_EVENTS_PER_LOG ||
      typeof item.cid !== "string"
    ) {
      return errorResponse(400, "invalid_probe", "each probe offer requires id, seq, and cid");
    }
    const idProblem = kind === "pointer" ? checkPointerId(item.id) : checkPinId(item.id);
    if (idProblem) return errorResponse(400, `invalid_${kind}_id`, idProblem);
    let cid: string;
    try {
      cid = parseCidHex(item.cid);
    } catch {
      return errorResponse(400, "invalid_cid", "probe CIDs must be 64 hexadecimal characters");
    }
    const key = `${item.id}\0${String(item.seq)}`;
    const prior = positions.get(key);
    if (prior !== undefined) {
      if (prior !== cid) {
        return errorResponse(400, "divergent_probe", "one probe position contains different offered CIDs");
      }
      continue;
    }
    positions.set(key, cid);
    offers.push({ id: item.id, seq: item.seq as number, cid });
  }

  const names = [...new Set(offers.map((offer) => offer.id))];
  if (isDemoMode(env) && names.length > DEMO_MAX_PUBLICATION_GROUPS) {
    return errorResponse(
      400,
      "probe_name_limit",
      `demo probe exceeds ${DEMO_MAX_PUBLICATION_GROUPS} distinct names`,
    );
  }

  const owner = crypto.randomUUID();
  const catalog = env.CATALOG.getByName("catalog");
  const prepared = await prepareProbe(env, owner);
  if (prepared) return prepared;
  try {
    const known = new Set(await catalog.knownNames(kind, names));
    const groups = new Map<string, ProbeOffer[]>();
    for (const offer of offers) {
      if (!known.has(offer.id)) continue;
      const group = groups.get(offer.id) ?? [];
      group.push(offer);
      groups.set(offer.id, group);
    }
    const entries = [...groups.entries()];
    const conflicts: Array<{ id: string; seq: number; offered: string; existing: string }> = [];
    let leaseRenewedAt = nowSeconds();
    for (let offset = 0; offset < entries.length; offset += DO_CONCURRENCY) {
      if (nowSeconds() - leaseRenewedAt >= 30) {
        const renewed = await catalog.renewProbe(owner, nowSeconds());
        if (!renewed.renewed) return syncBusy(1);
        leaseRenewedAt = nowSeconds();
      }
      const wave = entries.slice(offset, offset + DO_CONCURRENCY);
      const rows = await Promise.all(
        wave.map(async ([id, group]) => {
          const sequences = group.map((offer) => offer.seq);
          const existing =
            kind === "pointer"
              ? await env.POINTERS.getByName(`pointer:${id}`).eventCids(sequences)
              : await env.PINS.getByName(`pin:${id}`).eventCids(sequences);
          return { id, group, existing: new Map(existing.map((row) => [row.seq, row.eventCid])) };
        }),
      );
      for (const row of rows) {
        for (const offer of row.group) {
          const existing = row.existing.get(offer.seq);
          if (existing && existing !== offer.cid) {
            conflicts.push({ id: row.id, seq: offer.seq, offered: offer.cid, existing });
          }
        }
      }
      if (nowSeconds() - leaseRenewedAt >= 30) {
        const stillOwned = await catalog.renewProbe(owner, nowSeconds());
        if (!stillOwned.renewed) return syncBusy(1);
        leaseRenewedAt = nowSeconds();
      }
    }
    return jsonResponse({ conflicts });
  } finally {
    await catalog.finishProbe(owner);
  }
}

async function syncStatus(env: EdgeEnv): Promise<Response> {
  const status = await env.CATALOG.getByName("catalog").operationStatus(nowSeconds());
  return jsonResponse({
    phase: status.phase,
    staged_events: status.stagedEvents,
    unpublished_names: status.unpublishedNames,
    pointers: status.pointers,
    pins: status.pins,
  });
}

async function readOffer(
  request: Request,
): Promise<{ id: string; seq: number; cid: string } | Response> {
  const parsed = await readJsonBounded(request, JSON_BODY_LIMIT);
  if (parsed instanceof Response) return parsed;
  const body = asJsonObject(parsed);
  if (
    !body ||
    typeof body.id !== "string" ||
    !Number.isSafeInteger(body.seq) ||
    (body.seq as number) < 1 ||
    (body.seq as number) > MAX_EVENTS_PER_LOG ||
    typeof body.cid !== "string"
  ) {
    return errorResponse(400, "invalid_offer", "id, seq, and cid are required");
  }
  try {
    return { id: body.id, seq: body.seq as number, cid: parseCidHex(body.cid) };
  } catch {
    return errorResponse(400, "invalid_cid", "cid must be 64 hexadecimal characters");
  }
}

function htmlConsole(): Response {
  const random = new Uint8Array(18);
  crypto.getRandomValues(random);
  const nonce = btoa(String.fromCharCode(...random))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  const headers = responseHeaders({ cache: CACHE_PRIVATE });
  headers.set("content-type", "text/html; charset=utf-8");
  headers.set(
    "content-security-policy",
    [
      "default-src 'none'",
      `script-src 'self' 'nonce-${nonce}' 'wasm-unsafe-eval'`,
      `style-src-elem 'self' 'nonce-${nonce}'`,
      "style-src-attr 'unsafe-inline'",
      "connect-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "worker-src 'none'",
      "manifest-src 'none'",
    ].join("; "),
  );
  return new Response(consolePage(nonce), { status: 200, headers });
}

function corsPreflight(): Response {
  return emptyResponse(204, {
    cors: true,
    headers: {
      "access-control-allow-methods": "GET, HEAD, OPTIONS",
      "access-control-allow-headers": "If-None-Match, Range",
      "access-control-max-age": "600",
    },
  });
}

function notModified(etag: string, cors: boolean): Response {
  return emptyResponse(304, {
    cache: CACHE_IMMUTABLE,
    cors,
    headers: { etag },
  });
}

function matchesEtag(request: Request, etag: string): boolean {
  const offered = request.headers.get("if-none-match");
  if (!offered) return false;
  return offered.split(",").some((candidate) => {
    const normalized = candidate.trim().replace(/^W\//, "");
    return normalized === "*" || normalized === etag;
  });
}

function parseRange(
  header: string | null,
  size: number,
): { start: number; end: number } | "invalid" | null {
  if (!header) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match || (match[1] === "" && match[2] === "")) return "invalid";
  let start: number;
  let end: number;
  if (match[1] === "") {
    const suffix = Number(match[2]);
    if (!Number.isSafeInteger(suffix) || suffix <= 0 || size === 0) return "invalid";
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] === "" ? size - 1 : Number(match[2]);
    if (
      !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(end) ||
      start < 0 ||
      start >= size ||
      end < start
    ) {
      return "invalid";
    }
    end = Math.min(end, size - 1);
  }
  return { start, end };
}

function decodePath(encoded: string, field: string): string | Response {
  try {
    return decodeURIComponent(encoded);
  } catch {
    return errorResponse(400, "invalid_path_encoding", `${field} is not valid percent-encoded UTF-8`, undefined, {
      cors: true,
    });
  }
}

function methodNotAllowed(allow: string): Response {
  return errorResponse(405, "method_not_allowed", "method not allowed", undefined, {
    headers: { allow },
  });
}

function knownPath(path: string): boolean {
  return (
    path === "/" ||
    path === "/ui" ||
    path === "/health" ||
    path === "/ready" ||
    path === "/sync/missing" ||
    path === "/sync/flush" ||
    path === "/sync/import/pointer" ||
    path === "/sync/import/pin" ||
    path === "/sync/finalize" ||
    path === "/sync/abort" ||
    path === "/sync/probe/pointer" ||
    path === "/sync/probe/pin" ||
    path === "/sync/status" ||
    path === "/pointers" ||
    path.startsWith("/c/") ||
    path.startsWith("/i/") ||
    path.startsWith("/p/")
  );
}

function allowedMethods(path: string): string {
  if (path.startsWith("/c/")) return "GET, HEAD, PUT, OPTIONS";
  if (
    path.startsWith("/i/") ||
    path.startsWith("/p/") ||
    path === "/health" ||
    path === "/ready"
  ) {
    return "GET, HEAD, OPTIONS";
  }
  if (path === "/" || path === "/ui") return "GET, HEAD";
  if (path === "/sync/status") return "GET, HEAD";
  return "POST";
}
