import type { EdgeEnv } from "./types.ts";

const MIN_TOKEN_BYTES = 32;
const MAX_TOKEN_BYTES = 256;

export type AuthenticatedIngest = {
  /** Stable, non-secret rate-limit key. Never include it in logs or responses. */
  principalKey: string;
  usedPrevious: boolean;
};

export type IngestAuthResult =
  | { ok: true; auth: AuthenticatedIngest }
  | { ok: false; kind: "unconfigured" | "weak_configuration" | "missing" | "invalid" };

export type IngestAuthConfiguration = {
  usable: boolean;
  productionReady: boolean;
  kind:
    | "ready"
    | "legacy_aliases"
    | "legacy_only"
    | "unconfigured"
    | "weak_configuration";
};

export function bearer(header: string | null): string | null {
  if (!header) return null;
  const match = /^Bearer[\t ]+([^\s]+)$/i.exec(header);
  return match?.[1] ?? null;
}

/** Compare fixed-size digests without data-dependent early exit. */
export async function tokenMatches(expected: string, offered: string): Promise<boolean> {
  const [a, b] = await Promise.all([digest(expected), digest(offered)]);
  return equalDigest(a, b);
}

/**
 * Authenticate the ingest scope with overlap for zero-downtime rotation.
 * DAG-prefixed names remain one-release compatibility aliases and should be
 * removed after every deployment has moved to the scoped secret names.
 */
export async function authenticateIngest(
  header: string | null,
  env: Pick<
    EdgeEnv,
    | "INGEST_TOKEN_CURRENT"
    | "INGEST_TOKEN_PREVIOUS"
    | "DAG_INGEST_TOKEN_CURRENT"
    | "DAG_INGEST_TOKEN_PREVIOUS"
    | "DAG_NODE_TOKEN"
  >,
): Promise<IngestAuthResult> {
  const current =
    env.INGEST_TOKEN_CURRENT ?? env.DAG_INGEST_TOKEN_CURRENT ?? env.DAG_NODE_TOKEN;
  if (!current) return { ok: false, kind: "unconfigured" };

  const configured = [
    current,
    env.INGEST_TOKEN_PREVIOUS,
    env.INGEST_TOKEN_CURRENT ? env.DAG_INGEST_TOKEN_CURRENT : undefined,
    env.DAG_INGEST_TOKEN_PREVIOUS,
    env.INGEST_TOKEN_CURRENT || env.DAG_INGEST_TOKEN_CURRENT ? env.DAG_NODE_TOKEN : undefined,
  ].filter((candidate): candidate is string => candidate !== undefined);
  if (
    configured.some((candidate) => !validConfiguredToken(candidate)) ||
    hasDuplicateTokens(configured)
  ) {
    return { ok: false, kind: "weak_configuration" };
  }

  const offered = bearer(header);
  if (!offered) return { ok: false, kind: "missing" };
  // Reject non-portable/header-sensitive forms before hashing. Well-formed
  // wrong tokens still take the fixed five-digest comparison path below.
  if (!validConfiguredToken(offered)) {
    return { ok: false, kind: "invalid" };
  }

  // Always perform the same five comparisons. Filler values are already
  // configured secrets and prevent the number of configured rotation slots
  // from changing the comparison shape.
  const candidates = Array.from({ length: 5 }, (_, index) => configured[index] ?? configured[0]);
  const [offeredDigest, ...candidateDigests] = await Promise.all([
    digest(offered),
    ...candidates.map(digest),
  ]);
  const matches = candidateDigests.map((candidate) => equalDigest(offeredDigest, candidate));
  let anyMatch = 0;
  for (const match of matches) anyMatch |= Number(match);
  if (anyMatch === 0) return { ok: false, kind: "invalid" };

  return {
    ok: true,
    auth: {
      principalKey: bytesToHex(offeredDigest),
      usedPrevious: !matches[0],
    },
  };
}

/** Report configuration state without exposing or hashing any credential. */
export function ingestAuthConfiguration(
  env: Pick<
    EdgeEnv,
    | "INGEST_TOKEN_CURRENT"
    | "INGEST_TOKEN_PREVIOUS"
    | "DAG_INGEST_TOKEN_CURRENT"
    | "DAG_INGEST_TOKEN_PREVIOUS"
    | "DAG_NODE_TOKEN"
  >,
): IngestAuthConfiguration {
  const configured = [
    env.INGEST_TOKEN_CURRENT,
    env.INGEST_TOKEN_PREVIOUS,
    env.DAG_INGEST_TOKEN_CURRENT,
    env.DAG_INGEST_TOKEN_PREVIOUS,
    env.DAG_NODE_TOKEN,
  ].filter((candidate): candidate is string => candidate !== undefined);
  if (
    configured.length === 0 ||
    (!env.INGEST_TOKEN_CURRENT && !env.DAG_INGEST_TOKEN_CURRENT && !env.DAG_NODE_TOKEN)
  ) {
    return { usable: false, productionReady: false, kind: "unconfigured" };
  }
  if (
    configured.some((candidate) => !validConfiguredToken(candidate)) ||
    hasDuplicateTokens(configured)
  ) {
    return { usable: false, productionReady: false, kind: "weak_configuration" };
  }
  const hasLegacyAliases = Boolean(
    env.DAG_INGEST_TOKEN_CURRENT || env.DAG_INGEST_TOKEN_PREVIOUS || env.DAG_NODE_TOKEN,
  );
  if (!env.INGEST_TOKEN_CURRENT) {
    return { usable: true, productionReady: false, kind: "legacy_only" };
  }
  if (hasLegacyAliases) {
    return { usable: true, productionReady: false, kind: "legacy_aliases" };
  }
  return { usable: true, productionReady: true, kind: "ready" };
}

function validConfiguredToken(token: string): boolean {
  return (
    token.length >= MIN_TOKEN_BYTES &&
    token.length <= MAX_TOKEN_BYTES &&
    /^[A-Za-z0-9_-]+$/.test(token)
  );
}

function hasDuplicateTokens(tokens: readonly string[]): boolean {
  return new Set(tokens).size !== tokens.length;
}

async function digest(text: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function equalDigest(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength === b.byteLength && typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(a, b);
  }
  let diff = a.byteLength ^ b.byteLength;
  for (let i = 0; i < 32; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
