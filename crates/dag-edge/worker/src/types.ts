/**
 * Deployment bindings are generated from `wrangler.r2.jsonc` into
 * `worker-configuration.d.ts`. Secrets and the intentionally separate demo
 * configurations are represented here because Wrangler cannot infer secrets
 * and a production type generation run must not pretend a demo is production.
 */
export type EdgeEnv = Omit<
  Cloudflare.Env,
  "CHUNKS" | "DAG_EDGE_MODE" | "INGEST_RATE_LIMITER" | "PUBLIC_READ_RATE_LIMITER"
> & {
  readonly ASSETS: Fetcher;
  readonly CHUNKS?: R2Bucket;
  readonly CHUNKS_KV?: KVNamespace;
  readonly DAG_EDGE_MODE?: "production-r2" | "demo-r2" | "demo-kv" | "test";
  /** Injected only by the local Workerd/Vitest harness; never deploy. */
  readonly DAG_EDGE_TEST_HARNESS?: "workerd-local-only";
  /** Operator attestation required by `/ready` after perimeter controls exist. */
  readonly DAG_EDGE_PERIMETER_CONFIRMED?: "custom-domain-waf-account-limits-v1";
  readonly DAG_RETAINED_BYTES_LIMIT?: string;
  readonly DAG_RETAINED_OBJECTS_LIMIT?: string;
  readonly INGEST_TOKEN_CURRENT?: string;
  readonly INGEST_TOKEN_PREVIOUS?: string;
  /** Deprecated one-release scoped aliases. */
  readonly DAG_INGEST_TOKEN_CURRENT?: string;
  readonly DAG_INGEST_TOKEN_PREVIOUS?: string;
  /** Deprecated one-release compatibility alias. */
  readonly DAG_NODE_TOKEN?: string;
  readonly INGEST_RATE_LIMITER?: RateLimit;
  readonly PUBLIC_READ_RATE_LIMITER?: RateLimit;
};
