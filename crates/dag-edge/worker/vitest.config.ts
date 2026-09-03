import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.test.jsonc" },
      // This non-secret fixture exists only in the local Miniflare process; no
      // deployable Wrangler configuration contains an ingest credential.
      miniflare: {
        bindings: {
          DAG_EDGE_TEST_HARNESS: "workerd-local-only",
          INGEST_TOKEN_CURRENT: "test-ingest-token-00000000000000000000000000000000",
        },
      },
    }),
  ],
  test: {
    include: ["test/runtime/**/*.test.ts"],
  },
});
