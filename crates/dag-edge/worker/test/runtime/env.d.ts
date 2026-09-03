import type { EdgeEnv } from "../../src/types.ts";

declare module "cloudflare:test" {
  interface ProvidedEnv extends EdgeEnv {}
}
