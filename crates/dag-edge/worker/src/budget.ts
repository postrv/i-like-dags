import { MAX_CHUNK_SIZE } from "./limits.ts";
import type { EdgeEnv } from "./types.ts";

export type RetainedBudget =
  | { ok: true; bytes: number; objects: number }
  | { ok: false; reason: "missing" | "invalid" };

/** Parse deploy-time retained-storage ceilings without permissive coercion. */
export function retainedBudgetConfiguration(
  env: Pick<EdgeEnv, "DAG_RETAINED_BYTES_LIMIT" | "DAG_RETAINED_OBJECTS_LIMIT">,
): RetainedBudget {
  const bytes = parsePositiveDecimal(env.DAG_RETAINED_BYTES_LIMIT);
  const objects = parsePositiveDecimal(env.DAG_RETAINED_OBJECTS_LIMIT);
  if (bytes === null || objects === null) {
    return {
      ok: false,
      reason:
        env.DAG_RETAINED_BYTES_LIMIT === undefined || env.DAG_RETAINED_OBJECTS_LIMIT === undefined
          ? "missing"
          : "invalid",
    };
  }
  if (bytes < MAX_CHUNK_SIZE || objects < 1) return { ok: false, reason: "invalid" };
  return { ok: true, bytes, objects };
}

function parsePositiveDecimal(value: string | undefined): number | null {
  if (value === undefined || !/^[1-9][0-9]*$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}
