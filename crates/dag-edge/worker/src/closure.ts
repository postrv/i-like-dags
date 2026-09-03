import { CborLimitError } from "./cbor.ts";
import { type ChunkStore, getVerified } from "./chunks.ts";
import { decodeEntryForClosure, decodePinEvent, decodePinEventEntry } from "./dag.ts";
import {
  MAX_ENTRY_LINKS,
  MAX_REFERENCE_BYTES,
  MAX_REFERENCE_DEPTH,
  MAX_REFERENCE_LINKS,
  MAX_REFERENCE_OBJECTS,
} from "./limits.ts";

export type PublicationValidationHead =
  | { kind: "pointer"; name: string; cid: string }
  | { kind: "pin"; name: string; eventCid: string };

export type ClosureBudgets = {
  maxObjects: number;
  maxBytes: number;
  maxLinks: number;
  maxDepth: number;
};

export const DEFAULT_CLOSURE_BUDGETS: ClosureBudgets = {
  maxObjects: MAX_REFERENCE_OBJECTS,
  maxBytes: MAX_REFERENCE_BYTES,
  maxLinks: MAX_REFERENCE_LINKS,
  maxDepth: MAX_REFERENCE_DEPTH,
};

export type ReferenceClosureCode =
  | "reference_unavailable"
  | "reference_store_invalid"
  | "reference_object_limit"
  | "reference_byte_limit"
  | "reference_link_limit"
  | "reference_depth_limit"
  | "reference_entry_decode_limit"
  | "invalid_pin_head";

export class ReferenceClosureError extends Error {
  readonly code: ReferenceClosureCode;
  readonly status: 409 | 502;

  constructor(code: ReferenceClosureCode, message: string, status: 409 | 502 = 409) {
    super(message);
    this.name = "ReferenceClosureError";
    this.code = code;
    this.status = status;
  }
}

type Coverage = -1 | number;
type QueueItem = { cid: string; coverage: Coverage; graphDepth: number };
type CachedObject = { bytes: Uint8Array; links?: string[] | null };

/**
 * Validate exactly the roots a staged Edge publication would make live.
 *
 * Reads always pass through `getVerified`, so neither R2 metadata nor KV bytes
 * are trusted without recomputing the CID. The protocol exposes no operation
 * that deletes or mutates a valid CID object; after a revision is witnessed,
 * that immutability closes the validation-to-publication window.
 */
export async function validatePublicationClosure(
  store: ChunkStore,
  heads: PublicationValidationHead[],
  nowSeconds: number,
  budgets: ClosureBudgets = DEFAULT_CLOSURE_BUDGETS,
): Promise<{ objects: number; bytes: number; links: number; maxDepth: number }> {
  validateBudgets(budgets);
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) {
    throw new ReferenceClosureError("invalid_pin_head", "invalid closure validation time");
  }
  const walker = new ClosureWalker(store, budgets);

  for (const head of heads) {
    if (head.kind === "pointer") walker.addRoot(head.cid, -1);
  }
  for (const head of heads) {
    if (head.kind !== "pin") continue;
    const bytes = await walker.readObject(head.eventCid);
    let event;
    try {
      event = decodePinEvent(decodePinEventEntry(bytes));
    } catch {
      throw new ReferenceClosureError(
        "invalid_pin_head",
        `pin ${head.name} head is no longer a valid pin event`,
      );
    }
    if (event.pinId !== head.name) {
      throw new ReferenceClosureError(
        "invalid_pin_head",
        `pin ${head.name} head has a different identity`,
      );
    }
    // Edge has no configurable node identity yet. This is the same explicit
    // capability boundary as native protocol 3: only the default destination
    // identity `local` turns a Local pin into a live retention promise.
    const applies =
      event.scope.kind === "global" ||
      (event.scope.kind === "local" && event.scope.nodeId === "local");
    if (!applies || event.state !== "Active" || isExpired(event.expiresAt, nowSeconds)) {
      continue;
    }
    if (event.target.kind === "direct") {
      walker.addRoot(event.target.cid, 0);
    } else {
      walker.addRoot(event.target.root, event.target.maxDepth ?? -1);
    }
  }

  return walker.walk();
}

class ClosureWalker {
  private readonly queue: QueueItem[] = [];
  private queueOffset = 0;
  private readonly scheduled = new Map<string, Coverage>();
  private readonly expanded = new Map<string, Coverage>();
  private readonly cached = new Map<string, CachedObject>();
  private totalBytes = 0;
  private totalLinks = 0;
  private deepest = 0;

  constructor(
    private readonly store: ChunkStore,
    private readonly budgets: ClosureBudgets,
  ) {}

  addRoot(cid: string, coverage: Coverage): void {
    this.schedule(cid, coverage, 0);
  }

  async readObject(cid: string): Promise<Uint8Array> {
    const cached = this.cached.get(cid);
    if (cached) return cached.bytes;
    if (this.cached.size >= this.budgets.maxObjects) {
      throw new ReferenceClosureError(
        "reference_object_limit",
        `reference closure exceeds ${this.budgets.maxObjects} objects`,
      );
    }
    const got = await getVerified(this.store, cid);
    if (!(got instanceof Uint8Array)) {
      if (got.status >= 500) {
        throw new ReferenceClosureError(
          "reference_store_invalid",
          `reference closure is corrupt or unreadable at ${cid}`,
          502,
        );
      }
      throw new ReferenceClosureError(
        "reference_unavailable",
        `reference closure is missing ${cid}`,
      );
    }
    if (this.totalBytes + got.byteLength > this.budgets.maxBytes) {
      throw new ReferenceClosureError(
        "reference_byte_limit",
        `reference closure exceeds ${this.budgets.maxBytes} bytes`,
      );
    }
    this.totalBytes += got.byteLength;
    this.cached.set(cid, { bytes: got });
    return got;
  }

  async walk(): Promise<{ objects: number; bytes: number; links: number; maxDepth: number }> {
    while (this.queueOffset < this.queue.length) {
      const item = this.queue[this.queueOffset++];
      const scheduled = this.scheduled.get(item.cid);
      if (scheduled !== undefined && scheduled !== item.coverage && covers(scheduled, item.coverage)) {
        continue;
      }
      const expanded = this.expanded.get(item.cid);
      if (expanded !== undefined && covers(expanded, item.coverage)) continue;

      await this.readObject(item.cid);
      this.deepest = Math.max(this.deepest, item.graphDepth);
      this.expanded.set(item.cid, item.coverage);
      if (item.coverage === 0) continue;

      const links = this.entryLinks(item.cid);
      if (links.length > 0 && item.graphDepth >= this.budgets.maxDepth) {
        throw new ReferenceClosureError(
          "reference_depth_limit",
          `reference closure exceeds depth ${this.budgets.maxDepth}`,
        );
      }
      const childCoverage: Coverage = item.coverage === -1 ? -1 : item.coverage - 1;
      for (const target of links) {
        this.schedule(target, childCoverage, item.graphDepth + 1);
      }
    }
    return {
      objects: this.cached.size,
      bytes: this.totalBytes,
      links: this.totalLinks,
      maxDepth: this.deepest,
    };
  }

  private entryLinks(cid: string): string[] {
    const cached = this.cached.get(cid);
    if (!cached) throw new Error("closure object was not loaded");
    if (cached.links !== undefined) return cached.links ?? [];
    const remaining = this.budgets.maxLinks - this.totalLinks;
    let decoded;
    try {
      decoded = decodeEntryForClosure(cached.bytes, Math.min(remaining + 1, MAX_ENTRY_LINKS));
    } catch (error) {
      if (error instanceof CborLimitError) {
        throw new ReferenceClosureError(
          "reference_entry_decode_limit",
          `reference Entry at ${cid} exceeds the bounded decoder`,
        );
      }
      // Arbitrary content is a legitimate leaf. Only a completely valid Entry
      // envelope carries links and therefore extends the promised closure.
      cached.links = null;
      return [];
    }
    if (decoded.linkCount > remaining || decoded.links.length !== decoded.linkCount) {
      throw new ReferenceClosureError(
        "reference_link_limit",
        `reference closure exceeds ${this.budgets.maxLinks} links`,
      );
    }
    this.totalLinks += decoded.linkCount;
    cached.links = decoded.links;
    return decoded.links;
  }

  private schedule(cid: string, coverage: Coverage, graphDepth: number): void {
    const prior = this.scheduled.get(cid);
    if (prior !== undefined && covers(prior, coverage)) return;
    if (prior === undefined && this.scheduled.size >= this.budgets.maxObjects) {
      throw new ReferenceClosureError(
        "reference_object_limit",
        `reference closure exceeds ${this.budgets.maxObjects} objects`,
      );
    }
    this.scheduled.set(cid, coverage);
    this.queue.push({ cid, coverage, graphDepth });
  }
}

function covers(proved: Coverage, requested: Coverage): boolean {
  if (proved === -1) return true;
  if (requested === -1) return false;
  return proved >= requested;
}

function isExpired(expiresAt: number | bigint | null, nowSeconds: number): boolean {
  if (expiresAt === null) return false;
  return typeof expiresAt === "bigint"
    ? BigInt(nowSeconds) >= expiresAt
    : nowSeconds >= expiresAt;
}

function validateBudgets(budgets: ClosureBudgets): void {
  for (const [name, value] of Object.entries(budgets)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`invalid closure budget ${name}`);
    }
  }
}
