import { DurableObject } from "cloudflare:workers";
import { parseCidHex } from "./cid.ts";
import { checkPointerId } from "./ids.ts";
import { MAX_EVENTS_PER_LOG } from "./limits.ts";
import { formatOfferError, offerPointerEvent, type PointerEventView } from "./offer.ts";
import type { EdgeEnv } from "./types.ts";

export type PointerHeadView = { seq: number; cid: string | null; eventCid: string | null };
export type PointerOfferContext = {
  storedIdentity: string | null;
  existingEventCid: string | null;
  predecessorEventCid: string | null;
  predecessorNewCid: string | null;
  head: PointerHeadView;
};
export type PublishedPointerEvent = {
  seq: number;
  eventCid: string;
  event: PointerEventView;
};
export type LogImportResult =
  | { ok: true; filed: boolean }
  | { ok: false; status: 400 | 409; error: string; kind?: string };

/** One strongly-consistent Durable Object per committed pointer name. */
export class PointerObject extends DurableObject<EdgeEnv> {
  constructor(ctx: DurableObjectState, env: EdgeEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS events (
          seq INTEGER PRIMARY KEY,
          event_cid TEXT NOT NULL UNIQUE,
          new_cid TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        );
      `);
    });
  }

  head(): PointerHeadView {
    const row = this.ctx.storage.sql
      .exec<{ seq: number; event_cid: string; new_cid: string }>(
        "SELECT seq, event_cid, new_cid FROM events ORDER BY seq DESC LIMIT 1",
      )
      .toArray()[0];
    if (!row) return { seq: 0, cid: null, eventCid: null };
    return { seq: row.seq, cid: row.new_cid, eventCid: row.event_cid };
  }

  /** Read-only material needed for the Catalog to judge a staged offer. */
  offerContext(seq: number): PointerOfferContext {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) {
      throw new Error("invalid pointer event sequence");
    }
    const storedIdentity = this.ctx.storage.sql
      .exec<{ v: string }>("SELECT v FROM meta WHERE k = 'pointer_id'")
      .toArray()[0]?.v ?? null;
    const existingEventCid = this.ctx.storage.sql
      .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq)
      .toArray()[0]?.event_cid ?? null;
    const predecessor =
      seq > 1
        ? this.ctx.storage.sql
            .exec<{ event_cid: string; new_cid: string }>(
              "SELECT event_cid, new_cid FROM events WHERE seq = ?",
              seq - 1,
            )
            .toArray()[0]
        : undefined;
    return {
      storedIdentity,
      existingEventCid,
      predecessorEventCid: predecessor?.event_cid ?? null,
      predecessorNewCid: predecessor?.new_cid ?? null,
      head: this.head(),
    };
  }

  /** Existing mappings for authenticated, non-mutating dry-run probes. */
  eventCids(sequences: number[]): Array<{ seq: number; eventCid: string }> {
    if (!Array.isArray(sequences) || sequences.length > MAX_EVENTS_PER_LOG) {
      throw new Error("invalid pointer probe");
    }
    const out: Array<{ seq: number; eventCid: string }> = [];
    for (const seq of sequences) {
      if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) {
        throw new Error("invalid pointer probe sequence");
      }
      const eventCid = this.ctx.storage.sql
        .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq)
        .toArray()[0]?.event_cid;
      if (eventCid) out.push({ seq, eventCid });
    }
    return out;
  }

  /**
   * Idempotently copy one frozen Catalog group into the canonical log.
   * Partial execution is safe: a retry sees the same CIDs at every sequence.
   */
  publishBatch(id: string, events: PublishedPointerEvent[]): LogImportResult {
    if (!Array.isArray(events) || events.length > MAX_EVENTS_PER_LOG) {
      return { ok: false, status: 400, error: "invalid pointer publication batch" };
    }
    let filed = false;
    for (const item of events) {
      if (!item || typeof item !== "object") {
        return { ok: false, status: 400, error: "invalid pointer publication event" };
      }
      const result = this.importEvent(id, item.seq, item.eventCid, item.event);
      if (!result.ok) return result;
      filed ||= result.filed;
    }
    return { ok: true, filed };
  }

  importEvent(id: string, seq: number, eventCid: string, event: PointerEventView): LogImportResult {
    const validation = validateImport(id, seq, eventCid, event);
    if (validation) return validation;

    const storedIdentity = this.ctx.storage.sql
      .exec<{ v: string }>("SELECT v FROM meta WHERE k = 'pointer_id'")
      .toArray()[0]?.v;
    if (storedIdentity !== undefined && storedIdentity !== id) {
      return { ok: false, status: 409, kind: "identity_mismatch", error: "pointer object identity mismatch" };
    }

    const existingRow = this.ctx.storage.sql
      .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq)
      .toArray()[0];
    const predRow =
      seq > 1
        ? this.ctx.storage.sql
            .exec<{ event_cid: string; new_cid: string }>(
              "SELECT event_cid, new_cid FROM events WHERE seq = ?",
              seq - 1,
            )
            .toArray()[0]
        : undefined;
    const predecessor: PointerEventView | null = predRow
      ? { seq: seq - 1, pointerId: id, prev: null, new: predRow.new_cid }
      : null;
    const judged = offerPointerEvent(
      id,
      seq,
      eventCid,
      event,
      existingRow?.event_cid ?? null,
      predecessor,
    );
    if ("err" in judged) {
      return {
        ok: false,
        status: 409,
        error: formatOfferError(judged.err),
        kind: judged.err.kind,
      };
    }
    if (judged.ok === "already_filed") return { ok: true, filed: false };

    const count = this.ctx.storage.sql
      .exec<{ n: number }>("SELECT COUNT(*) AS n FROM events")
      .one().n;
    if (count >= MAX_EVENTS_PER_LOG) {
      return {
        ok: false,
        status: 400,
        error: `pointer log is full (${MAX_EVENTS_PER_LOG} events)`,
      };
    }

    this.ctx.storage.transactionSync(() => {
      if (storedIdentity === undefined) {
        this.ctx.storage.sql.exec("INSERT INTO meta (k, v) VALUES ('pointer_id', ?)", id);
      }
      this.ctx.storage.sql.exec(
        "INSERT INTO events (seq, event_cid, new_cid) VALUES (?, ?, ?)",
        seq,
        eventCid,
        event.new,
      );
    });
    return { ok: true, filed: true };
  }
}

function validateImport(
  id: string,
  seq: number,
  eventCid: string,
  event: PointerEventView,
): Extract<LogImportResult, { ok: false }> | null {
  const idError = typeof id === "string" ? checkPointerId(id) : "pointer id required";
  if (idError) return { ok: false, status: 400, error: idError };
  if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) {
    return { ok: false, status: 400, error: "invalid pointer event sequence" };
  }
  try {
    parseCidHex(eventCid);
  } catch {
    return { ok: false, status: 400, error: "invalid pointer event CID" };
  }
  if (
    event === null ||
    typeof event !== "object" ||
    !Number.isSafeInteger(event.seq) ||
    typeof event.pointerId !== "string" ||
    (event.prev !== null && typeof event.prev !== "string") ||
    typeof event.new !== "string"
  ) {
    return { ok: false, status: 400, error: "invalid pointer event" };
  }
  try {
    if (event.prev !== null) parseCidHex(event.prev);
    parseCidHex(event.new);
  } catch {
    return { ok: false, status: 400, error: "invalid CID in pointer event" };
  }
  return null;
}
