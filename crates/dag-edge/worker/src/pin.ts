import { DurableObject } from "cloudflare:workers";
import { parseCidHex } from "./cid.ts";
import { checkPinId } from "./ids.ts";
import { MAX_EVENTS_PER_LOG } from "./limits.ts";
import { formatOfferError, offerPinEvent, type PinEventView } from "./offer.ts";
import type { EdgeEnv } from "./types.ts";
import type { LogImportResult } from "./pointer.ts";

export type PinHeadView = { seq: number; eventCid: string | null };
export type PinOfferContext = {
  storedIdentity: string | null;
  existingEventCid: string | null;
  predecessorEventCid: string | null;
  head: PinHeadView;
};
export type PublishedPinEvent = {
  seq: number;
  eventCid: string;
  event: PinEventView;
};

/** One strongly-consistent Durable Object per committed pin name. */
export class PinObject extends DurableObject<EdgeEnv> {
  constructor(ctx: DurableObjectState, env: EdgeEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS events (
          seq INTEGER PRIMARY KEY,
          event_cid TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS meta (
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        );
      `);
    });
  }

  head(): PinHeadView {
    const row = this.ctx.storage.sql
      .exec<{ seq: number; event_cid: string }>(
        "SELECT seq, event_cid FROM events ORDER BY seq DESC LIMIT 1",
      )
      .toArray()[0];
    return row ? { seq: row.seq, eventCid: row.event_cid } : { seq: 0, eventCid: null };
  }

  offerContext(seq: number): PinOfferContext {
    if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) {
      throw new Error("invalid pin event sequence");
    }
    const storedIdentity = this.ctx.storage.sql
      .exec<{ v: string }>("SELECT v FROM meta WHERE k = 'pin_id'")
      .toArray()[0]?.v ?? null;
    const existingEventCid = this.ctx.storage.sql
      .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq)
      .toArray()[0]?.event_cid ?? null;
    const predecessorEventCid =
      seq > 1
        ? this.ctx.storage.sql
            .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq - 1)
            .toArray()[0]?.event_cid ?? null
        : null;
    return { storedIdentity, existingEventCid, predecessorEventCid, head: this.head() };
  }

  eventCids(sequences: number[]): Array<{ seq: number; eventCid: string }> {
    if (!Array.isArray(sequences) || sequences.length > MAX_EVENTS_PER_LOG) {
      throw new Error("invalid pin probe");
    }
    const out: Array<{ seq: number; eventCid: string }> = [];
    for (const seq of sequences) {
      if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) {
        throw new Error("invalid pin probe sequence");
      }
      const eventCid = this.ctx.storage.sql
        .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq)
        .toArray()[0]?.event_cid;
      if (eventCid) out.push({ seq, eventCid });
    }
    return out;
  }

  publishBatch(id: string, events: PublishedPinEvent[]): LogImportResult {
    if (!Array.isArray(events) || events.length > MAX_EVENTS_PER_LOG) {
      return { ok: false, status: 400, error: "invalid pin publication batch" };
    }
    let filed = false;
    for (const item of events) {
      if (!item || typeof item !== "object") {
        return { ok: false, status: 400, error: "invalid pin publication event" };
      }
      const result = this.importEvent(id, item.seq, item.eventCid, item.event);
      if (!result.ok) return result;
      filed ||= result.filed;
    }
    return { ok: true, filed };
  }

  importEvent(id: string, seq: number, eventCid: string, event: PinEventView): LogImportResult {
    const validation = validateImport(id, seq, eventCid, event);
    if (validation) return validation;

    const storedIdentity = this.ctx.storage.sql
      .exec<{ v: string }>("SELECT v FROM meta WHERE k = 'pin_id'")
      .toArray()[0]?.v;
    if (storedIdentity !== undefined && storedIdentity !== id) {
      return { ok: false, status: 409, kind: "identity_mismatch", error: "pin object identity mismatch" };
    }

    const existingRow = this.ctx.storage.sql
      .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq)
      .toArray()[0];
    const predRow =
      seq > 1
        ? this.ctx.storage.sql
            .exec<{ event_cid: string }>("SELECT event_cid FROM events WHERE seq = ?", seq - 1)
            .toArray()[0]
        : undefined;
    const judged = offerPinEvent(
      id,
      seq,
      eventCid,
      event,
      existingRow?.event_cid ?? null,
      predRow?.event_cid ?? null,
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
        error: `pin log is full (${MAX_EVENTS_PER_LOG} events)`,
      };
    }

    this.ctx.storage.transactionSync(() => {
      if (storedIdentity === undefined) {
        this.ctx.storage.sql.exec("INSERT INTO meta (k, v) VALUES ('pin_id', ?)", id);
      }
      this.ctx.storage.sql.exec(
        "INSERT INTO events (seq, event_cid) VALUES (?, ?)",
        seq,
        eventCid,
      );
    });
    return { ok: true, filed: true };
  }
}

function validateImport(
  id: string,
  seq: number,
  eventCid: string,
  event: PinEventView,
): Extract<LogImportResult, { ok: false }> | null {
  const idError = typeof id === "string" ? checkPinId(id) : "pin id required";
  if (idError) return { ok: false, status: 400, error: idError };
  if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) {
    return { ok: false, status: 400, error: "invalid pin event sequence" };
  }
  try {
    parseCidHex(eventCid);
  } catch {
    return { ok: false, status: 400, error: "invalid pin event CID" };
  }
  if (
    event === null ||
    typeof event !== "object" ||
    !Number.isSafeInteger(event.seq) ||
    typeof event.pinId !== "string" ||
    (event.prev !== null && typeof event.prev !== "string")
  ) {
    return { ok: false, status: 400, error: "invalid pin event" };
  }
  try {
    if (event.prev !== null) parseCidHex(event.prev);
  } catch {
    return { ok: false, status: 400, error: "invalid previous CID in pin event" };
  }
  return null;
}
