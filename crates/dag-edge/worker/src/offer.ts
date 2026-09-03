/**
 * Chain rules for filing a pointer or pin event.
 *
 * Port of `dag_core::offer`. The Worker must refuse the same forgeries
 * the laptop `import_event` refuses. I/O stays with the caller.
 */

export type OfferOutcome = "accept" | "already_filed";

export type OfferError =
  | { kind: "zero_seq" }
  | {
      kind: "identity_mismatch";
      eventCid: string;
      eventId: string;
      eventSeq: number;
      offeredId: string;
      offeredSeq: number;
    }
  | {
      kind: "divergent";
      id: string;
      seq: number;
      existing: string;
      offered: string;
    }
  | { kind: "create_has_prev"; id: string }
  | { kind: "missing_predecessor"; id: string; seq: number; needed: number }
  | {
      kind: "chain_broken";
      id: string;
      seq: number;
      prev: string;
      expected: string;
    }
  | {
      kind: "pin_prev_absent";
      id: string;
      seq: number;
      needed: number;
      expected: string;
    };

export function formatOfferError(err: OfferError): string {
  switch (err.kind) {
    case "zero_seq":
      return "sequence 0 is not a valid event position";
    case "identity_mismatch":
      return `event ${err.eventCid} describes (${err.eventId}, seq ${err.eventSeq}) but was offered as (${err.offeredId}, seq ${err.offeredSeq})`;
    case "divergent":
      return `${err.id} seq ${err.seq} already names ${err.existing}, refusing to replace it with ${err.offered}`;
    case "create_has_prev":
      return `${err.id} seq 1 must have no \`prev\``;
    case "missing_predecessor":
      return `${err.id} seq ${err.seq} cannot be imported before seq ${err.needed}`;
    case "chain_broken":
      return `${err.id} seq ${err.seq} breaks the chain: \`prev\` is ${err.prev}, expected ${err.expected}`;
    case "pin_prev_absent":
      return `${err.id} seq ${err.seq} has no \`prev\`: it cannot be shown to follow seq ${err.needed} (${err.expected})`;
  }
}

export type PointerEventView = {
  seq: number;
  pointerId: string;
  prev: string | null;
  new: string;
};

export type PinEventView = {
  seq: number;
  pinId: string;
  prev: string | null;
};

export function offerPointerEvent(
  pointerId: string,
  seq: number,
  eventCid: string,
  event: PointerEventView,
  existingAtSeq: string | null,
  predecessor: PointerEventView | null,
): { ok: OfferOutcome } | { err: OfferError } {
  if (seq === 0) return { err: { kind: "zero_seq" } };
  if (event.pointerId !== pointerId || event.seq !== seq) {
    return {
      err: {
        kind: "identity_mismatch",
        eventCid,
        eventId: event.pointerId,
        eventSeq: event.seq,
        offeredId: pointerId,
        offeredSeq: seq,
      },
    };
  }
  if (existingAtSeq !== null) {
    return existingAtSeq === eventCid
      ? { ok: "already_filed" }
      : {
          err: {
            kind: "divergent",
            id: pointerId,
            seq,
            existing: existingAtSeq,
            offered: eventCid,
          },
        };
  }
  if (seq === 1) {
    if (event.prev !== null) return { err: { kind: "create_has_prev", id: pointerId } };
    return { ok: "accept" };
  }
  if (predecessor === null) {
    return { err: { kind: "missing_predecessor", id: pointerId, seq, needed: seq - 1 } };
  }
  if (event.prev !== predecessor.new) {
    return {
      err: {
        kind: "chain_broken",
        id: pointerId,
        seq,
        prev: event.prev ?? "none",
        expected: predecessor.new,
      },
    };
  }
  return { ok: "accept" };
}

export function offerPinEvent(
  pinId: string,
  seq: number,
  eventCid: string,
  event: PinEventView,
  existingAtSeq: string | null,
  predecessorEventCid: string | null,
): { ok: OfferOutcome } | { err: OfferError } {
  if (seq === 0) return { err: { kind: "zero_seq" } };
  if (event.pinId !== pinId || event.seq !== seq) {
    return {
      err: {
        kind: "identity_mismatch",
        eventCid,
        eventId: event.pinId,
        eventSeq: event.seq,
        offeredId: pinId,
        offeredSeq: seq,
      },
    };
  }
  if (existingAtSeq !== null) {
    return existingAtSeq === eventCid
      ? { ok: "already_filed" }
      : {
          err: {
            kind: "divergent",
            id: pinId,
            seq,
            existing: existingAtSeq,
            offered: eventCid,
          },
        };
  }
  if (seq === 1) {
    if (event.prev !== null) return { err: { kind: "create_has_prev", id: pinId } };
    return { ok: "accept" };
  }
  if (predecessorEventCid === null) {
    return { err: { kind: "missing_predecessor", id: pinId, seq, needed: seq - 1 } };
  }
  if (event.prev === null) {
    return {
      err: {
        kind: "pin_prev_absent",
        id: pinId,
        seq,
        needed: seq - 1,
        expected: predecessorEventCid,
      },
    };
  }
  if (event.prev !== predecessorEventCid) {
    return {
      err: {
        kind: "chain_broken",
        id: pinId,
        seq,
        prev: event.prev,
        expected: predecessorEventCid,
      },
    };
  }
  return { ok: "accept" };
}
