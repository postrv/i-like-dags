import {
  asMap,
  decodeCbor,
  decodeEntryCbor,
  decodeEntryCborWithLinkLimit,
  encodeCbor,
  hasOwn,
  optional,
  required,
  type CborValue,
} from "./cbor.ts";
import { cidFromCbor, cidToIntArray } from "./cid.ts";
import {
  MAX_EVENTS_PER_LOG,
  MAX_PIN_EVENT_PAYLOAD,
  MAX_POINTER_EVENT_PAYLOAD,
} from "./limits.ts";
import type { PinEventView, PointerEventView } from "./offer.ts";

export type EntryView = {
  payload: Uint8Array;
  links: Array<{
    name: string | null;
    target: string;
    nameTruncated?: true;
  }>;
  linkCount: number;
  linksTruncated: boolean;
};

export function decodeEntry(bytes: Uint8Array): EntryView {
  const decoded = decodeEntryCbor(bytes, true);
  return {
    payload: decoded.payload,
    links: decoded.links.map((link) => ({
      name: link.name,
      target: cidFromCbor(link.target),
      ...(link.nameTruncated ? { nameTruncated: true as const } : {}),
    })),
    linkCount: decoded.linkCount,
    linksTruncated: decoded.links.length < decoded.linkCount,
  };
}

/** Decode enough of an Entry for a bounded closure walk. */
export function decodeEntryForClosure(
  bytes: Uint8Array,
  retainedLinkLimit: number,
): { links: string[]; linkCount: number } {
  const decoded = decodeEntryCborWithLinkLimit(bytes, retainedLinkLimit);
  return {
    links: decoded.links.map((link) => cidFromCbor(link.target)),
    linkCount: decoded.linkCount,
  };
}

/** Validate the complete Entry envelope while retaining no link objects. */
export function decodeEntryPayload(bytes: Uint8Array): Uint8Array {
  return decodeEntryCbor(bytes, false).payload;
}

/**
 * Native pointer/pin logs accept only payload-only event Entries. Keeping the
 * same shape here prevents Edge-only histories that protocol-3 peers would
 * later refuse.
 */
export function decodePointerEventEntry(bytes: Uint8Array): Uint8Array {
  return decodeCanonicalEventEntry(bytes, MAX_POINTER_EVENT_PAYLOAD);
}

export function decodePinEventEntry(bytes: Uint8Array): Uint8Array {
  return decodeCanonicalEventEntry(bytes, MAX_PIN_EVENT_PAYLOAD);
}

function decodeCanonicalEventEntry(bytes: Uint8Array, maxPayload: number): Uint8Array {
  const decoded = decodeEntryCbor(bytes, false);
  if (decoded.linkCount !== 0 || decoded.hasMeta) {
    throw new Error("control event Entry must not contain links or metadata");
  }
  if (decoded.payload.byteLength > maxPayload) {
    throw new Error(`control event payload exceeds ${maxPayload} bytes`);
  }
  return decoded.payload;
}

export function decodePointerEvent(bytes: Uint8Array): PointerEventView {
  const map = asMap(decodeCbor(bytes));
  const seq = eventSequence(required(map, "seq"));
  const pointerId = required(map, "pointer_id");
  if (typeof pointerId !== "string") throw new Error("pointer_id must be text");
  const prev = optional(map.prev);
  validateI64(required(map, "ts"), "ts");
  return {
    seq,
    pointerId,
    prev: prev === undefined ? null : cidFromCbor(prev),
    new: cidFromCbor(required(map, "new")),
  };
}

export type PinDecoded = PinEventView & {
  target: { kind: "direct"; cid: string } | { kind: "subtree"; root: string; maxDepth: number | null };
  scope: { kind: "global" } | { kind: "local"; nodeId: string };
  state: "Active" | "Deactivated";
  expiresAt: number | bigint | null;
};

export function decodePinEvent(bytes: Uint8Array): PinDecoded {
  const map = asMap(decodeCbor(bytes));
  const seq = eventSequence(required(map, "seq"));
  const pinId = required(map, "pin_id");
  if (typeof pinId !== "string") throw new Error("pin_id must be text");
  const prev = optional(map.prev);
  const expiresAt = decodeOptionalI64(map.expires_at, "expires_at");
  validateI64(required(map, "ts"), "ts");
  const author = optional(map.author);
  if (author !== undefined && typeof author !== "string") {
    throw new Error("author must be text or null");
  }
  return {
    seq,
    pinId,
    prev: prev === undefined ? null : cidFromCbor(prev),
    target: decodePinTarget(required(map, "target")),
    scope: decodePinScope(required(map, "scope")),
    state: decodePinState(required(map, "state")),
    expiresAt,
  };
}

function decodePinTarget(
  value: CborValue,
): PinDecoded["target"] {
  const map = asMap(value);
  const variants = Number(hasOwn(map, "Direct")) + Number(hasOwn(map, "Subtree"));
  if (variants !== 1 || Object.keys(map).length !== 1) throw new Error("unknown pin target");
  if (hasOwn(map, "Direct")) {
    return { kind: "direct", cid: cidFromCbor(map.Direct) };
  }
  if (hasOwn(map, "Subtree")) {
    const inner = asMap(map.Subtree);
    const depth = optional(inner.max_depth);
    if (depth !== undefined && !isUnsignedInteger(depth, 0xffff_ffff)) {
      throw new Error("max_depth must be a u32 or null");
    }
    return {
      kind: "subtree",
      root: cidFromCbor(required(inner, "root")),
      maxDepth: depth === undefined ? null : Number(depth),
    };
  }
  throw new Error("unknown pin target");
}

function decodePinScope(value: CborValue): PinDecoded["scope"] {
  if (value === "Global") return { kind: "global" };
  const map = asMap(value);
  if (Object.keys(map).length === 1 && hasOwn(map, "Local")) {
    const inner = asMap(map.Local);
    const nodeId = required(inner, "node_id");
    if (typeof nodeId !== "string") throw new Error("local pin node_id must be text");
    return { kind: "local", nodeId };
  }
  throw new Error("unknown pin scope");
}

function decodePinState(value: CborValue): PinDecoded["state"] {
  if (value === "Active" || value === "Deactivated") return value;
  throw new Error("unknown pin state");
}

function eventSequence(value: CborValue): number {
  if (!isUnsignedInteger(value, MAX_EVENTS_PER_LOG)) {
    throw new Error(`event seq must be between 1 and ${MAX_EVENTS_PER_LOG}`);
  }
  const seq = Number(value);
  if (seq === 0) throw new Error("event seq must start at 1");
  return seq;
}

function isUnsignedInteger(value: CborValue, max: number): value is number | bigint {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 && value <= max;
  }
  return typeof value === "bigint" && value >= 0n && value <= BigInt(max);
}

function decodeOptionalI64(
  value: CborValue | undefined,
  field: string,
): number | bigint | null {
  const present = optional(value);
  if (present === undefined) return null;
  validateI64(present, field);
  return present as number | bigint;
}

function validateI64(value: CborValue, field: string): void {
  if (typeof value === "number") {
    if (Number.isSafeInteger(value)) return;
  } else if (
    typeof value === "bigint" &&
    value >= -(1n << 63n) &&
    value <= (1n << 63n) - 1n
  ) {
    return;
  }
  throw new Error(`${field} must be an i64`);
}

/** ciborium-shaped Entry: payload as an array of ints, meta omitted. */
export function encodeEntry(payload: Uint8Array): Uint8Array {
  return encodeCbor({
    payload: Array.from(payload),
    links: [],
  });
}

/** ciborium-shaped PointerEvent. `prev` is null on create. */
export function encodePointerEvent(event: PointerEventView & { ts: number }): Uint8Array {
  return encodeCbor({
    seq: event.seq,
    pointer_id: event.pointerId,
    prev: event.prev === null ? null : cidToIntArray(event.prev),
    new: cidToIntArray(event.new),
    ts: event.ts,
  });
}
