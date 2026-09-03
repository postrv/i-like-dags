import { CborLimitError } from "./cbor.ts";
import { decodeEntry, decodePinEvent, decodePointerEvent } from "./dag.ts";

export type Inspect = {
  cid: string;
  size: number;
  kind: "entry" | "bytes";
  preview: string | null;
  links: { name: string | null; target: string; name_truncated?: true }[];
  link_count: number;
  links_truncated: boolean;
  pointer_event?: {
    seq: number;
    pointer_id: string;
    prev: string | null;
    new: string;
  };
  pin_event?: {
    seq: number;
    pin_id: string;
    prev: string | null;
    state: string;
  };
};

const PREVIEW = 240;
// Pointer/pin annotations are optional inspection sugar. Canonical events are
// tiny; do not run two generic schema decoders over an attacker-sized payload.
const INSPECT_EVENT_PAYLOAD_LIMIT = 16 * 1024;

export function inspectBytes(cid: string, bytes: Uint8Array): Inspect {
  try {
    const entry = decodeEntry(bytes);
    const out: Inspect = {
      cid,
      size: bytes.length,
      kind: "entry",
      preview: utf8Preview(entry.payload),
      links: entry.links.map((link) => ({
        name: link.name,
        target: link.target,
        ...(link.nameTruncated ? { name_truncated: true as const } : {}),
      })),
      link_count: entry.linkCount,
      links_truncated: entry.linksTruncated,
    };
    if (
      entry.payload.byteLength <= INSPECT_EVENT_PAYLOAD_LIMIT &&
      entry.payload.byteLength > 0 &&
      (entry.payload[0] >> 5) === 5
    ) {
      try {
        const ev = decodePointerEvent(entry.payload);
        out.pointer_event = {
          seq: ev.seq,
          pointer_id: ev.pointerId,
          prev: ev.prev,
          new: ev.new,
        };
        out.preview = null;
      } catch {
        // not a pointer event
      }
      try {
        const ev = decodePinEvent(entry.payload);
        out.pin_event = {
          seq: ev.seq,
          pin_id: ev.pinId,
          prev: ev.prev,
          state: ev.state,
        };
        if (!out.pointer_event) out.preview = null;
      } catch {
        // not a pin event
      }
    }
    return out;
  } catch (error) {
    if (error instanceof CborLimitError) throw error;
    return {
      cid,
      size: bytes.length,
      kind: "bytes",
      preview: utf8Preview(bytes),
      links: [],
      link_count: 0,
      links_truncated: false,
    };
  }
}

function utf8Preview(bytes: Uint8Array): string | null {
  if (bytes.length === 0) return "";
  const slice = bytes.subarray(0, PREVIEW);
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(slice);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text)) return null;
    return text + (bytes.length > PREVIEW ? "…" : "");
  } catch {
    return null;
  }
}
