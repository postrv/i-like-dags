/**
 * Small CBOR subset for Entry / PointerEvent / PinEvent.
 *
 * ciborium writes `Vec<u8>` and `Cid` as arrays of integers, not byte
 * strings. Decode accepts both. Encode matches ciborium so a CAS-minted
 * event is something `ciborium` on the laptop will read.
 *
 * Hostile input is refused: no indefinite lengths, no huge reservations
 * from a declared size, bounded depth.
 */

import {
  INSPECT_LINK_LIMIT,
  INSPECT_LINK_NAME_BYTES,
  MAX_CHUNK_SIZE,
  MAX_ENTRY_LINKS,
} from "./limits.ts";

const MAX_DEPTH = 8;
// A Rust `Vec<u8>` is encoded by ciborium as an integer array. A valid Entry
// can therefore contain close to four million array items while remaining
// under the chunk ceiling. Byte-shaped arrays are decoded directly into a
// Uint8Array so hostile input cannot allocate millions of boxed JS numbers.
const MAX_BYTE_ARRAY = MAX_CHUNK_SIZE;
// Generic event decoding never needs a large structural array. Entry links use
// the schema-aware streaming path below, which validates every link while
// retaining only the small public response prefix.
const MAX_STRUCTURAL_ARRAY = 4_096;
const MAX_GENERIC_STRUCTURE_STEPS = 16_384;
// A near-limit Rust Entry can contain about 100k minimal Links. Counting each
// link and map key gives that valid shape headroom while bounding work in
// ignored extension values independently of the byte-size ceiling.
const MAX_ENTRY_STRUCTURE_STEPS = 300_016;
const MAX_MAP = 4_096;
const MAX_BYTES = MAX_CHUNK_SIZE;
const MAX_TEXT = MAX_CHUNK_SIZE;
const FORBIDDEN_MAP_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const ENTRY_KEYS = ["payload", "links", "meta"] as const;
const LINK_KEYS = ["name", "target"] as const;
const META_KEYS = ["content_type", "encoding"] as const;
const TRUNCATED_TEXT = Symbol("truncated CBOR text");

export class CborLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborLimitError";
  }
}

export type CborValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | CborValue[]
  | { [key: string]: CborValue };

export type DecodedEntryCbor = {
  payload: Uint8Array;
  links: Array<{
    name: string | null;
    target: Uint8Array;
    nameTruncated?: true;
  }>;
  linkCount: number;
  /** `true` for any non-null `meta` map, including an otherwise empty map. */
  hasMeta: boolean;
};

export function decodeCbor(bytes: Uint8Array): CborValue {
  if (bytes.byteLength > MAX_CHUNK_SIZE) throw new CborLimitError("CBOR exceeds the chunk limit");
  const d = new Decoder(bytes, MAX_GENERIC_STRUCTURE_STEPS);
  const value = d.value(0);
  if (d.offset !== bytes.length) {
    throw new Error("CBOR trailing bytes");
  }
  return value;
}

/**
 * Decode the Rust Entry schema without constructing its attacker-sized link
 * array. All links are still parsed and schema-validated; callers either keep
 * no links (event import) or the fixed public inspection prefix.
 */
export function decodeEntryCbor(bytes: Uint8Array, retainLinks: boolean): DecodedEntryCbor {
  return decodeEntryCborWithLinkLimit(bytes, retainLinks ? INSPECT_LINK_LIMIT : 0);
}

/**
 * Decode an Entry while retaining at most a caller-selected number of links.
 * Every declared link is still parsed and schema-validated. Closure validation
 * uses this to keep its aggregate edge budget independent of the inspection
 * response limit.
 */
export function decodeEntryCborWithLinkLimit(
  bytes: Uint8Array,
  retainedLinkLimit: number,
): DecodedEntryCbor {
  if (bytes.byteLength > MAX_CHUNK_SIZE) throw new CborLimitError("Entry exceeds the chunk limit");
  if (
    !Number.isSafeInteger(retainedLinkLimit) ||
    retainedLinkLimit < 0 ||
    retainedLinkLimit > MAX_ENTRY_LINKS
  ) {
    throw new CborLimitError("invalid retained link limit");
  }
  const d = new Decoder(bytes, MAX_ENTRY_STRUCTURE_STEPS);
  const value = d.entry(retainedLinkLimit);
  if (d.offset !== bytes.length) throw new Error("CBOR trailing bytes");
  return value;
}

export function encodeCbor(value: CborValue): Uint8Array {
  const out: number[] = [];
  write(out, value);
  return new Uint8Array(out);
}

class Decoder {
  offset = 0;
  private bytes: Uint8Array;
  private structuralRemaining: number;
  constructor(bytes: Uint8Array, structuralBudget: number) {
    this.bytes = bytes;
    this.structuralRemaining = structuralBudget;
  }

  private spendStructural(count = 1): void {
    if (!Number.isSafeInteger(count) || count < 0 || count > this.structuralRemaining) {
      throw new CborLimitError("CBOR structural work limit exceeded");
    }
    this.structuralRemaining -= count;
  }

  private advance(n: number): number {
    if (this.offset + n > this.bytes.length) {
      throw new Error("CBOR truncated");
    }
    const start = this.offset;
    this.offset += n;
    return start;
  }

  private take(n: number): Uint8Array {
    const start = this.advance(n);
    return this.bytes.subarray(start, start + n);
  }

  private byte(): number {
    if (this.offset >= this.bytes.length) throw new Error("CBOR truncated");
    return this.bytes[this.offset++];
  }

  private peek(): number {
    if (this.offset >= this.bytes.length) throw new Error("CBOR truncated");
    return this.bytes[this.offset];
  }

  private checkDepth(depth: number): void {
    if (depth > MAX_DEPTH) throw new Error("CBOR too deep");
  }

  private argument(ai: number): number | bigint {
    if (ai < 24) return ai;
    if (ai === 24) return this.byte();
    if (ai === 25) {
      const b = this.take(2);
      return (b[0] << 8) | b[1];
    }
    if (ai === 26) {
      const b = this.take(4);
      return (
        ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
      );
    }
    if (ai === 27) {
      const b = this.take(8);
      let n = 0n;
      for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(b[i]);
      if (n > BigInt(Number.MAX_SAFE_INTEGER)) return n;
      return Number(n);
    }
    throw new Error("CBOR indefinite or reserved");
  }

  private containerLength(expectedMajor: number, max: number, message: string): number {
    const ib = this.byte();
    if ((ib >> 5) !== expectedMajor) throw new Error(message);
    return asCount(this.argument(ib & 0x1f), max);
  }

  private decodeText(bytes: Uint8Array): string {
    try {
      // `ignoreBOM: true` preserves U+FEFF, matching Rust Strings.
      return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      throw new Error("CBOR text is not valid UTF-8");
    }
  }

  private bytesMatchAscii(length: number, candidate: string): boolean {
    if (candidate.length !== length) return false;
    for (let i = 0; i < length; i++) {
      if (this.bytes[this.offset + i] !== candidate.charCodeAt(i)) return false;
    }
    return true;
  }

  private mapKey(depth: number, known: readonly string[] = []): string | null {
    this.checkDepth(depth);
    this.spendStructural();
    const ib = this.byte();
    if ((ib >> 5) !== 3) throw new Error("CBOR map key must be text");
    const len = asCount(this.argument(ib & 0x1f), MAX_TEXT);
    for (const candidate of known) {
      if (this.bytesMatchAscii(len, candidate)) {
        this.offset += len;
        return candidate;
      }
    }
    for (const forbidden of FORBIDDEN_MAP_KEYS) {
      if (this.bytesMatchAscii(len, forbidden)) {
        this.offset += len;
        throw new Error("CBOR map key is forbidden");
      }
    }
    const start = this.advance(len);
    validateUtf8(this.bytes, start, len);
    return null;
  }

  private byteSequence(message: string): Uint8Array {
    const ib = this.byte();
    const major = ib >> 5;
    const len = asCount(this.argument(ib & 0x1f), MAX_BYTE_ARRAY);
    if (major === 2) return this.take(len);
    if (major !== 4) throw new Error(message);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = this.byteValue(message);
    return out;
  }

  private fixedBytes(expected: number, retain: boolean, message: string): Uint8Array | null {
    const ib = this.byte();
    const major = ib >> 5;
    const len = asCount(this.argument(ib & 0x1f), MAX_BYTE_ARRAY);
    if (len !== expected || (major !== 2 && major !== 4)) throw new Error(message);
    if (major === 2) {
      if (!retain) {
        this.advance(len);
        return null;
      }
      return this.take(len);
    }
    const out = retain ? new Uint8Array(len) : null;
    for (let i = 0; i < len; i++) {
      const value = this.byteValue(message);
      if (out) out[i] = value;
    }
    return out;
  }

  private byteValue(message: string): number {
    const ib = this.byte();
    if ((ib >> 5) !== 0) throw new Error(message);
    const value = this.argument(ib & 0x1f);
    if (typeof value !== "number" || !Number.isInteger(value) || value > 255) {
      throw new Error(message);
    }
    return value;
  }

  private nullableText(retain: boolean): string | null | typeof TRUNCATED_TEXT {
    const ib = this.byte();
    if (ib === 0xf6) return null;
    if ((ib >> 5) !== 3) throw new Error("link name must be text or null");
    const len = asCount(this.argument(ib & 0x1f), MAX_TEXT);
    if (!retain) {
      const start = this.advance(len);
      validateUtf8(this.bytes, start, len);
      return null;
    }
    if (len > INSPECT_LINK_NAME_BYTES) {
      const start = this.advance(len);
      validateUtf8(this.bytes, start, len);
      return TRUNCATED_TEXT;
    }
    return this.decodeText(this.take(len));
  }

  entry(retainedLinkLimit: number): DecodedEntryCbor {
    this.spendStructural();
    const fields = this.containerLength(5, ENTRY_KEYS.length, "expected Entry map");
    const seen = new Set<string>();
    let payload: Uint8Array | undefined;
    let links: DecodedEntryCbor["links"] | undefined;
    let linkCount: number | undefined;
    let hasMeta = false;

    for (let i = 0; i < fields; i++) {
      const key = this.mapKey(1, ENTRY_KEYS);
      if (key !== null) {
        if (seen.has(key)) throw new Error(`CBOR map has duplicate key ${key}`);
        seen.add(key);
      }
      if (key === "payload") {
        payload = this.byteSequence("payload is not bytes");
      } else if (key === "links") {
        const decoded = this.entryLinks(retainedLinkLimit, 1);
        links = decoded.links;
        linkCount = decoded.count;
      } else if (key === "meta") {
        hasMeta = this.entryMeta(1);
      } else {
        throw new Error("Entry contains an unknown field");
      }
    }
    if (payload === undefined) throw new Error("missing required field payload");
    if (links === undefined || linkCount === undefined) throw new Error("missing required field links");
    return { payload, links, linkCount, hasMeta };
  }

  private entryLinks(
    retainedLinkLimit: number,
    depth: number,
  ): { links: DecodedEntryCbor["links"]; count: number } {
    this.checkDepth(depth);
    const count = this.containerLength(4, MAX_ENTRY_LINKS, "links must be an array");
    const links: DecodedEntryCbor["links"] = [];
    for (let i = 0; i < count; i++) {
      const retain = i < retainedLinkLimit;
      const link = this.entryLink(retain, depth + 1);
      if (link) links.push(link);
    }
    return { links, count };
  }

  private entryLink(retain: boolean, depth: number): DecodedEntryCbor["links"][number] | null {
    this.checkDepth(depth);
    this.spendStructural();
    const fields = this.containerLength(5, LINK_KEYS.length, "expected link map");
    let sawName = false;
    let sawTarget = false;
    let name: string | null = null;
    let nameTruncated = false;
    let target: Uint8Array | null = null;
    for (let i = 0; i < fields; i++) {
      const key = this.mapKey(depth + 1, LINK_KEYS);
      if (key === "name") {
        if (sawName) throw new Error("CBOR map has duplicate key name");
        sawName = true;
        const decoded = this.nullableText(retain);
        if (decoded === TRUNCATED_TEXT) {
          name = null;
          nameTruncated = true;
        } else {
          name = decoded;
        }
      } else if (key === "target") {
        if (sawTarget) throw new Error("CBOR map has duplicate key target");
        sawTarget = true;
        target = this.fixedBytes(32, retain, "CID must be 32 bytes");
      } else {
        throw new Error("link contains an unknown field");
      }
    }
    if (!sawTarget) throw new Error("missing required field target");
    if (!retain) return null;
    if (!target) throw new Error("CID must be 32 bytes");
    return {
      name,
      target,
      ...(nameTruncated ? { nameTruncated: true as const } : {}),
    };
  }

  private entryMeta(depth: number): boolean {
    this.checkDepth(depth);
    const first = this.peek();
    if (first === 0xf6) {
      this.byte();
      return false;
    }
    this.spendStructural();
    const fields = this.containerLength(
      5,
      META_KEYS.length,
      "entry meta must be a map or null",
    );
    const seen = new Set<string>();
    for (let i = 0; i < fields; i++) {
      const key = this.mapKey(depth + 1, META_KEYS);
      if (key !== null) {
        if (seen.has(key)) throw new Error(`CBOR map has duplicate key ${key}`);
        seen.add(key);
      }
      if (key === "content_type" || key === "encoding") {
        this.nullableText(false);
      } else {
        throw new Error("entry meta contains an unknown field");
      }
    }
    return true;
  }

  /** Parse and validate an ignored extension without constructing its tree. */
  private skipValue(depth: number): void {
    this.checkDepth(depth);
    this.spendStructural();
    const ib = this.byte();
    const major = ib >> 5;
    const ai = ib & 0x1f;
    switch (major) {
      case 0:
      case 1:
        this.argument(ai);
        return;
      case 2: {
        const len = asCount(this.argument(ai), MAX_BYTES);
        this.advance(len);
        return;
      }
      case 3: {
        const len = asCount(this.argument(ai), MAX_TEXT);
        const start = this.advance(len);
        validateUtf8(this.bytes, start, len);
        return;
      }
      case 4: {
        const len = asCount(this.argument(ai), MAX_BYTE_ARRAY);
        if (len === 0) return;
        if ((this.peek() >> 5) === 0) {
          for (let i = 0; i < len; i++) this.byteValue("CBOR byte array contains a non-byte");
          return;
        }
        if (len > MAX_STRUCTURAL_ARRAY) throw new CborLimitError("CBOR structural array is too large");
        for (let i = 0; i < len; i++) this.skipValue(depth + 1);
        return;
      }
      case 5: {
        const len = asCount(this.argument(ai), MAX_MAP);
        for (let i = 0; i < len; i++) {
          this.mapKey(depth + 1);
          this.skipValue(depth + 1);
        }
        return;
      }
      case 6:
        throw new Error("CBOR tags are not used by the DAG schema");
      case 7:
        if (ai === 20 || ai === 21 || ai === 22) return;
        if (ai === 23) throw new Error("CBOR undefined is not used by the DAG schema");
        if (ai === 25) {
          this.take(2);
          throw new Error("CBOR float16 not used here");
        }
        if (ai === 26) {
          this.take(4);
          throw new Error("CBOR float32 not used here");
        }
        if (ai === 27) {
          this.take(8);
          throw new Error("CBOR float64 not used here");
        }
        throw new Error("CBOR simple value");
      default:
        throw new Error("CBOR unknown major type");
    }
  }

  value(depth: number): CborValue {
    this.checkDepth(depth);
    this.spendStructural();
    const ib = this.byte();
    const major = ib >> 5;
    const ai = ib & 0x1f;
    switch (major) {
      case 0:
        return this.argument(ai);
      case 1: {
        const n = this.argument(ai);
        if (typeof n === "bigint") return -n - 1n;
        return -n - 1;
      }
      case 2: {
        const len = asCount(this.argument(ai), MAX_BYTES);
        return this.take(len);
      }
      case 3: {
        const len = asCount(this.argument(ai), MAX_TEXT);
        return this.decodeText(this.take(len));
      }
      case 4: {
        const len = asCount(this.argument(ai), MAX_BYTE_ARRAY);
        if (len === 0) return [];

        // In the schemas supported here, a non-empty array beginning with an
        // unsigned integer is a Vec<u8>/CID. Reject a mixed array instead of
        // rewinding into an attacker-controlled boxed allocation.
        if ((this.peek() >> 5) === 0) {
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            const ib = this.byte();
            if ((ib >> 5) !== 0) throw new Error("CBOR byte array contains a non-byte");
            const byte = this.argument(ib & 0x1f);
            if (typeof byte !== "number" || !Number.isInteger(byte) || byte > 255) {
              throw new Error("CBOR byte array contains a non-byte");
            }
            bytes[i] = byte;
          }
          return bytes;
        }

        if (len > MAX_STRUCTURAL_ARRAY) throw new CborLimitError("CBOR structural array is too large");
        const arr: CborValue[] = [];
        for (let i = 0; i < len; i++) arr.push(this.value(depth + 1));
        return arr;
      }
      case 5: {
        const len = asCount(this.argument(ai), MAX_MAP);
        const map = Object.create(null) as { [key: string]: CborValue };
        for (let i = 0; i < len; i++) {
          const k = this.value(depth + 1);
          if (typeof k !== "string") throw new Error("CBOR map key must be text");
          if (FORBIDDEN_MAP_KEYS.has(k)) throw new Error("CBOR map key is forbidden");
          if (Object.hasOwn(map, k)) throw new Error(`CBOR map has duplicate key ${k}`);
          map[k] = this.value(depth + 1);
        }
        return map;
      }
      case 6:
        throw new Error("CBOR tags are not used by the DAG schema");
      case 7:
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        if (ai === 23) throw new Error("CBOR undefined is not used by the DAG schema");
        if (ai === 25) {
          this.take(2);
          throw new Error("CBOR float16 not used here");
        }
        if (ai === 26) {
          this.take(4);
          throw new Error("CBOR float32 not used here");
        }
        if (ai === 27) {
          this.take(8);
          throw new Error("CBOR float64 not used here");
        }
        throw new Error("CBOR simple value");
      default:
        throw new Error("CBOR unknown major type");
    }
  }
}

/** Allocation-free fatal UTF-8 validation for ignored schema fields. */
function validateUtf8(bytes: Uint8Array, start = 0, length = bytes.length): void {
  const end = start + length;
  for (let i = start; i < end; i++) {
    const first = bytes[i];
    if (first <= 0x7f) continue;
    if (first >= 0xc2 && first <= 0xdf) {
      if (++i >= end || !continuation(bytes[i])) throw new Error("CBOR text is not valid UTF-8");
      continue;
    }
    if (first >= 0xe0 && first <= 0xef) {
      if (++i >= end) throw new Error("CBOR text is not valid UTF-8");
      const second = bytes[i];
      const secondOk =
        first === 0xe0
          ? second >= 0xa0 && second <= 0xbf
          : first === 0xed
            ? second >= 0x80 && second <= 0x9f
            : continuation(second);
      if (!secondOk || ++i >= end || !continuation(bytes[i])) {
        throw new Error("CBOR text is not valid UTF-8");
      }
      continue;
    }
    if (first >= 0xf0 && first <= 0xf4) {
      if (++i >= end) throw new Error("CBOR text is not valid UTF-8");
      const second = bytes[i];
      const secondOk =
        first === 0xf0
          ? second >= 0x90 && second <= 0xbf
          : first === 0xf4
            ? second >= 0x80 && second <= 0x8f
            : continuation(second);
      if (
        !secondOk ||
        ++i >= end ||
        !continuation(bytes[i]) ||
        ++i >= end ||
        !continuation(bytes[i])
      ) {
        throw new Error("CBOR text is not valid UTF-8");
      }
      continue;
    }
    throw new Error("CBOR text is not valid UTF-8");
  }
}

function continuation(byte: number | undefined): boolean {
  return byte !== undefined && byte >= 0x80 && byte <= 0xbf;
}

function asCount(n: number | bigint, max: number): number {
  if (typeof n === "bigint") {
    if (n < 0n) throw new Error("CBOR length out of range");
    if (n > BigInt(max)) throw new CborLimitError("CBOR length exceeds its structural limit");
    return Number(n);
  }
  if (!Number.isInteger(n) || n < 0) {
    throw new Error("CBOR length out of range");
  }
  if (n > max) throw new CborLimitError("CBOR length exceeds its structural limit");
  return n;
}

function write(out: number[], value: CborValue): void {
  if (value === null) {
    out.push(0xf6);
    return;
  }
  if (typeof value === "boolean") {
    out.push(value ? 0xf5 : 0xf4);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("CBOR encode: floats unused");
    writeInt(out, value);
    return;
  }
  if (typeof value === "bigint") {
    if (value >= 0n) writeUint(out, value);
    else writeUint(out, -value - 1n, 1);
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    writeHeader(out, 3, bytes.length);
    for (const b of bytes) out.push(b);
    return;
  }
  if (value instanceof Uint8Array) {
    writeHeader(out, 2, value.length);
    for (const b of value) out.push(b);
    return;
  }
  if (Array.isArray(value)) {
    writeHeader(out, 4, value.length);
    for (const item of value) write(out, item);
    return;
  }
  const keys = Object.keys(value);
  writeHeader(out, 5, keys.length);
  for (const k of keys) {
    write(out, k);
    write(out, value[k]);
  }
}

function writeInt(out: number[], n: number): void {
  if (n >= 0) writeUint(out, n, 0);
  else writeUint(out, -n - 1, 1);
}

function writeUint(out: number[], n: number | bigint, major = 0): void {
  const v = typeof n === "bigint" ? n : BigInt(n);
  if (v < 24n) {
    out.push((major << 5) | Number(v));
  } else if (v < 256n) {
    out.push((major << 5) | 24, Number(v));
  } else if (v < 65536n) {
    out.push((major << 5) | 25, Number(v >> 8n), Number(v & 0xffn));
  } else if (v < 0x100000000n) {
    out.push((major << 5) | 26);
    pushU32(out, Number(v));
  } else {
    out.push((major << 5) | 27);
    let rest = v;
    const bytes = new Array<number>(8);
    for (let i = 7; i >= 0; i--) {
      bytes[i] = Number(rest & 0xffn);
      rest >>= 8n;
    }
    for (const b of bytes) out.push(b);
  }
}

function writeHeader(out: number[], major: number, len: number): void {
  writeUint(out, len, major);
}

function pushU32(out: number[], n: number): void {
  out.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function asMap(value: CborValue): { [key: string]: CborValue } {
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array) {
    throw new Error("expected CBOR map");
  }
  return value;
}

export function asArray(value: CborValue): CborValue[] {
  if (!Array.isArray(value)) throw new Error("expected CBOR array");
  return value;
}

export function optional(value: CborValue | undefined): CborValue | undefined {
  if (value === undefined || value === null) return undefined;
  return value;
}

export function required(map: { [key: string]: CborValue }, key: string): CborValue {
  if (!Object.hasOwn(map, key)) throw new Error(`missing required field ${key}`);
  return map[key];
}

export function hasOwn(map: { [key: string]: CborValue }, key: string): boolean {
  return Object.hasOwn(map, key);
}
