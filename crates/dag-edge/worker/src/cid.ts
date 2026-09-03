import { EMPTY_CID_HEX } from "./limits.ts";

export const CID_LEN = 32;

const HEX = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0xf];
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Parse a 64-character hex CID. Length is checked, not just the alphabet. */
export function parseCidHex(hex: string): string {
  if (hex.length !== CID_LEN * 2 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("CID must be 64 hex characters");
  }
  return hex.toLowerCase();
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return new Uint8Array(digest);
}

export async function computeCidHex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(bytes));
}

/** A zero-length object is missing unless it is the empty digest. */
export function isTorn(size: number, cidHex: string): boolean {
  return size === 0 && cidHex !== EMPTY_CID_HEX;
}

/** Turn a CBOR CID (byte string or array of 0–255 ints) into hex. */
export function cidFromCbor(value: unknown): string {
  if (value instanceof Uint8Array) {
    if (value.length !== CID_LEN) {
      throw new Error(`CID must be ${CID_LEN} bytes`);
    }
    return bytesToHex(value);
  }
  if (Array.isArray(value)) {
    if (value.length !== CID_LEN) {
      throw new Error(`CID must be ${CID_LEN} bytes`);
    }
    const bytes = new Uint8Array(CID_LEN);
    for (let i = 0; i < CID_LEN; i++) {
      const n = value[i];
      if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 255) {
        throw new Error("CID array must be bytes");
      }
      bytes[i] = n;
    }
    return bytesToHex(bytes);
  }
  throw new Error("CID is not a byte string or byte array");
}

export function cidToIntArray(hex: string): number[] {
  const bytes = hexToBytes(parseCidHex(hex));
  return Array.from(bytes);
}
