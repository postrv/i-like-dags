import { MAX_ID_BYTES } from "./limits.ts";

// Terminal controls and Unicode bidi controls make authenticated control-plane
// names unsafe to log, diagnose, or compare by eye. Do not reject all Cf:
// ZWNJ/ZWJ are legitimate parts of Persian/Indic text and emoji sequences.
const UNSAFE_IDENTIFIER_CODE_POINT =
  /[\p{Cc}\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;

export function checkPointerId(id: string): string | null {
  if (!id.isWellFormed()) return "pointer id must be well-formed Unicode";
  if (utf8Length(id) > MAX_ID_BYTES) return "pointer id too long (max 256 bytes)";
  if (UNSAFE_IDENTIFIER_CODE_POINT.test(id)) {
    return "pointer id cannot contain Unicode control or format characters";
  }
  return null;
}

export function checkPinId(id: string): string | null {
  if (!id.isWellFormed()) return "Pin ID must be well-formed Unicode";
  if (id.length === 0) return "Pin ID cannot be empty";
  if (utf8Length(id) > MAX_ID_BYTES) return "Pin ID cannot exceed 256 bytes";
  if (UNSAFE_IDENTIFIER_CODE_POINT.test(id)) {
    return "Pin ID cannot contain Unicode control or format characters";
  }
  return null;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
