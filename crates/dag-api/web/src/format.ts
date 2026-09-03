/** Presentation helpers: hashes, sizes and times. */

import type { Cid, Unix } from './types.js';

/** First eight and last four hex characters — enough to recognise, short enough to scan. */
export function shortCid(cid: Cid | null | undefined): string {
  if (!cid) return '';
  return cid.length > 16 ? `${cid.slice(0, 8)}…${cid.slice(-4)}` : cid;
}

/** Byte count with a binary unit suffix. */
export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${n} B` : `${value.toFixed(1)} ${units[unit]}`;
}

/**
 * Coarse relative time, in either direction.
 *
 * Pin expiry timestamps are in the future, so a past-only formatter would
 * render "expires in an hour" as "0s ago".
 */
export function when(unix: Unix | null | undefined): string {
  if (!unix) return '—';
  const delta = Math.floor(Date.now() / 1000) - unix;
  const magnitude = Math.abs(delta);

  if (magnitude >= 86400) return new Date(unix * 1000).toISOString().slice(0, 10);

  const amount = magnitude < 60
    ? `${magnitude}s`
    : magnitude < 3600
      ? `${Math.floor(magnitude / 60)}m`
      : `${Math.floor(magnitude / 3600)}h`;

  return delta >= 0 ? `${amount} ago` : `in ${amount}`;
}

/** Wall-clock `HH:MM:SS`, for the event feed. */
export function clock(unix: Unix): string {
  return unix ? new Date(unix * 1000).toTimeString().slice(0, 8) : '';
}

/**
 * Two hues read straight out of the digest.
 *
 * A content address should look like its content: the same CID gets the same
 * colour everywhere in the console, so repeats are recognisable before you
 * have read a single hex character.
 */
export function swatchHues(cid: Cid): [number, number] {
  const byte = (at: number): number => parseInt(cid.slice(at, at + 2), 16) || 0;
  return [(byte(0) / 255) * 360, (byte(2) / 255) * 360];
}

/** CSS gradient for a CID swatch. */
export function swatch(cid: Cid): string {
  const [h1, h2] = swatchHues(cid);
  return `linear-gradient(135deg, hsl(${h1.toFixed(0)} 58% 55%), hsl(${h2.toFixed(0)} 58% 45%))`;
}

/**
 * Shorten any full digest embedded in an identifier.
 *
 * Job output pins are named after their content, so their IDs carry a 64-hex
 * run that would otherwise blow out a table column.
 */
export function abbreviate(id: string): string {
  return id.replace(/[0-9a-f]{64}/gi, (hex) => shortCid(hex));
}

/** Whether a string looks like a full content identifier. */
export function isCid(value: string): boolean {
  return /^[0-9a-f]{64}$/i.test(value.trim());
}
