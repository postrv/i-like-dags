/** Small DOM and markup helpers shared by every view. */

import { shortCid, swatch } from './format.js';
import type { Cid } from './types.js';

/** Escape a value for interpolation into HTML. */
export function esc(value: unknown): string {
  return String(value ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c,
  );
}

export function query<T extends Element>(selector: string, root: ParentNode = document): T | null {
  return root.querySelector<T>(selector);
}

/** Query an element that the page is known to contain; throws if the markup drifts. */
export function need<T extends Element>(selector: string, root: ParentNode = document): T {
  const element = root.querySelector<T>(selector);
  if (!element) throw new Error(`missing element: ${selector}`);
  return element;
}

export function queryAll<T extends Element>(selector: string, root: ParentNode = document): T[] {
  return [...root.querySelectorAll<T>(selector)];
}

/** A clickable content-address chip. Clicking any CID opens it in the Explorer. */
export function cidChip(cid: Cid | null | undefined, label?: string): string {
  if (!cid) return '<span class="muted">—</span>';
  return `<a class="cid" href="#/explorer?cid=${encodeURIComponent(cid)}" title="${esc(cid)}">
    <span class="cid-swatch" style="background:${swatch(cid)}"></span>
    <span class="cid-text">${esc(label ?? shortCid(cid))}</span>
  </a>`;
}

export function card(title: string, body: string, tools = ''): string {
  return `<section class="card">
    <div class="card-head"><h2>${esc(title)}</h2><div class="actions">${tools}</div></div>
    ${body}
  </section>`;
}

export function table(headers: string[], rows: string[]): string {
  return `<div class="table-wrap"><table>
    <thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('')}</tbody>
  </table></div>`;
}

export function empty(message: string): string {
  return `<div class="empty">${esc(message)}</div>`;
}

export function viewHead(title: string, blurb: string, actions = ''): string {
  return `<div class="view-head">
    <div><h1>${esc(title)}</h1><p>${esc(blurb)}</p></div>
    <div class="actions">${actions}</div>
  </div>`;
}

export function pill(text: string, tone: 'ok' | 'warn' | 'bad' | 'neutral' = 'neutral'): string {
  const cls = tone === 'neutral' ? '' : `pill-${tone}`;
  return `<span class="pill ${cls}">${esc(text)}</span>`;
}

export type ToastKind = 'ok' | 'bad' | '';

export function toast(message: string, kind: ToastKind = ''): void {
  const host = query('#toasts');
  if (!host) return;
  const el = document.createElement('div');
  el.className = kind ? `toast toast-${kind}` : 'toast';
  el.textContent = message;
  host.append(el);
  setTimeout(() => el.remove(), 5000);
}
