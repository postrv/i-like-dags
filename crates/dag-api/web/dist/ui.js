/** Small DOM and markup helpers shared by every view. */
import { shortCid, swatch } from './format.js';
/** Escape a value for interpolation into HTML. */
export function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}
export function query(selector, root = document) {
    return root.querySelector(selector);
}
/** Query an element that the page is known to contain; throws if the markup drifts. */
export function need(selector, root = document) {
    const element = root.querySelector(selector);
    if (!element)
        throw new Error(`missing element: ${selector}`);
    return element;
}
export function queryAll(selector, root = document) {
    return [...root.querySelectorAll(selector)];
}
/** A clickable content-address chip. Clicking any CID opens it in the Explorer. */
export function cidChip(cid, label) {
    if (!cid)
        return '<span class="muted">—</span>';
    return `<a class="cid" href="#/explorer?cid=${encodeURIComponent(cid)}" title="${esc(cid)}">
    <span class="cid-swatch" style="background:${swatch(cid)}"></span>
    <span class="cid-text">${esc(label ?? shortCid(cid))}</span>
  </a>`;
}
export function card(title, body, tools = '') {
    return `<section class="card">
    <div class="card-head"><h2>${esc(title)}</h2><div class="actions">${tools}</div></div>
    ${body}
  </section>`;
}
export function table(headers, rows) {
    return `<div class="table-wrap"><table>
    <thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('')}</tbody>
  </table></div>`;
}
export function empty(message) {
    return `<div class="empty">${esc(message)}</div>`;
}
export function viewHead(title, blurb, actions = '') {
    return `<div class="view-head">
    <div><h1>${esc(title)}</h1><p>${esc(blurb)}</p></div>
    <div class="actions">${actions}</div>
  </div>`;
}
export function pill(text, tone = 'neutral') {
    const cls = tone === 'neutral' ? '' : `pill-${tone}`;
    return `<span class="pill ${cls}">${esc(text)}</span>`;
}
export function toast(message, kind = '') {
    const host = query('#toasts');
    if (!host)
        return;
    const el = document.createElement('div');
    el.className = kind ? `toast toast-${kind}` : 'toast';
    el.textContent = message;
    host.append(el);
    setTimeout(() => el.remove(), 5000);
}
