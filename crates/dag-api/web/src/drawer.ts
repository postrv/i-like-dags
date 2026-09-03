/** The node detail drawer. */

import { api } from './api.js';
import { bytes, shortCid } from './format.js';
import { cidChip, esc, need, pill, query } from './ui.js';
import type { Cid, SignatureStatus } from './types.js';

/**
 * Render the signatures over a CID.
 *
 * `trusted` and `valid` are shown as separate verdicts on purpose. A valid but
 * untrusted signature is self-consistent and proves nothing about who made it:
 * the key it names is the signer's own claim, and only the local keyring can
 * vouch for that. Collapsing the two into one tick would invite exactly the
 * mistake the signing layer exists to prevent.
 */
function signatureRows(sigs: SignatureStatus[]): string {
  if (!sigs.length) {
    return '<p class="cell-note">Not signed.</p>';
  }
  return `<ul class="sig-list">${sigs.map((s) => {
    const verdict = s.trusted
      ? pill('trusted', 'ok')
      : s.valid
        ? pill('valid, untrusted key')
        : pill('invalid', 'bad');
    return `<li>
      ${verdict}
      <span class="mono cell-note">${esc(s.key_id.slice(0, 16))}</span>
      ${s.signer ? `<span class="cell-note">${esc(s.signer)}</span>` : ''}
    </li>`;
  }).join('')}</ul>`;
}

/** Open the drawer on a CID, loading its entry and retention side by side. */
export async function openNode(cid: Cid): Promise<void> {
  const drawer = need<HTMLElement>('#drawer');
  drawer.hidden = false;
  need('#drawer-title').textContent = shortCid(cid);

  const body = need('#drawer-body');
  body.innerHTML = '<div class="empty">Loading…</div>';

  try {
    // Signatures are optional context, not a precondition for the panel: a
    // failure to load them must not blank out the entry itself.
    const [entry, retention, sigs] = await Promise.all([
      api.entry(cid),
      api.retention(cid),
      api.signatures(cid).catch(() => null),
    ]);

    const links = entry.links.length
      ? `<div class="section-label">Links (${entry.links.length})</div>
         <div class="chips">${entry.links.map((l) =>
           cidChip(l.target, l.name ?? shortCid(l.target))).join('')}</div>`
      : '';

    const retained = retention.protected
      ? `${pill('protected', 'ok')}
         <div class="cell-note">${
           retention.sources.length ? esc(retention.sources.join(', ')) : 'system data policy'
         }</div>`
      : pill('collectable');

    body.innerHTML = `<div class="drawer-body">
      <dl class="kv">
        <dt>cid</dt><dd class="mono cid-full">${esc(entry.cid)}</dd>
        <dt>size</dt><dd class="nums">${bytes(entry.size)}</dd>
        <dt>kind</dt><dd>${entry.is_entry ? 'DAG entry' : 'raw chunk'}</dd>
        <dt>type</dt><dd>${esc(entry.content_type ?? '—')}</dd>
        <dt>integrity</dt><dd>${pill(
          entry.intact ? 'bytes match digest' : 'digest mismatch',
          entry.intact ? 'ok' : 'bad',
        )}</dd>
        <dt>retention</dt><dd>${retained}</dd>
      </dl>
      ${links}
      <div class="section-label">Payload</div>
      <pre class="payload">${esc(entry.preview ?? '')}</pre>
      ${entry.truncated ? '<p class="cell-note">Preview truncated.</p>' : ''}
      <div class="section-label">Signatures${
        sigs
          ? ` (${sigs.signatures.length}${sigs.truncated ? '+' : ''}, ${sigs.trusted}${sigs.trusted_complete ? '' : '+'} trusted)`
          : ''
      }</div>
      ${sigs ? signatureRows(sigs.signatures) : '<p class="cell-note">Unavailable.</p>'}
      ${sigs?.truncated
        ? '<p class="cell-note">More signatures are available through the paginated API.</p>'
        : ''}
      <div class="section-label">Download</div>
      <div class="chips">
        <a class="btn btn-sm" href="${api.fileUrl(entry.cid)}" download="${entry.cid}">File</a>
        <a class="btn btn-sm btn-ghost" href="/api/chunks?cid=${entry.cid}" download="${entry.cid}">Raw chunk</a>
      </div>
      <p class="cell-note">
        &ldquo;File&rdquo; reassembles a chunked manifest; &ldquo;raw chunk&rdquo; returns these bytes exactly.
      </p>
    </div>`;
  } catch (e) {
    body.innerHTML = `<div class="empty">${esc(e instanceof Error ? e.message : e)}</div>`;
  }
}

/** Close the drawer if it is open. */
export function closeDrawer(): void {
  const drawer = query<HTMLElement>('#drawer');
  if (drawer) drawer.hidden = true;
}
