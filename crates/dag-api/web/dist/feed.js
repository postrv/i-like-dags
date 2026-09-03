/** Rendering and filtering for the event feed, shared by Overview and Events. */
import { abbreviate, clock } from './format.js';
import { cidChip, esc, pill, queryAll } from './ui.js';
import { EVENT_KINDS, kindOf, statusName } from './types.js';
/** Kinds currently shown. Persists across view switches within a session. */
export const activeKinds = new Set(EVENT_KINDS);
/** One row of the feed. `fresh` triggers the arrival animation. */
export function feedRow(envelope, fresh = false) {
    const event = envelope.event;
    let subject;
    let detail;
    switch (event.type) {
        case 'PointerUpdate':
            subject = event.id;
            detail = cidChip(event.new);
            break;
        case 'PinEvent':
            subject = abbreviate(event.id);
            detail = pill(event.action, event.action === 'created' ? 'ok' : 'neutral');
            break;
        case 'JobRun': {
            const status = statusName(event.status);
            subject = event.job;
            detail = pill(`run #${event.run} ${status.toLowerCase()}`, status === 'Succeeded' ? 'ok' : status === 'Failed' ? 'bad' : 'neutral');
            break;
        }
        case 'StorageHealth':
            subject = event.check;
            detail = pill(event.ok ? 'ok' : 'failed', event.ok ? 'ok' : 'bad');
            break;
    }
    return `<li data-kind="${kindOf(event)}" class="${fresh ? 'fresh' : ''}">
    <span class="seq">${envelope.seq}</span>
    ${pill(kindOf(event))}
    <span class="mono feed-subject">${esc(subject)} ${detail}</span>
    <span class="when">${clock(envelope.envelope_ts)}</span>
  </li>`;
}
/**
 * A notice that the live stream dropped events for this client.
 *
 * Deliberately carries no `data-kind`: it is not one of the filterable streams,
 * and `applyFilter` leaves rows without a kind alone. A loss notice that the
 * filter could hide would be worse than none, because the console always
 * filters.
 */
export function laggedRow(missed) {
    return `<li class="fresh notice">
    <span class="seq">—</span>
    ${pill('lagged', 'bad')}
    <span class="mono feed-subject">dropped ${missed} event${missed === 1 ? '' : 's'} — this client fell behind the stream</span>
    <span class="when"></span>
  </li>`;
}
/** A durable-resume gap that requires an authoritative state refresh. */
export function replayRequiredRow(message) {
    return `<li class="fresh notice">
    <span class="seq">—</span>
    ${pill('replay required', 'bad')}
    <span class="mono feed-subject">${esc(message)}</span>
    <span class="when"></span>
  </li>`;
}
/** Newest first, which is how a feed is read. */
export function feedRows(events) {
    return events.slice().reverse().map((e) => feedRow(e)).join('');
}
/** Apply the current kind filter to whatever feed is on screen. */
export function applyFilter() {
    for (const item of queryAll('#feed li')) {
        const kind = item.dataset['kind'];
        item.hidden = kind ? !activeKinds.has(kind) : false;
    }
}
/** Toggle a kind and re-apply the filter. Returns the new state. */
export function toggleKind(kind) {
    if (activeKinds.has(kind))
        activeKinds.delete(kind);
    else
        activeKinds.add(kind);
    applyFilter();
    return activeKinds.has(kind);
}
