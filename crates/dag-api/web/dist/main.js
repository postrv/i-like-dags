/**
 * Entry point: routing, global actions, the live stream and the theme toggle.
 */
import { api } from './api.js';
import { closeDrawer, openNode } from './drawer.js';
import { bytes, isCid, shortCid } from './format.js';
import { applyFilter, feedRow, laggedRow, replayRequiredRow, toggleKind } from './feed.js';
import { bindGraphNodes, isViewName, views } from './views.js';
import { card, cidChip, esc, need, query, queryAll, toast } from './ui.js';
import { EVENT_KINDS } from './types.js';
function parseRoute() {
    const raw = location.hash.replace(/^#\/?/, '') || 'overview';
    const [name = '', queryString = ''] = raw.split('?');
    return {
        name: isViewName(name) ? name : 'overview',
        params: Object.fromEntries(new URLSearchParams(queryString)),
    };
}
let current = { name: 'overview', params: {} };
async function render() {
    current = parseRoute();
    for (const link of queryAll('.rail a')) {
        if (link.dataset['view'] === current.name)
            link.setAttribute('aria-current', 'page');
        else
            link.removeAttribute('aria-current');
    }
    try {
        await views[current.name](current.params);
        if (current.name === 'explorer') {
            bindGraphNodes(openNode);
            showLastUpload();
        }
        if (current.name === 'events' || current.name === 'overview')
            applyFilter();
    }
    catch (e) {
        need('#view').innerHTML = `<div class="card">
      <div class="empty">Could not load this view: ${esc(e instanceof Error ? e.message : e)}</div>
    </div>`;
    }
    await refreshStats();
}
// ---- shared chrome ---------------------------------------------------
async function refreshStats() {
    let stats;
    try {
        stats = await api.stats();
    }
    catch {
        // The stream indicator already reports connectivity; don't double-report.
        return;
    }
    const railStats = [
        ['chunks', stats.chunks],
        ['size', bytes(stats.bytes)],
        ['pointers', stats.pointers],
        ['pins', `${stats.active_pins}/${stats.pins}`],
        ['jobs', stats.jobs],
        ['events', stats.event_seq],
    ];
    need('#rail-stats').innerHTML = railStats
        .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
        .join('');
    // The recovery gate is the one piece of global state that changes what the
    // system will let you do, so it is surfaced on every view rather than buried.
    need('#banner').innerHTML = stats.recovered ? '' : `
    <div class="banner banner-warn">
      <strong>Recovery incomplete.</strong>
      <span>Collection is blocked. Stop this server and run <code>dag recover</code>
        so the bounded offline recovery can reconcile every safety index.</span>
    </div>`;
}
// ---- actions ---------------------------------------------------------
/** Run an async action with button feedback, a toast, and a re-render. */
async function act(button, label, fn) {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = '…';
    try {
        const message = await fn();
        toast(message, 'ok');
        await render();
    }
    catch (e) {
        toast(`${label} failed: ${e instanceof Error ? e.message : e}`, 'bad');
    }
    finally {
        button.disabled = false;
        button.textContent = original;
    }
}
function showReport(title, pairs) {
    const host = query('#report');
    if (!host)
        return;
    host.innerHTML = card(title, `<div class="card-body"><dl class="kv">
    ${pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="nums">${esc(v)}</dd>`).join('')}
  </dl></div>`);
}
function showLineage(report) {
    const host = query('#report');
    if (!host)
        return;
    host.innerHTML = card(`Provenance — ${report.pointer}`, `<div class="card-body">
    <ul class="lineage">${report.nodes.map((n) => `<li>
      <span class="indent" style="--depth:${n.depth}"></span>
      <span class="rule"></span>
      <span class="${n.intact ? 'ok-mark' : 'bad-mark'}">${n.intact ? '✓' : '✗'}</span>
      ${cidChip(n.cid)}
      <span class="muted">${esc(n.name ?? 'root')}</span>
      <span class="muted nums">${bytes(n.size)}</span>
    </li>`).join('')}</ul>
    <p class="lineage-summary">
      ${report.intact} of ${report.total_nodes} nodes re-hashed to their recorded CID.
      Retention: ${report.retained ? 'protected' : 'not pinned'}.
    </p>
  </div>`);
}
const actions = {
    seed: (button) => act(button, 'Load example', async () => {
        const report = await api.seed();
        location.hash = `#/explorer?pointer=${encodeURIComponent(report.production_pointer)}`;
        return `Loaded ${report.chunks} chunks across ${report.pointers} pointers`;
    }),
    'gc-dry': (button) => act(button, 'Collection', async () => {
        const report = await api.collect({ dry_run: true, min_age_secs: 0 });
        showReport('Collection (dry run)', [
            ['examined', report.examined],
            ['would delete', report.deleted],
            ['would free', bytes(report.bytes_freed)],
            ['held by pins', report.protected_by_pins],
            ['held by system policy', report.protected_by_system],
            ['too young', report.skipped_too_young],
            ['duration', `${report.duration_ms} ms`],
        ]);
        return `Would delete ${report.deleted} of ${report.examined} chunks`;
    }),
    verify: (button) => act(button, 'Verification', async () => {
        const report = await api.verify();
        showLineage(report);
        return report.verified
            ? `All ${report.total_nodes} nodes verified against their digests`
            : `${report.corrupt} of ${report.total_nodes} nodes failed verification`;
    }),
    unpin: (button) => act(button, 'Release', async () => {
        const id = button.dataset['id'] ?? '';
        await api.deactivatePin(id);
        return `Released ${id}`;
    }),
    'run-job': (button) => act(button, 'Run', async () => {
        const id = button.dataset['id'] ?? '';
        const outcome = await api.runJob(id);
        return `Run #${outcome.run_id} produced ${outcome.outputs.length} output(s)`;
    }),
};
document.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof Element))
        return;
    const trigger = target.closest('button[data-act]');
    if (trigger) {
        const action = actions[trigger.dataset['act'] ?? ''];
        if (action)
            void action(trigger);
        return;
    }
    const chip = target.closest('.chip[data-kind]');
    if (chip) {
        const kind = chip.dataset['kind'];
        if (kind)
            chip.setAttribute('aria-pressed', String(toggleKind(kind)));
    }
});
/**
 * The most recent upload, shown after `act` re-renders the view.
 *
 * `act` calls `render()` on success, which replaces the explorer's markup — so
 * the result has to survive that rather than be written into the old DOM.
 */
let lastUpload = null;
/** Paint the last upload's result into a freshly rendered explorer. */
function showLastUpload() {
    if (!lastUpload)
        return;
    const slot = query('#upload-result');
    if (!slot)
        return;
    slot.innerHTML = `<p class="cell-note">Stored ${esc(lastUpload.name)} — ${esc(lastUpload.summary)}.</p><div class="chips">${cidChip(lastUpload.cid, shortCid(lastUpload.cid))}</div>`;
}
document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement))
        return;
    if (form.id === 'explore-form') {
        event.preventDefault();
        const data = new FormData(form);
        const q = String(data.get('q') ?? '').trim();
        const key = isCid(q) ? 'cid' : 'pointer';
        location.hash = `#/explorer?${key}=${encodeURIComponent(q)}&depth=${data.get('depth')}`;
        void render();
        return;
    }
    if (form.id === 'upload-form') {
        event.preventDefault();
        const input = form.querySelector('input[name=file]');
        const submit = form.querySelector('button[type=submit]');
        const file = input?.files?.[0];
        if (!file || !submit)
            return;
        const chunked = Boolean(new FormData(form).get('chunked'));
        void act(submit, 'Store', async () => {
            const up = await api.uploadFile(file, chunked);
            // `new_chunks` counts paths absent before this upload. Existing paths
            // are still integrity-checked and repaired if necessary, but remain on
            // the deduplicated side of this accounting value.
            const detail = up.chunked
                ? `${up.chunks} chunks, ${up.new_chunks} new`
                : 'single chunk';
            lastUpload = { cid: up.cid, name: file.name, summary: `${bytes(up.size)}, ${detail}` };
            return `Stored ${file.name} — ${bytes(up.size)}, ${detail}`;
        });
        return;
    }
    if (form.id === 'pin-form') {
        event.preventDefault();
        const data = new FormData(form);
        const submit = form.querySelector('button[type=submit]');
        if (!submit)
            return;
        void act(submit, 'Pin', async () => {
            const id = String(data.get('id'));
            const ttl = data.get('ttl_secs');
            await api.createPin({
                id,
                cid: String(data.get('cid')).trim(),
                subtree: data.get('subtree') === 'true',
                ttl_secs: ttl ? Number(ttl) : null,
                author: 'console',
            });
            return `Pinned ${id}`;
        });
    }
});
need('#drawer-close').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape')
        closeDrawer();
});
// ---- live stream -----------------------------------------------------
// The stream is a nudge, not authoritative state: on each event the console
// re-fetches whatever the current view needs. Every successful connection also
// refreshes after the server has subscribed, so startup and reconnect have no
// unobserved gap. Explicit loss closes the stale EventSource and constructs a
// fresh one without its unsatisfiable Last-Event-ID.
let coalesce;
function setConnection(state, label) {
    need('#conn').dataset['state'] = state;
    need('#conn-label').textContent = label;
}
/** Push a row onto the live feed, keeping it bounded. */
function pushFeedRow(html) {
    const feed = query('#feed');
    if (!feed)
        return;
    feed.insertAdjacentHTML('afterbegin', html);
    for (const stale of [...feed.children].slice(200))
        stale.remove();
    applyFilter();
}
function nudge() {
    // Coalesce bursts: seeding the example emits a dozen events at once.
    clearTimeout(coalesce);
    coalesce = setTimeout(() => {
        if (current.name === 'events')
            void refreshStats();
        else
            void render();
    }, 250);
}
function connect() {
    const source = new EventSource('/api/events/stream');
    let resetting = false;
    source.onopen = () => {
        setConnection('live', 'live');
        // The server subscribes before returning SSE headers. Refreshing now means
        // mutations during the refresh are either in that snapshot or queued as a
        // subsequent nudge, including after an ordinary network reconnect.
        void render();
    };
    // EventSource reconnects on its own; say so rather than implying a dead end.
    source.onerror = () => {
        if (!resetting)
            setConnection('down', 'reconnecting');
    };
    // The server names every message after its event kind, and a named SSE
    // message is dispatched under that name — `onmessage` only ever fires for
    // unnamed ones, so listening there received nothing at all.
    for (const kind of EVENT_KINDS) {
        source.addEventListener(kind, (message) => {
            let envelope;
            try {
                envelope = JSON.parse(message.data);
            }
            catch {
                return;
            }
            pushFeedRow(feedRow(envelope, true));
            nudge();
        });
    }
    // A subscriber that falls behind has events dropped for it. The gap cannot
    // be read off the sequence numbers — this console filters, so gaps are
    // routine — so the server sends the count and we show it.
    source.addEventListener('lagged', (message) => {
        let missed = 0;
        try {
            missed = JSON.parse(message.data).missed;
        }
        catch {
            return;
        }
        pushFeedRow(laggedRow(missed));
        toast(`Live event stream dropped ${missed} event${missed === 1 ? '' : 's'}; reconciling`, 'bad');
        nudge();
    });
    source.addEventListener('replay-required', (message) => {
        if (resetting)
            return;
        let loss = null;
        try {
            const parsed = JSON.parse(message.data);
            if (parsed !== null && typeof parsed === 'object') {
                loss = parsed;
            }
        }
        catch {
            // A malformed loss notice is itself grounds to distrust continuity.
        }
        const detail = typeof loss?.message === 'string'
            ? loss.message
            : 'event continuity could not be verified; refreshing authoritative state';
        resetting = true;
        source.close();
        setConnection('down', 'reconciling');
        pushFeedRow(replayRequiredRow(detail));
        toast(`Live event replay required: ${detail}`, 'bad');
        // A new EventSource has an empty Last-Event-ID buffer. Its `onopen`
        // refreshes authoritative state only after the replacement subscription
        // exists, closing the refresh/stream race without rendering every missed
        // event individually.
        connect();
    });
}
// ---- theme -----------------------------------------------------------
const THEME_KEY = 'dag-console-theme';
function applyTheme(theme) {
    if (theme)
        document.documentElement.setAttribute('data-theme', theme);
    else
        document.documentElement.removeAttribute('data-theme');
    need('#theme-icon').textContent = theme === 'dark' ? '●' : theme === 'light' ? '○' : '◐';
}
function storedTheme() {
    const value = localStorage.getItem(THEME_KEY);
    return value === 'light' || value === 'dark' ? value : null;
}
applyTheme(storedTheme());
need('#theme-toggle').addEventListener('click', () => {
    // Cycle system → light → dark so the OS preference stays reachable.
    const next = storedTheme() === null ? 'light' : storedTheme() === 'light' ? 'dark' : null;
    if (next)
        localStorage.setItem(THEME_KEY, next);
    else
        localStorage.removeItem(THEME_KEY);
    applyTheme(next);
});
// ---- boot ------------------------------------------------------------
window.addEventListener('hashchange', () => void render());
// Avoid racing two initial renders. The first paints immediately; the
// subscription's `onopen` then performs the authoritative post-subscribe
// reconciliation that closes the startup gap.
void render().finally(connect);
