/**
 * The six views.
 *
 * Each is an async function that fetches what it needs and replaces `#view`
 * wholesale. There is no client-side store: the server is the single source of
 * truth and a re-render is cheap, so nothing can drift out of sync.
 */
import { api } from './api.js';
import { abbreviate, bytes, isCid, when } from './format.js';
import { feedRows, activeKinds } from './feed.js';
import { renderGraph } from './graph.js';
import { card, cidChip, empty, esc, need, pill, queryAll, table, viewHead } from './ui.js';
import { EVENT_KINDS } from './types.js';
const slot = () => need('#view');
// ---- overview --------------------------------------------------------
const overview = async () => {
    const [stats, replay] = await Promise.all([api.stats(), api.events(12)]);
    const events = replay.events;
    const tiles = [
        ['chunks', stats.chunks, bytes(stats.bytes)],
        ['pointers', stats.pointers, 'named references'],
        ['pins active', stats.active_pins, `of ${stats.pins} total`],
        ['jobs', stats.jobs, 'registered'],
        ['event seq', stats.event_seq, 'journal head'],
        [
            'recovery',
            stats.recovered ? 'ready' : 'blocked',
            stats.recovered ? 'collection permitted' : 'rebuild required',
        ],
    ];
    const blank = stats.chunks === 0
        ? `<div class="card"><div class="empty">
        <p>Nothing stored yet.</p>
        <p>Load the worked example — a model-release provenance ledger with datasets,
           pointers, an attestation job, retention pins and a full event history.</p>
        <p><button class="btn btn-primary" data-act="seed" type="button">Load worked example</button></p>
      </div></div>`
        : '';
    slot().innerHTML = `<div class="view stack">
    ${viewHead('Overview', 'Everything the control plane knows, at a glance.', `
      <button class="btn" data-act="seed" type="button">Load example</button>
      <button class="btn" data-act="gc-dry" type="button">Collect (dry run)</button>
      <button class="btn btn-primary" data-act="verify" type="button">Verify release</button>`)}
    <dl class="tiles">${tiles.map(([k, v, sub]) => `<div class="tile"><dt>${esc(k)}</dt>
        <dd>${esc(v)}<br><small>${esc(sub)}</small></dd></div>`).join('')}</dl>
    ${blank}
    ${card('Recent activity', events.length
        ? `<ul class="feed" id="feed">${feedRows(events)}</ul>`
        : empty('No events recorded yet.'), '<a class="btn btn-sm" href="#/events">Open stream</a>')}
    <div id="report"></div>
  </div>`;
};
// ---- explorer --------------------------------------------------------
const explorer = async (params) => {
    const target = params['cid'] ?? params['pointer'] ?? '';
    const depth = Number(params['depth'] ?? 4);
    slot().innerHTML = `<div class="view stack">
    ${viewHead('Explorer', 'Walk the link graph outward from any CID or pointer. Every node is '
        + 're-hashed as it is read, so tampering shows up here first.', `<form class="actions" id="explore-form">
        <input type="text" name="q" value="${esc(target)}" size="34"
               placeholder="CID or pointer id" aria-label="CID or pointer id">
        <label class="field field-inline">depth
          <input type="number" name="depth" value="${depth}" min="1" max="8">
        </label>
        <button class="btn btn-primary" type="submit">Walk</button>
      </form>`)}
    ${card('Store a file', `<form class="actions" id="upload-form">
        <input type="file" name="file" required aria-label="File to store">
        <label class="field field-inline">
          <input type="checkbox" name="chunked"> force chunking
        </label>
        <button class="btn" type="submit">Store</button>
      </form>
      <p class="cell-note">
        Content over 4&nbsp;MiB is split into content-defined chunks behind a
        manifest, so re-storing a file that changed in one place re-sends only
        the chunks that actually changed. The result opens in the drawer.
      </p>
      <div id="upload-result"></div>`)}
    <div id="graph-slot"></div>
  </div>`;
    const graphSlot = need('#graph-slot');
    if (!target) {
        graphSlot.innerHTML = card('Graph', empty('Enter a CID, or a pointer such as models/fraud-detector/production.'));
        return;
    }
    let graph;
    try {
        graph = await api.graph(isCid(target) ? { cid: target } : { pointer: target }, depth);
    }
    catch (e) {
        graphSlot.innerHTML = card('Graph', empty(e instanceof Error ? e.message : String(e)));
        return;
    }
    graphSlot.innerHTML = card(`Graph — ${graph.nodes.length} node${graph.nodes.length === 1 ? '' : 's'}`, `<div class="graph-wrap">${renderGraph(graph)}</div>
     <div class="graph-legend">
       <span>teal outline = retained</span>
       <span>✓ intact · ✗ digest mismatch</span>
       <span>depth increases left → right</span>
       ${graph.truncated ? '<span class="legend-warn">topology truncated at a safety limit</span>' : ''}
       ${graph.pointer_labels_truncated
        ? '<span class="legend-warn">pointer labels are partial (namespace scan limit reached)</span>'
        : ''}
     </div>`, cidChip(graph.root, 'root'));
};
// ---- pointers --------------------------------------------------------
const pointers = async (params) => {
    const page = await api.pointers(params['cursor']);
    const all = page.items;
    const rows = all.map((p) => `<tr>
    <td class="mono"><a href="#/pointers?id=${encodeURIComponent(p.id)}">${esc(p.id)}</a></td>
    <td class="nums">@${p.seq}</td>
    <td>${cidChip(p.cid)}</td>
    <td><a class="btn btn-sm" href="#/explorer?pointer=${encodeURIComponent(p.id)}">Walk</a></td>
  </tr>`);
    let detail = '';
    const selected = params['id'];
    if (selected) {
        const historyPage = await api.pointerHistory(selected, params['history_cursor']);
        const history = historyPage.items;
        detail = card(`History — ${selected}`, history.length
            ? table(['seq', 'moved to', 'from', 'when'], history.slice().reverse().map((e) => `<tr>
            <td class="nums">@${e.seq}</td>
            <td>${cidChip(e.cid)}</td>
            <td>${e.previous_cid ? cidChip(e.previous_cid) : '<span class="muted">created</span>'}</td>
            <td class="muted">${esc(when(e.ts))}</td>
          </tr>`))
            : empty('No history recorded.'), historyPage.next_cursor
            ? `<a class="btn btn-sm" href="#/pointers?id=${encodeURIComponent(selected)}&history_cursor=${encodeURIComponent(historyPage.next_cursor)}">Next history page</a>`
            : '');
    }
    slot().innerHTML = `<div class="view stack">
    ${viewHead('Pointers', 'Mutable names over immutable content. Every move appends to a log, '
        + 'so the history is the audit trail.')}
    ${card('Pointers (lexicographic page)', all.length ? table(['id', 'seq', 'resolves to', ''], rows) : empty('No pointers yet.'), page.next_cursor
        ? `<a class="btn btn-sm" href="#/pointers?cursor=${encodeURIComponent(page.next_cursor)}">Next page</a>`
        : '')}
    ${detail}
  </div>`;
};
// ---- pins ------------------------------------------------------------
const pins = async (params) => {
    const page = await api.pins(params['cursor']);
    const all = page.items;
    const rows = all.map((p) => `<tr>
    <td class="mono" title="${esc(p.id)}">${esc(abbreviate(p.id))}</td>
    <td>${pill(p.active ? 'active' : 'inactive', p.active ? 'ok' : 'neutral')}</td>
    <td>${cidChip(p.target_cid)}</td>
    <td>${p.subtree
        ? pill(`subtree${p.max_depth ? ` ≤${p.max_depth}` : ''}`)
        : '<span class="muted">direct</span>'}</td>
    <td class="mono">${esc(p.scope)}</td>
    <td class="muted">${p.expires_at ? esc(when(p.expires_at)) : 'never'}</td>
    <td>${p.active
        ? `<button class="btn btn-sm btn-danger" data-act="unpin" data-id="${esc(p.id)}" type="button">Release</button>`
        : ''}</td>
  </tr>`);
    slot().innerHTML = `<div class="view stack">
    ${viewHead('Pins', 'Retention expressed as data. A pin keeps its target — and, for a subtree '
        + 'pin, everything the target links — out of reach of collection.')}
    ${card('Retention (lexicographic page)', all.length
        ? table(['id', 'state', 'target', 'kind', 'scope', 'expires', ''], rows)
        : empty('No pins. Nothing is protected from collection.'), page.next_cursor
        ? `<a class="btn btn-sm" href="#/pins?cursor=${encodeURIComponent(page.next_cursor)}">Next page</a>`
        : '')}
    ${card('Create a pin', `<div class="card-body">
      <form class="form-row" id="pin-form">
        <label class="field">id
          <input type="text" name="id" required size="20" placeholder="release/v1"></label>
        <label class="field">cid
          <input type="text" name="cid" required size="26" placeholder="64 hex characters"></label>
        <label class="field">ttl seconds
          <input type="number" name="ttl_secs" min="1" placeholder="never"></label>
        <label class="field">covers
          <select name="subtree">
            <option value="false">this chunk</option>
            <option value="true">whole subtree</option>
          </select></label>
        <button class="btn btn-primary" type="submit">Pin</button>
      </form>
    </div>`)}
  </div>`;
};
// ---- jobs ------------------------------------------------------------
const jobs = async (params) => {
    const [page, adapters] = await Promise.all([api.jobs(params['cursor']), api.adapters()]);
    const all = page.items;
    const rows = all.map((job) => `<tr>
    <td class="mono">${esc(job.id)}</td>
    <td class="mono">${esc(job.code_ref)}</td>
    <td>${pill(job.determinism === 'Deterministic' ? 'deterministic' : 'side-effecting', job.determinism === 'Deterministic' ? 'ok' : 'warn')}</td>
    <td class="mono">${job.pointer_inputs.map(esc).join('<br>') || '<span class="muted">—</span>'}</td>
    <td class="mono">${esc(job.cache_policy)}</td>
    <td class="nums">${job.trigger_count}</td>
    <td class="actions">
      <a class="btn btn-sm" href="#/jobs?id=${encodeURIComponent(job.id)}">Runs</a>
      <button class="btn btn-sm btn-primary" data-act="run-job" data-id="${esc(job.id)}" type="button">Run</button>
    </td>
  </tr>`);
    let runs = '';
    const selected = params['id'];
    if (selected) {
        const page = await api.runs(selected, params['run_cursor']);
        const list = page.items;
        const older = page.next_cursor
            ? `<div class="actions"><a class="btn btn-sm" href="#/jobs?id=${encodeURIComponent(selected)}&run_cursor=${encodeURIComponent(page.next_cursor)}">Older runs</a></div>`
            : '';
        runs = card(`Runs — ${selected}`, list.length
            ? table(['run', 'revision', 'status', 'resolved inputs', 'outputs', 'started'], list.map((r) => `<tr>
            <td class="nums">#${esc(r.run_id)}</td>
            <td class="mono">${r.revision
                ? `${esc(r.revision.code_ref)} @${r.revision.event_seq} ${cidChip(r.revision.event_cid)}`
                : '<span class="muted">legacy</span>'}</td>
            <td>${pill(r.status.toLowerCase(), r.status === 'Succeeded' ? 'ok' : r.status === 'Failed' ? 'bad' : 'neutral')}${r.error ? `<div class="cell-note">${esc(r.error)}</div>` : ''}</td>
            <td>${r.pointer_inputs.map((i) => `<div class="cell-note mono">${esc(i.pointer_id)}@${i.seq} ${cidChip(i.cid)}</div>`).join('') || '<span class="muted">—</span>'}</td>
            <td>${r.outputs.map((o) => `<div class="cell-note">${esc(o.name)} ${cidChip(o.cid)}</div>`).join('') || '<span class="muted">—</span>'}</td>
            <td class="muted">${esc(when(r.started_at))}</td>
          </tr>`)) + older
            : empty('This job has not run yet.'));
    }
    slot().innerHTML = `<div class="view stack">
    ${viewHead('Jobs', 'A job resolves its inputs at trigger time and records exactly what it read. '
        + 'Deterministic jobs reproduce; side-effecting ones reuse their first run '
        + 'rather than repeating the effect.')}
    ${card('Registered (lexicographic page)', all.length
        ? table(['id', 'adapter', 'kind', 'pointer inputs', 'output policy', 'runs', ''], rows)
        : empty('No jobs registered. Load the worked example to see one.'), page.next_cursor
        ? `<a class="btn btn-sm" href="#/jobs?cursor=${encodeURIComponent(page.next_cursor)}">Next page</a>`
        : '')}
    ${runs}
    ${card('Available adapters', `<div class="card-body chips">
      ${adapters.map((a) => pill(
    // A simulated adapter reads as a peer of the real ones unless its
    // chip says otherwise, and its summary explains what it fakes.
    `${a.name} · ${a.simulated ? 'SIMULATED' : a.deterministic ? 'deterministic' : 'side-effecting'}`, a.simulated ? 'bad' : a.deterministic ? 'ok' : 'warn')).join('')}
    </div>
    <div class="card-body muted">${adapters.map((a) => `${esc(a.name)} — ${esc(a.summary)}`).join('<br>')}</div>`)}
  </div>`;
};
// ---- events ----------------------------------------------------------
const events = async () => {
    const replay = await api.events(200);
    const all = replay.events;
    // Retention trims the front of the journal, so "the oldest event shown" is
    // not the same as "the oldest event there was". Say which one this is.
    const trimmed = replay.truncated
        ? `<p class="muted">Journal starts at seq ${replay.truncated.earliest_seq}; `
            + `${replay.truncated.missing} older events have been dropped by retention.</p>`
        : '';
    slot().innerHTML = `<div class="view stack">
    ${viewHead('Events', 'One ordered journal for the whole control plane. Sequence numbers are '
        + 'assigned in order and never reused, so events are never reordered. A '
        + 'gap here is not evidence of loss on its own: filtering hides events, '
        + 'and retention drops the oldest.')}
    ${card('Stream', trimmed + `<ul class="feed" id="feed">${all.length ? feedRows(all) : '<li><span class="muted">No events yet.</span></li>'}</ul>`, `<div class="chips">${EVENT_KINDS.map((k) => `<button class="chip" data-kind="${k}" aria-pressed="${activeKinds.has(k)}" type="button">${k}</button>`).join('')}</div>`)}
  </div>`;
};
export const views = {
    overview,
    explorer,
    pointers,
    pins,
    jobs,
    events,
};
export function isViewName(value) {
    return Object.prototype.hasOwnProperty.call(views, value);
}
/** Attach click handlers to graph nodes after a render. */
export function bindGraphNodes(open) {
    for (const node of queryAll('.graph-node')) {
        const cid = node.dataset['cid'];
        if (!cid)
            continue;
        node.addEventListener('click', () => open(cid));
        node.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                open(cid);
            }
        });
    }
}
