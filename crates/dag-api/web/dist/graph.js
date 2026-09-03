/**
 * SVG rendering of a DAG walk.
 *
 * Layered left to right: a node's column is its distance from the root, so
 * lineage depth reads as horizontal distance and siblings stack vertically.
 */
import { bytes, shortCid, swatchHues } from './format.js';
import { esc } from './ui.js';
const COL = 310;
const ROW = 74;
const NODE_W = 200;
const NODE_H = 52;
const PAD = 24;
/** Clip a label to `max` characters, marking the cut. */
function truncate(text, max) {
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
export function renderGraph(graph) {
    if (graph.nodes.length === 0)
        return '';
    const byDepth = new Map();
    for (const node of graph.nodes) {
        const bucket = byDepth.get(node.depth);
        if (bucket)
            bucket.push(node);
        else
            byDepth.set(node.depth, [node]);
    }
    const position = new Map();
    for (const [depth, nodes] of byDepth) {
        nodes.forEach((node, row) => {
            position.set(node.cid, { x: PAD + depth * COL, y: PAD + row * ROW });
        });
    }
    const columns = Math.max(...byDepth.keys()) + 1;
    const rows = Math.max(...[...byDepth.values()].map((n) => n.length));
    const width = PAD * 2 + (columns - 1) * COL + NODE_W;
    const height = PAD * 2 + (rows - 1) * ROW + NODE_H;
    const edges = graph.edges.map((edge) => {
        const from = position.get(edge.from);
        const to = position.get(edge.to);
        // An edge can point outside the walk when it stopped at the depth limit.
        if (!from || !to)
            return '';
        const x1 = from.x + NODE_W;
        const y1 = from.y + NODE_H / 2;
        const x2 = to.x;
        const y2 = to.y + NODE_H / 2;
        const mid = (x1 + x2) / 2;
        // Labels sit in the gap between columns; the gap is COL - NODE_W wide, so
        // truncate rather than let a long link name run under the next node.
        const label = edge.name
            ? `<text class="graph-edge-label" x="${mid}" y="${(y1 + y2) / 2 - 5}"
              text-anchor="middle">${esc(truncate(edge.name, 14))}</text>`
            : '';
        return `<path class="graph-edge" d="M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}"/>${label}`;
    }).join('');
    const gradients = graph.nodes.map((node) => {
        const [h1, h2] = swatchHues(node.cid);
        return `<linearGradient id="sw-${node.cid.slice(0, 8)}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="hsl(${h1.toFixed(0)} 58% 55%)"/>
      <stop offset="100%" stop-color="hsl(${h2.toFixed(0)} 58% 45%)"/>
    </linearGradient>`;
    }).join('');
    const nodes = graph.nodes.map((node) => {
        const at = position.get(node.cid);
        if (!at)
            return '';
        // Prefer the most identifying label available: a pointer name beats a
        // content type, which beats "it's an entry".
        const label = node.pointers[0] ?? node.content_type ?? (node.is_entry ? 'entry' : 'chunk');
        const flags = [
            node.intact ? '✓ intact' : '✗ mismatch',
            ...(node.pinned ? ['pinned'] : []),
            bytes(node.size),
        ].join(' · ');
        return `<g class="graph-node" data-cid="${node.cid}" role="button" tabindex="0"
               aria-label="Node ${shortCid(node.cid)}, ${flags}">
      <rect x="${at.x}" y="${at.y}" width="${NODE_W}" height="${NODE_H}" rx="9"
            ${node.pinned ? 'style="stroke:var(--accent)"' : ''}/>
      <rect class="swatch" x="${at.x + 9}" y="${at.y + 10}" width="10" height="10" rx="2"
            style="fill:url(#sw-${node.cid.slice(0, 8)})"/>
      <text x="${at.x + 25}" y="${at.y + 19}">${shortCid(node.cid)}</text>
      <text class="sub" x="${at.x + 10}" y="${at.y + 35}">${esc(truncate(label, 28))}</text>
      <text class="flag ${node.intact ? '' : 'flag-bad'}" x="${at.x + 10}" y="${at.y + 46}">${esc(flags)}</text>
    </g>`;
    }).join('');
    return `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}"
               role="img" aria-label="Link graph, ${graph.nodes.length} nodes">
    <defs>${gradients}</defs>${edges}${nodes}
  </svg>`;
}
