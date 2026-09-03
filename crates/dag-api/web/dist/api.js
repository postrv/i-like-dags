/** Typed client for the dag HTTP API. */
/** An error carrying the server's message rather than a bare status code. */
export class ApiError extends Error {
    status;
    constructor(message, status) {
        super(message);
        this.status = status;
        this.name = 'ApiError';
    }
}
async function unwrap(res) {
    const text = await res.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    }
    catch {
        // Not JSON: fall through and use the raw body as the message.
    }
    if (!res.ok) {
        const message = (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string')
            ? data.error
            : text || `HTTP ${res.status}`;
        throw new ApiError(message, res.status);
    }
    return data;
}
async function get(path, params = {}) {
    const url = new URL(path, location.origin);
    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && value !== '') {
            url.searchParams.set(key, String(value));
        }
    }
    return unwrap(await fetch(url));
}
async function post(path, body = {}) {
    return unwrap(await fetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
    }));
}
export const api = {
    stats: () => get('/api/stats'),
    entry: (cid) => get('/api/entries', { cid }),
    graph: (root, depth) => get('/api/graph', { ...root, depth }),
    pointers: (cursor, limit = 100) => get('/api/pointers', { cursor, limit }),
    pointerHistory: (id, cursor, limit = 100) => get('/api/pointers/history', { id, cursor, limit }),
    setPointer: (id, cid) => post('/api/pointers', { id, cid }),
    pins: (cursor, limit = 100) => get('/api/pins', { cursor, limit }),
    createPin: (pin) => post('/api/pins', pin),
    deactivatePin: (id) => post('/api/pins/deactivate', { id }),
    jobs: (cursor, limit = 100) => get('/api/jobs', { cursor, limit }),
    runs: (id, cursor, limit = 25) => get('/api/jobs/runs', { id, cursor, limit }),
    runJob: (id) => post('/api/jobs/run', { id }),
    adapters: () => get('/api/adapters'),
    retention: (cid) => get('/api/gc/status', { cid }),
    collect: (options) => post('/api/gc/run', options),
    events: (limit, sinceSeq = 0) => get('/api/events', { limit, since_seq: sinceSeq }),
    signatures: (cid, cursor, limit = 100) => get('/api/signatures', { cid, cursor, limit }),
    /**
     * Upload a file of any size.
     *
     * The body is the raw bytes, not multipart: the server streams them straight
     * into the chunker, so a large file never has to be held in memory at either
     * end.
     */
    uploadFile: async (file, chunked = false) => {
        const url = new URL('/api/files', location.origin);
        if (file.type)
            url.searchParams.set('content_type', file.type);
        if (chunked)
            url.searchParams.set('chunked', 'true');
        return unwrap(await fetch(url, { method: 'POST', body: file }));
    },
    /** Where to download a stored file from. */
    fileUrl: (cid) => `/api/files?cid=${encodeURIComponent(cid)}`,
    seed: () => post('/api/usecase/seed'),
    verify: (pointer) => get('/api/usecase/verify', { pointer }),
};
