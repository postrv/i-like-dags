/** Typed client for the dag HTTP API. */

import type {
  Adapter, Cid, EntryView, EventReplay, GcReport, Graph, Job, Pin, Pointer,
  PointerEvent, Retention, Run, RunOutcome, SeedReport, Signatures,
  Page, Stats, Upload, VerifyReport,
} from './types.js';

type Params = Record<string, string | number | boolean | undefined | null>;

/** An error carrying the server's message rather than a bare status code. */
export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'ApiError';
  }
}

async function unwrap<T>(res: Response): Promise<T> {
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON: fall through and use the raw body as the message.
  }

  if (!res.ok) {
    const message =
      (data && typeof data === 'object' && 'error' in data && typeof data.error === 'string')
        ? data.error
        : text || `HTTP ${res.status}`;
    throw new ApiError(message, res.status);
  }
  return data as T;
}

async function get<T>(path: string, params: Params = {}): Promise<T> {
  const url = new URL(path, location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, String(value));
    }
  }
  return unwrap<T>(await fetch(url));
}

async function post<T>(path: string, body: unknown = {}): Promise<T> {
  return unwrap<T>(
    await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

export const api = {
  stats: () => get<Stats>('/api/stats'),

  entry: (cid: Cid) => get<EntryView>('/api/entries', { cid }),
  graph: (root: { cid?: Cid; pointer?: string }, depth: number) =>
    get<Graph>('/api/graph', { ...root, depth }),

  pointers: (cursor?: string, limit = 100) =>
    get<Page<Pointer>>('/api/pointers', { cursor, limit }),
  pointerHistory: (id: string, cursor?: string, limit = 100) =>
    get<Page<PointerEvent>>('/api/pointers/history', { id, cursor, limit }),
  setPointer: (id: string, cid: Cid) => post<Pointer>('/api/pointers', { id, cid }),

  pins: (cursor?: string, limit = 100) => get<Page<Pin>>('/api/pins', { cursor, limit }),
  createPin: (pin: {
    id: string;
    cid: Cid;
    subtree: boolean;
      ttl_secs: number | null;
    author?: string;
  }) => post<{ id: string }>('/api/pins', pin),
  deactivatePin: (id: string) => post<{ id: string }>('/api/pins/deactivate', { id }),

  jobs: (cursor?: string, limit = 100) => get<Page<Job>>('/api/jobs', { cursor, limit }),
  runs: (id: string, cursor?: string, limit = 25) =>
    get<Page<Run>>('/api/jobs/runs', { id, cursor, limit }),
  runJob: (id: string) => post<RunOutcome>('/api/jobs/run', { id }),
  adapters: () => get<Adapter[]>('/api/adapters'),

  retention: (cid: Cid) => get<Retention>('/api/gc/status', { cid }),
  collect: (options: { dry_run: boolean; min_age_secs?: number }) =>
    post<GcReport>('/api/gc/run', options),

  events: (limit: number, sinceSeq = 0) =>
    get<EventReplay>('/api/events', { limit, since_seq: sinceSeq }),

  signatures: (cid: Cid, cursor?: string, limit = 100) =>
    get<Signatures>('/api/signatures', { cid, cursor, limit }),

  /**
   * Upload a file of any size.
   *
   * The body is the raw bytes, not multipart: the server streams them straight
   * into the chunker, so a large file never has to be held in memory at either
   * end.
   */
  uploadFile: async (file: File, chunked = false): Promise<Upload> => {
    const url = new URL('/api/files', location.origin);
    if (file.type) url.searchParams.set('content_type', file.type);
    if (chunked) url.searchParams.set('chunked', 'true');
    return unwrap<Upload>(await fetch(url, { method: 'POST', body: file }));
  },

  /** Where to download a stored file from. */
  fileUrl: (cid: Cid) => `/api/files?cid=${encodeURIComponent(cid)}`,

  seed: () => post<SeedReport>('/api/usecase/seed'),
  verify: (pointer?: string) => get<VerifyReport>('/api/usecase/verify', { pointer }),
};
