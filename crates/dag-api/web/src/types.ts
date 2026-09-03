/**
 * Wire types for the dag HTTP API.
 *
 * These mirror the `serde` structs in `crates/dag-api/src/routes/`. Keeping
 * them in one place means a change to a Rust response shape shows up as a
 * type error at the call site rather than as `undefined` on screen.
 */

/** Hex-encoded SHA-256 content identifier, 64 characters. */
export type Cid = string;

/** POSIX seconds. */
export type Unix = number;

/** A bounded collection response with an explicit continuation. */
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  truncated: boolean;
}

export interface Stats {
  chunks: number;
  bytes: number;
  pointers: number;
  pins: number;
  active_pins: number;
  jobs: number;
  event_seq: number;
  recovered: boolean;
}

export interface Pointer {
  id: string;
  seq: number;
  cid: Cid;
}

export interface PointerEvent {
  seq: number;
  cid: Cid;
  previous_cid: Cid | null;
  ts: Unix;
}

export interface Pin {
  id: string;
  seq: number;
  active: boolean;
  state: 'Active' | 'Deactivated';
  scope: string;
  target_cid: Cid;
  subtree: boolean;
  max_depth: number | null;
  expires_at: Unix | null;
  ts: Unix;
  author: string | null;
}

export interface Job {
  id: string;
  code_ref: string;
  determinism: 'Deterministic' | 'SideEffecting';
  pointer_inputs: string[];
  static_inputs: Cid[];
  declared_outputs: string[];
  cache_policy: string;
  trigger: string;
  trigger_count: number;
}

export type RunStatusName = 'Pending' | 'Running' | 'Succeeded' | 'Failed';

export interface Run {
  run_id: string;
  job_id: string;
  status: RunStatusName;
  error: string | null;
  outputs: { name: string; cid: Cid }[];
  pointer_inputs: { pointer_id: string; cid: Cid; seq: number }[];
  static_inputs: Cid[];
  started_at: Unix;
  finished_at: Unix | null;
  node_id: string | null;
  revision: {
    event_cid: Cid;
    event_seq: number;
    code_ref: string;
  } | null;
}

export interface Adapter {
  name: string;
  deterministic: boolean;
  /** The adapter fabricates its output — a test double, not the real thing. */
  simulated: boolean;
  summary: string;
}

export interface EntryView {
  cid: Cid;
  size: number;
  is_entry: boolean;
  links: { name: string | null; target: Cid }[];
  content_type: string | null;
  preview: string | null;
  truncated: boolean;
  intact: boolean;
}

export interface GraphNode {
  cid: Cid;
  depth: number;
  size: number;
  is_entry: boolean;
  content_type: string | null;
  preview: string | null;
  intact: boolean;
  pointers: string[];
  pinned: boolean;
}

export interface GraphEdge {
  from: Cid;
  to: Cid;
  name: string | null;
}

export interface Graph {
  root: Cid;
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  /** Pointer labels are incomplete because the namespace exceeded the scan bound. */
  pointer_labels_truncated: boolean;
}

export interface Retention {
  cid: Cid;
  protected: boolean;
  sources: string[];
  earliest_expiry: Unix | null;
  system_protected: boolean;
}

export interface GcReport {
  dry_run: boolean;
  examined: number;
  deleted: number;
  bytes_freed: number;
  protected_by_pins: number;
  protected_by_system: number;
  skipped_too_young: number;
  errors: string[];
  duration_ms: number;
}

export interface SeedReport {
  production_pointer: string;
  attestation_v1: Cid;
  attestation_v2: Cid;
  dataset_pointer: string;
  job_id: string;
  release_pin: string;
  scratch_cid: Cid;
  chunks: number;
  pointers: number;
  pins: number;
  recovered: boolean;
}

export interface VerifiedNode {
  cid: Cid;
  name: string | null;
  depth: number;
  size: number;
  intact: boolean;
  error: string | null;
}

export interface VerifyReport {
  pointer: string;
  root: Cid;
  nodes: VerifiedNode[];
  total_nodes: number;
  intact: number;
  corrupt: number;
  total_bytes: number;
  retained: boolean;
  verified: boolean;
}

export interface RunOutcome {
  job_id: string;
  run_id: string;
  revision: { event_cid: Cid; event_seq: number; code_ref: string };
  outputs: { name: string; cid: Cid }[];
}

/**
 * A control-plane event. The `type` tag is the discriminant, matching serde's
 * `#[serde(tag = "type")]` on the Rust enum.
 */
export type DagEvent =
  | { type: 'PointerUpdate'; id: string; new: Cid; ts: Unix }
  | { type: 'PinEvent'; id: string; action: string; ts: Unix }
  | { type: 'JobRun'; job: string; run: string; status: RunStatus; ts: Unix }
  | { type: 'StorageHealth'; check: string; ok: boolean; ts: Unix };

/**
 * `RunStatus` serialises as a bare string for unit variants and as an object
 * for `Failed { message }`, which is serde's default enum representation.
 */
export type RunStatus = 'Pending' | 'Running' | 'Succeeded' | { Failed: { message: string } };

export interface EventEnvelope {
  seq: number;
  envelope_ts: Unix;
  event: DagEvent;
}

/** The part of a replay request the journal could not answer. */
export interface Truncated {
  requested_seq: number;
  earliest_seq: number;
  missing: number;
}

/**
 * `GET /api/events`.
 *
 * Not a bare array: retention trims the front of the journal, so a short
 * answer has to be distinguishable from a complete one.
 */
export interface EventReplay {
  events: EventEnvelope[];
  earliest_seq: number;
  truncated?: Truncated;
  /** Durable journal rows inspected while filling this page. */
  scanned: number;
  /** True when the public scan budget stopped a selective replay early. */
  scan_truncated: boolean;
}

/** The four filterable event streams. */
export const EVENT_KINDS = ['pointer', 'pin', 'job', 'storage'] as const;

export type EventKind = (typeof EVENT_KINDS)[number];

/** Why an SSE `Last-Event-ID` could not be resumed without a gap. */
export type ReplayRequiredReason =
  | 'retention'
  | 'scan_limit'
  | 'resume_limit'
  | 'cursor_ahead'
  | 'encoding';

/**
 * Body of the SSE `replay-required` event.
 *
 * The client must refresh ordinary API state and construct a new EventSource;
 * reconnecting the same object would send the same unsatisfiable cursor.
 */
export interface ReplayRequired {
  reason: ReplayRequiredReason;
  message: string;
  requested_last_event_id: number | null;
  earliest_available_seq: number | null;
  latest_available_seq: number | null;
  scanned: number;
  max_resume_events: number;
}

/** Which stream an event belongs to. */
export function kindOf(event: DagEvent): EventKind {
  switch (event.type) {
    case 'PointerUpdate': return 'pointer';
    case 'PinEvent': return 'pin';
    case 'JobRun': return 'job';
    case 'StorageHealth': return 'storage';
  }
}

/** Flatten a `RunStatus` to its variant name. */
export function statusName(status: RunStatus): RunStatusName {
  return typeof status === 'string' ? status : 'Failed';
}

/**
 * One signature over a CID, with both verdicts.
 *
 * `trusted` is computed against the local keyring's copy of the key; `valid`
 * means only that the envelope is self-consistent. Anything gating on
 * provenance must read `trusted` — an untrusted signature proves nothing about
 * who made it, because the key it names is the signer's own claim.
 */
export interface SignatureStatus {
  signature_cid: Cid;
  key_id: string;
  signer: string | null;
  trusted: boolean;
  valid: boolean;
  predicate: unknown;
}

/** `GET /api/signatures?cid=` */
export interface Signatures {
  cid: Cid;
  signatures: SignatureStatus[];
  /** Distinct trusted keys in this page; a safe lower bound when incomplete. */
  trusted: number;
  /** True only when `trusted` is the exact target-wide count. */
  trusted_complete: boolean;
  next_cursor: string | null;
  truncated: boolean;
}

/**
 * `POST /api/files`.
 *
 * `chunked` is absent for content that fitted in one chunk. When present,
 * `new_chunks` counts data-chunk paths that were absent before this upload.
 * Existing paths are still re-hashed through the store's idempotent put gate,
 * which may adopt an intact crash orphan or repair a corrupt one; those repairs
 * remain on the deduplicated side of this accounting value.
 */
export interface Upload {
  cid: Cid;
  size: number;
  chunked?: boolean;
  chunks?: number;
  new_chunks?: number;
  depth?: number;
}
