/** Hard caps so a peer cannot turn one request into unbounded work. */

/** Same ceiling as `dag_core::MAX_CHUNK_SIZE`. */
export const MAX_CHUNK_SIZE = 4 * 1024 * 1024;

/** Stream cancellation occurs as soon as the canonical chunk ceiling is crossed. */
export const CHUNK_BODY_LIMIT = MAX_CHUNK_SIZE;

/** Same batch ceiling the laptop `HttpDestination` uses. Do not lower. */
export const MISSING_BATCH = 4096;

/** Free/demo Workers allow at most 1000 internal-service subrequests. */
export const DEMO_MISSING_BATCH = 900;

/** JSON bodies (missing / import / CAS). 4096 hex CIDs need ~280 KiB. */
export const JSON_BODY_LIMIT = 512 * 1024;

/** One Durable Object will not grow past this many events. */
export const MAX_EVENTS_PER_LOG = 10_000;

/** Canonical pointer event payload ceiling shared with native ingestion. */
export const MAX_POINTER_EVENT_PAYLOAD = 4 * 1024;

/** Historical native pin events remain valid up to the physical chunk cap. */
export const MAX_PIN_EVENT_PAYLOAD = MAX_CHUNK_SIZE;

/** Catalog of pointer/pin names. Finalize reads this instead of listing R2. */
export const MAX_CATALOG_NAMES = 4096;

/** One replication transaction cannot stage more cross-object log writes. */
export const MAX_STAGED_EVENTS = 4096;

/**
 * A finalize may spend one store subrequest per newly verified closure object.
 * At the maximum 4096 publication groups, child RPCs plus six-wide progress
 * checkpoints consume 4779 calls. Keeping closure reads at 128 leaves room for
 * the Catalog RPCs beneath the production configuration's 5000-subrequest
 * fail-stop.
 */
export const MAX_REFERENCE_OBJECTS = 128;

/** Aggregate bytes hashed and decoded by one closure validation. */
export const MAX_REFERENCE_BYTES = 32 * 1024 * 1024;

/** Aggregate Entry edges parsed by one closure validation, before deduplication. */
export const MAX_REFERENCE_LINKS = 8192;

/** Longest reachable path accepted for an otherwise-unbounded live root. */
export const MAX_REFERENCE_DEPTH = 256;

/**
 * Demo KV has a 1000-internal-service-call ceiling. 700 child groups, 117
 * six-wide progress writes, 128 closure reads, and coordination calls remain
 * below that ceiling. Production can use the full staged-event bound.
 */
export const DEMO_MAX_PUBLICATION_GROUPS = 700;

/**
 * Exact finalize receipts retained by the Catalog. Older receipts may be
 * evicted, but their UUIDs then remain unknown and can never mint a new empty
 * publication.
 */
export const MAX_TERMINAL_SYNC_SESSIONS = 1024;

/** Sliding lease for a replication that has not crossed publication. */
export const SYNC_SESSION_SECONDS = 5 * 60;

/** Short recovery lease for CAS and read-only probe coordination. */
export const OPERATION_LEASE_SECONDS = 60;

/** One alarm invocation performs at most this many R2 reconciliation probes. */
export const RESERVATION_RECONCILE_BATCH = 16;

/** Bound concurrent Durable Object RPCs and Worker outgoing connections. */
export const DO_CONCURRENCY = 6;

/** Same as `PointerLog` / `validate_pin_id`. */
export const MAX_ID_BYTES = 256;

/**
 * Parallel object-store HEADs inside one `/sync/missing` request. The request
 * batch is deduplicated first and then split into these platform-sized waves.
 */
export const MISSING_CONCURRENCY = 6;

/** `/i/:cid` never serializes an attacker-sized link array. */
export const INSPECT_LINK_LIMIT = 256;

/** Oversized link labels are omitted from inspection output. */
export const INSPECT_LINK_NAME_BYTES = 256;

/** Hard parser-work ceiling for a single Entry, below the 4 MiB physical maximum. */
export const MAX_ENTRY_LINKS = 100_000;

/** SHA-256 of the empty byte string. A size-0 object is torn unless it is this CID. */
export const EMPTY_CID_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
