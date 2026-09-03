import { DurableObject } from "cloudflare:workers";
import type { PublicationValidationHead } from "./closure.ts";
import {
  cancelR2ReservationMarker,
  inspectR2BudgetObject,
} from "./chunks.ts";
import { parseCidHex } from "./cid.ts";
import { checkPinId, checkPointerId } from "./ids.ts";
import {
  DO_CONCURRENCY,
  MAX_CATALOG_NAMES,
  MAX_EVENTS_PER_LOG,
  MAX_ID_BYTES,
  MAX_STAGED_EVENTS,
  MAX_TERMINAL_SYNC_SESSIONS,
  OPERATION_LEASE_SECONDS,
  RESERVATION_RECONCILE_BATCH,
  SYNC_SESSION_SECONDS,
} from "./limits.ts";
import {
  formatOfferError,
  offerPinEvent,
  offerPointerEvent,
  type PinEventView,
  type PointerEventView,
} from "./offer.ts";
import type { PinHeadView, PinOfferContext, PublishedPinEvent } from "./pin.ts";
import type { PointerOfferContext, PublishedPointerEvent, PointerHeadView } from "./pointer.ts";
import type { EdgeEnv } from "./types.ts";

export type CatalogKind = "pointer" | "pin";
export type TerminalSessionOutcome =
  | "completed"
  | "expired"
  | "aborted"
  | "validation_failed"
  | "legacy_discarded";
export type TerminalSessionRefusal = {
  outcome: Exclude<TerminalSessionOutcome, "completed"> | "completed";
  status: number;
  code: string;
  message: string;
};
type CatalogCoordinationStart =
  | { state: "ready" }
  | { state: "publishing" }
  | { state: "recover_cas"; owner: string; name: string }
  | { state: "busy"; retryAfterSeconds: number };
export type CatalogStart = CatalogCoordinationStart
  | ({ state: "terminal" } & TerminalSessionRefusal);
export type CatalogCasStart = CatalogCoordinationStart | { state: "catalog_full"; limit: number };
export type CatalogFinalizeStart =
  | { state: "publishing" }
  | { state: "complete"; pointers: number; pins: number }
  | {
      state: "validate";
      sessionId: string;
      revision: number;
      heads: PublicationValidationHead[];
    }
  | { state: "recover_cas"; owner: string; name: string }
  | { state: "busy"; retryAfterSeconds: number }
  | ({ state: "terminal" } & TerminalSessionRefusal)
  | { state: "unknown" };
export type CatalogStageResult =
  | { ok: true; filed: boolean }
  | { ok: false; status: 400 | 409 | 507; error: string; kind: string };
export type PointerCatalogState =
  | { state: "absent" }
  | { state: "blocked" }
  | { state: "bootstrap" }
  | { state: "ready"; seq: number; cid: string };
export type PublicationGroup =
  | { kind: "pointer"; name: string; events: PublishedPointerEvent[] }
  | { kind: "pin"; name: string; events: PublishedPinEvent[] };
export type ChunkBudgetLease =
  | { state: "existing" }
  | { state: "reserved" }
  | { state: "busy"; retryAfterSeconds: number }
  | { state: "quota"; resource: "bytes" | "objects" };

type RegistryRow = { head_seq: number | null; head_cid: string | null };
type SessionRow = {
  session_id: string;
  phase: "staging" | "publishing";
  touched_at: number;
  revision: number;
  validated_revision: number | null;
};
type TerminalSessionRow = {
  session_id: string;
  outcome: TerminalSessionOutcome;
  terminal_at: number;
  pointers: number;
  pins: number;
  http_status: number;
  error_code: string;
  error_message: string;
};
type LeaseRow = { owner: string; name: string; touched_at: number };
type ProbeLeaseRow = { owner: string; touched_at: number };
type ChunkReservationRow = {
  cid: string;
  size: number;
  absent_since: number | null;
};
type StagedRow = {
  kind: CatalogKind;
  name: string;
  seq: number;
  event_cid: string;
  prev_cid: string | null;
  new_cid: string | null;
  child_published: number;
};

/**
 * The publication authority for Edge history.
 *
 * Imports live only in this SQLite Durable Object until finalize freezes the
 * batch, idempotently copies every name to its canonical child, and atomically
 * exposes all new heads here. Public readers therefore cannot observe a
 * transfer that the source later aborts or refuses to finalize.
 */
export class CatalogObject extends DurableObject<EdgeEnv> {
  constructor(ctx: DurableObjectState, env: EdgeEnv) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS names (
          kind TEXT NOT NULL,
          name TEXT NOT NULL,
          PRIMARY KEY (kind, name)
        );
        CREATE TABLE IF NOT EXISTS registry (
          kind TEXT NOT NULL CHECK (kind IN ('pointer', 'pin')),
          name TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('pending', 'committed')),
          owner TEXT,
          reserved_at INTEGER,
          head_seq INTEGER,
          head_cid TEXT,
          PRIMARY KEY (kind, name)
        );
      `);

      const columns = new Set(
        this.ctx.storage.sql
          .exec<{ name: string }>("PRAGMA table_info(registry)")
          .toArray()
          .map((column) => column.name),
      );
      if (!columns.has("head_seq")) {
        this.ctx.storage.sql.exec("ALTER TABLE registry ADD COLUMN head_seq INTEGER");
      }
      if (!columns.has("head_cid")) {
        this.ctx.storage.sql.exec("ALTER TABLE registry ADD COLUMN head_cid TEXT");
      }

      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS sync_session (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          session_id TEXT NOT NULL,
          phase TEXT NOT NULL CHECK (phase IN ('staging', 'publishing')),
          touched_at INTEGER NOT NULL,
          revision INTEGER NOT NULL DEFAULT 0,
          validated_revision INTEGER
        );
        CREATE TABLE IF NOT EXISTS terminal_sessions (
          session_id TEXT PRIMARY KEY,
          outcome TEXT NOT NULL CHECK (
            outcome IN ('completed', 'expired', 'aborted', 'validation_failed', 'legacy_discarded')
          ),
          terminal_at INTEGER NOT NULL,
          pointers INTEGER NOT NULL DEFAULT 0,
          pins INTEGER NOT NULL DEFAULT 0,
          http_status INTEGER NOT NULL DEFAULT 409,
          error_code TEXT NOT NULL DEFAULT 'sync_session_expired',
          error_message TEXT NOT NULL DEFAULT 'replication session expired before publication'
        );
        CREATE TABLE IF NOT EXISTS cas_lease (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          owner TEXT NOT NULL,
          name TEXT NOT NULL,
          touched_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS probe_lease (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          owner TEXT NOT NULL,
          touched_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS staged_events (
          session_id TEXT NOT NULL,
          kind TEXT NOT NULL CHECK (kind IN ('pointer', 'pin')),
          name TEXT NOT NULL,
          seq INTEGER NOT NULL,
          event_cid TEXT NOT NULL,
          prev_cid TEXT,
          new_cid TEXT,
          child_published INTEGER NOT NULL DEFAULT 0 CHECK (child_published IN (0, 1)),
          PRIMARY KEY (kind, name, seq),
          UNIQUE (kind, name, event_cid)
        );
        CREATE INDEX IF NOT EXISTS staged_publication
          ON staged_events (session_id, child_published, kind, name, seq);
        CREATE TABLE IF NOT EXISTS chunk_budget (
          cid TEXT PRIMARY KEY,
          size INTEGER NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('reserved', 'committed')),
          owner TEXT,
          reserved_at INTEGER,
          absent_since INTEGER
        );
        CREATE TABLE IF NOT EXISTS budget_totals (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          retained_bytes INTEGER NOT NULL,
          retained_objects INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO budget_totals
          (singleton, retained_bytes, retained_objects) VALUES (1, 0, 0);
        UPDATE budget_totals SET
          retained_bytes = (SELECT COALESCE(SUM(size), 0) FROM chunk_budget),
          retained_objects = (SELECT COUNT(*) FROM chunk_budget)
          WHERE singleton = 1;

        DELETE FROM registry WHERE state = 'pending';
        INSERT OR IGNORE INTO registry
          (kind, name, state, owner, reserved_at, head_seq, head_cid)
          SELECT kind, name, 'committed', NULL, NULL, NULL, NULL
          FROM names
          WHERE kind IN ('pointer', 'pin')
            AND length(CAST(name AS BLOB)) <= ${MAX_ID_BYTES}
            AND instr(name, char(0)) = 0
            AND (kind = 'pointer' OR length(CAST(name AS BLOB)) > 0);
      `);

      const terminalColumns = new Set(
        this.ctx.storage.sql
          .exec<{ name: string }>("PRAGMA table_info(terminal_sessions)")
          .toArray()
          .map((column) => column.name),
      );
      if (!terminalColumns.has("http_status")) {
        this.ctx.storage.sql.exec(
          "ALTER TABLE terminal_sessions ADD COLUMN http_status INTEGER NOT NULL DEFAULT 409",
        );
      }
      if (!terminalColumns.has("error_code")) {
        this.ctx.storage.sql.exec(
          "ALTER TABLE terminal_sessions ADD COLUMN error_code TEXT NOT NULL DEFAULT 'sync_session_expired'",
        );
      }
      if (!terminalColumns.has("error_message")) {
        this.ctx.storage.sql.exec(
          `ALTER TABLE terminal_sessions ADD COLUMN error_message TEXT NOT NULL
           DEFAULT 'replication session expired before publication'`,
        );
      }

      const legacyExpiredSessionTable = this.ctx.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'expired_session'",
        )
        .toArray()[0];
      if (legacyExpiredSessionTable) {
        this.ctx.storage.transactionSync(() => {
          this.ctx.storage.sql.exec(
            `INSERT OR REPLACE INTO terminal_sessions
              (session_id, outcome, terminal_at, pointers, pins,
               http_status, error_code, error_message)
             SELECT session_id, 'expired', expired_at, 0, 0, 409,
               'sync_session_expired', 'replication session expired before publication'
             FROM expired_session`,
          );
          this.ctx.storage.sql.exec("DROP TABLE expired_session");
          this.pruneTerminalSessions();
        });
      }

      const sessionColumns = new Set(
        this.ctx.storage.sql
          .exec<{ name: string }>("PRAGMA table_info(sync_session)")
          .toArray()
          .map((column) => column.name),
      );
      const legacySessionSchema =
        !sessionColumns.has("revision") || !sessionColumns.has("validated_revision");
      if (!sessionColumns.has("revision")) {
        this.ctx.storage.sql.exec(
          "ALTER TABLE sync_session ADD COLUMN revision INTEGER NOT NULL DEFAULT 0",
        );
      }
      if (!sessionColumns.has("validated_revision")) {
        this.ctx.storage.sql.exec(
          "ALTER TABLE sync_session ADD COLUMN validated_revision INTEGER",
        );
      }
      if (legacySessionSchema) {
        // Older Edge builds accepted non-canonical event Entries and had no
        // durable closure witness. No Catalog head was public until completion,
        // so discard the prepublication session rather than publish history a
        // native protocol-3 peer can refuse. Already-written child rows remain
        // hidden and an exact reoffer reconciles them idempotently.
        this.ctx.storage.transactionSync(() => {
          this.ctx.storage.sql.exec(
            `INSERT OR REPLACE INTO terminal_sessions
              (session_id, outcome, terminal_at, pointers, pins,
               http_status, error_code, error_message)
             SELECT session_id, 'legacy_discarded', touched_at, 0, 0, 409,
               'sync_session_legacy_discarded',
               'legacy replication session was discarded before publication'
             FROM sync_session WHERE singleton = 1`,
          );
          this.pruneTerminalSessions();
          this.ctx.storage.sql.exec("DELETE FROM staged_events");
          this.ctx.storage.sql.exec("DELETE FROM sync_session");
        });
      }

      const budgetColumns = new Set(
        this.ctx.storage.sql
          .exec<{ name: string }>("PRAGMA table_info(chunk_budget)")
          .toArray()
          .map((column) => column.name),
      );
      if (!budgetColumns.has("absent_since")) {
        this.ctx.storage.sql.exec("ALTER TABLE chunk_budget ADD COLUMN absent_since INTEGER");
      }
      await this.scheduleNextChunkAlarm();
    });
  }

  beginSession(sessionId: string, nowSeconds: number): CatalogStart {
    validateOwnerAndTime(sessionId, nowSeconds);
    this.expirePrepublication(nowSeconds);
    const terminal = this.terminalSession(sessionId);
    if (terminal) return { state: "terminal", ...terminalRefusal(terminal) };
    const probe = this.probeLease();
    if (probe) {
      const age = leaseAge(nowSeconds, probe.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec("DELETE FROM probe_lease WHERE singleton = 1");
    }

    const cas = this.casLease();
    if (cas) {
      const age = leaseAge(nowSeconds, cas.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec(
        "UPDATE cas_lease SET owner = ?, touched_at = ? WHERE singleton = 1",
        sessionId,
        nowSeconds,
      );
      return { state: "recover_cas", owner: sessionId, name: cas.name };
    }

    const session = this.session();
    if (session?.phase === "publishing") return { state: "publishing" };
    if (session) {
      if (session.session_id !== sessionId) {
        return busy(Math.max(1, SYNC_SESSION_SECONDS - leaseAge(nowSeconds, session.touched_at)));
      }
      this.ctx.storage.sql.exec("UPDATE sync_session SET touched_at = ? WHERE singleton = 1", nowSeconds);
      return { state: "ready" };
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO sync_session (singleton, session_id, phase, touched_at) VALUES (1, ?, 'staging', ?)",
      sessionId,
      nowSeconds,
    );
    return { state: "ready" };
  }

  beginFinalize(sessionId: string, nowSeconds: number): CatalogFinalizeStart {
    validateOwnerAndTime(sessionId, nowSeconds);
    this.expirePrepublication(nowSeconds);
    const existingSession = this.session();
    if (!existingSession || existingSession.session_id !== sessionId) {
      const terminal = this.terminalSession(sessionId);
      if (!terminal) return { state: "unknown" };
      if (terminal.outcome === "completed") {
        return { state: "complete", pointers: terminal.pointers, pins: terminal.pins };
      }
      return { state: "terminal", ...terminalRefusal(terminal) };
    }

    if (existingSession.phase === "publishing") {
      return this.publicationStart(existingSession);
    }

    const probe = this.probeLease();
    if (probe) {
      const age = leaseAge(nowSeconds, probe.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec("DELETE FROM probe_lease WHERE singleton = 1");
    }
    const cas = this.casLease();
    if (cas) {
      const age = leaseAge(nowSeconds, cas.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec(
        "UPDATE cas_lease SET owner = ?, touched_at = ? WHERE singleton = 1",
        sessionId,
        nowSeconds,
      );
      return { state: "recover_cas", owner: sessionId, name: cas.name };
    }
    this.ctx.storage.sql.exec(
      "UPDATE sync_session SET touched_at = ? WHERE singleton = 1 AND session_id = ?",
      nowSeconds,
      sessionId,
    );
    return this.validationSnapshot({ ...existingSession, touched_at: nowSeconds });
  }

  /** Resume a publication already observed by another Catalog operation. */
  beginPublicationRecovery(nowSeconds: number): CatalogFinalizeStart {
    validateTime(nowSeconds);
    const session = this.session();
    if (!session || session.phase !== "publishing") return { state: "unknown" };
    return this.publicationStart(session);
  }

  beginCas(owner: string, name: string, nowSeconds: number): CatalogCasStart {
    validateOwnerAndTime(owner, nowSeconds);
    validateKindAndName("pointer", name);
    this.expirePrepublication(nowSeconds);
    const session = this.session();
    if (session?.phase === "publishing") return { state: "publishing" };
    if (session) return busy(Math.max(1, SYNC_SESSION_SECONDS - leaseAge(nowSeconds, session.touched_at)));

    const probe = this.probeLease();
    if (probe) {
      const age = leaseAge(nowSeconds, probe.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec("DELETE FROM probe_lease WHERE singleton = 1");
    }
    const cas = this.casLease();
    if (cas) {
      const age = leaseAge(nowSeconds, cas.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec(
        "UPDATE cas_lease SET owner = ?, touched_at = ? WHERE singleton = 1",
        owner,
        nowSeconds,
      );
      return { state: "recover_cas", owner, name: cas.name };
    }
    if (!this.nameIsCounted("pointer", name) && this.catalogNameCount() >= MAX_CATALOG_NAMES) {
      return { state: "catalog_full", limit: MAX_CATALOG_NAMES };
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO cas_lease (singleton, owner, name, touched_at) VALUES (1, ?, ?, ?)",
      owner,
      name,
      nowSeconds,
    );
    return { state: "ready" };
  }

  beginProbe(owner: string, nowSeconds: number): CatalogStart {
    validateOwnerAndTime(owner, nowSeconds);
    this.expirePrepublication(nowSeconds);
    const session = this.session();
    if (session?.phase === "publishing") return { state: "publishing" };
    if (session) return busy(Math.max(1, SYNC_SESSION_SECONDS - leaseAge(nowSeconds, session.touched_at)));
    const cas = this.casLease();
    if (cas) {
      const age = leaseAge(nowSeconds, cas.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec(
        "UPDATE cas_lease SET owner = ?, touched_at = ? WHERE singleton = 1",
        owner,
        nowSeconds,
      );
      return { state: "recover_cas", owner, name: cas.name };
    }

    const probe = this.probeLease();
    if (probe) {
      const age = leaseAge(nowSeconds, probe.touched_at);
      if (age < OPERATION_LEASE_SECONDS) return busy(OPERATION_LEASE_SECONDS - age);
      this.ctx.storage.sql.exec(
        "UPDATE probe_lease SET owner = ?, touched_at = ? WHERE singleton = 1",
        owner,
        nowSeconds,
      );
      return { state: "ready" };
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO probe_lease (singleton, owner, touched_at) VALUES (1, ?, ?)",
      owner,
      nowSeconds,
    );
    return { state: "ready" };
  }

  finishProbe(owner: string): { released: boolean } {
    validateOwner(owner);
    const row = this.probeLease();
    if (!row || row.owner !== owner) return { released: false };
    this.ctx.storage.sql.exec("DELETE FROM probe_lease WHERE singleton = 1 AND owner = ?", owner);
    return { released: true };
  }

  renewProbe(owner: string, nowSeconds: number): { renewed: boolean } {
    validateOwnerAndTime(owner, nowSeconds);
    const row = this.probeLease();
    if (!row || row.owner !== owner) return { renewed: false };
    this.ctx.storage.sql.exec(
      "UPDATE probe_lease SET touched_at = ? WHERE singleton = 1 AND owner = ?",
      nowSeconds,
      owner,
    );
    return { renewed: true };
  }

  async reserveChunk(
    owner: string,
    cid: string,
    size: number,
    nowSeconds: number,
    bytesLimit: number,
    objectsLimit: number,
  ): Promise<ChunkBudgetLease> {
    validateOwnerAndTime(owner, nowSeconds);
    parseCidHex(cid);
    if (!Number.isSafeInteger(size) || size < 0) throw new Error("invalid chunk size");
    if (!Number.isSafeInteger(bytesLimit) || bytesLimit < 1) throw new Error("invalid byte budget");
    if (!Number.isSafeInteger(objectsLimit) || objectsLimit < 1) throw new Error("invalid object budget");
    const row = this.ctx.storage.sql
      .exec<{ size: number; state: "reserved" | "committed"; owner: string | null; reserved_at: number | null }>(
        "SELECT size, state, owner, reserved_at FROM chunk_budget WHERE cid = ?",
        cid,
      )
      .toArray()[0];
    if (row) {
      if (row.size !== size) throw new Error("CID budget row has an inconsistent size");
      if (row.state === "committed") return { state: "existing" };
      const age = leaseAge(nowSeconds, row.reserved_at ?? nowSeconds);
      if (row.owner !== owner && age < OPERATION_LEASE_SECONDS) {
        return { state: "busy", retryAfterSeconds: OPERATION_LEASE_SECONDS - age };
      }
      this.ctx.storage.sql.exec(
        `UPDATE chunk_budget SET owner = ?, reserved_at = ?, absent_since = NULL
         WHERE cid = ? AND state = 'reserved'`,
        owner,
        nowSeconds,
        cid,
      );
      await this.scheduleNextChunkAlarm();
      return { state: "reserved" };
    }
    const totals = this.ctx.storage.sql
      .exec<{ retained_bytes: number; retained_objects: number }>(
        "SELECT retained_bytes, retained_objects FROM budget_totals WHERE singleton = 1",
      )
      .one();
    if (totals.retained_objects + 1 > objectsLimit) return { state: "quota", resource: "objects" };
    if (totals.retained_bytes + size > bytesLimit) return { state: "quota", resource: "bytes" };
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT INTO chunk_budget (cid, size, state, owner, reserved_at)
         VALUES (?, ?, 'reserved', ?, ?)`,
        cid,
        size,
        owner,
        nowSeconds,
      );
      this.ctx.storage.sql.exec(
        `UPDATE budget_totals SET retained_bytes = retained_bytes + ?,
          retained_objects = retained_objects + 1 WHERE singleton = 1`,
        size,
      );
    });
    await this.scheduleNextChunkAlarm();
    return { state: "reserved" };
  }

  async commitChunk(owner: string, cid: string): Promise<{ committed: boolean }> {
    validateOwner(owner);
    parseCidHex(cid);
    const row = this.ctx.storage.sql
      .exec<{ state: "reserved" | "committed"; owner: string | null }>(
        "SELECT state, owner FROM chunk_budget WHERE cid = ?",
        cid,
      )
      .toArray()[0];
    if (!row) throw new Error("chunk budget reservation is missing");
    if (row.state === "committed") return { committed: false };
    if (row.owner !== owner) throw new Error("chunk budget reservation changed");
    this.ctx.storage.sql.exec(
      `UPDATE chunk_budget SET state = 'committed', owner = NULL,
        reserved_at = NULL, absent_since = NULL
       WHERE cid = ? AND state = 'reserved' AND owner = ?`,
      cid,
      owner,
    );
    await this.scheduleNextChunkAlarm();
    return { committed: true };
  }

  async renewChunk(
    owner: string,
    cid: string,
    nowSeconds: number,
  ): Promise<{ renewed: boolean }> {
    validateOwnerAndTime(owner, nowSeconds);
    parseCidHex(cid);
    const changed = this.ctx.storage.sql
      .exec(
        `UPDATE chunk_budget SET reserved_at = ?, absent_since = NULL
         WHERE cid = ? AND state = 'reserved' AND owner = ?`,
        nowSeconds,
        cid,
        owner,
      ).rowsWritten;
    if (changed > 0) await this.scheduleNextChunkAlarm();
    return { renewed: changed > 0 };
  }

  claimExpiredChunkReservations(
    owner: string,
    nowSeconds: number,
    limit: number,
  ): ChunkReservationRow[] {
    validateOwnerAndTime(owner, nowSeconds);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > RESERVATION_RECONCILE_BATCH) {
      throw new Error("invalid chunk reconciliation batch");
    }
    const cutoff = Math.max(0, nowSeconds - OPERATION_LEASE_SECONDS);
    const candidates = this.ctx.storage.sql
      .exec<ChunkReservationRow>(
        `SELECT cid, size, absent_since FROM chunk_budget
         WHERE state = 'reserved' AND reserved_at <= ?
         ORDER BY COALESCE(absent_since, reserved_at), cid LIMIT ?`,
        cutoff,
        limit,
      )
      .toArray();
    const claimed: ChunkReservationRow[] = [];
    this.ctx.storage.transactionSync(() => {
      for (const candidate of candidates) {
        const written = this.ctx.storage.sql
          .exec(
            `UPDATE chunk_budget SET owner = ?, reserved_at = ?
             WHERE cid = ? AND state = 'reserved' AND reserved_at <= ?`,
            owner,
            nowSeconds,
            candidate.cid,
            cutoff,
          ).rowsWritten;
        if (written > 0) claimed.push(candidate);
      }
    });
    return claimed;
  }

  markChunkAbsent(
    owner: string,
    cid: string,
    nowSeconds: number,
    resetGrace: boolean,
  ): { marked: boolean } {
    validateOwnerAndTime(owner, nowSeconds);
    parseCidHex(cid);
    const changed = this.ctx.storage.sql
      .exec(
        `UPDATE chunk_budget SET reserved_at = ?,
          absent_since = CASE WHEN ? = 1 OR absent_since IS NULL THEN ? ELSE absent_since END
         WHERE cid = ? AND state = 'reserved' AND owner = ?`,
        nowSeconds,
        resetGrace ? 1 : 0,
        nowSeconds,
        cid,
        owner,
      ).rowsWritten;
    return { marked: changed > 0 };
  }

  async releaseChunkAfterAbsence(
    owner: string,
    cid: string,
    nowSeconds: number,
  ): Promise<{ released: boolean }> {
    validateOwnerAndTime(owner, nowSeconds);
    parseCidHex(cid);
    const row = this.ctx.storage.sql
      .exec<{ size: number; absent_since: number | null }>(
        `SELECT size, absent_since FROM chunk_budget
         WHERE cid = ? AND state = 'reserved' AND owner = ?`,
        cid,
        owner,
      )
      .toArray()[0];
    if (
      !row ||
      row.absent_since === null ||
      leaseAge(nowSeconds, row.absent_since) < OPERATION_LEASE_SECONDS
    ) {
      return { released: false };
    }
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        "DELETE FROM chunk_budget WHERE cid = ? AND state = 'reserved' AND owner = ?",
        cid,
        owner,
      );
      this.ctx.storage.sql.exec(
        `UPDATE budget_totals SET retained_bytes = retained_bytes - ?,
          retained_objects = retained_objects - 1 WHERE singleton = 1`,
        row.size,
      );
    });
    await this.scheduleNextChunkAlarm();
    return { released: true };
  }

  async alarm(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    if (!r2ReconciliationAvailable(this.env)) {
      const scheduled = await this.ctx.storage.getAlarm();
      if (scheduled !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    try {
      const owner = crypto.randomUUID();
      const claimed = this.claimExpiredChunkReservations(
        owner,
        now,
        RESERVATION_RECONCILE_BATCH,
      );
      for (const reservation of claimed) {
        await this.reconcileChunkReservation(owner, reservation, now);
      }
      await this.scheduleNextChunkAlarm();
    } catch {
      console.error(JSON.stringify({ level: "error", event: "chunk_reservation_reconciliation_failed" }));
      await this.ctx.storage.setAlarm(Date.now() + 5_000);
    }
  }

  budgetStatus(): {
    retainedBytes: number;
    retainedObjects: number;
    reservations: number;
    legacyHeadsPending: number;
    unvalidatedPublicationPending: boolean;
  } {
    const totals = this.ctx.storage.sql
      .exec<{ retained_bytes: number; retained_objects: number }>(
        "SELECT retained_bytes, retained_objects FROM budget_totals WHERE singleton = 1",
      )
      .one();
    const reservations = this.ctx.storage.sql
      .exec<{ n: number }>("SELECT COUNT(*) AS n FROM chunk_budget WHERE state = 'reserved'")
      .one().n;
    const legacyHeadsPending = this.ctx.storage.sql
      .exec<{ n: number }>(
        `SELECT COUNT(*) AS n FROM registry
         WHERE state = 'committed' AND (head_seq IS NULL OR head_cid IS NULL)`,
      )
      .one().n;
    const session = this.session();
    // Readiness requires an exact durable witness for the frozen revision.
    // NULL is the recoverable pre-witness legacy shape; a different non-NULL
    // revision is corrupt and must also fail readiness even though recovery
    // will refuse to clear it automatically.
    const unvalidatedPublicationPending =
      session?.phase === "publishing" &&
      session.validated_revision !== session.revision;
    return {
      retainedBytes: totals.retained_bytes,
      retainedObjects: totals.retained_objects,
      reservations,
      legacyHeadsPending,
      unvalidatedPublicationPending,
    };
  }

  legacyHeadPending(kind: CatalogKind, name: string): boolean {
    validateKindAndName(kind, name);
    const row = this.registry(kind, name);
    return Boolean(row && (row.head_seq === null || row.head_cid === null));
  }

  stagePointer(
    sessionId: string,
    name: string,
    seq: number,
    eventCid: string,
    event: PointerEventView,
    canonical: PointerOfferContext,
    provenLegacyHead: PointerHeadView | null,
    nowSeconds: number,
  ): CatalogStageResult {
    validateStageArguments("pointer", sessionId, name, seq, eventCid, nowSeconds);
    validatePointerEvent(event);
    const sessionError = this.requireStagingSession(sessionId, nowSeconds);
    if (sessionError) return sessionError;
    validatePointerHead(canonical.head);
    if (provenLegacyHead !== null) validatePointerHead(provenLegacyHead);
    if (
      this.legacyHeadPending("pointer", name) &&
      (provenLegacyHead === null || !samePointerHead(provenLegacyHead, canonical.head))
    ) {
      return refused("legacy_head_unverified", "legacy pointer head was not integrity-verified");
    }
    if (canonical.storedIdentity !== null && canonical.storedIdentity !== name) {
      return refused("identity_mismatch", "pointer object identity mismatch");
    }
    const existing = this.stagedAt("pointer", name, seq);
    if (existing) {
      return existing.event_cid === eventCid
        ? { ok: true, filed: false }
        : refused("divergent", "pointer sequence already names a different event");
    }
    if (canonical.existingEventCid !== null) {
      if (canonical.existingEventCid !== eventCid) {
        return refused("divergent", "pointer sequence already names a different event");
      }
      this.cacheLegacyPointerUnchecked(name, canonical.head);
      if (this.needsCanonicalPublication("pointer", name, seq)) {
        const capacity = this.checkStageCapacity("pointer", name);
        if (capacity) return capacity;
        this.ctx.storage.transactionSync(() => {
          this.ctx.storage.sql.exec(
            `INSERT INTO staged_events
              (session_id, kind, name, seq, event_cid, prev_cid, new_cid, child_published)
             VALUES (?, 'pointer', ?, ?, ?, ?, ?, 1)`,
            sessionId,
            name,
            seq,
            eventCid,
            event.prev,
            event.new,
          );
          this.bumpSessionRevision(sessionId, nowSeconds);
        });
      }
      return { ok: true, filed: false };
    }

    const stagedPred = seq > 1 ? this.stagedAt("pointer", name, seq - 1) : undefined;
    const predecessor: PointerEventView | null = stagedPred
      ? { seq: seq - 1, pointerId: name, prev: null, new: stagedPred.new_cid as string }
      : canonical.predecessorNewCid === null
        ? null
        : { seq: seq - 1, pointerId: name, prev: null, new: canonical.predecessorNewCid };
    const judged = offerPointerEvent(name, seq, eventCid, event, null, predecessor);
    if ("err" in judged) return refused(judged.err.kind, formatOfferError(judged.err));
    const capacity = this.checkStageCapacity("pointer", name);
    if (capacity) return capacity;
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT INTO staged_events
          (session_id, kind, name, seq, event_cid, prev_cid, new_cid, child_published)
         VALUES (?, 'pointer', ?, ?, ?, ?, ?, 0)`,
        sessionId,
        name,
        seq,
        eventCid,
        event.prev,
        event.new,
      );
      this.bumpSessionRevision(sessionId, nowSeconds);
    });
    this.cacheLegacyPointerUnchecked(name, canonical.head);
    return { ok: true, filed: true };
  }

  stagePin(
    sessionId: string,
    name: string,
    seq: number,
    eventCid: string,
    event: PinEventView,
    canonical: PinOfferContext,
    provenLegacyHead: PinHeadView | null,
    nowSeconds: number,
  ): CatalogStageResult {
    validateStageArguments("pin", sessionId, name, seq, eventCid, nowSeconds);
    validatePinEvent(event);
    const sessionError = this.requireStagingSession(sessionId, nowSeconds);
    if (sessionError) return sessionError;
    validatePinHead(canonical.head);
    if (provenLegacyHead !== null) validatePinHead(provenLegacyHead);
    if (
      this.legacyHeadPending("pin", name) &&
      (provenLegacyHead === null || !samePinHead(provenLegacyHead, canonical.head))
    ) {
      return refused("legacy_head_unverified", "legacy pin head was not integrity-verified");
    }
    if (canonical.storedIdentity !== null && canonical.storedIdentity !== name) {
      return refused("identity_mismatch", "pin object identity mismatch");
    }
    const existing = this.stagedAt("pin", name, seq);
    if (existing) {
      return existing.event_cid === eventCid
        ? { ok: true, filed: false }
        : refused("divergent", "pin sequence already names a different event");
    }
    if (canonical.existingEventCid !== null) {
      if (canonical.existingEventCid !== eventCid) {
        return refused("divergent", "pin sequence already names a different event");
      }
      this.cacheLegacyPin(name, canonical.head);
      if (this.needsCanonicalPublication("pin", name, seq)) {
        const capacity = this.checkStageCapacity("pin", name);
        if (capacity) return capacity;
        this.ctx.storage.transactionSync(() => {
          this.ctx.storage.sql.exec(
            `INSERT INTO staged_events
              (session_id, kind, name, seq, event_cid, prev_cid, new_cid, child_published)
             VALUES (?, 'pin', ?, ?, ?, ?, NULL, 1)`,
            sessionId,
            name,
            seq,
            eventCid,
            event.prev,
          );
          this.bumpSessionRevision(sessionId, nowSeconds);
        });
      }
      return { ok: true, filed: false };
    }
    const stagedPred = seq > 1 ? this.stagedAt("pin", name, seq - 1) : undefined;
    const predecessorEventCid = stagedPred?.event_cid ?? canonical.predecessorEventCid;
    const judged = offerPinEvent(name, seq, eventCid, event, null, predecessorEventCid);
    if ("err" in judged) return refused(judged.err.kind, formatOfferError(judged.err));
    const capacity = this.checkStageCapacity("pin", name);
    if (capacity) return capacity;
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT INTO staged_events
          (session_id, kind, name, seq, event_cid, prev_cid, new_cid, child_published)
         VALUES (?, 'pin', ?, ?, ?, ?, NULL, 0)`,
        sessionId,
        name,
        seq,
        eventCid,
        event.prev,
      );
      this.bumpSessionRevision(sessionId, nowSeconds);
    });
    this.cacheLegacyPin(name, canonical.head);
    return { ok: true, filed: true };
  }

  freezePublication(sessionId: string, revision: number, nowSeconds: number):
    | { state: "publishing" }
    | { state: "missing" }
    | { state: "changed" }
    | { state: "busy"; retryAfterSeconds: number } {
    validateOwnerAndTime(sessionId, nowSeconds);
    if (!Number.isSafeInteger(revision) || revision < 0 || revision > MAX_STAGED_EVENTS) {
      throw new Error("invalid session revision");
    }
    this.expirePrepublication(nowSeconds);
    const session = this.session();
    if (!session) return { state: "missing" };
    if (session.session_id !== sessionId) {
      return busy(Math.max(1, SYNC_SESSION_SECONDS - leaseAge(nowSeconds, session.touched_at)));
    }
    if (session.revision !== revision) return { state: "changed" };
    if (session.phase === "publishing") {
      if (session.validated_revision === revision) return { state: "publishing" };
      if (session.validated_revision !== null) {
        throw new Error("publication validation witness does not match its revision");
      }
    } else if (session.validated_revision !== null) {
      throw new Error("staging session already has a validation witness");
    }

    // The revision comparison and witness/phase write are one SQLite
    // transaction. Durable Object output gates persist this witness before the
    // caller can issue the first child publication RPC.
    this.ctx.storage.transactionSync(() => {
      const current = this.session();
      if (
        !current ||
        current.session_id !== sessionId ||
        current.revision !== revision ||
        (current.validated_revision !== null && current.validated_revision !== revision)
      ) {
        throw new Error("publication session changed during freeze");
      }
      this.ctx.storage.sql.exec(
        `UPDATE sync_session
         SET phase = 'publishing', validated_revision = ?, touched_at = ?
         WHERE singleton = 1 AND session_id = ? AND revision = ?`,
        revision,
        nowSeconds,
        sessionId,
        revision,
      );
    });
    return { state: "publishing" };
  }

  /**
   * Terminalize only the exact unwitnessed snapshot whose validation failed.
   * This also releases a legacy publishing row that predates the durable
   * validation witness. A witnessed publication or a peer that changed the
   * session/revision while validation was doing external reads must survive.
   */
  clearFailedValidation(
    sessionId: string,
    revision: number,
    nowSeconds: number,
    failureStatus: number,
    failureCode: string,
    failureMessage: string,
  ): { cleared: boolean } {
    validateOwnerAndTime(sessionId, nowSeconds);
    validateTerminalFailure(failureStatus, failureCode, failureMessage);
    if (!Number.isSafeInteger(revision) || revision < 0 || revision > MAX_STAGED_EVENTS) {
      throw new Error("invalid session revision");
    }
    const session = this.session();
    if (
      !session ||
      session.session_id !== sessionId ||
      (session.phase !== "staging" && session.phase !== "publishing") ||
      session.revision !== revision ||
      session.validated_revision !== null
    ) {
      return { cleared: false };
    }
    this.ctx.storage.transactionSync(() => {
      const current = this.session();
      if (
        !current ||
        current.session_id !== sessionId ||
        (current.phase !== "staging" && current.phase !== "publishing") ||
        current.revision !== revision ||
        current.validated_revision !== null
      ) {
        throw new Error("validation session changed during cleanup");
      }
      // Keep a terminal receipt for this exact failed session. Native clients
      // retry finalize, and without the receipt a retry could be confused with
      // a never-started transfer after the staged offer was discarded.
      this.recordTerminalSession(
        sessionId,
        "validation_failed",
        nowSeconds,
        failureStatus,
        failureCode,
        failureMessage,
      );
      this.ctx.storage.sql.exec(
        "DELETE FROM staged_events WHERE session_id = ?",
        sessionId,
      );
      this.ctx.storage.sql.exec(
        `DELETE FROM sync_session
         WHERE singleton = 1 AND session_id = ?
           AND phase IN ('staging', 'publishing')
           AND revision = ? AND validated_revision IS NULL`,
        sessionId,
        revision,
      );
    });
    return { cleared: true };
  }

  publicationPlan():
    | { state: "idle" }
    | { state: "unvalidated" }
    | { state: "publishing"; sessionId: string; groups: PublicationGroup[] } {
    const session = this.session();
    if (!session || session.phase !== "publishing") return { state: "idle" };
    if (session.validated_revision !== session.revision) return { state: "unvalidated" };
    const rows = this.ctx.storage.sql
      .exec<StagedRow>(
        `SELECT kind, name, seq, event_cid, prev_cid, new_cid, child_published
         FROM staged_events
         WHERE session_id = ? AND child_published = 0
         ORDER BY kind, name, seq`,
        session.session_id,
      )
      .toArray();
    const groups: PublicationGroup[] = [];
    for (const row of rows) {
      const previous = groups.at(-1);
      if (!previous || previous.kind !== row.kind || previous.name !== row.name) {
        groups.push(
          row.kind === "pointer"
            ? { kind: "pointer", name: row.name, events: [] }
            : { kind: "pin", name: row.name, events: [] },
        );
      }
      const group = groups.at(-1) as PublicationGroup;
      if (group.kind === "pointer") {
        if (row.new_cid === null) throw new Error("staged pointer is missing its head CID");
        group.events.push({
          seq: row.seq,
          eventCid: row.event_cid,
          event: { seq: row.seq, pointerId: row.name, prev: row.prev_cid, new: row.new_cid },
        });
      } else {
        group.events.push({
          seq: row.seq,
          eventCid: row.event_cid,
          event: { seq: row.seq, pinId: row.name, prev: row.prev_cid },
        });
      }
    }
    return { state: "publishing", sessionId: session.session_id, groups };
  }

  markPublishedBatch(
    sessionId: string,
    groups: Array<{ kind: CatalogKind; name: string }>,
  ): { marked: number } {
    validateOwner(sessionId);
    if (!Array.isArray(groups) || groups.length > DO_CONCURRENCY) {
      throw new Error("invalid publication progress batch");
    }
    const session = this.session();
    if (
      !session ||
      session.phase !== "publishing" ||
      session.validated_revision !== session.revision ||
      session.session_id !== sessionId
    ) {
      throw new Error("publication session changed");
    }
    let marked = 0;
    this.ctx.storage.transactionSync(() => {
      for (const group of groups) {
        validateKindAndName(group.kind, group.name);
        const count = this.ctx.storage.sql
          .exec<{ n: number }>(
            `SELECT COUNT(*) AS n FROM staged_events
             WHERE session_id = ? AND kind = ? AND name = ? AND child_published = 0`,
            sessionId,
            group.kind,
            group.name,
          )
          .one().n;
        if (count === 0) continue;
        this.ctx.storage.sql.exec(
          `UPDATE staged_events SET child_published = 1
           WHERE session_id = ? AND kind = ? AND name = ?`,
          sessionId,
          group.kind,
          group.name,
        );
        marked++;
      }
    });
    return { marked };
  }

  completePublication(nowSeconds: number):
    | { state: "idle" }
    | { state: "unvalidated" }
    | { state: "pending"; groups: number }
    | { state: "complete"; pointers: number; pins: number } {
    validateTime(nowSeconds);
    const session = this.session();
    if (!session || session.phase !== "publishing") return { state: "idle" };
    if (session.validated_revision !== session.revision) return { state: "unvalidated" };
    const unpublished = this.ctx.storage.sql
      .exec<{ n: number }>(
        "SELECT COUNT(DISTINCT kind || char(0) || name) AS n FROM staged_events WHERE session_id = ? AND child_published = 0",
        session.session_id,
      )
      .one().n;
    if (unpublished > 0) return { state: "pending", groups: unpublished };

    const heads = this.ctx.storage.sql
      .exec<StagedRow>(
        `SELECT e.kind, e.name, e.seq, e.event_cid, e.prev_cid, e.new_cid, e.child_published
         FROM staged_events e
         WHERE e.session_id = ?
           AND e.seq = (
             SELECT MAX(last.seq) FROM staged_events last
             WHERE last.session_id = e.session_id AND last.kind = e.kind AND last.name = e.name
           )
         ORDER BY e.kind, e.name`,
        session.session_id,
      )
      .toArray();
    let pointers = 0;
    let pins = 0;
    this.ctx.storage.transactionSync(() => {
      for (const head of heads) {
        const cid = head.kind === "pointer" ? head.new_cid : head.event_cid;
        if (cid === null) throw new Error("publication head is missing a CID");
        this.publishHeadMonotonic(head.kind, head.name, head.seq, cid);
        this.ctx.storage.sql.exec("INSERT OR IGNORE INTO names (kind, name) VALUES (?, ?)", head.kind, head.name);
        if (head.kind === "pointer") pointers++;
        else pins++;
      }
      // Head exposure, the exact idempotent completion receipt, and removal of
      // staged state are one SQLite commit. A lost HTTP 200 can therefore
      // replay the same counts without guessing whether publication crossed.
      this.recordTerminalSession(
        session.session_id,
        "completed",
        nowSeconds,
        409,
        "sync_session_complete",
        "replication session already completed and cannot be reused",
        pointers,
        pins,
      );
      this.ctx.storage.sql.exec("DELETE FROM staged_events WHERE session_id = ?", session.session_id);
      this.ctx.storage.sql.exec("DELETE FROM sync_session WHERE singleton = 1");
    });
    return { state: "complete", pointers, pins };
  }

  abortSession(
    sessionId: string,
    nowSeconds: number,
  ):
    | { state: "aborted" | "absent" | "publishing" }
    | { state: "busy"; retryAfterSeconds: number }
    | ({ state: "terminal" } & TerminalSessionRefusal) {
    validateOwnerAndTime(sessionId, nowSeconds);
    this.expirePrepublication(nowSeconds);
    const session = this.session();
    if (!session) {
      const terminal = this.terminalSession(sessionId);
      if (terminal) return { state: "terminal", ...terminalRefusal(terminal) };
      return { state: "absent" };
    }
    if (session.session_id !== sessionId) {
      return busy(Math.max(1, SYNC_SESSION_SECONDS - leaseAge(nowSeconds, session.touched_at)));
    }
    if (session.phase === "publishing") return { state: "publishing" };
    this.ctx.storage.transactionSync(() => {
      this.recordTerminalSession(
        sessionId,
        "aborted",
        nowSeconds,
        409,
        "sync_session_aborted",
        "replication session was aborted",
      );
      this.ctx.storage.sql.exec("DELETE FROM staged_events WHERE session_id = ?", sessionId);
      this.ctx.storage.sql.exec("DELETE FROM sync_session WHERE singleton = 1");
    });
    return { state: "aborted" };
  }

  /**
   * Undo only a brand-new, still-empty staging lease after a child context
   * changed while the caller was acquiring Catalog coordination. Existing
   * staged work and every nonzero revision are preserved.
   */
  releaseEmptySession(sessionId: string): { released: boolean } {
    validateOwner(sessionId);
    const session = this.session();
    if (
      !session ||
      session.session_id !== sessionId ||
      session.phase !== "staging" ||
      session.revision !== 0 ||
      session.validated_revision !== null
    ) {
      return { released: false };
    }
    const staged = this.ctx.storage.sql
      .exec<{ n: number }>(
        "SELECT COUNT(*) AS n FROM staged_events WHERE session_id = ?",
        sessionId,
      )
      .one().n;
    if (staged !== 0) return { released: false };
    this.ctx.storage.sql.exec(
      `DELETE FROM sync_session
       WHERE singleton = 1 AND session_id = ? AND phase = 'staging'
         AND revision = 0 AND validated_revision IS NULL`,
      sessionId,
    );
    return { released: true };
  }

  pointerState(name: string): PointerCatalogState {
    validateKindAndName("pointer", name);
    const row = this.registry("pointer", name);
    if (!row) return { state: "absent" };
    if (row.head_seq === null || row.head_cid === null) {
      if (this.session()?.phase === "publishing" || this.casLease()) return { state: "blocked" };
      return { state: "bootstrap" };
    }
    validateHead(row.head_seq, row.head_cid);
    return { state: "ready", seq: row.head_seq, cid: row.head_cid };
  }

  pointerStateForCas(owner: string, name: string): PointerCatalogState {
    validateOwner(owner);
    validateKindAndName("pointer", name);
    const lease = this.casLease();
    if (!lease || lease.owner !== owner || lease.name !== name) throw new Error("CAS lease changed");
    const row = this.registry("pointer", name);
    if (!row) return { state: "absent" };
    if (row.head_seq === null || row.head_cid === null) return { state: "bootstrap" };
    validateHead(row.head_seq, row.head_cid);
    return { state: "ready", seq: row.head_seq, cid: row.head_cid };
  }

  cacheLegacyPointerForProbe(
    owner: string,
    name: string,
    head: PointerHeadView,
  ): PointerCatalogState {
    validateOwner(owner);
    const lease = this.probeLease();
    if (!lease || lease.owner !== owner) throw new Error("probe lease changed");
    return this.cacheLegacyPointerUnchecked(name, head);
  }

  cacheLegacyPointerForCas(
    owner: string,
    name: string,
    head: PointerHeadView,
  ): PointerCatalogState {
    validateOwner(owner);
    validateKindAndName("pointer", name);
    const lease = this.casLease();
    if (!lease || lease.owner !== owner || lease.name !== name) throw new Error("CAS lease changed");
    return this.cacheLegacyPointerUnchecked(name, head);
  }

  private cacheLegacyPointerUnchecked(name: string, head: PointerHeadView): PointerCatalogState {
    validateKindAndName("pointer", name);
    validatePointerHead(head);
    const existing = this.registry("pointer", name);
    if (!existing) return { state: "absent" };
    if (existing.head_seq !== null && existing.head_cid !== null) {
      validateHead(existing.head_seq, existing.head_cid);
      return { state: "ready", seq: existing.head_seq, cid: existing.head_cid };
    }
    if (head.seq === 0) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("DELETE FROM registry WHERE kind = 'pointer' AND name = ?", name);
        this.ctx.storage.sql.exec("DELETE FROM names WHERE kind = 'pointer' AND name = ?", name);
      });
      return { state: "absent" };
    }
    this.ctx.storage.sql.exec(
      `UPDATE registry SET head_seq = ?, head_cid = ?
       WHERE kind = 'pointer' AND name = ? AND state = 'committed' AND head_seq IS NULL`,
      head.seq,
      head.cid,
      name,
    );
    return { state: "ready", seq: head.seq, cid: head.cid as string };
  }

  private cacheLegacyPin(name: string, head: PinHeadView): void {
    validateKindAndName("pin", name);
    validatePinHead(head);
    const existing = this.registry("pin", name);
    if (!existing || (existing.head_seq !== null && existing.head_cid !== null)) return;
    if (head.seq === 0) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("DELETE FROM registry WHERE kind = 'pin' AND name = ?", name);
        this.ctx.storage.sql.exec("DELETE FROM names WHERE kind = 'pin' AND name = ?", name);
      });
      return;
    }
    this.publishHeadMonotonic("pin", name, head.seq, head.eventCid as string);
  }

  publishCas(
    owner: string,
    name: string,
    expectedSeq: number,
    seq: number,
    targetCid: string,
  ): { published: true } {
    validateOwner(owner);
    validateKindAndName("pointer", name);
    validateHead(seq, targetCid);
    if (!Number.isSafeInteger(expectedSeq) || expectedSeq < 0 || seq !== expectedSeq + 1) {
      throw new Error("invalid CAS sequence");
    }
    const lease = this.casLease();
    if (!lease || lease.owner !== owner || lease.name !== name) throw new Error("CAS lease changed");
    const current = this.registry("pointer", name);
    if (current) {
      if (current.head_seq === null || current.head_cid === null) throw new Error("legacy pointer head was not bootstrapped");
      if (current.head_seq !== expectedSeq) throw new Error("committed pointer head changed");
    } else if (expectedSeq !== 0) {
      throw new Error("committed pointer head is absent");
    }
    this.ctx.storage.transactionSync(() => {
      this.publishHeadMonotonic("pointer", name, seq, targetCid);
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO names (kind, name) VALUES ('pointer', ?)", name);
      this.ctx.storage.sql.exec("DELETE FROM cas_lease WHERE singleton = 1 AND owner = ?", owner);
    });
    return { published: true };
  }

  publishRecoveredCas(
    owner: string,
    name: string,
    head: PointerHeadView,
  ): { ok: true; published: boolean } | { ok: false; error: string } {
    validateOwner(owner);
    validateKindAndName("pointer", name);
    validatePointerHead(head);
    const lease = this.casLease();
    if (!lease || lease.owner !== owner || lease.name !== name) throw new Error("CAS lease changed");
    const current = this.registry("pointer", name);
    let published = false;
    if (current && current.head_seq !== null && current.head_cid !== null) {
      if (head.seq < current.head_seq) return { ok: false, error: "canonical pointer log is behind its committed head" };
      if (head.seq === current.head_seq && head.cid !== current.head_cid) {
        return { ok: false, error: "canonical pointer log conflicts with its committed head" };
      }
      published = head.seq > current.head_seq;
    } else {
      published = head.seq > 0;
    }
    this.ctx.storage.transactionSync(() => {
      if (head.seq > 0 && head.cid !== null) {
        this.publishHeadMonotonic("pointer", name, head.seq, head.cid);
        this.ctx.storage.sql.exec("INSERT OR IGNORE INTO names (kind, name) VALUES ('pointer', ?)", name);
      } else if (current && current.head_seq === null) {
        this.ctx.storage.sql.exec("DELETE FROM registry WHERE kind = 'pointer' AND name = ?", name);
        this.ctx.storage.sql.exec("DELETE FROM names WHERE kind = 'pointer' AND name = ?", name);
      }
      this.ctx.storage.sql.exec("DELETE FROM cas_lease WHERE singleton = 1 AND owner = ?", owner);
    });
    return { ok: true, published };
  }

  cancelCas(owner: string): { released: boolean } {
    validateOwner(owner);
    const lease = this.casLease();
    if (!lease || lease.owner !== owner) return { released: false };
    this.ctx.storage.sql.exec("DELETE FROM cas_lease WHERE singleton = 1 AND owner = ?", owner);
    return { released: true };
  }

  renewCas(owner: string, name: string, nowSeconds: number): { renewed: boolean } {
    validateOwnerAndTime(owner, nowSeconds);
    validateKindAndName("pointer", name);
    const lease = this.casLease();
    if (!lease || lease.owner !== owner || lease.name !== name) return { renewed: false };
    this.ctx.storage.sql.exec(
      "UPDATE cas_lease SET touched_at = ? WHERE singleton = 1 AND owner = ? AND name = ?",
      nowSeconds,
      owner,
      name,
    );
    return { renewed: true };
  }

  knownNames(kind: CatalogKind, names: string[]): string[] {
    if (!Array.isArray(names) || names.length > MAX_CATALOG_NAMES) throw new Error("invalid probe names");
    const known: string[] = [];
    for (const name of names) {
      validateKindAndName(kind, name);
      if (this.registry(kind, name)) known.push(name);
    }
    return known;
  }

  contains(kind: CatalogKind, name: string): boolean {
    validateKindAndName(kind, name);
    return this.registry(kind, name) !== undefined;
  }

  counts(): { pointers: number; pins: number; staged: number; phase: string } {
    const pointers = this.ctx.storage.sql
      .exec<{ n: number }>("SELECT COUNT(*) AS n FROM registry WHERE kind = 'pointer' AND state = 'committed'")
      .one().n;
    const pins = this.ctx.storage.sql
      .exec<{ n: number }>("SELECT COUNT(*) AS n FROM registry WHERE kind = 'pin' AND state = 'committed'")
      .one().n;
    const staged = this.ctx.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM staged_events").one().n;
    return { pointers, pins, staged, phase: this.session()?.phase ?? "idle" };
  }

  operationStatus(nowSeconds: number): {
    phase: "idle" | "staging" | "publishing" | "cas" | "probe";
    stagedEvents: number;
    unpublishedNames: number;
    pointers: number;
    pins: number;
  } {
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) throw new Error("invalid status time");
    this.expirePrepublication(nowSeconds);
    const counts = this.counts();
    const session = this.session();
    const phase = session?.phase ?? (this.casLease() ? "cas" : this.probeLease() ? "probe" : "idle");
    const unpublishedNames = this.ctx.storage.sql
      .exec<{ n: number }>("SELECT COUNT(DISTINCT kind || char(0) || name) AS n FROM staged_events WHERE child_published = 0")
      .one().n;
    return { phase, stagedEvents: counts.staged, unpublishedNames, pointers: counts.pointers, pins: counts.pins };
  }

  private async reconcileChunkReservation(
    owner: string,
    reservation: ChunkReservationRow,
    nowSeconds: number,
  ): Promise<void> {
    const bucket = this.env.CHUNKS;
    if (!bucket) throw new Error("R2 reconciliation is unavailable");
    for (let attempt = 0; attempt < 3; attempt++) {
      const observed = await inspectR2BudgetObject(bucket, reservation.cid, reservation.size);
      if (observed.state === "valid") {
        await this.commitChunk(owner, reservation.cid);
        return;
      }
      if (observed.state === "marker") {
        const fenced = await cancelR2ReservationMarker(
          bucket,
          reservation.cid,
          observed.etag,
          owner,
        );
        if (!fenced) continue;
        this.markChunkAbsent(owner, reservation.cid, nowSeconds, true);
        return;
      }
      if (observed.state === "absent") {
        if (
          reservation.absent_since !== null &&
          leaseAge(nowSeconds, reservation.absent_since) >= OPERATION_LEASE_SECONDS
        ) {
          const released = await this.releaseChunkAfterAbsence(
            owner,
            reservation.cid,
            nowSeconds,
          );
          if (released.released) return;
        }
        this.markChunkAbsent(owner, reservation.cid, nowSeconds, false);
        return;
      }

      // An out-of-band or corrupt object is still a retained object. Never
      // free its logical charge from metadata alone; a later authenticated
      // upload may safely repair it with the expected content-addressed bytes.
      await this.renewChunk(owner, reservation.cid, nowSeconds);
      return;
    }

    // Conditional fencing lost a race repeatedly. Keep the row charged and
    // retry after another full lease instead of guessing which R2 write won.
    await this.renewChunk(owner, reservation.cid, nowSeconds);
  }

  private async scheduleNextChunkAlarm(): Promise<void> {
    if (!r2ReconciliationAvailable(this.env)) {
      const scheduled = await this.ctx.storage.getAlarm();
      if (scheduled !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    const next = this.ctx.storage.sql
      .exec<{ reserved_at: number | null }>(
        `SELECT MIN(reserved_at) AS reserved_at FROM chunk_budget
         WHERE state = 'reserved'`,
      )
      .one().reserved_at;
    const scheduled = await this.ctx.storage.getAlarm();
    if (next === null) {
      if (scheduled !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    const due = Math.max(Date.now() + 1_000, (next + OPERATION_LEASE_SECONDS) * 1_000);
    if (scheduled === null || scheduled > due) await this.ctx.storage.setAlarm(due);
  }

  private requireStagingSession(sessionId: string, nowSeconds: number): Extract<CatalogStageResult, { ok: false }> | null {
    const session = this.session();
    if (!session || session.phase !== "staging" || session.session_id !== sessionId) {
      return refused("sync_session_changed", "replication session is not active");
    }
    this.ctx.storage.sql.exec("UPDATE sync_session SET touched_at = ? WHERE singleton = 1", nowSeconds);
    return null;
  }

  private bumpSessionRevision(sessionId: string, nowSeconds: number): void {
    const session = this.session();
    if (!session || session.phase !== "staging" || session.session_id !== sessionId) {
      throw new Error("replication session changed while staging an event");
    }
    if (session.revision >= MAX_STAGED_EVENTS) throw new Error("replication session revision overflow");
    this.ctx.storage.sql.exec(
      `UPDATE sync_session
       SET revision = revision + 1, validated_revision = NULL, touched_at = ?
       WHERE singleton = 1 AND session_id = ? AND phase = 'staging'`,
      nowSeconds,
      sessionId,
    );
  }

  private validationSnapshot(
    session: SessionRow,
  ): Extract<CatalogFinalizeStart, { state: "validate" }> {
    if (!Number.isSafeInteger(session.revision) || session.revision < 0) {
      throw new Error("invalid replication session revision");
    }
    const rows = this.ctx.storage.sql
      .exec<StagedRow>(
        `SELECT e.kind, e.name, e.seq, e.event_cid, e.prev_cid, e.new_cid, e.child_published
         FROM staged_events e
         WHERE e.session_id = ?
           AND e.seq = (
             SELECT MAX(last.seq) FROM staged_events last
             WHERE last.session_id = e.session_id AND last.kind = e.kind AND last.name = e.name
           )
         ORDER BY e.kind, e.name`,
        session.session_id,
      )
      .toArray();
    const heads: PublicationValidationHead[] = rows.map((row) => {
      if (row.kind === "pointer") {
        if (row.new_cid === null) throw new Error("staged pointer is missing its head CID");
        return { kind: "pointer", name: row.name, cid: row.new_cid };
      }
      return { kind: "pin", name: row.name, eventCid: row.event_cid };
    });
    return {
      state: "validate",
      sessionId: session.session_id,
      revision: session.revision,
      heads,
    };
  }

  private publicationStart(session: SessionRow): CatalogFinalizeStart {
    if (session.validated_revision === session.revision) return { state: "publishing" };
    if (session.validated_revision !== null) {
      throw new Error("publication validation witness does not match its revision");
    }
    // A legacy process may have frozen the session before durable validation
    // witnesses existed. Revalidate every final head, including groups whose
    // child log may already have been written, before any resume is allowed.
    return this.validationSnapshot(session);
  }

  private checkStageCapacity(kind: CatalogKind, name: string): Extract<CatalogStageResult, { ok: false }> | null {
    const events = this.ctx.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM staged_events").one().n;
    if (events >= MAX_STAGED_EVENTS) {
      return { ok: false, status: 507, kind: "sync_full", error: `sync stages at most ${MAX_STAGED_EVENTS} events` };
    }
    if (!this.nameIsCounted(kind, name) && this.catalogNameCount() >= MAX_CATALOG_NAMES) {
      return { ok: false, status: 507, kind: "catalog_full", error: `catalog is full (${MAX_CATALOG_NAMES} names)` };
    }
    return null;
  }

  private catalogNameCount(): number {
    return this.ctx.storage.sql
      .exec<{ n: number }>(
        `SELECT COUNT(*) AS n FROM (
           SELECT kind, name FROM registry WHERE state = 'committed'
           UNION
           SELECT kind, name FROM staged_events
         )`,
      )
      .one().n;
  }

  private nameIsCounted(kind: CatalogKind, name: string): boolean {
    return (
      this.registry(kind, name) !== undefined ||
      this.ctx.storage.sql
        .exec<{ n: number }>(
          "SELECT COUNT(*) AS n FROM staged_events WHERE kind = ? AND name = ?",
          kind,
          name,
        )
        .one().n > 0
    );
  }

  private stagedAt(kind: CatalogKind, name: string, seq: number): StagedRow | undefined {
    return this.ctx.storage.sql
      .exec<StagedRow>(
        `SELECT kind, name, seq, event_cid, prev_cid, new_cid, child_published
         FROM staged_events WHERE kind = ? AND name = ? AND seq = ?`,
        kind,
        name,
        seq,
      )
      .toArray()[0];
  }

  private needsCanonicalPublication(kind: CatalogKind, name: string, seq: number): boolean {
    const current = this.registry(kind, name);
    return !current || current.head_seq === null || current.head_cid === null || current.head_seq < seq;
  }

  private publishHeadMonotonic(kind: CatalogKind, name: string, seq: number, cid: string): void {
    validateKindAndName(kind, name);
    validateHead(seq, cid);
    const current = this.registry(kind, name);
    if (current?.head_seq !== null && current?.head_seq !== undefined) {
      if (seq < current.head_seq) throw new Error("refusing to regress a committed head");
      if (seq === current.head_seq) {
        if (current.head_cid !== cid) throw new Error("committed head divergence");
        return;
      }
      this.ctx.storage.sql.exec(
        `UPDATE registry SET state = 'committed', owner = NULL, reserved_at = NULL,
          head_seq = ?, head_cid = ? WHERE kind = ? AND name = ?`,
        seq,
        cid,
        kind,
        name,
      );
      return;
    }
    if (current) {
      this.ctx.storage.sql.exec(
        `UPDATE registry SET state = 'committed', owner = NULL, reserved_at = NULL,
          head_seq = ?, head_cid = ? WHERE kind = ? AND name = ?`,
        seq,
        cid,
        kind,
        name,
      );
    } else {
      this.ctx.storage.sql.exec(
        `INSERT INTO registry
          (kind, name, state, owner, reserved_at, head_seq, head_cid)
         VALUES (?, ?, 'committed', NULL, NULL, ?, ?)`,
        kind,
        name,
        seq,
        cid,
      );
    }
  }

  private expirePrepublication(nowSeconds: number): void {
    const session = this.session();
    if (session?.phase === "staging" && leaseAge(nowSeconds, session.touched_at) >= SYNC_SESSION_SECONDS) {
      this.ctx.storage.transactionSync(() => {
        this.recordTerminalSession(
          session.session_id,
          "expired",
          nowSeconds,
          409,
          "sync_session_expired",
          "replication session expired before publication",
        );
        this.ctx.storage.sql.exec("DELETE FROM staged_events WHERE session_id = ?", session.session_id);
        this.ctx.storage.sql.exec("DELETE FROM sync_session WHERE singleton = 1");
      });
    }
  }

  private terminalSession(sessionId: string): TerminalSessionRow | undefined {
    return this.ctx.storage.sql
      .exec<TerminalSessionRow>(
        `SELECT session_id, outcome, terminal_at, pointers, pins,
           http_status, error_code, error_message
         FROM terminal_sessions WHERE session_id = ?`,
        sessionId,
      )
      .toArray()[0];
  }

  private recordTerminalSession(
    sessionId: string,
    outcome: TerminalSessionOutcome,
    terminalAt: number,
    httpStatus: number,
    errorCode: string,
    errorMessage: string,
    pointers = 0,
    pins = 0,
  ): void {
    validateTerminalFailure(httpStatus, errorCode, errorMessage);
    this.ctx.storage.sql.exec(
      `INSERT OR REPLACE INTO terminal_sessions
        (session_id, outcome, terminal_at, pointers, pins,
         http_status, error_code, error_message)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      sessionId,
      outcome,
      terminalAt,
      pointers,
      pins,
      httpStatus,
      errorCode,
      errorMessage,
    );
    this.pruneTerminalSessions();
  }

  private pruneTerminalSessions(): void {
    this.ctx.storage.sql.exec(
      `DELETE FROM terminal_sessions
       WHERE rowid IN (
         SELECT rowid FROM terminal_sessions
         ORDER BY rowid DESC
         LIMIT -1 OFFSET ${MAX_TERMINAL_SYNC_SESSIONS}
       )`,
    );
  }

  private session(): SessionRow | undefined {
    return this.ctx.storage.sql
      .exec<SessionRow>(
        `SELECT session_id, phase, touched_at, revision, validated_revision
         FROM sync_session WHERE singleton = 1`,
      )
      .toArray()[0];
  }

  private casLease(): LeaseRow | undefined {
    return this.ctx.storage.sql
      .exec<LeaseRow>("SELECT owner, name, touched_at FROM cas_lease WHERE singleton = 1")
      .toArray()[0];
  }

  private probeLease(): ProbeLeaseRow | undefined {
    return this.ctx.storage.sql
      .exec<ProbeLeaseRow>("SELECT owner, touched_at FROM probe_lease WHERE singleton = 1")
      .toArray()[0];
  }

  private registry(kind: CatalogKind, name: string): RegistryRow | undefined {
    return this.ctx.storage.sql
      .exec<RegistryRow>(
        "SELECT head_seq, head_cid FROM registry WHERE kind = ? AND name = ? AND state = 'committed'",
        kind,
        name,
      )
      .toArray()[0];
  }
}

function refused(kind: string, error: string): Extract<CatalogStageResult, { ok: false }> {
  return { ok: false, status: 409, kind, error };
}

function terminalRefusal(row: TerminalSessionRow): TerminalSessionRefusal {
  validateTerminalFailure(row.http_status, row.error_code, row.error_message);
  return {
    outcome: row.outcome,
    status: row.http_status,
    code: row.error_code,
    message: row.error_message,
  };
}

function busy(seconds: number): Extract<CatalogStart, { state: "busy" }> {
  return { state: "busy", retryAfterSeconds: Math.max(1, Math.ceil(seconds)) };
}

function leaseAge(nowSeconds: number, touchedAt: number): number {
  return Math.max(0, nowSeconds - touchedAt);
}

function validateStageArguments(
  kind: CatalogKind,
  sessionId: string,
  name: string,
  seq: number,
  eventCid: string,
  nowSeconds: number,
): void {
  validateOwnerAndTime(sessionId, nowSeconds);
  validateKindAndName(kind, name);
  if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) throw new Error("invalid event sequence");
  parseCidHex(eventCid);
}

function validatePointerEvent(event: PointerEventView): void {
  if (
    !event ||
    typeof event !== "object" ||
    !Number.isSafeInteger(event.seq) ||
    typeof event.pointerId !== "string" ||
    (event.prev !== null && typeof event.prev !== "string") ||
    typeof event.new !== "string"
  ) throw new Error("invalid pointer event");
  if (event.prev !== null) parseCidHex(event.prev);
  parseCidHex(event.new);
}

function validatePinEvent(event: PinEventView): void {
  if (
    !event ||
    typeof event !== "object" ||
    !Number.isSafeInteger(event.seq) ||
    typeof event.pinId !== "string" ||
    (event.prev !== null && typeof event.prev !== "string")
  ) throw new Error("invalid pin event");
  if (event.prev !== null) parseCidHex(event.prev);
}

function validatePointerHead(head: PointerHeadView): void {
  if (!head || typeof head !== "object" || !Number.isSafeInteger(head.seq) || head.seq < 0) {
    throw new Error("invalid pointer head");
  }
  if (head.seq === 0) {
    if (head.cid !== null || head.eventCid !== null) throw new Error("invalid empty pointer head");
    return;
  }
  if (head.cid === null || head.eventCid === null) throw new Error("invalid pointer head");
  parseCidHex(head.cid);
  parseCidHex(head.eventCid);
}

function validatePinHead(head: PinHeadView): void {
  if (!head || typeof head !== "object" || !Number.isSafeInteger(head.seq) || head.seq < 0) {
    throw new Error("invalid pin head");
  }
  if (head.seq === 0) {
    if (head.eventCid !== null) throw new Error("invalid empty pin head");
    return;
  }
  if (head.seq > MAX_EVENTS_PER_LOG || head.eventCid === null) throw new Error("invalid pin head");
  parseCidHex(head.eventCid);
}

function samePointerHead(left: PointerHeadView, right: PointerHeadView): boolean {
  return left.seq === right.seq && left.cid === right.cid && left.eventCid === right.eventCid;
}

function samePinHead(left: PinHeadView, right: PinHeadView): boolean {
  return left.seq === right.seq && left.eventCid === right.eventCid;
}

function validateHead(seq: number, cid: string): void {
  if (!Number.isSafeInteger(seq) || seq < 1 || seq > MAX_EVENTS_PER_LOG) throw new Error("invalid head sequence");
  parseCidHex(cid);
}

function validateOwnerAndTime(owner: string, nowSeconds: number): void {
  validateOwner(owner);
  validateTime(nowSeconds);
}

function validateTerminalFailure(status: number, code: string, message: string): void {
  if (!Number.isSafeInteger(status) || status < 400 || status > 599) {
    throw new Error("invalid terminal HTTP status");
  }
  if (typeof code !== "string" || !/^[a-z0-9_]{1,64}$/.test(code)) {
    throw new Error("invalid terminal error code");
  }
  if (
    typeof message !== "string" ||
    message.length < 1 ||
    message.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(message)
  ) {
    throw new Error("invalid terminal error message");
  }
}

function validateTime(nowSeconds: number): void {
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) throw new Error("invalid lease time");
}

function validateOwner(owner: string): void {
  if (
    typeof owner !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(owner)
  ) throw new Error("invalid operation owner");
}

function validateKindAndName(kind: CatalogKind, name: string): void {
  if (kind !== "pointer" && kind !== "pin") throw new Error("invalid catalog kind");
  if (typeof name !== "string") throw new Error("invalid catalog name");
  const problem = kind === "pointer" ? checkPointerId(name) : checkPinId(name);
  if (problem) throw new Error(problem);
}

function r2ReconciliationAvailable(env: EdgeEnv): boolean {
  return Boolean(
    env.CHUNKS &&
      (env.DAG_EDGE_MODE === "production-r2" ||
        env.DAG_EDGE_MODE === "demo-r2" ||
        (env.DAG_EDGE_MODE === "test" &&
          env.DAG_EDGE_TEST_HARNESS === "workerd-local-only")),
  );
}
