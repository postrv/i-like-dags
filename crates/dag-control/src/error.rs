//! # Control Plane Errors
//!
//! One error type for the whole control plane, so callers can branch on what
//! went wrong instead of matching on message text.
//!
//! The domain errors ([`CoreError`], [`PointerError`], [`PinError`],
//! [`JobError`]) are carried transparently rather than flattened into strings:
//! a caller that cares whether a pointer was missing or a pin already existed
//! can still reach that, and the CLI's exit-code mapping depends on it.

use dag_core::{CoreError, JobError, PinError};
use thiserror::Error;

use crate::pointer::PointerError;

/// Everything the control plane can fail with.
///
/// Marked `#[non_exhaustive]`: new variants are additive, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ControlError {
    /// Garbage collection was attempted before the recovery gate was satisfied.
    #[error("recovery not complete; stop the server and run `dag recover` first")]
    NotRecovered,

    /// Full recovery would materialise more store objects than its operator
    /// selected ceiling.
    #[error(
        "full recovery needs to scan more than {limit} store objects; no recovery phase was started. \
         Size the deployment and rerun `dag recover --max-objects <N>`, or use 0 only in an \
         explicitly sized offline maintenance window"
    )]
    RecoveryInventoryLimit { limit: usize },

    /// The inventory fits the object ceiling but exceeds the operator's
    /// aggregate read/working-set budget.
    #[error(
        "full recovery needs to scan {required} store bytes, above the {limit}-byte ceiling; no recovery phase was started. Size the deployment and rerun `dag recover --max-bytes <N>`, or use 0 only in an explicitly sized offline maintenance window"
    )]
    RecoveryBytesLimit { limit: u64, required: u64 },

    /// Full recovery would scan or replace more persisted control rows than
    /// its operator-selected ceiling.
    #[error(
        "full recovery needs to process {rows} control rows, above the {limit}-row ceiling; \
         no recovery phase was started. Size the database and raise `dag recover --max-objects`, \
         or use 0 only in an explicitly sized offline maintenance window"
    )]
    RecoveryTableLimit { limit: usize, rows: u64 },

    /// An ordinary GC request would materialise more persisted control rows
    /// than its end-to-end work budget permits.
    #[error(
        "garbage collection needs to process {rows} control rows, above the finite {limit}-row ceiling; no chunks were deleted. Use an explicitly unbounded offline collection only after sizing the deployment"
    )]
    GcControlStateLimit { limit: usize, rows: u64 },

    /// A full recovery phase found state it could not safely reconcile.
    ///
    /// The durable in-progress marker remains present, so GC stays closed
    /// across retries and process restarts.
    #[error("full recovery remains incomplete: {detail}")]
    RecoveryIncomplete { detail: String },

    /// A pin covers more than the retention snapshot could enumerate, so the
    /// snapshot understates what is protected.
    ///
    /// Refusing here rather than collecting is [R6] applied to the one case
    /// where "when in doubt, retain" is not a preference but the difference
    /// between a working hold and a destroyed one: everything past the
    /// ceiling would look unprotected and be deleted.
    ///
    /// [R6]: https://github.com/postrv/i-like-dags/blob/main/docs/SYSTEM_OVERVIEW.md
    #[error(
        "pin {pin_id} covers more than {max_expansion} objects (enumerated {expanded} \
         before stopping); collection would treat the remainder as unprotected. \
         Raise the ceiling with `--max-subtree-expansion` and re-run"
    )]
    RetentionIncomplete {
        pin_id: String,
        expanded: usize,
        max_expansion: usize,
    },

    /// An entry inside a pinned subtree could not be read, so what lies
    /// below it is unknown rather than absent.
    ///
    /// Its own variant because the remedy is different from the ceiling
    /// case: no flag raises this, and the honest answer is to repair or
    /// restore the named entry. Refusing is [R6] — a permissions error or a
    /// bad sector must not quietly shrink the protected set and let
    /// collection take the remainder.
    ///
    /// [R6]: https://github.com/postrv/i-like-dags/blob/main/docs/SYSTEM_OVERVIEW.md
    #[error(
        "pin {pin_id} covers an entry this store cannot read ({cid}), so what \
         lies below it cannot be enumerated; collection would treat the \
         remainder as unprotected. Repair or restore that entry — \
         `dag index verify` finds the rest — and re-run"
    )]
    RetentionUnreadable { pin_id: String, cid: String },

    /// The data directory predates the redb migration (ADR-001).
    #[error(
        "{path} holds a pre-redb data directory (found {found}); \
         run `dag migrate --data-dir {path}` to convert it"
    )]
    LegacyDataDir { path: String, found: String },

    /// A durable sled-to-redb migration marker is still active.
    ///
    /// Normal opens must not race or accidentally bless the published half of
    /// an interrupted migration. Only the explicit migration command knows
    /// how to validate the staged database and resume retiring the originals.
    #[error(
        "{path} has an interrupted sled-to-redb migration ({marker}); \
         rerun `dag migrate --data-dir {path}` to resume it"
    )]
    MigrationInProgress { path: String, marker: String },

    /// A final redb database and live sled sources coexist without a durable
    /// migration marker, so neither can safely be chosen as authoritative.
    #[error(
        "{path} contains both {database} and live pre-redb databases ({found}) \
         without an active migration marker. Refusing the ambiguous layout; \
         preserve every file and restore or complete the migration from a \
         verified backup"
    )]
    MixedStorageLayout {
        path: String,
        database: String,
        found: String,
    },

    /// Migration evidence exists, but the filesystem is not a layout that a
    /// normal control-plane open may safely bless.
    ///
    /// In particular, a completion receipt or retired sled backups prove that
    /// `control.redb` used to exist. Initialising a fresh database beside that
    /// evidence would turn a recoverable loss into an apparently healthy empty
    /// deployment.
    #[error(
        "{path} contains migration artifacts ({found}) that do not form a safe \
         completed {database} layout. Refusing to create or open a control \
         database; preserve every artifact and recover from a verified backup"
    )]
    UnsafeMigrationLayout {
        path: String,
        database: String,
        found: String,
    },

    /// A filesystem operation failed, named by what was being attempted.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// The directory was written by a newer release than this binary.
    ///
    /// Its own variant because the alternative is redb reporting its format
    /// skew as `Corrupted(..)`, and against a provenance store the word
    /// "corrupted" sends an operator to restore from backup when the fix is
    /// to run the newer binary.
    #[error(
        "this data directory is at schema version {found}, and this build \
         understands {supported}. It was written by a newer release of `dag`; \
         nothing is wrong with it — run that version instead"
    )]
    SchemaTooNew { found: u32, supported: u32 },

    /// The directory predates a format change this build cannot read back.
    #[error(
        "this data directory is at schema version {found}, which this build \
         (version {supported}) can no longer read"
    )]
    SchemaTooOld { found: u32, supported: u32 },

    /// The control database is present but not a usable redb file.
    ///
    /// Distinguished from [`Self::Database`] because it is the expected
    /// artifact of an interrupted copy, a full disk, or a killed process —
    /// and because redb answers a half-written file with a panic rather than
    /// an error, which reaches the operator as exit 101 and a path inside
    /// `~/.cargo/registry`.
    #[error(
        "{path} is not a readable control database ({detail}). A half-written \
         file is what an interrupted copy or a full disk leaves behind; \
         restore it, or preserve and move it aside, then rebuild every derived \
         safety index offline with `dag recover --max-objects 100000 \
         --max-bytes 1073741824`"
    )]
    ControlDbUnreadable { path: String, detail: String },

    /// Another process already holds this data directory open.
    ///
    /// Its own variant rather than a flattened [`Self::Database`] string
    /// because it is neither a bug nor corruption: redb locks the file to one
    /// handle, so one process owns a directory at a time. It is the everyday
    /// collision — `dag serve` running while a CLI command fires, or two CI
    /// jobs sharing a directory — and it is transient, so callers need to be
    /// able to tell it apart in order to wait and retry.
    #[error(
        "{path} is already open by another process (`dag serve`, or another \
         `dag` command). One process owns a data directory at a time; retry, \
         or pass --lock-timeout <secs> to wait"
    )]
    DatabaseLocked { path: String },

    /// The control database (redb) failed. The string names the table or log
    /// that was being touched — a bare redb error says nothing about where.
    #[error("control database error: {0}")]
    Database(String),

    /// Content-addressed storage failed.
    #[error(transparent)]
    Core(#[from] CoreError),

    /// A pointer operation failed.
    #[error(transparent)]
    Pointer(#[from] PointerError),

    /// A pin operation failed.
    #[error(transparent)]
    Pin(#[from] PinError),

    /// A job operation failed.
    #[error(transparent)]
    Job(#[from] JobError),

    /// An event-journal operation needed a journal that was not configured.
    #[error("no event journal configured")]
    NoJournal,

    /// Encoding or decoding a stored record failed.
    ///
    /// On a read path this means on-disk corruption or a record written by an
    /// incompatible version — not a caller mistake.
    #[error("codec error: {0}")]
    Codec(String),

    /// Input failed validation before anything was written.
    #[error("{0}")]
    Invalid(String),

    /// A bounded durable queue or other admission-controlled resource is full.
    ///
    /// Distinct from invalid input and internal failure: callers may retry
    /// after an operator drains/compacts the named resource.
    #[error("capacity limit reached: {0}")]
    Capacity(String),

    /// A remote node failed at the transport level during replication
    /// (ADR-005) — unreachable, reset, or answering outside the protocol.
    ///
    /// Distinct from [`Self::Invalid`] because the remedy differs: this is an
    /// availability problem (check the address, the token, the network), not
    /// bad input. The CLI maps it to `EX_UNAVAILABLE`.
    #[error("remote node: {0}")]
    Remote(String),
}

impl From<serde_json::Error> for ControlError {
    fn from(e: serde_json::Error) -> Self {
        Self::Codec(format!("json: {}", e))
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for ControlError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::Codec(format!("cbor encode: {}", e))
    }
}

impl From<ciborium::de::Error<std::io::Error>> for ControlError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Self::Codec(format!("cbor decode: {}", e))
    }
}

impl ControlError {
    /// Attach the operation being attempted to a filesystem error.
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Attach the log or table being touched to a database error.
    pub(crate) fn db(context: &str, e: impl std::fmt::Display) -> Self {
        Self::Database(format!("{}: {}", context, e))
    }
}

/// Control-plane result, defaulting to [`ControlError`].
pub type Result<T, E = ControlError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_directory_error_names_the_migration_command() {
        let e = ControlError::LegacyDataDir {
            path: "/data/dag".into(),
            found: "index, pointer.db".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("dag migrate --data-dir /data/dag"), "{}", msg);
        assert!(msg.contains("index, pointer.db"), "{}", msg);
    }

    #[test]
    fn interrupted_migration_error_names_the_only_safe_resume_command() {
        let error = ControlError::MigrationInProgress {
            path: "/data/dag".into(),
            marker: "/data/dag/.control-redb-migration-v1".into(),
        };
        let message = error.to_string();
        assert!(
            message.contains("dag migrate --data-dir /data/dag"),
            "{message}"
        );
        assert!(message.contains("interrupted"), "{message}");
    }

    #[test]
    fn unsafe_migration_layout_error_refuses_empty_reinitialization() {
        let error = ControlError::UnsafeMigrationLayout {
            path: "/data/dag".into(),
            database: "control.redb".into(),
            found: ".control-redb-migration-v1.complete, pointer.db.sled.bak".into(),
        };
        let message = error.to_string();
        assert!(message.contains("Refusing to create or open"), "{message}");
        assert!(message.contains("verified backup"), "{message}");
    }

    #[test]
    fn io_errors_keep_the_operation_context_and_the_source() {
        let e = ControlError::io(
            "failed to create /data/dag",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        assert!(e.to_string().contains("failed to create /data/dag"));
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn domain_errors_convert_and_stay_matchable() {
        // The point of `#[error(transparent)]` + `#[from]`: a caller can still
        // tell a missing pointer from a database failure after conversion.
        let e: ControlError = PointerError::NotFound("p1".into()).into();
        assert!(matches!(
            e,
            ControlError::Pointer(PointerError::NotFound(_))
        ));
        assert_eq!(e.to_string(), "Pointer p1 not found");

        let e: ControlError = CoreError::ChunkNotFound("abc".into()).into();
        assert!(matches!(e, ControlError::Core(CoreError::ChunkNotFound(_))));
    }

    #[test]
    fn database_errors_name_the_log_that_failed() {
        let e = ControlError::db("job log", "table not found");
        assert_eq!(
            e.to_string(),
            "control database error: job log: table not found"
        );
    }
}
