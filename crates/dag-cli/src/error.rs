//! CLI-level errors that need their own exit code.

/// Conditions the CLI reports that are not failures of the library beneath it.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// A provenance walk found content that no longer matches its CID.
    ///
    /// This is a successful *query* with a bad answer, so the library returns
    /// it as a report; the CLI turns it into a non-zero exit so `dag usecase
    /// verify` can be used as a check in a pipeline.
    #[error("verification failed: {corrupt} of {total} nodes do not match their recorded CID")]
    VerificationFailed { corrupt: usize, total: usize },

    /// `dag verify` found no trusted signature (or damaged content).
    ///
    /// Same shape as [`Self::VerificationFailed`]: the query succeeded, the
    /// answer is bad, and a pipeline gating on `dag verify` needs the
    /// non-zero exit.
    #[error(
        "signature verification failed: intact={intact}, {signatures} signature(s), {trusted} trusted key(s)"
    )]
    SignatureVerificationFailed {
        intact: bool,
        signatures: usize,
        trusted: usize,
    },

    /// `dag index verify` re-hashed the store and something did not match.
    ///
    /// The scan itself succeeded, so the library returns a report; without
    /// this the command exited 0 however much of the store had rotted, and an
    /// operator alerting on exit status from cron would never have been told.
    #[error(
        "integrity check failed: {invalid} of {total} chunks did not verify \
         ({missing} missing, {corrupt} corrupt, {stale} stale index, {unreadable} unreadable)"
    )]
    DamagedStore {
        invalid: usize,
        total: usize,
        missing: usize,
        corrupt: usize,
        stale: usize,
        unreadable: usize,
    },
}
