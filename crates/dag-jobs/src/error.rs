//! Errors from resolving, running and recording jobs.
//!
//! [`RunError`] is what [`crate::JobAdapter`] returns, so it is part of the
//! extension point: a third-party adapter has to be able to report a failure
//! this type can carry. [`RunError::Adapter`] exists for exactly that — it
//! boxes any `std::error::Error` — while the named variants cover the failures
//! callers actually branch on (a withheld adapter, an invalid config, a
//! command that failed or timed out).

use dag_control::ControlError;
use dag_core::{CoreError, JobError};
use thiserror::Error;

/// Any error an adapter implementation wants to report.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Everything job execution can fail with.
///
/// Marked `#[non_exhaustive]`: new variants are additive, so match with a
/// wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RunError {
    /// Content-addressed storage failed.
    #[error(transparent)]
    Core(#[from] CoreError),

    /// The control plane failed.
    #[error(transparent)]
    Control(#[from] ControlError),

    /// A job-domain error: unknown job, unknown run, bad spec.
    #[error(transparent)]
    Job(#[from] JobError),

    /// The adapter exists but was not granted to this caller.
    ///
    /// Deliberately distinct from [`JobError::AdapterNotFound`]: "not found"
    /// would send an operator hunting for a build flag when what they need is
    /// a capability at the call site.
    #[error("adapter {adapter:?} is not available here: {reason}")]
    AdapterWithheld { adapter: String, reason: String },

    /// The job spec omitted the configuration its adapter requires.
    #[error("job {job} uses the {adapter:?} adapter, which requires a `config` in its spec")]
    ConfigMissing { job: String, adapter: String },

    /// The adapter configuration was present but unusable.
    #[error("invalid {adapter:?} config for job {job}: {message}")]
    ConfigInvalid {
        adapter: String,
        job: String,
        message: String,
    },

    /// A command ran to completion but reported failure.
    #[error("command {command:?} exited with {status}: {stderr}")]
    CommandFailed {
        command: String,
        status: String,
        stderr: String,
    },

    /// A command outlived its timeout and was killed.
    #[error("command {command:?} exceeded its {timeout_secs}s timeout and was killed")]
    Timeout { command: String, timeout_secs: u64 },

    /// A filesystem operation failed, named by what was being attempted.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// An adapter reported a failure of its own.
    #[error("adapter {adapter:?} failed: {source}")]
    Adapter {
        adapter: String,
        #[source]
        source: BoxError,
    },

    /// The request was well-formed but cannot be satisfied — an output the
    /// command was supposed to produce is missing, a declared path escapes the
    /// working directory, and so on.
    #[error("{0}")]
    Invalid(String),

    /// Another error with the operation that produced it attached.
    ///
    /// The underlying typed error stays reachable through
    /// [`std::error::Error::source`], and [`RunError::kind`] peels these off
    /// when matching.
    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: Box<RunError>,
    },
}

impl From<serde_json::Error> for RunError {
    fn from(e: serde_json::Error) -> Self {
        Self::Core(CoreError::Serialization(format!("json: {}", e)))
    }
}

impl RunError {
    /// Attach the operation being attempted to a filesystem error.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Report an adapter-specific failure.
    pub fn adapter(adapter: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self::Adapter {
            adapter: adapter.into(),
            source: source.into(),
        }
    }

    /// The underlying error, with any [`RunError::Context`] wrappers removed.
    ///
    /// Match on this rather than on the error itself when the context strings
    /// are not what you are branching on.
    pub fn kind(&self) -> &RunError {
        match self {
            Self::Context { source, .. } => source.kind(),
            other => other,
        }
    }
}

/// Attach the operation being attempted to any error convertible to
/// [`RunError`].
pub(crate) trait Contextualize<T> {
    /// Wrap the error in [`RunError::Context`], computing the message lazily.
    fn ctx(self, context: impl FnOnce() -> String) -> Result<T, RunError>;
}

impl<T, E: Into<RunError>> Contextualize<T> for Result<T, E> {
    fn ctx(self, context: impl FnOnce() -> String) -> Result<T, RunError> {
        self.map_err(|e| RunError::Context {
            context: context(),
            source: Box::new(e.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_preserves_the_typed_error_underneath() {
        let e: Result<(), CoreError> = Err(CoreError::ChunkNotFound("abc".into()));
        let wrapped = e.ctx(|| "reading input".to_string()).unwrap_err();

        assert!(wrapped.to_string().starts_with("reading input: "));
        // The point of the wrapper: context for humans, type for programs.
        assert!(matches!(
            wrapped.kind(),
            RunError::Core(CoreError::ChunkNotFound(_))
        ));
        assert!(std::error::Error::source(&wrapped).is_some());
    }

    #[test]
    fn kind_peels_nested_context() {
        let e: Result<(), CoreError> = Err(CoreError::InvalidCid("zz".into()));
        let once = e.ctx(|| "inner".to_string()).unwrap_err();
        let twice: Result<(), RunError> = Err(once);
        let twice = twice.ctx(|| "outer".to_string()).unwrap_err();

        assert_eq!(twice.to_string(), "outer: inner: Invalid CID format: zz");
        assert!(matches!(
            twice.kind(),
            RunError::Core(CoreError::InvalidCid(_))
        ));
    }

    #[test]
    fn adapter_errors_carry_arbitrary_sources() {
        let e = RunError::adapter("my-adapter", std::io::Error::other("boom"));
        assert_eq!(e.to_string(), "adapter \"my-adapter\" failed: boom");
    }

    #[test]
    fn withheld_adapter_explains_itself_rather_than_reading_as_missing() {
        let e = RunError::AdapterWithheld {
            adapter: "exec".into(),
            reason: "requires --allow-exec".into(),
        };
        assert_eq!(
            e.to_string(),
            "adapter \"exec\" is not available here: requires --allow-exec"
        );
    }
}
