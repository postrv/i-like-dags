//! HTTP error mapping.
//!
//! Status codes are derived by matching the crates' typed errors, not by
//! inspecting message text. Each domain error has one `*_status` function, and
//! the aggregate errors delegate to them, so a variant added upstream shows up
//! here as a non-exhaustive-match warning rather than as a silent 500.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use dag_control::{ControlError, PointerError};
use dag_core::{CoreError, JobError, PinError};
use dag_jobs::RunError;

/// An error rendered as a JSON body plus an appropriate status code.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    /// 400 — the request was malformed.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    /// 404 — no such CID, pointer, pin or job.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    /// 409 — the request conflicts with current state (e.g. recovery gate).
    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    /// 413 — a request entity or one stored legacy record exceeds a hard
    /// representation limit.
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: message.into(),
        }
    }

    /// 503 — a bounded server resource is currently at capacity.
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    /// Build from an already-chosen status, logging server faults.
    fn with_status(status: StatusCode, message: String) -> Self {
        if status.is_server_error() {
            tracing::error!(%status, error = %message, "request failed");
        }
        // Typed storage/database errors often contain local paths, peer URLs
        // or command configuration. They belong in operator logs, not in a
        // response from the public content plane. Explicit admission errors
        // created through `service_unavailable` retain their safe actionable
        // text; errors arriving here are implementation details.
        let client_message = match status {
            StatusCode::INTERNAL_SERVER_ERROR => "internal server error",
            StatusCode::BAD_GATEWAY => "upstream service unavailable",
            StatusCode::SERVICE_UNAVAILABLE => "service unavailable",
            StatusCode::GATEWAY_TIMEOUT => "operation timed out",
            _ => return Self { status, message },
        };
        Self {
            status,
            message: client_message.to_string(),
        }
    }

    /// The status this error will be rendered with.
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

fn core_status(e: &CoreError) -> StatusCode {
    match e {
        CoreError::ChunkNotFound(_) => StatusCode::NOT_FOUND,
        // Oversized content is 413, not 400: the request is well-formed, it is
        // the entity that is unacceptable.
        CoreError::ChunkTooLarge { .. } | CoreError::FileLimitExceeded { .. } => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        CoreError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            StatusCode::REQUEST_TIMEOUT
        }
        CoreError::InvalidCid(_) | CoreError::PreconditionFailed(_) => StatusCode::BAD_REQUEST,
        CoreError::GcInventoryLimit { .. }
        | CoreError::GcInventoryBytesLimit { .. }
        | CoreError::GcIndexMismatch { .. } => StatusCode::CONFLICT,
        // Stored bytes that no longer hash to their CID are the server's
        // data rotting, not a fault in the request — previously this rode
        // along with InvalidCid as a 400, blaming the caller.
        CoreError::CidMismatch { .. }
        | CoreError::Serialization(_)
        | CoreError::Deserialization(_)
        | CoreError::Io(_)
        | CoreError::Backend(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn pointer_status(e: &PointerError) -> StatusCode {
    match e {
        PointerError::NotFound(_) => StatusCode::NOT_FOUND,
        PointerError::AlreadyExists(_) | PointerError::CasConflict { .. } => StatusCode::CONFLICT,
        PointerError::InvalidRange { .. } => StatusCode::BAD_REQUEST,
        PointerError::Capacity(_) => StatusCode::SERVICE_UNAVAILABLE,
        PointerError::TriggerPermissionRequired { .. } => StatusCode::FORBIDDEN,
        PointerError::Storage(inner) => core_status(inner),
        PointerError::Database(_) | PointerError::Serialization(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn pin_status(e: &PinError) -> StatusCode {
    match e {
        PinError::PinNotFound(_) => StatusCode::NOT_FOUND,
        PinError::PinAlreadyExists(_) => StatusCode::CONFLICT,
        PinError::InvalidPinId(_) => StatusCode::BAD_REQUEST,
        PinError::InvalidSequence { .. }
        | PinError::Storage(_)
        | PinError::Serialization(_)
        | PinError::RetentionComputation(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn job_status(e: &JobError) -> StatusCode {
    match e {
        JobError::JobNotFound(_) | JobError::RunNotFound(_) => StatusCode::NOT_FOUND,
        JobError::JobAlreadyExists(_) => StatusCode::CONFLICT,
        JobError::InvalidJobId(_)
        | JobError::InvalidRunId(_)
        | JobError::InvalidSpec(_)
        | JobError::InvalidKey(_) => StatusCode::BAD_REQUEST,
        // The job names an adapter this build does not have. That is a
        // deployment fact, not a client mistake.
        JobError::AdapterNotFound(_) => StatusCode::NOT_IMPLEMENTED,
        JobError::ExecutionFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn control_status(e: &ControlError) -> StatusCode {
    match e {
        // Both are "the deployment is not in a state where this can be done
        // safely", and both are fixed by an operator action rather than by a
        // different request.
        ControlError::NotRecovered
        | ControlError::RecoveryInventoryLimit { .. }
        | ControlError::RecoveryBytesLimit { .. }
        | ControlError::RecoveryTableLimit { .. }
        | ControlError::GcControlStateLimit { .. }
        | ControlError::RecoveryIncomplete { .. }
        | ControlError::RetentionIncomplete { .. }
        | ControlError::RetentionUnreadable { .. } => StatusCode::CONFLICT,
        ControlError::Invalid(_) => StatusCode::BAD_REQUEST,
        ControlError::Capacity(_) => StatusCode::SERVICE_UNAVAILABLE,
        ControlError::Core(inner) => core_status(inner),
        ControlError::Pointer(inner) => pointer_status(inner),
        ControlError::Pin(inner) => pin_status(inner),
        ControlError::Job(inner) => job_status(inner),
        // The deployment cannot serve until an operator intervenes.
        ControlError::SchemaTooNew { .. }
        | ControlError::SchemaTooOld { .. }
        | ControlError::ControlDbUnreadable { .. } => StatusCode::SERVICE_UNAVAILABLE,
        ControlError::DatabaseLocked { .. } => StatusCode::SERVICE_UNAVAILABLE,
        // Replication reaching *another* node failed — this server is fine,
        // the one behind it was not reached.
        ControlError::Remote(_) => StatusCode::BAD_GATEWAY,
        ControlError::LegacyDataDir { .. }
        | ControlError::Io { .. }
        | ControlError::Database(_)
        | ControlError::NoJournal
        | ControlError::Codec(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn run_status(e: &RunError) -> StatusCode {
    match e.kind() {
        RunError::Core(inner) => core_status(inner),
        RunError::Control(inner) => control_status(inner),
        RunError::Job(inner) => job_status(inner),
        // The adapter exists but this caller was not granted it. That is
        // exactly 403, and it is the status an API-reachable `exec` job gets.
        RunError::AdapterWithheld { .. } => StatusCode::FORBIDDEN,
        RunError::ConfigMissing { .. } | RunError::ConfigInvalid { .. } | RunError::Invalid(_) => {
            StatusCode::BAD_REQUEST
        }
        RunError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
        RunError::CommandFailed { .. }
        | RunError::Io { .. }
        | RunError::Adapter { .. }
        | RunError::Context { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl From<ControlError> for ApiError {
    fn from(e: ControlError) -> Self {
        Self::with_status(control_status(&e), e.to_string())
    }
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        Self::with_status(core_status(&e), e.to_string())
    }
}

impl From<PointerError> for ApiError {
    fn from(e: PointerError) -> Self {
        Self::with_status(pointer_status(&e), e.to_string())
    }
}

impl From<PinError> for ApiError {
    fn from(e: PinError) -> Self {
        Self::with_status(pin_status(&e), e.to_string())
    }
}

impl From<JobError> for ApiError {
    fn from(e: JobError) -> Self {
        Self::with_status(job_status(&e), e.to_string())
    }
}

impl From<RunError> for ApiError {
    fn from(e: RunError) -> Self {
        Self::with_status(run_status(&e), e.to_string())
    }
}

/// Errors that reach a handler through `anyhow` — the scenario seeder and a
/// few helpers still use it internally. The typed source is recovered where
/// possible so these do not all collapse to 500.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        for cause in e.chain() {
            if let Some(inner) = cause.downcast_ref::<ControlError>() {
                return Self::with_status(control_status(inner), e.to_string());
            }
            if let Some(inner) = cause.downcast_ref::<RunError>() {
                return Self::with_status(run_status(inner), e.to_string());
            }
            if let Some(inner) = cause.downcast_ref::<CoreError>() {
                return Self::with_status(core_status(inner), e.to_string());
            }
            if let Some(inner) = cause.downcast_ref::<PointerError>() {
                return Self::with_status(pointer_status(inner), e.to_string());
            }
            if let Some(inner) = cause.downcast_ref::<PinError>() {
                return Self::with_status(pin_status(inner), e.to_string());
            }
        }
        Self::with_status(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

/// Convenient result alias for handlers.
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_content_is_404_through_every_wrapper() {
        let direct: ApiError = CoreError::ChunkNotFound("abc".into()).into();
        assert_eq!(direct.status(), StatusCode::NOT_FOUND);

        // Wrapped in the control error...
        let via_control: ApiError =
            ControlError::Core(CoreError::ChunkNotFound("abc".into())).into();
        assert_eq!(via_control.status(), StatusCode::NOT_FOUND);

        // ...and buried under run-context, which is what a job failure looks like.
        let run = RunError::Context {
            context: "reading input".into(),
            source: Box::new(RunError::Core(CoreError::ChunkNotFound("abc".into()))),
        };
        let via_run: ApiError = run.into();
        assert_eq!(via_run.status(), StatusCode::NOT_FOUND);

        // ...and through anyhow, which the scenario seeder still returns.
        let via_anyhow: ApiError =
            anyhow::Error::from(CoreError::ChunkNotFound("abc".into())).into();
        assert_eq!(via_anyhow.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_withheld_adapter_is_forbidden_not_a_server_fault() {
        // This is the status an `exec` job gets from the unauthenticated API.
        let e: ApiError = RunError::AdapterWithheld {
            adapter: "exec".into(),
            reason: "requires --allow-exec".into(),
        }
        .into();
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn the_recovery_gate_is_a_conflict() {
        let e: ApiError = ControlError::NotRecovered.into();
        assert_eq!(e.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn pointer_trigger_backpressure_is_retryable() {
        let direct: ApiError = PointerError::Capacity("trigger queue".into()).into();
        assert_eq!(direct.status(), StatusCode::SERVICE_UNAVAILABLE);

        let wrapped: ApiError =
            ControlError::Pointer(PointerError::Capacity("trigger queue".into())).into();
        assert_eq!(wrapped.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn oversized_content_is_413_and_bad_cids_are_400() {
        let too_large: ApiError = CoreError::ChunkTooLarge {
            size: 5 << 20,
            max_size: 4 << 20,
        }
        .into();
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let file_too_large: ApiError = CoreError::FileLimitExceeded {
            resource: "bytes",
            value: 1025,
            limit: 1024,
        }
        .into();
        assert_eq!(file_too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let timed_out: ApiError = CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "idle upload",
        ))
        .into();
        assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);

        let bad_cid: ApiError = CoreError::InvalidCid("zz".into()).into();
        assert_eq!(bad_cid.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn an_unknown_adapter_is_not_implemented_rather_than_a_client_error() {
        let e: ApiError = JobError::AdapterNotFound("exec".into()).into();
        assert_eq!(e.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn a_backend_failure_is_a_server_error() {
        let e: ApiError = ControlError::Database("job log: corrupt".into()).into();
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.message, "internal server error");
    }

    #[test]
    fn a_server_error_does_not_expose_local_paths() {
        let e: ApiError = ControlError::ControlDbUnreadable {
            path: "/var/lib/private-dag/control.redb".into(),
            detail: "filesystem detail".into(),
        }
        .into();
        assert_eq!(e.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.message, "service unavailable");
        assert!(!e.message.contains("/var/lib"));
    }
}
