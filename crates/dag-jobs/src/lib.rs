//! Job execution: adapters, the runner with first-run effect caching, and the
//! run lifecycle that ties them to the control plane.
//!
//! # Capabilities
//!
//! Some adapters can do things a caller may not want to permit. Running a local
//! command is the obvious one, and the caller that must not permit it is the
//! HTTP server: `dag serve` has no built-in authentication, and browser-origin
//! controls are not permission to launch a local process.
//!
//! [`Capabilities`] makes that an explicit, typed decision at the call site
//! rather than an accident of which adapters happen to be registered.
//! [`execute_once`] grants nothing; the CLI opts in, the server never does.
//!
//! # Test doubles among the built-ins
//!
//! [`FakeFetchAdapter`] (`fake_fetch`) is registered in [`default_runner`] so
//! the side-effecting half of the runner — first-run effect caching, attested
//! adoption — is exercisable without a network. It is a double: it makes no
//! request and emits [`SIMULATED_FETCH_PAYLOAD`], which says as much in its own
//! bytes. [`builtin_adapters`] reports it with
//! [`AdapterInfo::simulated`]` == true`, and every surface that lists adapters
//! is expected to show that.
//!
//! **This workspace ships no HTTP client.** Fetching a URL means running one
//! through the `exec` adapter, behind its capability gate.

pub mod adapters;
pub mod error;
#[cfg(all(feature = "exec", unix))]
pub mod exec;
pub mod execution;
pub mod runner;
pub mod worker;

pub use error::{BoxError, RunError};

/// Job-execution result, defaulting to [`RunError`].
pub type Result<T, E = RunError> = std::result::Result<T, E>;

pub use adapters::{
    AttestAdapter, ConcatAdapter, EchoAdapter, FakeFetchAdapter, HashAdapter, JobAdapter,
    JobContext, MAX_ADAPTER_INPUT_BYTES, SIMULATED_FETCH_PAYLOAD, SIMULATED_FETCH_URL,
};
pub use dag_control::{AttestedEffects, EffectCache, EffectClaimSink, PinCreator};
pub use execution::{
    builtin_adapters, default_runner, effect_origin_label, execute_once, execute_once_hooked,
    execute_once_with, resolve_inputs, runner_with_capabilities, AdapterInfo, Capabilities,
    Execution, RunOutcome,
};
pub use runner::{EffectHooks, EffectOutcome, JobRunner};
pub use worker::{run_worker_until, work_once, WorkCycle, WorkerOptions, WorkerRunOutcome};

#[cfg(all(feature = "exec", unix))]
pub use exec::{ExecAdapter, ExecConfig};
