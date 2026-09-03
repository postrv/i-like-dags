//! The `exec` adapter: run a local command over content-addressed inputs.
//!
//! This turns the job system from a demo into something that can drive real
//! work — a training script, a compiler, a report generator — while keeping the
//! provenance guarantees the rest of the system provides: inputs are resolved
//! from CIDs and pointers, outputs are stored as content, and the run record
//! says exactly which revisions were read.
//!
//! # Threat model — read this before enabling it
//!
//! **The exec adapter runs arbitrary commands with the full privileges of the
//! `dag` process. There is no sandbox.** It is a build tool, not a jail. Every
//! mitigation below is defence in depth around that one fact:
//!
//! - **Compile-time opt-in.** Gated behind the `exec` cargo feature, off by
//!   default, so a `dag` built for storage duty cannot execute anything.
//! - **Never reachable from the HTTP API.** `dag serve` has no built-in
//!   authentication. Its loopback, Host, fetch-metadata, and CORS restrictions
//!   reduce browser exposure, but none is authority to execute a process.
//!   Exec is therefore registered only when a caller explicitly asks for
//!   [`crate::Capabilities::exec`], which the CLI can do and the HTTP server
//!   never does.
//! - **No shell.** The command and its arguments are passed to the OS
//!   directly, so there is no shell to inject metacharacters into. A config
//!   wanting a pipeline must invoke a shell explicitly and owns that decision.
//! - **Empty environment by default.** The child gets only what the config
//!   declares plus a minimal `PATH`, so secrets in the parent environment
//!   (cloud credentials, tokens) are not inherited into job processes.
//! - **Working directory is a fresh temp dir**, removed afterwards. The
//!   command sees its inputs under `inputs/` and is expected to write under
//!   `outputs/`; nothing else is prepared for it.
//! - **Wall-clock timeout**, always set, defaulting to five minutes. Every
//!   command starts in its own Unix process group; an overrun kills that group
//!   before reaping its leader, so ordinary child processes cannot survive the
//!   timeout. Configs cannot raise it above one hour. The adapter is withheld
//!   on non-Unix targets where this guarantee is not implemented.
//! - **Bounded process streams and collected outputs.** Stdout and stderr are
//!   drained concurrently with a 16 MiB ceiling each, declared output paths
//!   must resolve inside the fresh workspace, and per-file plus aggregate
//!   ingestion limits are checked before content is published. A non-zero
//!   command surfaces only the newest 20 stderr lines within 16 KiB; that tail
//!   can reach the run record and logs, so commands must not print secrets.
//!
//! What this does *not* do: restrict filesystem access outside the temp dir,
//! limit memory or CPU, impose a filesystem quota while the command is still
//! running, isolate the network, or prevent a command from reading the data
//! directory itself. If you need those, run `dag` inside a container or a VM
//! — the isolation belongs to the platform, and pretending otherwise
//! in-process would be security theatre.
//!
//! # Configuration
//!
//! ```json
//! {
//!   "command": "python3",
//!   "args": ["train.py", "--data", "inputs/datasets~customer-transactions"],
//!   "env": { "PYTHONHASHSEED": "0" },
//!   "outputs": { "model": "outputs/model.bin", "metrics": "outputs/metrics.json" },
//!   "timeout_secs": 3600,
//!   "capture_stdout": true
//! }
//! ```
//!
//! Inputs are materialised before the command runs:
//!
//! - static inputs as `inputs/static-<n>`, in spec order;
//! - pointer inputs as `inputs/<pointer id with '/' replaced by '~'>`.
//!
//! A chunked file (a `file/v1` manifest) is reassembled into a whole file, so a
//! job over a 50 GB model sees a 50 GB file, not a manifest. Outputs are read
//! back through the same path, so a large output is chunked on the way in.
//!
//! # Caching
//!
//! Exec is always side-effecting: running a command is an effect. Its effect
//! key covers the command, arguments, environment, declared outputs *and* the
//! resolved input manifest, which gives build-cache semantics — the same
//! command over the same inputs is not re-run, and changing any part of the
//! command invalidates that. Set `CachePolicy::None` on the job if you want a
//! command to run every time.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Contextualize, RunError};
use crate::Result;
use async_trait::async_trait;
use dag_core::{Cid, ContentStore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::adapters::{JobAdapter, JobContext};

/// Default wall-clock limit for a command.
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;
/// No single command may retain a worker indefinitely.
pub const MAX_TIMEOUT_SECS: u64 = 60 * 60;
/// Captured stdout and stderr are each bounded independently.
pub const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum stderr bytes surfaced in a failed-command error. The full stream
/// may be captured explicitly as an output, but errors flow through tracing,
/// HTTP and the durable run record and therefore need a much smaller bound.
pub const MAX_FAILURE_STDERR_BYTES: usize = 16 * 1024;
/// One declared output file may occupy at most one GiB.
pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
/// Aggregate declared files plus captured streams per run.
pub const MAX_TOTAL_OUTPUT_BYTES: u64 = 4 * MAX_OUTPUT_BYTES;
/// One materialised input may occupy at most one GiB.
pub const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
/// Aggregate materialised inputs per run.
pub const MAX_TOTAL_INPUT_BYTES: u64 = 4 * MAX_INPUT_BYTES;
const JOB_FILE_LIMITS: dag_core::FileLimits = dag_core::FileLimits {
    max_file_size: MAX_INPUT_BYTES,
    max_chunks: 65_536,
    max_manifest_nodes: 8_192,
    max_links: 131_072,
    max_fetches: 131_073,
};
const MAX_ARGS: usize = 1_024;
const MAX_ENV_VARS: usize = 256;
const MAX_OUTPUTS: usize = 256;
const MAX_CONFIG_TEXT_BYTES: usize = 64 * 1024;
/// Conservative portable ceiling for one materialised input path component.
/// Common Unix filesystems support 255-byte names; rejecting at that boundary
/// gives an explicit adapter error instead of an OS-dependent partial layout.
const MAX_INPUT_FILE_NAME_BYTES: usize = 255;

/// `PATH` given to the child when the config does not set one.
///
/// Deliberately not inherited: a job's toolchain should be a declared part of
/// its configuration, not whatever happened to be on the operator's path.
pub const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Exec adapter configuration, read from [`dag_core::JobSpec::config`].
///
/// `BTreeMap` for `env` and `outputs`: their serialisation feeds the effect
/// key, and a `HashMap` would order it differently run to run, so identical
/// configs would miss the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecConfig {
    /// Program to run. Resolved against `PATH`; not interpreted by a shell.
    pub command: String,
    /// Arguments, passed verbatim.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment for the child. The parent's environment is *not* inherited.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Outputs to collect: declared name → path relative to the working
    /// directory. A declared output the command did not produce fails the run.
    #[serde(default)]
    pub outputs: BTreeMap<String, String>,
    /// Wall-clock limit. Defaults to [`DEFAULT_TIMEOUT_SECS`].
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Also store the command's stdout as an output named `stdout`.
    #[serde(default)]
    pub capture_stdout: bool,
    /// Also store the command's stderr as an output named `stderr`.
    #[serde(default)]
    pub capture_stderr: bool,
    /// Treat a non-zero exit status as success.
    ///
    /// Off by default. Useful for a command whose exit code is part of the
    /// result (a linter, a checker) rather than a failure signal.
    #[serde(default)]
    pub allow_failure: bool,
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

impl ExecConfig {
    fn validate(&self) -> Result<()> {
        if self.command.trim().is_empty() {
            return Err(RunError::Invalid(
                "exec config needs a non-empty `command`".to_string(),
            ));
        }
        if self.command.len() > 4_096 || contains_nul(&self.command) {
            return Err(RunError::Invalid(
                "exec `command` must be at most 4096 bytes and contain no NUL".to_string(),
            ));
        }
        if self.timeout_secs == 0 || self.timeout_secs > MAX_TIMEOUT_SECS {
            return Err(RunError::Invalid(format!(
                "exec `timeout_secs` must be between 1 and {MAX_TIMEOUT_SECS}"
            )));
        }
        if self.outputs.is_empty() && !self.capture_stdout && !self.capture_stderr {
            return Err(RunError::Invalid(
                "exec config collects nothing: declare `outputs`, or set \
                 `capture_stdout`/`capture_stderr`"
                    .to_string(),
            ));
        }
        if self.args.len() > MAX_ARGS {
            return Err(RunError::Invalid(format!(
                "exec config has {} arguments; the limit is {MAX_ARGS}",
                self.args.len()
            )));
        }
        if self.env.len() > MAX_ENV_VARS {
            return Err(RunError::Invalid(format!(
                "exec config has {} environment variables; the limit is {MAX_ENV_VARS}",
                self.env.len()
            )));
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(RunError::Invalid(format!(
                "exec config has {} declared outputs; the limit is {MAX_OUTPUTS}",
                self.outputs.len()
            )));
        }
        let text_bytes = self
            .args
            .iter()
            .map(String::len)
            .chain(
                self.env
                    .iter()
                    .flat_map(|(key, value)| [key.len(), value.len()]),
            )
            .chain(
                self.outputs
                    .iter()
                    .flat_map(|(name, path)| [name.len(), path.len()]),
            )
            .try_fold(0usize, |total, len| total.checked_add(len))
            .ok_or_else(|| RunError::Invalid("exec config text size overflowed".into()))?;
        if text_bytes > MAX_CONFIG_TEXT_BYTES {
            return Err(RunError::Invalid(format!(
                "exec config contains {text_bytes} bytes of arguments, environment and output names; the limit is {MAX_CONFIG_TEXT_BYTES}"
            )));
        }
        if self.args.iter().any(|arg| contains_nul(arg)) {
            return Err(RunError::Invalid(
                "exec arguments cannot contain NUL bytes".into(),
            ));
        }
        for (key, value) in &self.env {
            if key.is_empty() || key.contains('=') || contains_nul(key) || contains_nul(value) {
                return Err(RunError::Invalid(format!(
                    "exec environment name {key:?} is empty/invalid or its value contains NUL"
                )));
            }
        }
        for (name, path) in &self.outputs {
            if name.is_empty() || contains_nul(name) || contains_nul(path) {
                return Err(RunError::Invalid(
                    "exec output names and paths must be non-empty and contain no NUL".into(),
                ));
            }
            if !is_portable_relative_output_path(path) {
                return Err(RunError::Invalid(format!(
                    "output {:?} must be a portable relative path with ordinary components: {:?}",
                    name, path
                )));
            }
        }
        for reserved in ["stdout", "stderr"] {
            if self.outputs.contains_key(reserved) {
                return Err(RunError::Invalid(format!(
                    "output name {:?} is reserved for capture_{}",
                    reserved, reserved
                )));
            }
        }
        Ok(())
    }
}

fn contains_nul(value: &str) -> bool {
    value.as_bytes().contains(&0)
}

/// Runs a declared command over materialised inputs.
///
/// See the [module docs](self) for the threat model. Construct it only where
/// [`crate::Capabilities::exec`] has been granted.
pub struct ExecAdapter;

/// Filesystem-safe name for a pointer input.
///
/// Pointer IDs are paths (`datasets/customer-transactions`), which would nest
/// directories under `inputs/` and collide with `..` handling. `~` keeps the
/// name readable and flat.
fn input_file_name(pointer_id: &str) -> String {
    pointer_id.replace(['/', '\\'], "~")
}

/// Whether one already-flat component is portable across the filesystems on
/// which the native worker can run.
///
/// In particular, `:` can introduce a Windows drive prefix or NTFS alternate
/// stream, and device basenames such as `NUL.txt` are not ordinary files.
/// Refusing those spellings on every host keeps a recorded manifest's layout
/// independent of where the worker happens to execute it.
fn is_portable_input_file_name(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_INPUT_FILE_NAME_BYTES
        || name.ends_with(' ')
        || name.ends_with('.')
        || name
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return false;
    }

    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    !matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            upper.as_str(),
            "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}

/// Validate the textual path grammar independent of the current host.
/// Forward slash is the only accepted separator; backslash could be a literal
/// on Unix and a separator on Windows, which would give a replicated job two
/// different output layouts. Canonical containment is still rechecked after
/// the command exits to defeat symlink traversal.
fn is_portable_relative_output_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(is_portable_input_file_name)
}

/// Plan every input pathname before writing any of them.
///
/// The historical slash-to-tilde spelling is retained for job compatibility,
/// but it is not injective (`a/b` and `a~b` both become `a~b`) and a pointer
/// named `static-0` would otherwise overwrite the first static input. Refuse
/// those ambiguous manifests rather than executing against bytes different
/// from the immutable manifest recorded for the run.
fn pointer_input_file_names(ctx: &JobContext<'_>) -> Result<Vec<String>> {
    let mut occupied = HashSet::with_capacity(
        ctx.manifest
            .static_inputs
            .len()
            .saturating_add(ctx.manifest.pointer_heads.len()),
    );
    for index in 0..ctx.manifest.static_inputs.len() {
        occupied.insert(format!("static-{index}"));
    }

    let mut names = Vec::with_capacity(ctx.manifest.pointer_heads.len());
    for resolved in &ctx.manifest.pointer_heads {
        let name = input_file_name(&resolved.pointer_id);
        if !is_portable_input_file_name(&name) {
            return Err(RunError::Invalid(format!(
                "pointer input {:?} does not map to a portable input filename of at most {MAX_INPUT_FILE_NAME_BYTES} bytes",
                resolved.pointer_id
            )));
        }
        if !occupied.insert(name.clone()) {
            return Err(RunError::Invalid(format!(
                "pointer input {:?} maps to duplicate exec input filename {:?}; rename the pointer or use a static input without that collision",
                resolved.pointer_id, name
            )));
        }
        names.push(name);
    }
    Ok(names)
}

#[async_trait]
impl JobAdapter for ExecAdapter {
    fn name(&self) -> &'static str {
        "exec"
    }

    /// Always side-effecting: running a command is an effect, and the effect
    /// cache is what gives this build-cache semantics.
    fn is_deterministic(&self) -> bool {
        false
    }

    fn effect_spec(&self, ctx: &JobContext<'_>) -> Option<String> {
        // Serialise the whole config: the command, its arguments, its
        // environment and what it collects all change what the effect *is*.
        // The manifest is hashed into the key separately by the runner.
        let config: ExecConfig = ctx.parse_config("exec").ok()?;
        serde_json::to_string(&config).ok()
    }

    async fn run(
        &self,
        store: &Arc<dyn ContentStore>,
        ctx: &JobContext<'_>,
    ) -> Result<Vec<(String, Cid)>> {
        let config: ExecConfig = ctx.parse_config("exec")?;
        config.validate()?;

        // Fresh working directory, removed when `workspace` drops — including
        // on the error paths below.
        let workspace = tempfile::Builder::new()
            .prefix("dag-exec-")
            .tempdir()
            .map_err(|e| RunError::io("creating a working directory for the command", e))?;
        let root = workspace.path().to_path_buf();

        materialise_inputs(store, ctx, &root)?;
        std::fs::create_dir_all(root.join("outputs"))
            .map_err(|e| RunError::io("creating the outputs directory", e))?;

        let output = run_command(&config, &root).await?;

        if !output.status.success() && !config.allow_failure {
            // Stderr is the operator's first question, so put it in the error
            // rather than making them go and find the failed run's record.
            let tail = failure_stderr_tail(&output.stderr);
            return Err(RunError::CommandFailed {
                command: config.command.clone(),
                status: output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "a signal".to_string()),
                stderr: if tail.is_empty() {
                    "(no stderr)".to_string()
                } else {
                    tail
                },
            });
        }

        collect_outputs(store, &config, &root, &output)
    }
}

/// Keep at most the newest 20 lines and 16 KiB of stderr without first
/// allocating a String for the adapter's full 16 MiB capture. Starting in the
/// middle of an invalid UTF-8 sequence is repaired lossily, then the final
/// String is trimmed on a character boundary so its encoded size is bounded.
fn failure_stderr_tail(stderr: &[u8]) -> String {
    let start = stderr.len().saturating_sub(MAX_FAILURE_STDERR_BYTES);
    let bounded = String::from_utf8_lossy(&stderr[start..]);
    let mut lines: Vec<&str> = bounded.lines().rev().take(20).collect();
    lines.reverse();
    let tail = lines.join("\n");
    if tail.len() <= MAX_FAILURE_STDERR_BYTES {
        return tail;
    }

    let mut start = tail.len() - MAX_FAILURE_STDERR_BYTES;
    while !tail.is_char_boundary(start) {
        start += 1;
    }
    tail[start..].to_string()
}

/// Write each resolved input into `<root>/inputs/`.
///
/// Chunked files are reassembled, so a command always sees whole files.
fn materialise_inputs(
    store: &Arc<dyn ContentStore>,
    ctx: &JobContext<'_>,
    root: &Path,
) -> Result<()> {
    // The layout itself is part of what the command consumes. Establish that
    // it is unambiguous before content reads or filesystem writes begin.
    let pointer_file_names = pointer_input_file_names(ctx)?;

    // Validate every declared total and the aggregate before creating a
    // single input file. Otherwise a hostile late manifest can consume the
    // workspace quota with earlier inputs and fail only after substantial I/O.
    let mut total = 0u64;
    for cid in ctx.manifest.static_inputs.iter().chain(
        ctx.manifest
            .pointer_heads
            .iter()
            .map(|resolved| &resolved.head_cid),
    ) {
        let bytes = store
            .get_chunk(cid)
            .ctx(|| format!("inspecting input {}", cid))?;
        let size = dag_core::file::inspect_from_bytes_with_limits(&bytes, &JOB_FILE_LIMITS)
            .ctx(|| format!("validating input manifest {}", cid))?
            .map_or(bytes.len() as u64, |info| info.size);
        if size > MAX_INPUT_BYTES {
            return Err(RunError::Invalid(format!(
                "exec input {cid} is {size} bytes; the per-input limit is {MAX_INPUT_BYTES}"
            )));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| RunError::Invalid("exec input byte count overflowed".into()))?;
        if total > MAX_TOTAL_INPUT_BYTES {
            return Err(RunError::Invalid(format!(
                "exec inputs total {total} bytes; the aggregate limit is {MAX_TOTAL_INPUT_BYTES}"
            )));
        }
    }

    let inputs = root.join("inputs");
    std::fs::create_dir_all(&inputs)
        .map_err(|e| RunError::io("creating the inputs directory", e))?;

    for (i, cid) in ctx.manifest.static_inputs.iter().enumerate() {
        write_input(store, cid, &inputs.join(format!("static-{}", i)))?;
    }
    for (resolved, name) in ctx.manifest.pointer_heads.iter().zip(pointer_file_names) {
        write_input(store, &resolved.head_cid, &inputs.join(name))?;
    }
    Ok(())
}

/// Materialise one CID as a file, reassembling it if it is a file manifest.
fn write_input(store: &Arc<dyn ContentStore>, cid: &Cid, path: &Path) -> Result<()> {
    let bytes = store
        .get_chunk(cid)
        .ctx(|| format!("reading input {}", cid))?;

    // A file manifest becomes the file it describes; `join` re-hashes every
    // chunk, so a command never sees content that failed verification.
    if dag_core::file::inspect_from_bytes_with_limits(&bytes, &JOB_FILE_LIMITS)
        .ctx(|| format!("validating input manifest {}", cid))?
        .is_some()
    {
        let file = std::fs::File::create(path)
            .map_err(|e| RunError::io(format!("creating {}", path.display()), e))?;
        let mut writer = std::io::BufWriter::new(file);
        dag_core::file::join_with_limits(store.as_ref(), cid, &mut writer, &JOB_FILE_LIMITS)
            .ctx(|| format!("reassembling input {}", cid))?;
        return Ok(());
    }

    std::fs::write(path, &bytes).map_err(|e| RunError::io(format!("writing {}", path.display()), e))
}

/// Spawn the command and wait for it, enforcing the timeout.
#[derive(Debug)]
struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_command(config: &ExecConfig, root: &Path) -> Result<CommandOutput> {
    let mut command = tokio::process::Command::new(&config.command);
    command
        .args(&config.args)
        .current_dir(root)
        // No shell, and no inherited environment: see the module threat model.
        .env_clear()
        .env("PATH", DEFAULT_PATH)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Killing the child when the future is dropped is what makes the
        // timeout below actually stop the work rather than just stop waiting.
        .kill_on_drop(true);

    // The PID becomes the process-group ID. Keeping every ordinary descendant
    // in this private group lets the timeout terminate the work, not merely
    // the executable at the root of it.
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);

    for (key, value) in &config.env {
        command.env(key, value);
    }

    let started = std::time::Instant::now();
    let timeout = Duration::from_secs(config.timeout_secs);
    let mut child = command.spawn().map_err(|e| {
        RunError::io(
            format!(
                "failed to run {:?} (is it installed and on PATH {:?}?)",
                config.command, DEFAULT_PATH
            ),
            e,
        )
    })?;
    let process_group = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| RunError::Invalid("exec child did not expose a valid process id".into()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        RunError::Invalid("exec child did not expose its configured stdout pipe".into())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        RunError::Invalid("exec child did not expose its configured stderr pipe".into())
    })?;

    // Read both pipes concurrently with the child wait. Waiting first can
    // deadlock when an OS pipe fills; collecting with `Command::output`, on
    // the other hand, grows two Vecs without a ceiling. A reader crossing its
    // limit cancels the wait and the child is killed below.
    let execution = async {
        let stdout = read_bounded(stdout, "stdout", MAX_CAPTURE_BYTES);
        let stderr = read_bounded(stderr, "stderr", MAX_CAPTURE_BYTES);
        // Drain the streams before reaping the group leader. If a descendant
        // inherits a pipe and outlives the leader, the leader remains a zombie
        // (and its PID cannot be reused) until the timeout kills the group.
        let (stdout, stderr) = tokio::try_join!(stdout, stderr)?;
        let status = child
            .wait()
            .await
            .map_err(|error| RunError::io("waiting for the exec child", error))?;
        Ok::<_, RunError>(CommandOutput {
            status,
            stdout,
            stderr,
        })
    };

    let output = match tokio::time::timeout(timeout, execution).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            terminate_command_group(&mut child, process_group).await;
            return Err(error);
        }
        Err(_) => {
            terminate_command_group(&mut child, process_group).await;
            return Err(RunError::Timeout {
                command: config.command.clone(),
                timeout_secs: config.timeout_secs,
            });
        }
    };

    tracing::info!(
        command = %config.command,
        exit = ?output.status.code(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "exec adapter ran a command"
    );

    Ok(output)
}

/// Kill the private process group before reaping its leader.
///
/// The leader is deliberately still waitable on every error/timeout path, so
/// its numeric PID cannot be recycled into an unrelated process group between
/// selecting the target and sending the signal.
async fn terminate_command_group(
    child: &mut tokio::process::Child,
    process_group: rustix::process::Pid,
) {
    if let Err(error) =
        rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL)
    {
        tracing::warn!(%error, pid = process_group.as_raw_pid(), "failed to kill exec process group");
        // Fallback for a platform/runtime anomaly. This does not replace the
        // group kill, but it still prevents the direct child surviving.
        let _ = child.start_kill();
    }
    if let Err(error) = child.wait().await {
        tracing::warn!(%error, pid = process_group.as_raw_pid(), "failed to reap exec process-group leader");
    }
}

async fn read_bounded<R>(mut reader: R, label: &str, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buf)
            .await
            .map_err(|error| RunError::io(format!("reading exec {label}"), error))?;
        if read == 0 {
            return Ok(out);
        }
        let next = out
            .len()
            .checked_add(read)
            .ok_or_else(|| RunError::Invalid(format!("exec {label} size overflowed")))?;
        if next > limit {
            return Err(RunError::Invalid(format!(
                "exec {label} exceeded the {limit}-byte capture limit; redirect verbose output to a declared file"
            )));
        }
        out.try_reserve(read).map_err(|_| {
            RunError::Invalid(format!(
                "exec {label} could not reserve its bounded capture buffer"
            ))
        })?;
        out.extend_from_slice(&buf[..read]);
    }
}

/// Store the declared output files, plus captured streams.
fn collect_outputs(
    store: &Arc<dyn ContentStore>,
    config: &ExecConfig,
    root: &Path,
    output: &CommandOutput,
) -> Result<Vec<(String, Cid)>> {
    let mut collected = Vec::new();
    let mut total_bytes = 0u64;
    let canonical_root = root
        .canonicalize()
        .map_err(|error| RunError::io("canonicalizing the exec workspace", error))?;

    for (name, relative) in &config.outputs {
        let path = root.join(relative);
        if !path.exists() {
            return Err(RunError::Invalid(format!(
                "command succeeded but declared output {:?} is missing at {:?}",
                name, relative
            )));
        }
        let canonical = path.canonicalize().map_err(|error| {
            RunError::io(
                format!("canonicalizing declared output {:?}", relative),
                error,
            )
        })?;
        if !canonical.starts_with(&canonical_root) {
            return Err(RunError::Invalid(format!(
                "declared output {name:?} resolves outside the exec workspace: {relative:?}"
            )));
        }
        let metadata = std::fs::metadata(&canonical)
            .map_err(|error| RunError::io(format!("inspecting {}", canonical.display()), error))?;
        if metadata.is_dir() {
            return Err(RunError::Invalid(format!(
                "declared output {:?} is a directory ({:?}); archive it in the \
                 command if you need a tree",
                name, relative
            )));
        }
        if !metadata.is_file() {
            return Err(RunError::Invalid(format!(
                "declared output {name:?} is not a regular file: {relative:?}"
            )));
        }
        account_output_bytes(&mut total_bytes, metadata.len(), name)?;

        collected.push((name.clone(), store_file(store, &canonical)?));
    }

    if config.capture_stdout {
        account_output_bytes(&mut total_bytes, output.stdout.len() as u64, "stdout")?;
        collected.push((
            "stdout".to_string(),
            store_bytes(store, &output.stdout, "stdout")?,
        ));
    }
    if config.capture_stderr {
        account_output_bytes(&mut total_bytes, output.stderr.len() as u64, "stderr")?;
        collected.push((
            "stderr".to_string(),
            store_bytes(store, &output.stderr, "stderr")?,
        ));
    }

    // Stable order so a re-run's outputs compare equal element-wise.
    collected.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(collected)
}

fn account_output_bytes(total: &mut u64, next: u64, name: &str) -> Result<()> {
    if next > MAX_OUTPUT_BYTES {
        return Err(RunError::Invalid(format!(
            "exec output {name:?} is {next} bytes; the per-output limit is {MAX_OUTPUT_BYTES}"
        )));
    }
    let updated = total
        .checked_add(next)
        .ok_or_else(|| RunError::Invalid("exec output byte count overflowed".into()))?;
    if updated > MAX_TOTAL_OUTPUT_BYTES {
        return Err(RunError::Invalid(format!(
            "exec outputs total {updated} bytes; the aggregate limit is {MAX_TOTAL_OUTPUT_BYTES}"
        )));
    }
    *total = updated;
    Ok(())
}

fn store_bytes(store: &Arc<dyn ContentStore>, bytes: &[u8], name: &str) -> Result<Cid> {
    match dag_core::file::store_auto_with_limits(
        store.as_ref(),
        std::io::Cursor::new(bytes),
        None,
        false,
        &dag_core::ChunkerConfig::default(),
        &JOB_FILE_LIMITS,
    )
    .ctx(|| format!("storing captured exec {name}"))?
    {
        dag_core::StoredContent::Chunk { cid, .. } => Ok(cid),
        dag_core::StoredContent::File(report) => Ok(report.cid),
    }
}

/// Store one produced file, chunking it if it exceeds the chunk limit.
fn store_file(store: &Arc<dyn ContentStore>, path: &PathBuf) -> Result<Cid> {
    let file = std::fs::File::open(path)
        .map_err(|e| RunError::io(format!("opening {}", path.display()), e))?;
    let size_before = file
        .metadata()
        .map_err(|e| RunError::io(format!("inspecting {}", path.display()), e))?
        .len();
    if size_before > MAX_OUTPUT_BYTES {
        return Err(RunError::Invalid(format!(
            "exec output {} is {size_before} bytes; the limit is {MAX_OUTPUT_BYTES}",
            path.display()
        )));
    }
    // A background descendant could still append after the direct child has
    // exited. Read at most one byte beyond the ceiling and reject that result
    // instead of following an ever-growing file until disk exhaustion.
    let reader = std::io::BufReader::new(std::io::Read::take(file, MAX_OUTPUT_BYTES + 1));

    let stored = dag_core::file::store_auto_with_limits(
        store.as_ref(),
        reader,
        None,
        false,
        &dag_core::ChunkerConfig::default(),
        &JOB_FILE_LIMITS,
    )
    .ctx(|| format!("storing {}", path.display()))?;
    match stored {
        dag_core::StoredContent::Chunk { cid, size } if size <= MAX_OUTPUT_BYTES => Ok(cid),
        dag_core::StoredContent::File(report) if report.size <= MAX_OUTPUT_BYTES => Ok(report.cid),
        dag_core::StoredContent::Chunk { size, .. } => Err(RunError::Invalid(format!(
            "exec output {} grew to {size} bytes while it was being stored; the limit is {MAX_OUTPUT_BYTES}",
            path.display()
        ))),
        dag_core::StoredContent::File(report) => Err(RunError::Invalid(format!(
            "exec output {} grew to {} bytes while it was being stored; the limit is {MAX_OUTPUT_BYTES}",
            path.display(), report.size
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::{
        Determinism, InputManifest, JobId, JobInput, JobPolicy, JobSpec, ResolvedPointer,
    };
    use dag_storage::FsStore;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Arc<dyn ContentStore>) {
        let temp = TempDir::new().unwrap();
        let store: Arc<dyn ContentStore> =
            Arc::new(FsStore::new(temp.path().join("data")).unwrap());
        (temp, store)
    }

    fn spec_with(config: serde_json::Value) -> JobSpec {
        JobSpec {
            job_id: JobId::from("exec-test"),
            placement: None,
            inputs: JobInput::new(),
            determinism: Determinism::SideEffecting,
            declared_outputs: vec![],
            code_ref: "exec".into(),
            policy: JobPolicy::default(),
            config: Some(config),
        }
    }

    fn manifest(static_inputs: Vec<Cid>) -> InputManifest {
        InputManifest {
            static_inputs,
            pointer_heads: vec![],
            resolved_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn ambiguous_input_filenames_fail_before_materialisation() {
        let (temp, store) = setup();
        let first = store.put_chunk(b"first", None).unwrap();
        let second = store.put_chunk(b"second", None).unwrap();
        let spec = spec_with(serde_json::json!({
            "command": "true",
            "outputs": { "unused": "unused" },
        }));

        for (index, input_manifest) in [
            InputManifest {
                static_inputs: vec![first.clone()],
                pointer_heads: vec![ResolvedPointer {
                    pointer_id: "static-0".into(),
                    head_cid: second.clone(),
                    log_seq: 1,
                }],
                resolved_at_unix: 1_700_000_000,
            },
            InputManifest {
                static_inputs: vec![],
                pointer_heads: vec![
                    ResolvedPointer {
                        pointer_id: "a/b".into(),
                        head_cid: first.clone(),
                        log_seq: 1,
                    },
                    ResolvedPointer {
                        pointer_id: "a~b".into(),
                        head_cid: second.clone(),
                        log_seq: 1,
                    },
                ],
                resolved_at_unix: 1_700_000_000,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let workspace = temp.path().join(format!("workspace-{index}"));
            std::fs::create_dir(&workspace).unwrap();
            let error =
                materialise_inputs(&store, &JobContext::new(&spec, &input_manifest), &workspace)
                    .unwrap_err();
            assert!(error.to_string().contains("duplicate exec input filename"));
            assert!(!workspace.join("inputs").exists());
        }
    }

    #[test]
    fn exec_input_filenames_are_portable_across_windows_and_unix() {
        for valid in ["release", "a~b", "data-01.json", "模型"] {
            assert!(is_portable_input_file_name(valid), "{valid:?}");
        }
        for invalid in [
            "",
            ".",
            "..",
            "C:payload",
            "stream:secret",
            "NUL",
            "nul.txt",
            "COM1",
            "lpt9.log",
            "trailing.",
            "trailing ",
            "wild*card",
            "line\nbreak",
        ] {
            assert!(!is_portable_input_file_name(invalid), "{invalid:?}");
        }
    }

    #[test]
    fn overlimit_manifest_inputs_fail_before_materialisation() {
        let (temp, store) = setup();
        let leaf = store.put_chunk(b"x", None).unwrap();
        let payload = serde_json::json!({
            "kind": dag_core::file::FILE_KIND,
            "size": MAX_INPUT_BYTES + 1,
            "chunks": 1,
            "depth": 1,
            "links": 1,
        });
        let root = store
            .put_entry(&dag_core::Entry::new(
                serde_json::to_vec(&payload).unwrap(),
                vec![dag_core::Link::unnamed(leaf)],
                None,
            ))
            .unwrap();
        let spec = spec_with(serde_json::json!({
            "command": "true",
            "outputs": { "unused": "unused" },
        }));
        let input_manifest = manifest(vec![root]);
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();

        let error =
            materialise_inputs(&store, &JobContext::new(&spec, &input_manifest), &workspace)
                .unwrap_err();
        assert!(error.to_string().contains("maximum allowed"));
        assert!(
            !workspace.join("inputs").exists(),
            "all totals must be preflighted before any input file is created"
        );
    }

    #[tokio::test]
    async fn runs_a_command_and_collects_its_output() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "printf 'built' > outputs/artifact.txt"],
            "outputs": { "artifact": "outputs/artifact.txt" },
        }));
        let m = manifest(vec![]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .expect("command should succeed");

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "artifact");
        assert_eq!(store.get_chunk(&outputs[0].1).unwrap(), b"built");
    }

    /// The whole point: a command reads content-addressed inputs as files.
    #[tokio::test]
    async fn inputs_are_materialised_as_files() {
        let (_temp, store) = setup();
        let a = store.put_chunk(b"alpha", None).unwrap();
        let b = store.put_chunk(b"beta", None).unwrap();

        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "cat inputs/static-0 inputs/static-1 > outputs/joined"],
            "outputs": { "joined": "outputs/joined" },
        }));
        let m = manifest(vec![a, b]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap();
        assert_eq!(store.get_chunk(&outputs[0].1).unwrap(), b"alphabeta");
    }

    /// A chunked file must arrive as the original file, not as its manifest.
    #[tokio::test]
    async fn a_chunked_input_is_reassembled_for_the_command() {
        let (_temp, store) = setup();

        // Small chunks so this splits without needing megabytes.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let report = dag_core::file::split(
            store.as_ref(),
            std::io::Cursor::new(data.clone()),
            None,
            &dag_core::ChunkerConfig {
                min_size: 1024,
                avg_size: 4096,
                max_size: 16384,
                links_per_manifest: 64,
            },
        )
        .unwrap();
        assert!(report.chunks > 5, "test needs a genuinely chunked input");

        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "wc -c < inputs/static-0 > outputs/size"],
            "outputs": { "size": "outputs/size" },
        }));
        let m = manifest(vec![report.cid]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap();
        let size = String::from_utf8(store.get_chunk(&outputs[0].1).unwrap()).unwrap();
        assert_eq!(
            size.trim(),
            data.len().to_string(),
            "the command should see the whole reassembled file"
        );
    }

    /// A large output must be chunked on the way back in, not rejected by I2.
    #[tokio::test]
    async fn a_large_output_is_chunked_on_the_way_in() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            // 5 MiB: over MAX_CHUNK_SIZE, so it must become a manifest.
            "args": ["-c", "dd if=/dev/zero of=outputs/big bs=1024 count=5120 2>/dev/null"],
            "outputs": { "big": "outputs/big" },
            "timeout_secs": 60,
        }));
        let m = manifest(vec![]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap();

        let bytes = store.get_chunk(&outputs[0].1).unwrap();
        let info = dag_core::file::info_from_bytes(&bytes)
            .expect("a 5 MiB output should be stored as a file manifest");
        assert_eq!(info.size, 5 * 1024 * 1024);
    }

    #[tokio::test]
    async fn a_failing_command_fails_the_run_with_its_stderr() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "echo 'something broke' >&2; exit 3"],
            "outputs": { "never": "outputs/never" },
        }));
        let m = manifest(vec![]);

        let err = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains('3'), "exit status should be reported: {}", err);
        assert!(
            err.contains("something broke"),
            "stderr should be surfaced: {}",
            err
        );
    }

    #[test]
    fn a_failed_command_surfaces_only_a_bounded_recent_stderr_tail() {
        let marker = "LATEST-💥";
        let mut one_long_line = vec![b'x'; MAX_CAPTURE_BYTES];
        let marker_start = one_long_line.len() - marker.len();
        one_long_line[marker_start..].copy_from_slice(marker.as_bytes());
        let tail = failure_stderr_tail(&one_long_line);
        assert!(tail.len() <= MAX_FAILURE_STDERR_BYTES);
        assert!(tail.ends_with(marker));
        assert!(std::str::from_utf8(tail.as_bytes()).is_ok());

        let many_lines = (0..30)
            .map(|line| format!("line-{line:02}"))
            .collect::<Vec<_>>()
            .join("\n");
        let tail = failure_stderr_tail(many_lines.as_bytes());
        assert_eq!(tail.lines().count(), 20);
        assert!(tail.starts_with("line-10"));
        assert!(tail.ends_with("line-29"));
    }

    #[tokio::test]
    async fn allow_failure_keeps_a_non_zero_exit() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "echo lint-warning; exit 1"],
            "allow_failure": true,
            "capture_stdout": true,
        }));
        let m = manifest(vec![]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap();
        let stdout = store.get_chunk(&outputs[0].1).unwrap();
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "lint-warning");
    }

    #[tokio::test]
    async fn captured_streams_have_a_hard_byte_ceiling() {
        let bytes = [b'x'; 9];
        let error = read_bounded(&bytes[..], "stdout", 8).await.unwrap_err();
        assert!(error.to_string().contains("8-byte capture limit"));

        let accepted = read_bounded(&bytes[..8], "stdout", 8).await.unwrap();
        assert_eq!(accepted, bytes[..8]);
    }

    #[test]
    fn a_large_captured_stream_is_stored_as_a_file_manifest() {
        let (_temp, store) = setup();
        let bytes = vec![b'x'; dag_core::MAX_CHUNK_SIZE + 1];
        let cid = store_bytes(&store, &bytes, "stdout").unwrap();
        let root = store.get_chunk(&cid).unwrap();
        let info = dag_core::file::info_from_bytes(&root)
            .expect("capture larger than one chunk must use a file manifest");
        assert_eq!(info.size, bytes.len() as u64);
    }

    #[tokio::test]
    async fn a_missing_declared_output_fails_the_run() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "true"],
            "outputs": { "expected": "outputs/never-written" },
        }));
        let m = manifest(vec![]);

        let err = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing"), "got: {}", err);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_output_symlink_cannot_escape_the_workspace() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "ln -s /etc/hosts outputs/leak"],
            "outputs": { "leak": "outputs/leak" },
        }));
        let error = ExecAdapter
            .run(&store, &JobContext::new(&spec, &manifest(vec![])))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("outside the exec workspace"));
    }

    #[tokio::test]
    async fn a_timeout_kills_the_command() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "sleep 30"],
            "capture_stdout": true,
            "timeout_secs": 1,
        }));
        let m = manifest(vec![]);

        let started = std::time::Instant::now();
        let err = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("timeout"), "got: {}", err);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the timeout must actually stop waiting, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_timeout_kills_descendant_processes() {
        let workspace = tempfile::tempdir().unwrap();
        let config: ExecConfig = serde_json::from_value(serde_json::json!({
            "command": "sh",
            "args": [
                "-c",
                "(sleep 2; printf survived > descendant-survived) & wait"
            ],
            "timeout_secs": 1
        }))
        .unwrap();

        let error = run_command(&config, workspace.path()).await.unwrap_err();
        assert!(error.to_string().contains("timeout"), "{error}");

        // If only the shell were killed, its background subshell would write
        // this marker one second later. Give it ample scheduling headroom.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !workspace.path().join("descendant-survived").exists(),
            "a descendant survived the exec timeout"
        );
    }

    /// The environment is not inherited: a secret in the parent must not reach
    /// the child.
    #[tokio::test]
    async fn the_parent_environment_is_not_inherited() {
        let (_temp, store) = setup();
        // SAFETY: single-threaded test setup; nothing else reads this var.
        unsafe { std::env::set_var("DAG_EXEC_TEST_SECRET", "leaked") };

        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "printf '%s' \"${DAG_EXEC_TEST_SECRET:-absent}\" > outputs/env"],
            "outputs": { "env": "outputs/env" },
        }));
        let m = manifest(vec![]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap();
        assert_eq!(
            store.get_chunk(&outputs[0].1).unwrap(),
            b"absent",
            "the parent environment must not leak into job processes"
        );

        unsafe { std::env::remove_var("DAG_EXEC_TEST_SECRET") };
    }

    #[tokio::test]
    async fn declared_env_reaches_the_command() {
        let (_temp, store) = setup();
        let spec = spec_with(serde_json::json!({
            "command": "sh",
            "args": ["-c", "printf '%s' \"$GREETING\" > outputs/env"],
            "env": { "GREETING": "hello" },
            "outputs": { "env": "outputs/env" },
        }));
        let m = manifest(vec![]);

        let outputs = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap();
        assert_eq!(store.get_chunk(&outputs[0].1).unwrap(), b"hello");
    }

    /// Path traversal in a declared output would let a command hand back a
    /// file from outside its workspace — including from the data directory.
    #[test]
    fn config_validation_rejects_escaping_outputs() {
        let base = |outputs: serde_json::Value| -> ExecConfig {
            serde_json::from_value(serde_json::json!({
                "command": "true",
                "outputs": outputs,
            }))
            .unwrap()
        };

        assert!(base(serde_json::json!({ "escape": "../../etc/passwd" }))
            .validate()
            .is_err());
        assert!(base(serde_json::json!({ "absolute": "/etc/passwd" }))
            .validate()
            .is_err());
        for path in [
            r"..\outside",
            r"outputs\windows-only",
            "C:outside",
            "outputs/file:stream",
            "outputs/NUL.txt",
            "outputs//ambiguous",
            "outputs/trailing.",
        ] {
            assert!(
                base(serde_json::json!({ "portable": path }))
                    .validate()
                    .is_err(),
                "{path:?}"
            );
        }
        assert!(base(serde_json::json!({ "fine": "outputs/ok" }))
            .validate()
            .is_ok());
        // Reserved names would collide with capture_stdout/stderr.
        assert!(base(serde_json::json!({ "stdout": "outputs/x" }))
            .validate()
            .is_err());
    }

    #[test]
    fn config_validation_rejects_empty_and_pointless_configs() {
        let parse = |v: serde_json::Value| -> ExecConfig { serde_json::from_value(v).unwrap() };

        assert!(parse(serde_json::json!({ "command": "  " }))
            .validate()
            .is_err());
        assert!(
            parse(serde_json::json!({ "command": "true", "timeout_secs": 0 }))
                .validate()
                .is_err()
        );
        // Collects nothing: almost certainly a mistake, and the run would
        // report success having produced no evidence of anything.
        assert!(parse(serde_json::json!({ "command": "true" }))
            .validate()
            .is_err());
        assert!(parse(serde_json::json!({
            "command": "true",
            "capture_stdout": true,
            "timeout_secs": MAX_TIMEOUT_SECS + 1,
        }))
        .validate()
        .is_err());
    }

    #[test]
    fn aggregate_output_accounting_is_checked() {
        let mut total = MAX_TOTAL_OUTPUT_BYTES - 1;
        account_output_bytes(&mut total, 1, "last").unwrap();
        assert_eq!(total, MAX_TOTAL_OUTPUT_BYTES);
        assert!(account_output_bytes(&mut total, 1, "overflow").is_err());
        assert_eq!(total, MAX_TOTAL_OUTPUT_BYTES);
        assert!(account_output_bytes(&mut 0, MAX_OUTPUT_BYTES + 1, "huge").is_err());
    }

    /// The effect key must cover the command, or changing it would serve a
    /// stale cached result.
    #[test]
    fn the_effect_spec_covers_the_configuration() {
        let m = manifest(vec![]);

        let one = spec_with(serde_json::json!({
            "command": "sh", "args": ["-c", "echo one"], "capture_stdout": true,
        }));
        let two = spec_with(serde_json::json!({
            "command": "sh", "args": ["-c", "echo two"], "capture_stdout": true,
        }));

        let spec_one = ExecAdapter.effect_spec(&JobContext::new(&one, &m));
        let spec_two = ExecAdapter.effect_spec(&JobContext::new(&two, &m));

        assert!(spec_one.is_some());
        assert_ne!(
            spec_one, spec_two,
            "different commands must produce different effect keys"
        );

        // And it must be stable for an unchanged config.
        let again = ExecAdapter.effect_spec(&JobContext::new(&one, &m));
        assert_eq!(spec_one, again);
    }

    #[tokio::test]
    async fn a_missing_config_is_a_clear_error() {
        let (_temp, store) = setup();
        let mut spec = spec_with(serde_json::json!({}));
        spec.config = None;
        let m = manifest(vec![]);

        let err = ExecAdapter
            .run(&store, &JobContext::new(&spec, &m))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("requires a `config`"),
            "the error should say what is missing: {}",
            err
        );
    }
}
