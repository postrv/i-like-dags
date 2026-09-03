//! `dag` — command-line interface to the content-addressed DAG system.
//!
//! Every subcommand runs against a single [`Control`] opened from `--data-dir`
//! (default `.dag`). That is deliberate: content, pointers, pins, jobs and
//! events must all see the same deployment, or garbage collection would scan a
//! store that nothing else writes to.

mod commands;
mod error;
mod output;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dag_control::Control;
use std::path::PathBuf;

use output::{bytes, Format};

#[derive(Parser)]
#[command(name = "dag", version, about = "Content-addressed DAG system")]
struct Cli {
    /// Data directory holding chunks, logs and indexes
    #[arg(long, global = true, default_value = ".dag")]
    data_dir: PathBuf,

    /// Emit JSON on stdout instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    /// Pretty-print JSON (implies --json)
    #[arg(long, global = true)]
    pretty: bool,

    /// Seconds to wait for another process to release the data directory
    ///
    /// One process owns a data directory at a time (redb locks the database
    /// file). Without this, a concurrent invocation fails immediately, which
    /// makes `dag` awkward to call from a build or CI job that runs steps in
    /// parallel.
    #[arg(long, global = true, default_value_t = 0)]
    lock_timeout: u64,

    /// Diagnostic log format on stderr (also: DAG_LOG_FORMAT=json|text).
    ///
    /// `json` emits one JSON object per line with structured fields —
    /// what a log shipper wants from a long-running `dag serve` or
    /// `dag node serve`. stdout is unaffected either way; it stays the
    /// command's own output.
    #[arg(long, global = true, value_enum)]
    log_format: Option<LogFormat>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Store content and print its CID (content over 4 MiB is chunked)
    #[command(alias = "put-chunk")]
    Put {
        #[command(flatten)]
        source: commands::content::Source,
        /// Content-type hint recorded alongside the chunk
        #[arg(long)]
        content_type: Option<String>,
        /// Store as a chunked file even when it would fit in one chunk
        #[arg(long)]
        chunked: bool,
        /// Batch the durability flushes, roughly doubling ingest throughput
        ///
        /// Trades immediate durability for speed: if the process dies
        /// mid-ingest, it returns no root CID and can leave unpublished,
        /// unindexed files. Re-ingesting the same replayable input verifies
        /// intact orphans and repairs short ones before publishing a manifest.
        #[arg(long)]
        fast: bool,
    },
    /// Retrieve a chunk by CID
    #[command(alias = "get-chunk")]
    Get {
        /// CID to fetch
        #[arg(long)]
        cid: String,
        /// Write bytes to this file
        #[arg(long)]
        out: Option<PathBuf>,
        /// Write raw bytes to stdout
        #[arg(long, conflicts_with = "out")]
        raw: bool,
    },
    /// Store a DAG entry: a payload plus immutable links to other CIDs
    PutEntry {
        #[command(flatten)]
        source: OptionalSource,
        /// Link as `<CID>` or `<CID>:<name>`; repeatable
        #[arg(long, value_name = "CID[:NAME]")]
        link: Vec<String>,
        /// Content-type hint
        #[arg(long)]
        content_type: Option<String>,
    },
    /// List the links of a stored entry
    GetLinks {
        /// CID of the entry
        #[arg(long)]
        cid: String,
    },
    /// Local chunk index: stats, verification, rebuild
    Index {
        #[command(subcommand)]
        cmd: commands::content::IndexCmd,
    },
    /// Mutable named references with full history
    Pointer {
        #[command(subcommand)]
        cmd: commands::pointer::PointerCmd,
    },
    /// Retention policy: keep content alive across collection
    Pin {
        #[command(subcommand)]
        cmd: commands::pin::PinCmd,
    },
    /// Garbage collection and retention inspection
    Gc {
        #[command(subcommand)]
        cmd: commands::gc::GcCmd,
    },
    /// Recover all GC-safety indexes offline; filed logs are authoritative by default
    Recover {
        /// Maximum store objects and control rows to process; 0 removes the ceiling
        #[arg(long, default_value_t = dag_control::DEFAULT_RECOVERY_MAX_OBJECTS)]
        max_objects: usize,
        /// Maximum aggregate store bytes to scan; 0 removes the ceiling
        #[arg(long, default_value_t = dag_control::DEFAULT_RECOVERY_MAX_BYTES)]
        max_bytes: u64,
        /// Adopt unsigned control-shaped records found outside the filed logs.
        /// Use only after verifying every content-store writer was authorised
        /// to reconstruct pointer, pin, and job history.
        #[arg(long)]
        trust_unfiled_control_events: bool,
    },
    /// Job specs, runs, and adapters
    Job {
        #[command(subcommand)]
        cmd: commands::job::JobCmd,
    },
    /// Unified event stream
    Events {
        #[command(subcommand)]
        cmd: commands::events::EventCmd,
    },
    /// Replicate this data directory to or from another one
    Sync {
        #[command(subcommand)]
        cmd: commands::sync::SyncCmd,
    },
    /// Complete deployment snapshots (content plus local control-plane state)
    Backup {
        #[command(subcommand)]
        cmd: commands::backup::BackupCmd,
    },
    /// The authenticated node port: serve it, or ping another node's
    Node {
        #[command(subcommand)]
        cmd: commands::node::NodeCmd,
    },
    /// Summarise the deployment
    Status,
    /// Serve the HTTP API and web console
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
        /// Let pages on this origin call the API (repeatable).
        ///
        /// Off by default, and the console never needs it — it is served from
        /// the same origin. Granting an origin hands it an API with no
        /// authentication, so name only origins you control.
        #[arg(long = "allow-origin", value_name = "ORIGIN")]
        allow_origin: Vec<String>,
        /// Mount write/GC/job routes on a non-loopback address.
        ///
        /// The server is still unauthenticated. Anyone who can reach the
        /// port can delete data. The public listener is `dag content serve`.
        #[arg(long)]
        expose_control: bool,
        /// Aggregate HTTP connection ceiling
        #[arg(long, default_value_t = 256)]
        max_connections: usize,
        /// HTTP connection ceiling attributed to one direct peer IP
        #[arg(long, default_value_t = 32)]
        max_connections_per_source: usize,
    },
    /// The public read-only content plane (ADR-006)
    Content {
        #[command(subcommand)]
        cmd: commands::serve::ContentCmd,
    },
    /// Load the worked example described in docs/USE_CASE.md
    Usecase {
        #[command(subcommand)]
        cmd: commands::usecase::UsecaseCmd,
    },
    /// Convert a pre-redb (sled) data directory to the current layout
    Migrate {
        /// Report what would be copied without changing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage signing keys and the trust keyring
    Key {
        #[command(subcommand)]
        cmd: commands::key::KeyCmd,
    },
    /// Sign a CID with a local key, storing the signature as an entry
    Sign {
        /// CID to sign
        #[arg(long)]
        cid: String,
        /// Name of the local signing key (see `dag key generate`)
        #[arg(long)]
        key: String,
        /// Subject name recorded in the statement
        #[arg(long)]
        name: Option<String>,
        /// Free-text note recorded in the predicate
        #[arg(long)]
        note: Option<String>,
        /// Structured JSON predicate recorded in the statement — e.g. a
        /// checker verdict. Mutually exclusive with --note.
        #[arg(long, conflicts_with = "note")]
        predicate: Option<String>,
        /// in-toto `predicateType` URI. External verifiers dispatch on this,
        /// so emitting e.g. SLSA Provenance means setting it here.
        #[arg(long)]
        predicate_type: Option<String>,
    },
    /// Export DSSE envelopes for external supply-chain verifiers
    Signatures {
        /// CID whose covering signatures should be exported (or, with
        /// --import, the CID the envelope must cover)
        #[arg(long, required_unless_present = "import")]
        cid: Option<String>,
        /// Write one `<sig-cid>.dsse.json` per signature here (default: stdout)
        #[arg(long, conflicts_with = "import")]
        out_dir: Option<PathBuf>,
        /// Import an externally-produced DSSE envelope (Ed25519 over an
        /// in-toto v1 statement) as a stored signature entry. Nothing is
        /// stored unless it verifies and its subject's bytes are intact here
        #[arg(long, value_name = "DSSE_JSON")]
        import: Option<PathBuf>,
        /// Hex public key the imported envelope must verify against
        /// (default: try every key in the keyring)
        #[arg(long, requires = "import")]
        key: Option<String>,
    },
    /// Verify content and its signatures; exits non-zero without a trusted one
    Verify {
        /// CID to verify
        #[arg(long)]
        cid: String,
        /// Trusted signatures required for success. Two independent
        /// verifiers held to agreement is `--min-trusted 2`.
        #[arg(long, default_value_t = 1)]
        min_trusted: usize,
    },
}

/// A `Source` where all variants are optional (an entry may have no payload).
#[derive(clap::Args, Debug)]
#[group(required = false, multiple = false)]
pub struct OptionalSource {
    /// Read the payload from a file
    #[arg(long)]
    pub payload_file: Option<PathBuf>,
    /// Use this string literally as the payload
    #[arg(long)]
    pub payload: Option<String>,
}

impl OptionalSource {
    fn as_source(&self) -> Option<commands::content::Source> {
        match (&self.payload_file, &self.payload) {
            (None, None) => None,
            (file, data) => Some(commands::content::Source {
                file: file.clone(),
                data: data.clone(),
                stdin: false,
            }),
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", error_chain(&e));
        std::process::exit(exit_code(&e));
    }
}

/// Diagnostic log encoding. See the `--log-format` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    /// Human-readable lines.
    Text,
    /// One JSON object per line, fields intact — for log shippers.
    Json,
}

/// Flag beats environment beats default; an unparseable environment value
/// falls back to text rather than stopping the tool, the same posture the
/// journal-retention variable takes.
fn resolve_log_format(flag: Option<LogFormat>, env: Option<&str>) -> LogFormat {
    if let Some(format) = flag {
        return format;
    }
    match env.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("json") => LogFormat::Json,
        _ => LogFormat::Text,
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Logs go to stderr so stdout stays parseable; RUST_LOG tunes verbosity.
    let env_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
    };
    match resolve_log_format(
        cli.log_format,
        std::env::var("DAG_LOG_FORMAT").ok().as_deref(),
    ) {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(env_filter())
            .init(),
        LogFormat::Text => tracing_subscriber::fmt()
            .fmt_fields(output::SafeTextFields)
            .with_writer(std::io::stderr)
            .with_env_filter(env_filter())
            .init(),
    }
    let fmt = Format {
        json: cli.json || cli.pretty,
        pretty: cli.pretty,
    };

    // Migration runs before Control::open on purpose: open refuses the very
    // layout migrate exists to convert.
    if let Commands::Migrate { dry_run } = cli.command {
        return commands::migrate::handle(&cli.data_dir, dry_run, fmt);
    }

    // Remote-only and offline backup invocations route before the normal
    // control plane opens. Create must preserve an older database byte for
    // byte rather than stamp/upgrade it; restore must validate without
    // migrating it; and opening a missing destination would defeat restore's
    // create-new safety property.
    let command = match cli.command {
        Commands::Backup {
            cmd: commands::backup::BackupCmd::Create { out },
        } => {
            return commands::backup::create_waiting(
                &cli.data_dir,
                &out,
                fmt,
                std::time::Duration::from_secs(cli.lock_timeout),
            );
        }
        Commands::Backup {
            cmd: commands::backup::BackupCmd::Verify { source, max_bytes },
        } => return commands::backup::verify_bounded(&source, fmt, max_bytes),
        Commands::Backup {
            cmd: commands::backup::BackupCmd::Restore { source, max_bytes },
        } => {
            return commands::backup::restore_bounded(&source, &cli.data_dir, fmt, max_bytes);
        }
        Commands::Node {
            cmd:
                commands::node::NodeCmd::Info {
                    remote,
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                },
        } => {
            return commands::node::info(
                &remote,
                token,
                token_file,
                ca_cert,
                tls_domain,
                allow_insecure_transport,
                fmt,
            );
        }
        Commands::Pointer {
            cmd:
                commands::pointer::PointerCmd::Resolve {
                    remote: Some(url),
                    id,
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                    ..
                },
        } => {
            return commands::pointer::resolve_remote(
                &url,
                commands::node::connect_options(
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                )?,
                &id,
                fmt,
            );
        }
        Commands::Pointer {
            cmd:
                commands::pointer::PointerCmd::Update {
                    remote: Some(url),
                    id,
                    cid,
                    expect_seq,
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                    pin_history: _,
                },
        } => {
            // clap's `requires` pairing guarantees the expectation arrived.
            let expect_seq = expect_seq.expect("clap requires expect_seq with remote");
            return commands::pointer::update_remote(
                &url,
                commands::node::connect_options(
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                )?,
                &id,
                &cid,
                expect_seq,
                fmt,
            );
        }
        Commands::Events {
            cmd:
                commands::events::EventCmd::Tail {
                    remote: Some(url),
                    filter,
                    since_seq,
                    since,
                    follow,
                    limit,
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                },
        } => {
            if since.is_some() {
                // Resolving a wall-clock start needs the journal's own
                // timestamps, which live on the other node; the protocol
                // speaks sequence numbers.
                anyhow::bail!(
                    "--since applies to the local journal; use --since-seq with --remote"
                );
            }
            return commands::events::tail_remote(
                &url,
                commands::node::connect_options(
                    token,
                    token_file,
                    ca_cert,
                    tls_domain,
                    allow_insecure_transport,
                )?,
                filter,
                since_seq,
                follow,
                limit,
                fmt,
            );
        }
        other => other,
    };

    let control = Control::open_waiting(
        &cli.data_dir,
        std::time::Duration::from_secs(cli.lock_timeout),
    )
    .with_context(|| format!("opening data directory {}", cli.data_dir.display()))?;

    match command {
        Commands::Put {
            source,
            content_type,
            chunked,
            fast,
        } => commands::content::put(&control, &source, content_type, chunked, fast, fmt),

        Commands::Get { cid, out, raw } => commands::content::get(&control, &cid, out, raw),

        Commands::PutEntry {
            source,
            link,
            content_type,
        } => commands::content::put_entry(
            &control,
            source.as_source().as_ref(),
            &link,
            content_type,
            fmt,
        ),

        Commands::GetLinks { cid } => commands::content::get_links(&control, &cid, fmt),

        Commands::Index { cmd } => commands::content::index(&control, cmd, fmt),

        Commands::Pointer { cmd } => commands::pointer::handle(&control, cmd, fmt),

        Commands::Pin { cmd } => commands::pin::handle(&control, cmd, fmt),

        Commands::Gc { cmd } => commands::gc::handle(&control, cmd, fmt),

        Commands::Recover {
            max_objects,
            max_bytes,
            trust_unfiled_control_events,
        } => {
            let report = if trust_unfiled_control_events {
                control.recover_with_limits_trusting_store_control_events(max_objects, max_bytes)?
            } else {
                control.recover_with_limits(max_objects, max_bytes)?
            };
            fmt.emit(&report, |r| {
                format!(
                    "recovery complete: {} pointer heads (+{} events), {} pin heads (+{} events), \
                     {} job heads (+{} events), {} signatures and {} effect claims indexed",
                    r.pointers_rebuilt,
                    r.pointer_events_adopted,
                    r.pins_rebuilt,
                    r.pin_events_adopted,
                    r.jobs_rebuilt,
                    r.job_events_adopted,
                    r.signatures_indexed,
                    r.claims_indexed,
                )
            })
        }

        // Owned, like `serve`: `events compact --reclaim` has to close the
        // control plane before redb will hand its free pages back.
        Commands::Events { cmd } => commands::events::handle(control, cmd, fmt),

        // Owned: a grpc:// remote shares the control plane with a runtime
        // via `Arc`, which needs ownership.
        Commands::Sync { cmd } => commands::sync::handle(control, cmd, fmt),

        // Every backup form was routed before Control::open.
        Commands::Backup { .. } => unreachable!("offline backup command routed before open"),

        Commands::Node { cmd } => match cmd {
            commands::node::NodeCmd::Serve {
                listen,
                token,
                token_file,
                auth_file,
                tls_cert,
                tls_key,
                allow_insecure_transport,
                max_connections,
                max_connections_per_source,
                allow_exec_jobs,
            } => commands::node::serve(
                control,
                &listen,
                commands::node::ServeCommandOptions {
                    token,
                    token_file,
                    auth_file,
                    tls_cert,
                    tls_key,
                    allow_insecure_transport,
                    max_connections,
                    max_connections_per_source,
                    allow_exec_jobs,
                },
            ),
            // Info returned before the directory opened.
            commands::node::NodeCmd::Info { .. } => unreachable!("routed before Control::open"),
        },

        Commands::Status => status(&control, fmt),

        // Async commands get a runtime here rather than making `main` async:
        // `events tail` uses a blocking receive that would panic on a runtime thread.
        Commands::Job { cmd } => {
            tokio::runtime::Runtime::new()?.block_on(commands::job::handle(&control, cmd, fmt))
        }

        Commands::Usecase { cmd } => {
            tokio::runtime::Runtime::new()?.block_on(commands::usecase::handle(&control, cmd, fmt))
        }

        Commands::Serve {
            addr,
            allow_origin,
            expose_control,
            max_connections,
            max_connections_per_source,
        } => tokio::runtime::Runtime::new()?.block_on(commands::serve::handle(
            control,
            &addr,
            &allow_origin,
            expose_control,
            max_connections,
            max_connections_per_source,
        )),

        Commands::Content { cmd } => tokio::runtime::Runtime::new()?
            .block_on(commands::serve::handle_content_cmd(control, cmd)),

        Commands::Key { cmd } => commands::key::handle(&control, cmd, fmt),

        Commands::Sign {
            cid,
            key,
            name,
            note,
            predicate,
            predicate_type,
        } => commands::sign::sign(
            &control,
            commands::sign::SignRequest {
                cid,
                key_name: key,
                name,
                note,
                predicate,
                predicate_type,
            },
            fmt,
        ),

        Commands::Signatures {
            cid,
            out_dir,
            import,
            key,
        } => match import {
            Some(path) => commands::sign::import_envelope(
                &control,
                &path,
                key.as_deref(),
                cid.as_deref(),
                fmt,
            ),
            None => commands::sign::export(
                &control,
                cid.as_deref().expect("clap requires cid without --import"),
                out_dir.as_deref(),
            ),
        },

        Commands::Verify { cid, min_trusted } => {
            commands::sign::verify(&control, &cid, min_trusted, fmt)
        }

        // Handled before Control::open above; unreachable by construction.
        Commands::Migrate { .. } => unreachable!("migrate returns before Control::open"),
    }
}

fn status(control: &Control, fmt: Format) -> Result<()> {
    let stats = control.stats()?;
    fmt.emit(&stats, |s| {
        format!(
            "chunks     {} ({})\npointers   {}\npins       {} ({} active)\njobs       {} ({} pending, {} running)\ntriggers   {} queued, {} dead-lettered\nevents     seq {}\nrecovered  {}",
            s.chunks,
            bytes(s.bytes),
            s.pointers,
            s.pins,
            s.active_pins,
            s.jobs,
            s.pending_runs,
            s.running_runs,
            s.trigger_queue,
            s.trigger_dead_letters,
            s.event_seq,
            if s.recovered { "yes" } else { "no — stop the server and run `dag recover`" },
        )
    })
}

/// BSD sysexits codes, so scripts can branch on *why* a command failed.
mod exit {
    /// Input data was malformed, or stored data did not verify.
    pub const DATAERR: i32 = 65;
    /// A named input does not exist.
    pub const NOINPUT: i32 = 66;
    /// A required service or adapter is not available in this build.
    pub const UNAVAILABLE: i32 = 69;
    /// An internal error: a bug, or a corrupt database.
    pub const SOFTWARE: i32 = 70;
    /// A read or write failed.
    pub const IOERR: i32 = 74;
    /// Transient: retrying later may succeed.
    pub const TEMPFAIL: i32 = 75;
    /// The caller lacks permission — here, a capability was not granted.
    pub const NOPERM: i32 = 77;
    /// The deployment is misconfigured; an operator must act.
    pub const CONFIG: i32 = 78;
}

fn core_exit(e: &dag_core::CoreError) -> i32 {
    use dag_core::CoreError as C;
    match e {
        C::ChunkNotFound(_) => exit::NOINPUT,
        C::ChunkTooLarge { .. }
        | C::FileLimitExceeded { .. }
        | C::InvalidCid(_)
        | C::CidMismatch { .. }
        | C::PreconditionFailed(_)
        | C::Serialization(_)
        | C::Deserialization(_) => exit::DATAERR,
        C::GcInventoryLimit { .. }
        | C::GcInventoryBytesLimit { .. }
        | C::GcIndexMismatch { .. } => exit::CONFIG,
        C::Io(_) => exit::IOERR,
        C::Backend(_) => exit::SOFTWARE,
    }
}

fn job_exit(e: &dag_core::JobError) -> i32 {
    use dag_core::JobError as J;
    match e {
        J::JobNotFound(_) | J::RunNotFound(_) => exit::NOINPUT,
        J::AdapterNotFound(_) => exit::UNAVAILABLE,
        J::InvalidJobId(_)
        | J::InvalidRunId(_)
        | J::InvalidKey(_)
        | J::InvalidSpec(_)
        | J::JobAlreadyExists(_) => exit::DATAERR,
        J::ExecutionFailed(_) => exit::SOFTWARE,
    }
}

fn pointer_exit(e: &dag_control::PointerError) -> i32 {
    use dag_control::PointerError as P;
    match e {
        P::NotFound(_) => exit::NOINPUT,
        P::Capacity(_) => exit::TEMPFAIL,
        P::TriggerPermissionRequired { .. } => exit::NOPERM,
        P::AlreadyExists(_)
        | P::CasConflict { .. }
        | P::InvalidRange { .. }
        | P::Serialization(_) => exit::DATAERR,
        P::Storage(inner) => core_exit(inner),
        P::Database(_) => exit::SOFTWARE,
    }
}

fn control_exit(e: &dag_control::ControlError) -> i32 {
    use dag_control::ControlError as C;
    match e {
        // These all need an operator to do something — run a rebuild, resume
        // or repair a migration, raise a ceiling — before anything proceeds.
        C::NotRecovered
        | C::RecoveryInventoryLimit { .. }
        | C::RecoveryBytesLimit { .. }
        | C::RecoveryTableLimit { .. }
        | C::GcControlStateLimit { .. }
        | C::RecoveryIncomplete { .. }
        | C::LegacyDataDir { .. }
        | C::MigrationInProgress { .. }
        | C::MixedStorageLayout { .. }
        | C::UnsafeMigrationLayout { .. }
        | C::RetentionIncomplete { .. }
        // An unreadable entry inside a pin: an operator repairs or restores
        // it. Same class of answer as the ceiling case.
        | C::RetentionUnreadable { .. }
        // Run a different binary, or restore the file. Either way an operator
        // acts; neither is a bug in this one.
        | C::SchemaTooNew { .. }
        | C::SchemaTooOld { .. }
        | C::ControlDbUnreadable { .. } => exit::CONFIG,
        C::Core(inner) => core_exit(inner),
        C::Job(inner) => job_exit(inner),
        C::Pointer(inner) => pointer_exit(inner),
        C::Pin(_) => exit::NOINPUT,
        C::Io { .. } => exit::IOERR,
        C::Invalid(_) | C::Codec(_) => exit::DATAERR,
        // Someone else has the directory. Transient by nature — the caller's
        // correct response is to wait, not to file a bug, which is what
        // EX_SOFTWARE would have told them.
        C::DatabaseLocked { .. } => exit::TEMPFAIL,
        C::Capacity(_) => exit::TEMPFAIL,
        // The other node, not this process: check the address, token, network.
        C::Remote(_) => exit::UNAVAILABLE,
        C::Database(_) | C::NoJournal => exit::SOFTWARE,
        _ => exit::SOFTWARE,
    }
}

fn run_exit(e: &dag_jobs::RunError) -> i32 {
    use dag_jobs::RunError as R;
    match e.kind() {
        R::Core(inner) => core_exit(inner),
        R::Control(inner) => control_exit(inner),
        R::Job(inner) => job_exit(inner),
        // The adapter exists and was deliberately withheld: the fix is a flag
        // on this invocation, so "permission" is the honest signal.
        R::AdapterWithheld { .. } => exit::NOPERM,
        R::ConfigMissing { .. } | R::ConfigInvalid { .. } | R::Invalid(_) => exit::DATAERR,
        R::Timeout { .. } => exit::TEMPFAIL,
        R::Io { .. } => exit::IOERR,
        R::CommandFailed { .. } | R::Adapter { .. } => exit::SOFTWARE,
        _ => exit::SOFTWARE,
    }
}

/// Map errors to BSD sysexits-style codes so scripts can branch on them.
///
/// The whole causal chain is searched, not just the outermost error: a typed
/// error wrapped in context by a caller still deserves its own code.
fn exit_code(e: &anyhow::Error) -> i32 {
    for cause in e.chain() {
        // A verification verdict is the CLI's own; it outranks whatever the
        // library reported underneath.
        if cause.downcast_ref::<error::CliError>().is_some() {
            return exit::DATAERR;
        }
        // Operator must pass a flag or use `dag content serve`. Not a bug.
        if cause
            .downcast_ref::<dag_api::ControlPlaneBindRefused>()
            .is_some()
        {
            return exit::CONFIG;
        }
        if let Some(inner) = cause.downcast_ref::<dag_jobs::RunError>() {
            return run_exit(inner);
        }
        if let Some(inner) = cause.downcast_ref::<dag_control::ControlError>() {
            return control_exit(inner);
        }
        if let Some(inner) = cause.downcast_ref::<dag_core::CoreError>() {
            return core_exit(inner);
        }
        if let Some(inner) = cause.downcast_ref::<dag_core::JobError>() {
            return job_exit(inner);
        }
        if let Some(inner) = cause.downcast_ref::<dag_control::PointerError>() {
            return pointer_exit(inner);
        }
        if cause.downcast_ref::<dag_core::PinError>().is_some() {
            return exit::NOINPUT;
        }
    }
    exit::SOFTWARE
}

/// Render an error together with its causal chain.
fn error_chain(e: &anyhow::Error) -> String {
    use std::fmt::Write;
    let top = e.to_string();
    let mut s = format!("Error: {}", output::terminal_text(&top));
    for cause in e.chain().skip(1) {
        let detail = cause.to_string();
        let _ = write!(&mut s, "\n  caused by: {}", output::terminal_text(&detail));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn error_chain_cannot_inject_terminal_lines_or_escape_sequences() {
        let error =
            anyhow::anyhow!("remote said first\nforged\u{1b}[31m").context("outer\u{202e}text");
        let rendered = error_chain(&error);
        assert_eq!(rendered.lines().count(), 2);
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(rendered.contains(r"outer\u{202e}text"));
        assert!(rendered.contains(r"first\nforged\u{1b}[31m"));
    }

    #[test]
    fn content_serve_and_expose_control_parse() {
        let cli =
            Cli::try_parse_from(["dag", "content", "serve", "--addr", "0.0.0.0:8081"]).unwrap();
        match cli.command {
            Commands::Content {
                cmd: commands::serve::ContentCmd::Serve { addr, .. },
            } => assert_eq!(addr, "0.0.0.0:8081"),
            _ => panic!("expected Content::Serve"),
        }

        let cli = Cli::try_parse_from(["dag", "serve", "--expose-control"]).unwrap();
        match cli.command {
            Commands::Serve { expose_control, .. } => assert!(expose_control),
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn put_chunk_alias_still_parses() {
        let cli = Cli::try_parse_from(["dag", "put-chunk", "--data", "hello"]).unwrap();
        match cli.command {
            Commands::Put { source, .. } => {
                assert_eq!(source.data.as_deref(), Some("hello"));
            }
            _ => panic!("expected Put"),
        }
    }

    #[test]
    fn data_dir_is_accepted_after_the_subcommand() {
        // Regression: --data-dir used to be positional-order dependent, so
        // `dag pointer list --data-dir X` failed.
        let cli = Cli::try_parse_from(["dag", "pointer", "list", "--data-dir", "/tmp/x"]).unwrap();
        assert_eq!(cli.data_dir, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn log_format_prefers_the_flag_then_the_environment_then_text() {
        use LogFormat::{Json, Text};
        assert_eq!(resolve_log_format(Some(Json), Some("text")), Json);
        assert_eq!(resolve_log_format(Some(Text), Some("json")), Text);
        assert_eq!(resolve_log_format(None, Some("json")), Json);
        assert_eq!(resolve_log_format(None, Some(" JSON ")), Json);
        assert_eq!(
            resolve_log_format(None, Some("yaml")),
            Text,
            "a typo must not stop the tool"
        );
        assert_eq!(resolve_log_format(None, None), Text);

        let cli = Cli::try_parse_from(["dag", "--log-format", "json", "status"]).unwrap();
        assert_eq!(cli.log_format, Some(Json));
    }

    #[test]
    fn exit_codes_distinguish_the_conditions_scripts_branch_on() {
        let code = |e: anyhow::Error| exit_code(&e);

        // Missing input vs malformed input vs a broken deployment.
        assert_eq!(
            code(dag_core::CoreError::ChunkNotFound("abc".into()).into()),
            exit::NOINPUT
        );
        assert_eq!(
            code(dag_core::CoreError::InvalidCid("zz".into()).into()),
            exit::DATAERR
        );
        assert_eq!(
            code(dag_control::ControlError::NotRecovered.into()),
            exit::CONFIG
        );
        assert_eq!(
            code(
                dag_control::ControlError::LegacyDataDir {
                    path: "/d".into(),
                    found: "index".into()
                }
                .into()
            ),
            exit::CONFIG
        );
        assert_eq!(
            code(
                dag_control::ControlError::MigrationInProgress {
                    path: "/d".into(),
                    marker: "/d/.control-redb-migration-v1".into(),
                }
                .into()
            ),
            exit::CONFIG
        );
        assert_eq!(
            code(
                dag_control::ControlError::UnsafeMigrationLayout {
                    path: "/d".into(),
                    database: "control.redb".into(),
                    found: "pointer.db.sled.bak".into(),
                }
                .into()
            ),
            exit::CONFIG
        );
        assert_eq!(
            code(dag_control::ControlError::Database("job log: gone".into()).into()),
            exit::SOFTWARE
        );
        assert_eq!(
            code(dag_control::PointerError::Capacity("trigger queue".into()).into()),
            exit::TEMPFAIL
        );
        assert_eq!(
            code(
                dag_api::ControlPlaneBindRefused {
                    addr: "1.2.3.4:8080".parse().unwrap()
                }
                .into()
            ),
            exit::CONFIG
        );
    }

    #[test]
    fn a_withheld_adapter_exits_as_a_permission_problem() {
        // `dag job run-once` on an exec job without --allow-exec: the fix is a
        // flag, not a rebuild, and the exit code has to say so.
        let e: anyhow::Error = dag_jobs::RunError::AdapterWithheld {
            adapter: "exec".into(),
            reason: "requires --allow-exec".into(),
        }
        .into();
        assert_eq!(exit_code(&e), exit::NOPERM);

        // Whereas an adapter this build genuinely lacks is unavailable.
        let e: anyhow::Error = dag_core::JobError::AdapterNotFound("exec".into()).into();
        assert_eq!(exit_code(&e), exit::UNAVAILABLE);
    }

    #[test]
    fn typed_errors_keep_their_code_through_context_wrapping() {
        // Regression: exit codes used to be read off the outermost error only,
        // so adding context downgraded everything to EX_SOFTWARE.
        let inner = dag_jobs::RunError::Context {
            context: "reading input".into(),
            source: Box::new(dag_jobs::RunError::Core(
                dag_core::CoreError::ChunkNotFound("abc".into()),
            )),
        };
        assert_eq!(exit_code(&anyhow::Error::from(inner)), exit::NOINPUT);

        let wrapped = anyhow::Error::from(dag_control::ControlError::NotRecovered)
            .context("running garbage collection");
        assert_eq!(exit_code(&wrapped), exit::CONFIG);
    }

    #[test]
    fn a_failed_verification_outranks_the_library_error_beneath_it() {
        let e: anyhow::Error = error::CliError::SignatureVerificationFailed {
            intact: true,
            signatures: 1,
            trusted: 0,
        }
        .into();
        assert_eq!(exit_code(&e), exit::DATAERR);
    }

    /// Bad stored data, not a usage error — the same verdict `dag verify`
    /// gives, so a pipeline can gate on either with one code.
    #[test]
    fn a_failed_integrity_scan_is_a_data_error() {
        let e: anyhow::Error = error::CliError::DamagedStore {
            invalid: 2,
            total: 20,
            missing: 1,
            corrupt: 1,
            stale: 0,
            unreadable: 0,
        }
        .into();
        assert_eq!(exit_code(&e), exit::DATAERR);
    }

    #[test]
    fn put_requires_exactly_one_source() {
        assert!(Cli::try_parse_from(["dag", "put"]).is_err());
        assert!(Cli::try_parse_from(["dag", "put", "--data", "a", "--stdin"]).is_err());
        assert!(Cli::try_parse_from(["dag", "put", "--stdin"]).is_ok());
    }

    #[test]
    fn partial_store_rebuild_limits_require_the_explicit_store_scan() {
        for subsystem in ["pointer", "pin", "job"] {
            assert!(
                Cli::try_parse_from(["dag", subsystem, "rebuild", "--max-objects", "10"]).is_err(),
                "{subsystem} accepted a store inventory limit without --from-store"
            );
            assert!(Cli::try_parse_from([
                "dag",
                subsystem,
                "rebuild",
                "--from-store",
                "--trust-unfiled-control-events",
                "--max-objects",
                "0",
                "--max-bytes",
                "0",
            ])
            .is_ok());
        }
    }
}
