//! Job commands: register specs, trigger runs, and inspect run history.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use dag_control::Control;
use dag_core::{JobId, JobRun, RunStatus};

use crate::output::{short_cid, terminal_text, ts, Format};

/// A valid spec is materially smaller (config alone is capped at 64 KiB),
/// but this leaves room for all bounded names, CIDs and ordinary whitespace.
const MAX_JOB_SPEC_FILE_BYTES: usize = 512 * 1024;

#[derive(Subcommand, Debug)]
pub enum JobCmd {
    /// Register a job from a JSON spec file
    Create {
        /// Path to a JSON JobSpec (see crates/dag-cli/examples/)
        #[arg(long)]
        spec: PathBuf,
        /// Also write the resulting job ID to this file
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Replace a registered job's spec, keeping its history
    ///
    /// Appends an `Updated` event chained to the current head, so the old spec
    /// stays readable and `dag job rebuild` can prove the chain. The `job_id`
    /// in the file selects the job and cannot be changed. Changing `code_ref`
    /// or `config` changes the effect key, so cached effects from the old spec
    /// stop matching rather than being served for the new one.
    Update {
        /// Path to a JSON JobSpec naming an existing job
        #[arg(long)]
        spec: PathBuf,
    },
    /// Enqueue a run without executing it
    Trigger {
        /// Job ID
        #[arg(long)]
        job_id: String,
    },
    /// Execute one run now: trigger, resolve inputs, run, record
    RunOnce {
        /// Job ID
        #[arg(long)]
        job_id: String,
        /// Permit the `exec` adapter to run this job's configured command.
        ///
        /// Required for `code_ref: "exec"` jobs. Runs the command with this
        /// process's privileges and no sandbox, so it is opt-in per invocation
        /// rather than something a stored job spec can decide for you.
        #[arg(long)]
        allow_exec: bool,
        /// Publish a signed effect claim for this run's outputs, using this
        /// local key (see `dag key generate`). The claim is pinned as a
        /// subtree, so `dag sync` carries it and its outputs (ADR-003).
        #[arg(long, value_name = "KEY_ID")]
        attest_key: Option<String>,
        /// On an effect-cache miss, adopt outputs from a claim signed by a
        /// keyring-trusted key instead of executing. With no trusted keys
        /// this changes nothing; trust is granted with `dag key trust`.
        #[arg(long)]
        adopt_attested: bool,
    },
    /// Show recent runs for a job
    Runs {
        /// Job ID
        #[arg(long)]
        job_id: String,
        /// Maximum runs to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Compact old terminal run records under an explicit retention policy
    CompactRuns {
        /// Job whose terminal history should be compacted
        #[arg(long)]
        job_id: String,
        /// Number of newest terminal runs to retain
        #[arg(long, default_value_t = 1_000)]
        keep_terminal: usize,
        /// Maximum rows deleted in this transaction
        #[arg(long, default_value_t = dag_control::MAX_RUN_COMPACTION_DELETE)]
        max_delete: usize,
        /// Report what is eligible without deleting anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect permanently refused pointer-trigger intents
    DeadLetters {
        /// Maximum entries to show
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Purge a reviewed, bounded batch of trigger dead letters
    CompactDeadLetters {
        /// Maximum rows deleted in this transaction
        #[arg(long, default_value_t = dag_control::MAX_DEAD_LETTER_DELETE)]
        max_delete: usize,
        /// Report the bounded selection without deleting it
        #[arg(long)]
        dry_run: bool,
    },
    /// List registered jobs
    List,
    /// Fire a job whenever a pointer is updated
    SubscribePointer {
        /// Job ID to subscribe
        #[arg(long)]
        job_id: String,
        /// Pointer whose updates trigger the job
        #[arg(long)]
        pointer_id: String,
    },
    /// Stop a pointer from triggering a job
    UnsubscribePointer {
        /// Job ID to unsubscribe
        #[arg(long)]
        job_id: String,
        /// Pointer whose updates must stop triggering the job
        #[arg(long)]
        pointer_id: String,
    },
    /// List the adapters a job spec's `code_ref` can name
    Adapters,
    /// Rebuild job heads from the event log
    ///
    /// This diagnostic repairs job heads only. Full recovery also reconciles
    /// the chunk, pointer, pin, signature and effect-claim indexes; use bounded
    /// offline `dag recover` to certify the GC recovery gate.
    Rebuild {
        /// Recover from the content store instead of the events table.
        ///
        /// The events table lives in `control.redb`; if that file was lost,
        /// the ordinary rebuild has nothing to read and recovers nothing. Job
        /// event entries are in `data/` and survive, so this scans for them.
        /// Run *history* does not: runs live only in the database.
        #[arg(long)]
        from_store: bool,
        /// Trust unsigned job-shaped records found among ordinary content.
        /// Requires `--from-store`; use only after verifying store-writer provenance.
        #[arg(long, requires = "from_store")]
        trust_unfiled_control_events: bool,
        /// Maximum store objects to scan (default 100000); 0 removes the ceiling.
        #[arg(long, requires = "from_store")]
        max_objects: Option<usize>,
        /// Maximum aggregate store bytes to scan (default 1 GiB); 0 removes the ceiling.
        #[arg(long, requires = "from_store")]
        max_bytes: Option<u64>,
    },
}

pub async fn handle(control: &Control, cmd: JobCmd, fmt: Format) -> Result<()> {
    match cmd {
        JobCmd::Create { spec, out } => {
            let file = std::fs::File::open(&spec)
                .with_context(|| format!("opening {}", spec.display()))?;
            let bytes = super::read_bounded(
                file,
                MAX_JOB_SPEC_FILE_BYTES,
                &format!("JobSpec {}", spec.display()),
            )?;
            let parsed = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing JobSpec in {}", spec.display()))?;

            let job_id = control.create_job(parsed)?;
            if let Some(path) = out {
                std::fs::write(&path, job_id.to_string())
                    .with_context(|| format!("writing {}", path.display()))?;
            }

            let value = serde_json::json!({ "job_id": job_id.to_string() });
            fmt.emit(value, |_| terminal_text(job_id.as_ref()).into_owned())
        }

        JobCmd::Update { spec } => {
            let file = std::fs::File::open(&spec)
                .with_context(|| format!("opening {}", spec.display()))?;
            let bytes = super::read_bounded(
                file,
                MAX_JOB_SPEC_FILE_BYTES,
                &format!("JobSpec {}", spec.display()),
            )?;
            let parsed = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing JobSpec in {}", spec.display()))?;

            let job_id = control.update_job(parsed)?;
            let value = serde_json::json!({ "job_id": job_id.to_string(), "status": "Updated" });
            fmt.emit(value, |_| {
                format!("updated {}", terminal_text(job_id.as_ref()))
            })
        }

        JobCmd::Trigger { job_id } => {
            control.trigger_job(JobId::from(job_id.clone()))?;
            let value = serde_json::json!({ "job_id": job_id, "status": "Pending" });
            fmt.emit(value, |_| {
                format!("enqueued run for {}", terminal_text(&job_id))
            })
        }

        JobCmd::RunOnce {
            job_id,
            allow_exec,
            attest_key,
            adopt_attested,
        } => {
            let id = JobId::from(job_id.clone());

            // Local command execution is opt-in per invocation. The CLI is the
            // only path that can grant it — the HTTP API never does, because
            // it is unauthenticated. See `dag_jobs::exec` for the threat model.
            let caps = if allow_exec {
                dag_jobs::Capabilities::none().with_exec()
            } else {
                dag_jobs::Capabilities::none()
            };

            // Attestation and adoption are likewise per-invocation opt-ins
            // (ADR-003): the attester exists only if a key was named, and
            // adoption only consults keyring-trusted claims.
            let attester = attest_key
                .map(|key_id| {
                    super::key::load_signing_key(control, &key_id)
                        .map(|key| dag_control::EffectAttester::new(control, key))
                })
                .transpose()?;
            let hooks = dag_jobs::EffectHooks {
                adopt: adopt_attested.then_some(control as &dyn dag_control::AttestedEffects),
                attest: attester
                    .as_ref()
                    .map(|a| a as &dyn dag_control::EffectClaimSink),
            };

            let outcome = dag_jobs::execute_once_hooked(control, &id, caps, hooks).await?;

            // Say which of the three things happened. "Succeeded" over
            // outputs this node adopted on someone else's signed word reads
            // exactly like "succeeded" over outputs it built.
            let origin = dag_jobs::effect_origin_label(&outcome.origin);
            let value = serde_json::json!({
                "job_id": job_id,
                "run_id": outcome.run_id.to_string(),
                "origin": origin,
                "revision": {
                    "event_cid": outcome.revision.event_cid.to_hex(),
                    "event_seq": outcome.revision.event_seq,
                    "code_ref": outcome.revision.code_ref,
                },
                "outputs": outcome.outputs.iter()
                    .map(|(name, cid)| serde_json::json!({ "name": name, "cid": cid.to_hex() }))
                    .collect::<Vec<_>>(),
            });

            fmt.emit(value, |v| {
                let outputs = v["outputs"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|o| {
                                format!(
                                    "\n  {} -> {}",
                                    terminal_text(o["name"].as_str().unwrap_or("")),
                                    o["cid"].as_str().unwrap_or("")
                                )
                            })
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                format!(
                    "run {} succeeded ({}, revision {}@{} {}){}",
                    outcome.run_id,
                    origin,
                    terminal_text(&outcome.revision.code_ref),
                    outcome.revision.event_seq,
                    short_cid(&outcome.revision.event_cid.to_hex()),
                    outputs
                )
            })
        }

        JobCmd::Runs { job_id, limit } => {
            let runs = control.runs(JobId::from(job_id.clone()), limit)?;
            fmt.emit(&runs, |runs| {
                if runs.is_empty() {
                    return format!("no runs for {}", terminal_text(&job_id));
                }
                let mut lines = vec![format!(
                    "{:<14} {:<12} {:<10} {:<28} {:<22} OUTPUTS",
                    "RUN", "STATUS", "ORIGIN", "REVISION", "STARTED"
                )];
                lines.extend(runs.iter().map(format_run));
                lines.join("\n")
            })
        }

        JobCmd::CompactRuns {
            job_id,
            keep_terminal,
            max_delete,
            dry_run,
        } => {
            let report = control.compact_job_runs(
                JobId::from(job_id.clone()),
                keep_terminal,
                max_delete,
                dry_run,
            )?;
            fmt.emit(&report, |report| {
                if report.dry_run {
                    format!(
                        "{}: {} terminal runs are eligible; a bounded pass can remove up to {}",
                        terminal_text(&job_id),
                        report.eligible,
                        report.eligible.min(max_delete as u64)
                    )
                } else {
                    format!(
                        "{}: deleted {} terminal runs; {} remain eligible",
                        terminal_text(&job_id),
                        report.deleted,
                        report.remaining_eligible
                    )
                }
            })
        }

        JobCmd::DeadLetters { limit } => {
            let letters = control.job_log.list_trigger_dead_letters(limit)?;
            fmt.emit(&letters, |letters| {
                if letters.is_empty() {
                    return "no trigger dead letters".to_string();
                }
                letters
                    .iter()
                    .map(|letter| {
                        format!(
                            "{}  {}  {}",
                            ts(letter.failed_at_unix),
                            terminal_text(letter.job_id.as_ref()),
                            terminal_text(&letter.error)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }

        JobCmd::CompactDeadLetters {
            max_delete,
            dry_run,
        } => {
            let report = control
                .job_log
                .compact_trigger_dead_letters(max_delete, dry_run)?;
            fmt.emit(&report, |report| {
                if report.dry_run {
                    format!(
                        "{} of {} trigger dead letters selected for a bounded purge",
                        report.selected, report.total
                    )
                } else {
                    format!(
                        "deleted {} trigger dead letters; {} remain",
                        report.deleted, report.remaining
                    )
                }
            })
        }

        JobCmd::List => {
            let jobs = control.job_log.list_jobs()?;
            let rendered: Vec<_> = jobs
                .iter()
                .map(|j| {
                    serde_json::json!({
                        "job_id": j.spec.job_id.to_string(),
                        "code_ref": j.spec.code_ref,
                        "determinism": format!("{:?}", j.spec.determinism),
                        "pointer_inputs": j.spec.inputs.pointer_inputs,
                        "static_inputs": j.spec.inputs.static_inputs.len(),
                        "declared_outputs": j.spec.declared_outputs,
                    })
                })
                .collect();

            fmt.emit(rendered, |jobs| {
                if jobs.is_empty() {
                    return "no jobs".to_string();
                }
                jobs.iter()
                    .map(|j| {
                        format!(
                            "{:<28} {:<12} {}",
                            terminal_text(j["job_id"].as_str().unwrap_or("")),
                            terminal_text(j["code_ref"].as_str().unwrap_or("")),
                            j["determinism"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }

        JobCmd::SubscribePointer { job_id, pointer_id } => {
            control.subscribe_pointer(&pointer_id, JobId::from(job_id.clone()))?;
            let value = serde_json::json!({ "job_id": job_id, "pointer_id": pointer_id });
            fmt.emit(value, |_| {
                format!(
                    "{} now triggers on {}",
                    terminal_text(&job_id),
                    terminal_text(&pointer_id)
                )
            })
        }

        JobCmd::UnsubscribePointer { job_id, pointer_id } => {
            let removed = control.unsubscribe_pointer(&pointer_id, JobId::from(job_id.clone()))?;
            let value = serde_json::json!({
                "job_id": job_id,
                "pointer_id": pointer_id,
                "removed": removed,
            });
            fmt.emit(value, |_| {
                if removed {
                    format!(
                        "{} no longer triggers on {}",
                        terminal_text(&job_id),
                        terminal_text(&pointer_id)
                    )
                } else {
                    format!(
                        "{} was not subscribed to {}",
                        terminal_text(&job_id),
                        terminal_text(&pointer_id)
                    )
                }
            })
        }

        JobCmd::Adapters => {
            // A simulated adapter is called out in its own column rather than
            // listed as a peer of the real ones: `fake_fetch` fabricates its
            // output, and an operator picking an adapter from this list has no
            // other way to find that out.
            let adapters = dag_jobs::builtin_adapters();
            fmt.emit(adapters, |adapters| {
                adapters
                    .iter()
                    .map(|a| {
                        let kind = if a.simulated {
                            "SIMULATED"
                        } else if a.deterministic {
                            "deterministic"
                        } else {
                            "side-effecting"
                        };
                        format!("{:<14} {:<15} {}", a.name, kind, a.summary)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }

        JobCmd::Rebuild {
            from_store,
            trust_unfiled_control_events,
            max_objects,
            max_bytes,
        } => {
            if from_store {
                if !trust_unfiled_control_events {
                    anyhow::bail!(
                        "store-scanned job records are unsigned ordinary content; rerun with --from-store --trust-unfiled-control-events only after verifying every store writer was authorised to reconstruct job history"
                    );
                }
                let report = control.rebuild_jobs_from_store_with_limits(
                    max_objects.unwrap_or(dag_control::DEFAULT_RECOVERY_MAX_OBJECTS),
                    max_bytes.unwrap_or(dag_control::DEFAULT_RECOVERY_MAX_BYTES),
                )?;
                return emit_store_rebuild(&report, fmt, false);
            }

            let report = control.rebuild_jobs()?;
            fmt.emit(&report, |r| {
                format!(
                    "job rebuild complete: {} jobs, {} heads rebuilt, {} validation errors",
                    r.jobs_processed, r.heads_rebuilt, r.validation_errors
                )
            })
        }
    }
}

/// Render a store-scan rebuild, saying plainly that it happened.
fn emit_store_rebuild(
    report: &dag_control::JobStoreRebuildReport,
    fmt: Format,
    fell_back: bool,
) -> Result<()> {
    let out = serde_json::json!({
        "source": "store",
        "fell_back": fell_back,
        "chunks_scanned": report.chunks_scanned,
        "events_found": report.events_found,
        "events_skipped": report.events_skipped,
        "skipped": report.skipped,
        "heads_rebuilt": report.heads_rebuilt,
    });
    fmt.emit(out, |o| {
        let mut lines = Vec::new();
        if fell_back {
            lines.push(
                "the job event log is empty but the store is not; \
                 recovering from the content store instead"
                    .to_string(),
            );
        }
        lines.push(format!(
            "rebuilt {} jobs from {} chunks ({} events found, {} skipped). \
             Run history lives only in the database and does not come back.",
            o["heads_rebuilt"], o["chunks_scanned"], o["events_found"], o["events_skipped"]
        ));
        for reason in &report.skipped {
            lines.push(format!("  skipped {}", terminal_text(reason)));
        }
        lines.join("\n")
    })
}

fn format_run(run: &JobRun) -> String {
    let status = match &run.status {
        RunStatus::Pending => "Pending".to_string(),
        RunStatus::Running => "Running".to_string(),
        RunStatus::Succeeded => "Succeeded".to_string(),
        RunStatus::Failed { message } => format!("Failed({})", terminal_text(message)),
    };
    let outputs = run
        .outputs
        .iter()
        .map(|(name, cid)| format!("{}={}", terminal_text(name), short_cid(&cid.to_hex())))
        .collect::<Vec<_>>()
        .join(" ");
    let revision = run
        .revision
        .as_ref()
        .map(|revision| {
            format!(
                "{}@{}:{}",
                terminal_text(&revision.code_ref),
                revision.event_seq,
                short_cid(&revision.event_cid.to_hex())
            )
        })
        .unwrap_or_else(|| "legacy".to_string());
    format!(
        "{:<14} {:<12} {:<10} {:<28} {:<22} {}",
        run.run_id.to_string(),
        status,
        // Whether this node did the work, reused its own cache, or adopted
        // another node's signed claim (ADR-003). Three different provenance
        // stories that used to render identically.
        dag_jobs::effect_origin_label(&run.origin),
        revision,
        ts(run.started_at_unix),
        outputs
    )
}
