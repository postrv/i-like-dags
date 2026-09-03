//! Garbage collection commands.

use anyhow::Result;
use clap::Subcommand;
use dag_control::{Control, GcRequest, RetentionStatus};

use crate::output::{bytes, terminal_text, ts, Format};

#[derive(Subcommand, Debug)]
pub enum GcCmd {
    /// Collect unreferenced chunks, honouring pins and the recovery gate
    Run {
        /// Node whose local-scoped pins apply alongside global pins
        #[arg(long, default_value = "local")]
        node_id: String,
        /// Cap deletions/itemised results in this pass
        ///
        /// A finite value also caps inventory at 100,000 objects. Zero
        /// explicitly removes both ceilings for an offline operator-controlled
        /// run.
        #[arg(long, default_value_t = dag_storage::DEFAULT_GC_MAX_DELETIONS)]
        max_delete: usize,
        /// Report what would be deleted without deleting it
        #[arg(long)]
        dry_run: bool,
        /// Chunks younger than this are never collected
        #[arg(long, default_value = "60")]
        min_age_secs: u64,
        /// Allow collection of control-plane logs and NodeLinks
        #[arg(long)]
        no_system_protection: bool,
        /// Ceiling on how many objects one pin's subtree may enumerate
        ///
        /// Collection refuses to run when a pin covers more than this, rather
        /// than protecting a prefix and deleting the rest.
        #[arg(long)]
        max_subtree_expansion: Option<usize>,
        /// List every collected CID, not just the totals
        #[arg(long)]
        show_collected: bool,
        /// Store the report in the ledger as a gc-disposition/v1 record.
        ///
        /// The record chains to its predecessors under the pointer
        /// `system/gc/dispositions`, retains itself (a live head is a GC
        /// root), and can be signed and replicated like any content —
        /// deletion with a defensible paper trail
        #[arg(long, conflicts_with = "dry_run")]
        record: bool,
    },
    /// Explain why a CID is (or is not) retained
    Status {
        /// CID to inspect
        #[arg(long)]
        cid: String,
        /// Also apply this node's local-scoped pins
        #[arg(long)]
        node_id: Option<String>,
    },
}

pub fn handle(control: &Control, cmd: GcCmd, fmt: Format) -> Result<()> {
    match cmd {
        GcCmd::Run {
            node_id,
            max_delete,
            dry_run,
            min_age_secs,
            no_system_protection,
            max_subtree_expansion,
            show_collected,
            record,
        } => {
            if let Some(cap) = max_subtree_expansion {
                control.set_max_subtree_expansion(cap);
            }

            let req = GcRequest {
                node_id,
                dry_run,
                max_delete,
                min_age_secs,
                system_protection: !no_system_protection,
            };

            let started = std::time::Instant::now();
            if record && max_delete == 0 {
                anyhow::bail!(
                    "--record requires a finite --max-delete so its itemised disposition can be built with bounded memory"
                );
            }
            let needs_details = record || show_collected || fmt.json;
            let report = if needs_details {
                control.run_gc(&req)?
            } else {
                control.run_gc_summary(&req)?
            };
            let duration_ms = started.elapsed().as_millis() as u64;

            let disposition = if record {
                let cid = control.record_gc_disposition(&report)?.to_hex();
                fmt.note(format!(
                    "# disposition recorded: {cid} (pointer system/gc/dispositions)"
                ));
                Some(cid)
            } else {
                None
            };

            // The itemised list is the disposition record: once the bytes are
            // gone, a count cannot answer what was destroyed. Always in JSON,
            // behind a flag in the human rendering so a large run stays
            // readable.
            let collected: Vec<serde_json::Value> = report
                .collected
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "cid": c.cid.to_hex(),
                        "bytes": c.bytes,
                        "age_secs": c.age_secs,
                    })
                })
                .collect();

            let out = serde_json::json!({
                "dry_run": report.dry_run,
                "node_id": report.node_id,
                "examined": report.total_chunks_examined,
                "deleted": report.chunks_deleted,
                "bytes_freed": report.bytes_freed,
                "protected_by_pins": report.protected_by_pins,
                "protected_by_system": report.protected_by_system,
                "skipped_too_young": report.skipped_too_young,
                "truncated_by_max_delete": report.truncated_by_max_deletions,
                "collected": collected,
                "errors": report.errors,
                "errors_truncated": report.errors_truncated,
                "duration_ms": duration_ms,
                "disposition_cid": disposition,
            });

            fmt.emit(out, move |o| {
                let mut s = format!(
                    "GC {}: examined {}, deleted {} ({}), protected {} / {} system, {} too young, {}ms",
                    if o["dry_run"].as_bool().unwrap_or(false) { "(dry-run)" } else { "complete" },
                    o["examined"], o["deleted"],
                    bytes(o["bytes_freed"].as_u64().unwrap_or(0)),
                    o["protected_by_pins"], o["protected_by_system"],
                    o["skipped_too_young"], o["duration_ms"],
                );
                if o["truncated_by_max_delete"].as_bool().unwrap_or(false) {
                    s.push_str("\n  stopped at --max-delete; the counts above cover part of the store, not all of it");
                }
                if show_collected {
                    for c in o["collected"].as_array().into_iter().flatten() {
                        s.push_str(&format!(
                            "\n  - {} ({})",
                            c["cid"].as_str().unwrap_or_default(),
                            bytes(c["bytes"].as_u64().unwrap_or(0))
                        ));
                    }
                }
                s
            })
        }

        GcCmd::Status { cid, node_id } => {
            let parsed = super::parse_cid(&cid)?;
            let status = control.retention_status(&parsed, node_id.as_deref())?;
            let out = describe(&cid, &status);

            fmt.emit(out, |o| {
                if o["protected"].as_bool().unwrap_or(false) {
                    let reasons = o["sources"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .map(|reason| terminal_text(reason).into_owned())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    let expiry = o["earliest_expiry"]
                        .as_i64()
                        .map(ts)
                        .unwrap_or_else(|| "never".into());
                    format!("{}: PROTECTED by [{}], expires {}", cid, reasons, expiry)
                } else {
                    format!("{}: UNPROTECTED", cid)
                }
            })
        }
    }
}

/// Flatten a retention status into the JSON shape shared by the CLI and API.
pub fn describe(cid: &str, status: &RetentionStatus) -> serde_json::Value {
    match status {
        RetentionStatus::Unprotected => serde_json::json!({
            "cid": cid,
            "protected": false,
            "sources": [],
            "importance": 0,
            "earliest_expiry": serde_json::Value::Null,
            "system_protected": false,
        }),
        RetentionStatus::Protected(eff) => serde_json::json!({
            "cid": cid,
            "protected": true,
            "sources": eff.sources,
            "earliest_expiry": eff.earliest_expiry,
            "system_protected": eff.is_system_protected,
        }),
    }
}
