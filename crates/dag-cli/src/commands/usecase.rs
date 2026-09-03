//! The worked example, rendered for a terminal.
//!
//! The scenario itself lives in `dag_api::scenario` so the web console can
//! offer the same thing; this module only formats it.

use anyhow::Result;
use clap::Subcommand;
use dag_api::scenario::{self, VerifyReport};
use dag_control::Control;

use crate::error::CliError;

use crate::output::{short_cid, terminal_text, Format};

#[derive(Subcommand, Debug)]
pub enum UsecaseCmd {
    /// Build the worked example in this data directory
    Seed {
        /// Skip the recovery rebuilds that unblock garbage collection
        #[arg(long)]
        no_recover: bool,
    },
    /// Walk a release back to its inputs and re-verify every byte
    Verify {
        /// Pointer naming the release to verify
        #[arg(long, default_value = scenario::PTR_PRODUCTION)]
        pointer: String,
        /// Verify a release by its root CID instead of by name
        ///
        /// This is how a *historical* release is checked: resolve it with
        /// `dag pointer resolve --id <P> --at-seq N` (or `--as-of`) and pass
        /// the CID here. Verifying by name only ever checks what is live now.
        #[arg(long, conflicts_with = "pointer")]
        cid: Option<String>,
    },
}

pub async fn handle(control: &Control, cmd: UsecaseCmd, fmt: Format) -> Result<()> {
    match cmd {
        UsecaseCmd::Seed { no_recover } => {
            for step in STEPS {
                fmt.note(step);
            }
            let report = scenario::seed(control, !no_recover).await?;

            fmt.emit(&report, |r| {
                format!(
                    "\nseeded the model-release provenance ledger\n\
                     \n  {} -> {}\n  {} chunks, {} pointers, {} pins, recovery {}\n\
                     \nnext:\n  dag usecase verify\n  dag pointer history --id {}\n  dag serve",
                    terminal_text(&r.production_pointer),
                    short_cid(&r.attestation_v2),
                    r.chunks,
                    r.pointers,
                    r.pins,
                    if r.recovered {
                        "complete"
                    } else {
                        "incomplete"
                    },
                    terminal_text(&r.dataset_pointer),
                )
            })
        }

        UsecaseCmd::Verify { pointer, cid } => {
            let report = match cid {
                Some(cid) => scenario::verify_cid(control, &super::parse_cid(cid)?)?,
                None => scenario::verify(control, &pointer)?,
            };
            fmt.emit(&report, |r: &&VerifyReport| render_verify(r))?;

            // Report first, then fail: the caller wants to see *which* nodes
            // are bad, and a checker that always exits 0 is not a checker.
            if report.verified {
                Ok(())
            } else {
                Err(CliError::VerificationFailed {
                    corrupt: report.corrupt,
                    total: report.total_nodes,
                }
                .into())
            }
        }
    }
}

const STEPS: [&str; 8] = [
    "① publishing raw artefacts as immutable chunks",
    "② wrapping the dataset in an entry that carries its data card",
    "③ naming each input with a pointer",
    "④ registering the attestation job over those pointers",
    "⑤ running the attestation for release v1",
    "⑥ revising the dataset — the same job now attests different inputs",
    "⑦ pinning the release subtree so the whole lineage survives GC",
    "⑧ completing recovery so garbage collection is permitted",
];

fn render_verify(r: &VerifyReport) -> String {
    let mut out = format!(
        "provenance for {}\n  root {}\n",
        terminal_text(&r.pointer),
        r.root
    );
    for node in &r.nodes {
        out.push_str(&format!(
            "  {}{} {} {}{}\n",
            "  ".repeat(node.depth as usize),
            if node.intact { "✓" } else { "✗" },
            short_cid(&node.cid),
            terminal_text(node.name.as_deref().unwrap_or("(root)")),
            node.error
                .as_ref()
                .map(|e| format!("  [{}]", terminal_text(e)))
                .unwrap_or_default(),
        ));
    }
    out.push_str(&format!(
        "\n{} of {} nodes intact, {} bytes, retention: {}",
        r.intact,
        r.total_nodes,
        r.total_bytes,
        if r.retained {
            "protected"
        } else {
            "NOT PINNED"
        }
    ));
    out
}
