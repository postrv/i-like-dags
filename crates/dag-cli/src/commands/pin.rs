//! Pin commands: retention policy expressed as data.

use anyhow::{Context, Result};
use clap::Subcommand;
use dag_control::{now_unix, validate_pin_id, Control};
use dag_core::{PinHead, PinScope, PinState, PinTarget};

use crate::output::{short_cid, terminal_text, ts, Format};

#[derive(Subcommand, Debug)]
pub enum PinCmd {
    /// Create a pin, protecting content from garbage collection
    Create {
        /// Pin ID
        #[arg(long)]
        id: String,
        /// `<CID>` for a single chunk, or `<CID>:<depth>` for a bounded subtree
        #[arg(long, value_name = "CID[:DEPTH]")]
        target: String,
        /// `global`, or `local:<NODE_ID>`
        #[arg(long, default_value = "global")]
        scope: String,
        /// Expire this pin after N seconds
        #[arg(long)]
        ttl_secs: Option<i64>,
        /// Recorded as the pin's author
        #[arg(long)]
        author: Option<String>,
    },
    /// Deactivate a pin, releasing its retention
    Deactivate {
        /// Pin ID
        #[arg(long)]
        id: String,
        /// Recorded as the event's author
        #[arg(long)]
        author: Option<String>,
    },
    /// List pins
    List {
        /// Only pins currently providing retention
        #[arg(long)]
        active_only: bool,
    },
    /// Show a pin's current state
    Info {
        /// Pin ID
        #[arg(long)]
        id: String,
    },
    /// Show a pin's event history
    History {
        /// Pin ID
        #[arg(long)]
        id: String,
        /// First sequence number to include
        #[arg(long, default_value = "1")]
        from: u64,
        /// Exclusive upper bound
        #[arg(long)]
        to: Option<u64>,
    },
    /// Repair pin heads; use `dag recover` to certify the full recovery gate
    Rebuild {
        /// Report what would be rebuilt without writing
        #[arg(long)]
        dry_run: bool,
        /// Recover from the content store alone, ignoring the events table.
        ///
        /// The ordinary rebuild trusts only the filed events table. This is the
        /// explicit route for when that table is lost or suspect: it rebuilds
        /// from pin event entries in `data/` plus the pin-by-target index. It
        /// reads every chunk and requires the store-writer trust acknowledgement.
        // There is no dry-run form of a store scan: the point of the flag is
        // to write what the table lost.
        #[arg(long, conflicts_with = "dry_run")]
        from_store: bool,
        /// Trust unsigned pin-shaped records found among ordinary content.
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

/// Parse `<CID>`, `<CID>:<depth>` or `<CID>:full` into a pin target.
pub fn parse_target(spec: &str) -> Result<PinTarget> {
    match spec.split_once(':') {
        // The whole subtree, however deep. This is what "pin the release"
        // means, so it gets a word rather than a magic number.
        Some((cid, "full")) => Ok(PinTarget::Subtree {
            root: super::parse_cid(cid)?,
            max_depth: None,
        }),
        Some((cid, depth)) => {
            let root = super::parse_cid(cid)?;
            let max_depth = depth
                .parse::<u32>()
                .with_context(|| format!("invalid subtree depth {:?}", depth))?;
            // A subtree of depth 0 is just the root — indistinguishable from a
            // direct pin, and invariably written by someone who believed 0
            // meant "unlimited". Refusing loudly beats silently leaving their
            // lineage unprotected for the collector.
            if max_depth == 0 {
                anyhow::bail!(
                    "subtree depth 0 would pin only the root: \
                     use a bare CID for a direct pin, or ':full' for the whole subtree"
                );
            }
            Ok(PinTarget::Subtree {
                root,
                max_depth: Some(max_depth),
            })
        }
        None => Ok(PinTarget::Direct(super::parse_cid(spec)?)),
    }
}

/// Parse `global` or `local:<node>` into a pin scope.
pub fn parse_scope(spec: &str) -> Result<PinScope> {
    if spec == "global" {
        return Ok(PinScope::Global);
    }
    match spec.strip_prefix("local:") {
        Some(node_id) if !node_id.is_empty() => Ok(PinScope::Local {
            node_id: node_id.to_string(),
        }),
        _ => anyhow::bail!(
            "invalid scope {:?}: expected `global` or `local:<NODE_ID>`",
            spec
        ),
    }
}

fn checked_expiry(now: i64, ttl: i64) -> Result<i64> {
    now.checked_add(ttl)
        .ok_or_else(|| anyhow::anyhow!("--ttl-secs exceeds the supported absolute timestamp range"))
}

pub fn handle(control: &Control, cmd: PinCmd, fmt: Format) -> Result<()> {
    match cmd {
        PinCmd::Create {
            id,
            target,
            scope,
            ttl_secs,
            author,
        } => {
            validate_pin_id(&id).map_err(|e| anyhow::anyhow!("invalid pin ID: {}", e))?;
            let target = parse_target(&target)?;
            let scope = parse_scope(&scope)?;
            // TTL is relative on the command line but absolute on disk (R5).
            //
            // A non-positive TTL is refused rather than stored: it produces a
            // pin that is already expired the instant it is written, which
            // `pin create` then reports as success and `pin list` shows as
            // an entry. The operator believes content is retained and the next
            // collection takes it. `--pin-history` refuses a zero TTL for the
            // same reason; this is the same mistake reachable directly.
            if let Some(ttl) = ttl_secs {
                if ttl <= 0 {
                    anyhow::bail!(
                        "--ttl-secs must be positive: {} would create a pin that has \
                         already expired. Omit the flag for a pin that never expires.",
                        ttl
                    );
                }
            }
            let now = now_unix();
            let expires_at = ttl_secs.map(|ttl| checked_expiry(now, ttl)).transpose()?;

            control
                .pin_log
                .create(&id, target, scope, expires_at, author)?;

            let out = serde_json::json!({ "pin_id": id, "expires_at": expires_at });
            fmt.emit(out, |_| format!("pinned {}", terminal_text(&id)))
        }

        PinCmd::Deactivate { id, author } => {
            control.pin_log.deactivate(&id, author)?;
            let out = serde_json::json!({ "pin_id": id, "state": "Deactivated" });
            fmt.emit(out, |_| format!("deactivated {}", terminal_text(&id)))
        }

        PinCmd::List { active_only } => {
            let now = now_unix();
            let mut rows = Vec::new();
            for pin_id in control.pin_log.list()? {
                // A head ID whose row cannot be decoded is corruption, not an
                // absent pin. A partial listing would make an operator believe
                // retention is narrower than the database actually says.
                let head = control.pin_log.head(&pin_id)?;
                let active = head.is_providing_retention(now);
                if active_only && !active {
                    continue;
                }
                rows.push(describe(&pin_id, &head, active));
            }

            fmt.emit(rows, |rows| {
                if rows.is_empty() {
                    return "no pins".to_string();
                }
                rows.iter()
                    .map(|r| {
                        format!(
                            "{:<28} {:<8} {:<10} {}",
                            terminal_text(r["pin_id"].as_str().unwrap_or("")),
                            if r["active"].as_bool().unwrap_or(false) {
                                "active"
                            } else {
                                "inactive"
                            },
                            terminal_text(r["scope"].as_str().unwrap_or("")),
                            short_cid(r["target_cid"].as_str().unwrap_or("")),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }

        PinCmd::Info { id } => {
            let head = control.pin_log.head(&id)?;
            let active = head.is_providing_retention(now_unix());
            let out = describe(&id, &head, active);
            fmt.emit(out, |o| {
                format!(
                    "{}\n  state:      {}\n  scope:      {}\n  target:     {}\n  importance: {}\n  expires:    {}\n  updated:    {}",
                    terminal_text(o["pin_id"].as_str().unwrap_or("")),
                    o["state"].as_str().unwrap_or(""),
                    terminal_text(o["scope"].as_str().unwrap_or("")),
                    o["target_cid"].as_str().unwrap_or(""),
                    o["importance"],
                    o["expires_at"].as_i64().map(ts).unwrap_or_else(|| "never".into()),
                    ts(o["ts"].as_i64().unwrap_or(0)),
                )
            })
        }

        PinCmd::History { id, from, to } => {
            let history = control.pin_log.history(&id, from..to.unwrap_or(u64::MAX))?;
            fmt.emit(&history, |h| {
                if h.is_empty() {
                    return format!("no history for {}", terminal_text(&id));
                }
                h.iter()
                    .map(|e| format!("@{:<4} {:?}  {}", e.seq, e.state, ts(e.ts)))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }

        PinCmd::Rebuild {
            dry_run,
            from_store,
            trust_unfiled_control_events,
            max_objects,
            max_bytes,
        } => {
            if from_store {
                if !trust_unfiled_control_events {
                    anyhow::bail!(
                        "store-scanned pin records are unsigned ordinary content; rerun with --from-store --trust-unfiled-control-events only after verifying every store writer was authorised to reconstruct pin history"
                    );
                }
                let report = control.rebuild_pins_from_store_with_limits(
                    max_objects.unwrap_or(dag_control::DEFAULT_RECOVERY_MAX_OBJECTS),
                    max_bytes.unwrap_or(dag_control::DEFAULT_RECOVERY_MAX_BYTES),
                )?;
                return emit_store_rebuild(&report, control, fmt, false);
            }

            // A dry run previews the table rebuild without writing, so it never
            // scans the store.
            if dry_run {
                let report = control.rebuild_pins(true)?;
                return fmt.emit(&report, |r| {
                    format!(
                        "pin rebuild (dry-run): {} pins, {} heads rebuilt, {} validation errors",
                        r.pins_processed, r.heads_rebuilt, r.validation_errors
                    )
                });
            }

            // The filed table remains authoritative unless the operator makes
            // the explicit unsigned-store trust decision above.
            let report = control.rebuild_pins(false)?;
            fmt.emit(&report, |r| {
                format!(
                    "pin rebuild complete: {} pins, {} heads rebuilt, {} validation errors",
                    r.pins_processed, r.heads_rebuilt, r.validation_errors
                )
            })
        }
    }
}

/// Render a store-scan rebuild, saying plainly that it happened.
fn emit_store_rebuild(
    report: &dag_control::PinStoreRebuildReport,
    control: &Control,
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
        "recovered": control.is_recovered()?,
    });
    fmt.emit(out, |o| {
        let mut lines = Vec::new();
        if fell_back {
            lines.push(
                "the pin event log is empty but the store is not; \
                 recovering from the content store instead"
                    .to_string(),
            );
        }
        lines.push(format!(
            "rebuilt {} pins from {} chunks ({} events found, {} skipped; \
             recovery complete: {})",
            o["heads_rebuilt"],
            o["chunks_scanned"],
            o["events_found"],
            o["events_skipped"],
            o["recovered"]
        ));
        for reason in &report.skipped {
            lines.push(format!("  skipped {}", terminal_text(reason)));
        }
        lines.join("\n")
    })
}

/// Flatten a pin head into the JSON shape shared by the CLI and HTTP API.
pub fn describe(pin_id: &str, head: &PinHead, active: bool) -> serde_json::Value {
    let (target_cid, depth) = match &head.event.target {
        PinTarget::Direct(cid) => (cid.to_hex(), None),
        PinTarget::Subtree { root, max_depth } => (root.to_hex(), *max_depth),
    };
    let scope = match &head.event.scope {
        PinScope::Global => "global".to_string(),
        PinScope::Local { node_id } => format!("local:{}", node_id),
    };
    serde_json::json!({
        "pin_id": pin_id,
        "seq": head.event.seq,
        "active": active,
        "state": match head.event.state {
            PinState::Active => "Active",
            PinState::Deactivated => "Deactivated",
        },
        "scope": scope,
        "target_cid": target_cid,
        "subtree": depth.is_some() || matches!(head.event.target, PinTarget::Subtree { .. }),
        "max_depth": depth,
        "expires_at": head.event.expires_at,
        "ts": head.event.ts,
        "author": head.event.author,
        "event_cid": head.event_cid.to_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::Cid;

    #[test]
    fn parse_scope_accepts_global_and_local() {
        assert_eq!(parse_scope("global").unwrap(), PinScope::Global);
        assert_eq!(
            parse_scope("local:node-a").unwrap(),
            PinScope::Local {
                node_id: "node-a".into()
            }
        );
        assert!(parse_scope("local:").is_err());
        assert!(parse_scope("nonsense").is_err());
    }

    #[test]
    fn parse_target_distinguishes_direct_from_subtree() {
        let hex = Cid::compute(b"x").to_hex();
        assert!(matches!(parse_target(&hex).unwrap(), PinTarget::Direct(_)));
        assert!(matches!(
            parse_target(&format!("{}:3", hex)).unwrap(),
            PinTarget::Subtree {
                max_depth: Some(3),
                ..
            }
        ));
        assert!(matches!(
            parse_target(&format!("{}:full", hex)).unwrap(),
            PinTarget::Subtree {
                max_depth: None,
                ..
            }
        ));
        assert!(parse_target("not-hex").is_err());
    }

    /// Depth 0 is always a mistake — it reads as "unlimited" but would pin
    /// only the root, leaving the lineage collectable.
    #[test]
    fn parse_target_refuses_depth_zero() {
        let hex = Cid::compute(b"x").to_hex();
        let err = parse_target(&format!("{}:0", hex)).unwrap_err();
        assert!(err.to_string().contains(":full"), "got: {}", err);
    }

    #[test]
    fn pin_expiry_arithmetic_is_checked() {
        assert_eq!(checked_expiry(100, 20).unwrap(), 120);
        assert!(checked_expiry(i64::MAX - 1, 2).is_err());
    }
}
