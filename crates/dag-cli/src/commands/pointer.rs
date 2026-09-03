//! Pointer commands: mutable named references backed by an append-only log.

use anyhow::Result;
use clap::Subcommand;
use dag_control::{validate_pointer_id, Control};
use dag_core::ContentStore;

use crate::output::{short_cid, terminal_text, ts, Format};

#[derive(Subcommand)]
pub enum PointerCmd {
    /// Create a pointer at an initial CID
    Create {
        /// Pointer ID
        #[arg(long)]
        id: String,
        /// CID the pointer starts at
        #[arg(long)]
        cid: String,
        /// Also pin this version's whole subtree for this many seconds —
        /// the flight-recorder flag. History entries are permanent but
        /// superseded *bytes* are collectable; this keeps them
        /// reconstructable for a review window (pin `history/<id>/<seq>`)
        #[arg(long, value_name = "TTL_SECS")]
        pin_history: Option<u64>,
    },
    /// Move an existing pointer to a new CID
    Update {
        /// Pointer ID
        #[arg(long)]
        id: String,
        /// CID to move to
        #[arg(long)]
        cid: String,
        /// Update a pointer on another node (grpc://host:port) instead.
        ///
        /// Remote writes are compare-and-set: --expect-seq is required, the
        /// node applies the update only if its head is exactly that
        /// sequence, and a stale expectation is refused naming the actual
        /// head so you can re-read and retry. Local updates keep their
        /// unconditional append semantics.
        #[arg(long, requires = "expect_seq")]
        remote: Option<String>,
        /// Head sequence the update expects on the remote; 0 creates
        #[arg(long, requires = "remote")]
        expect_seq: Option<u64>,
        /// Also pin this version's whole subtree for this many seconds —
        /// the flight-recorder flag (pin `history/<id>/<seq>`). Local only
        #[arg(long, value_name = "TTL_SECS", conflicts_with = "remote")]
        pin_history: Option<u64>,
        /// Base64url bearer token for the remote node (prefer --token-file)
        #[arg(long, requires = "remote")]
        token: Option<String>,
        /// File holding the bearer token for the remote node
        #[arg(long, requires = "remote")]
        token_file: Option<std::path::PathBuf>,
        /// Additional PEM CA certificate for a grpcs:// remote; platform
        /// native roots remain trusted
        #[arg(long, requires = "remote")]
        ca_cert: Option<std::path::PathBuf>,
        /// Hostname to verify the server certificate against
        #[arg(long, requires = "remote")]
        tls_domain: Option<String>,
        /// Permit grpc:// to a non-loopback host for remote development
        #[arg(long, requires = "remote")]
        allow_insecure_transport: bool,
    },
    /// Print the CID a pointer currently resolves to
    Resolve {
        /// Pointer ID
        #[arg(long)]
        id: String,
        /// Resolve as of this sequence number instead of the current head
        #[arg(long, conflicts_with = "as_of")]
        at_seq: Option<u64>,
        /// Resolve as of this RFC 3339 instant, e.g. 2026-03-12T00:00:00Z
        ///
        /// Picks the last update at or before the instant, which is what
        /// "what was live on the 12th" means.
        #[arg(long)]
        as_of: Option<String>,
        /// Resolve on another node (grpc://host:port) instead. Historical
        /// selectors stay local — the protocol answers heads
        #[arg(long, conflicts_with_all = ["at_seq", "as_of"])]
        remote: Option<String>,
        /// Base64url bearer token for the remote node (prefer --token-file)
        #[arg(long, requires = "remote")]
        token: Option<String>,
        /// File holding the bearer token for the remote node
        #[arg(long, requires = "remote")]
        token_file: Option<std::path::PathBuf>,
        /// Additional PEM CA certificate for a grpcs:// remote; platform
        /// native roots remain trusted
        #[arg(long, requires = "remote")]
        ca_cert: Option<std::path::PathBuf>,
        /// Hostname to verify the server certificate against
        #[arg(long, requires = "remote")]
        tls_domain: Option<String>,
        /// Permit grpc:// to a non-loopback host for remote development
        #[arg(long, requires = "remote")]
        allow_insecure_transport: bool,
    },
    /// Show the pointer's head (CID plus sequence number)
    Head {
        /// Pointer ID
        #[arg(long)]
        id: String,
    },
    /// Show the pointer's update history
    History {
        /// Pointer ID
        #[arg(long)]
        id: String,
        /// First sequence number to include
        #[arg(long, default_value = "1")]
        from: u64,
        /// Exclusive upper bound; defaults to the current head
        #[arg(long)]
        to: Option<u64>,
    },
    /// List every known pointer
    List,
    /// Repair pointer heads; use `dag recover` to certify the full recovery gate
    Rebuild {
        /// Report what would be rebuilt without writing
        #[arg(long)]
        dry_run: bool,
        /// Recover from the content store alone, ignoring the events table.
        ///
        /// The ordinary rebuild trusts only the filed events table. This is the
        /// explicit route for when that table is lost or suspect: it skips the
        /// table and rebuilds from event entries in `data/`. It reads every
        /// chunk and requires the separate store-writer trust acknowledgement.
        // There is no dry-run form of a store scan: the point of the flag is
        // to write what the table lost.
        #[arg(long, conflicts_with = "dry_run")]
        from_store: bool,
        /// Trust unsigned pointer-shaped records found among ordinary content.
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

/// Resolve a pointer on another node. Takes no `Control` — main routes here
/// before the local directory opens.
pub fn resolve_remote(
    url: &str,
    connect: dag_net::ConnectOptions,
    id: &str,
    fmt: Format,
) -> Result<()> {
    use dag_control::ControlError;
    let runtime = tokio::runtime::Runtime::new()?;
    let (cid, seq) = runtime.block_on(async {
        let node = dag_net::RemoteNode::connect_with(url, connect)
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))?;
        node.resolve_pointer(id)
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))
    })?;

    let out = serde_json::json!({
        "pointer_id": id, "cid": cid.to_hex(), "seq": seq, "remote": url,
    });
    fmt.emit(out, |_| cid.to_hex())
}

/// Compare-and-set a pointer on another node. Takes no `Control` — main
/// routes here before the local directory opens.
pub fn update_remote(
    url: &str,
    connect: dag_net::ConnectOptions,
    id: &str,
    cid: &str,
    expect_seq: u64,
    fmt: Format,
) -> Result<()> {
    use dag_control::ControlError;
    let cid = super::parse_cid(cid)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let seq = runtime.block_on(async {
        let node = dag_net::RemoteNode::connect_with(url, connect)
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))?;
        // A stale expectation comes back FAILED_PRECONDITION naming the
        // actual head — surfaced verbatim, since it is the retry recipe.
        node.update_pointer(id, &cid, expect_seq)
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))
    })?;

    let out = serde_json::json!({
        "pointer_id": id, "seq": seq, "cid": cid.to_hex(), "remote": url,
    });
    fmt.emit(out, |o| {
        format!(
            "updated {} @{} -> {} on {}",
            terminal_text(o["pointer_id"].as_str().unwrap_or("")),
            o["seq"],
            short_cid(o["cid"].as_str().unwrap_or("")),
            terminal_text(url)
        )
    })
}

/// Reject a `--pin-history` value before anything is written.
///
/// The pin is applied *after* the pointer moves, so a TTL rejected later
/// would leave the pointer updated and the command failing — the operator
/// would have to read the error carefully to know the write had happened.
/// Validated here, at parse time, the flag is all-or-nothing.
fn check_pin_history(ttl_secs: Option<u64>) -> Result<()> {
    if let Some(0) = ttl_secs {
        anyhow::bail!(
            "--pin-history needs a positive TTL (seconds); for permanent \
             retention create a pin without one: `dag pin create --target <CID>:full`"
        );
    }
    Ok(())
}

/// The flight-recorder half of `--pin-history`: a subtree pin over the
/// version just named, expiring after the review window.
///
/// The pin is what makes the difference between "the history *names* this
/// deploy" and "the history can *reproduce* it": superseded bytes are
/// collectable the moment the pointer moves on, and incident review always
/// happens after the pointer moved on.
fn pin_history(
    control: &Control,
    pointer_id: &str,
    seq: u64,
    cid: &dag_core::Cid,
    ttl_secs: u64,
    fmt: Format,
) -> Result<()> {
    let pin_id = format!("history/{pointer_id}/{seq}");
    control.pin_log.create(
        &pin_id,
        dag_core::PinTarget::Subtree {
            root: cid.clone(),
            max_depth: None,
        },
        dag_core::PinScope::Global,
        Some(dag_control::now_unix() + ttl_secs as i64),
        Some("pointer --pin-history".into()),
    )?;
    fmt.note(format!(
        "# pinned {} for {ttl_secs}s",
        terminal_text(&pin_id)
    ));
    Ok(())
}

pub fn handle(control: &Control, cmd: PointerCmd, fmt: Format) -> Result<()> {
    match cmd {
        PointerCmd::Create {
            id,
            cid,
            pin_history: pin_ttl,
        } => {
            validate_pointer_id(&id).map_err(|e| anyhow::anyhow!("invalid pointer ID: {}", e))?;
            check_pin_history(pin_ttl)?;
            let cid = super::parse_cid(cid)?;
            control.pointer_log.create(&id, cid.clone())?;
            if let Some(ttl) = pin_ttl {
                pin_history(control, &id, 1, &cid, ttl, fmt)?;
            }

            let out = serde_json::json!({
                "pointer_id": id, "seq": 1u64, "cid": cid.to_hex(),
            });
            fmt.emit(out, |o| {
                format!(
                    "created {} @1 -> {}",
                    terminal_text(o["pointer_id"].as_str().unwrap_or("")),
                    short_cid(o["cid"].as_str().unwrap_or(""))
                )
            })
        }

        PointerCmd::Update {
            id,
            cid,
            pin_history: pin_ttl,
            // Routed to `update_remote` by main before the directory opened;
            // reaching here means the write is local.
            remote: _,
            expect_seq: _,
            token: _,
            token_file: _,
            ca_cert: _,
            tls_domain: _,
            allow_insecure_transport: _,
        } => {
            validate_pointer_id(&id).map_err(|e| anyhow::anyhow!("invalid pointer ID: {}", e))?;
            check_pin_history(pin_ttl)?;
            let cid = super::parse_cid(cid)?;
            let (seq, prev) = control.pointer_log.update(&id, cid.clone())?;
            if let Some(ttl) = pin_ttl {
                pin_history(control, &id, seq, &cid, ttl, fmt)?;
            }

            let out = serde_json::json!({
                "pointer_id": id, "seq": seq,
                "cid": cid.to_hex(), "previous_cid": prev.to_hex(),
            });
            fmt.emit(out, |o| {
                format!(
                    "updated {} @{} -> {}",
                    terminal_text(o["pointer_id"].as_str().unwrap_or("")),
                    o["seq"],
                    short_cid(o["cid"].as_str().unwrap_or(""))
                )
            })
        }

        PointerCmd::Resolve {
            id,
            at_seq,
            as_of,
            remote: _,
            token: _,
            token_file: _,
            ca_cert: _,
            tls_domain: _,
            allow_insecure_transport: _,
        } => {
            match historical_selector(at_seq, as_of.as_deref())? {
                None => {
                    let cid = control.pointer_log.resolve(&id)?;
                    let out = serde_json::json!({ "pointer_id": id, "cid": cid.to_hex() });
                    fmt.emit(out, |_| cid.to_hex())
                }
                Some(selector) => {
                    let event = resolve_historical(control, &id, selector)?;
                    let cid = event.new.to_hex();
                    // Say plainly whether the bytes are still here. Only a
                    // pointer's *current* head is a retention root, so a
                    // superseded version can be named for ever and collected —
                    // the history is intact, the content need not be.
                    let present = control.store.has_chunk(&event.new)?;
                    let out = serde_json::json!({
                        "pointer_id": id,
                        "cid": cid,
                        "seq": event.seq,
                        "ts": event.ts,
                        "content_present": present,
                    });
                    fmt.emit(out, move |_| {
                        if present {
                            cid.clone()
                        } else {
                            format!(
                                "{cid}\n  warning: this version's content is no longer stored. \
                                 Only the current head is a retention root; pin a version to keep it."
                            )
                        }
                    })
                }
            }
        }

        PointerCmd::Head { id } => {
            let head = control.pointer_log.get_head(&id)?;
            let out = serde_json::json!({
                "pointer_id": id,
                "seq": head.seq,
                "cid": head.current_cid.to_hex(),
            });
            fmt.emit(out, |o| {
                format!(
                    "{} @{} -> {}",
                    terminal_text(&id),
                    o["seq"],
                    head.current_cid.to_hex()
                )
            })
        }

        PointerCmd::History { id, from, to } => {
            let end = match to {
                Some(t) => t,
                None => control.pointer_log.get_head(&id)?.seq + 1,
            };
            let history = control.pointer_log.history(&id, from..end)?;

            let rendered: Vec<_> = history
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "seq": e.seq,
                        "pointer_id": e.pointer_id,
                        "cid": e.new.to_hex(),
                        "previous_cid": e.prev.as_ref().map(|c| c.to_hex()),
                        "ts": e.ts,
                    })
                })
                .collect();

            fmt.emit(rendered, |events| {
                if events.is_empty() {
                    return format!("no history for {}", terminal_text(&id));
                }
                events
                    .iter()
                    .map(|e| {
                        format!(
                            "@{:<4} {}  {}",
                            e["seq"],
                            short_cid(e["cid"].as_str().unwrap_or("")),
                            ts(e["ts"].as_i64().unwrap_or(0))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }

        PointerCmd::List => {
            let pointers = control.pointer_log.list_pointers()?;
            fmt.emit(pointers, |p| {
                if p.is_empty() {
                    "no pointers".to_string()
                } else {
                    p.iter()
                        .map(|id| terminal_text(id).into_owned())
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            })
        }

        PointerCmd::Rebuild {
            dry_run,
            from_store,
            trust_unfiled_control_events,
            max_objects,
            max_bytes,
        } => {
            if dry_run {
                let pointers = control.pointer_log.list_pointers()?;
                let out = serde_json::json!({
                    "dry_run": true,
                    "would_rebuild": pointers.len(),
                    "pointers": pointers,
                });
                return fmt.emit(out, |o| {
                    format!("would rebuild {} pointers", o["would_rebuild"])
                });
            }

            if from_store {
                if !trust_unfiled_control_events {
                    anyhow::bail!(
                        "store-scanned pointer records are unsigned ordinary content; rerun with --from-store --trust-unfiled-control-events only after verifying every store writer was authorised to reconstruct pointer history"
                    );
                }
                let report = control.rebuild_pointers_from_store_with_limits(
                    max_objects.unwrap_or(dag_control::DEFAULT_RECOVERY_MAX_OBJECTS),
                    max_bytes.unwrap_or(dag_control::DEFAULT_RECOVERY_MAX_BYTES),
                )?;
                return emit_store_rebuild(&report, control, fmt, false);
            }

            // The filed events table is the authority. Store scanning can
            // repair a lost/truncated table, but legacy event entries are
            // unsigned ordinary content and therefore require the explicit
            // trust flag above.
            let rebuilt = control.rebuild_pointers()?;
            let out = serde_json::json!({
                "dry_run": false,
                "source": "events",
                "rebuilt_count": rebuilt,
                "recovered": control.is_recovered()?,
            });
            fmt.emit(out, |o| {
                format!(
                    "rebuilt {} pointers (recovery complete: {})",
                    o["rebuilt_count"], o["recovered"]
                )
            })
        }
    }
}

/// Render a store-scan rebuild, saying plainly that it happened.
fn emit_store_rebuild(
    report: &dag_control::PointerStoreRebuildReport,
    control: &Control,
    fmt: Format,
    fell_back: bool,
) -> Result<()> {
    let out = serde_json::json!({
        "dry_run": false,
        "source": "store",
        "fell_back": fell_back,
        "chunks_scanned": report.chunks_scanned,
        "events_found": report.events_found,
        "events_skipped": report.events_skipped,
        "skipped": report.skipped,
        "rebuilt_count": report.heads_rebuilt,
        "recovered": control.is_recovered()?,
    });
    fmt.emit(out, |o| {
        let mut lines = Vec::new();
        if fell_back {
            lines.push(
                "the pointer event log is empty but the store is not; \
                 recovering from the content store instead"
                    .to_string(),
            );
        }
        lines.push(format!(
            "rebuilt {} pointers from {} chunks ({} events found, {} skipped; \
             recovery complete: {})",
            o["rebuilt_count"],
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

/// How a historical resolve was asked for.
enum Selector {
    /// The state at exactly this sequence number.
    Seq(u64),
    /// The last update at or before this POSIX instant.
    AsOf(i64),
}

/// Turn the two mutually exclusive flags into one selector, or `None` when
/// neither was given and the caller wants the current head.
fn historical_selector(at_seq: Option<u64>, as_of: Option<&str>) -> Result<Option<Selector>> {
    match (at_seq, as_of) {
        (None, None) => Ok(None),
        (Some(seq), _) => {
            if seq == 0 {
                anyhow::bail!("--at-seq starts at 1; sequence 0 never exists");
            }
            Ok(Some(Selector::Seq(seq)))
        }
        (None, Some(text)) => {
            let when = chrono::DateTime::parse_from_rfc3339(text).map_err(|e| {
                anyhow::anyhow!(
                    "--as-of {text:?} is not an RFC 3339 instant ({e}); \
                                 try 2026-03-12T00:00:00Z"
                )
            })?;
            Ok(Some(Selector::AsOf(when.timestamp())))
        }
    }
}

/// Resolve a pointer as it stood at a past sequence number or instant.
///
/// This is the question incident review actually asks — "what configuration
/// was live at the moment of the outage" — and until now the history was
/// listable but not resolvable, so answering it meant piping `history`
/// through `jq` and comparing timestamps by hand.
fn resolve_historical(
    control: &Control,
    id: &str,
    selector: Selector,
) -> Result<dag_core::PointerEvent> {
    let history = control.pointer_log.history(id, 1..u64::MAX)?;
    if history.is_empty() {
        anyhow::bail!("pointer {id} has no history");
    }

    match selector {
        Selector::Seq(seq) => history
            .into_iter()
            .find(|e| e.seq == seq)
            .ok_or_else(|| anyhow::anyhow!("pointer {id} has no update at sequence {seq}")),
        Selector::AsOf(when) => history.into_iter().rfind(|e| e.ts <= when).ok_or_else(|| {
            anyhow::anyhow!("pointer {id} did not exist at that instant; its first update is later")
        }),
    }
}
