//! Event stream commands: replay from the journal and follow live.

use anyhow::Result;
use clap::Subcommand;
use dag_control::{Control, Event};
use std::collections::HashSet;
use std::io::Write;

use crate::output::{terminal_text, Format};

/// Maximum JSON envelope accepted from a remote event server.
///
/// The native server emits at most 128 KiB per response. Repeating the bound
/// at the display boundary protects the CLI when it is connected to a
/// non-conforming or hostile gRPC implementation.
const MAX_REMOTE_EVENT_JSON_BYTES: usize = 128 * 1024;

#[derive(Subcommand)]
pub enum EventCmd {
    /// Stream events as JSONL (Ctrl-C to exit)
    Tail {
        /// Comma-separated kinds to include: pointer, pin, job, storage
        #[arg(long)]
        filter: Option<String>,
        /// Replay from this journal sequence number before following
        #[arg(long)]
        since_seq: Option<u64>,
        /// Replay from this moment (RFC 3339, e.g. 2026-08-04T09:00:00Z)
        /// before following — resolved against the local journal's own
        /// timestamps
        #[arg(long, conflicts_with = "since_seq")]
        since: Option<String>,
        /// After replaying, keep following live events
        #[arg(long)]
        follow: bool,
        /// Return at most this many events, counting back from the newest —
        /// the same rule as `GET /api/events?limit=`
        #[arg(long)]
        limit: Option<usize>,
        /// Tail another node instead of this directory (grpc://host:port).
        /// Does not open the local data directory at all
        #[arg(long)]
        remote: Option<String>,
        /// Base64url bearer token for the remote node. Prefer --token-file: a token
        /// passed here is visible in process listings
        #[arg(long)]
        token: Option<String>,
        /// File holding the bearer token for the remote node
        #[arg(long)]
        token_file: Option<std::path::PathBuf>,
        /// Additional PEM CA certificate for a grpcs:// remote; platform
        /// native roots remain trusted
        #[arg(long)]
        ca_cert: Option<std::path::PathBuf>,
        /// Hostname to verify the server certificate against, when it
        /// differs from the host in the URL
        #[arg(long)]
        tls_domain: Option<String>,
        /// Permit grpc:// to a non-loopback host for remote development
        #[arg(long, requires = "remote")]
        allow_insecure_transport: bool,
    },
    /// Drop old events from the journal
    Compact {
        /// Number of recent events to keep
        #[arg(long, default_value = "100000")]
        keep_last: u64,
        /// Report what would be dropped without writing
        #[arg(long)]
        dry_run: bool,
        /// After deleting, hand the freed pages back to the filesystem.
        ///
        /// Closes the control plane to do it, so this is the last thing the
        /// command does.
        #[arg(long)]
        reclaim: bool,
    },
}

/// The stream kind an event belongs to, as used by `--filter`.
pub fn kind_of(event: &Event) -> &'static str {
    event.kind()
}

/// Parse a `--filter` value into a set of kinds; `None` means "everything".
pub fn parse_filter(spec: Option<&str>) -> Option<HashSet<String>> {
    let spec = spec?;
    let set: HashSet<String> = spec
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

/// Whether an envelope passes the parsed filter.
pub fn passes(filter: Option<&HashSet<String>>, event: &Event) -> bool {
    filter.is_none_or(|set| set.contains(kind_of(event)))
}

/// Parse a `--since` value to unix seconds.
///
/// RFC 3339 only, stated in the help text — accepting looser formats
/// silently would make "2026-08-04" mean midnight in some timezone the
/// operator did not pick.
pub fn parse_since(raw: &str) -> Result<i64> {
    chrono::DateTime::parse_from_rfc3339(raw.trim())
        .map(|dt| dt.timestamp())
        .map_err(|e| {
            anyhow::anyhow!("--since needs an RFC 3339 timestamp like 2026-08-04T09:00:00Z: {e}")
        })
}

/// Parse and canonically re-encode a remote envelope before writing JSONL.
///
/// Printing the peer-provided `json` string verbatim would let an otherwise
/// authenticated server inject new terminal lines or escape sequences. A
/// typed round trip both validates the claimed wire metadata and makes
/// `serde_json` escape every control character in stored event text.
fn canonical_remote_event(seq: u64, ts: i64, json: &str) -> Result<String> {
    if json.len() > MAX_REMOTE_EVENT_JSON_BYTES {
        anyhow::bail!(
            "remote event {seq} exceeds the {MAX_REMOTE_EVENT_JSON_BYTES}-byte response limit"
        );
    }
    let decoded: dag_control::EventEnvelope = serde_json::from_str(json)
        .map_err(|_| anyhow::anyhow!("remote event {seq} is not a valid event envelope"))?;
    if decoded.v != 1 {
        anyhow::bail!(
            "remote event {seq} uses unsupported envelope schema {}",
            decoded.v
        );
    }
    if decoded.seq != seq || decoded.envelope_ts != ts {
        anyhow::bail!("remote event {seq} disagrees with its authenticated wire metadata");
    }
    serde_json::to_string(&decoded)
        .map_err(|_| anyhow::anyhow!("remote event {seq} could not be encoded safely"))
}

/// Tail a remote node's event stream — the counterpart of the local tail,
/// producing the same JSONL lines from the same envelopes.
///
/// Deliberately takes no `Control`: watching another node's events must not
/// require (or lock) a local data directory. `main` routes here before
/// opening one.
pub fn tail_remote(
    url: &str,
    connect: dag_net::ConnectOptions,
    filter: Option<String>,
    since_seq: Option<u64>,
    follow: bool,
    limit: Option<usize>,
    fmt: Format,
) -> Result<()> {
    use dag_control::ControlError;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let remote = dag_net::RemoteNode::connect_with(url, connect)
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))?;

        let types: Vec<String> = parse_filter(filter.as_deref())
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        let replay = since_seq.is_some();
        let since = since_seq.unwrap_or(0);
        // Mirror the local tail: no --since-seq means live-follow; with one,
        // --follow decides whether the stream continues past the replay.
        let no_follow = replay && !follow;

        if replay {
            fmt.note(format!(
                "# replaying from seq {} on {}",
                since,
                terminal_text(url)
            ));
            if limit.is_none() {
                fmt.note(format!(
                    "# remote replay has a {}-event safety ceiling; an incomplete answer ends with an error",
                    dag_net::MAX_REMOTE_EVENT_REPLAY_EVENTS
                ));
            }
        }

        let mut stream = remote
            .subscribe_events(
                replay,
                since,
                limit.map(|l| l as u64).unwrap_or(0),
                &types,
                no_follow,
            )
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))?;

        if !no_follow {
            fmt.note("# following live events (Ctrl-C to exit)");
        }

        let mut stdout = std::io::stdout();
        let mut first: Option<u64> = None;
        while let Some(envelope) = stream
            .message()
            .await
            .map_err(|e| ControlError::Remote(format!("event stream: {}", e.message())))?
        {
            // Retention trims the front of the remote journal too; the first
            // sequence number arriving above the request says so.
            if replay && first.is_none() && envelope.seq > since {
                fmt.note(format!(
                    "# remote journal starts at seq {} (requested from {})",
                    envelope.seq, since
                ));
            }
            first.get_or_insert(envelope.seq);
            writeln!(
                stdout,
                "{}",
                canonical_remote_event(envelope.seq, envelope.ts, &envelope.json)?
            )?;
            stdout.flush()?;
        }
        Ok(())
    })
}

pub fn handle(control: Control, cmd: EventCmd, fmt: Format) -> Result<()> {
    match cmd {
        EventCmd::Tail {
            filter,
            since_seq,
            since,
            follow,
            limit,
            // Routed to `tail_remote` by main before the directory opened;
            // reaching here means the tail is local.
            remote: _,
            token: _,
            token_file: _,
            ca_cert: _,
            tls_domain: _,
            allow_insecure_transport: _,
        } => {
            // A wall-clock start resolves to a sequence number against the
            // journal's own timestamps, then flows down the existing path.
            let since_seq = match since {
                Some(raw) => {
                    let ts = parse_since(&raw)?;
                    match control.event_bus.seq_at_or_after(ts)? {
                        Some(seq) => Some(seq),
                        None => {
                            // Nothing that recent yet: an empty replay from
                            // the *next* event keeps `--follow` meaningful.
                            fmt.note(format!(
                                "# no journal events at or after {}",
                                terminal_text(&raw)
                            ));
                            Some(control.event_bus.current_seq())
                        }
                    }
                }
                None => since_seq,
            };
            let filter = parse_filter(filter.as_deref());
            let mut stdout = std::io::stdout();

            // Subscribe before replaying so nothing emitted mid-replay is lost.
            let mut rx = control.event_bus.subscribe();

            if let Some(start) = since_seq {
                fmt.note(format!("# replaying from seq {}", start));

                // The filter goes down with the request: the journal counts the
                // limit against matching events, so `--filter pin --limit 10`
                // yields ten pins rather than ten rows that might contain none.
                let matches = |event: &Event| passes(filter.as_ref(), event);
                let window = control.event_bus.replay(start, limit, &matches)?;

                // Retention trims the front of the journal. Saying nothing here
                // is what made a partial answer look complete.
                if let Some(t) = window.truncated {
                    fmt.note(format!(
                        "# journal starts at seq {}; {} events before it have been dropped \
                         (requested from {})",
                        t.earliest_seq, t.missing, t.requested_seq
                    ));
                }

                // A gap between two *matching* events is expected whenever a
                // filter is active — the non-matching events in between were
                // never candidates. Only an unfiltered replay can read a jump
                // in seq as a missing event.
                let report_gaps = filter.is_none();
                let mut prev: Option<u64> = None;
                for envelope in &window.events {
                    if report_gaps {
                        if let Some(p) = prev {
                            if p + 1 != envelope.seq {
                                fmt.note(format!("# gap in journal: {} -> {}", p, envelope.seq));
                            }
                        }
                    }
                    prev = Some(envelope.seq);
                    writeln!(stdout, "{}", serde_json::to_string(envelope)?)?;
                }
                stdout.flush()?;
                fmt.note(match prev {
                    Some(seq) => format!("# replay complete (last seq {})", seq),
                    None => "# replay complete (no events)".to_string(),
                });

                if !follow {
                    return Ok(());
                }
            }

            fmt.note("# following live events (Ctrl-C to exit)");
            loop {
                match rx.blocking_recv() {
                    Ok(envelope) => {
                        if passes(filter.as_ref(), &envelope.event) {
                            writeln!(stdout, "{}", serde_json::to_string(&envelope)?)?;
                            stdout.flush()?;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        fmt.note(format!("# lagged, missed {} events", n));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Ok(())
        }

        EventCmd::Compact {
            keep_last,
            dry_run,
            reclaim,
        } => {
            if dry_run {
                // Counted against the journal as it stands. Reporting the
                // cutoff sequence number here, as this once did, told an
                // operator "would drop 501 events" twice in a row — the second
                // time with nothing left to drop.
                let report = control.event_bus.plan_compaction(keep_last)?;
                return fmt.emit(&report, |r| {
                    format!(
                        "would drop {} events below seq {}, keeping {}",
                        r.events_deleted, r.cutoff_seq, r.events_kept
                    )
                });
            }

            let report = control.event_bus.compact_keep_last(keep_last)?;
            fmt.emit(&report, |r| {
                format!(
                    "compacted: dropped {} events below seq {}, kept {}",
                    r.events_deleted, r.cutoff_seq, r.events_kept
                )
            })?;

            if !reclaim {
                return Ok(());
            }

            // redb hands pages back only through `Database::compact`, which
            // needs the file to itself. Dropping the control plane releases the
            // single `Arc<Database>` every log shares.
            let data_dir = control.path().to_path_buf();
            drop(control);

            let report = dag_control::reclaim_control_db(&data_dir)?;
            fmt.emit(&report, |r| {
                if r.compacted {
                    format!(
                        "reclaimed {} bytes ({} -> {})",
                        r.bytes_reclaimed, r.bytes_before, r.bytes_after
                    )
                } else {
                    format!(
                        "nothing to reclaim: {} bytes holding {} bytes of live data, \
                         which is already lean enough that rewriting it would grow it",
                        r.bytes_before, r.live_bytes
                    )
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ptr_event() -> Event {
        Event::PointerUpdate {
            id: "p".into(),
            new: dag_core::Cid::compute(b"x"),
            ts: 0,
        }
    }

    #[test]
    fn since_accepts_rfc3339_and_refuses_bare_dates_with_guidance() {
        assert_eq!(parse_since("1970-01-01T00:00:10Z").unwrap(), 10);
        assert_eq!(
            parse_since(" 1970-01-01T01:00:00+01:00 ").unwrap(),
            0,
            "offsets normalise to the same instant"
        );
        // A bare date has no timezone the operator chose; refuse with the
        // format named rather than guessing midnight-somewhere.
        let err = parse_since("2026-08-04").unwrap_err().to_string();
        assert!(err.contains("RFC 3339"), "{err}");
    }

    #[test]
    fn empty_filter_means_everything() {
        assert!(parse_filter(None).is_none());
        assert!(parse_filter(Some("")).is_none());
        assert!(passes(None, &ptr_event()));
    }

    #[test]
    fn filter_selects_by_kind() {
        let f = parse_filter(Some("pin, job")).unwrap();
        assert!(!passes(Some(&f), &ptr_event()));
        assert!(passes(
            Some(&f),
            &Event::PinEvent {
                id: "a".into(),
                action: "create".into(),
                ts: 0
            }
        ));
    }

    #[test]
    fn remote_events_are_typed_and_control_characters_stay_json_escaped() {
        let envelope = dag_control::EventEnvelope {
            v: 1,
            seq: 7,
            envelope_ts: 11,
            event: Event::PointerUpdate {
                id: "forged\nline\u{1b}[31m".into(),
                new: dag_core::Cid::compute(b"x"),
                ts: 10,
            },
        };
        let peer_json = serde_json::to_string(&envelope).unwrap();
        let line = canonical_remote_event(7, 11, &peer_json).unwrap();
        assert!(!line.contains('\n'));
        assert!(!line.contains('\u{1b}'));
        assert!(line.contains("\\n"));
        assert!(line.contains("\\u001b"));
    }

    #[test]
    fn remote_events_reject_injected_lines_metadata_drift_and_oversize() {
        assert!(canonical_remote_event(1, 2, "{}\nforged").is_err());

        let envelope = dag_control::EventEnvelope {
            v: 1,
            seq: 9,
            envelope_ts: 4,
            event: ptr_event(),
        };
        let peer_json = serde_json::to_string(&envelope).unwrap();
        assert!(canonical_remote_event(8, 4, &peer_json).is_err());
        assert!(canonical_remote_event(9, 5, &peer_json).is_err());
        assert!(
            canonical_remote_event(9, 4, &"x".repeat(MAX_REMOTE_EVENT_JSON_BYTES + 1)).is_err()
        );
    }
}
