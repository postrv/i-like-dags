//! Content and entry commands: chunks, DAG entries, and the local index.

use anyhow::{Context, Result};
use clap::Subcommand;
use dag_control::Control;
use dag_core::{ContentStore, Entry, Link, MetaHint};
use std::path::PathBuf;
use std::time::Duration;

use crate::output::{bytes, terminal_text, Format};

/// Where the bytes for a `put` come from.
#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
pub struct Source {
    /// Read the chunk from a file
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Use this string literally as the chunk body
    #[arg(long)]
    pub data: Option<String>,

    /// Read the chunk body from stdin
    #[arg(long)]
    pub stdin: bool,
}

impl Source {
    /// Materialise a payload up to a caller-selected semantic ceiling.
    pub fn read_bounded(&self, max_bytes: usize) -> Result<Vec<u8>> {
        if let Some(path) = &self.file {
            let file =
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
            return super::read_bounded(file, max_bytes, &format!("payload {}", path.display()));
        }
        if let Some(data) = &self.data {
            return super::read_bounded(
                std::io::Cursor::new(data.as_bytes()),
                max_bytes,
                "literal payload",
            );
        }
        super::read_bounded(std::io::stdin().lock(), max_bytes, "stdin payload")
    }
}

#[derive(Subcommand, Debug)]
pub enum IndexCmd {
    /// Show index statistics
    Stats,
    /// Re-hash every indexed chunk and report mismatches
    Verify {
        /// Node ID recorded in the report
        #[arg(long, default_value = "local")]
        node_id: String,
    },
    /// Rebuild the index by walking the data directory
    Reindex,
}

/// `dag put`
///
/// Content up to `MAX_CHUNK_SIZE` is stored as a single chunk, exactly as
/// before. Anything larger is split into content-defined chunks behind a file
/// manifest — `dag get` on the returned CID reassembles and re-verifies the
/// whole file. `--chunked` forces the manifest form for small content too,
/// which keeps CIDs stable for a file that starts small and grows.
pub fn put(
    control: &Control,
    source: &Source,
    content_type: Option<String>,
    chunked: bool,
    fast: bool,
    fmt: Format,
) -> Result<()> {
    let config = dag_core::ChunkerConfig::default();

    // Batching the fsyncs roughly doubles ingest throughput, but it is opt-in
    // rather than the default. `Control::bulk_ingest` documents the trade: a
    // crash part-way can leave unpublished, unindexed files and the failed
    // invocation returns no root CID. Re-ingest is safe — `split` now offers
    // even present chunks through `put_chunk`, which verifies/adopts an intact
    // orphan or repairs a short one — but the caller must retain replayable
    // input. Durable writes avoid the replay window entirely.
    //
    // Each source becomes a Read; `store_auto` decides chunk-vs-manifest and
    // streams, so no input is fully buffered. The same function backs
    // `POST /api/files` — one definition of what a store means.
    fn ingest<S: dag_core::ContentStore + ?Sized>(
        store: &S,
        source: &Source,
        content_type: Option<String>,
        chunked: bool,
        config: &dag_core::ChunkerConfig,
    ) -> Result<dag_core::StoredContent> {
        Ok(if let Some(path) = &source.file {
            let reader = std::io::BufReader::new(
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
            );
            dag_core::file::store_auto(store, reader, content_type, chunked, config)?
        } else if source.stdin {
            let stdin = std::io::stdin().lock();
            dag_core::file::store_auto(store, stdin, content_type, chunked, config)?
        } else {
            let body = source
                .data
                .as_deref()
                .context("content source is missing")?
                .as_bytes();
            dag_core::file::store_auto(
                store,
                std::io::Cursor::new(body),
                content_type,
                chunked,
                config,
            )?
        })
    }

    let stored = if fast {
        control.bulk_ingest(|store| ingest(store, source, content_type, chunked, &config))?
    } else {
        ingest(
            control.store.as_ref(),
            source,
            content_type,
            chunked,
            &config,
        )?
    };

    match stored {
        dag_core::StoredContent::File(r) => {
            fmt.note(format!(
                "chunked: {} ({} chunks, {} new, depth {})",
                bytes(r.size),
                r.chunks,
                r.new_chunks,
                r.depth
            ));
            let out = serde_json::json!({
                "cid": r.cid.to_hex(),
                "size": r.size,
                "chunked": true,
                "chunks": r.chunks,
                "new_chunks": r.new_chunks,
                "depth": r.depth,
            });
            fmt.emit(out, |_| r.cid.to_hex())
        }
        dag_core::StoredContent::Chunk { cid, size } => {
            let out = serde_json::json!({ "cid": cid.to_hex(), "size": size });
            fmt.emit(out, |_| cid.to_hex())
        }
    }
}

/// `dag get`
///
/// If the CID names a file manifest, the original file is reassembled — every
/// chunk re-hashed on the way out — so `put` and `get` stay symmetric up to
/// the core's 64 GiB local safety ceiling. `--raw` always returns the stored
/// bytes as-is, which for a manifest is the manifest entry itself.
pub fn get(control: &Control, cid: &str, out: Option<PathBuf>, raw: bool) -> Result<()> {
    use std::io::Write;

    let cid = super::parse_cid(cid)?;
    let body = control.store.get_chunk(&cid)?;

    let manifest = if raw {
        None
    } else {
        dag_core::file::inspect_from_bytes(&body)?
    };

    match (out, raw, manifest) {
        // A chunked file, reassembled and verified as it streams out.
        (Some(path), _, Some(_)) => {
            let file = std::fs::File::create(&path)
                .with_context(|| format!("creating {}", path.display()))?;
            let mut writer = std::io::BufWriter::new(file);
            let info = dag_core::file::join(control.store.as_ref(), &cid, &mut writer)?;
            writer.flush()?;
            eprintln!(
                "reassembled {} ({} chunks) to {}",
                bytes(info.size),
                info.chunks,
                terminal_text(&path.display().to_string())
            );
        }
        (None, _, Some(info)) => {
            anyhow::bail!(
                "{} is a chunked file ({}, {} chunks); pass --out <file> to reassemble it, \
                 or --raw for the manifest entry itself",
                cid,
                bytes(info.size),
                info.chunks
            );
        }

        // Ordinary content, byte-for-byte what it always was.
        (Some(path), _, None) => {
            std::fs::write(&path, &body).with_context(|| format!("writing {}", path.display()))?;
            eprintln!(
                "wrote {} to {}",
                bytes(body.len() as u64),
                terminal_text(&path.display().to_string())
            );
        }
        (None, true, None) => {
            std::io::stdout().write_all(&body)?;
        }
        (None, false, None) => {
            anyhow::bail!(
                "refusing to write binary data to a terminal: pass --out <file> or --raw"
            );
        }
    }
    Ok(())
}

/// `dag put-entry`
pub fn put_entry(
    control: &Control,
    source: Option<&Source>,
    links: &[String],
    content_type: Option<String>,
    fmt: Format,
) -> Result<()> {
    let payload = match source {
        Some(s) => s.read_bounded(dag_core::MAX_CHUNK_SIZE)?,
        None => Vec::new(),
    };

    let links = links
        .iter()
        .map(|spec| parse_link(spec))
        .collect::<Result<Vec<_>>>()?;

    let meta = content_type.map(|ct| MetaHint {
        content_type: Some(ct),
        encoding: None,
    });

    let entry = Entry::new(payload, links, meta);
    let cid = control.store.put_entry(&entry)?;

    let out = serde_json::json!({
        "cid": cid.to_hex(),
        "links": entry.links.len(),
        "payload_bytes": entry.payload.len(),
    });
    fmt.emit(out, |_| cid.to_hex())
}

/// `dag get-links`
pub fn get_links(control: &Control, cid: &str, fmt: Format) -> Result<()> {
    let cid = super::parse_cid(cid)?;
    let links = control.store.get_links(&cid)?;

    let rendered: Vec<_> = links
        .iter()
        .map(|l| {
            serde_json::json!({
                "target": l.target.to_hex(),
                "name": l.name,
            })
        })
        .collect();

    fmt.emit(rendered, |links| {
        if links.is_empty() {
            "no links".to_string()
        } else {
            links
                .iter()
                .map(|l| match l.get("name").and_then(|n| n.as_str()) {
                    Some(name) => format!(
                        "{}  {}",
                        l["target"].as_str().unwrap_or(""),
                        terminal_text(name)
                    ),
                    None => l["target"].as_str().unwrap_or("").to_string(),
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    })
}

/// A link spec is `<cid>` or `<cid>:<name>`.
fn parse_link(spec: &str) -> Result<Link> {
    let (cid_part, name) = match spec.split_once(':') {
        Some((cid, name)) => (cid, Some(name.to_string())),
        None => (spec, None),
    };
    let cid = super::parse_cid(cid_part)
        .map_err(|e| anyhow::anyhow!("in link spec {:?}: {}", spec, e))?;
    Ok(Link::new(cid, name))
}

/// `dag index ...`
pub fn index(control: &Control, cmd: IndexCmd, fmt: Format) -> Result<()> {
    let index = control
        .store
        .get_index()
        .context("store was opened without an index")?;

    match cmd {
        IndexCmd::Stats => {
            // An unreadable derived index is operational damage, not an empty
            // store. Preserve the fallible count instead of reporting a
            // reassuring zero.
            let out = serde_json::json!({ "total_chunks": index.count()? });
            fmt.emit(out, |o| format!("{} chunks indexed", o["total_chunks"]))
        }
        IndexCmd::Verify { node_id } => {
            let scanner = dag_storage::IntegrityScanner::with_index(
                control.store.clone(),
                index,
                Duration::from_secs(60),
            );
            let result = scanner.scan_once(&node_id)?;

            let invalid: Vec<_> = result
                .reports
                .iter()
                .filter(|r| !r.is_valid)
                .map(|r| {
                    serde_json::json!({
                        "cid": r.cid.to_hex(),
                        "error": r.error_message.as_deref().unwrap_or("unknown"),
                    })
                })
                .collect();

            let out = serde_json::json!({
                "node_id": node_id,
                "total_chunks": result.total_chunks,
                "valid_chunks": result.valid_chunks,
                "invalid_chunks": result.invalid_chunks,
                // Broken out because the remedies differ: missing bytes must be
                // restored from elsewhere, corrupt bytes replaced, a stale index
                // only reindexed, and an unreadable chunk is a disk problem.
                "missing_chunks": result.missing_chunks,
                "corrupt_chunks": result.corrupt_chunks,
                "stale_index_entries": result.stale_index_entries,
                "unreadable_chunks": result.unreadable_chunks,
                "invalid_reports": invalid,
                "invalid_reports_truncated": result.reports_truncated,
                "invalid_report_limit": dag_storage::integrity::MAX_INTEGRITY_REPORTS,
            });

            fmt.emit(out, |o| {
                let mut s = format!(
                    "{}/{} chunks valid, {} invalid",
                    o["valid_chunks"], o["total_chunks"], o["invalid_chunks"]
                );
                for (label, count, remedy) in [
                    ("missing", result.missing_chunks, "restore them"),
                    ("corrupt", result.corrupt_chunks, "replace the bytes"),
                    (
                        "stale index",
                        result.stale_index_entries,
                        "run `dag index reindex`",
                    ),
                    (
                        "unreadable",
                        result.unreadable_chunks,
                        "check disk and permissions",
                    ),
                ] {
                    if count > 0 {
                        s.push_str(&format!("\n  {} {} — {}", count, label, remedy));
                    }
                }
                if result.reports_truncated {
                    s.push_str(&format!(
                        "\n  per-chunk diagnostics truncated at {}; aggregate counts are complete",
                        dag_storage::integrity::MAX_INTEGRITY_REPORTS
                    ));
                }
                s
            })?;

            // A scan that found damage must not exit 0: this command's whole
            // purpose is to be gated on.
            if result.invalid_chunks > 0 {
                return Err(crate::error::CliError::DamagedStore {
                    invalid: result.invalid_chunks,
                    total: result.total_chunks,
                    missing: result.missing_chunks,
                    corrupt: result.corrupt_chunks,
                    stale: result.stale_index_entries,
                    unreadable: result.unreadable_chunks,
                }
                .into());
            }
            Ok(())
        }
        IndexCmd::Reindex => {
            let count = control.store.reindex()?;
            let out = serde_json::json!({ "reindexed_chunks": count });
            fmt.emit(out, |_| format!("reindexed {} chunks", count))
        }
    }
}
