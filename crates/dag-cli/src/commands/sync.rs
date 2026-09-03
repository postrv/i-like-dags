//! Replication between two data directories, or to a remote node.
//!
//! The remote is a filesystem path (ADR-002), a `grpc://host:port` node
//! URL (ADR-005), or an `https://` Edge replica (ADR-007). All three run
//! the same engine with the same report.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use dag_control::{sync, Control, ControlError, HttpDestination, SyncOptions, SyncReport};
use dag_net::RemoteNode;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::output::{bytes, terminal_text, Format};

/// Environment fallback for the remote node token.
pub const TOKEN_ENV: &str = "DAG_NODE_TOKEN";

/// A token file may contain a trailing newline, but it is still a tiny secret.
/// Keeping the byte budget separate from the accepted token length produces a
/// useful "file too large" diagnostic before allocating an attacker-selected
/// amount of memory.
const MAX_TOKEN_FILE_BYTES: u64 = 4 * 1024;

/// Whether an operator-supplied transport file contains confidential bytes.
/// Public certificate material still receives the regular-file and size
/// checks, while secrets additionally receive Unix ownership/mode checks.
#[derive(Clone, Copy)]
pub(super) enum TransportFileSensitivity {
    Public,
    Secret,
}

#[derive(Subcommand)]
pub enum SyncCmd {
    /// Copy everything this directory has that the remote lacks
    Push {
        /// Data directory, grpc:// node, or https:// Edge replica
        #[arg(long)]
        remote: String,
        /// Report what would be transferred without writing anything
        #[arg(long)]
        dry_run: bool,
        /// Base64url bearer token for a grpc:// or https:// remote. Prefer
        /// --token-file: a token passed here is visible in process listings
        #[arg(long)]
        token: Option<String>,
        /// File holding the bearer token for a grpc:// remote
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Additional PEM CA certificate for a grpcs:// remote; platform
        /// native roots remain trusted
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Hostname to verify the server certificate against, when it
        /// differs from the host in the URL
        #[arg(long)]
        tls_domain: Option<String>,
        /// Permit plaintext to a non-loopback remote for development
        #[arg(long)]
        allow_insecure_transport: bool,
        /// Source identity whose local-scoped pins should root content
        #[arg(long, default_value = "local")]
        node_id: String,
        /// Maximum content-walk work; 0 selects the safe local default
        #[arg(long, default_value_t = 1_000_000)]
        max_walk: usize,
    },
    /// Copy everything the remote has that this directory lacks
    Pull {
        /// Data directory or grpc:// node to copy from
        #[arg(long)]
        remote: String,
        /// Report what would be transferred without writing anything
        #[arg(long)]
        dry_run: bool,
        /// Base64url bearer token for a grpc:// or https:// remote. Prefer
        /// --token-file: a token passed here is visible in process listings
        #[arg(long)]
        token: Option<String>,
        /// File holding the bearer token for a grpc:// remote
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Additional PEM CA certificate for a grpcs:// remote; platform
        /// native roots remain trusted
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Hostname to verify the server certificate against, when it
        /// differs from the host in the URL
        #[arg(long)]
        tls_domain: Option<String>,
        /// Permit plaintext to a non-loopback remote for development
        #[arg(long)]
        allow_insecure_transport: bool,
        /// Source identity whose local-scoped pins should root content
        #[arg(long, default_value = "local")]
        node_id: String,
        /// Maximum content-walk work; 0 requests the server's safe cap
        #[arg(long, default_value_t = 1_000_000)]
        max_walk: usize,
    },
}

pub fn handle(control: Control, cmd: SyncCmd, fmt: Format) -> Result<()> {
    let (
        remote,
        dry_run,
        pushing,
        token,
        token_file,
        ca_cert,
        tls_domain,
        allow_insecure_transport,
        source_node_id,
        max_walk,
    ) = match cmd {
        SyncCmd::Push {
            remote,
            dry_run,
            token,
            token_file,
            ca_cert,
            tls_domain,
            allow_insecure_transport,
            node_id,
            max_walk,
        } => (
            remote,
            dry_run,
            true,
            token,
            token_file,
            ca_cert,
            tls_domain,
            allow_insecure_transport,
            node_id,
            max_walk,
        ),
        SyncCmd::Pull {
            remote,
            dry_run,
            token,
            token_file,
            ca_cert,
            tls_domain,
            allow_insecure_transport,
            node_id,
            max_walk,
        } => (
            remote,
            dry_run,
            false,
            token,
            token_file,
            ca_cert,
            tls_domain,
            allow_insecure_transport,
            node_id,
            max_walk,
        ),
    };

    let opts = SyncOptions {
        dry_run,
        source_node_id,
        max_walk,
    };

    let report = if dag_control::is_http_remote(&remote) {
        if !pushing {
            bail!(
                "{remote} is a push destination (ADR-007); pull from a data directory or grpc:// node"
            );
        }
        if ca_cert.is_some() || tls_domain.is_some() {
            bail!("--ca-cert/--tls-domain apply to grpcs:// remotes; https:// uses the platform TLS roots");
        }
        http_push(
            control,
            &remote,
            &opts,
            token,
            token_file,
            allow_insecure_transport,
        )?
    } else if RemoteNode::is_remote_url(&remote) {
        let connect = super::node::connect_options(
            token,
            token_file,
            ca_cert,
            tls_domain,
            allow_insecure_transport,
        )?;
        remote_transfer(control, &remote, pushing, &opts, connect)?
    } else {
        if token.is_some()
            || token_file.is_some()
            || ca_cert.is_some()
            || tls_domain.is_some()
            || allow_insecure_transport
        {
            bail!("--token/--token-file/--ca-cert/--tls-domain/--allow-insecure-transport only apply to a grpc:// or https:// remote");
        }
        directory_transfer(&control, &remote, pushing, &opts)?
    };

    let complete = report.is_complete();
    fmt.emit(&report, |r| render(r, pushing))?;

    // A partial transfer exits non-zero so a backup script notices. The
    // successful part is still on disk, and re-running retries the rest.
    if !complete {
        if let Some(truncation) = &report.truncation {
            bail!(
                "source graph walk stopped at {} CID(s) (limit {}, at least {} frontier item(s) remain); no destination heads were published; increase --max-walk or reduce the root set",
                truncation.visited,
                truncation.limit,
                truncation.remaining_frontier
            );
        }
        if report.failures.is_empty() && !report.divergent.is_empty() {
            bail!(
                "{} event(s) refused as divergent history (the destination already filed different events at those names)",
                report.divergent.len()
            );
        }
        if report.divergent.is_empty() {
            bail!(
                "{} of {} chunk(s) did not transfer",
                report.failures.len(),
                report.failures.len() + report.chunks_sent
            );
        }
        bail!(
            "{} chunk(s) failed to transfer; {} event(s) refused as divergent history",
            report.failures.len(),
            report.divergent.len()
        );
    }

    Ok(())
}

/// The ADR-002 path: both sides are directories on this machine.
fn directory_transfer(
    control: &Control,
    remote: &str,
    pushing: bool,
    opts: &SyncOptions,
) -> Result<SyncReport> {
    let remote_path = PathBuf::from(remote);

    // redb locks its database file to one handle, so the two directories must
    // genuinely differ. Comparing canonical paths catches `.` versus an
    // absolute path, and symlinks pointing at the same place.
    let local_path = control.path().to_path_buf();
    if same_directory(&local_path, &remote_path) {
        bail!(
            "{} and {} are the same data directory",
            local_path.display(),
            remote_path.display()
        );
    }

    // A pull creates the local side's counterpart if it does not exist; a push
    // to a directory that is not there is almost certainly a typo in a path,
    // and creating it silently would write a replica somewhere unintended.
    if pushing && !remote_path.exists() {
        bail!(
            "{} does not exist; create it first if you meant to replicate there",
            remote_path.display()
        );
    }

    let remote = Control::open(&remote_path)
        .with_context(|| format!("opening remote data directory {}", remote_path.display()))?;

    if pushing {
        sync::push(control, &remote, opts)
    } else {
        sync::pull(control, &remote, opts)
    }
    .with_context(|| {
        format!(
            "{} {}",
            if pushing {
                "pushing to"
            } else {
                "pulling from"
            },
            remote_path.display()
        )
    })
}

/// The ADR-007 path: the other side is an HTTP Edge replica.
fn http_push(
    control: Control,
    url: &str,
    opts: &SyncOptions,
    token: Option<String>,
    token_file: Option<PathBuf>,
    allow_insecure_transport: bool,
) -> Result<SyncReport> {
    let token = resolve_token(token, token_file)?
        .ok_or_else(|| anyhow::anyhow!("{url} requires --token, --token-file, or ${TOKEN_ENV}"))?;
    let dest = if allow_insecure_transport {
        HttpDestination::new_allowing_insecure_transport(url, token)?
    } else {
        HttpDestination::new(url, token)?
    };
    sync::replicate(&control, &dest, opts).with_context(|| format!("pushing to {url}"))
}

/// The ADR-005 path: the other side is a node behind a socket.
fn remote_transfer(
    control: Control,
    url: &str,
    pushing: bool,
    opts: &SyncOptions,
    connect: dag_net::ConnectOptions,
) -> Result<SyncReport> {
    let local = Arc::new(control);
    let runtime = tokio::runtime::Runtime::new()?;

    runtime
        .block_on(async {
            let remote = RemoteNode::connect_with(url, connect)
                .await
                .map_err(|e| ControlError::Remote(e.to_string()))?;
            if pushing {
                dag_net::sync::push(local.clone(), &remote, opts).await
            } else {
                dag_net::sync::pull(local.clone(), &remote, opts).await
            }
        })
        .with_context(|| {
            format!(
                "{} {}",
                if pushing {
                    "pushing to"
                } else {
                    "pulling from"
                },
                url
            )
        })
}

/// Token precedence: `--token`, then `--token-file`, then `$DAG_NODE_TOKEN`.
///
/// Absence is not an error — a loopback node may serve without one; the
/// server answers `Unauthenticated` if it disagrees.
pub fn resolve_token(token: Option<String>, token_file: Option<PathBuf>) -> Result<Option<String>> {
    if let Some(token) = token {
        return validate_resolved_token(token, "--token").map(Some);
    }
    if let Some(path) = token_file {
        let bytes = read_transport_file(
            &path,
            "token file",
            MAX_TOKEN_FILE_BYTES,
            TransportFileSensitivity::Secret,
        )?;
        let raw = std::str::from_utf8(&bytes)
            .with_context(|| format!("token file {} is not UTF-8", path.display()))?;
        // Accept the one line ending secret-file tools conventionally add, but
        // do not silently normalize spaces, multiple lines, or other bytes.
        let trimmed = raw
            .strip_suffix("\r\n")
            .or_else(|| raw.strip_suffix('\n'))
            .unwrap_or(raw);
        if trimmed.is_empty() {
            bail!("token file {} is empty", path.display());
        }
        return validate_resolved_token(trimmed.to_string(), "--token-file").map(Some);
    }
    std::env::var(TOKEN_ENV)
        .ok()
        .filter(|token| !token.is_empty())
        .map(|token| validate_resolved_token(token, TOKEN_ENV))
        .transpose()
}

fn validate_resolved_token(token: String, source: &str) -> Result<String> {
    dag_net::auth::validate_token(&token)
        .map_err(|reason| anyhow::anyhow!("bearer token from {source} is invalid: {reason}"))?;
    Ok(token)
}

/// Read an operator-selected transport input without trusting its advertised
/// size. The opened descriptor is required to be a regular file, and a second
/// bounded read catches growth after the metadata check.
pub(super) fn read_transport_file(
    path: &Path,
    description: &str,
    max_bytes: u64,
    sensitivity: TransportFileSensitivity,
) -> Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    if path_metadata.file_type().is_symlink() {
        bail!(
            "{description} {} must be a regular file, not a symbolic link",
            path.display()
        );
    }
    if !path_metadata.is_file() {
        bail!(
            "{description} {} must be a regular file, not a directory or special file",
            path.display()
        );
    }

    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{open, Mode, OFlags};

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| {
            format!(
                "opening {description} {} without following symbolic links",
                path.display()
            )
        })?;
        File::from(descriptor)
    };

    #[cfg(not(unix))]
    let mut file =
        File::open(path).with_context(|| format!("opening {description} {}", path.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting opened {description} {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "{description} {} must be a regular file, not a directory or special file",
            path.display()
        );
    }
    if matches!(sensitivity, TransportFileSensitivity::Secret) {
        validate_secret_file_security(path, description, &metadata)?;
    }
    if metadata.len() > max_bytes {
        bail!(
            "{description} {} is {} bytes; maximum is {max_bytes}",
            path.display(),
            metadata.len()
        );
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {description} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!(
            "{description} {} grew beyond the {max_bytes}-byte maximum while it was read",
            path.display()
        );
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_secret_file_security(
    path: &Path,
    description: &str,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o007 != 0 {
        bail!(
            "{description} {} grants world access (mode {mode:04o}); remove all world permissions",
            path.display()
        );
    }
    if mode & 0o020 != 0 {
        bail!(
            "{description} {} is group-writable (mode {mode:04o}); a credential must not be replaceable by its group",
            path.display()
        );
    }
    if mode & 0o050 != 0 {
        eprintln!(
            "warning: {description} {} grants group access (mode {mode:04o}); use 0600 unless a dedicated service group intentionally owns access",
            terminal_text(&path.display().to_string())
        );
    }

    let owner = metadata.uid();
    let effective_user = rustix::process::geteuid().as_raw();
    if owner != effective_user && owner != 0 {
        eprintln!(
            "warning: {description} {} is owned by uid {owner}, not the effective uid {effective_user} or root; verify the file's provisioning authority",
            terminal_text(&path.display().to_string())
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file_security(
    _path: &Path,
    _description: &str,
    _metadata: &std::fs::Metadata,
) -> Result<()> {
    // Windows ACL ownership and access checks require platform-specific policy.
    // The regular-file, no-preexisting-link and byte-budget checks still apply;
    // deployment tooling must restrict the file's ACL to the service identity.
    Ok(())
}

fn same_directory(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        // An uncreated remote cannot be the local directory, which exists.
        _ => a == b,
    }
}

fn render(r: &SyncReport, pushing: bool) -> String {
    use std::fmt::Write;

    let direction = if pushing { "pushed" } else { "pulled" };
    let mut s = if r.dry_run {
        format!(
            "would transfer {} chunk(s), {}",
            r.chunks_sent,
            bytes(r.bytes_sent)
        )
    } else {
        format!(
            "{} {} chunk(s), {}",
            direction,
            r.chunks_sent,
            bytes(r.bytes_sent)
        )
    };

    let _ = write!(&mut s, "\nalready present  {}", r.chunks_skipped);

    if !r.dry_run {
        let _ = write!(
            &mut s,
            "\npointer events   {}\npin events       {}\
             \npointers         {} rebuilt\npins             {} rebuilt\
             \nsignatures       {} indexed\neffect claims    {} indexed",
            r.pointer_events,
            r.pin_events,
            r.pointers_rebuilt,
            r.pins_rebuilt,
            r.signatures_indexed,
            r.claims_indexed
        );
    }

    if !r.missing_at_source.is_empty() {
        let _ = write!(
            &mut s,
            "\nabsent at source {} (history names collected bytes; the log \
             still transferred whole)",
            r.missing_at_source.len()
        );
    }

    if let Some(truncation) = &r.truncation {
        let _ = write!(
            &mut s,
            "\nwalk truncated   {} visited at limit {}; at least {} frontier item(s) remain",
            truncation.visited, truncation.limit, truncation.remaining_frontier
        );
    }

    if r.publication_blocked {
        let _ = write!(
            &mut s,
            "\npublication      blocked (event-derived heads and indexes unchanged)"
        );
    }

    if !r.divergent.is_empty() {
        let _ = write!(
            &mut s,
            "\n\n{} divergent event(s) (destination already filed a different CID):",
            r.divergent.len()
        );
        for f in r.divergent.iter().take(10) {
            let _ = write!(
                &mut s,
                "\n  {}  {}",
                crate::output::short_cid(&f.cid),
                terminal_text(&f.reason)
            );
        }
        if r.divergent.len() > 10 {
            let _ = write!(&mut s, "\n  … and {} more", r.divergent.len() - 10);
        }
        let _ = write!(
            &mut s,
            "\n\nthat is a refuse, not a retry — a new seed is a new log \
             (event `ts` changes the CID). Content that arrived is already \
             safe; public resolve is unchanged."
        );
    }

    if !r.failures.is_empty() {
        let _ = write!(&mut s, "\n\n{} failure(s):", r.failures.len());
        for f in r.failures.iter().take(10) {
            let _ = write!(
                &mut s,
                "\n  {}  {}",
                crate::output::short_cid(&f.cid),
                terminal_text(&f.reason)
            );
        }
        if r.failures.len() > 10 {
            let _ = write!(&mut s, "\n  … and {} more", r.failures.len() - 10);
        }
        let _ = write!(&mut s, "\n\nre-run to retry; what arrived is already safe");
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_secret(path: &Path, bytes: impl AsRef<[u8]>) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn direct_client_tokens_are_validated_without_echoing_the_secret() {
        let secret =
            "overlong-sensitive-token-".to_string() + &"x".repeat(dag_net::auth::MAX_TOKEN_BYTES);
        let error = resolve_token(Some(secret.clone()), None).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("32 to 256 bytes"));
        assert!(!rendered.contains(&secret));

        let error = resolve_token(Some("too-short".into()), None).unwrap_err();
        assert!(format!("{error:#}").contains("32 to 256 bytes"));

        for malformed in [
            format!("{}!", "x".repeat(32)),
            format!("{}\u{7f}", "x".repeat(32)),
            format!("{}é", "x".repeat(32)),
        ] {
            let error = resolve_token(Some(malformed.clone()), None).unwrap_err();
            let rendered = format!("{error:#}");
            assert!(rendered.contains("base64url"), "{rendered}");
            assert!(!rendered.contains(&malformed));
        }
    }

    #[test]
    fn token_file_allows_one_trailing_newline_but_rejects_internal_whitespace() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        let token = "valid-client-token-0123456789abcdef";
        write_secret(&path, format!("{token}\n"));
        assert_eq!(
            resolve_token(None, Some(path.clone())).unwrap().as_deref(),
            Some(token)
        );

        write_secret(&path, "invalid client token 0123456789abcdef");
        let error = resolve_token(None, Some(path.clone())).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("base64url"));
        assert!(!rendered.contains("invalid client token"));

        write_secret(&path, format!("{token}\n\n"));
        let error = resolve_token(None, Some(path)).unwrap_err();
        assert!(format!("{error:#}").contains("base64url"));
    }

    #[test]
    fn token_file_read_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        write_secret(&path, vec![b's'; MAX_TOKEN_FILE_BYTES as usize + 1]);

        let error = resolve_token(None, Some(path)).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("maximum is 4096"), "{rendered}");
        assert!(!rendered.contains(&"s".repeat(64)));
    }
}
