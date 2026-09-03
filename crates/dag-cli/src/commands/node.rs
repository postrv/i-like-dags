//! `dag node` — the authenticated node port (ADR-005).
//!
//! `serve` is the counterpart of `dag serve` for *other nodes* rather than
//! humans: gRPC, scoped rotating bearer credentials, TLS, and a hard refusal
//! to bind plaintext or unauthenticated beyond loopback by default. `info` is
//! the operational ping.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use dag_control::{Control, ControlError};
use dag_net::{
    AuthScope, ConnectOptions, ConnectionLimits, CredentialSet, RemoteNode, ServeOptions,
    ServerCredential, TlsIdentity,
};
use serde::{Deserialize, Serialize};

use crate::output::{terminal_text, Format};

const MAX_AUTH_FILE_BYTES: u64 = 64 * 1024;
const MAX_CA_CERT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TLS_CERT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TLS_KEY_BYTES: u64 = 256 * 1024;

#[derive(Subcommand)]
pub enum NodeCmd {
    /// Serve the node protocol (gRPC) for replication, pointer updates and
    /// event streaming
    Serve {
        /// Address to listen on. Non-loopback requires TLS and credentials
        #[arg(long, default_value = "127.0.0.1:7411")]
        listen: String,
        /// Legacy all-scopes base64url bearer token. Prefer --auth-file; a
        /// value passed here is visible in process listings
        #[arg(long, conflicts_with = "auth_file")]
        token: Option<String>,
        /// Legacy all-scopes base64url bearer-token file. Prefer --auth-file
        #[arg(long, conflicts_with = "auth_file")]
        token_file: Option<PathBuf>,
        /// JSON file containing scoped current and optional previous credentials.
        /// Add `trigger` to authorize pointer-driven local jobs
        #[arg(long, conflicts_with_all = ["token", "token_file"])]
        auth_file: Option<PathBuf>,
        /// PEM certificate chain; with --tls-key, the port serves TLS
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for --tls-cert
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Permit a plaintext non-loopback listener for remote development
        #[arg(long)]
        allow_insecure_transport: bool,
        /// Aggregate node-port TCP connection ceiling
        #[arg(long, default_value_t = 128)]
        max_connections: usize,
        /// TCP connection ceiling attributed to one peer IP. Raise this when
        /// a trusted L4 proxy intentionally represents many clients
        #[arg(long, default_value_t = 16)]
        max_connections_per_source: usize,
        /// Allow the background worker to run command-backed jobs. Disabled
        /// by default; this grants local process-execution capability. Remote
        /// pointer-driven runs also require that credential's `trigger` scope
        #[arg(long)]
        allow_exec_jobs: bool,
    },
    /// Ask a remote node for its version, schema and store shape
    Info {
        /// Node URL (grpc://host:port, or grpcs:// for TLS)
        #[arg(long)]
        remote: String,
        /// Base64url bearer token for the remote node
        #[arg(long)]
        token: Option<String>,
        /// File holding the bearer token
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
        /// Permit grpc:// to a non-loopback host for remote development
        #[arg(long)]
        allow_insecure_transport: bool,
    },
}

/// Build client connect options from the CLI's remote flags.
pub fn connect_options(
    token: Option<String>,
    token_file: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    tls_domain: Option<String>,
    allow_insecure_transport: bool,
) -> Result<ConnectOptions> {
    let ca_cert_pem = match ca_cert {
        Some(path) => Some(super::sync::read_transport_file(
            &path,
            "CA certificate",
            MAX_CA_CERT_BYTES,
            super::sync::TransportFileSensitivity::Public,
        )?),
        None => None,
    };
    Ok(ConnectOptions {
        token: super::sync::resolve_token(token, token_file)?,
        ca_cert_pem,
        tls_domain,
        allow_insecure_transport,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthFile {
    current: AuthFileCredential,
    #[serde(default)]
    previous: Option<AuthFileCredential>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthFileCredential {
    token: String,
    scopes: Vec<AuthScope>,
}

fn server_credentials(
    token: Option<String>,
    token_file: Option<PathBuf>,
    auth_file: Option<PathBuf>,
) -> Result<CredentialSet> {
    if let Some(path) = auth_file {
        let bytes = super::sync::read_transport_file(
            &path,
            "node auth file",
            MAX_AUTH_FILE_BYTES,
            super::sync::TransportFileSensitivity::Secret,
        )?;
        let file: AuthFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing node auth file {}", path.display()))?;
        if file
            .previous
            .as_ref()
            .is_some_and(|previous| previous.token == file.current.token)
        {
            bail!(
                "current and previous credentials in node auth file {} use the same token; rotation slots must be distinct",
                path.display()
            );
        }
        let current = credential_from_file(file.current, "current")?;
        let previous = file
            .previous
            .map(|credential| credential_from_file(credential, "previous"))
            .transpose()?;
        return Ok(CredentialSet::rotating(current, previous));
    }

    let token = super::sync::resolve_token(token, token_file)?;
    if token.is_some() {
        eprintln!(
            "warning: legacy --token/--token-file authentication grants every node scope, including trigger; \
             migrate to --auth-file for rotation and least privilege"
        );
    }
    Ok(CredentialSet::legacy_admin(token.as_deref())?)
}

fn credential_from_file(credential: AuthFileCredential, slot: &str) -> Result<ServerCredential> {
    ServerCredential::new(credential.token, credential.scopes)
        .with_context(|| format!("invalid {slot} credential in node auth file"))
}

/// Run the node port until interrupted. Takes ownership of the open control
/// plane, exactly like `dag serve` — redb locks the directory to one handle.
pub struct ServeCommandOptions {
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub auth_file: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub allow_insecure_transport: bool,
    pub max_connections: usize,
    pub max_connections_per_source: usize,
    pub allow_exec_jobs: bool,
}

pub fn serve(control: Control, listen: &str, options: ServeCommandOptions) -> Result<()> {
    let addr: std::net::SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid listen address {listen:?}"))?;

    let credentials = server_credentials(options.token, options.token_file, options.auth_file)?;
    let allow_exec_jobs = options.allow_exec_jobs;

    let tls = match (options.tls_cert, options.tls_key) {
        (Some(cert), Some(key)) => Some(TlsIdentity {
            cert_pem: super::sync::read_transport_file(
                &cert,
                "TLS certificate",
                MAX_TLS_CERT_BYTES,
                super::sync::TransportFileSensitivity::Public,
            )?,
            key_pem: super::sync::read_transport_file(
                &key,
                "TLS private key",
                MAX_TLS_KEY_BYTES,
                super::sync::TransportFileSensitivity::Secret,
            )?,
        }),
        // clap's `requires` guarantees the pair arrives whole.
        _ => None,
    };

    if credentials.is_empty() {
        // bind() refuses non-loopback outright; loopback without credentials is
        // legal but worth a line, same posture as `dag serve`.
        eprintln!("node port serving without credentials: loopback callers only");
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let control = Arc::new(control);
        // Binding also validates the listener's transport/auth posture, TLS
        // identity and connection limits. Keep the durable worker stopped —
        // and do not even construct its exec capability — until the node port
        // is known to be ready.
        let bound = dag_net::bind(
            Arc::clone(&control),
            addr,
            ServeOptions {
                credentials,
                tls,
                allow_insecure_transport: options.allow_insecure_transport,
                connection_limits: ConnectionLimits {
                    total: options.max_connections,
                    per_source: options.max_connections_per_source,
                },
            },
        )
        .await
        .map_err(|e| anyhow::Error::from(ControlError::Remote(e.to_string())))?;
        tracing::info!(addr = %bound.local_addr, "node protocol listening");

        let worker_capabilities = if allow_exec_jobs {
            dag_jobs::Capabilities::none().with_exec()
        } else {
            dag_jobs::Capabilities::none()
        };
        let (worker_stop, mut worker_stopped) = tokio::sync::watch::channel(false);
        let worker_control = Arc::clone(&control);
        let worker = tokio::spawn(async move {
            dag_jobs::run_worker_until(
                worker_control,
                dag_jobs::WorkerOptions::default(),
                worker_capabilities,
                async move {
                    while !*worker_stopped.borrow() {
                        if worker_stopped.changed().await.is_err() {
                            break;
                        }
                    }
                },
            )
            .await
        });

        let serving = bound.serve_until(async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => tracing::info!("shutdown signal received"),
                Err(error) => tracing::error!(%error, "failed to listen for shutdown signal"),
            }
        });
        let result = serving
            .await
            .map_err(|e| anyhow::Error::from(ControlError::Remote(e.to_string())));
        let _ = worker_stop.send(true);
        match worker.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "background job worker stopped"),
            Err(error) if error.is_cancelled() => {}
            Err(error) => tracing::error!(%error, "background job worker task failed"),
        }
        result
    })
}

/// What `dag node info` prints; mirrors the proto response in a serde shape.
#[derive(Serialize)]
struct InfoReport {
    remote: String,
    version: String,
    schema_version: u32,
    chunks: u64,
    bytes: u64,
    pointers: u64,
    pins: u64,
    recovered: bool,
}

/// Ping a remote node. Deliberately takes no `Control` — asking another node
/// how it is doing must not require (or lock) a local data directory.
pub fn info(
    remote: &str,
    token: Option<String>,
    token_file: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    tls_domain: Option<String>,
    allow_insecure_transport: bool,
    fmt: Format,
) -> Result<()> {
    let opts = connect_options(
        token,
        token_file,
        ca_cert,
        tls_domain,
        allow_insecure_transport,
    )?;
    let runtime = tokio::runtime::Runtime::new()?;
    let response = runtime.block_on(async {
        let node = RemoteNode::connect_with(remote, opts)
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))?;
        node.info()
            .await
            .map_err(|e| ControlError::Remote(e.to_string()))
    })?;

    let report = InfoReport {
        remote: remote.to_string(),
        version: response.version,
        schema_version: response.schema_version,
        chunks: response.chunks,
        bytes: response.bytes,
        pointers: response.pointers,
        pins: response.pins,
        recovered: response.recovered,
    };
    fmt.emit(&report, |r| {
        format!(
            "node       {}\nversion    {}\nschema     v{}\nchunks     {} ({})\
             \npointers   {}\npins       {}\nrecovered  {}",
            terminal_text(&r.remote),
            terminal_text(&r.version),
            r.schema_version,
            r.chunks,
            crate::output::bytes(r.bytes),
            r.pointers,
            r.pins,
            r.recovered
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use dag_core::{ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, TriggerPolicy};

    fn write_secret(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn auth_file_accepts_scoped_current_and_previous_without_exposing_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-auth.json");
        write_secret(
            &path,
            r#"{
                "current": {"token": "test-current-0000000000000000000000", "scopes": ["read", "sync", "pointer", "trigger"]},
                "previous": {"token": "test-previous-11111111111111111111", "scopes": ["read", "sync"]}
            }"#,
        );

        let credentials = server_credentials(None, None, Some(path)).unwrap();
        let debug = format!("{credentials:?}");
        assert!(debug.contains("Read"));
        assert!(debug.contains("Sync"));
        assert!(debug.contains("Pointer"));
        assert!(debug.contains("Trigger"));
        assert!(!debug.contains("test-current-0000000000000000000000"));
        assert!(!debug.contains("test-previous-11111111111111111111"));
    }

    #[test]
    fn auth_file_rejects_empty_scopes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-auth.json");
        write_secret(
            &path,
            r#"{"current":{"token":"test-empty-scope-22222222222222222","scopes":[]}}"#,
        );

        let error = match server_credentials(None, None, Some(path)) {
            Err(error) => error,
            Ok(_) => panic!("auth file with empty scopes was accepted"),
        };
        let rendered = format!("{error:#}");
        assert!(rendered.contains("no scopes"), "{rendered}");
        assert!(!rendered.contains("test-empty-scope-22222222222222222"));
    }

    #[test]
    fn auth_file_rejects_non_base64url_tokens_before_server_start() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-auth.json");
        for token in [
            format!("{}!", "x".repeat(32)),
            format!("{}\u{7f}", "x".repeat(32)),
            format!("{}é", "x".repeat(32)),
        ] {
            write_secret(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "current": {"token": token.clone(), "scopes": ["read"]}
                }))
                .unwrap(),
            );
            let error = server_credentials(None, None, Some(path.clone())).unwrap_err();
            let rendered = format!("{error:#}");
            assert!(rendered.contains("base64url"), "{rendered}");
            assert!(!rendered.contains(&token));
        }
    }

    #[test]
    fn auth_file_rejects_reusing_one_plaintext_token_across_rotation_slots() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-auth.json");
        let token = "test-duplicate-3333333333333333333";
        write_secret(
            &path,
            format!(
                r#"{{
                    "current": {{"token": "{token}", "scopes": ["read"]}},
                    "previous": {{"token": "{token}", "scopes": ["sync"]}}
                }}"#
            ),
        );

        let error = server_credentials(None, None, Some(path)).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("rotation slots must be distinct"));
        assert!(!rendered.contains(token));
    }

    #[test]
    fn auth_file_read_is_bounded_before_json_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-auth.json");
        write_secret(&path, vec![b'x'; MAX_AUTH_FILE_BYTES as usize + 1]);

        let error = server_credentials(None, None, Some(path)).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("maximum is 65536"), "{rendered}");
        assert!(!rendered.contains(&"x".repeat(64)));
    }

    #[cfg(unix)]
    #[test]
    fn transport_inputs_reject_symbolic_links_and_special_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("ca.pem");
        let link = directory.path().join("ca-link.pem");
        std::fs::write(&target, b"public certificate bytes").unwrap();
        symlink(&target, &link).unwrap();

        let link_error = super::super::sync::read_transport_file(
            &link,
            "CA certificate",
            MAX_CA_CERT_BYTES,
            super::super::sync::TransportFileSensitivity::Public,
        )
        .unwrap_err();
        assert!(format!("{link_error:#}").contains("not a symbolic link"));

        let special_error = super::super::sync::read_transport_file(
            std::path::Path::new("/dev/null"),
            "CA certificate",
            MAX_CA_CERT_BYTES,
            super::super::sync::TransportFileSensitivity::Public,
        )
        .unwrap_err();
        assert!(format!("{special_error:#}").contains("special file"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_reject_world_access_but_allow_service_group_read() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-auth.json");
        let body = r#"{"current":{"token":"mode-test-secret-0123456789abcdef","scopes":["read"]}}"#;
        write_secret(&path, body);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();
        let error = server_credentials(None, None, Some(path.clone())).unwrap_err();
        assert!(format!("{error:#}").contains("grants world access"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        server_credentials(None, None, Some(path)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_listener_leaves_trigger_run_and_exec_state_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("exec-marker");
        let control = Control::open(directory.path()).unwrap();
        let first = control.store.put_chunk(b"first", None).unwrap();
        let second = control.store.put_chunk(b"second", None).unwrap();
        control.pointer_log.create("release", first).unwrap();

        let job = JobSpec {
            job_id: JobId::from("must-not-run-without-listener"),
            placement: None,
            inputs: JobInput::new().with_pointer("release"),
            determinism: Determinism::SideEffecting,
            declared_outputs: vec!["stdout".to_string()],
            code_ref: "exec".to_string(),
            policy: JobPolicy {
                trigger: TriggerPolicy::OnPointerUpdate,
                ..JobPolicy::default()
            },
            config: Some(serde_json::json!({
                "command": "/bin/sh",
                "args": [
                    "-c",
                    "printf started > \"$1\"",
                    "dag-node-listener-test",
                    marker.to_string_lossy(),
                ],
                "capture_stdout": true,
            })),
        };
        control.create_job(job.clone()).unwrap();
        control
            .subscribe_pointer("release", job.job_id.clone())
            .unwrap();
        control.pointer_log.update("release", second).unwrap();
        assert_eq!(control.job_log.trigger_queue_depths().unwrap(), (1, 0));
        assert!(control.runs(job.job_id.clone(), 10).unwrap().is_empty());

        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = occupied.local_addr().unwrap().to_string();
        let error = serve(
            control,
            &listen,
            ServeCommandOptions {
                token: None,
                token_file: None,
                auth_file: None,
                tls_cert: None,
                tls_key: None,
                allow_insecure_transport: false,
                max_connections: 8,
                max_connections_per_source: 4,
                allow_exec_jobs: true,
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("binding"));
        drop(occupied);

        let reopened = Control::open(directory.path()).unwrap();
        assert_eq!(reopened.job_log.trigger_queue_depths().unwrap(), (1, 0));
        assert!(reopened.runs(job.job_id, 10).unwrap().is_empty());
        assert!(
            !marker.exists(),
            "exec adapter ran before listener readiness"
        );
    }
}
