//! `dag serve` — the HTTP API and web console.
//!
//! `dag content serve` — the read-only content plane (ADR-006).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Subcommand;
use dag_control::Control;

/// `dag content` subcommands.
#[derive(Subcommand, Debug)]
pub enum ContentCmd {
    /// Serve the read-only content plane — GET-by-CID, no writes, no console
    Serve {
        /// Address to listen on. A public bind is the point of this command.
        #[arg(long, default_value = "127.0.0.1:8081")]
        addr: String,
        /// Let pages on this origin read the plane (repeatable). `*` is refused.
        #[arg(long = "allow-origin", value_name = "ORIGIN")]
        allow_origin: Vec<String>,
        /// Aggregate HTTP connection ceiling
        #[arg(long, default_value_t = 256)]
        max_connections: usize,
        /// HTTP connection ceiling attributed to one direct peer IP
        #[arg(long, default_value_t = 32)]
        max_connections_per_source: usize,
    },
}

/// Dispatch `dag content …`.
pub async fn handle_content_cmd(control: Control, cmd: ContentCmd) -> Result<()> {
    match cmd {
        ContentCmd::Serve {
            addr,
            allow_origin,
            max_connections,
            max_connections_per_source,
        } => {
            handle_content(
                control,
                &addr,
                &allow_origin,
                max_connections,
                max_connections_per_source,
            )
            .await
        }
    }
}

/// Start the console on `addr`, taking ownership of the already-open control
/// plane. Ownership matters: redb locks the database file, so the server must
/// reuse this `Control` rather than opening a second one.
///
/// `allow_origin` is empty for every ordinary run. The console is served from
/// the same origin as the API, so it needs no grant, and this server has no
/// authentication — an origin named here can do everything the console can.
///
/// A non-loopback bind without `expose_control` is refused before the
/// listener is created (ADR-006).
pub async fn handle(
    control: Control,
    addr: &str,
    allow_origin: &[String],
    expose_control: bool,
    max_connections: usize,
    max_connections_per_source: usize,
) -> Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid listen address {:?}", addr))?;

    // Validated before the listener binds, so a typo is a startup error rather
    // than a silently narrower policy than the operator asked for.
    let mut options =
        dag_api::ServerOptions::allow_origins(allow_origin).context("invalid --allow-origin")?;
    if expose_control {
        options = options.expose_control();
    }
    options = options
        .with_connection_limits(max_connections, max_connections_per_source)
        .context("invalid HTTP connection limits")?;

    dag_api::serve_with(Arc::new(control), addr, options).await
}

/// Start the read-only content plane. It exposes no mutation routes; TLS and
/// distributed rate controls still belong at the deployment proxy.
pub async fn handle_content(
    control: Control,
    addr: &str,
    allow_origin: &[String],
    max_connections: usize,
    max_connections_per_source: usize,
) -> Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid listen address {:?}", addr))?;
    let options = dag_api::ServerOptions::allow_origins(allow_origin)
        .context("invalid --allow-origin")?
        .with_connection_limits(max_connections, max_connections_per_source)
        .context("invalid HTTP connection limits")?;
    dag_api::serve_content(Arc::new(control), addr, options).await
}
