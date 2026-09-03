//! What the node protocol can fail with, on either side of the wire.

use std::net::SocketAddr;
use thiserror::Error;

/// Everything `dag-net` can fail with.
///
/// Server-side setup failures ([`NetError::CredentialsRequired`],
/// [`NetError::InsecureTransportRefused`], [`NetError::Io`])
/// happen before a socket accepts anything; client-side failures divide into
/// "could not reach the node" ([`NetError::Transport`]) and "the node said
/// no" ([`NetError::Status`]), which callers report differently — the first
/// is an availability problem, the second carries the server's own reason.
#[derive(Debug, Error)]
pub enum NetError {
    /// A non-loopback bind was requested with no credentials configured.
    ///
    /// Refused outright rather than warned about: the node protocol can file
    /// history and write chunks, so serving it unauthenticated beyond the
    /// local machine is not a posture an operator should be able to reach by
    /// accident.
    #[error(
        "refusing to serve the node protocol on non-loopback {addr} without \
         credentials; pass --auth-file, or bind 127.0.0.1"
    )]
    CredentialsRequired { addr: SocketAddr },

    /// A plaintext server or client was aimed beyond loopback without the
    /// deliberately noisy development override.
    #[error(
        "refusing plaintext transport for non-loopback {destination}; use TLS, or pass \
         --allow-insecure-transport only for an explicitly accepted development risk"
    )]
    InsecureTransportRefused { destination: String },

    /// Server credential configuration was malformed.
    #[error("invalid node authentication configuration: {reason}")]
    InvalidAuthConfig { reason: String },

    /// Server resource/admission configuration was malformed.
    #[error("invalid node server configuration: {reason}")]
    InvalidServerConfig { reason: String },

    /// A filesystem or socket operation failed, named by what was attempted.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// A remote URL that could not be understood.
    #[error("invalid remote URL {url:?}: {reason}")]
    BadUrl { url: String, reason: String },

    /// The channel to the remote failed — connection refused, reset, TLS
    /// handshake failure. The node was not reached.
    #[error("cannot reach node: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// The remote answered with a refusal. The message is the server's own.
    #[error("node refused: {}", .0.message())]
    Status(#[from] tonic::Status),
}

impl NetError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}
