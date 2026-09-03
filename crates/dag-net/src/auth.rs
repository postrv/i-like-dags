//! Scoped, rotation-friendly bearer authentication for the node port.
//!
//! Servers retain only SHA-256 token digests. A credential set may contain a
//! current credential and a previous credential so operators can roll clients
//! without a flag day. Each credential carries only the protocol scopes it
//! needs; `admin` is an explicit wildcard used by the legacy single-token
//! compatibility route.

use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::error::NetError;

/// Shared state for the transport's unauthenticated setup deadline.
///
/// The raw socket cannot tell whether encrypted bytes are a valid HTTP/2
/// request. Tonic attaches this value to every request, and the interceptor
/// marks it complete only after the first request has passed authentication
/// and scope checks. Until then the connection keeps its short, non-resettable
/// setup deadline.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectionSetup {
    complete: Arc<AtomicBool>,
}

impl ConnectionSetup {
    pub(crate) fn complete(&self) {
        self.complete.store(true, Ordering::Release);
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }
}

/// Metadata key the token travels under.
pub const AUTHORIZATION: &str = "authorization";

/// Scheme prefix on the metadata value.
pub const BEARER: &str = "Bearer ";

/// Minimum UTF-8 byte length of a bearer token.
pub const MIN_TOKEN_BYTES: usize = 32;

/// Maximum UTF-8 byte length of a bearer token.
pub const MAX_TOKEN_BYTES: usize = 256;

/// Validate the portable representation accepted by server and native client.
///
/// Padding-free base64url is intentionally narrower than generic gRPC metadata:
/// the same credential can travel through JSON, environment variables, files,
/// shells and proxies without Unicode normalization or delimiter ambiguity.
pub fn validate_token(token: &str) -> Result<(), &'static str> {
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len()) {
        return Err("bearer token must be 32 to 256 bytes");
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("bearer token must use only base64url characters (A-Z, a-z, 0-9, _ and -)");
    }
    Ok(())
}

/// A least-privilege grant on the node protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthScope {
    /// Operational node information.
    Read,
    /// Replication source and destination calls.
    Sync,
    /// Pointer reads and compare-and-set updates.
    Pointer,
    /// Permit pointer mutations to enqueue locally configured job triggers.
    ///
    /// This is deliberately separate from [`Self::Pointer`]: a credential may
    /// be allowed to move a pointer without also being allowed to start the
    /// side effects attached to that pointer by the destination operator.
    Trigger,
    /// Event replay and streaming.
    Events,
    /// Explicit wildcard, principally for the legacy token route.
    Admin,
}

impl AuthScope {
    const fn bit(self) -> u8 {
        match self {
            Self::Read => 1 << 0,
            Self::Sync => 1 << 1,
            Self::Pointer => 1 << 2,
            Self::Trigger => 1 << 3,
            Self::Events => 1 << 4,
            Self::Admin => 1 << 5,
        }
    }
}

impl fmt::Display for AuthScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Sync => "sync",
            Self::Pointer => "pointer",
            Self::Trigger => "trigger",
            Self::Events => "events",
            Self::Admin => "admin",
        })
    }
}

impl FromStr for AuthScope {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "sync" => Ok(Self::Sync),
            "pointer" => Ok(Self::Pointer),
            "trigger" => Ok(Self::Trigger),
            "events" => Ok(Self::Events),
            "admin" => Ok(Self::Admin),
            _ => Err("expected read, sync, pointer, trigger, events, or admin"),
        }
    }
}

/// Scopes carried from authentication into the typed RPC request.
///
/// Service interceptors enforce the coarse service scope. Methods that can
/// cross another authority boundary use this extension for their conditional
/// check; notably, a pointer mutation needs `trigger` only when its atomic
/// transaction would enqueue locally configured work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantedScopes(u8);

impl GrantedScopes {
    fn loopback_without_credentials() -> Self {
        // An unauthenticated listener is permitted only on loopback. Preserve
        // the historical local-call behavior by treating that trusted local
        // transport as the legacy all-scopes compatibility route.
        Self(AuthScope::Admin.bit())
    }

    pub(crate) fn grants(self, required: AuthScope) -> bool {
        self.0 & (required.bit() | AuthScope::Admin.bit()) != 0
    }
}

/// One server-side credential. The plaintext token is hashed on construction
/// and is never retained or exposed through `Debug`.
#[derive(Clone)]
pub struct ServerCredential {
    digest: [u8; 32],
    scopes: u8,
}

impl ServerCredential {
    /// Hash `token` and grant it exactly `scopes`.
    pub fn new(
        token: impl AsRef<str>,
        scopes: impl IntoIterator<Item = AuthScope>,
    ) -> Result<Self, NetError> {
        let token = token.as_ref();
        if let Err(reason) = validate_token(token) {
            return Err(NetError::InvalidAuthConfig {
                reason: reason.into(),
            });
        }

        let scopes = scopes.into_iter().fold(0, |bits, scope| bits | scope.bit());
        if scopes == 0 {
            return Err(NetError::InvalidAuthConfig {
                reason: "credential has no scopes".into(),
            });
        }

        Ok(Self {
            digest: digest(token.as_bytes()),
            scopes,
        })
    }
}

impl fmt::Debug for ServerCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerCredential")
            .field("token", &"[redacted]")
            .field("scopes", &ScopeDebug(self.scopes))
            .finish()
    }
}

struct ScopeDebug(u8);

impl fmt::Debug for ScopeDebug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for scope in [
            AuthScope::Read,
            AuthScope::Sync,
            AuthScope::Pointer,
            AuthScope::Trigger,
            AuthScope::Events,
            AuthScope::Admin,
        ] {
            if self.0 & scope.bit() != 0 {
                list.entry(&scope);
            }
        }
        list.finish()
    }
}

/// Active server credentials. During a rotation both current and previous
/// are accepted; remove `previous` after all clients have moved.
#[derive(Clone, Default)]
pub struct CredentialSet {
    current: Option<ServerCredential>,
    previous: Option<ServerCredential>,
}

impl CredentialSet {
    /// No authentication. Only loopback servers may use this set.
    pub const fn none() -> Self {
        Self {
            current: None,
            previous: None,
        }
    }

    /// A current credential, and optionally the immediately previous one.
    pub fn rotating(current: ServerCredential, previous: Option<ServerCredential>) -> Self {
        Self {
            current: Some(current),
            previous,
        }
    }

    /// Compatibility for the historical single token. This is deliberately
    /// explicit: it grants `admin`, cannot overlap a rotation, and should be
    /// replaced with [`Self::rotating`]. Transport policy is still enforced.
    pub fn legacy_admin(token: Option<&str>) -> Result<Self, NetError> {
        match token {
            Some(token) => Ok(Self::rotating(
                ServerCredential::new(token, [AuthScope::Admin])?,
                None,
            )),
            None => Ok(Self::none()),
        }
    }

    /// Whether no caller credential is required.
    pub fn is_empty(&self) -> bool {
        self.current.is_none()
    }
}

impl fmt::Debug for CredentialSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSet")
            .field("current", &self.current)
            .field("previous", &self.previous)
            .finish()
    }
}

/// Server-side check for one service scope.
///
/// Authentication compares fixed-size digests in constant time. Both current
/// and previous slots are always checked before deciding, so a request cannot
/// distinguish which side of a rotation accepted it through an early exit.
#[derive(Clone)]
pub(crate) struct RequireToken {
    credentials: CredentialSet,
    required: AuthScope,
}

impl RequireToken {
    pub(crate) fn new(credentials: CredentialSet, required: AuthScope) -> Self {
        Self {
            credentials,
            required,
        }
    }
}

impl Interceptor for RequireToken {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if self.credentials.is_empty() {
            mark_connection_setup_complete(&request);
            request
                .extensions_mut()
                .insert(GrantedScopes::loopback_without_credentials());
            return Ok(request);
        }

        let Some(offered) = request
            .metadata()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix(BEARER))
        else {
            return Err(authentication_failed());
        };
        let offered = digest(offered.as_bytes());

        let current_match = self
            .credentials
            .current
            .as_ref()
            .is_some_and(|credential| digests_match(&offered, &credential.digest));
        let previous_match = self
            .credentials
            .previous
            .as_ref()
            .is_some_and(|credential| digests_match(&offered, &credential.digest));

        // Always derive the effective grant after checking both rotation slots.
        // Direct library callers can construct duplicate digests even though
        // the CLI rejects them. In that ambiguous case use the intersection,
        // never the union: two disjoint least-privilege slots must not combine
        // into a more powerful credential. Masks avoid an early exit based on
        // which rotation slot matched.
        let current_mask = 0u8.wrapping_sub(current_match as u8);
        let previous_mask = 0u8.wrapping_sub(previous_match as u8);
        let current_scopes = self
            .credentials
            .current
            .as_ref()
            .map_or(0, |credential| credential.scopes)
            & current_mask;
        let previous_scopes = self
            .credentials
            .previous
            .as_ref()
            .map_or(0, |credential| credential.scopes)
            & previous_mask;
        let both_mask = current_mask & previous_mask;
        let union = current_scopes | previous_scopes;
        let intersection = current_scopes & previous_scopes;
        let granted = (union & !both_mask) | (intersection & both_mask);

        let authenticated = current_match | previous_match;
        let authorized = GrantedScopes(granted).grants(self.required);
        if !authenticated {
            Err(authentication_failed())
        } else if !authorized {
            Err(Status::permission_denied("permission denied"))
        } else {
            mark_connection_setup_complete(&request);
            request.extensions_mut().insert(GrantedScopes(granted));
            Ok(request)
        }
    }
}

fn mark_connection_setup_complete(request: &Request<()>) {
    if let Some(setup) = request.extensions().get::<ConnectionSetup>() {
        setup.complete();
    }
}

fn authentication_failed() -> Status {
    // Missing, malformed and incorrect credentials are intentionally
    // indistinguishable to callers.
    Status::unauthenticated("authentication failed")
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Constant-time comparison of two fixed-size digests.
fn digests_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_TOKEN: &str = "current-token-0123456789abcdef0123456789";
    const PREVIOUS_TOKEN: &str = "previous-token-0123456789abcdef01234567";
    const READ_TOKEN: &str = "read-only-token-0123456789abcdef01234567";
    const RIGHT_TOKEN: &str = "right-token-0123456789abcdef0123456789ab";
    const LEGACY_TOKEN: &str = "legacy-token-0123456789abcdef0123456789a";
    const REDACTED_TOKEN: &str = "do-not-log-me-0123456789abcdef0123456789";

    fn request_with(value: Option<&str>) -> Request<()> {
        let mut req = Request::new(());
        if let Some(value) = value {
            req.metadata_mut()
                .insert(AUTHORIZATION, value.parse().unwrap());
        }
        req
    }

    fn credential(token: &str, scopes: &[AuthScope]) -> ServerCredential {
        ServerCredential::new(token, scopes.iter().copied()).unwrap()
    }

    fn request_with_setup(value: Option<&str>) -> (Request<()>, ConnectionSetup) {
        let setup = ConnectionSetup::default();
        let mut request = request_with(value);
        request.extensions_mut().insert(setup.clone());
        (request, setup)
    }

    #[test]
    fn no_credentials_admit_loopback_calls() {
        let mut auth = RequireToken::new(CredentialSet::none(), AuthScope::Sync);
        for request in [request_with(None), request_with(Some("Bearer anything"))] {
            let admitted = auth.call(request).unwrap();
            let scopes = *admitted.extensions().get::<GrantedScopes>().unwrap();
            assert!(scopes.grants(AuthScope::Pointer));
            assert!(scopes.grants(AuthScope::Trigger));
        }
    }

    #[test]
    fn setup_deadline_is_disarmed_only_after_authorization() {
        let credentials =
            CredentialSet::rotating(credential(RIGHT_TOKEN, &[AuthScope::Read]), None);
        let mut auth = RequireToken::new(credentials, AuthScope::Read);

        let (wrong, wrong_setup) = request_with_setup(Some("Bearer wrong"));
        assert!(auth.call(wrong).is_err());
        assert!(!wrong_setup.is_complete());

        let (right, right_setup) = request_with_setup(Some(concat!(
            "Bearer ",
            "right-token-0123456789abcdef0123456789ab"
        )));
        assert!(auth.call(right).is_ok());
        assert!(right_setup.is_complete());
    }

    #[test]
    fn current_and_previous_credentials_work_during_rotation() {
        let credentials = CredentialSet::rotating(
            credential(CURRENT_TOKEN, &[AuthScope::Sync]),
            Some(credential(PREVIOUS_TOKEN, &[AuthScope::Sync])),
        );
        let mut auth = RequireToken::new(credentials, AuthScope::Sync);

        assert!(auth
            .call(request_with(Some(concat!(
                "Bearer ",
                "current-token-0123456789abcdef0123456789"
            ))))
            .is_ok());
        assert!(auth
            .call(request_with(Some(concat!(
                "Bearer ",
                "previous-token-0123456789abcdef01234567"
            ))))
            .is_ok());
    }

    #[test]
    fn a_valid_token_without_the_service_scope_is_denied() {
        let credentials = CredentialSet::rotating(credential(READ_TOKEN, &[AuthScope::Read]), None);
        let mut auth = RequireToken::new(credentials, AuthScope::Sync);

        let err = auth
            .call(request_with(Some(concat!(
                "Bearer ",
                "read-only-token-0123456789abcdef01234567"
            ))))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(err.message(), "permission denied");
    }

    #[test]
    fn missing_malformed_and_wrong_tokens_share_one_response() {
        let credentials =
            CredentialSet::rotating(credential(RIGHT_TOKEN, &[AuthScope::Read]), None);
        let mut auth = RequireToken::new(credentials, AuthScope::Read);

        for wrong in [
            None,
            Some("Bearer wrong"),
            Some(concat!(
                "Bearer ",
                "right-token-0123456789abcdef0123456789ab "
            )),
            Some(RIGHT_TOKEN),
            Some(concat!(
                "bearer ",
                "right-token-0123456789abcdef0123456789ab"
            )),
            Some("Bearer"),
        ] {
            let err = auth.call(request_with(wrong)).unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated, "{wrong:?}");
            assert_eq!(err.message(), "authentication failed", "{wrong:?}");
        }
    }

    #[test]
    fn admin_is_an_explicit_wildcard() {
        let credentials = CredentialSet::legacy_admin(Some(LEGACY_TOKEN)).unwrap();
        for required in [
            AuthScope::Read,
            AuthScope::Sync,
            AuthScope::Pointer,
            AuthScope::Trigger,
            AuthScope::Events,
            AuthScope::Admin,
        ] {
            let mut auth = RequireToken::new(credentials.clone(), required);
            assert!(auth
                .call(request_with(Some(concat!(
                    "Bearer ",
                    "legacy-token-0123456789abcdef0123456789a"
                ))))
                .is_ok());
        }
    }

    #[test]
    fn admitted_request_carries_the_matching_credentials_exact_scopes() {
        let credentials = CredentialSet::rotating(
            credential(RIGHT_TOKEN, &[AuthScope::Pointer, AuthScope::Trigger]),
            None,
        );
        let mut auth = RequireToken::new(credentials, AuthScope::Pointer);
        let admitted = auth
            .call(request_with(Some(concat!(
                "Bearer ",
                "right-token-0123456789abcdef0123456789ab"
            ))))
            .unwrap();
        let scopes = *admitted.extensions().get::<GrantedScopes>().unwrap();
        assert!(scopes.grants(AuthScope::Pointer));
        assert!(scopes.grants(AuthScope::Trigger));
        assert!(!scopes.grants(AuthScope::Sync));
        assert!(!scopes.grants(AuthScope::Admin));
    }

    #[test]
    fn duplicate_rotation_digest_intersects_instead_of_unioning_scopes() {
        let credentials = CredentialSet::rotating(
            credential(RIGHT_TOKEN, &[AuthScope::Read, AuthScope::Pointer]),
            Some(credential(
                RIGHT_TOKEN,
                &[AuthScope::Read, AuthScope::Trigger],
            )),
        );
        let offered = Some(concat!(
            "Bearer ",
            "right-token-0123456789abcdef0123456789ab"
        ));

        let mut read_auth = RequireToken::new(credentials.clone(), AuthScope::Read);
        let admitted = read_auth.call(request_with(offered)).unwrap();
        let scopes = *admitted.extensions().get::<GrantedScopes>().unwrap();
        assert!(scopes.grants(AuthScope::Read));
        assert!(!scopes.grants(AuthScope::Pointer));
        assert!(!scopes.grants(AuthScope::Trigger));

        let mut pointer_auth = RequireToken::new(credentials, AuthScope::Pointer);
        let error = pointer_auth.call(request_with(offered)).unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(error.message(), "permission denied");
    }

    #[test]
    fn debug_output_never_contains_the_token_or_digest() {
        let credentials = CredentialSet::rotating(
            credential(REDACTED_TOKEN, &[AuthScope::Read, AuthScope::Events]),
            None,
        );
        let debug = format!("{credentials:?}");
        assert!(!debug.contains(REDACTED_TOKEN));
        assert!(debug.contains("redacted"));
        assert!(debug.contains("Read"));
    }

    #[test]
    fn digest_comparison_is_exact() {
        let a = digest(b"one");
        let b = digest(b"two");
        assert!(digests_match(&a, &a));
        assert!(!digests_match(&a, &b));
    }

    #[test]
    fn token_policy_enforces_byte_boundaries_and_base64url_without_echoing_secrets() {
        assert!(ServerCredential::new("x".repeat(32), [AuthScope::Read]).is_ok());
        assert!(ServerCredential::new("x".repeat(256), [AuthScope::Read]).is_ok());
        assert!(
            ServerCredential::new("Az09_-Az09_-Az09_-Az09_-Az09_-12", [AuthScope::Read]).is_ok()
        );

        for invalid in [
            "x".repeat(31),
            "x".repeat(257),
            format!("{} {}", "x".repeat(16), "y".repeat(16)),
            format!("{}\n{}", "x".repeat(16), "y".repeat(16)),
            format!("{}!", "x".repeat(32)),
            format!("{}\u{7f}", "x".repeat(32)),
            format!("{}é", "x".repeat(32)),
        ] {
            let error = ServerCredential::new(&invalid, [AuthScope::Read]).unwrap_err();
            let rendered = error.to_string();
            assert!(!rendered.contains(&invalid));
            assert!(rendered.contains("32 to 256") || rendered.contains("base64url"));
        }
    }
}
