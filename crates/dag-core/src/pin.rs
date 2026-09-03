//! Pin types for retention policies
//!
//! This module defines the core data structures for the pin system,
//! which provides retention policies to prevent garbage collection of
//! important content.

use crate::Cid;
use serde::{Deserialize, Serialize};

/// Unique identifier for a pin
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PinId(pub String);

impl std::fmt::Display for PinId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PinId {
    fn from(s: String) -> Self {
        PinId(s)
    }
}

impl AsRef<str> for PinId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Scope of a pin (global vs node-local)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinScope {
    /// Pin applies globally across all nodes
    Global,
    /// Pin applies only to a specific node
    Local { node_id: String },
}

/// Target of a pin (what content to retain)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinTarget {
    /// Pin a single CID directly
    Direct(Cid),
    /// Pin a CID and its subtree up to max_depth
    Subtree { root: Cid, max_depth: Option<u32> },
}

/// State of a pin (active or deactivated)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinState {
    /// Pin is active and providing retention
    Active,
    /// Pin has been deactivated and no longer provides retention
    Deactivated,
}

/// Event in the pin log representing a pin state change
///
/// **`importance` was removed in schema 2.** It was recorded on every pin and
/// consulted by nothing: retention is a union, so a pin either protects
/// content or does not, and no code path ever had two pins to choose between.
/// `pin create --importance` therefore implied a ranking the collector could
/// not act on, which is the same species of false promise as reporting content
/// intact when its chunks are gone. Ranking retention needs a quota mechanism
/// that would break pins under a size budget; if that is ever built, it should
/// reintroduce the field deliberately rather than inherit an inert one.
///
/// Events written under schema 1 still carry the key and still decode — serde
/// ignores it — which is why a version-1 directory opens without migration.
/// The reverse does not hold, and that is what the schema bump announces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinEvent {
    /// Sequence number for this pin (monotonic per pin_id)
    pub seq: u64,
    /// ID of the pin this event applies to
    pub pin_id: String,
    /// What content this pin targets
    pub target: PinTarget,
    /// Scope of retention (global vs local)
    pub scope: PinScope,
    /// Absolute expiry time (POSIX seconds), None = never expires
    pub expires_at: Option<i64>,
    /// Current state of the pin
    pub state: PinState,
    /// Timestamp when this event was created (POSIX seconds)
    pub ts: i64,
    /// Author of this pin event (optional)
    pub author: Option<String>,
    /// CID of the event entry at `seq - 1`; `None` on a create.
    ///
    /// This is the pin log's equivalent of [`crate::PointerEvent::prev`], and
    /// it exists for the same reason: without it, a replica importing pin
    /// events has nothing to check a later event *against*, so a hostile
    /// source could append a deactivation to somebody else's live pin. See
    /// `PinLog::import_event`.
    ///
    /// Skipped on the wire when absent, so every event written before this
    /// field existed encodes to exactly the bytes it always did — and keeps
    /// the CID it was stored, pinned and signed under (I1). There is a golden
    /// test below that will fail if that ever stops being true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Cid>,
}

impl PinEvent {
    /// Check if this pin event is expired at the given timestamp
    pub fn is_expired(&self, now: i64) -> bool {
        match self.expires_at {
            Some(expiry) => now >= expiry,
            None => false,
        }
    }

    /// Check if this pin event is providing active retention
    pub fn is_providing_retention(&self, now: i64) -> bool {
        matches!(self.state, PinState::Active) && !self.is_expired(now)
    }
}

/// Head information for a pin
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinHead {
    /// The latest pin event
    pub event: PinEvent,
    /// CID of the entry containing this event
    pub event_cid: Cid,
}

impl PinHead {
    /// Check if this pin is currently providing retention
    pub fn is_providing_retention(&self, now: i64) -> bool {
        self.event.is_providing_retention(now)
    }
}

/// Error types for pin operations
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("Invalid pin ID: {0}")]
    InvalidPinId(String),

    #[error("Pin not found: {0}")]
    PinNotFound(String),

    #[error("Pin already exists: {0}")]
    PinAlreadyExists(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid sequence: expected {expected}, got {actual}")]
    InvalidSequence { expected: u64, actual: u64 },

    #[error("Retention computation error: {0}")]
    RetentionComputation(String),
}

/// Validate a pin ID for safety and consistency
pub fn validate_pin_id(pin_id: &str) -> Result<(), PinError> {
    if pin_id.is_empty() {
        return Err(PinError::InvalidPinId("Pin ID cannot be empty".to_string()));
    }

    if pin_id.len() > 256 {
        return Err(PinError::InvalidPinId(
            "Pin ID cannot exceed 256 characters".to_string(),
        ));
    }

    if pin_id.contains('\0') {
        return Err(PinError::InvalidPinId(
            "Pin ID cannot contain NUL bytes".to_string(),
        ));
    }

    if let Err(reason) = crate::validate_identifier_text(pin_id) {
        return Err(PinError::InvalidPinId(reason.into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Entry;
    use sha2::{Digest as _, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn large_historical_pin_payload_is_frozen_for_edge_interop() {
        let event = PinEvent {
            seq: 1,
            pin_id: "edge-large-fixture".into(),
            target: PinTarget::Direct(Cid::from_bytes(&[0x07; 32]).unwrap()),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1_700_000_000,
            author: Some("x".repeat(5_000)),
            prev: None,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        // Edge's protocol-3 decoder consumes this exact Rust-generated golden
        // shape. Historical pin payloads may exceed the pointer log's 4 KiB
        // cap, while the enclosing immutable chunk still supplies the bound.
        assert_eq!(payload.len(), 5_137);
        assert_eq!(
            hex::encode(Sha256::digest(&payload)),
            "2f752304dd6459b1525394185803c477c6ebb7b945882f9d4362be2846b864fe"
        );
        assert_eq!(
            ciborium::de::from_reader::<PinEvent, _>(payload.as_slice()).unwrap(),
            event
        );
    }

    /// The same logical pin event the schema-1 golden below describes.
    fn golden_event() -> PinEvent {
        PinEvent {
            seq: 1,
            pin_id: "golden".to_string(),
            target: PinTarget::Direct(Cid::compute(b"golden target")),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1_700_000_000,
            author: Some("tester".to_string()),
            prev: None,
        }
    }

    /// A pin event as schema 1 wrote it, byte for byte — `importance` and
    /// all. Frozen: these are bytes that exist in directories in the field.
    const SCHEMA_1_PAYLOAD: &str = "a963736571016670696e5f696466676f6c64656e66746172676574a1664469726563749820\
07183f18a918ad189b15186f18e718731853181a184a18a4185118c90b186118bb188918ca18dd18b4182318ee18f6186118d7188f\
187a18f8188218516573636f706566476c6f62616c6a696d706f7274616e636518646a657870697265735f6174f6657374617465664\
163746976656274731a6553f10066617574686f7266746573746572";

    /// A pin event written by schema 1 still decodes here.
    ///
    /// This is the compatibility direction that has to hold: removing
    /// `importance` must not orphan a single event already on disk, which is
    /// why a version-1 directory opens without migration. serde ignores the
    /// key it no longer knows.
    #[test]
    fn a_schema_1_event_still_decodes() {
        let bytes = hex::decode(SCHEMA_1_PAYLOAD.replace(['\n', ' '], "")).unwrap();
        let decoded: PinEvent = ciborium::de::from_reader(bytes.as_slice())
            .expect("a pin event written by schema 1 no longer decodes");

        assert_eq!(
            decoded,
            golden_event(),
            "a field other than importance moved"
        );
    }

    /// And the current encoding is frozen in its turn.
    ///
    /// Pin events are content-addressed: their CIDs are what the event log
    /// files, what subtree pins protect and what signatures cover. Changing
    /// the encoding renames every event a build writes, so it may only ever
    /// happen deliberately and with a schema bump — as it did when
    /// `importance` was removed for schema 2. If this fails and you did not
    /// mean it, you have renamed events; if you did mean it, bump the schema.
    #[test]
    fn the_schema_2_encoding_is_frozen() {
        const GOLDEN_PAYLOAD: &str = "a863736571016670696e5f696466676f6c64656e66746172676574a1664469726563749820\
07183f18a918ad189b15186f18e718731853181a184a18a4185118c90b186118bb188918ca18dd18b4182318ee18f6186118d7188f\
187a18f8188218516573636f706566476c6f62616c6a657870697265735f6174f6657374617465664163746976656274731a6553f1\
0066617574686f7266746573746572";
        const GOLDEN_CID: &str = "080b650b20271bf01a3d0db10e98dd647b799d08074fe16957dfc872c2c719a1";

        let mut payload = Vec::new();
        ciborium::ser::into_writer(&golden_event(), &mut payload).unwrap();
        assert_eq!(
            hex::encode(&payload),
            GOLDEN_PAYLOAD.replace(['\n', ' '], ""),
            "the pin event encoding changed"
        );

        let entry = Entry::with_payload(payload);
        let cid = Cid::compute(&entry.to_bytes_cbor().unwrap());
        assert_eq!(cid.to_hex(), GOLDEN_CID, "a pin event was renamed");
    }

    /// The `prev` round trip, unchanged by the removal.
    #[test]
    fn an_event_encoded_without_prev_decodes_with_prev_none() {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&golden_event(), &mut payload).unwrap();

        let round_tripped: PinEvent = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(round_tripped.prev, None);
        assert_eq!(round_tripped, golden_event());
    }

    /// And a `prev` that is present survives the round trip.
    #[test]
    fn a_prev_is_carried_through_the_encoding() {
        let event = PinEvent {
            seq: 2,
            prev: Some(Cid::compute(b"the event at seq 1")),
            state: PinState::Deactivated,
            ..golden_event()
        };

        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let round_tripped: PinEvent = ciborium::de::from_reader(payload.as_slice()).unwrap();
        assert_eq!(round_tripped, event);
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn test_pin_id_validation() {
        // Valid IDs
        assert!(validate_pin_id("valid-pin").is_ok());
        assert!(validate_pin_id("pin.with.dots").is_ok());
        assert!(validate_pin_id("pin/with/slashes").is_ok());
        assert!(validate_pin_id("pin:with:colons").is_ok());
        assert!(validate_pin_id("pin with spaces").is_ok());
        assert!(validate_pin_id("模型/é/مرحبا").is_ok());

        // Invalid IDs
        assert!(validate_pin_id("").is_err());
        assert!(validate_pin_id("pin\0with\0nul").is_err());
        assert!(validate_pin_id("pin\nforged").is_err());
        assert!(validate_pin_id("pin\u{001b}[2J").is_err());
        assert!(validate_pin_id("pin\u{2067}txt\u{2069}").is_err());
        assert!(validate_pin_id(&"a".repeat(257)).is_err());
    }

    #[test]
    fn test_pin_event_expiry() {
        let current_time = now();

        // Never expires
        let never_expires = PinEvent {
            seq: 1,
            pin_id: "test".to_string(),
            target: PinTarget::Direct(Cid::compute(b"test")),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: current_time,
            author: None,
            prev: None,
        };

        assert!(!never_expires.is_expired(current_time));
        assert!(!never_expires.is_expired(current_time + 1000));
        assert!(never_expires.is_providing_retention(current_time));

        // Expires in future
        let expires_future = PinEvent {
            expires_at: Some(current_time + 3600), // 1 hour from now
            ..never_expires.clone()
        };

        assert!(!expires_future.is_expired(current_time));
        assert!(expires_future.is_providing_retention(current_time));
        assert!(expires_future.is_expired(current_time + 3601));
        assert!(!expires_future.is_providing_retention(current_time + 3601));

        // Already expired
        let expired = PinEvent {
            expires_at: Some(current_time - 1), // 1 second ago
            ..never_expires.clone()
        };

        assert!(expired.is_expired(current_time));
        assert!(!expired.is_providing_retention(current_time));

        // Deactivated but not expired
        let deactivated = PinEvent {
            state: PinState::Deactivated,
            ..never_expires.clone()
        };

        assert!(!deactivated.is_expired(current_time));
        assert!(!deactivated.is_providing_retention(current_time)); // Deactivated
    }

    #[test]
    fn test_pin_target_serialization() {
        let direct = PinTarget::Direct(Cid::compute(b"test"));
        let subtree = PinTarget::Subtree {
            root: Cid::compute(b"root"),
            max_depth: Some(5),
        };

        // Should serialize/deserialize to CBOR without errors
        let mut direct_cbor = Vec::new();
        ciborium::into_writer(&direct, &mut direct_cbor).unwrap();
        let direct_back: PinTarget = ciborium::from_reader(&direct_cbor[..]).unwrap();
        assert_eq!(direct, direct_back);

        let mut subtree_cbor = Vec::new();
        ciborium::into_writer(&subtree, &mut subtree_cbor).unwrap();
        let subtree_back: PinTarget = ciborium::from_reader(&subtree_cbor[..]).unwrap();
        assert_eq!(subtree, subtree_back);
    }
}
