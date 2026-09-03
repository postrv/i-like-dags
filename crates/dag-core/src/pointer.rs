use crate::Cid;
use serde::{Deserialize, Serialize};

/// Unique identifier for a mutable pointer
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PointerId(pub String);

impl PointerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PointerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PointerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PointerId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// An event in a pointer's append-only history
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerEvent {
    /// Sequence number for this pointer (monotonic, starts at 1)
    pub seq: u64,
    /// The pointer identifier this event belongs to
    pub pointer_id: String,
    /// Previous CID (None for create events)
    pub prev: Option<Cid>,
    /// New CID this pointer now points to
    pub new: Cid,
    /// Unix timestamp (seconds) when event was created
    pub ts: i64,
}

impl PointerEvent {
    pub fn create_event(pointer_id: impl Into<String>, initial_cid: Cid, timestamp: i64) -> Self {
        Self {
            seq: 1,
            pointer_id: pointer_id.into(),
            prev: None,
            new: initial_cid,
            ts: timestamp,
        }
    }

    pub fn update_event(
        pointer_id: impl Into<String>,
        seq: u64,
        prev_cid: Cid,
        new_cid: Cid,
        timestamp: i64,
    ) -> Self {
        Self {
            seq,
            pointer_id: pointer_id.into(),
            prev: Some(prev_cid),
            new: new_cid,
            ts: timestamp,
        }
    }

    pub fn is_create(&self) -> bool {
        self.seq == 1 && self.prev.is_none()
    }

    pub fn is_update(&self) -> bool {
        self.seq > 1 && self.prev.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Entry;

    #[test]
    fn test_pointer_id_creation() {
        let id1 = PointerId::new("test-pointer");
        let id2 = PointerId::from("test-pointer");
        let id3: PointerId = "test-pointer".into();

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(id1.as_str(), "test-pointer");
        assert_eq!(id1.to_string(), "test-pointer");
    }

    #[test]
    fn test_pointer_event_creation() {
        let cid1 = Cid::compute(b"initial content");
        let cid2 = Cid::compute(b"updated content");

        let create_event = PointerEvent::create_event("test-ptr", cid1.clone(), 1000);
        assert!(create_event.is_create());
        assert!(!create_event.is_update());
        assert_eq!(create_event.seq, 1);
        assert_eq!(create_event.prev, None);
        assert_eq!(create_event.new, cid1);
        assert_eq!(create_event.ts, 1000);

        let update_event =
            PointerEvent::update_event("test-ptr", 2, cid1.clone(), cid2.clone(), 2000);
        assert!(!update_event.is_create());
        assert!(update_event.is_update());
        assert_eq!(update_event.seq, 2);
        assert_eq!(update_event.prev, Some(cid1));
        assert_eq!(update_event.new, cid2);
        assert_eq!(update_event.ts, 2000);
    }

    #[test]
    fn test_pointer_event_serialization() {
        let cid = Cid::compute(b"test data");
        let event = PointerEvent::create_event("serialization-test", cid, 1234567890);

        // Test CBOR round-trip
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&event, &mut cbor_bytes).unwrap();

        let decoded: PointerEvent = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn pointer_entry_encoding_is_frozen_for_edge_interop() {
        const PAYLOAD_HEX: &str = "a563736571016a706f696e7465725f69646c656467652f666978747572656470726576f6636e6577982011111111111111111111111111111111111111111111111111111111111111116274731a6553f100";
        const ENTRY_HEX: &str = "a2677061796c6f6164985218a5186318731865187101186a1870186f1869186e187418651872185f18691864186c1865186418671865182f18661869187818741875187218651864187018721865187618f61863186e18651877189818201111111111111111111111111111111111111111111111111111111111111111186218741873181a1865185318f100656c696e6b7380";
        let target = Cid::from_bytes(&[0x11; 32]).unwrap();
        let event = PointerEvent::create_event("edge/fixture", target, 1_700_000_000);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let entry = Entry::with_payload(payload.clone())
            .to_bytes_cbor()
            .unwrap();
        assert_eq!(hex::encode(payload), PAYLOAD_HEX);
        assert_eq!(hex::encode(entry), ENTRY_HEX);
    }
}
