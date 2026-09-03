//! In-process replica log: the same offer rules as `PointerLog` /
//! `PinLog`, without redb.
//!
//! The Edge Worker (ADR-007) and the HTTP stand-in both file history
//! through this type. The durable map on Cloudflare is a Durable Object;
//! here it is a `BTreeMap`. The judgement is [`crate::offer`].

use std::collections::BTreeMap;
use std::sync::RwLock;

use crate::offer::{offer_pin_event, offer_pointer_event, OfferError, OfferOutcome};
use crate::{Cid, ContentStore, CoreError, Entry, PinEvent, PointerEvent, MAX_CHUNK_SIZE};

/// A replica that holds chunks in a [`ContentStore`] and event mappings
/// in process-local maps.
pub struct ReplicaLog<S: ContentStore> {
    store: S,
    pointer_events: RwLock<BTreeMap<(String, u64), Cid>>,
    pin_events: RwLock<BTreeMap<(String, u64), Cid>>,
    pointer_heads: RwLock<BTreeMap<String, (u64, Cid)>>,
    pin_heads: RwLock<BTreeMap<String, (u64, Cid)>>,
}

/// Why a replica operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaError {
    #[error(transparent)]
    Offer(#[from] OfferError),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(
        "pointer {id} is at seq {actual} (cid {actual_cid}), not {expected}; re-read and retry"
    )]
    CasConflict {
        id: String,
        expected: u64,
        actual: u64,
        actual_cid: String,
    },
    #[error("{0} not found")]
    NotFound(String),
    #[error("invalid log id: {0}")]
    InvalidId(String),
}

impl<S: ContentStore> ReplicaLog<S> {
    /// Wrap an existing store.
    pub fn new(store: S) -> Self {
        Self {
            store,
            pointer_events: RwLock::new(BTreeMap::new()),
            pin_events: RwLock::new(BTreeMap::new()),
            pointer_heads: RwLock::new(BTreeMap::new()),
            pin_heads: RwLock::new(BTreeMap::new()),
        }
    }

    /// The store this replica writes chunks into.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Store one chunk after re-hashing. A CID mismatch is refused.
    pub fn store_chunk(&self, cid: &Cid, bytes: &[u8]) -> Result<(), ReplicaError> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: bytes.len(),
                max_size: MAX_CHUNK_SIZE,
            }
            .into());
        }
        let computed = Cid::compute(bytes);
        if &computed != cid {
            return Err(CoreError::CidMismatch {
                expected: cid.clone(),
                computed,
            }
            .into());
        }
        self.store.put_chunk(bytes, None)?;
        Ok(())
    }

    /// CIDs from `cids` this replica does not hold (or holds as a torn
    /// zero-length object — see [`crate::traits::ContentStore::has_chunk`]).
    pub fn missing(&self, cids: &[Cid]) -> Result<Vec<Cid>, ReplicaError> {
        let mut out = Vec::new();
        for cid in cids {
            if !self.store.has_chunk(cid)? {
                out.push(cid.clone());
            }
        }
        Ok(out)
    }

    /// File a pointer event. `Ok(true)` means a new mapping was written.
    pub fn import_pointer(
        &self,
        id: &str,
        seq: u64,
        event_cid: &Cid,
    ) -> Result<bool, ReplicaError> {
        check_pointer_id(id)?;
        let entry = self.store.get_entry(event_cid)?;
        let event = decode_pointer(&entry.payload)?;
        let mut map = self
            .pointer_events
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let existing = map.get(&(id.to_string(), seq)).cloned();
        let predecessor = if seq > 1 {
            match map.get(&(id.to_string(), seq - 1)).cloned() {
                Some(prev_cid) => Some(decode_pointer(&self.store.get_entry(&prev_cid)?.payload)?),
                None => None,
            }
        } else {
            None
        };
        match offer_pointer_event(
            id,
            seq,
            event_cid,
            &event,
            existing.as_ref(),
            predecessor.as_ref(),
        )? {
            OfferOutcome::AlreadyFiled => Ok(false),
            OfferOutcome::Accept => {
                map.insert((id.to_string(), seq), event_cid.clone());
                Ok(true)
            }
        }
    }

    /// File a pin event. `Ok(true)` means a new mapping was written.
    pub fn import_pin(&self, id: &str, seq: u64, event_cid: &Cid) -> Result<bool, ReplicaError> {
        crate::validate_pin_id(id).map_err(|e| ReplicaError::InvalidId(e.to_string()))?;
        let entry = self.store.get_entry(event_cid)?;
        let event = decode_pin(&entry.payload)?;
        let mut map = self.pin_events.write().unwrap_or_else(|e| e.into_inner());
        let existing = map.get(&(id.to_string(), seq)).cloned();
        let predecessor_cid = if seq > 1 {
            map.get(&(id.to_string(), seq - 1)).cloned()
        } else {
            None
        };
        match offer_pin_event(
            id,
            seq,
            event_cid,
            &event,
            existing.as_ref(),
            predecessor_cid.as_ref(),
        )? {
            OfferOutcome::AlreadyFiled => Ok(false),
            OfferOutcome::Accept => {
                map.insert((id.to_string(), seq), event_cid.clone());
                Ok(true)
            }
        }
    }

    /// Compare-and-set a pointer head. `expect_seq == 0` means create.
    ///
    /// Writes a new event entry into the store, then files it. The single
    /// write lock is the serialization point — the Durable Object is the
    /// Edge equivalent.
    pub fn update_cas(
        &self,
        id: &str,
        new_cid: Cid,
        expect_seq: u64,
        ts: i64,
    ) -> Result<u64, ReplicaError> {
        check_pointer_id(id)?;
        let mut map = self
            .pointer_events
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let current = current_seq_locked(&map, id);
        if current != expect_seq {
            // Report the *head* CID (the pointer's current target), not the
            // event CID — that matches `PointerLog::update_cas`.
            let actual_cid = self
                .pointer_heads
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(id)
                .map(|(_, cid)| cid.to_hex())
                .or_else(|| {
                    (current > 0)
                        .then(|| map.get(&(id.to_string(), current)).map(|c| c.to_hex()))
                        .flatten()
                })
                .unwrap_or_else(|| "none".into());
            return Err(ReplicaError::CasConflict {
                id: id.to_string(),
                expected: expect_seq,
                actual: current,
                actual_cid,
            });
        }

        let predecessor = if expect_seq == 0 {
            None
        } else {
            let prev_event_cid = map
                .get(&(id.to_string(), expect_seq))
                .cloned()
                .ok_or_else(|| ReplicaError::NotFound(id.to_string()))?;
            Some(decode_pointer(
                &self.store.get_entry(&prev_event_cid)?.payload,
            )?)
        };
        let event = match &predecessor {
            None => PointerEvent::create_event(id, new_cid.clone(), ts),
            Some(prev) => PointerEvent::update_event(
                id,
                expect_seq + 1,
                prev.new.clone(),
                new_cid.clone(),
                ts,
            ),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&event, &mut buf)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let event_cid = self.store.put_entry(&Entry::with_payload(buf))?;
        let seq = event.seq;
        offer_pointer_event(id, seq, &event_cid, &event, None, predecessor.as_ref())?;
        map.insert((id.to_string(), seq), event_cid);
        drop(map);
        self.pointer_heads
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), (seq, new_cid));
        Ok(seq)
    }

    /// Rebuild heads from whatever events were filed.
    pub fn finalize(&self) -> (u32, u32) {
        let pointers = rebuild_heads(
            &self
                .pointer_events
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            &self.pointer_heads,
            |store_cid| {
                let entry = self.store.get_entry(store_cid).ok()?;
                let event = decode_pointer(&entry.payload).ok()?;
                Some(event.new)
            },
        );
        let pins = rebuild_heads(
            &self.pin_events.read().unwrap_or_else(|e| e.into_inner()),
            &self.pin_heads,
            |store_cid| Some(store_cid.clone()),
        );
        (pointers, pins)
    }

    /// Resolve a pointer head after [`Self::finalize`].
    pub fn resolve_pointer(&self, id: &str) -> Option<Cid> {
        self.pointer_heads
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .map(|(_, cid)| cid.clone())
    }

    /// Filed pointer events as `(id, seq, event_cid)`.
    pub fn pointer_event_cids(&self) -> Vec<(String, u64, Cid)> {
        self.pointer_events
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|((id, seq), cid)| (id.clone(), *seq, cid.clone()))
            .collect()
    }
}

fn check_pointer_id(id: &str) -> Result<(), ReplicaError> {
    // Same rules as `PointerLog::validate_pointer_id`: binary keys make most
    // characters safe. Empty and normal Unicode are allowed; terminal and
    // bidi-format controls are not.
    if id.len() > 256 {
        return Err(ReplicaError::InvalidId(
            "pointer id too long (max 256 bytes)".into(),
        ));
    }
    if id.bytes().any(|b| b == 0) {
        return Err(ReplicaError::InvalidId(
            "pointer id cannot contain null bytes".into(),
        ));
    }
    if let Err(reason) = crate::validate_identifier_text(id) {
        return Err(ReplicaError::InvalidId(reason.into()));
    }
    Ok(())
}

fn current_seq_locked(map: &BTreeMap<(String, u64), Cid>, id: &str) -> u64 {
    map.iter()
        .filter(|((name, _), _)| name == id)
        .map(|((_, seq), _)| *seq)
        .max()
        .unwrap_or(0)
}

fn rebuild_heads(
    events: &BTreeMap<(String, u64), Cid>,
    heads: &RwLock<BTreeMap<String, (u64, Cid)>>,
    target: impl Fn(&Cid) -> Option<Cid>,
) -> u32 {
    let mut next: BTreeMap<String, (u64, Cid)> = BTreeMap::new();
    for ((id, seq), event_cid) in events {
        let Some(cid) = target(event_cid) else {
            continue;
        };
        let entry = next.entry(id.clone()).or_insert((0, cid.clone()));
        if *seq > entry.0 {
            *entry = (*seq, cid);
        }
    }
    let count = next.len() as u32;
    *heads.write().unwrap_or_else(|e| e.into_inner()) = next;
    count
}

fn decode_pointer(bytes: &[u8]) -> Result<PointerEvent, CoreError> {
    crate::decode_cbor_exact(bytes)
}

fn decode_pin(bytes: &[u8]) -> Result<PinEvent, CoreError> {
    crate::decode_cbor_exact(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::PointerEvent;

    fn store_event(store: &MemoryStore, event: &PointerEvent) -> Cid {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(event, &mut buf).unwrap();
        store.put_entry(&Entry::with_payload(buf)).unwrap()
    }

    #[test]
    fn replica_imports_reject_event_payloads_with_trailing_cbor() {
        let log = ReplicaLog::new(MemoryStore::new());

        let pointer = PointerEvent::create_event("pointer", Cid::compute(b"target"), 1);
        let mut pointer_payload = Vec::new();
        ciborium::ser::into_writer(&pointer, &mut pointer_payload).unwrap();
        pointer_payload.push(0xf6);
        let pointer_cid = log
            .store()
            .put_entry(&Entry::with_payload(pointer_payload))
            .unwrap();
        assert!(matches!(
            log.import_pointer("pointer", 1, &pointer_cid),
            Err(ReplicaError::Core(CoreError::Deserialization(_)))
        ));

        let pin = PinEvent {
            seq: 1,
            pin_id: "pin".into(),
            target: crate::PinTarget::Direct(Cid::compute(b"target")),
            scope: crate::PinScope::Global,
            expires_at: None,
            state: crate::PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let mut pin_payload = Vec::new();
        ciborium::ser::into_writer(&pin, &mut pin_payload).unwrap();
        pin_payload.push(0xff);
        let pin_cid = log
            .store()
            .put_entry(&Entry::with_payload(pin_payload))
            .unwrap();
        assert!(matches!(
            log.import_pin("pin", 1, &pin_cid),
            Err(ReplicaError::Core(CoreError::Deserialization(_)))
        ));
    }

    #[test]
    fn import_is_idempotent_and_refuses_divergence() {
        let log = ReplicaLog::new(MemoryStore::new());
        let head = Cid::compute(b"head");
        let event = PointerEvent::create_event("p", head, 1);
        let cid = store_event(log.store(), &event);
        assert!(log.import_pointer("p", 1, &cid).unwrap());
        assert!(!log.import_pointer("p", 1, &cid).unwrap());
        // A different CID at the same position: we need a real entry so the
        // decoder runs. Plant one that claims the same id/seq.
        let forged = PointerEvent::create_event("p", Cid::compute(b"else"), 1);
        let forged_cid = store_event(log.store(), &forged);
        assert!(matches!(
            log.import_pointer("p", 1, &forged_cid),
            Err(ReplicaError::Offer(OfferError::Divergent { .. }))
        ));
    }

    #[test]
    fn update_must_follow_the_predecessor() {
        let log = ReplicaLog::new(MemoryStore::new());
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"b");
        let create = PointerEvent::create_event("p", a.clone(), 1);
        let create_cid = store_event(log.store(), &create);
        log.import_pointer("p", 1, &create_cid).unwrap();

        let ok = PointerEvent::update_event("p", 2, a, b.clone(), 2);
        let ok_cid = store_event(log.store(), &ok);
        assert!(log.import_pointer("p", 2, &ok_cid).unwrap());

        let forged = PointerEvent::update_event("p", 3, Cid::compute(b"nope"), b, 3);
        let forged_cid = store_event(log.store(), &forged);
        assert!(matches!(
            log.import_pointer("p", 3, &forged_cid),
            Err(ReplicaError::Offer(OfferError::ChainBroken { .. }))
        ));
    }

    #[test]
    fn cas_refuses_a_stale_expectation() {
        let log = ReplicaLog::new(MemoryStore::new());
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"b");
        assert_eq!(log.update_cas("p", a, 0, 1).unwrap(), 1);
        assert!(matches!(
            log.update_cas("p", b, 0, 2),
            Err(ReplicaError::CasConflict {
                expected: 0,
                actual: 1,
                ..
            })
        ));
        assert_eq!(log.update_cas("p", Cid::compute(b"c"), 1, 3).unwrap(), 2);
        log.finalize();
        assert_eq!(log.resolve_pointer("p").unwrap(), Cid::compute(b"c"));
    }

    #[test]
    fn a_nul_pointer_id_is_refused() {
        let log = ReplicaLog::new(MemoryStore::new());
        let cid = Cid::compute(b"x");
        assert!(matches!(
            log.import_pointer("bad\0id", 1, &cid),
            Err(ReplicaError::InvalidId(_))
        ));
        assert!(matches!(
            log.import_pin("", 1, &cid),
            Err(ReplicaError::InvalidId(_))
        ));
    }

    #[test]
    fn replica_pointer_ids_match_terminal_safe_core_rules() {
        let log = ReplicaLog::new(MemoryStore::new());
        let cid = Cid::compute(b"event");
        for id in [
            "bad\nline",
            "bad\u{001b}[2J",
            "bad\u{202e}txt",
            "bad\u{2067}txt\u{2069}",
        ] {
            assert!(matches!(
                log.import_pointer(id, 1, &cid),
                Err(ReplicaError::InvalidId(_))
            ));
        }
        assert!(!matches!(
            log.import_pointer("模型/é/مرحبا", 1, &cid),
            Err(ReplicaError::InvalidId(_))
        ));
    }
}
