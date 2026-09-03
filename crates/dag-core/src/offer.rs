//! Pure chain rules for filing a pointer or pin event.
//!
//! `PointerLog::import_event` and the Edge replica (ADR-007) must refuse
//! the same forgeries. The I/O — reading the offered entry, looking up the
//! predecessor — stays with the caller; this module only judges what it is
//! shown.

use crate::{Cid, PinEvent, PointerEvent};

/// The offered event may be filed, or is already filed at this position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferOutcome {
    /// New mapping; the caller should write it.
    Accept,
    /// This exact `(id, seq, cid)` is already on file. Idempotent success.
    AlreadyFiled,
}

/// Why an offered event cannot be filed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OfferError {
    /// Sequence numbers start at 1.
    #[error("sequence 0 is not a valid event position")]
    ZeroSeq,
    /// The event bytes describe a different id or seq than the offer.
    #[error(
        "event {event_cid} describes ({event_id}, seq {event_seq}) but was offered as ({offered_id}, seq {offered_seq})"
    )]
    IdentityMismatch {
        event_cid: Cid,
        event_id: String,
        event_seq: u64,
        offered_id: String,
        offered_seq: u64,
    },
    /// A different event is already filed at this position.
    #[error("{id} seq {seq} already names {existing}, refusing to replace it with {offered}")]
    Divergent {
        id: String,
        seq: u64,
        existing: Cid,
        offered: Cid,
    },
    /// Seq 1 must be a create: no `prev`.
    #[error("{id} seq 1 must have no `prev`")]
    CreateHasPrev { id: String },
    /// A later event cannot be filed before its predecessor.
    #[error("{id} seq {seq} cannot be imported before seq {needed}")]
    MissingPredecessor { id: String, seq: u64, needed: u64 },
    /// `prev` does not name what the predecessor actually ended at.
    #[error("{id} seq {seq} breaks the chain: `prev` is {prev}, expected {expected}")]
    ChainBroken {
        id: String,
        seq: u64,
        prev: String,
        expected: Cid,
    },
    /// A pin event at seq > 1 with no `prev` cannot be shown to follow anyone.
    #[error(
        "{id} seq {seq} has no `prev`: it cannot be shown to follow seq {needed} ({expected})"
    )]
    PinPrevAbsent {
        id: String,
        seq: u64,
        needed: u64,
        expected: Cid,
    },
}

/// Judge a pointer-event offer against the chain already on file.
///
/// `predecessor` is the decoded event at `seq - 1`. Pointer `prev` names
/// that event's `new` (the previous head CID), not the previous event CID.
pub fn offer_pointer_event(
    pointer_id: &str,
    seq: u64,
    event_cid: &Cid,
    event: &PointerEvent,
    existing_at_seq: Option<&Cid>,
    predecessor: Option<&PointerEvent>,
) -> Result<OfferOutcome, OfferError> {
    if seq == 0 {
        return Err(OfferError::ZeroSeq);
    }
    if event.pointer_id != pointer_id || event.seq != seq {
        return Err(OfferError::IdentityMismatch {
            event_cid: event_cid.clone(),
            event_id: event.pointer_id.clone(),
            event_seq: event.seq,
            offered_id: pointer_id.to_string(),
            offered_seq: seq,
        });
    }
    if let Some(existing) = existing_at_seq {
        return if existing == event_cid {
            Ok(OfferOutcome::AlreadyFiled)
        } else {
            Err(OfferError::Divergent {
                id: pointer_id.to_string(),
                seq,
                existing: existing.clone(),
                offered: event_cid.clone(),
            })
        };
    }
    if seq == 1 {
        if event.prev.is_some() {
            return Err(OfferError::CreateHasPrev {
                id: pointer_id.to_string(),
            });
        }
        return Ok(OfferOutcome::Accept);
    }
    let Some(prev_event) = predecessor else {
        return Err(OfferError::MissingPredecessor {
            id: pointer_id.to_string(),
            seq,
            needed: seq - 1,
        });
    };
    if event.prev.as_ref() != Some(&prev_event.new) {
        return Err(OfferError::ChainBroken {
            id: pointer_id.to_string(),
            seq,
            prev: display_opt_cid(event.prev.as_ref()),
            expected: prev_event.new.clone(),
        });
    }
    Ok(OfferOutcome::Accept)
}

fn display_opt_cid(cid: Option<&Cid>) -> String {
    cid.map(Cid::to_hex).unwrap_or_else(|| "none".into())
}

/// Judge a pin-event offer against the chain already on file.
///
/// Pin `prev` names the **previous event CID**, not the pin target. That is
/// the check `PinLog::import_event` has always made.
pub fn offer_pin_event(
    pin_id: &str,
    seq: u64,
    event_cid: &Cid,
    event: &PinEvent,
    existing_at_seq: Option<&Cid>,
    predecessor_event_cid: Option<&Cid>,
) -> Result<OfferOutcome, OfferError> {
    if seq == 0 {
        return Err(OfferError::ZeroSeq);
    }
    if event.pin_id != pin_id || event.seq != seq {
        return Err(OfferError::IdentityMismatch {
            event_cid: event_cid.clone(),
            event_id: event.pin_id.clone(),
            event_seq: event.seq,
            offered_id: pin_id.to_string(),
            offered_seq: seq,
        });
    }
    if let Some(existing) = existing_at_seq {
        return if existing == event_cid {
            Ok(OfferOutcome::AlreadyFiled)
        } else {
            Err(OfferError::Divergent {
                id: pin_id.to_string(),
                seq,
                existing: existing.clone(),
                offered: event_cid.clone(),
            })
        };
    }
    if seq == 1 {
        if event.prev.is_some() {
            return Err(OfferError::CreateHasPrev {
                id: pin_id.to_string(),
            });
        }
        return Ok(OfferOutcome::Accept);
    }
    let Some(prev_cid) = predecessor_event_cid else {
        return Err(OfferError::MissingPredecessor {
            id: pin_id.to_string(),
            seq,
            needed: seq - 1,
        });
    };
    match &event.prev {
        None => Err(OfferError::PinPrevAbsent {
            id: pin_id.to_string(),
            seq,
            needed: seq - 1,
            expected: prev_cid.clone(),
        }),
        Some(claimed) if claimed != prev_cid => Err(OfferError::ChainBroken {
            id: pin_id.to_string(),
            seq,
            prev: claimed.to_hex(),
            expected: prev_cid.clone(),
        }),
        Some(_) => Ok(OfferOutcome::Accept),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::{PinScope, PinState, PinTarget};
    use crate::Cid;

    fn cid(label: &str) -> Cid {
        Cid::compute(label.as_bytes())
    }

    fn create(id: &str, head: Cid) -> PointerEvent {
        PointerEvent::create_event(id, head, 1)
    }

    fn update(id: &str, seq: u64, prev: Cid, new: Cid) -> PointerEvent {
        PointerEvent::update_event(id, seq, prev, new, seq as i64)
    }

    #[test]
    fn pointer_create_is_accepted_and_is_idempotent() {
        let head = cid("h");
        let event = create("p", head.clone());
        let event_cid = cid("e1");
        assert_eq!(
            offer_pointer_event("p", 1, &event_cid, &event, None, None).unwrap(),
            OfferOutcome::Accept
        );
        assert_eq!(
            offer_pointer_event("p", 1, &event_cid, &event, Some(&event_cid), None).unwrap(),
            OfferOutcome::AlreadyFiled
        );
        let other = cid("other");
        assert!(matches!(
            offer_pointer_event("p", 1, &event_cid, &event, Some(&other), None),
            Err(OfferError::Divergent { .. })
        ));
    }

    #[test]
    fn pointer_update_must_name_the_predecessors_head() {
        let a = cid("a");
        let b = cid("b");
        let prev = create("p", a.clone());
        let ok = update("p", 2, a.clone(), b.clone());
        let event_cid = cid("e2");
        assert_eq!(
            offer_pointer_event("p", 2, &event_cid, &ok, None, Some(&prev)).unwrap(),
            OfferOutcome::Accept
        );
        let forged = update("p", 2, cid("nope"), b);
        assert!(matches!(
            offer_pointer_event("p", 2, &event_cid, &forged, None, Some(&prev)),
            Err(OfferError::ChainBroken { .. })
        ));
        assert!(matches!(
            offer_pointer_event("p", 2, &event_cid, &ok, None, None),
            Err(OfferError::MissingPredecessor { .. })
        ));
    }

    #[test]
    fn pin_seq_greater_than_one_without_prev_is_refused() {
        let target = cid("t");
        let prev_event = cid("prev-event");
        let event = PinEvent {
            seq: 2,
            pin_id: "hold".into(),
            target: PinTarget::Direct(target),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: None,
        };
        let event_cid = cid("deact");
        assert!(matches!(
            offer_pin_event("hold", 2, &event_cid, &event, None, Some(&prev_event)),
            Err(OfferError::PinPrevAbsent { .. })
        ));
    }

    #[test]
    fn pin_prev_must_be_the_previous_event_cid() {
        let target = cid("t");
        let prev_event = cid("prev-event");
        let event = PinEvent {
            seq: 2,
            pin_id: "hold".into(),
            target: PinTarget::Direct(target),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: Some(prev_event.clone()),
        };
        let event_cid = cid("deact");
        assert_eq!(
            offer_pin_event("hold", 2, &event_cid, &event, None, Some(&prev_event)).unwrap(),
            OfferOutcome::Accept
        );
        let wrong = cid("wrong");
        assert!(matches!(
            offer_pin_event("hold", 2, &event_cid, &event, None, Some(&wrong)),
            Err(OfferError::ChainBroken { .. })
        ));
    }
}
