//! Seam 2: can ordinary user content be adopted as history?
//!
//! A store scan identifies events by a strict CBOR decode into the event
//! struct, which is far stronger than field sniffing but is still a guess:
//! `dag put-entry` stores an arbitrary payload, and an event entry the log
//! itself writes is byte-for-byte an ordinary payload-only entry. So the
//! store-scan trust boundary is exactly `data/` — anyone who can write a chunk
//! can offer a candidate event (ADR-002 leaves these logs unsigned).
//!
//! What the *chain validation* is for is rejecting candidates that cannot be a
//! real chain — a broken `prev`, a gap, a cross-type decode — and, crucially,
//! an unchained event grafted onto history the database already commits to.
//! These tests establish where that line actually falls.

use dag_control::Control;
use dag_core::{Cid, ContentStore, Entry, PinEvent, PinScope, PinState, PinTarget, PointerEvent};
use tempfile::TempDir;

fn put_event_entry<T: serde::Serialize>(control: &Control, event: &T) -> Cid {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(event, &mut payload).unwrap();
    control
        .store
        .put_entry(&Entry::with_payload(payload))
        .unwrap()
}

fn pin_event(pin_id: &str, seq: u64, target: Cid, state: PinState, prev: Option<Cid>) -> PinEvent {
    PinEvent {
        seq,
        pin_id: pin_id.to_string(),
        target: PinTarget::Direct(target),
        scope: PinScope::Global,
        expires_at: None,
        state,
        ts: 1_700_000_000,
        author: Some("attacker".into()),
        prev,
    }
}

/// THE FIX. A forged `prev`-less deactivation planted in `data/` must not be
/// adopted as a seq-2 extension of a live pin — that would switch the pin off
/// and unprotect its content, the very attack `import_event` was hardened
/// against. It is refused, reported, and the pin stays active.
#[test]
fn a_forged_prevless_deactivation_cannot_switch_off_a_live_pin() {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();

    let target = control.store.put_chunk(b"protected", None).unwrap();
    control
        .pin_log
        .create(
            "keep",
            PinTarget::Direct(target.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    // Attacker plants a seq-2 deactivation with no chain link.
    put_event_entry(
        &control,
        &pin_event("keep", 2, target, PinState::Deactivated, None),
    );

    let report = control.rebuild_pins_from_store().unwrap();
    assert!(
        report.skipped.iter().any(|s| s.contains("keep")),
        "the injection was not refused loudly: {report:?}"
    );

    let head = control.pin_log.head("keep").unwrap();
    assert_eq!(head.event.seq, 1, "the pin was extended by a forged event");
    assert!(
        matches!(head.event.state, PinState::Active),
        "a forged prev-less deactivation switched off a live pin"
    );
}

/// The fix must not break genuine recovery of *legacy* history — a pin whose
/// deactivation was written before `PinEvent::prev` existed. When the whole
/// chain is recovered from scratch (nothing is filed), a `prev`-less seq-2 is
/// legacy history, not an injection, and is adopted. Refusing it would bring a
/// deactivated pin back as active.
#[test]
fn a_prevless_legacy_chain_is_still_recovered_from_scratch() {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();

    // Nothing is created through the log: both events are planted as content,
    // as a pre-`prev` deployment's store would hold them, and the database
    // knows of neither.
    let target = control.store.put_chunk(b"legacy content", None).unwrap();
    put_event_entry(
        &control,
        &pin_event("legacy", 1, target.clone(), PinState::Active, None),
    );
    put_event_entry(
        &control,
        &pin_event("legacy", 2, target, PinState::Deactivated, None),
    );

    let report = control.rebuild_pins_from_store().unwrap();
    assert_eq!(report.heads_rebuilt, 1, "{report:?}");
    assert!(report.skipped.is_empty(), "{report:?}");

    let head = control.pin_log.head("legacy").unwrap();
    assert_eq!(head.event.seq, 2);
    assert!(
        matches!(head.event.state, PinState::Deactivated),
        "a legacy prev-less deactivation was lost, resurrecting the pin as active"
    );
}

/// A real `PinEvent` entry must not be mistaken for a `PointerEvent`, and vice
/// versa. Cross-type decoding is blocked by each struct's required fields
/// (`PointerEvent` needs `pointer_id` and `new`; `PinEvent` needs `pin_id`,
/// `target`, `scope`, ...), so neither log adopts the other's events.
#[test]
fn events_do_not_cross_decode_between_logs() {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();

    let target = control.store.put_chunk(b"x", None).unwrap();
    // A real pin event as content...
    put_event_entry(
        &control,
        &pin_event("a-pin", 1, target.clone(), PinState::Active, None),
    );
    // ...and a real pointer event as content.
    put_event_entry(
        &control,
        &PointerEvent::create_event("a-pointer", target, 1_700_000_000),
    );

    // The pointer scan sees only the pointer event, never the pin event.
    let ptr = control.rebuild_pointers_from_store().unwrap();
    assert_eq!(ptr.events_found, 1, "{ptr:?}");
    assert_eq!(
        control.pointer_log.list_pointers().unwrap(),
        vec!["a-pointer"]
    );

    // The pin scan sees only the pin event, never the pointer event.
    let pin = control.rebuild_pins_from_store().unwrap();
    assert_eq!(pin.events_found, 1, "{pin:?}");
    assert_eq!(control.pin_log.list().unwrap(), vec!["a-pin"]);
}

/// The store-scan trust boundary, stated as an executable fact: a well-formed
/// seq-1 create planted via `put-entry` for a pointer that never existed *is*
/// adopted. There is no structural way to tell it from a real create — the log
/// writes byte-identical entries — and these logs are unsigned by design
/// (ADR-002). The defence is not prevention but visibility: the forgery is
/// counted in `events_found`/`heads_rebuilt`, never adopted silently.
#[test]
fn a_fictional_create_is_adopted_but_never_silently() {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();

    let payload = control.store.put_chunk(b"anything", None).unwrap();
    put_event_entry(
        &control,
        &PointerEvent::create_event("ghost", payload.clone(), 1_700_000_000),
    );

    let report = control.rebuild_pointers_from_store().unwrap();
    assert_eq!(report.events_found, 1);
    assert_eq!(
        report.heads_rebuilt, 1,
        "the create was visible in the report"
    );
    assert_eq!(control.pointer_log.resolve("ghost").unwrap(), payload);
}

/// Chain validation *does* reject an internally inconsistent forgery: a seq-2
/// pointer event whose `prev` does not name seq-1's `new` is a broken chain,
/// skipped and reported rather than adopted.
#[test]
fn an_inconsistent_forged_pointer_chain_is_rejected() {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();

    let a = control.store.put_chunk(b"a", None).unwrap();
    let b = control.store.put_chunk(b"b", None).unwrap();
    let wrong = control.store.put_chunk(b"unrelated", None).unwrap();

    // seq 1 -> a.
    put_event_entry(
        &control,
        &PointerEvent::create_event("liar", a.clone(), 1_700_000_000),
    );
    // seq 2 claims to follow `wrong`, but seq 1 ended at `a`.
    put_event_entry(
        &control,
        &PointerEvent::update_event("liar", 2, wrong, b, 1_700_000_001),
    );

    let report = control.rebuild_pointers_from_store().unwrap();
    assert_eq!(report.events_found, 2);
    assert_eq!(
        report.heads_rebuilt, 0,
        "a broken chain was adopted: {report:?}"
    );
    assert!(
        report.skipped.iter().any(|s| s.contains("liar")),
        "the broken chain was dropped without saying so: {report:?}"
    );
    assert!(control.pointer_log.list_pointers().unwrap().is_empty());
}
