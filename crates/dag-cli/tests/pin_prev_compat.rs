//! A pin event written before `dag_core::PinEvent::prev` existed still reads.
//!
//! `prev` was added under schema version 1 as an optional, `skip_serializing_if
//! = "Option::is_none"` field, and the claim is that a directory written by a
//! pre-`prev` binary and one written after are both "version 1" and both
//! readable. There is a golden test in `dag-core` that the *bytes* of a
//! `prev`-less event are unchanged, and a unit test that it *decodes*. Neither
//! exercises the paths an operator actually hits on such a directory: the
//! store-scan recovery, and replication.
//!
//! These tests hand-encode events exactly as a pre-`prev` binary would have —
//! a create and a deactivation, both with no `prev` on the wire — and drive
//! the real recovery. The result is a boundary worth pinning, because the two
//! paths deliberately disagree:
//!
//! * **explicitly trusted local store-scan recovery tolerates a `prev`-less
//!   later event.** A directory whose pin was deactivated by an old binary
//!   recovers *as deactivated*. This is the read-compatibility the "one format"
//!   claim rests on; the operator must acknowledge that legacy store records
//!   are unsigned ordinary content.
//! * **sync import refuses it.** Across nodes a `prev`-less seq>1 event cannot
//!   be shown to follow its predecessor rather than be grafted onto it, so it
//!   is refused — the destination keeps the pin active, which over-retains
//!   (the safe direction, R6) rather than switching off a hold on someone
//!   else's word.
//!
//! If those two behaviours ever converge, one of two guarantees has silently
//! broken: either an old directory has become unreadable, or a hostile remote
//! can deactivate a pin it never created.

use std::path::Path;

use assert_cmd::Command;
use dag_control::Control;
use dag_core::{Cid, ContentStore, Entry, PinEvent, PinScope, PinState, PinTarget};
use serde_json::Value;
use tempfile::TempDir;

const PIN_ID: &str = "legacy";
const PROTECTED_ARTIFACT: &[u8] = b"the protected artifact";

fn dag(data_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("dag").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

fn json(cmd: &mut Command) -> Value {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// A pin event shaped exactly as a pre-`prev` binary wrote it: `prev` is
/// `None`, so it is skipped on the wire and the CBOR carries no `prev` key at
/// all — byte-identical to what the old encoder produced.
fn legacy_event(seq: u64, state: PinState) -> PinEvent {
    PinEvent {
        seq,
        pin_id: PIN_ID.to_string(),
        target: PinTarget::Direct(Cid::compute(PROTECTED_ARTIFACT)),
        scope: PinScope::Global,
        expires_at: None,
        state,
        ts: 1_700_000_000,
        author: Some("an-older-dag".to_string()),
        prev: None,
    }
}

fn seed_target(store: &dyn ContentStore) {
    let cid = store.put_chunk(PROTECTED_ARTIFACT, None).unwrap();
    assert_eq!(cid, Cid::compute(PROTECTED_ARTIFACT));
}

/// Store `event` as a content entry, the way `PinLog` stores pin events: the
/// entry payload is the CBOR of the event, and the chunk bytes are the CBOR of
/// the entry. Returns the CID the event now lives under.
fn inject(store: &dyn ContentStore, event: &PinEvent) -> Cid {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(event, &mut payload).unwrap();
    // Prove we really did produce a `prev`-less encoding: a CBOR map key is a
    // text string, and "prev" must not appear anywhere in these bytes.
    assert!(
        !payload.windows(4).any(|w| w == b"prev"),
        "the hand-encoded event carries a `prev` key; it is not pre-`prev` shaped"
    );
    let entry = Entry::with_payload(payload);
    store.put_entry(&entry).unwrap()
}

#[test]
fn a_pre_prev_create_recovers_as_active() {
    let temp = TempDir::new().unwrap();
    {
        let control = Control::open(temp.path()).unwrap();
        let store = control.store.as_ref();
        seed_target(store);
        inject(store, &legacy_event(1, PinState::Active));
    }

    let report = json(dag(temp.path()).args([
        "pin",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(report["events_found"], 1);
    assert_eq!(report["events_skipped"], 0);
    assert_eq!(report["heads_rebuilt"], 1);

    let info = json(dag(temp.path()).args(["pin", "info", "--id", PIN_ID, "--json"]));
    assert_eq!(info["state"], "Active");
    assert_eq!(info["seq"], 1);
    assert_eq!(
        info["active"], true,
        "a recovered pre-`prev` create must still protect its target"
    );
}

/// The case the "one format" claim actually stands or falls on: an old binary
/// deactivated a pin, and its `prev`-less deactivation must survive recovery.
#[test]
fn a_pre_prev_deactivation_is_honored_by_store_recovery() {
    let temp = TempDir::new().unwrap();
    {
        let control = Control::open(temp.path()).unwrap();
        let store = control.store.as_ref();
        seed_target(store);
        inject(store, &legacy_event(1, PinState::Active));
        inject(store, &legacy_event(2, PinState::Deactivated));
    }

    let report = json(dag(temp.path()).args([
        "pin",
        "rebuild",
        "--from-store",
        "--trust-unfiled-control-events",
        "--json",
    ]));
    assert_eq!(report["events_found"], 2);
    assert_eq!(
        report["events_skipped"], 0,
        "a `prev`-less deactivation is legitimate history in this deployment's \
         own store; it must not be skipped: {report}"
    );
    assert_eq!(report["heads_rebuilt"], 1);

    let info = json(dag(temp.path()).args(["pin", "info", "--id", PIN_ID, "--json"]));
    assert_eq!(
        info["state"], "Deactivated",
        "the old binary's deactivation was lost on recovery: {info}"
    );
    assert_eq!(info["seq"], 2);
    assert_eq!(
        info["active"], false,
        "a deactivated pin must not be reported as protecting its target"
    );
}

/// The other side of the boundary, exercised at the control layer because it
/// is a replication concern the CLI does not surface directly: sync import
/// refuses the same `prev`-less deactivation the store scan accepted. The
/// create imports; the deactivation does not.
#[test]
fn sync_import_refuses_a_pre_prev_deactivation() {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();
    let store = control.store.as_ref();
    seed_target(store);

    let create_cid = inject(store, &legacy_event(1, PinState::Active));
    let deactivate_cid = inject(store, &legacy_event(2, PinState::Deactivated));

    // seq 1 with no `prev` is exactly what import expects for a create.
    assert!(
        control.pin_log.import_event(PIN_ID, 1, &create_cid).is_ok(),
        "a `prev`-less create is a valid seq-1 event and must import"
    );

    // seq 2 with no `prev` cannot be shown to follow seq 1, so import refuses
    // it — over-retaining rather than switching a pin off on a remote's word.
    let err = control
        .pin_log
        .import_event(PIN_ID, 2, &deactivate_cid)
        .expect_err("a `prev`-less seq-2 event must not import");
    let text = err.to_string();
    assert!(
        text.contains("prev"),
        "the refusal must name the missing chain link: {text}"
    );
}
