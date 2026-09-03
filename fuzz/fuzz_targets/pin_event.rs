//! Pin events, decoded from arbitrary bytes.
//!
//! The same reachability as pointer events — `import_event` and the
//! store-scan rebuild — but the stakes differ: a pin event decides what
//! collection may not delete, so a decoder that accepts a malformed
//! deactivation is one step from unprotecting content.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded: Result<dag_core::PinEvent, _> = ciborium::de::from_reader(data);
    let Ok(event) = decoded else { return };

    let mut re_encoded = Vec::new();
    ciborium::ser::into_writer(&event, &mut re_encoded)
        .expect("a decoded pin event could not be re-encoded");
    let again: dag_core::PinEvent = ciborium::de::from_reader(re_encoded.as_slice())
        .expect("re-encoded pin event did not decode");

    assert_eq!(event.seq, again.seq);
    assert_eq!(event.pin_id, again.pin_id);
    assert_eq!(event.target, again.target);
    assert_eq!(event.expires_at, again.expires_at);

    // Whatever the target is, its CID is 32 bytes — a subtree pin's root is
    // walked, and a walk that starts from a malformed CID is exactly the
    // shape that used to panic in `chunk_path`.
    match &event.target {
        dag_core::PinTarget::Direct(cid) => {
            assert_eq!(cid.as_bytes().len(), dag_core::CID_LEN)
        }
        dag_core::PinTarget::Subtree { root, .. } => {
            assert_eq!(root.as_bytes().len(), dag_core::CID_LEN)
        }
    }
});
