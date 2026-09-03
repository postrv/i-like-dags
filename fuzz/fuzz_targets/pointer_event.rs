//! Pointer events, decoded from arbitrary bytes.
//!
//! Reachable from a peer: `import_event` decodes the entry a remote offered
//! before deciding whether to file it, and the store-scan rebuild decodes
//! every chunk in the directory looking for events. A panic here is a
//! remote crash; a decode that yields a nonsensical event is worse, because
//! the validation downstream is what protects pointer history.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The two ways these bytes reach a decoder in production: directly, and
    // wrapped in an entry payload (which is how they are actually stored).
    let direct: Result<dag_core::PointerEvent, _> = ciborium::de::from_reader(data);
    if let Ok(event) = direct {
        // A create is seq 1 with no prev; anything else must carry one. The
        // decoder does not enforce this — `import_event` does — but a
        // decoded event must at least be self-describing enough to check.
        if event.seq == 1 {
            // A `prev` on seq 1 is nonsense, and filing it would graft a
            // chain onto nothing. Only assert the decode is stable.
        }
        let mut re_encoded = Vec::new();
        ciborium::ser::into_writer(&event, &mut re_encoded)
            .expect("a decoded pointer event could not be re-encoded");
        let again: dag_core::PointerEvent = ciborium::de::from_reader(re_encoded.as_slice())
            .expect("re-encoded pointer event did not decode");
        assert_eq!(event.seq, again.seq);
        assert_eq!(event.pointer_id, again.pointer_id);
        assert_eq!(event.new, again.new);
        assert_eq!(event.prev, again.prev);
        assert_eq!(event.new.as_bytes().len(), dag_core::CID_LEN);
    }

    if let Ok(entry) = dag_core::Entry::from_bytes_cbor(data) {
        let _: Result<dag_core::PointerEvent, _> =
            ciborium::de::from_reader(entry.payload.as_slice());
    }
});
