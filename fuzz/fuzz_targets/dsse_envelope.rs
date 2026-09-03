//! DSSE envelopes and the statements inside them, from arbitrary bytes.
//!
//! This is now an *import* surface: `dag signatures --import` takes a file
//! from wherever the operator got it, and the parse happens before any key
//! check. Base64 and JSON are both attacker-controlled, and a statement's
//! subject digests become CIDs the system then looks up.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The envelope as it arrives: JSON text.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(envelope) = serde_json::from_str::<dag_core::signing::Envelope>(text) else {
        return;
    };

    // Re-serialising must not fail: the import path stores this verbatim.
    let json = serde_json::to_string(&envelope).expect("decoded envelope did not re-serialise");
    let again: dag_core::signing::Envelope =
        serde_json::from_str(&json).expect("re-serialised envelope did not decode");
    assert_eq!(envelope.payload, again.payload);
    assert_eq!(envelope.payload_type, again.payload_type);
    assert_eq!(envelope.signatures.len(), again.signatures.len());

    // The payload is base64 of a statement. Decoding it and reading the
    // subject digests is what import does before it knows whether to trust
    // anything, so it must be total.
    use base64::Engine;
    let Ok(payload) = base64::engine::general_purpose::STANDARD.decode(&envelope.payload) else {
        return;
    };
    let Ok(statement) = serde_json::from_slice::<dag_core::signing::Statement>(&payload) else {
        return;
    };

    // Every CID this yields must be well-formed — the import path turns
    // them into store lookups, and a short one used to be a panic.
    for cid in statement.subject_cids() {
        assert_eq!(cid.as_bytes().len(), dag_core::CID_LEN);
    }
});
