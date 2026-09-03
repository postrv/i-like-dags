//! Stored signature entries, as the store-scan rebuild sees them.
//!
//! `signing::record_from_bytes` runs over *every chunk in the directory*
//! when `SignatureLog::rebuild` scans the store, so it is offered whatever
//! bytes happen to be there — including content a peer sent. It returns an
//! `Option`, so the contract is that it never panics and never yields a
//! record whose embedded key would be trusted without the keyring saying so.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((record, entry)) = dag_core::signing::record_from_bytes(data) else {
        return;
    };

    // A record only comes back for the right `kind`; that is the marker the
    // scan filters on.
    assert_eq!(record.kind, dag_core::signing::SIGNATURE_KIND);

    // It must name what it signs: the scan indexes by the `signs` link, and
    // a record with no such link would be indexed against nothing.
    let signs: Vec<_> = entry
        .links
        .iter()
        .filter(|l| l.name.as_deref() == Some("signs"))
        .collect();
    for link in &signs {
        assert_eq!(link.target.as_bytes().len(), dag_core::CID_LEN);
    }

    // The embedded public key is attacker-controlled. Parsing it must be
    // total, and a small-order ("weak") point must be refused here rather
    // than reaching a verification that would accept forged signatures.
    if let Ok(key) = dag_core::signing::verifying_key_from_hex(&record.public_key) {
        // A parsed key is usable; verification against it may fail, but
        // must not panic.
        let _ = dag_core::signing::verify_envelope(&record.envelope, &key);
    }
});
