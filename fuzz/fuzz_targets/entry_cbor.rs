//! The CBOR entry decoder, against arbitrary bytes.
//!
//! `Entry::from_bytes_cbor` is the widest hostile-input surface in the
//! system: every chunk a peer sends, every file restored from a backup, and
//! every byte a `reindex` scan picks up is offered to it. It must reject or
//! accept — never panic, never allocate unboundedly on a small input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(entry) = dag_core::Entry::from_bytes_cbor(data) else {
        return;
    };

    // A decode that succeeded must survive the round trip it implies:
    // re-encoding and decoding again yields the same shape. This is what
    // makes a CID stable, so a decoder that accepts something it cannot
    // reproduce is a defect even though nothing panicked.
    let Ok(re_encoded) = entry.to_bytes_cbor() else {
        panic!("an entry that decoded could not be re-encoded");
    };
    let round_tripped = dag_core::Entry::from_bytes_cbor(&re_encoded)
        .expect("re-encoded entry did not decode");

    assert_eq!(entry.payload, round_tripped.payload);
    assert_eq!(entry.links.len(), round_tripped.links.len());
    for (a, b) in entry.links.iter().zip(round_tripped.links.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.target, b.target);
    }

    // Every link target must be a well-formed CID. The decoder is the only
    // thing standing between a hostile entry and a path built from its
    // bytes, and "CIDs are always 32 bytes" is the invariant that keeps
    // `chunk_path` from slicing something shorter.
    for link in &entry.links {
        assert_eq!(
            link.target.as_bytes().len(),
            dag_core::CID_LEN,
            "decoded a link whose target is not a 32-byte CID"
        );
    }
});
