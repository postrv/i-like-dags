//! Verification means all the way down.
//!
//! A chunked file's CID names a manifest. The manifest hashing correctly
//! proves the *list of parts* is intact and says nothing about the parts, so
//! every check that stopped there — `dag verify`, the J7 adoption gate, the
//! attestation it publishes — reported success over content that was gone.
//! For artefacts large enough to be chunked, which is what this system is
//! for, that made the central claim false.

use dag_control::test_utils::TestControl;
use dag_core::{Cid, ContentStore};

/// Store `bytes` as a chunked file and return its manifest CID plus the
/// CIDs of its data chunks.
fn store_file(tc: &TestControl, bytes: Vec<u8>) -> (Cid, Vec<Cid>) {
    let stored = dag_core::file::store_auto(
        tc.control.store.as_ref(),
        std::io::Cursor::new(bytes),
        None,
        false,
        &dag_core::ChunkerConfig::default(),
    )
    .unwrap();
    let root = match stored {
        dag_core::StoredContent::File(r) => r.cid,
        dag_core::StoredContent::Chunk { cid, .. } => cid,
    };
    let parts = tc
        .control
        .store
        .get_links(&root)
        .unwrap()
        .into_iter()
        .map(|l| l.target)
        .collect();
    (root, parts)
}

/// Nine MiB, so it certainly chunks.
fn big() -> Vec<u8> {
    (0..(9 * 1024 * 1024)).map(|i| (i % 251) as u8).collect()
}

#[test]
fn a_manifest_missing_a_data_chunk_does_not_verify() {
    let tc = TestControl::new().unwrap();
    let (root, parts) = store_file(&tc, big());
    assert!(parts.len() > 1, "setup: the file must be chunked");

    // Intact to begin with, and the walk reports what it checked.
    let info = dag_core::file::verify_deep(tc.control.store.as_ref(), &root)
        .unwrap()
        .expect("a manifest");
    assert_eq!(info.size, 9 * 1024 * 1024);

    // Remove one interior data chunk — rot, a partial restore, a collection
    // that ran against a stale protected set.
    std::fs::remove_file(tc.control.store.chunk_path(&parts[1])).unwrap();

    // The manifest's own bytes are still perfect...
    let manifest_bytes = tc.control.store.get_chunk(&root).unwrap();
    assert_eq!(Cid::compute(&manifest_bytes), root);

    // ...and the deep check must still refuse, naming the missing part
    // rather than the root that named it.
    let err = dag_core::file::verify_deep(tc.control.store.as_ref(), &root).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(&parts[1].to_hex()),
        "the failure should name the missing part: {msg}"
    );
}

#[test]
fn a_plain_chunk_is_fully_checked_by_its_own_hash() {
    let tc = TestControl::new().unwrap();
    let cid = tc.control.store.put_chunk(b"small enough", None).unwrap();

    // Not a manifest: nothing deeper exists, and that is a pass, not a skip.
    assert!(dag_core::file::verify_deep(tc.control.store.as_ref(), &cid)
        .unwrap()
        .is_none());

    // Corrupt it and the same call refuses.
    std::fs::write(tc.control.store.chunk_path(&cid), b"tampered!!!!").unwrap();
    assert!(dag_core::file::verify_deep(tc.control.store.as_ref(), &cid).is_err());
}

#[test]
fn a_claim_over_an_incomplete_output_is_neither_published_nor_adopted() {
    let tc = TestControl::new().unwrap();
    let (root, parts) = store_file(&tc, big());

    let key = dag_core::EffectKey::new(
        dag_core::JobId::from("big-job".to_string()),
        Cid::compute(b"the resolved input manifest"),
        "model=demo".to_string(),
    );
    let signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let public_hex = hex::encode(signing.verifying_key().to_bytes());
    tc.control
        .signature_log
        .trust_key(
            &public_hex,
            Some("builder".into()),
            &[dag_control::TrustPurpose::Adopt],
        )
        .unwrap();

    // Publishing while the output is whole: fine, and adoptable.
    let outputs = vec![("artifact".to_string(), root.clone())];
    tc.control.attest_effect(&key, &outputs, &signing).unwrap();
    assert!(
        tc.control.adopt_attested(&key).unwrap().is_some(),
        "an intact output should adopt"
    );

    // Now lose a data chunk. The claim and its signature are untouched and
    // still verify; only the *content* is incomplete.
    std::fs::remove_file(tc.control.store.chunk_path(&parts[1])).unwrap();

    assert!(
        tc.control.adopt_attested(&key).unwrap().is_none(),
        "adopted an output whose data chunks are gone — the run would have \
         been recorded as succeeded, and the broken outputs written into the \
         local effect cache"
    );

    // And a node must not *publish* a signed claim for what it cannot
    // produce: that is the signature vouching for absent bytes.
    let err = tc
        .control
        .attest_effect(&key, &outputs, &signing)
        .unwrap_err();
    assert!(
        err.to_string().contains("refusing to claim output"),
        "{err}"
    );
}
