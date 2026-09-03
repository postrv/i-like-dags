//! DSSE import: the export format, accepted back — with every refusal that
//! keeps a provenance store meaning something.

use dag_control::test_utils::TestControl;
use dag_control::TrustPurpose;
use dag_core::signing::Envelope;
use dag_core::ContentStore;

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// Sign on one directory, carry the envelope (as JSON, the export shape),
/// import on another that holds the same content.
#[test]
fn an_exported_envelope_imports_across_directories_and_verifies() {
    let source = TestControl::new().unwrap();
    let dest = TestControl::new().unwrap();

    let signer = key(7);
    let public_hex = hex::encode(signer.verifying_key().to_bytes());

    // Same bytes on both sides — content travels by sync or by hand; the
    // envelope is what we are moving here.
    let body: &[u8] = b"the released artefact";
    let target = source.control.store.put_chunk(body, None).unwrap();
    dest.control.store.put_chunk(body, None).unwrap();

    let sig_cid = source
        .control
        .signature_log
        .sign(
            &target,
            Some("release".into()),
            serde_json::json!({"approved": true}),
            &signer,
        )
        .unwrap();

    // The export shape: the envelope alone, JSON, as `--out-dir` writes it.
    let records = source.control.signature_log.records_for(&target).unwrap();
    let json = serde_json::to_string(&records[0].1.envelope).unwrap();
    let envelope: Envelope = serde_json::from_str(&json).unwrap();

    // Import with an explicit key.
    let (imported_cid, imported_target) = dest
        .control
        .signature_log
        .import_envelope(&envelope, Some(&public_hex), None)
        .unwrap();
    assert_eq!(imported_target, target);
    // Identical record bytes land on the identical CID — the signature entry
    // is content-addressed like everything else.
    assert_eq!(imported_cid, sig_cid);

    // The imported signature is valid; trusted only once the keyring says so.
    let statuses = dest.control.signature_log.verify(&target).unwrap();
    assert_eq!(statuses.len(), 1);
    assert!(statuses[0].valid);
    assert!(!statuses[0].trusted);

    dest.control
        .signature_log
        .trust_key(
            &public_hex,
            Some("release signer".into()),
            &[TrustPurpose::Verify],
        )
        .unwrap();
    let statuses = dest.control.signature_log.verify(&target).unwrap();
    assert!(statuses[0].trusted);
}

#[test]
fn without_an_explicit_key_the_keyring_is_the_gate() {
    let source = TestControl::new().unwrap();
    let dest = TestControl::new().unwrap();

    let signer = key(9);
    let body: &[u8] = b"content";
    let target = source.control.store.put_chunk(body, None).unwrap();
    dest.control.store.put_chunk(body, None).unwrap();
    source
        .control
        .signature_log
        .sign(&target, None, serde_json::json!({}), &signer)
        .unwrap();
    let envelope = source.control.signature_log.records_for(&target).unwrap()[0]
        .1
        .envelope
        .clone();

    // Empty keyring, no --key: refused, nothing stored.
    let err = dest
        .control
        .signature_log
        .import_envelope(&envelope, None, None)
        .unwrap_err();
    assert!(err.to_string().contains("no key"), "{err}");
    assert!(dest
        .control
        .signature_log
        .list_for(&target)
        .unwrap()
        .is_empty());

    // A keyring holding an *unrelated* key: still refused.
    let stranger = key(11);
    dest.control
        .signature_log
        .trust_key(
            &hex::encode(stranger.verifying_key().to_bytes()),
            None,
            &[TrustPurpose::Verify],
        )
        .unwrap();
    let err = dest
        .control
        .signature_log
        .import_envelope(&envelope, None, None)
        .unwrap_err();
    assert!(err.to_string().contains("did not verify"), "{err}");

    // Trust the actual signer: the keyring now vouches, import lands.
    dest.control
        .signature_log
        .trust_key(
            &hex::encode(signer.verifying_key().to_bytes()),
            None,
            &[TrustPurpose::Verify],
        )
        .unwrap();
    let (_, imported_target) = dest
        .control
        .signature_log
        .import_envelope(&envelope, None, None)
        .unwrap();
    assert_eq!(imported_target, target);
}

#[test]
fn the_refusals_that_keep_the_store_honest() {
    let source = TestControl::new().unwrap();
    let dest = TestControl::new().unwrap();

    let signer = key(13);
    let public_hex = hex::encode(signer.verifying_key().to_bytes());
    let body: &[u8] = b"present here";
    let target = source.control.store.put_chunk(body, None).unwrap();
    source
        .control
        .signature_log
        .sign(&target, None, serde_json::json!({}), &signer)
        .unwrap();
    let envelope = source.control.signature_log.records_for(&target).unwrap()[0]
        .1
        .envelope
        .clone();

    // 1. Content absent at the importer: an attestation over bytes this
    //    store cannot produce is refused, exactly as local signing would be.
    let err = dest
        .control
        .signature_log
        .import_envelope(&envelope, Some(&public_hex), None)
        .unwrap_err();
    assert!(
        err.to_string().contains("not found") || err.to_string().contains("Chunk"),
        "{err}"
    );

    // 2. A tampered payload no longer verifies — refused, not stored.
    dest.control.store.put_chunk(body, None).unwrap();
    let mut forged = envelope.clone();
    forged.payload = {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let mut payload = engine.decode(&envelope.payload).unwrap();
        payload[0] ^= 1;
        engine.encode(payload)
    };
    let err = dest
        .control
        .signature_log
        .import_envelope(&forged, Some(&public_hex), None)
        .unwrap_err();
    assert!(err.to_string().contains("did not verify"), "{err}");
    assert!(dest
        .control
        .signature_log
        .list_for(&target)
        .unwrap()
        .is_empty());

    // 3. An expectation mismatch: the envelope covers something else.
    let other = dest.control.store.put_chunk(b"different", None).unwrap();
    let err = dest
        .control
        .signature_log
        .import_envelope(&envelope, Some(&public_hex), Some(&other))
        .unwrap_err();
    assert!(err.to_string().contains("not the requested"), "{err}");
}
