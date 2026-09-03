//! Signature log integration: signing, the keyring, verification verdicts,
//! and the attack the trust model exists to stop.

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::TrustPurpose;
use dag_core::signing;
use dag_core::ContentStore;
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}

#[test]
fn sign_then_verify_with_a_trusted_key() -> Result<()> {
    let tc = TestControl::new()?;
    let content = tc.control.store.put_chunk(b"release artefact", None)?;

    let signer = key(1);
    tc.control.signature_log.trust_key(
        &pubkey_hex(&signer),
        Some("build server".into()),
        &[TrustPurpose::Verify],
    )?;

    let sig_cid = tc.control.signature_log.sign(
        &content,
        Some("artefact".into()),
        serde_json::json!({"note": "release v1"}),
        &signer,
    )?;

    let statuses = tc.control.signature_log.verify(&content)?;
    assert_eq!(statuses.len(), 1);
    let status = &statuses[0];
    assert_eq!(status.signature_cid, sig_cid);
    assert!(status.trusted, "keyring key must yield a trusted verdict");
    assert!(status.valid);
    assert_eq!(status.signer.as_deref(), Some("build server"));
    assert_eq!(status.predicate["note"], "release v1");
    Ok(())
}

#[test]
fn an_unknown_key_is_valid_but_untrusted() -> Result<()> {
    let tc = TestControl::new()?;
    let content = tc.control.store.put_chunk(b"content", None)?;

    let stranger = key(2);
    tc.control
        .signature_log
        .sign(&content, None, serde_json::json!({}), &stranger)?;

    let statuses = tc.control.signature_log.verify(&content)?;
    assert_eq!(statuses.len(), 1);
    assert!(!statuses[0].trusted, "nobody vouched for this key");
    assert!(statuses[0].valid, "but the envelope is self-consistent");
    assert!(statuses[0].signer.is_none());
    Ok(())
}

/// The attack the verification rule exists for: a signature record that
/// *claims* a trusted key's ID but was actually signed by another key. If
/// verification consulted the embedded key, this would pass as trusted.
#[test]
fn a_keyid_spoof_is_neither_trusted_nor_valid() -> Result<()> {
    let tc = TestControl::new()?;
    let content = tc.control.store.put_chunk(b"high-value content", None)?;

    let trusted = key(3);
    tc.control.signature_log.trust_key(
        &pubkey_hex(&trusted),
        Some("the real signer".into()),
        &[TrustPurpose::Verify],
    )?;

    // Attacker signs with their own key, then rewrites the record to claim
    // the trusted key's ID (keeping their own public key embedded, since the
    // signature only verifies against that).
    let attacker = key(4);
    let statement = signing::Statement::for_cid(&content, None, serde_json::json!({}));
    let envelope = {
        let mut envelope = signing::sign_statement(&statement, &attacker)?;
        envelope.signatures[0].keyid = signing::key_id(&trusted.verifying_key());
        envelope
    };
    let record = signing::SignatureRecord {
        kind: signing::SIGNATURE_KIND.to_string(),
        key_id: signing::key_id(&trusted.verifying_key()),
        public_key: hex::encode(attacker.verifying_key().as_bytes()),
        envelope,
    };
    let entry = dag_core::Entry::new(
        serde_json::to_vec(&record)?,
        vec![dag_core::Link::named(content.clone(), "signs")],
        None,
    );
    let forged_cid = tc.control.store.put_entry(&entry)?;

    // Plant it in the index the way an ingested signature would be.
    tc.control.signature_log.rebuild()?;
    let statuses = tc.control.signature_log.verify(&content)?;
    let forged = statuses
        .iter()
        .find(|s| s.signature_cid == forged_cid)
        .expect("forged signature should be indexed");

    assert!(
        !forged.trusted,
        "SPOOF ACCEPTED: claiming a trusted key ID must not grant trust"
    );
    assert!(
        !forged.valid,
        "the embedded key's ID does not match the claim, so it is not even valid"
    );
    Ok(())
}

#[test]
fn a_trusted_envelope_does_not_validate_a_mismatched_embedded_key() -> Result<()> {
    let tc = TestControl::new()?;
    let content = tc.control.store.put_chunk(b"trusted statement", None)?;
    let trusted = key(31);
    let unrelated = key(32);
    tc.control
        .signature_log
        .trust_key(&pubkey_hex(&trusted), None, &[TrustPurpose::Verify])?;

    let statement = signing::Statement::for_cid(&content, None, serde_json::json!({}));
    let record = signing::SignatureRecord {
        kind: signing::SIGNATURE_KIND.to_string(),
        key_id: signing::key_id(&trusted.verifying_key()),
        // The envelope is genuinely trusted, but the stored record's claim of
        // self-contained validity is false because this is another key.
        public_key: pubkey_hex(&unrelated),
        envelope: signing::sign_statement(&statement, &trusted)?,
    };
    tc.control.store.put_entry(&dag_core::Entry::new(
        serde_json::to_vec(&record)?,
        vec![dag_core::Link::named(content.clone(), "signs")],
        None,
    ))?;
    tc.control.signature_log.rebuild()?;

    let status = &tc.control.signature_log.verify(&content)?[0];
    assert!(
        status.trusted,
        "the keyring correctly verifies the envelope"
    );
    assert!(
        !status.valid,
        "keyring trust must not mask a mismatched embedded public key"
    );
    Ok(())
}

/// The other way to claim authorship you don't have: instead of borrowing a
/// trusted key's ID, sign under a *small-order* key. Ed25519's cofactorless
/// verification equation `[s]B = R + [k]A` is satisfiable without any secret
/// when `A` has small order — here `A = R = identity, s = 0` verifies against
/// literally any statement. Such a signature must earn neither verdict, and
/// the key must not be trustable in the first place.
#[test]
fn a_small_order_key_forgery_is_neither_trusted_nor_valid() -> Result<()> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let tc = TestControl::new()?;
    let content = tc
        .control
        .store
        .put_chunk(b"content the attacker never had", None)?;

    // The identity point, as a public key.
    let identity_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    let identity: [u8; 32] = hex::decode(identity_hex).unwrap().try_into().unwrap();
    let weak = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
    assert!(weak.is_weak(), "test vector must be a small-order point");

    // Forge: R = identity, s = 0, over a statement covering the target.
    let statement = signing::Statement::for_cid(&content, None, serde_json::json!({"note": "ok"}));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&identity);
    let envelope = signing::Envelope {
        payload: BASE64.encode(serde_json::to_vec(&statement)?),
        payload_type: signing::PAYLOAD_TYPE.to_string(),
        signatures: vec![signing::EnvelopeSignature {
            keyid: signing::key_id(&weak),
            sig: BASE64.encode(sig),
        }],
    };
    let record = signing::SignatureRecord {
        kind: signing::SIGNATURE_KIND.to_string(),
        key_id: signing::key_id(&weak),
        public_key: identity_hex.to_string(),
        envelope,
    };
    let entry = dag_core::Entry::new(
        serde_json::to_vec(&record)?,
        vec![dag_core::Link::named(content.clone(), "signs")],
        None,
    );
    let forged_cid = tc.control.store.put_entry(&entry)?;

    tc.control.signature_log.rebuild()?;
    let statuses = tc.control.signature_log.verify(&content)?;
    let forged = statuses
        .iter()
        .find(|s| s.signature_cid == forged_cid)
        .expect("forged signature should be indexed");

    assert!(
        !forged.valid,
        "SMALL-ORDER FORGERY ACCEPTED: a signature nobody could have produced read as valid"
    );
    assert!(!forged.trusted, "and it certainly must not be trusted");

    // Nor can an operator be talked into putting one in the keyring, which
    // is the same forgery dressed as a trusted signer.
    assert!(
        tc.control
            .signature_log
            .trust_key(
                identity_hex,
                Some("plausible-looking CI key".into()),
                &[TrustPurpose::Verify],
            )
            .is_err(),
        "a small-order key must not be trustable"
    );
    Ok(())
}

/// A signature whose statement covers some other CID must not count for a
/// target it merely got indexed against.
#[test]
fn a_signature_for_other_content_does_not_transfer() -> Result<()> {
    let tc = TestControl::new()?;
    let content_a = tc.control.store.put_chunk(b"content A", None)?;
    let content_b = tc.control.store.put_chunk(b"content B", None)?;

    let signer = key(5);
    tc.control
        .signature_log
        .trust_key(&pubkey_hex(&signer), None, &[TrustPurpose::Verify])?;

    // Sign B, then craft an entry linking that envelope to A.
    let statement = signing::Statement::for_cid(&content_b, None, serde_json::json!({}));
    let envelope = signing::sign_statement(&statement, &signer)?;
    let record = signing::SignatureRecord {
        kind: signing::SIGNATURE_KIND.to_string(),
        key_id: signing::key_id(&signer.verifying_key()),
        public_key: pubkey_hex(&signer),
        envelope,
    };
    let entry = dag_core::Entry::new(
        serde_json::to_vec(&record)?,
        vec![dag_core::Link::named(content_a.clone(), "signs")],
        None,
    );
    tc.control.store.put_entry(&entry)?;
    tc.control.signature_log.rebuild()?;

    let statuses = tc.control.signature_log.verify(&content_a)?;
    assert_eq!(statuses.len(), 1);
    assert!(
        !statuses[0].trusted && !statuses[0].valid,
        "a real signature of B is not a signature of A"
    );
    Ok(())
}

#[test]
fn untrusting_a_key_downgrades_without_erasing() -> Result<()> {
    let tc = TestControl::new()?;
    let content = tc.control.store.put_chunk(b"content", None)?;

    let signer = key(6);
    let trusted =
        tc.control
            .signature_log
            .trust_key(&pubkey_hex(&signer), None, &[TrustPurpose::Verify])?;
    tc.control
        .signature_log
        .sign(&content, None, serde_json::json!({}), &signer)?;

    assert!(tc.control.signature_log.verify(&content)?[0].trusted);

    assert!(tc.control.signature_log.untrust_key(&trusted.key_id)?);
    let statuses = tc.control.signature_log.verify(&content)?;
    assert!(!statuses[0].trusted, "trust is revoked");
    assert!(statuses[0].valid, "the signature itself is untouched");
    Ok(())
}

#[test]
fn the_index_rebuilds_from_the_store() -> Result<()> {
    let tc = TestControl::new()?;
    let a = tc.control.store.put_chunk(b"aaa", None)?;
    let b = tc.control.store.put_chunk(b"bbb", None)?;

    let signer = key(7);
    tc.control
        .signature_log
        .sign(&a, None, serde_json::json!({}), &signer)?;
    tc.control
        .signature_log
        .sign(&a, None, serde_json::json!({"second": true}), &signer)?;
    tc.control
        .signature_log
        .sign(&b, None, serde_json::json!({}), &signer)?;

    let before_a = tc.control.signature_log.list_for(&a)?;
    let before_b = tc.control.signature_log.list_for(&b)?;
    assert_eq!((before_a.len(), before_b.len()), (2, 1));

    let count = tc.control.signature_log.rebuild()?;
    assert_eq!(count, 3);

    let mut after_a = tc.control.signature_log.list_for(&a)?;
    let mut sorted_before_a = before_a.clone();
    after_a.sort_by_key(|c| c.to_hex());
    sorted_before_a.sort_by_key(|c| c.to_hex());
    assert_eq!(after_a, sorted_before_a);
    assert_eq!(tc.control.signature_log.list_for(&b)?.len(), 1);
    Ok(())
}

#[test]
fn signing_absent_or_corrupt_content_is_refused() -> Result<()> {
    let tc = TestControl::new()?;
    let signer = key(8);

    let absent = dag_core::Cid::compute(b"never stored");
    assert!(tc
        .control
        .signature_log
        .sign(&absent, None, serde_json::json!({}), &signer)
        .is_err());

    // Corrupt content in place: signing must refuse to bless it. The store
    // itself catches the mismatch on read; sign_cid re-checks in case a store
    // implementation doesn't.
    let cid = tc.control.store.put_chunk(b"was fine", None)?;
    std::fs::write(tc.control.store.chunk_path(&cid), b"rotted")?;
    let err = tc
        .control
        .signature_log
        .sign(&cid, None, serde_json::json!({}), &signer)
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to sign") || msg.contains("mismatch"),
        "corrupt content must not be signable, got: {}",
        msg
    );
    Ok(())
}

/// ADR-004, the other direction: a builder key trusted only for adoption
/// must not add a vote to verification gates like `--min-trusted`.
#[test]
fn an_adopt_only_key_does_not_count_toward_verification() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let control = dag_control::Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);

    let target = control.store.put_chunk(b"artifact", None)?;
    control
        .signature_log
        .sign(&target, None, serde_json::json!({}), &signer)?;
    control.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        Some("builder".into()),
        &[dag_control::TrustPurpose::Adopt],
    )?;

    let statuses = control.signature_log.verify(&target)?;
    assert_eq!(statuses.len(), 1);
    assert!(
        !statuses[0].trusted,
        "adopt-only keys must not earn the trusted verdict in verification"
    );
    assert!(
        statuses[0].valid,
        "the signature itself is still internally valid"
    );

    let for_adoption = control
        .signature_log
        .verify_for(&target, dag_control::TrustPurpose::Adopt)?;
    assert!(
        for_adoption[0].trusted,
        "the same signature is trusted for adoption"
    );
    Ok(())
}

/// The distinct-key count has to hold over the *real* verification pipeline,
/// not only over hand-built `SignatureStatus` values. One trusted key signing
/// the same target twice is one signer — and this is the exact number the
/// CLI's `--min-trusted` gate and the `/api/signatures` top-level `trusted`
/// field both consume. A regression that counted signature entries rather
/// than keys would let a single trusted key satisfy "N independent checkers",
/// and the two-distinct-keys case alone cannot tell the two countings apart.
#[test]
fn distinct_counting_holds_over_real_duplicate_signatures() -> Result<()> {
    use dag_control::signatures::{distinct_trusted_keys, distinct_valid_keys};

    let tc = TestControl::new()?;
    let content = tc.control.store.put_chunk(b"a proof certificate", None)?;

    let signer = key(11);
    tc.control.signature_log.trust_key(
        &pubkey_hex(&signer),
        Some("solo checker".into()),
        &[TrustPurpose::Verify],
    )?;

    // The same key signs twice, differing only in the predicate it carries,
    // so the two signature entries are genuinely distinct on disk.
    tc.control
        .signature_log
        .sign(&content, None, serde_json::json!({"pass": 1}), &signer)?;
    tc.control
        .signature_log
        .sign(&content, None, serde_json::json!({"pass": 2}), &signer)?;

    let statuses = tc.control.signature_log.verify(&content)?;
    assert_eq!(statuses.len(), 2, "both signatures are stored and reported");
    assert!(
        statuses.iter().all(|s| s.trusted && s.valid),
        "both are trusted and valid — they are from the trusted key"
    );
    assert_eq!(
        distinct_trusted_keys(&statuses),
        1,
        "two signatures, one key, one trusted signer"
    );
    assert_eq!(
        distinct_valid_keys(&statuses),
        1,
        "and one valid signer, counted the same way"
    );
    Ok(())
}
