//! Signatures must follow the retention of what they sign.
//!
//! Found live during the 2026-08 end-to-end pass: sign a pinned release, run
//! routine collection, and the signature entry vanished — the subtree pin
//! walks *down* from the attestation, but the signature points *at* it, so
//! nothing retained it. `dag verify` then failed with `Chunk not found`
//! (exit 66) instead of reporting what was lost. The flagship claim — "a
//! regulator can verify who approved this" — broke on the first collection
//! after signing.
//!
//! The retention rule these tests pin: a signature entry whose target is
//! protected is protected too, transitively (a counter-signature on a
//! protected signature stays as well). A signature on collectable content
//! falls with it — evidence about nothing retains nothing.

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::{GcRequest, TrustPurpose};
use dag_core::{ContentStore, PinScope, PinTarget};
use dag_storage::GcCapableStore;
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}

/// Satisfy the M6 recovery gate so `run_gc` will proceed.
fn recovered(tc: &TestControl) -> Result<()> {
    tc.control.recovery_state.mark_complete_for_test()?;
    Ok(())
}

fn request() -> GcRequest {
    GcRequest {
        node_id: "local".into(),
        dry_run: false,
        max_delete: 0,
        min_age_secs: 0,
        system_protection: true,
    }
}

#[test]
fn a_signature_on_pinned_content_survives_collection() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let content = tc.control.store.put_chunk(b"release artefact", None)?;
    tc.control.pin_log.create(
        "release/v1",
        PinTarget::Direct(content.clone()),
        PinScope::Global,
        None,
        Some("test".into()),
    )?;

    let signer = key(1);
    tc.control.signature_log.trust_key(
        &pubkey_hex(&signer),
        Some("release manager".into()),
        &[TrustPurpose::Verify],
    )?;
    let sig_cid = tc.control.signature_log.sign(
        &content,
        Some("artefact".into()),
        serde_json::json!({"note": "approved"}),
        &signer,
    )?;

    tc.control.run_gc(&request())?;

    assert!(
        tc.control.store.get_chunk(&sig_cid).is_ok(),
        "collection took the signature off pinned content"
    );
    let statuses = tc.control.signature_log.verify(&content)?;
    assert_eq!(statuses.len(), 1);
    assert!(
        statuses[0].trusted,
        "the surviving signature must still verify as trusted"
    );
    Ok(())
}

/// The upper bound: retention must not widen to signatures on content
/// nothing retains. When the target is collectable, its signature goes
/// with it.
#[test]
fn a_signature_on_collectable_content_falls_with_it() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let content = tc.control.store.put_chunk(b"scratch output", None)?;
    let sig_cid = tc
        .control
        .signature_log
        .sign(&content, None, serde_json::json!({}), &key(2))?;

    tc.control.run_gc(&request())?;

    assert!(
        tc.control.store.get_chunk(&content).is_err(),
        "unpinned content should have been collected"
    );
    assert!(
        tc.control.store.get_chunk(&sig_cid).is_err(),
        "a signature on collected content should be collected with it"
    );
    Ok(())
}

/// A counter-signature vouches for a signature. If the base signature is
/// protected (because its target is), the counter-signature must be too —
/// the rule is transitive, not one level deep.
#[test]
fn a_countersignature_on_a_protected_signature_is_protected() -> Result<()> {
    let tc = TestControl::new()?;
    recovered(&tc)?;

    let content = tc.control.store.put_chunk(b"release artefact", None)?;
    tc.control.pin_log.create(
        "release/v1",
        PinTarget::Direct(content.clone()),
        PinScope::Global,
        None,
        Some("test".into()),
    )?;

    let sig_cid = tc
        .control
        .signature_log
        .sign(&content, None, serde_json::json!({}), &key(3))?;
    let counter_cid =
        tc.control
            .signature_log
            .sign(&sig_cid, None, serde_json::json!({}), &key(4))?;

    tc.control.run_gc(&request())?;

    assert!(
        tc.control.store.get_chunk(&sig_cid).is_ok(),
        "the base signature is on pinned content and must survive"
    );
    assert!(
        tc.control.store.get_chunk(&counter_cid).is_ok(),
        "the counter-signature covers a protected signature and must survive"
    );
    Ok(())
}

/// The degradation half: when a signature entry is gone but the index still
/// names it — a directory that collected before this fix, or lost the chunk
/// any other way — `verify` must report the loss, not fail with a raw
/// `Chunk not found` that hides which signatures *do* survive.
#[test]
fn verify_reports_a_missing_signature_instead_of_erroring() -> Result<()> {
    let tc = TestControl::new()?;

    let content = tc.control.store.put_chunk(b"content", None)?;
    let signer = key(5);
    tc.control
        .signature_log
        .trust_key(&pubkey_hex(&signer), None, &[TrustPurpose::Verify])?;
    let gone = tc
        .control
        .signature_log
        .sign(&content, None, serde_json::json!({}), &signer)?;
    let kept = tc.control.signature_log.sign(
        &content,
        None,
        serde_json::json!({"note": "second"}),
        &signer,
    )?;

    tc.control.store.delete_chunk(&gone)?;

    let statuses = tc.control.signature_log.verify(&content)?;
    assert_eq!(statuses.len(), 2, "both index entries must be reported");

    let missing = statuses
        .iter()
        .find(|s| s.signature_cid == gone)
        .expect("the missing signature must still appear in the report");
    assert!(!missing.trusted, "a missing signature proves nothing");
    assert!(!missing.valid);
    assert_eq!(missing.key_id, "<missing>");

    let survivor = statuses
        .iter()
        .find(|s| s.signature_cid == kept)
        .expect("the surviving signature must be reported");
    assert!(
        survivor.trusted,
        "one lost signature must not take down the survivors"
    );

    // The export path skips what it cannot read, per its contract.
    let records = tc.control.signature_log.records_for(&content)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, kept);
    Ok(())
}
