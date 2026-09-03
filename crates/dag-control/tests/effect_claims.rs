//! Attested effect claims (ADR-003): a signed cache entry a replica can
//! adopt instead of re-executing — if, and only if, it trusts the builder.

use anyhow::Result;
use dag_control::integration::PinCreator;
use dag_control::sync::{push, SyncOptions};
use dag_control::{Control, GcRequest, TrustPurpose};
use dag_core::{Cid, ContentStore, EffectKey, JobId, PinScope, PinTarget};
use tempfile::tempdir;

fn key_for(job: &str, spec: &str) -> EffectKey {
    EffectKey::new(
        JobId::from(job.to_string()),
        Cid::compute(b"manifest"),
        spec.to_string(),
    )
}

fn store_outputs(control: &Control) -> Vec<(String, Cid)> {
    let a = control.store.put_chunk(b"artifact-bytes", None).unwrap();
    let b = control.store.put_chunk(b"log-bytes", None).unwrap();
    vec![("artifact".into(), a), ("log".into(), b)]
}

#[test]
fn attest_stores_signs_indexes_and_pins_idempotently() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let key = key_for("job-a", "spec-a");
    let outputs = store_outputs(&control);

    let claim_cid = control.attest_effect(&key, &outputs, &signer)?;

    // Indexed under the effect key.
    assert_eq!(
        control.job_log.claims_for_key(&key)?,
        vec![claim_cid.clone()]
    );
    // Signed: at least one signature covers the claim entry.
    assert!(!control.signature_log.list_for(&claim_cid)?.is_empty());
    // Pinned as a subtree, so sync and GC treat the claim and its outputs as
    // roots. ensure_pin's contract: false means the pin already existed.
    let created = PinCreator::ensure_pin(
        &*control.pin_log,
        &format!("effect/{}", claim_cid.to_hex()),
        PinTarget::Subtree {
            root: claim_cid.clone(),
            max_depth: None,
        },
        PinScope::Global,
        None,
    )?;
    assert!(
        !created,
        "attest_effect should have pinned the claim already"
    );

    // Attesting the same claim again is a complete no-op: same entry CID,
    // still exactly one index row, one signature (Ed25519 is deterministic).
    let again = control.attest_effect(&key, &outputs, &signer)?;
    assert_eq!(again, claim_cid);
    assert_eq!(control.job_log.claims_for_key(&key)?.len(), 1);
    assert_eq!(control.signature_log.list_for(&claim_cid)?.len(), 1);
    Ok(())
}

#[test]
fn attest_refuses_outputs_that_are_not_in_the_store() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let key = key_for("job-a", "spec-a");
    let absent = Cid::compute(b"never stored");
    let result = control.attest_effect(&key, &[("artifact".into(), absent)], &signer);
    assert!(
        result.is_err(),
        "a claim over absent outputs is an attestation nobody could check"
    );
    Ok(())
}

#[test]
fn attest_publishes_retention_before_a_saturated_claim_index_can_fail() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    control.recover()?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let key = key_for("job-a", "saturated-index");
    let outputs = store_outputs(&control);
    let entry = dag_control::effects::claim_entry(&key, &outputs);
    let claim_cid = Cid::compute(&entry.to_bytes_cbor()?);

    // Fill the derived accelerator to its supported per-key ceiling. The
    // following attestation must fail at indexing, after storing the claim.
    let existing = (0..dag_control::job::MAX_EFFECT_CLAIMS_PER_KEY)
        .map(|index| Cid::compute(format!("prior-claim-{index}").as_bytes()))
        .collect();
    control
        .job_log
        .replace_claims(std::collections::HashMap::from([(
            key.to_binary_key(),
            existing,
        )]))?;

    let error = control
        .attest_effect(&key, &outputs, &signer)
        .expect_err("a saturated derived claim row must refuse another index entry");
    assert!(error.to_string().contains("maximum"), "{error}");

    // The pin is primary retention state and must already exist. Retrying the
    // idempotent ensure operation therefore reports that it created nothing.
    let created = PinCreator::ensure_pin(
        &*control.pin_log,
        &format!("effect/{}", claim_cid.to_hex()),
        PinTarget::Subtree {
            root: claim_cid.clone(),
            max_depth: None,
        },
        PinScope::Global,
        None,
    )?;
    assert!(!created, "retention must precede the fallible index write");

    // Exercise the real destructive boundary: neither the stored claim nor
    // either promised output may be offered for collection after that error.
    control.run_gc(&GcRequest {
        node_id: "test-node".into(),
        dry_run: false,
        max_delete: 100_000,
        min_age_secs: 0,
        system_protection: true,
    })?;
    assert!(control.store.has_chunk(&claim_cid)?);
    for (_, output) in outputs {
        assert!(control.store.has_chunk(&output)?);
    }
    Ok(())
}

#[test]
fn adoption_requires_a_trusted_key() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let key = key_for("job-a", "spec-a");
    let outputs = store_outputs(&control);
    control.attest_effect(&key, &outputs, &signer)?;

    // The claim exists, is internally valid, and its outputs are present —
    // but the key is not trusted here, so adoption must refuse.
    assert_eq!(control.adopt_attested(&key)?, None);

    control.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        None,
        &[TrustPurpose::Adopt],
    )?;
    assert_eq!(control.adopt_attested(&key)?, Some(outputs));
    Ok(())
}

#[test]
fn adoption_budget_exhaustion_is_a_safe_cache_miss() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let key = key_for("job-a", "signature-fan-in");
    let outputs = store_outputs(&control);
    let claim_entry = dag_control::effects::claim_entry(&key, &outputs);
    let claim_cid = control.store.put_entry(&claim_entry)?;
    control
        .job_log
        .index_claim(&key.to_binary_key(), &claim_cid)?;

    // Schema-shaped but unverifiable records are ordinary untrusted content.
    // Recovery may index them for an explicit INVALID verdict, but adoption
    // must stop at its aggregate budget and fall back to execution (None), not
    // allocate/verify the full per-target index or fail the job.
    for index in 0..=dag_control::signatures::MAX_SIGNATURE_AGGREGATE_RECORDS {
        let record = dag_core::signing::SignatureRecord {
            kind: dag_core::signing::SIGNATURE_KIND.into(),
            key_id: format!("invalid-{index}"),
            public_key: "00".into(),
            envelope: dag_core::signing::Envelope {
                payload: "e30=".into(),
                payload_type: dag_core::signing::PAYLOAD_TYPE.into(),
                signatures: Vec::new(),
            },
        };
        control.store.put_entry(&dag_core::Entry::new(
            serde_json::to_vec(&record)?,
            vec![dag_core::Link::named(claim_cid.clone(), "signs")],
            None,
        ))?;
    }
    control.signature_log.rebuild()?;

    assert_eq!(
        control.adopt_attested(&key)?,
        None,
        "untrusted evidence volume must degrade to ordinary execution"
    );
    Ok(())
}

#[test]
fn adoption_rejects_a_claim_indexed_under_the_wrong_key() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    control.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        None,
        &[TrustPurpose::Adopt],
    )?;

    let key = key_for("job-a", "spec-a");
    let outputs = store_outputs(&control);
    let claim_cid = control.attest_effect(&key, &outputs, &signer)?;

    // Poison the index: file the same claim under a different effect key.
    // Adoption must re-check the claim's own key against the request and
    // refuse, rather than trusting the index.
    let other = key_for("job-b", "spec-b");
    control
        .job_log
        .index_claim(&other.to_binary_key(), &claim_cid)?;
    assert_eq!(control.adopt_attested(&other)?, None);
    Ok(())
}

#[test]
fn adoption_requires_the_output_content_to_be_present_and_intact() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    control.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        None,
        &[TrustPurpose::Adopt],
    )?;

    // Build the claim by hand so it can name an output that is not stored:
    // the trusted signature is genuine, but the bytes it promises are absent.
    let key = key_for("job-a", "spec-a");
    let absent = Cid::compute(b"never stored");
    let entry = dag_control::effects::claim_entry(&key, &[("artifact".into(), absent)]);
    let claim_cid = control.store.put_entry(&entry)?;
    control
        .job_log
        .index_claim(&key.to_binary_key(), &claim_cid)?;
    control.signature_log.sign(
        &claim_cid,
        Some("effect-claim".into()),
        serde_json::json!({}),
        &signer,
    )?;

    assert_eq!(
        control.adopt_attested(&key)?,
        None,
        "a trusted claim whose outputs are absent must not be adopted"
    );
    Ok(())
}

#[test]
fn claims_travel_with_sync_and_a_replica_can_adopt() -> Result<()> {
    let builder_dir = tempdir()?;
    let replica_dir = tempdir()?;
    let builder = Control::open(builder_dir.path())?;
    let replica = Control::open(replica_dir.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);

    let key = key_for("vdw33/shard", "lean-config");
    let outputs = store_outputs(&builder);
    builder.attest_effect(&key, &outputs, &signer)?;

    let report = push(&builder, &replica, &SyncOptions::default())?;
    assert!(
        report.claims_indexed >= 1,
        "the destination should index transferred claims, got {:?}",
        report
    );

    // Trust does not travel: before the replica trusts the builder's key,
    // the transferred claim earns nothing.
    assert_eq!(replica.adopt_attested(&key)?, None);

    replica.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        None,
        &[TrustPurpose::Adopt],
    )?;
    let adopted = replica.adopt_attested(&key)?;
    assert_eq!(adopted, Some(outputs.clone()));

    // And the outputs genuinely arrived: the subtree pin made them roots.
    for (_, cid) in &outputs {
        assert_eq!(replica.store.get_chunk(cid)?, builder.store.get_chunk(cid)?);
    }
    Ok(())
}

#[test]
fn rebuild_reconstructs_the_claim_index_from_the_store() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let key = key_for("job-a", "spec-a");
    let outputs = store_outputs(&control);
    let claim_cid = control.attest_effect(&key, &outputs, &signer)?;

    // Wipe the index the blunt way: file the claim under a bogus key only.
    // rebuild must restore the true mapping from the entries themselves.
    let rebuilt = control.rebuild_effect_claims()?;
    assert_eq!(rebuilt, 1);
    assert_eq!(control.job_log.claims_for_key(&key)?, vec![claim_cid]);
    Ok(())
}

/// ADR-004: adoption needs a key trusted *for adoption*. A verify-only
/// grant — the default, and the meaning of every pre-ADR-004 entry —
/// leaves the claim exactly as trustworthy as it was: usable as evidence,
/// not as a substitute for execution.
#[test]
fn adoption_requires_the_adopt_purpose() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let key = key_for("job-a", "spec-a");
    let outputs = store_outputs(&control);
    control.attest_effect(&key, &outputs, &signer)?;

    // Trusted with the default grant: verification only.
    control.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        None,
        &[TrustPurpose::Verify],
    )?;
    assert_eq!(
        control.adopt_attested(&key)?,
        None,
        "a verify-only grant must not permit adoption"
    );

    // The wider grant is an explicit re-trust; the entry is replaced.
    control.signature_log.trust_key(
        &hex::encode(signer.verifying_key().as_bytes()),
        None,
        &[TrustPurpose::Verify, TrustPurpose::Adopt],
    )?;
    assert_eq!(control.adopt_attested(&key)?, Some(outputs));
    Ok(())
}
