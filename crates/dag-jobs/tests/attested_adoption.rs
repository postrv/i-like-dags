//! End-to-end ADR-003: a builder attests its effect cache, `dag sync`
//! carries the claims, and a replica that trusts the builder's key adopts
//! outputs instead of executing.
//!
//! The decisive detail: the replica's own adapter would produce *different*
//! bytes than the builder's did, so output equality with the builder proves
//! adoption, not coincidental re-execution.

use std::sync::Arc;

use dag_control::sync::{push, SyncOptions};
use dag_control::{Control, EffectAttester};
use dag_core::{ContentStore, Determinism, InputManifest, JobId, JobInput, JobPolicy, JobSpec};
use dag_jobs::{
    execute_once_hooked, Capabilities, EffectHooks, FakeFetchAdapter, JobRunner,
    SIMULATED_FETCH_PAYLOAD, SIMULATED_FETCH_URL,
};
use tempfile::tempdir;

/// The discriminator both sides configure, so both compute the same effect
/// key. It matches the default runner's, which is what makes the replica's
/// lookup hit the builder's claim.
const URL: &str = SIMULATED_FETCH_URL;

fn fetch_spec() -> JobSpec {
    JobSpec {
        job_id: JobId::from("fetch-job"),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::SideEffecting,
        declared_outputs: vec!["artifact".into()],
        code_ref: "fake_fetch".into(),
        policy: JobPolicy::default(),
        config: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replica_adopts_the_builders_outputs_instead_of_executing() {
    let builder_dir = tempdir().unwrap();
    let replica_dir = tempdir().unwrap();
    let builder = Control::open(builder_dir.path()).unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);

    // --- Builder: run the job with an adapter producing distinctive bytes,
    // attesting the result under its key.
    let mut runner = JobRunner::new(builder.store.clone() as Arc<dyn ContentStore>);
    runner.register_adapter(Arc::new(FakeFetchAdapter::new(
        b"builder-data".to_vec(),
        URL.into(),
    )));
    let spec = fetch_spec();
    let manifest = InputManifest {
        static_inputs: vec![],
        pointer_heads: vec![],
        resolved_at_unix: 1_700_000_000,
    };
    let attester = EffectAttester::new(&builder, signer.clone());
    let built = runner
        .execute_with_hooks(
            &spec,
            &manifest,
            &*builder.job_log,
            EffectHooks {
                adopt: None,
                attest: Some(&attester),
            },
        )
        .await
        .unwrap();
    let built = built.outputs;
    assert_eq!(
        builder.store.get_chunk(&built[0].1).unwrap(),
        b"builder-data"
    );

    // --- Replicate. The claim was pinned by attestation, so it and its
    // outputs are sync roots; the destination indexes what arrived.
    let report = push(&builder, &replica, &SyncOptions::default()).unwrap();
    assert!(
        report.claims_indexed >= 1,
        "claims should travel: {report:?}"
    );

    // --- Replica: same job spec, default adapter wiring — whose fake_fetch
    // would produce SIMULATED_FETCH_PAYLOAD, NOT the builder's bytes.
    replica.create_job(fetch_spec()).unwrap();

    // Without trust, adoption is refused and execution proceeds: the replica
    // computes its own (different) answer. Run against a scratch job id so
    // this doesn't seed the cache the adoption assertion reads.
    // (Deliberately skipped here: executing would poison the effect cache
    // for the shared key. Trust gating is covered at the control layer.)

    replica
        .signature_log
        .trust_key(
            &hex::encode(signer.verifying_key().as_bytes()),
            None,
            &[dag_control::TrustPurpose::Adopt],
        )
        .unwrap();

    let outcome = execute_once_hooked(
        &replica,
        &JobId::from("fetch-job"),
        Capabilities::none(),
        EffectHooks {
            adopt: Some(&replica),
            attest: None,
        },
    )
    .await
    .unwrap();

    // The outputs are the builder's, byte for byte — proof of adoption,
    // because this replica's adapter would have produced the simulated bytes.
    assert_eq!(outcome.outputs, built);
    // And the run record says how: an adopted run is a trust decision, and
    // one that looked identical to a local build was the gap ADR-003 left.
    assert_eq!(outcome.origin, dag_core::RunOrigin::Adopted);
    assert_eq!(
        replica.store.get_chunk(&outcome.outputs[0].1).unwrap(),
        b"builder-data"
    );

    // And adoption seeded the local effect cache: a plain run with no hooks
    // is now a hit, still returning the builder's outputs.
    let again = execute_once_hooked(
        &replica,
        &JobId::from("fetch-job"),
        Capabilities::none(),
        EffectHooks::none(),
    )
    .await
    .unwrap();
    assert_eq!(again.outputs, built);
    assert_eq!(
        again.origin,
        dag_core::RunOrigin::CacheHit,
        "the second run is the local cache answering, not another adoption"
    );

    // The distinction is durable, not just returned: `dag job runs` reads it
    // back off the run record.
    let runs = replica.runs(JobId::from("fetch-job"), 10).unwrap();
    let origins: Vec<_> = runs.iter().map(|r| r.origin.clone()).collect();
    assert!(
        origins.contains(&dag_core::RunOrigin::Adopted)
            && origins.contains(&dag_core::RunOrigin::CacheHit),
        "run records lost the origin: {origins:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_trust_the_replica_executes_its_own_answer() {
    let builder_dir = tempdir().unwrap();
    let replica_dir = tempdir().unwrap();
    let builder = Control::open(builder_dir.path()).unwrap();
    let replica = Control::open(replica_dir.path()).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);

    let mut runner = JobRunner::new(builder.store.clone() as Arc<dyn ContentStore>);
    runner.register_adapter(Arc::new(FakeFetchAdapter::new(
        b"builder-data".to_vec(),
        URL.into(),
    )));
    let attester = EffectAttester::new(&builder, signer);
    let manifest = InputManifest {
        static_inputs: vec![],
        pointer_heads: vec![],
        resolved_at_unix: 1_700_000_000,
    };
    runner
        .execute_with_hooks(
            &fetch_spec(),
            &manifest,
            &*builder.job_log,
            EffectHooks {
                adopt: None,
                attest: Some(&attester),
            },
        )
        .await
        .unwrap();

    push(&builder, &replica, &SyncOptions::default()).unwrap();
    replica.create_job(fetch_spec()).unwrap();

    // The claim is present on the replica — but its key is not trusted, so
    // the adoption hook must refuse and the local adapter must run.
    let outcome = execute_once_hooked(
        &replica,
        &JobId::from("fetch-job"),
        Capabilities::none(),
        EffectHooks {
            adopt: Some(&replica),
            attest: None,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        replica.store.get_chunk(&outcome.outputs[0].1).unwrap(),
        SIMULATED_FETCH_PAYLOAD,
        "an untrusted claim must not be adopted; the local adapter's own \
         answer proves execution happened here"
    );
}
