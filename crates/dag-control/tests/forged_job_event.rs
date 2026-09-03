//! A job spec must not be rewritable by anyone who can write a chunk.
//!
//! `JobLog::rebuild_from_store` recovers job specs by decoding chunks, which
//! is the only way to get them back after a lost `control.redb`. It used to
//! order a job's recovered events by their `ts` field — a number chosen by
//! whoever wrote the chunk. Writing a chunk needs no authority in this system:
//! `POST /api/chunks` is unauthenticated by design, `Sync.PutChunk` accepts
//! whatever a peer offers, and a sync source sends what it likes. So a single
//! planted `Updated { ts: i64::MAX }` sorted last, won, and became the spec —
//! `code_ref` and adapter `config` both — the next time an operator recovered.
//!
//! That is the closest thing this system has to remote code selection, and it
//! landed through the recovery path, which is exactly when an operator is
//! least able to notice.

use dag_control::test_utils::TestControl;
use dag_control::JobEvent;
use dag_core::{
    CachePolicy, Cid, ContentStore, Determinism, Entry, JobId, JobInput, JobPolicy, JobSpec,
    TriggerPolicy,
};

fn spec(id: &str, code_ref: &str) -> JobSpec {
    JobSpec {
        job_id: JobId::from(id),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::Deterministic,
        declared_outputs: vec![],
        code_ref: code_ref.into(),
        policy: JobPolicy {
            cache_outputs: CachePolicy::None,
            trigger: TriggerPolicy::Manual,
        },
        config: None,
    }
}

/// Write a job event straight into the content store, the way anything with
/// chunk-write access can.
fn plant(tc: &TestControl, event: &JobEvent) -> Cid {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(event, &mut payload).unwrap();
    tc.control
        .store
        .put_entry(&Entry::with_payload(payload))
        .unwrap()
}

#[test]
fn a_planted_update_does_not_become_the_recovered_spec() {
    let tc = TestControl::new().unwrap();
    let id = JobId::from("release-build");
    tc.control
        .create_job(spec("release-build", "hash"))
        .unwrap();

    // The forgery: same job, hostile code_ref, dated past the heat death of
    // anything, chained to nothing because the attacker has no event to chain
    // to.
    plant(
        &tc,
        &JobEvent::Updated {
            spec: spec("release-build", "exec"),
            ts: i64::MAX,
            prev: None,
        },
    );

    let report = tc.control.rebuild_jobs_from_store().unwrap();

    let head = tc.control.job_log.get_job(&id).unwrap().unwrap();
    assert_eq!(
        head.spec.code_ref, "hash",
        "a chunk anyone can write rewrote the job's code_ref"
    );
    assert_eq!(head.seq, 1, "the forged event was filed as history");

    // And the refusal is reported rather than swallowed: an operator running
    // recovery has to be able to see that something in `data/` claimed to be
    // their job.
    assert!(
        report.skipped.iter().any(|s| s.contains("release-build")),
        "the refusal was not reported: {:?}",
        report.skipped
    );
    assert_eq!(report.events_skipped, 2, "the whole job is refused, not the forgery alone — with two candidate roots the log no longer says one thing");
}

#[test]
fn a_planted_second_created_does_not_replace_the_spec() {
    let tc = TestControl::new().unwrap();
    let id = JobId::from("release-build");
    tc.control
        .create_job(spec("release-build", "hash"))
        .unwrap();

    plant(
        &tc,
        &JobEvent::Created {
            spec: spec("release-build", "exec"),
            ts: i64::MAX,
            prev: None,
        },
    );

    tc.control.rebuild_jobs_from_store().unwrap();

    assert_eq!(
        tc.control
            .job_log
            .get_job(&id)
            .unwrap()
            .unwrap()
            .spec
            .code_ref,
        "hash"
    );
}

/// Grafting onto the real chain is refused too: even an attacker who has
/// learned the head event's CID produces a fork, not a successor, because the
/// honest update is already there.
#[test]
fn a_graft_onto_the_real_head_forks_and_is_refused() {
    let tc = TestControl::new().unwrap();
    let id = JobId::from("release-build");
    tc.control
        .create_job(spec("release-build", "hash"))
        .unwrap();
    tc.control
        .update_job(spec("release-build", "concat"))
        .unwrap();

    // The CID of the Created event, which is what the honest Updated chains
    // to — the best case for an attacker, and still not enough.
    let root_cid = tc
        .control
        .job_log
        .event_cids()
        .unwrap()
        .into_iter()
        .find(|(job, seq, _)| job == "release-build" && *seq == 1)
        .map(|(_, _, cid)| cid)
        .unwrap();

    plant(
        &tc,
        &JobEvent::Updated {
            spec: spec("release-build", "exec"),
            ts: i64::MAX,
            prev: Some(root_cid),
        },
    );

    let report = tc.control.rebuild_jobs_from_store().unwrap();

    assert_eq!(
        tc.control
            .job_log
            .get_job(&id)
            .unwrap()
            .unwrap()
            .spec
            .code_ref,
        "concat"
    );
    assert!(
        report.skipped.iter().any(|s| s.contains("forks")),
        "expected a fork refusal: {:?}",
        report.skipped
    );
}

/// The positive control: refusing everything would pass all of the above, so
/// pin the case that must still work — an honest chain recovers, in chain
/// order, with nothing skipped.
#[test]
fn an_honest_chain_still_recovers_in_order() {
    let tc = TestControl::new().unwrap();
    let id = JobId::from("evolving");
    tc.control.create_job(spec("evolving", "hash")).unwrap();
    tc.control.update_job(spec("evolving", "concat")).unwrap();
    tc.control.update_job(spec("evolving", "echo")).unwrap();

    let report = tc.control.rebuild_jobs_from_store().unwrap();
    assert_eq!(report.events_skipped, 0, "{:?}", report.skipped);
    assert_eq!(report.heads_rebuilt, 1);

    let head = tc.control.job_log.get_job(&id).unwrap().unwrap();
    assert_eq!(head.spec.code_ref, "echo", "the newest spec in chain order");
    assert_eq!(head.seq, 3);
}

/// The chain must decide the order, not the clock. An honest deployment whose
/// system time went backwards between two updates — an NTP correction, a VM
/// restored from a snapshot — must still recover the later spec.
#[test]
fn a_backwards_clock_does_not_reorder_history() {
    let tc = TestControl::new().unwrap();
    let id = JobId::from("evolving");
    tc.control.create_job(spec("evolving", "hash")).unwrap();

    // Chain a second event by hand so its timestamp predates the first, which
    // is what a clock stepping backwards produces.
    let root_cid = tc
        .control
        .job_log
        .event_cids()
        .unwrap()
        .into_iter()
        .find(|(job, seq, _)| job == "evolving" && *seq == 1)
        .map(|(_, _, cid)| cid)
        .unwrap();
    plant(
        &tc,
        &JobEvent::Updated {
            spec: spec("evolving", "concat"),
            ts: 0,
            prev: Some(root_cid),
        },
    );

    let report = tc.control.rebuild_jobs_from_store().unwrap();
    assert_eq!(report.events_skipped, 0, "{:?}", report.skipped);
    assert_eq!(
        tc.control
            .job_log
            .get_job(&id)
            .unwrap()
            .unwrap()
            .spec
            .code_ref,
        "concat",
        "the chain, not the timestamp, orders history"
    );
}
