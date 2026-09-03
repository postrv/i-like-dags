//! Job events, from arbitrary bytes — the decode half of a spec recovery.
//!
//! `JobLog::rebuild_from_store` recovers job specs by decoding every chunk in
//! `data/` and keeping whatever parses as a `JobEvent`. Writing a chunk needs
//! no authority in this system (`POST /api/chunks` is unauthenticated by
//! design, `Sync.PutChunk` takes what a peer offers), so this decoder is fed
//! attacker-chosen bytes by construction, and what comes out of it selects a
//! `code_ref` and carries adapter `config`.
//!
//! The chain rules that decide *which* decoded events are adopted are tested
//! in `dag-control/tests/forged_job_event.rs`; what is fuzzed here is the
//! layer below — that decoding is total, and that anything which decodes is
//! internally consistent enough for the chain logic to reason about.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exactly the sequence the store scan performs.
    let Ok(entry) = dag_core::Entry::from_bytes_cbor(data) else {
        return;
    };
    let Ok(event) =
        ciborium::de::from_reader::<dag_control::JobEvent, _>(entry.payload.as_slice())
    else {
        return;
    };

    // Re-encoding must succeed and round-trip. Job events are stored as
    // entries and addressed by CID, so a decoder that accepts something it
    // cannot reproduce would let a chain reference an event that no longer
    // has the name it was filed under.
    let mut re_encoded = Vec::new();
    ciborium::ser::into_writer(&event, &mut re_encoded)
        .expect("a decoded job event did not re-encode");
    let round_tripped: dag_control::JobEvent =
        ciborium::de::from_reader(re_encoded.as_slice()).expect("re-encoded event did not decode");

    // The fields the chain walk and the head rebuild actually read.
    match (&event, &round_tripped) {
        (
            dag_control::JobEvent::Created { spec: a, ts: t1, prev: p1 },
            dag_control::JobEvent::Created { spec: b, ts: t2, prev: p2 },
        )
        | (
            dag_control::JobEvent::Updated { spec: a, ts: t1, prev: p1 },
            dag_control::JobEvent::Updated { spec: b, ts: t2, prev: p2 },
        ) => {
            assert_eq!(a.job_id, b.job_id);
            assert_eq!(a.code_ref, b.code_ref);
            assert_eq!(t1, t2);
            assert_eq!(p1, p2);
            // A `prev` that decoded is a chain link the rebuild will compare
            // against a real event CID, so it has to be a whole CID.
            if let Some(prev) = p1 {
                assert_eq!(prev.as_bytes().len(), dag_core::CID_LEN);
            }
        }
        (
            dag_control::JobEvent::Triggered { reason: a, ts: t1 },
            dag_control::JobEvent::Triggered { reason: b, ts: t2 },
        ) => {
            assert_eq!(a, b);
            assert_eq!(t1, t2);
        }
        (a, b) => panic!("a job event changed variant across a round trip: {a:?} -> {b:?}"),
    }
});
