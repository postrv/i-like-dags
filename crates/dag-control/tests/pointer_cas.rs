//! Compare-and-set pointer updates (ADR-005 decision 3).
//!
//! The CAS is what makes a *remote* write safe: the primary serializes
//! writers, and an update whose expectation is stale is refused with the
//! actual head named, so the caller re-reads instead of silently clobbering
//! a concurrent write.

use dag_control::pointer::PointerError;
use dag_control::test_utils::TestControl;
use dag_core::{Cid, ContentStore};
use std::sync::Arc;

fn put(tc: &TestControl, bytes: &[u8]) -> Cid {
    tc.control.store.put_chunk(bytes, None).unwrap()
}

#[test]
fn expect_zero_creates_and_a_matching_expectation_advances() {
    let tc = TestControl::new().unwrap();
    let v1 = put(&tc, b"one");
    let v2 = put(&tc, b"two");

    let seq = tc
        .control
        .pointer_log
        .update_cas("p", v1.clone(), 0)
        .unwrap();
    assert_eq!(seq, 1);
    assert_eq!(tc.control.pointer_log.resolve("p").unwrap(), v1);

    let seq = tc
        .control
        .pointer_log
        .update_cas("p", v2.clone(), 1)
        .unwrap();
    assert_eq!(seq, 2);
    assert_eq!(tc.control.pointer_log.resolve("p").unwrap(), v2);
}

#[test]
fn a_stale_expectation_is_refused_naming_the_actual_head() {
    let tc = TestControl::new().unwrap();
    let v1 = put(&tc, b"one");
    let v2 = put(&tc, b"two");
    let v3 = put(&tc, b"three");

    tc.control.pointer_log.create("p", v1).unwrap();
    tc.control.pointer_log.update("p", v2.clone()).unwrap(); // head is now seq 2

    let err = tc.control.pointer_log.update_cas("p", v3, 1).unwrap_err();
    match &err {
        PointerError::CasConflict {
            pointer_id,
            expected,
            actual,
            actual_cid,
        } => {
            assert_eq!(pointer_id, "p");
            assert_eq!(*expected, 1);
            assert_eq!(*actual, 2);
            assert_eq!(actual_cid, &v2.to_hex());
        }
        other => panic!("expected CasConflict, got {other}"),
    }
    // The refusal names enough to retry without another round trip.
    let msg = err.to_string();
    assert!(msg.contains("seq 2"), "{msg}");
    assert!(msg.contains("not 1"), "{msg}");

    // Nothing moved.
    let head = tc.control.pointer_log.get_head("p").unwrap();
    assert_eq!(head.seq, 2);
    assert_eq!(head.current_cid, v2);
}

#[test]
fn expect_zero_against_an_existing_pointer_is_a_conflict_not_already_exists() {
    let tc = TestControl::new().unwrap();
    let v1 = put(&tc, b"one");
    let v2 = put(&tc, b"two");

    tc.control.pointer_log.create("p", v1).unwrap();

    let err = tc.control.pointer_log.update_cas("p", v2, 0).unwrap_err();
    assert!(
        matches!(
            err,
            PointerError::CasConflict {
                expected: 0,
                actual: 1,
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn an_expectation_for_a_pointer_that_does_not_exist_is_not_found() {
    let tc = TestControl::new().unwrap();
    let v = put(&tc, b"value");

    let err = tc
        .control
        .pointer_log
        .update_cas("ghost", v, 3)
        .unwrap_err();
    assert!(matches!(err, PointerError::NotFound(_)), "{err}");
}

#[test]
fn concurrent_writers_with_the_same_expectation_cannot_both_win() {
    let tc = TestControl::new().unwrap();
    let v1 = put(&tc, b"base");
    tc.control.pointer_log.create("p", v1).unwrap();

    let control = Arc::new(tc.control);
    let mut candidates = Vec::new();
    for i in 0..16 {
        candidates.push(
            control
                .store
                .put_chunk(format!("candidate {i}").as_bytes(), None)
                .unwrap(),
        );
    }

    let mut handles = Vec::new();
    for cid in candidates {
        let control = control.clone();
        handles.push(std::thread::spawn(move || {
            control.pointer_log.update_cas("p", cid, 1)
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let wins = results.iter().filter(|r| r.is_ok()).count();
    let conflicts = results
        .iter()
        .filter(|r| matches!(r, Err(PointerError::CasConflict { .. })))
        .count();

    assert_eq!(wins, 1, "CAS admitted {wins} writers past the same head");
    assert_eq!(conflicts, 15);
    assert_eq!(control.pointer_log.get_head("p").unwrap().seq, 2);
}

#[test]
fn plain_update_still_appends_without_an_expectation() {
    // The CAS is opt-in: local `pointer update` keeps last-write-wins
    // append semantics, unchanged.
    let tc = TestControl::new().unwrap();
    let v1 = put(&tc, b"one");
    let v2 = put(&tc, b"two");
    let v3 = put(&tc, b"three");

    tc.control.pointer_log.create("p", v1).unwrap();
    tc.control.pointer_log.update("p", v2).unwrap();
    tc.control.pointer_log.update("p", v3.clone()).unwrap();
    assert_eq!(tc.control.pointer_log.get_head("p").unwrap().seq, 3);
    assert_eq!(tc.control.pointer_log.resolve("p").unwrap(), v3);
}
