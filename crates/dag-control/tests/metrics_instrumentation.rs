//! The metrics registry observes real work: store I/O, collection, sync
//! imports, and everything crossing the event bus.

use dag_control::test_utils::TestControl;
use dag_core::{Cid, ContentStore, PinScope, PinTarget};

fn put(tc: &TestControl, bytes: &[u8]) -> Cid {
    tc.control.store.put_chunk(bytes, None).unwrap()
}

#[test]
fn store_io_is_counted_timed_and_sized() {
    let tc = TestControl::new().unwrap();
    let m = &tc.control.metrics;

    let cid = put(&tc, b"twelve bytes");
    let bytes = tc.control.store.get_chunk(&cid).unwrap();
    assert_eq!(bytes.len(), 12);

    assert_eq!(m.store_put_total.get(), 1);
    assert_eq!(m.store_put_bytes_total.get(), 12);
    assert_eq!(m.store_put_seconds.count(), 1);
    assert_eq!(m.store_get_total.get(), 1);
    assert_eq!(m.store_get_bytes_total.get(), 12);
    assert_eq!(m.store_get_seconds.count(), 1);

    // A failed read is timed but not counted as served.
    let absent = Cid::compute(b"never stored");
    assert!(tc.control.store.get_chunk(&absent).is_err());
    assert_eq!(m.store_get_total.get(), 1);
    assert_eq!(m.store_get_seconds.count(), 2);
}

#[test]
fn a_collection_records_its_shape_and_a_refusal_counts_apart() {
    let tc = TestControl::new().unwrap();
    let m = &tc.control.metrics;

    // Before recovery is marked, collection is refused at the gate.
    let req = dag_control::GcRequest {
        min_age_secs: 0,
        ..Default::default()
    };
    assert!(tc.control.run_gc(&req).is_err());
    assert_eq!(m.gc_refused_total.get(), 1);
    assert_eq!(m.gc_runs_total.get(), 0);

    // Test-only shortcut for the complete pointer/retention/safety gate.
    tc.control.recovery_state.mark_complete_for_test().unwrap();

    let keep = put(&tc, b"pinned survivor");
    tc.control
        .pin_log
        .create(
            "keep",
            PinTarget::Direct(keep),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();
    put(&tc, b"unreferenced and collectable");

    let report = tc.control.run_gc(&req).unwrap();
    assert_eq!(m.gc_runs_total.get(), 1);
    assert_eq!(m.gc_refused_total.get(), 1, "the refusal count moved");
    assert!(m.gc_examined_total.get() >= 2);
    assert_eq!(m.gc_deleted_total.get(), report.chunks_deleted as u64);
    assert_eq!(m.gc_bytes_freed_total.get(), report.bytes_freed as u64);
    assert_eq!(m.gc_seconds.count(), 1);
}

#[test]
fn a_sync_destination_counts_receipts_imports_and_refusals() {
    let src = TestControl::new().unwrap();
    let dst = TestControl::new().unwrap();

    let v1 = put(&src, b"one");
    src.control.pointer_log.create("p", v1).unwrap();

    dag_control::sync::push(
        &src.control,
        &dst.control,
        &dag_control::SyncOptions::default(),
    )
    .unwrap();

    let m = &dst.control.metrics;
    assert!(m.sync_chunks_received_total.get() >= 2); // content + event entry
    assert!(m.sync_bytes_received_total.get() > 0);
    assert_eq!(m.sync_events_imported_total.get(), 1);
    assert_eq!(m.sync_events_refused_total.get(), 0);
    // The source pushed; nothing arrived *at* it.
    assert_eq!(src.control.metrics.sync_chunks_received_total.get(), 0);

    // Divergent history: the destination's refusal is counted as such.
    let other = TestControl::new().unwrap();
    let b = put(&other, b"other value");
    other.control.pointer_log.create("p", b).unwrap();
    let report = dag_control::sync::push(
        &other.control,
        &dst.control,
        &dag_control::SyncOptions::default(),
    )
    .unwrap();
    assert!(!report.is_complete());
    assert_eq!(m.sync_events_refused_total.get(), 1);
}

#[test]
fn the_event_bus_counts_kinds_and_job_statuses() {
    let tc = TestControl::new().unwrap();
    let m = &tc.control.metrics;

    let cid = put(&tc, b"content");
    tc.control.pointer_log.create("p", cid.clone()).unwrap();
    tc.control
        .pin_log
        .create("keep", PinTarget::Direct(cid), PinScope::Global, None, None)
        .unwrap();

    assert_eq!(m.event_counter("pointer").unwrap().get(), 1);
    assert_eq!(m.event_counter("pin").unwrap().get(), 1);
    assert_eq!(m.event_counter("job").unwrap().get(), 0);

    // A job-run event carries its status into the labeled series.
    tc.control.event_bus.emit(dag_control::Event::JobRun {
        job: "j".into(),
        run: "1".into(),
        status: dag_core::RunStatus::Succeeded,
        ts: 0,
    });
    assert_eq!(m.event_counter("job").unwrap().get(), 1);
    assert_eq!(m.job_status_counter("succeeded").unwrap().get(), 1);
    assert_eq!(m.job_status_counter("failed").unwrap().get(), 0);
}

#[test]
fn two_open_directories_count_in_isolation() {
    // The registry is per-Control, not a global — the property that keeps
    // embedders' numbers (and these tests) honest.
    let a = TestControl::new().unwrap();
    let b = TestControl::new().unwrap();

    put(&a, b"only in a");
    assert_eq!(a.control.metrics.store_put_total.get(), 1);
    assert_eq!(b.control.metrics.store_put_total.get(), 0);
}
