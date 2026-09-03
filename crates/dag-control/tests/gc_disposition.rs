//! Disposition records: deletion with a paper trail that retains itself.

use dag_control::test_utils::TestControl;
use dag_control::GcRequest;
use dag_core::ContentStore;

/// Read content that may be a plain chunk or a chunked-file manifest —
/// exactly what `dag get` does.
fn read_content(tc: &TestControl, cid: &dag_core::Cid) -> Vec<u8> {
    let mut out = Vec::new();
    match dag_core::file::join(tc.control.store.as_ref(), cid, &mut out) {
        Ok(_) => out,
        Err(_) => tc.control.store.get_chunk(cid).unwrap(),
    }
}

fn collectable_run(tc: &TestControl) -> dag_core::GcReport {
    // Something to delete, old enough to be eligible.
    let hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    for i in 0..5u32 {
        let cid = tc
            .control
            .store
            .put_chunk(format!("garbage {i} {}", rand_tag(tc)).as_bytes(), None)
            .unwrap();
        filetime::set_file_mtime(tc.control.store.chunk_path(&cid), hour_ago).unwrap();
    }
    tc.control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            ..Default::default()
        })
        .unwrap()
}

/// Distinct content per call without pulling in a rand crate.
fn rand_tag(tc: &TestControl) -> u64 {
    tc.control.event_bus.current_seq().wrapping_add(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64,
    )
}

#[test]
fn dispositions_chain_retain_themselves_and_reproduce_the_full_report() {
    let tc = TestControl::new().unwrap();
    tc.control.recovery_state.mark_complete_for_test().unwrap();

    // First collection, recorded.
    let first_report = collectable_run(&tc);
    assert!(first_report.chunks_deleted > 0);
    let first_record = tc.control.record_gc_disposition(&first_report).unwrap();

    // The pointer names it, and the full report reassembles from the ledger:
    // every collected CID, not a summary — the count cannot answer "what was
    // destroyed", the list can.
    assert_eq!(
        tc.control
            .pointer_log
            .resolve("system/gc/dispositions")
            .unwrap(),
        first_record
    );
    let links = tc.control.store.get_links(&first_record).unwrap();
    let report_link = links
        .iter()
        .find(|l| l.name.as_deref() == Some("report"))
        .expect("record links its report");
    let report_bytes = read_content(&tc, &report_link.target);
    let recovered: dag_core::GcReport = serde_json::from_slice(&report_bytes).unwrap();
    assert_eq!(recovered.chunks_deleted, first_report.chunks_deleted);
    assert_eq!(recovered.collected.len(), first_report.collected.len());

    // Second collection, recorded: the new record links its predecessor.
    let second_report = collectable_run(&tc);
    let second_record = tc.control.record_gc_disposition(&second_report).unwrap();
    let links = tc.control.store.get_links(&second_record).unwrap();
    let prev = links
        .iter()
        .find(|l| l.name.as_deref() == Some("prev"))
        .expect("second record links the first");
    assert_eq!(prev.target, first_record);

    // The chain retains itself: a further collection — with everything aged
    // so nothing is shielded by youth — leaves both records and both report
    // files intact, because the live head is a transitive root.
    let hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    for cid in tc
        .control
        .store
        .get_links(&second_record)
        .unwrap()
        .iter()
        .map(|l| l.target.clone())
        .chain([first_record.clone(), second_record.clone()])
    {
        let path = tc.control.store.chunk_path(&cid);
        if path.exists() {
            filetime::set_file_mtime(path, hour_ago).unwrap();
        }
    }
    let sweep = tc
        .control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            ..Default::default()
        })
        .unwrap();
    let _ = sweep;

    for record in [&first_record, &second_record] {
        assert!(
            tc.control.store.has_chunk(record).unwrap(),
            "a disposition record was collected"
        );
    }
    // And the first report file — two hops from the head, via prev — too.
    let first_links = tc.control.store.get_links(&first_record).unwrap();
    let first_report_cid = &first_links
        .iter()
        .find(|l| l.name.as_deref() == Some("report"))
        .unwrap()
        .target;
    let again = read_content(&tc, first_report_cid);
    assert!(!again.is_empty());
}
