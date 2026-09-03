//! Resolving a wall-clock moment to a journal sequence number — what
//! `events tail --since <RFC3339>` runs on.

use dag_control::test_utils::TestControl;
use dag_core::ContentStore;

#[test]
fn a_moment_resolves_to_the_first_event_at_or_after_it() {
    let tc = TestControl::new().unwrap();

    for i in 0..3 {
        let cid = tc
            .control
            .store
            .put_chunk(format!("content {i}").as_bytes(), None)
            .unwrap();
        tc.control
            .pointer_log
            .create(&format!("p{i}"), cid)
            .unwrap();
    }

    // Learn the journal's own timestamps, then ask around them.
    let rows = tc.control.event_bus.replay_from(0).unwrap();
    assert_eq!(rows.len(), 3);
    let first_ts = rows[0].envelope_ts;

    // Everything was stamped at or after the first row's moment.
    assert_eq!(
        tc.control.event_bus.seq_at_or_after(first_ts).unwrap(),
        Some(0)
    );
    // The distant past resolves to the start of what survives.
    assert_eq!(tc.control.event_bus.seq_at_or_after(0).unwrap(), Some(0));
    // The future resolves to nothing.
    assert_eq!(
        tc.control
            .event_bus
            .seq_at_or_after(rows[2].envelope_ts + 3600)
            .unwrap(),
        None
    );
}

#[test]
fn journaled_envelopes_carry_the_schema_version_and_old_rows_read_as_v1() {
    let tc = TestControl::new().unwrap();
    let cid = tc.control.store.put_chunk(b"content", None).unwrap();
    tc.control.pointer_log.create("p", cid).unwrap();

    let rows = tc.control.event_bus.replay_from(0).unwrap();
    assert_eq!(rows[0].v, dag_control::events::ENVELOPE_SCHEMA_VERSION);

    // A row journaled before the field existed: no `v` key at all.
    let legacy = r#"{"seq":9,"envelope_ts":100,"event":{"type":"PinEvent","id":"old","action":"created","ts":100}}"#;
    let parsed: dag_control::EventEnvelope = serde_json::from_str(legacy).unwrap();
    assert_eq!(parsed.v, 1, "pre-field rows are schema 1 — they defined it");
    assert_eq!(parsed.seq, 9);
}
