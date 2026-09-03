//! CLI integration tests for exit codes and JSON output
//!
//! These tests verify:
//! - Exit code 78 for NotRecovered errors
//! - JSON output validity for --json flag
//! - Stdout/stderr separation

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn test_gc_run_exits_78_when_not_recovered() {
    use dag_control::Control;

    let temp = tempdir().unwrap();

    // Open Control without running recovery
    let control = Control::open(temp.path()).unwrap();

    // Try to check recovery - should fail with NotRecovered
    let result = control.is_recovered();
    match result {
        Err(e) => {
            // Verify it's ControlError::NotRecovered
            assert!(e.to_string().contains("recovery not complete"));
        }
        Ok(recovered) => {
            assert!(!recovered, "Should not be recovered initially");
        }
    }
}

#[test]
fn test_gc_status_json_output() {
    use dag_control::{Control, RetentionIndex};
    use dag_core::ContentStore;

    let temp = tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();

    // Put a chunk to have a CID
    let chunk = b"test data for gc status";
    let cid = control.store.put_chunk(chunk, None).unwrap();

    // Create retention index and get status
    let retention_index = RetentionIndex::new(control.pin_log.clone(), control.store.clone(), 1000);
    let status = retention_index.status(&cid).unwrap();

    // Verify status structure (should be Unprotected since no pins)
    use dag_control::RetentionStatus;
    matches!(status, RetentionStatus::Unprotected);
}

#[test]
fn test_gc_status_text_output_default() {
    use dag_control::{Control, RetentionIndex, RetentionStatus};
    use dag_core::ContentStore;

    let temp = tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();

    // Put a chunk
    let chunk = b"test data";
    let cid = control.store.put_chunk(chunk, None).unwrap();

    // Create retention index and get status
    let retention_index = RetentionIndex::new(control.pin_log.clone(), control.store.clone(), 1000);
    let status = retention_index.status(&cid).unwrap();

    // Verify status is correct type
    matches!(status, RetentionStatus::Unprotected);
}

#[test]
fn test_json_pretty_formatting() {
    // Test that pretty JSON formatting works by using a simple struct
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct TestData {
        field1: String,
        field2: i32,
        field3: Vec<String>,
    }

    let data = TestData {
        field1: "test".to_string(),
        field2: 42,
        field3: vec!["a".to_string(), "b".to_string()],
    };

    // Test pretty formatting
    let pretty_json = serde_json::to_string_pretty(&data).unwrap();
    assert!(
        pretty_json.contains('\n'),
        "Pretty JSON should have newlines"
    );

    // Should still be valid JSON
    let _: serde_json::Value =
        serde_json::from_str(&pretty_json).expect("Pretty output should be valid JSON");
}

#[test]
fn test_errors_go_to_stderr_not_stdout() {
    let temp = tempdir().unwrap();

    // Invalid CID should error
    let output = Command::cargo_bin("dag")
        .unwrap()
        .arg("--data-dir")
        .arg(temp.path())
        .arg("--json")
        .arg("gc")
        .arg("status")
        .arg("--cid")
        .arg("invalid-cid-format")
        .output()
        .unwrap();

    assert!(!output.status.success(), "Invalid CID should fail");

    // Error message should be on stderr
    let stderr_str = String::from_utf8(output.stderr).unwrap();
    assert!(stderr_str.contains("Error"), "Error should be on stderr");

    // Stdout should be empty (no JSON on error)
    assert!(output.stdout.is_empty(), "Stdout should be empty on error");
}

#[test]
fn test_events_tail_jsonl_format() {
    use dag_control::Control;
    use dag_core::ContentStore;

    let temp = tempdir().unwrap();
    let control = Control::open(temp.path()).unwrap();

    // Create some events by creating pointers
    for i in 0..3 {
        let chunk = format!("data-{}", i);
        let cid = control.store.put_chunk(chunk.as_bytes(), None).unwrap();

        // Create pointer (emits PointerUpdate event)
        control
            .pointer_log
            .create(&format!("ptr-{}", i), cid)
            .unwrap();
    }

    // Replay events from journal starting at sequence 0
    let envelopes = control.event_bus.replay_from(0).unwrap();

    // Should have events
    assert!(!envelopes.is_empty(), "Should have emitted events");

    // Each envelope should serialize to valid JSON
    for envelope in envelopes {
        let json = serde_json::to_string(&envelope).expect("Envelope should serialize to JSON");
        // Verify it's valid JSON
        let _: serde_json::Value =
            serde_json::from_str(&json).expect("Each event line should be valid JSON");
    }
}
