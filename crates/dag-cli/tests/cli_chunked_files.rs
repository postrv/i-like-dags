//! End-to-end chunked-file behaviour through the real binary.
//!
//! `dag put` on content over 4 MiB must produce a manifest whose `dag get`
//! reassembles the original bytes — the CLI contract stays symmetric no
//! matter the size.

use assert_cmd::Command;
use tempfile::tempdir;

/// Deterministic pseudorandom bytes; incompressible, so chunk boundaries are
/// realistic.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

fn dag(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("dag").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

#[test]
fn a_six_mib_file_round_trips_through_put_and_get() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let original = noise(6 * 1024 * 1024, 4242);
    let input = temp.path().join("model.bin");
    std::fs::write(&input, &original).unwrap();

    // put: succeeds (this used to hard-fail on I2) and reports chunking.
    let out = dag(&data_dir)
        .args(["put", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["chunked"], true);
    assert_eq!(json["size"], original.len() as u64);
    assert!(json["chunks"].as_u64().unwrap() > 1, "should have split");
    let cid = json["cid"].as_str().unwrap().to_string();

    // get: reassembles byte-for-byte.
    let restored_path = temp.path().join("restored.bin");
    dag(&data_dir)
        .args(["get", "--cid", &cid, "--out"])
        .arg(&restored_path)
        .assert()
        .success();
    let restored = std::fs::read(&restored_path).unwrap();
    assert_eq!(restored, original, "reassembly must be byte-identical");

    // get without --out refuses rather than dumping binary at a terminal,
    // and names the fix.
    let out = dag(&data_dir)
        .args(["get", "--cid", &cid])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--out"));

    // --raw returns the manifest entry itself, not the file.
    let out = dag(&data_dir)
        .args(["get", "--cid", &cid, "--raw"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        out.stdout.len() < 100 * 1024,
        "manifest should be small, got {} bytes",
        out.stdout.len()
    );

    // The second put of the same file stores nothing new.
    let out = dag(&data_dir)
        .args(["put", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["cid"].as_str().unwrap(), cid, "determinism");
    assert_eq!(json["new_chunks"], 0, "full dedup on identical content");
}

#[test]
fn small_content_is_stored_exactly_as_before() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let out = dag(&data_dir)
        .args(["put", "--json", "--data", "hello world"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    // No "chunked" key, and the CID is the plain content hash — the single
    // chunk fast path is untouched.
    assert!(json.get("chunked").is_none());
    assert_eq!(
        json["cid"].as_str().unwrap(),
        dag_core::Cid::compute(b"hello world").to_hex()
    );
}

#[test]
fn chunked_flag_forces_a_manifest_for_small_content() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let out = dag(&data_dir)
        .args(["put", "--json", "--chunked", "--data", "tiny"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["chunked"], true);
    assert_eq!(json["chunks"], 1);

    // And it still reads back correctly.
    let restored = temp.path().join("tiny.bin");
    dag(&data_dir)
        .args(["get", "--cid", json["cid"].as_str().unwrap(), "--out"])
        .arg(&restored)
        .assert()
        .success();
    assert_eq!(std::fs::read(&restored).unwrap(), b"tiny");
}
