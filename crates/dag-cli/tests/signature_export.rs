//! The DSSE envelopes have to be reachable, or "the format existing
//! supply-chain verifiers consume" is true of the bytes and false of anything
//! you can do with them.
//!
//! Before this the envelope was buried inside a CBOR entry: `dag get --raw`
//! returned CBOR, and `GET /api/signatures` returned verdicts without the
//! envelope, so producing a `.dsse.json` for `cosign` meant hand-decoding.

use std::process::Command;

use anyhow::Result;
use tempfile::TempDir;

fn dag(dir: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dag"));
    cmd.arg("--data-dir").arg(dir.path());
    cmd
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Put content, generate a key, sign, and return (content cid, key id).
fn seed(dir: &TempDir, predicate_type: Option<&str>) -> Result<String> {
    let out = dag(dir)
        .args(["put", "--data", "release artifact"])
        .output()?;
    assert!(out.status.success(), "put failed: {out:?}");
    let cid = stdout(&out).trim().to_string();

    let out = dag(dir)
        .args(["key", "generate", "--id", "builder"])
        .output()?;
    assert!(out.status.success(), "key generate failed: {out:?}");

    let mut cmd = dag(dir);
    cmd.args(["sign", "--cid", &cid, "--key", "builder"]);
    if let Some(pt) = predicate_type {
        cmd.args(["--predicate-type", pt]);
        cmd.args(["--predicate", r#"{"buildType":"demo"}"#]);
    }
    let out = cmd.output()?;
    assert!(out.status.success(), "sign failed: {out:?}");

    Ok(cid)
}

#[test]
fn signatures_export_emits_a_standalone_dsse_envelope() -> Result<()> {
    let dir = TempDir::new()?;
    let cid = seed(&dir, None)?;

    let out = dag(&dir).args(["signatures", "--cid", &cid]).output()?;
    assert!(out.status.success(), "export failed: {out:?}");

    let envelope: serde_json::Value = serde_json::from_str(stdout(&out).trim())?;

    // The three fields a DSSE consumer requires.
    assert_eq!(
        envelope["payloadType"], "application/vnd.in-toto+json",
        "payloadType is what tells a verifier how to read the payload"
    );
    assert!(envelope["payload"].is_string(), "payload must be base64");
    let sigs = envelope["signatures"]
        .as_array()
        .expect("signatures must be an array");
    assert_eq!(sigs.len(), 1);
    assert!(sigs[0]["keyid"].is_string());
    assert!(sigs[0]["sig"].is_string());
    Ok(())
}

#[test]
fn the_exported_payload_names_the_signed_cid_as_a_sha256_subject() -> Result<()> {
    let dir = TempDir::new()?;
    let cid = seed(&dir, None)?;

    let out = dag(&dir).args(["signatures", "--cid", &cid]).output()?;
    let envelope: serde_json::Value = serde_json::from_str(stdout(&out).trim())?;

    // A CID *is* a sha256 digest, which is the whole reason these envelopes
    // drop into existing tooling unmodified.
    use base64::Engine;
    let payload =
        base64::engine::general_purpose::STANDARD.decode(envelope["payload"].as_str().unwrap())?;
    let statement: serde_json::Value = serde_json::from_slice(&payload)?;

    assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(statement["subject"][0]["digest"]["sha256"], cid);
    Ok(())
}

#[test]
fn the_predicate_type_is_settable_because_verifiers_dispatch_on_it() -> Result<()> {
    let dir = TempDir::new()?;
    let slsa = "https://slsa.dev/provenance/v1";
    let cid = seed(&dir, Some(slsa))?;

    let out = dag(&dir).args(["signatures", "--cid", &cid]).output()?;
    let envelope: serde_json::Value = serde_json::from_str(stdout(&out).trim())?;

    use base64::Engine;
    let payload =
        base64::engine::general_purpose::STANDARD.decode(envelope["payload"].as_str().unwrap())?;
    let statement: serde_json::Value = serde_json::from_slice(&payload)?;

    assert_eq!(
        statement["predicateType"], slsa,
        "hardcoding predicateType meant no statement could ever be a kind an \
         external verifier recognises"
    );
    assert_eq!(statement["predicate"]["buildType"], "demo");
    Ok(())
}

#[test]
fn export_writes_one_file_per_signature_when_given_a_directory() -> Result<()> {
    let dir = TempDir::new()?;
    let cid = seed(&dir, None)?;

    let out_dir = TempDir::new()?;
    let out = dag(&dir)
        .args(["signatures", "--cid", &cid, "--out-dir"])
        .arg(out_dir.path())
        .output()?;
    assert!(out.status.success(), "export failed: {out:?}");

    let files: Vec<_> = std::fs::read_dir(out_dir.path())?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), 1, "one envelope per signature, got {files:?}");
    assert!(
        files[0].ends_with(".dsse.json"),
        "the extension is what makes it obvious to a human and a tool: {files:?}"
    );

    let body = std::fs::read_to_string(out_dir.path().join(&files[0]))?;
    let envelope: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(envelope["payloadType"], "application/vnd.in-toto+json");
    Ok(())
}

#[test]
fn exporting_a_cid_with_no_signatures_is_not_an_error() -> Result<()> {
    let dir = TempDir::new()?;
    let out = dag(&dir).args(["put", "--data", "unsigned"]).output()?;
    let cid = stdout(&out).trim().to_string();

    let out = dag(&dir).args(["signatures", "--cid", &cid]).output()?;
    assert!(
        out.status.success(),
        "absence of signatures is a fact, not a failure"
    );
    assert!(stdout(&out).trim().is_empty());
    Ok(())
}
