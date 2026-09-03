//! End-to-end signing through the real binary: key lifecycle, sign, verify,
//! and the exit codes a pipeline depends on.

use assert_cmd::Command;
use tempfile::tempdir;

fn dag(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("dag").unwrap();
    cmd.arg("--data-dir").arg(data_dir);
    cmd
}

#[test]
fn sign_and_verify_round_trip_with_exit_codes() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    // Store content.
    let out = dag(&data_dir)
        .args(["put", "--json", "--data", "release artefact"])
        .output()
        .unwrap();
    let cid = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string();

    // Unverifiable content is a non-zero exit: no signatures at all.
    dag(&data_dir)
        .args(["verify", "--cid", &cid])
        .assert()
        .failure()
        .code(65);

    // Generate a key, trusting it in the same breath.
    let out = dag(&data_dir)
        .args(["key", "generate", "--json", "--id", "release", "--trust"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let keygen: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(keygen["trusted"], true);

    // The secret key file is owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(keygen["path"].as_str().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "secret key must be mode 0600");
        let keys_mode = std::fs::metadata(data_dir.join("keys"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            keys_mode & 0o777,
            0o700,
            "secret-key directory must be mode 0700"
        );
    }

    // Sign, then verify: exit 0 and a trusted verdict.
    dag(&data_dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "release",
            "--note",
            "approved for production",
        ])
        .assert()
        .success();

    let out = dag(&data_dir)
        .args(["verify", "--json", "--cid", &cid])
        .output()
        .unwrap();
    assert!(out.status.success(), "trusted signature should verify");
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verdict["verified"], true);
    assert_eq!(verdict["trusted"], 1);
    assert_eq!(
        verdict["signatures"][0]["predicate"]["note"],
        "approved for production"
    );

    // Untrust the key: verification degrades and the exit goes non-zero.
    let key_id = keygen["key_id"].as_str().unwrap();
    dag(&data_dir)
        .args(["key", "untrust", "--key-id", key_id])
        .assert()
        .success();
    dag(&data_dir)
        .args(["verify", "--cid", &cid])
        .assert()
        .failure()
        .code(65);
}

#[test]
fn signing_a_chunked_file_manifest_works() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    // A >4 MiB file becomes a manifest; the manifest CID is what gets signed —
    // and because the manifest covers every chunk by hash, one signature
    // covers the whole file.
    let big = vec![7u8; 5 * 1024 * 1024];
    let input = temp.path().join("model.bin");
    std::fs::write(&input, &big).unwrap();

    let out = dag(&data_dir)
        .args(["put", "--json", "--file"])
        .arg(&input)
        .output()
        .unwrap();
    let cid = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string();

    dag(&data_dir)
        .args(["key", "generate", "--id", "ci", "--trust"])
        .assert()
        .success();
    dag(&data_dir)
        .args(["sign", "--cid", &cid, "--key", "ci", "--name", "model.bin"])
        .assert()
        .success();
    dag(&data_dir)
        .args(["verify", "--cid", &cid])
        .assert()
        .success();
}

#[test]
fn key_generate_refuses_to_overwrite() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    dag(&data_dir)
        .args(["key", "generate", "--id", "once"])
        .assert()
        .success();
    let out = dag(&data_dir)
        .args(["key", "generate", "--id", "once"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to overwrite"));
}

#[test]
fn key_loading_is_bounded_and_validates_all_persisted_identity_fields() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let generated = dag(&data_dir)
        .args(["key", "generate", "--json", "--id", "release"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let generated: serde_json::Value = serde_json::from_slice(&generated.stdout).unwrap();
    let path = std::path::PathBuf::from(generated["path"].as_str().unwrap());
    let original = std::fs::read(&path).unwrap();
    let original_json: serde_json::Value = serde_json::from_slice(&original).unwrap();

    for (field, replacement, expected_error) in [
        (
            "id",
            serde_json::json!("different"),
            "declares id \"different\", expected \"release\"",
        ),
        (
            "public_key",
            serde_json::json!("00"),
            "public_key does not match its secret seed",
        ),
        (
            "key_id",
            serde_json::json!("00"),
            "key_id does not match its secret seed",
        ),
    ] {
        let mut tampered = original_json.clone();
        tampered[field] = replacement;
        std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let out = dag(&data_dir)
            .args(["key", "export", "--id", "release", "--format", "hex"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "tampered {field} was accepted");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(expected_error),
            "unexpected error for {field}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let mut unknown = original_json.clone();
    unknown["future_or_hostile_field"] = serde_json::json!(true);
    std::fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    let out = dag(&data_dir).args(["key", "list"]).output().unwrap();
    assert!(
        !out.status.success(),
        "listing must not silently hide an invalid local key"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown field"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Duplicate fields are ambiguous and serde's struct decoder rejects them.
    let mut duplicate = String::from_utf8(original.clone()).unwrap();
    let closing = duplicate.rfind('}').unwrap();
    duplicate.replace_range(closing..=closing, ",\"id\":\"release\"}");
    std::fs::write(&path, duplicate).unwrap();
    let out = dag(&data_dir)
        .args(["key", "export", "--id", "release", "--format", "hex"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "duplicate JSON fields were accepted");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("duplicate field"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::write(&path, vec![b' '; 4 * 1024 + 1]).unwrap();
    let out = dag(&data_dir)
        .args(["key", "export", "--id", "release", "--format", "hex"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "oversized key file was accepted");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("maximum is 4096"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn key_loading_accepts_owner_read_only_but_rejects_exposed_secrets() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    let generated = dag(&data_dir)
        .args(["key", "generate", "--json", "--id", "mounted"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let generated: serde_json::Value = serde_json::from_slice(&generated.stdout).unwrap();
    let path = std::path::PathBuf::from(generated["path"].as_str().unwrap());

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(
        data_dir.join("keys"),
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    dag(&data_dir)
        .args(["key", "export", "--id", "mounted", "--format", "hex"])
        .assert()
        .success();

    std::fs::set_permissions(
        data_dir.join("keys"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = dag(&data_dir)
        .args(["key", "export", "--id", "mounted", "--format", "hex"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "group-readable secret was accepted");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("grants group/world access"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(
        data_dir.join("keys"),
        std::fs::Permissions::from_mode(0o720),
    )
    .unwrap();
    let out = dag(&data_dir)
        .args(["key", "export", "--id", "mounted", "--format", "hex"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "group-writable key directory was accepted"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("group/world-writable"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn key_loading_never_follows_key_or_directory_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    let generated = dag(&data_dir)
        .args(["key", "generate", "--json", "--id", "release"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let generated: serde_json::Value = serde_json::from_slice(&generated.stdout).unwrap();
    let key_path = std::path::PathBuf::from(generated["path"].as_str().unwrap());
    let outside = temp.path().join("outside-key.json");
    std::fs::rename(&key_path, &outside).unwrap();
    symlink(&outside, &key_path).unwrap();

    let out = dag(&data_dir)
        .args(["key", "export", "--id", "release", "--format", "hex"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "key-file symlink was followed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("without following links"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::remove_file(&key_path).unwrap();
    std::fs::remove_dir(data_dir.join("keys")).unwrap();
    let external_keys = temp.path().join("external-keys");
    std::fs::create_dir(&external_keys).unwrap();
    std::fs::set_permissions(&external_keys, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&external_keys, data_dir.join("keys")).unwrap();

    let out = dag(&data_dir).args(["key", "list"]).output().unwrap();
    assert!(!out.status.success(), "key-directory symlink was followed");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("without following links"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn key_listing_rejects_special_files_without_blocking() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");
    // Open the control plane once so the data directory exists, then place a
    // FIFO where a JSON key would otherwise be consumed. `O_NONBLOCK` on key
    // reads is what makes rejecting this safe even when there is no writer.
    dag(&data_dir).args(["key", "list"]).assert().success();
    let keys = data_dir.join("keys");
    std::fs::create_dir(&keys).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(keys.join("fifo.json"))
        .status()
        .unwrap();
    assert!(status.success());

    let out = dag(&data_dir).args(["key", "list"]).output().unwrap();
    assert!(!out.status.success(), "special-file key entry was accepted");
}

/// The dual-checker shape (ADR-003's sibling, docs/PROOF_ARTIFACTS.md):
/// two independent verifiers each sign the same subject with a structured
/// verdict predicate, and a pipeline gates on *both* being trusted.
#[test]
fn two_checker_verdicts_gate_on_min_trusted() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let out = dag(&data_dir)
        .args(["put", "--json", "--data", "a proof certificate"])
        .output()
        .unwrap();
    let cid = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string();

    for key in ["checker-python", "checker-rust"] {
        dag(&data_dir)
            .args(["key", "generate", "--id", key, "--trust"])
            .assert()
            .success();
    }

    // Each checker signs with a structured verdict, not free text.
    dag(&data_dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "checker-python",
            "--predicate",
            r#"{"type":"vcot-verdict/v1","checker":"checker.py","verdict":"accepted"}"#,
        ])
        .assert()
        .success();
    dag(&data_dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "checker-rust",
            "--predicate",
            r#"{"type":"vcot-verdict/v1","checker":"vcot-check","verdict":"accepted"}"#,
        ])
        .assert()
        .success();

    // Exact agreement, gateable: both signatures must be trusted.
    let out = dag(&data_dir)
        .args(["verify", "--json", "--cid", &cid, "--min-trusted", "2"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "two trusted verdicts should satisfy 2"
    );
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verdict["trusted"], 2);
    assert_eq!(
        verdict["signatures"][0]["predicate"]["type"],
        "vcot-verdict/v1"
    );

    // Demand more agreement than exists: exit 65, same as unverifiable.
    dag(&data_dir)
        .args(["verify", "--cid", &cid, "--min-trusted", "3"])
        .assert()
        .failure()
        .code(65);

    // One checker changing its mind out loud is still one checker: a third
    // signature from an already-counted key adds a signature, not agreement.
    dag(&data_dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "checker-rust",
            "--predicate",
            r#"{"type":"vcot-verdict/v1","checker":"vcot-check","verdict":"accepted","rerun":true}"#,
        ])
        .assert()
        .success();
    let out = dag(&data_dir)
        .args(["verify", "--json", "--cid", &cid, "--min-trusted", "2"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "two distinct checkers still satisfy 2"
    );
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verdict["signatures"].as_array().unwrap().len(), 3);
    assert_eq!(verdict["trusted"], 2, "three signatures, two distinct keys");
    dag(&data_dir)
        .args(["verify", "--cid", &cid, "--min-trusted", "3"])
        .assert()
        .failure()
        .code(65);

    // A malformed predicate is a usage error, not a stored lie.
    dag(&data_dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "checker-rust",
            "--predicate",
            "not json",
        ])
        .assert()
        .failure();

    // --predicate and --note are mutually exclusive by construction.
    dag(&data_dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "checker-rust",
            "--note",
            "x",
            "--predicate",
            "{}",
        ])
        .assert()
        .failure();
}

/// `--min-trusted N` sells "N independent checkers agreed". Counting
/// *signatures* would let one key buy that guarantee by signing twice — the
/// cheapest possible attack on a gate, available to anyone who already holds
/// one trusted key. The count is of distinct keys.
#[test]
fn one_key_signing_twice_does_not_satisfy_min_trusted_two() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let out = dag(&data_dir)
        .args(["put", "--json", "--data", "a proof certificate"])
        .output()
        .unwrap();
    let cid = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string();

    dag(&data_dir)
        .args(["key", "generate", "--id", "solo", "--trust"])
        .assert()
        .success();

    // The same key, twice, differing only in the note it carries.
    for note in ["first pass", "second pass"] {
        dag(&data_dir)
            .args(["sign", "--cid", &cid, "--key", "solo", "--note", note])
            .assert()
            .success();
    }

    let out = dag(&data_dir)
        .args(["verify", "--json", "--cid", &cid])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "one trusted key satisfies the default"
    );
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        verdict["signatures"].as_array().unwrap().len(),
        2,
        "both signatures are stored and reported"
    );
    assert_eq!(verdict["trusted"], 1, "but they come from one key");
    assert_eq!(verdict["valid"], 1);

    // The gate that matters.
    dag(&data_dir)
        .args(["verify", "--cid", &cid, "--min-trusted", "2"])
        .assert()
        .failure()
        .code(65);
}

/// ADR-004: `--for` scopes what a trust grant covers, and the default is
/// verification only — an adopt-only key signs validly but earns no
/// trusted verdict in `dag verify`.
#[test]
fn trust_grants_are_purpose_scoped_at_the_cli() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let out = dag(&data_dir)
        .args(["put", "--json", "--data", "built artefact"])
        .output()
        .unwrap();
    let cid = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["cid"]
        .as_str()
        .unwrap()
        .to_string();

    // A builder key trusted for adoption only.
    let out = dag(&data_dir)
        .args([
            "key", "generate", "--json", "--id", "builder", "--trust", "--for", "adopt",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    dag(&data_dir)
        .args(["sign", "--cid", &cid, "--key", "builder"])
        .assert()
        .success();

    // Its signature is valid but must not satisfy verification gates.
    let out = dag(&data_dir)
        .args(["verify", "--json", "--cid", &cid])
        .output()
        .unwrap();
    assert!(!out.status.success(), "adopt-only must not verify");
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verdict["trusted"], 0);
    assert_eq!(verdict["valid"], 1);
    assert_eq!(verdict["signatures"][0]["key_purposes"][0], "adopt");

    // The keyring says what each grant covers.
    let out = dag(&data_dir).args(["key", "list"]).output().unwrap();
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(listing.contains("for adopt"), "got: {listing}");

    // Unknown purposes are a usage error at the CLI boundary.
    dag(&data_dir)
        .args([
            "key",
            "trust",
            "--public-key",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--for",
            "sudo",
        ])
        .assert()
        .failure();
}
