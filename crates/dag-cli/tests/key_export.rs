//! Exporting a public key in a format an external verifier accepts.
//!
//! `dag signatures --cid` gives you a standalone DSSE envelope, but a verifier
//! also needs the *public key* — and `cosign`, `openssl` and the rest of the
//! supply-chain ecosystem speak PKIX/SubjectPublicKeyInfo PEM, not the raw
//! 32-byte hex this system stores. Without an export path an operator has to
//! hand-assemble the SPKI DER wrapper, which is exactly the kind of "true of
//! the bytes, false of anything you can do with them" gap the envelope export
//! itself was added to close. These tests prove the two exported artifacts —
//! envelope and PEM — are between them sufficient for a third party.

use std::process::Command;

use anyhow::Result;
use base64::Engine;
use tempfile::TempDir;

fn dag(dir: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dag"));
    cmd.arg("--data-dir").arg(dir.path());
    cmd
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The Ed25519 SPKI DER prefix (RFC 8410): SEQ { SEQ { OID 1.3.101.112 },
/// BIT STRING { 0x00, <32-byte key> } }. A PKIX public key is exactly this
/// twelve-byte header followed by the raw key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn gen_key(dir: &TempDir, id: &str, trust: bool) -> Result<String> {
    let mut cmd = dag(dir);
    cmd.args(["key", "generate", "--json", "--id", id]);
    if trust {
        cmd.arg("--trust");
    }
    let out = cmd.output()?;
    assert!(out.status.success(), "key generate failed: {out:?}");
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim())?;
    Ok(v["public_key"].as_str().unwrap().to_string())
}

/// `dag key export --id <name> --format pem` prints a PKIX PEM whose body is
/// the SPKI wrapper around the exact 32 raw public-key bytes.
#[test]
fn key_export_pem_is_a_pkix_public_key() -> Result<()> {
    let dir = TempDir::new()?;
    let pub_hex = gen_key(&dir, "builder", false)?;
    let raw = hex::decode(&pub_hex)?;

    let out = dag(&dir)
        .args(["key", "export", "--id", "builder", "--format", "pem"])
        .output()?;
    assert!(out.status.success(), "export failed: {out:?}");
    let pem = stdout(&out);

    assert!(
        pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "not a PEM public key: {pem}"
    );
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));

    // The base64 body must decode to the SPKI wrapper + the raw key, so a
    // tool that reads PKIX gets exactly this signer's key and no other.
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD.decode(body.trim())?;
    assert_eq!(der.len(), 44, "SPKI DER for Ed25519 is 44 bytes");
    assert_eq!(&der[..12], &ED25519_SPKI_PREFIX, "wrong SPKI header");
    assert_eq!(&der[12..], raw.as_slice(), "PEM must carry this exact key");
    Ok(())
}

/// Export by raw hex, too — a verifier holding only the hex from a keyring or
/// an envelope's `keyid` resolution needs no local secret key to get a PEM.
#[test]
fn key_export_accepts_a_raw_public_key_hex() -> Result<()> {
    let dir = TempDir::new()?;
    let pub_hex = gen_key(&dir, "builder", false)?;

    let out = dag(&dir)
        .args(["key", "export", "--public-key", &pub_hex, "--format", "pem"])
        .output()?;
    assert!(out.status.success(), "export by hex failed: {out:?}");
    assert!(stdout(&out).contains("BEGIN PUBLIC KEY"));

    // hex format round-trips the input.
    let out = dag(&dir)
        .args(["key", "export", "--public-key", &pub_hex, "--format", "hex"])
        .output()?;
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), pub_hex);
    Ok(())
}

/// The point of the whole layer: a third party with *only* the exported
/// envelope and the exported public key can verify authorship, using nothing
/// from this system. This reconstructs DSSE PAE and checks the Ed25519
/// signature with a fresh verifying key parsed from the PEM alone.
#[test]
fn envelope_and_pem_verify_from_first_principles() -> Result<()> {
    let dir = TempDir::new()?;

    let out = dag(&dir)
        .args(["put", "--data", "release artifact v1"])
        .output()?;
    let cid = stdout(&out).trim().to_string();
    gen_key(&dir, "builder", true)?;

    let predicate_type = "https://slsa.dev/provenance/v1";
    let out = dag(&dir)
        .args([
            "sign",
            "--cid",
            &cid,
            "--key",
            "builder",
            "--predicate-type",
            predicate_type,
            "--predicate",
            r#"{"buildType":"demo"}"#,
        ])
        .output()?;
    assert!(out.status.success(), "sign failed: {out:?}");

    // The two artifacts a third party would receive.
    let envelope: serde_json::Value = serde_json::from_str(
        stdout(&dag(&dir).args(["signatures", "--cid", &cid]).output()?).trim(),
    )?;
    let pem = stdout(
        &dag(&dir)
            .args(["key", "export", "--id", "builder", "--format", "pem"])
            .output()?,
    );

    // --- From here on, only `envelope` and `pem` are in scope. ---

    // 1. Recover the verifying key from the PEM by stripping the SPKI wrapper.
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD.decode(body.trim())?;
    assert_eq!(&der[..12], &ED25519_SPKI_PREFIX);
    let key_bytes: [u8; 32] = der[12..].try_into()?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)?;

    // 2. Rebuild the DSSE PAE over (payloadType, payload) exactly as the spec
    //    defines it: "DSSEv1 SP LEN(type) SP type SP LEN(body) SP body".
    let payload_type = envelope["payloadType"].as_str().unwrap();
    let payload =
        base64::engine::general_purpose::STANDARD.decode(envelope["payload"].as_str().unwrap())?;
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(&payload);

    // 3. Verify the signature — strictly, the way a careful verifier would.
    let sig_bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(envelope["signatures"][0]["sig"].as_str().unwrap())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature not 64 bytes"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    key.verify_strict(&pae, &sig)
        .map_err(|e| anyhow::anyhow!("third party could not verify: {e}"))?;

    // 4. The statement is a well-formed in-toto v1 statement naming the CID.
    //    Nothing from this system was consulted: no keyring, no store, no CBOR.
    let statement: serde_json::Value = serde_json::from_slice(&payload)?;
    assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(statement["subject"][0]["digest"]["sha256"], cid);
    assert_eq!(statement["predicateType"], predicate_type);
    Ok(())
}
