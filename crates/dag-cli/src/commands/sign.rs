//! `dag sign` and `dag verify` — attach identity to content, and check it.

use anyhow::{Context, Result};
use dag_control::Control;

use crate::error::CliError;
use crate::output::{short_cid, terminal_text, Format};

/// A stored signature entry cannot exceed one 4 MiB chunk. JSON/base64 and
/// whitespace may expand the external envelope, but it must remain bounded
/// before parsing and decoding.
const MAX_ENVELOPE_FILE_BYTES: usize = dag_core::MAX_CHUNK_SIZE * 2;

/// `dag sign --cid <C> --key <name> [--note <text> | --predicate <json>]`
/// What `dag sign` was asked to do.
///
/// A struct rather than a widening argument list: the statement fields travel
/// together, and clap already groups them.
pub struct SignRequest {
    pub cid: String,
    pub key_name: String,
    pub name: Option<String>,
    pub note: Option<String>,
    pub predicate: Option<String>,
    pub predicate_type: Option<String>,
}

pub fn sign(control: &Control, req: SignRequest, fmt: Format) -> Result<()> {
    let cid = super::parse_cid(&req.cid)?;
    let key = super::key::load_signing_key(control, &req.key_name)?;

    // clap enforces that --note and --predicate are mutually exclusive.
    let predicate = match (req.predicate, req.note) {
        (Some(json), _) => serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("--predicate is not valid JSON: {}", e))?,
        (None, Some(note)) => serde_json::json!({ "note": note }),
        (None, None) => serde_json::json!({}),
    };

    let predicate_type = req
        .predicate_type
        .unwrap_or_else(|| dag_core::signing::DEFAULT_PREDICATE_TYPE.to_string());
    let sig_cid =
        control
            .signature_log
            .sign_with_type(&cid, req.name, predicate, &predicate_type, &key)?;

    let key_name = req.key_name;
    let out = serde_json::json!({
        "signature_cid": sig_cid.to_hex(),
        "signs": cid.to_hex(),
        "key": key_name,
        "key_id": dag_core::signing::key_id(&key.verifying_key()),
        "predicate_type": predicate_type,
    });
    fmt.emit(out, move |_| {
        format!(
            "signed {} with key {:?}\n  signature entry {}",
            short_cid(&cid.to_hex()),
            terminal_text(&key_name),
            sig_cid.to_hex()
        )
    })
}

/// `dag signatures export --cid <C> [--out-dir <D>]`
///
/// Writes each covering signature as a standalone DSSE envelope — the shape
/// `cosign verify-attestation` and `slsa-verifier` consume. Without this the
/// envelope was reachable only by hand-decoding the CBOR entry that wraps it,
/// so "the format existing supply-chain verifiers consume" was true of the
/// bytes and false of anything you could do with them.
pub fn export(control: &Control, cid: &str, out_dir: Option<&std::path::Path>) -> Result<()> {
    let target = super::parse_cid(cid)?;
    let records = control.signature_log.records_for(&target)?;

    let mut written = Vec::new();
    for (sig_cid, record) in &records {
        let json = serde_json::to_string_pretty(&record.envelope)?;
        match out_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir)?;
                let path = dir.join(format!("{}.dsse.json", sig_cid.to_hex()));
                std::fs::write(&path, json)?;
                written.push(path.display().to_string());
            }
            None => println!("{json}"),
        }
    }

    if out_dir.is_some() {
        for path in &written {
            eprintln!("wrote {}", terminal_text(path));
        }
        eprintln!(
            "{} envelope(s) for {}",
            written.len(),
            short_cid(&target.to_hex())
        );
    } else if records.is_empty() {
        eprintln!("no signatures cover {}", short_cid(&target.to_hex()));
    }
    Ok(())
}

/// `dag signatures --import <file> [--cid <C>] [--key <hex>]`
///
/// The other direction: an envelope minted elsewhere — another dag
/// deployment, a CI signer, anything emitting Ed25519 DSSE over in-toto v1 —
/// becomes an ordinary stored signature. Nothing lands unless it verifies
/// against `--key` (or, absent that, some key already in the keyring), its
/// statement names exactly one sha256 subject, and that subject's bytes are
/// present and intact here. ECDSA envelopes (cosign's default) fail
/// verification and are refused, not stored.
pub fn import_envelope(
    control: &Control,
    path: &std::path::Path,
    key_hex: Option<&str>,
    expect_cid: Option<&str>,
    fmt: Format,
) -> Result<()> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening envelope {}", path.display()))?;
    let raw = super::read_bounded(
        file,
        MAX_ENVELOPE_FILE_BYTES,
        &format!("DSSE envelope {}", path.display()),
    )?;
    let envelope: dag_core::signing::Envelope = serde_json::from_slice(&raw)
        .with_context(|| format!("{} is not a DSSE envelope", path.display()))?;

    let expected = expect_cid.map(super::parse_cid).transpose()?;
    let (sig_cid, target) =
        control
            .signature_log
            .import_envelope(&envelope, key_hex, expected.as_ref())?;

    let out = serde_json::json!({
        "signature_cid": sig_cid.to_hex(),
        "target_cid": target.to_hex(),
        "source": path.display().to_string(),
    });
    fmt.emit(out, |o| {
        format!(
            "imported {} covering {}",
            short_cid(o["signature_cid"].as_str().unwrap_or("")),
            short_cid(o["target_cid"].as_str().unwrap_or(""))
        )
    })
}

/// `dag verify --cid <C> [--min-trusted <n>]`
///
/// Checks the content's own hash first, then every signature covering it.
/// Exit is non-zero unless the content is intact and at least `min_trusted`
/// *distinct trusted keys* have signed it — this is the command a pipeline
/// gates on. Two independent checkers held to agreement is `--min-trusted 2`,
/// and it means two checkers: one key signing twice does not satisfy it.
pub fn verify(control: &Control, cid: &str, min_trusted: usize, fmt: Format) -> Result<()> {
    let cid = super::parse_cid(cid)?;

    // Content first: a signature over rotted bytes must not read as success.
    //
    // "The content" means all of it. For a chunked file the CID names a
    // manifest, and the manifest hashing correctly proves only that the list
    // of parts is intact — this used to stop there and report `intact` for a
    // file whose data chunks were gone, which is the opposite of what the
    // command exists to say. `verify_deep` walks the manifest and re-hashes
    // every part; for a plain chunk it is the same single check as before.
    let deep = dag_core::file::verify_deep(control.store.as_ref(), &cid);
    let (intact, detail) = match &deep {
        Ok(Some(info)) => (
            true,
            Some(format!("{} bytes in {} chunks", info.size, info.chunks)),
        ),
        Ok(None) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    let statuses = if intact {
        control.signature_log.verify(&cid)?
    } else {
        Vec::new()
    };
    // Distinct keys, not signatures: see `distinct_trusted_keys`.
    let trusted = dag_control::signatures::distinct_trusted_keys(&statuses);
    let valid = dag_control::signatures::distinct_valid_keys(&statuses);
    let ok = intact && trusted >= min_trusted.max(1);

    let out = serde_json::json!({
        "cid": cid.to_hex(),
        "intact": intact,
        "content": detail,
        "signatures": statuses,
        "trusted": trusted,
        "valid": valid,
        "required": min_trusted.max(1),
        "verified": ok,
    });
    fmt.emit(&out, |o| {
        let mut s = format!(
            "{} {}\n",
            if intact { "✓" } else { "✗" },
            short_cid(&cid.to_hex())
        );
        if !intact {
            // Name what actually failed: for a chunked file the root is fine
            // and a *part* is missing, and "content does not match its CID"
            // would send an operator to re-hash the wrong thing.
            match o["content"].as_str() {
                Some(why) => {
                    s.push_str("  content is not intact: ");
                    s.push_str(&terminal_text(why));
                    s.push('\n');
                }
                None => s.push_str("  content does not match its CID\n"),
            }
        }
        for sig in o["signatures"].as_array().unwrap() {
            let key_id = sig["key_id"].as_str().unwrap();
            let abbreviated_key_id = key_id.chars().take(16).collect::<String>();
            let verdict = if sig["trusted"].as_bool().unwrap() {
                "trusted"
            } else if sig["valid"].as_bool().unwrap() {
                "valid, UNTRUSTED key"
            } else if key_id == "<missing>" {
                // The index names an entry the store no longer holds —
                // collected before signatures followed their target's
                // retention, or lost with a disk. Name the loss; "INVALID"
                // would read as an attack.
                "MISSING: entry not in the store"
            } else {
                "INVALID"
            };
            s.push_str(&format!(
                "  {} {}  {}{}\n",
                if sig["trusted"].as_bool().unwrap() {
                    "✓"
                } else {
                    "✗"
                },
                // Sentinels like `<missing>` are shorter than 16 hex chars.
                terminal_text(&abbreviated_key_id),
                verdict,
                sig["signer"]
                    .as_str()
                    .map(|c| format!("  ({})", terminal_text(c)))
                    .unwrap_or_default(),
            ));
        }
        s.push_str(&format!(
            "\n{} signature(s) from {} trusted key(s), {} valid key(s)",
            o["signatures"].as_array().unwrap().len(),
            trusted,
            valid
        ));
        s
    })?;

    if ok {
        Ok(())
    } else {
        Err(CliError::SignatureVerificationFailed {
            intact,
            signatures: statuses.len(),
            trusted,
        }
        .into())
    }
}
