//! `dag verify` when the signature index names an entry the store lost.
//!
//! Found live: after collection took a signature entry (pre-fix), `verify`
//! died with `Chunk not found` — exit 66, no verdict, no hint of what was
//! lost. The control layer now reports the loss as a `<missing>` status;
//! this pins the CLI half: the report renders (the sentinel is shorter than
//! the 16 hex chars the renderer slices), the verdict names the loss, and
//! the exit code is 65 — "no trusted signature", the failure with a remedy —
//! not a panic and not a bare I/O error.

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

#[test]
fn a_lost_signature_entry_degrades_the_verdict_instead_of_erroring() -> Result<()> {
    let dir = TempDir::new()?;

    let out = dag(&dir)
        .args(["put", "--data", "release artifact"])
        .output()?;
    assert!(out.status.success(), "put failed: {out:?}");
    let cid = stdout(&out).trim().to_string();

    let out = dag(&dir)
        .args(["key", "generate", "--id", "builder", "--trust"])
        .output()?;
    assert!(out.status.success(), "key generate failed: {out:?}");

    let out = dag(&dir)
        .args(["sign", "--cid", &cid, "--key", "builder"])
        .output()?;
    assert!(out.status.success(), "sign failed: {out:?}");
    let sign_text = stdout(&out);
    let sig_cid = sign_text
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("sign output names the signature entry CID")
        .to_string();

    // The verdict is trusted while the entry exists.
    let out = dag(&dir).args(["verify", "--cid", &cid]).output()?;
    assert!(out.status.success(), "verify should pass pre-loss: {out:?}");

    // Lose the signature entry the way any chunk is lost: its file goes.
    let sig_path = dir
        .path()
        .join("data")
        .join(&sig_cid[..2])
        .join(&sig_cid[2..]);
    std::fs::remove_file(&sig_path)?;

    let out = dag(&dir).args(["verify", "--cid", &cid]).output()?;
    let text = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(65),
        "expected exit 65 (no trusted signature), got {:?}: {text}",
        out.status.code()
    );
    assert!(
        text.contains("MISSING"),
        "the report must say the entry is missing, got: {text}"
    );
    Ok(())
}
