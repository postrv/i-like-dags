//! "What configuration was live at the moment of the incident?"
//!
//! The history was listable but not resolvable, so answering that meant
//! piping `pointer history` through `jq` and comparing timestamps by hand.
//! ALL_USE_CASES.md §8 described a resolve at a sequence number as though it
//! existed; these tests are it existing.

use std::process::Command;

use anyhow::Result;
use tempfile::TempDir;

fn dag(dir: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dag"));
    cmd.arg("--data-dir").arg(dir.path());
    cmd
}

fn run(dir: &TempDir, args: &[&str]) -> Result<(bool, String, String)> {
    let out = dag(dir).args(args).output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn put(dir: &TempDir, data: &str) -> Result<String> {
    let (ok, out, err) = run(dir, &["put", "--data", data])?;
    assert!(ok, "put failed: {err}");
    Ok(out.trim().to_string())
}

/// Three deployed configurations, oldest first.
fn seed(dir: &TempDir) -> Result<Vec<String>> {
    let v1 = put(dir, "replicas=1")?;
    let v2 = put(dir, "replicas=3")?;
    let v3 = put(dir, "replicas=9")?;

    let (ok, _, err) = run(dir, &["pointer", "create", "--id", "cfg", "--cid", &v1])?;
    assert!(ok, "create failed: {err}");
    for cid in [&v2, &v3] {
        let (ok, _, err) = run(dir, &["pointer", "update", "--id", "cfg", "--cid", cid])?;
        assert!(ok, "update failed: {err}");
    }
    Ok(vec![v1, v2, v3])
}

#[test]
fn resolve_without_flags_still_gives_the_current_head() -> Result<()> {
    let dir = TempDir::new()?;
    let cids = seed(&dir)?;

    let (ok, out, _) = run(&dir, &["pointer", "resolve", "--id", "cfg"])?;
    assert!(ok);
    assert_eq!(out.trim(), cids[2], "the default must not change meaning");
    Ok(())
}

#[test]
fn at_seq_resolves_the_configuration_that_was_live_then() -> Result<()> {
    let dir = TempDir::new()?;
    let cids = seed(&dir)?;

    for (seq, expected) in [(1, &cids[0]), (2, &cids[1]), (3, &cids[2])] {
        let (ok, out, err) = run(
            &dir,
            &[
                "pointer",
                "resolve",
                "--id",
                "cfg",
                "--at-seq",
                &seq.to_string(),
            ],
        )?;
        assert!(ok, "resolve at seq {seq} failed: {err}");
        assert!(
            out.contains(expected.as_str()),
            "seq {seq} should resolve to {expected}, got {out}"
        );
    }
    Ok(())
}

#[test]
fn as_of_picks_the_last_update_at_or_before_the_instant() -> Result<()> {
    let dir = TempDir::new()?;
    let cids = seed(&dir)?;

    // Far future: the newest version was live.
    let (ok, out, err) = run(
        &dir,
        &[
            "pointer",
            "resolve",
            "--id",
            "cfg",
            "--as-of",
            "2099-01-01T00:00:00Z",
        ],
    )?;
    assert!(ok, "as-of failed: {err}");
    assert!(out.contains(cids[2].as_str()), "got {out}");

    // Before the pointer existed: that is a refusal, not an empty answer.
    let (ok, _, err) = run(
        &dir,
        &[
            "pointer",
            "resolve",
            "--id",
            "cfg",
            "--as-of",
            "2000-01-01T00:00:00Z",
        ],
    )?;
    assert!(!ok, "an instant before the first update has no answer");
    assert!(
        err.contains("did not exist"),
        "the message should say why, got {err}"
    );
    Ok(())
}

#[test]
fn a_missing_sequence_and_a_bad_instant_are_both_refused_clearly() -> Result<()> {
    let dir = TempDir::new()?;
    seed(&dir)?;

    let (ok, _, err) = run(
        &dir,
        &["pointer", "resolve", "--id", "cfg", "--at-seq", "9"],
    )?;
    assert!(!ok);
    assert!(err.contains("no update at sequence 9"), "got {err}");

    let (ok, _, err) = run(
        &dir,
        &[
            "pointer",
            "resolve",
            "--id",
            "cfg",
            "--as-of",
            "last tuesday",
        ],
    )?;
    assert!(!ok);
    assert!(
        err.contains("RFC 3339"),
        "the message should name the format it wanted, got {err}"
    );
    Ok(())
}

#[test]
fn a_historical_resolve_says_when_the_content_is_gone() -> Result<()> {
    // The honest half of this feature. Only a pointer's *current* head is a
    // retention root, so a superseded version stays named for ever while its
    // bytes become collectable. Answering "what was live" with a CID whose
    // content has been collected, and not saying so, would be worse than not
    // answering.
    let dir = TempDir::new()?;
    let cids = seed(&dir)?;

    // GC is gated on a complete, coherent recovery of every safety index;
    // rebuilding only pointer and pin heads is deliberately insufficient.
    let (ok, _, err) = run(&dir, &["recover"])?;
    assert!(ok, "recovery failed: {err}");
    let (ok, _, err) = run(&dir, &["gc", "run", "--min-age-secs", "0"])?;
    assert!(ok, "gc failed: {err}");

    // The current head survived, so it still reports present.
    let (ok, out, _) = run(
        &dir,
        &[
            "--json", "pointer", "resolve", "--id", "cfg", "--at-seq", "3",
        ],
    )?;
    assert!(ok);
    let head: serde_json::Value = serde_json::from_str(&out)?;
    assert_eq!(head["cid"], cids[2]);
    assert_eq!(
        head["content_present"], true,
        "the live version is a retention root"
    );

    // A superseded one did not.
    let (ok, out, _) = run(
        &dir,
        &[
            "--json", "pointer", "resolve", "--id", "cfg", "--at-seq", "1",
        ],
    )?;
    assert!(ok, "naming a collected version is still a valid answer");
    let old: serde_json::Value = serde_json::from_str(&out)?;
    assert_eq!(old["cid"], cids[0]);
    assert_eq!(
        old["content_present"], false,
        "an unpinned superseded version is collectable, and the answer must admit it"
    );
    Ok(())
}
