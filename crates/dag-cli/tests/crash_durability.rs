//! Kill an ingest and reopen the store — the one thing the durability suite
//! never did.
//!
//! `dag-storage`'s durability tests defend the write ordering by *reading* it:
//! they assert fsync counts and race a reader thread against a delete. None of
//! them kills a process mid-write and reopens the directory, so every
//! durability claim rested on the ordering being correct in the source rather
//! than on a survivor being observed. These do the latter, through the real
//! binary, on Unix (where `Child::kill` is `SIGKILL`).
//!
//! The claim under test is the one the whole write path is ordered around:
//! **the index never names bytes that are not durably present.** A process
//! killed part-way leaves unindexed files (garbage a reindex reclaims), never
//! an index entry pointing at bytes that never landed — so a reopened store
//! verifies clean, and re-running the same ingest completes and reads back
//! byte-for-byte.
//!
//! `SIGKILL` deliberately does *not* reproduce torn page-cache writes; that
//! needs power loss. The storage integration suite models the resulting short
//! canonical file directly. Together the tests assert both halves of the
//! recovery contract: a killed `--fast` writer leaves no bad durable index
//! entry, and a later ingest verifies/adopts intact orphans while repairing a
//! mismatched one before it publishes the manifest.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

/// 8 MiB, which the default chunker (avg 1 MiB) splits into roughly eight
/// chunks — enough that a durable ingest, fsyncing each one, is reliably still
/// running when we look, while keeping the whole test to a few seconds.
const FILE_SIZE: usize = 8 * 1024 * 1024;

fn dag_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dag"))
}

/// Deterministic pseudo-random bytes (xorshift64), written to `path` and
/// returned so a round trip can be checked exactly. Varied content is what
/// gives content-defined chunking real boundaries to find.
fn write_random_file(path: &Path, size: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut bytes = Vec::with_capacity(size);
    while bytes.len() < size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(size);
    fs::write(path, &bytes).unwrap();
    bytes
}

/// Count chunk files actually published to their canonical path:
/// `<data_dir>/data/<2 hex>/<62 hex>`. Excludes the `.tmp*` files a write is
/// still assembling, so this counts durable progress, not work in flight.
fn published_chunks(data_dir: &Path) -> usize {
    let root = data_dir.join("data");
    let Ok(shards) = fs::read_dir(&root) else {
        return 0;
    };
    let mut n = 0;
    for shard in shards.flatten() {
        let name = shard.file_name();
        let name = name.to_string_lossy();
        if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Ok(files) = fs::read_dir(shard.path()) {
            for f in files.flatten() {
                let fname = f.file_name();
                let fname = fname.to_string_lossy();
                if fname.len() == 62 && fname.bytes().all(|b| b.is_ascii_hexdigit()) {
                    n += 1;
                }
            }
        }
    }
    n
}

fn spawn_put(data_dir: &Path, file: &Path, fast: bool) -> Child {
    let mut cmd = Command::new(dag_bin());
    cmd.arg("--data-dir")
        .arg(data_dir)
        .arg("put")
        .arg("--file")
        .arg(file);
    if fast {
        cmd.arg("--fast");
    }
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dag put")
}

/// What the child was doing when we stopped watching.
#[derive(Debug, PartialEq)]
enum Kill {
    /// We killed it after chunks appeared but before it finished — the case
    /// the test is really about.
    MidIngest,
    /// It finished before we could catch it. Rare on a real disk with a
    /// durable ingest, but possible; the durable outcome must still hold, so
    /// the test proceeds either way.
    FinishedFirst,
}

/// Poll the data directory and `SIGKILL` the child once `min_chunks` have been
/// published, so the kill lands mid-ingest without relying on a fixed sleep.
/// Falls back to `FinishedFirst` if the ingest completes first.
fn kill_mid_ingest(child: &mut Child, data_dir: &Path, min_chunks: usize) -> Kill {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(_status) = child.try_wait().expect("try_wait") {
            return Kill::FinishedFirst;
        }
        if published_chunks(data_dir) >= min_chunks {
            child.kill().expect("SIGKILL the ingest");
            child.wait().expect("reap killed child");
            return Kill::MidIngest;
        }
        if Instant::now() >= deadline {
            // The ingest is stuck rather than fast; kill it anyway so the test
            // does not hang, and treat whatever landed as mid-ingest.
            let _ = child.kill();
            let _ = child.wait();
            return Kill::MidIngest;
        }
        sleep(Duration::from_millis(1));
    }
}

fn run(data_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(dag_bin());
    cmd.arg("--data-dir").arg(data_dir);
    for a in args {
        cmd.arg(a);
    }
    cmd.output().expect("run dag")
}

fn json(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {}",
            String::from_utf8_lossy(out)
        )
    })
}

/// The core ordering claim: a durable ingest killed part-way leaves a store
/// whose index verifies clean, that re-ingests to completion, and reads back
/// byte-for-byte.
#[test]
fn a_killed_durable_ingest_verifies_clean_and_reingests_intact() {
    let temp = TempDir::new().unwrap();
    let big = temp.path().join("big.bin");
    let original = write_random_file(&big, FILE_SIZE);
    let data_dir = temp.path().join("store");

    let mut child = spawn_put(&data_dir, &big, false);
    let how = kill_mid_ingest(&mut child, &data_dir, 2);
    eprintln!(
        "durable: {how:?}, {} chunks published before reopen",
        published_chunks(&data_dir)
    );

    // The index must never name bytes a crash left unwritten. A reopened store
    // must therefore verify clean — exit 0, nothing invalid, nothing missing.
    let verify = run(&data_dir, &["index", "verify", "--json"]);
    assert!(
        verify.status.success(),
        "a store reopened after a mid-ingest crash must verify clean (exit {:?}); stderr: {}",
        verify.status.code(),
        String::from_utf8_lossy(&verify.stderr)
    );
    let report = json(&verify.stdout);
    assert_eq!(
        report["invalid_chunks"], 0,
        "the index named bytes that are not intact: {report}"
    );
    assert_eq!(
        report["missing_chunks"], 0,
        "the index named bytes that are not present — the ordering claim broke: {report}"
    );

    // Re-running the same ingest must complete. Unindexed leftovers are
    // verified and adopted when intact, repaired when mismatched, and freshly
    // written where absent; either way the run finishes and names the file.
    let put = run(
        &data_dir,
        &["put", "--file", big.to_str().unwrap(), "--json"],
    );
    assert!(
        put.status.success(),
        "re-ingest after a crash must succeed; stderr: {}",
        String::from_utf8_lossy(&put.stderr)
    );
    let cid = json(&put.stdout)["cid"].as_str().unwrap().to_string();

    // And the content the store now names must be exactly what went in —
    // every chunk re-hashed as `get` reassembles it.
    let roundtrip = temp.path().join("roundtrip.bin");
    let get = run(
        &data_dir,
        &["get", "--cid", &cid, "--out", roundtrip.to_str().unwrap()],
    );
    assert!(
        get.status.success(),
        "get after re-ingest must reassemble the file; stderr: {}",
        String::from_utf8_lossy(&get.stderr)
    );
    assert_eq!(
        fs::read(&roundtrip).unwrap(),
        original,
        "the reassembled file does not match the bytes that were ingested"
    );

    // A clean verify after the whole cycle, for good measure.
    let verify2 = run(&data_dir, &["index", "verify", "--json"]);
    assert!(verify2.status.success(), "store must still verify clean");
}

/// The `--fast` path: same crash, followed by a durable re-ingest. Process
/// death keeps the page cache, but the recovery claim is stronger than that
/// accident: a re-ingest must pass every present chunk through the integrity
/// gate and finish with a clean index and byte-identical content.
#[test]
fn a_killed_fast_ingest_never_leaves_the_index_blessing_bad_bytes() {
    let temp = TempDir::new().unwrap();
    let big = temp.path().join("big.bin");
    let original = write_random_file(&big, FILE_SIZE);
    let data_dir = temp.path().join("store");

    let mut child = spawn_put(&data_dir, &big, true);
    let how = kill_mid_ingest(&mut child, &data_dir, 2);
    eprintln!(
        "fast: {how:?}, {} chunks published before reopen",
        published_chunks(&data_dir)
    );

    // A `--fast` ingest defers its index writes, so a mid-ingest kill leaves
    // present-but-unindexed files. Anything it did index crossed the same
    // bytes-before-index durability barrier and therefore must verify clean.
    let verify = run(&data_dir, &["index", "verify", "--json"]);
    assert!(
        verify.status.success(),
        "verify after a fast-ingest crash must pass, got {:?}: {}",
        verify.status.code(),
        String::from_utf8_lossy(&verify.stderr)
    );
    eprintln!("fast: verify-after-crash exit {:?}", verify.status.code());

    // Re-run durably. Every present object is re-hashed; intact orphans are
    // adopted and a torn one is rewritten before the manifest can be returned.
    let put = run(
        &data_dir,
        &["put", "--file", big.to_str().unwrap(), "--json"],
    );
    assert!(
        put.status.success(),
        "durable re-ingest after a fast crash must succeed; stderr: {}",
        String::from_utf8_lossy(&put.stderr)
    );
    let cid = json(&put.stdout)["cid"].as_str().unwrap().to_string();

    let verify2 = run(&data_dir, &["index", "verify", "--json"]);
    assert!(
        verify2.status.success(),
        "verify after durable re-ingest must pass, got {:?}: {}",
        verify2.status.code(),
        String::from_utf8_lossy(&verify2.stderr)
    );
    eprintln!(
        "fast: verify-after-reingest exit {:?}",
        verify2.status.code()
    );

    // The load-bearing invariant: if the index blesses the store, the content
    // it names is genuinely intact. `get` re-hashes every chunk, so this
    // catches an index that vouches for bytes it should not.
    let roundtrip = temp.path().join("roundtrip.bin");
    let get = run(
        &data_dir,
        &["get", "--cid", &cid, "--out", roundtrip.to_str().unwrap()],
    );
    assert!(
        get.status.success(),
        "index verified clean but get failed — the index blessed bytes it \
         should not have; stderr: {}",
        String::from_utf8_lossy(&get.stderr)
    );
    assert_eq!(
        fs::read(&roundtrip).unwrap(),
        original,
        "index verified clean but the reassembled file is wrong — silent corruption"
    );
}
