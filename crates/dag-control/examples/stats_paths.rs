//! Times the two ways of answering "how much content is here", against the
//! same directory, so the claim in `docs/experiments/scale-envelope.md` is a
//! measurement rather than an assertion.
//!
//! ```bash
//! cargo build --release --example stats_paths -p dag-control
//! ./target/release/examples/stats_paths /tmp/scale/primary
//! ```
//!
//! - **index scan** — one redb read transaction summing recorded lengths.
//!   What [`Control::stats`] does.
//! - **filesystem walk** — enumerate every chunk file, then `stat` each one.
//!   What it used to do, kept here as the comparison and as the fallback for
//!   a store opened without an index.

use std::path::PathBuf;
use std::time::Instant;

use dag_control::Control;
use dag_storage::GcCapableStore;

fn main() {
    let dir = match std::env::args().nth(1) {
        Some(dir) => PathBuf::from(dir),
        None => {
            eprintln!("usage: stats_paths <data-dir>");
            std::process::exit(64);
        }
    };

    let control = Control::open(&dir).expect("open control");

    let started = Instant::now();
    let stats = control.stats().expect("stats");
    let index_secs = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let cids = control.store.list_all_cids().expect("list");
    let walked_bytes: u64 = cids
        .iter()
        .filter_map(|cid| control.store.get_chunk_size(cid).ok())
        .map(|s| s as u64)
        .sum();
    let walk_secs = started.elapsed().as_secs_f64();

    println!("path,seconds,chunks,bytes");
    println!(
        "index scan,{:.3},{},{}",
        index_secs, stats.chunks, stats.bytes
    );
    println!(
        "filesystem walk,{:.3},{},{}",
        walk_secs,
        cids.len(),
        walked_bytes
    );
    // Stated as a ratio, not as "faster": at small, cache-warm sizes the two
    // paths measure the same, and the index path is preferred for what it
    // *counts* (see docs/experiments/scale-envelope.md) as much as for speed.
    if index_secs > 0.0 {
        eprintln!("walk / index = {:.2}x", walk_secs / index_secs.max(1e-9));
    }
    // A difference here is not an error: files the index never saw are
    // orphans from an interrupted ingest, which is exactly what the index
    // deliberately does not count.
    if cids.len() != stats.chunks {
        eprintln!(
            "note: {} file(s) on disk are unindexed (orphans awaiting reindex)",
            cids.len().saturating_sub(stats.chunks)
        );
    }
}
