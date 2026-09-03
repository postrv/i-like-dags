//! The scale-envelope experiment: what a million chunks actually costs.
//!
//! Run manually, in release, against a scratch directory — in two phases so
//! each fits a bounded shell:
//!
//! ```bash
//! cargo build --release --example scale_envelope -p dag-control
//! ./target/release/examples/scale_envelope seed    /tmp/scale 1000000 100000
//! /usr/bin/time -l \
//! ./target/release/examples/scale_envelope measure /tmp/scale 1000000 100000
//! ```
//!
//! Not a test: it takes minutes and gigabytes on purpose. The numbers it
//! prints are recorded in `docs/experiments/scale-envelope.md`; re-run it
//! whenever retention, collection, sync or the store change shape.
//!
//! Three scale dimensions, exercised deliberately:
//!
//! - **store size** (`loose` unreferenced chunks): ingest, collection scan
//!   and delete, stats;
//! - **protected-set size** (`tree` chunks under one `:full` subtree pin,
//!   linked through a fan-out-1000 entry tree — the same shape `file/v1`
//!   manifests produce): retention expansion (R4), the GC protected set;
//! - **sync wanted-set**: everything the pin and pointers reach travels to a
//!   fresh replica; the loose million correctly does not.
//!
//! Chunk content is a pure function of its index, so `measure` can recompute
//! any CID `seed` stored without a manifest file between the phases.

use std::path::PathBuf;
use std::time::Instant;

use dag_control::{Control, GcRequest, SyncOptions};
use dag_core::{Cid, ContentStore, Entry, Link, PinScope, PinTarget};

const LOOSE_TAG: u8 = 0xA5;
const TREE_TAG: u8 = 0x5A;

fn chunk_body(tag: u8, i: usize) -> [u8; 1024] {
    let mut buf = [0u8; 1024];
    buf[..8].copy_from_slice(&(i as u64).to_le_bytes());
    buf[8] = tag;
    buf
}

struct Phases(Vec<(&'static str, f64, String)>);

impl Phases {
    fn timed(&mut self, name: &'static str, f: impl FnOnce() -> String) {
        let start = Instant::now();
        let detail = f();
        let seconds = start.elapsed().as_secs_f64();
        eprintln!("{:>32}  {:>9.2}s  {}", name, seconds, detail);
        self.0.push((name, seconds, detail));
    }

    fn dump(&self) {
        println!("phase,seconds,detail");
        for (name, seconds, detail) in &self.0 {
            println!("{},{:.3},{}", name, seconds, detail);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = || -> ! {
        eprintln!("usage: scale_envelope <seed|measure> <work-dir> [loose] [tree]");
        std::process::exit(64);
    };
    let mode = args.first().cloned().unwrap_or_else(|| usage());
    let work_dir = PathBuf::from(args.get(1).cloned().unwrap_or_else(|| usage()));
    let loose: usize = args
        .get(2)
        .map(|s| s.parse().expect("loose count"))
        .unwrap_or(1_000_000);
    let tree: usize = args
        .get(3)
        .map(|s| s.parse().expect("tree count"))
        .unwrap_or(100_000);

    let mut phases = Phases(Vec::new());
    match mode.as_str() {
        "seed" => seed(&work_dir, loose, tree, &mut phases),
        "measure" => measure(&work_dir, loose, tree, &mut phases),
        _ => usage(),
    }
    phases.dump();
}

fn seed(work_dir: &std::path::Path, loose: usize, tree: usize, phases: &mut Phases) {
    if work_dir.exists() {
        eprintln!("refusing to seed over existing {}", work_dir.display());
        std::process::exit(64);
    }
    std::fs::create_dir_all(work_dir).expect("create work dir");
    let control = Control::open(&work_dir.join("primary")).expect("open primary");

    phases.timed("ingest loose (bulk, deferred)", || {
        control
            .bulk_ingest(|staging| {
                for i in 0..loose {
                    staging.put_chunk(&chunk_body(LOOSE_TAG, i), None)?;
                }
                Ok::<_, dag_core::CoreError>(())
            })
            .expect("bulk ingest");
        format!("{loose} x 1KiB")
    });

    let mut leaves: Vec<Cid> = Vec::with_capacity(tree);
    phases.timed("ingest tree leaves", || {
        control
            .bulk_ingest(|staging| {
                for i in 0..tree {
                    leaves.push(staging.put_chunk(&chunk_body(TREE_TAG, i), None)?);
                }
                Ok::<_, dag_core::CoreError>(())
            })
            .expect("tree ingest");
        format!("{tree} x 1KiB")
    });

    let mut root: Option<Cid> = None;
    phases.timed("build entry tree", || {
        let mut level: Vec<Cid> = leaves.clone();
        let mut entries = 0usize;
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(1000));
            for group in level.chunks(1000) {
                let entry = Entry {
                    payload: Vec::new(),
                    links: group
                        .iter()
                        .map(|cid| Link {
                            name: None,
                            target: cid.clone(),
                        })
                        .collect(),
                    meta: None,
                };
                next.push(control.store.put_entry(&entry).expect("put entry"));
                entries += 1;
            }
            level = next;
        }
        root = Some(level[0].clone());
        format!("{entries} interior entries")
    });
    let root = root.unwrap();

    phases.timed("create 1000 pointers", || {
        for (i, cid) in leaves
            .iter()
            .step_by((tree / 1000).max(1))
            .take(1000)
            .enumerate()
        {
            control
                .pointer_log
                .create(&format!("scale/p{i}"), cid.clone())
                .expect("pointer create");
        }
        String::new()
    });

    phases.timed("pin subtree :full", || {
        control
            .pin_log
            .create(
                "scale/keep-tree",
                PinTarget::Subtree {
                    root: root.clone(),
                    max_depth: None,
                },
                PinScope::Global,
                None,
                None,
            )
            .expect("pin create");
        String::new()
    });
}

fn measure(work_dir: &std::path::Path, loose: usize, tree: usize, phases: &mut Phases) {
    let control = Control::open(&work_dir.join("primary")).expect("open primary");

    phases.timed("rebuild (recovery gate)", || {
        let pointers = control.rebuild_pointers().expect("rebuild pointers");
        let pins = control.rebuild_pins(false).expect("rebuild pins");
        format!("{} pointers, {} pins", pointers, pins.heads_rebuilt)
    });

    phases.timed("stats()", || {
        let stats = control.stats().expect("stats");
        format!("{} chunks, {} bytes", stats.chunks, stats.bytes)
    });

    phases.timed("metrics render", || {
        format!(
            "{} bytes of exposition text",
            control.metrics.render().len()
        )
    });

    phases.timed("retention refresh (R4 walk)", || {
        control.retention.refresh_cache().expect("refresh");
        String::new()
    });

    let replica = Control::open(&work_dir.join("replica")).expect("open replica");
    phases.timed("sync push referenced set", || {
        let report = dag_control::sync::push(&control, &replica, &SyncOptions::default())
            .expect("sync push");
        assert!(report.is_complete(), "{} failures", report.failures.len());
        format!(
            "{} chunks, {} bytes, {} ptr events",
            report.chunks_sent, report.bytes_sent, report.pointer_events
        )
    });

    phases.timed("sync push (repeat, warm)", || {
        let report = dag_control::sync::push(&control, &replica, &SyncOptions::default())
            .expect("repeat sync");
        assert_eq!(report.chunks_sent, 0, "warm sync re-sent content");
        format!("{} skipped", report.chunks_skipped)
    });

    let request = GcRequest {
        min_age_secs: 0,
        ..Default::default()
    };

    phases.timed("gc dry run", || {
        let report = control
            .run_gc(&GcRequest {
                dry_run: true,
                ..request.clone()
            })
            .expect("gc dry");
        format!(
            "{} examined, {} would delete",
            report.total_chunks_examined, report.chunks_deleted
        )
    });

    phases.timed("gc real run", || {
        let report = control.run_gc(&request).expect("gc real");
        format!(
            "{} deleted, {} bytes freed, {} protected",
            report.chunks_deleted, report.bytes_freed, report.protected_by_pins
        )
    });

    phases.timed("stats() after collection", || {
        format!("{} chunks remain", control.stats().expect("stats").chunks)
    });

    // The replica proves the transfer, not just the report: sampled leaves
    // under the pin must be present and intact where they landed. Loose
    // chunks correctly did not travel.
    phases.timed("replica spot verify", || {
        let mut checked = 0usize;
        for i in (0..tree).step_by((tree / 1000).max(1)) {
            let expected = Cid::compute(&chunk_body(TREE_TAG, i));
            let bytes = replica.store.get_chunk(&expected).expect("replica read");
            assert_eq!(Cid::compute(&bytes), expected);
            checked += 1;
        }
        let loose_sample = Cid::compute(&chunk_body(LOOSE_TAG, loose / 2));
        assert!(
            !replica.store.has_chunk(&loose_sample).unwrap_or(true),
            "unreferenced content travelled"
        );
        format!("{checked} leaves re-hashed on the replica")
    });
}
