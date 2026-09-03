//! A bounded soak: everything the embedded pitch promises can happen at
//! once, happening at once, on one `Control`.
//!
//! Writers ingest, pointers churn, collections run, a replica pulls, and a
//! scraper reads stats — concurrently, for a few wall-clock seconds. The
//! assertions are the invariants that must survive contention, not timing:
//! no operation fails for a concurrency reason, nothing pinned or named is
//! lost, and the directory is internally consistent afterwards.
//!
//! One process per *directory* is the documented rule; one `Control` shared
//! across threads is the documented exception — every method takes `&self`.
//! This test is that sentence, executed.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dag_control::test_utils::TestControl;
use dag_control::{Control, ControlError, GcRequest, SyncOptions};
use dag_core::{Cid, ContentStore, CoreError, PinScope, PinTarget};

/// How long the storm lasts. Long enough for thousands of operations per
/// role and several full collection cycles; short enough for the suite.
const SOAK: Duration = Duration::from_secs(4);

#[test]
fn everything_at_once_loses_nothing() {
    let tc = TestControl::new().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();

    // Recovery gate up front, so collections may run.
    tc.control.recovery_state.mark_complete_for_test().unwrap();

    // Aged, unreferenced garbage: old enough to pass the min-age gate, so
    // mid-storm collections genuinely delete (a storm in which nothing is
    // ever eligible would prove nothing about deletion under contention).
    let hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - Duration::from_secs(3600),
    );
    for i in 0..500u32 {
        let cid = tc
            .control
            .store
            .put_chunk(format!("aged garbage {i}").as_bytes(), None)
            .unwrap();
        filetime::set_file_mtime(tc.control.store.chunk_path(&cid), hour_ago).unwrap();
    }

    // Aged *adoptable* content: what a revert names. Old enough that no
    // ingest guard covers it — only the fix under test (naming notes the
    // reference) keeps a mid-sweep collection off it.
    let mut adoptable: Vec<Cid> = Vec::new();
    for i in 0..50u32 {
        let cid = tc
            .control
            .store
            .put_chunk(format!("old revision {i}").as_bytes(), None)
            .unwrap();
        filetime::set_file_mtime(tc.control.store.chunk_path(&cid), hour_ago).unwrap();
        adoptable.push(cid);
    }

    // A pinned baseline that must survive every collection in the storm.
    let precious = tc.control.store.put_chunk(b"the precious", None).unwrap();
    tc.control
        .pin_log
        .create(
            "soak/keep",
            PinTarget::Direct(precious.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    // Reopen: the in-flight registry is per-process and remembers the seed
    // writes above regardless of file mtimes, which would shield the "aged"
    // sets from every collection. Real aged garbage was written by an
    // *earlier* process; dropping and reopening the control is that reality.
    let data_dir = tc.control.path().to_path_buf();
    let seeded = tc.control;
    drop(seeded);
    let control = Arc::new(Control::open(&data_dir).unwrap());
    let replica = Arc::new(Control::open(replica_dir.path()).unwrap());
    // Guarantee one valid current head even if the collector wins the first
    // scheduling race and removes every still-unreferenced alternative.
    control
        .pointer_log
        .create("soak/adopted", adoptable[0].clone())
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let failures: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let fail = |failures: &Arc<std::sync::Mutex<Vec<String>>>, msg: String| {
        failures.lock().unwrap().push(msg);
    };

    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

    // ---- Writers: distinct content, some of it named ----------------------
    let put_count = Arc::new(AtomicUsize::new(0));
    for writer in 0..3u64 {
        let control = control.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        let put_count = put_count.clone();
        handles.push(std::thread::spawn(move || {
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let body = format!("writer {writer} chunk {i}");
                match control.store.put_chunk(body.as_bytes(), None) {
                    Ok(_) => {
                        put_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => fail(&failures, format!("put: {e}")),
                }
                i += 1;
            }
        }));
    }

    // ---- Pointer churn: one pointer per thread, updated hard --------------
    // Every named CID is recorded so the survivors can be audited afterwards.
    let mut churn_logs: Vec<Arc<std::sync::Mutex<Vec<Cid>>>> = Vec::new();
    for churner in 0..2u64 {
        let control = control.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        churn_logs.push(log.clone());
        handles.push(std::thread::spawn(move || {
            let id = format!("soak/churn{churner}");
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let body = format!("churn {churner} value {i}");
                let cid = match control.store.put_chunk(body.as_bytes(), None) {
                    Ok(cid) => cid,
                    Err(e) => {
                        fail(&failures, format!("churn put: {e}"));
                        continue;
                    }
                };
                let result = if i == 0 {
                    control.pointer_log.create(&id, cid.clone()).map(|_| ())
                } else {
                    control.pointer_log.update(&id, cid.clone()).map(|_| ())
                };
                match result {
                    Ok(()) => log.lock().unwrap().push(cid),
                    Err(e) => fail(&failures, format!("pointer {id}: {e}")),
                }
                i += 1;
            }
        }));
    }

    // ---- Collector: repeated full collections mid-storm -------------------
    // Default min-age: the storm's fresh writes are age-shielded (that gate
    // is exactly what protects a live ingest), while the pre-aged garbage
    // and adoptable sets are fully eligible.
    let gc_runs = Arc::new(AtomicUsize::new(0));
    {
        let control = control.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        let gc_runs = gc_runs.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match control.run_gc(&GcRequest::default()) {
                    Ok(_) => {
                        gc_runs.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => fail(&failures, format!("gc: {e}")),
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }));
    }

    // ---- Adopter: reverts a pointer to aged content mid-storm -------------
    // The race the soak first caught: naming old, unreferenced bytes while a
    // collection whose snapshot predates the name is mid-sweep. The contract
    // audited below: content readable at naming time is never collected
    // afterwards. Adoptions that lost the race to a *prior* sweep are
    // legitimately refused — publication now validates the reference closure
    // and cannot create a dangling head for bytes a prior sweep removed.
    let adopted: Arc<std::sync::Mutex<Vec<Cid>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let control = control.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        let adopted = adopted.clone();
        let targets = adoptable.clone();
        handles.push(std::thread::spawn(move || {
            let id = "soak/adopted";
            let mut created = true;
            for cid in targets.iter().cycle() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let result = if created {
                    control.pointer_log.update(id, cid.clone()).map(|_| ())
                } else {
                    control.pointer_log.create(id, cid.clone()).map(|_| ())
                };
                match result {
                    Ok(()) => created = true,
                    Err(dag_control::PointerError::Storage(CoreError::PreconditionFailed(_))) => {
                        // The collector got this still-unreferenced target
                        // first. Refusing it is the required fail-closed result.
                        continue;
                    }
                    Err(e) => {
                        fail(&failures, format!("adopt: {e}"));
                        continue;
                    }
                }
                // Readable now => must still be readable when the storm ends.
                if control.store.get_chunk(cid).is_ok() {
                    adopted.lock().unwrap().push(cid.clone());
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        }));
    }

    // ---- Replicator: pulls a consistent copy while everything moves -------
    let syncs = Arc::new(AtomicUsize::new(0));
    {
        let control = control.clone();
        let replica = replica.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        let syncs = syncs.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Mid-storm sources legitimately produce per-chunk failures
                // (a churned pointer can outrun the walk); refused *events*
                // would mean divergence, which one directory cannot have.
                match dag_control::sync::push(&control, &replica, &SyncOptions::default()) {
                    Ok(_) => {
                        syncs.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(ControlError::Invalid(msg))
                        if msg.contains("source event generation changed") =>
                    {
                        // Writers advanced the source while this snapshot
                        // was walking it. Retry on the next loop; that is
                        // the documented recovery, not a lost write.
                    }
                    Err(e) => fail(&failures, format!("sync: {e}")),
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }));
    }

    // ---- Scraper: the observability read path under write load ------------
    {
        let control = control.clone();
        let stop = stop.clone();
        let failures = failures.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Err(e) = control.stats() {
                    fail(&failures, format!("stats: {e}"));
                }
                let _ = control.metrics.render();
                std::thread::sleep(Duration::from_millis(20));
            }
        }));
    }

    // ---- Run the storm ------------------------------------------------------
    let started = Instant::now();
    while started.elapsed() < SOAK {
        std::thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        handle.join().expect("a soak thread panicked");
    }

    // ---- The audit ----------------------------------------------------------
    let failures = failures.lock().unwrap();
    assert!(
        failures.is_empty(),
        "operations failed under contention:\n{}",
        failures.join("\n")
    );

    // Work actually happened — a storm that did nothing proves nothing.
    // The floor is deliberately modest: every durable write here is an
    // F_FULLFSYNC, serialized at the device, and five roles fsync-storming
    // one SSD is exactly the contention this test exists to survive.
    assert!(
        put_count.load(Ordering::Relaxed) > 50,
        "writers barely ran: {}",
        put_count.load(Ordering::Relaxed)
    );
    assert!(gc_runs.load(Ordering::Relaxed) >= 2, "gc barely ran");
    assert!(syncs.load(Ordering::Relaxed) >= 2, "sync barely ran");

    // The pinned chunk survived every mid-storm collection.
    assert_eq!(control.store.get_chunk(&precious).unwrap(), b"the precious");

    // Collections deleted for real while everything else ran.
    assert!(
        control.metrics.gc_deleted_total.get() > 0,
        "no mid-storm collection deleted anything; the soak proved nothing"
    );

    // Every adoption that was readable when named is still here: naming
    // registers the reference, so no snapshot-stale sweep may take it.
    let adopted = adopted.lock().unwrap();
    assert!(!adopted.is_empty(), "the adopter never published a target");
    for cid in adopted.iter() {
        assert!(
            control.store.get_chunk(cid).is_ok(),
            "adopted content {cid} was collected after being named"
        );
    }

    // Every pointer resolves to the last CID its writer recorded, and the
    // full history of named CIDs survived collection: a pointer's history
    // entries are permanent even where superseded *bytes* are collectable.
    for (churner, log) in churn_logs.iter().enumerate() {
        let id = format!("soak/churn{churner}");
        let named = log.lock().unwrap();
        assert!(!named.is_empty());
        let head = control.pointer_log.get_head(&id).unwrap();
        assert_eq!(head.seq, named.len() as u64, "{id} lost an update");
        assert_eq!(
            &head.current_cid,
            named.last().unwrap(),
            "{id} resolved to something no writer wrote last"
        );
        // The current head's bytes must exist; GC treats heads as roots.
        control
            .store
            .get_chunk(named.last().unwrap())
            .expect("head bytes were collected");
    }

    // The event chain is internally consistent after the storm: a full
    // rebuild from the logs reproduces exactly the heads we hold.
    let rebuilt = control.rebuild_pointers().unwrap();
    assert!(rebuilt >= 2);
    for (churner, log) in churn_logs.iter().enumerate() {
        let id = format!("soak/churn{churner}");
        assert_eq!(
            &control.pointer_log.resolve(&id).unwrap(),
            log.lock().unwrap().last().unwrap()
        );
    }

    // Publication and collection share the mutation gate, and publication
    // validates the complete target closure. The race may refuse an update,
    // but it may never leave a dangling current head.
    let adopted_head = control.pointer_log.resolve("soak/adopted").unwrap();
    control
        .store
        .get_chunk(&adopted_head)
        .expect("publication left a dangling adopted head");

    // The replica converges once the storm has stopped.
    let report = dag_control::sync::push(&control, &replica, &SyncOptions::default()).unwrap();
    assert!(report.is_complete(), "{:?}", report.failures);
    for (churner, log) in churn_logs.iter().enumerate() {
        let id = format!("soak/churn{churner}");
        assert_eq!(
            &replica.pointer_log.resolve(&id).unwrap(),
            log.lock().unwrap().last().unwrap(),
            "replica disagrees about {id}"
        );
    }
}
