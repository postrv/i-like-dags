//! Explicit store-adoption diagnostics when `control.redb` is gone but
//! `data/` survives.
//!
//! Filed control tables are authoritative by default: strict-decoding event
//! bytes found only in the content store are unsigned candidates, not trusted
//! state. These tests exercise the explicit trust-accepting diagnostic helpers
//! directly. They prove those helpers can reconstruct individual logs, but
//! also that partial reconstruction cannot mint the full recovery certificate
//! required by garbage collection.

use std::path::Path;

use dag_control::{Control, ControlError, CONTROL_DB_FILE};
use dag_core::{
    ContentStore, Determinism, JobId, JobInput, JobPolicy, JobSpec, PinScope, PinState, PinTarget,
};
use tempfile::TempDir;

/// Delete the control database, leaving `data/` untouched, and reopen.
///
/// redb locks the file to one handle, so the caller must have dropped its
/// `Control` before calling this.
fn reopen_without_database(dir: &Path) -> Control {
    let db = dir.join(CONTROL_DB_FILE);
    assert!(db.exists(), "no database to delete at {}", db.display());
    std::fs::remove_file(&db).unwrap();
    assert!(dir.join("data").exists(), "the chunk store was removed too");
    Control::open(dir).unwrap()
}

fn job_spec(id: &str, code_ref: &str) -> JobSpec {
    JobSpec {
        job_id: JobId::from(id),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["out".into()],
        code_ref: code_ref.into(),
        policy: JobPolicy::default(),
        config: None,
    }
}

#[test]
fn bounded_partial_store_rebuilds_refuse_before_mutating_tables() {
    let temp = TempDir::new().unwrap();
    {
        let control = Control::open(temp.path()).unwrap();
        let target = control.store.put_chunk(b"target", None).unwrap();
        control.pointer_log.create("model", target).unwrap();
    }

    let control = reopen_without_database(temp.path());
    assert!(control.pointer_log.list_pointers().unwrap().is_empty());
    assert!(control.pin_log.list().unwrap().is_empty());
    assert!(control.job_log.list_jobs().unwrap().is_empty());

    let pointer_error = control
        .rebuild_pointers_from_store_with_limits(1, 0)
        .unwrap_err();
    assert!(matches!(
        pointer_error,
        ControlError::RecoveryInventoryLimit { limit: 1 }
    ));

    let pin_error = control
        .rebuild_pins_from_store_with_limits(0, 1)
        .unwrap_err();
    assert!(matches!(
        pin_error,
        ControlError::RecoveryBytesLimit { limit: 1, .. }
    ));

    let job_error = control
        .rebuild_jobs_from_store_with_limits(1, 0)
        .unwrap_err();
    assert!(matches!(
        job_error,
        ControlError::RecoveryInventoryLimit { limit: 1 }
    ));

    assert!(control.pointer_log.list_pointers().unwrap().is_empty());
    assert!(control.pin_log.list().unwrap().is_empty());
    assert!(control.job_log.list_jobs().unwrap().is_empty());

    let report = control
        .rebuild_pointers_from_store_with_limits(0, 0)
        .unwrap();
    assert_eq!(report.heads_rebuilt, 1);
    assert_eq!(control.pointer_log.list_pointers().unwrap(), vec!["model"]);
}

#[test]
fn pointers_and_their_histories_come_back_from_the_store_alone() {
    let temp = TempDir::new().unwrap();

    let (v1, v2, v3, before_events) = {
        let control = Control::open(temp.path()).unwrap();
        let v1 = control.store.put_chunk(b"version one", None).unwrap();
        let v2 = control.store.put_chunk(b"version two", None).unwrap();
        let v3 = control.store.put_chunk(b"version three", None).unwrap();

        control.pointer_log.create("model", v1.clone()).unwrap();
        control.pointer_log.update("model", v2.clone()).unwrap();
        control.pointer_log.update("model", v3.clone()).unwrap();
        control.pointer_log.create("dataset", v1.clone()).unwrap();

        let before = control.pointer_log.event_cids().unwrap();
        (v1, v2, v3, before)
    };

    let control = reopen_without_database(temp.path());

    // A table-only rebuild has no filed events after the database was lost.
    assert_eq!(
        control.pointer_log.rebuild_from_events().unwrap(),
        0,
        "the table-based rebuild found events in a database that was deleted"
    );
    assert!(control.pointer_log.list_pointers().unwrap().is_empty());

    // The explicit trust-accepting store scan can reconstruct this log.
    let report = control.rebuild_pointers_from_store().unwrap();
    assert_eq!(report.heads_rebuilt, 2, "{:?}", report);
    assert_eq!(report.events_found, 4, "{:?}", report);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    assert_eq!(
        control.pointer_log.list_pointers().unwrap(),
        vec!["dataset", "model"]
    );
    assert_eq!(control.pointer_log.resolve("model").unwrap(), v3);
    assert_eq!(control.pointer_log.resolve("dataset").unwrap(), v1);

    let history = control.pointer_log.history("model", 1..4).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].new, v1);
    assert_eq!(history[1].new, v2);
    assert_eq!(history[2].new, v3);
    assert_eq!(history[1].prev, Some(v1.clone()));
    assert_eq!(history[2].prev, Some(v2));

    // Byte-identical: the recovered log names the same event entries, not
    // re-minted ones.
    assert_eq!(control.pointer_log.event_cids().unwrap(), before_events);

    // Neither this subsystem repair nor the pointer+pin pair can certify the
    // job, signature, effect-claim, and chunk-index recovery phases.
    assert!(
        !control.is_recovered().unwrap(),
        "a pointer-only store rebuild minted a full recovery certificate"
    );
    control.rebuild_pins_from_store().unwrap();
    assert!(
        !control.is_recovered().unwrap(),
        "partial pointer and pin rebuilds minted a full recovery certificate"
    );
}

#[test]
fn pins_and_their_histories_come_back_from_the_store_alone() {
    let temp = TempDir::new().unwrap();

    let (kept, dropped, before_events) = {
        let control = Control::open(temp.path()).unwrap();
        let kept = control.store.put_chunk(b"keep this", None).unwrap();
        let dropped = control.store.put_chunk(b"let this go", None).unwrap();

        control
            .pin_log
            .create(
                "keep",
                PinTarget::Direct(kept.clone()),
                PinScope::Global,
                None,
                Some("alice".into()),
            )
            .unwrap();
        control
            .pin_log
            .create(
                "temp",
                PinTarget::Subtree {
                    root: dropped.clone(),
                    max_depth: Some(3),
                },
                PinScope::Local {
                    node_id: "node-a".into(),
                },
                None,
                None,
            )
            .unwrap();
        control
            .pin_log
            .deactivate("temp", Some("bob".into()))
            .unwrap();

        let before = control.pin_log.event_cids().unwrap();
        (kept, dropped, before)
    };

    let control = reopen_without_database(temp.path());

    let table_rebuild = control.pin_log.rebuild(false).unwrap();
    assert_eq!(
        table_rebuild.heads_rebuilt, 0,
        "the table-based rebuild found events in a database that was deleted"
    );

    let report = control.rebuild_pins_from_store().unwrap();
    assert_eq!(report.heads_rebuilt, 2, "{:?}", report);
    assert_eq!(report.events_found, 3, "{:?}", report);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    assert_eq!(control.pin_log.list().unwrap(), vec!["keep", "temp"]);

    let keep = control.pin_log.head("keep").unwrap();
    assert_eq!(keep.event.seq, 1);
    assert!(matches!(keep.event.state, PinState::Active));
    assert_eq!(keep.event.target, PinTarget::Direct(kept.clone()));
    assert_eq!(keep.event.author, Some("alice".into()));

    let temp_pin = control.pin_log.head("temp").unwrap();
    assert_eq!(temp_pin.event.seq, 2);
    assert!(matches!(temp_pin.event.state, PinState::Deactivated));
    assert_eq!(temp_pin.event.author, Some("bob".into()));
    assert_eq!(
        temp_pin.event.scope,
        PinScope::Local {
            node_id: "node-a".into()
        }
    );

    let history = control.pin_log.history("temp", 1..3).unwrap();
    assert_eq!(history.len(), 2);
    assert!(matches!(history[0].state, PinState::Active));
    assert!(matches!(history[1].state, PinState::Deactivated));
    assert_eq!(
        history[1].target,
        PinTarget::Subtree {
            root: dropped,
            max_depth: Some(3)
        }
    );

    assert_eq!(control.pin_log.event_cids().unwrap(), before_events);

    // The reverse index is derived too, and recovery has to rebuild it or
    // `pin list-by-target` silently reports nothing.
    assert_eq!(
        control
            .pin_log
            .list_by_target(&PinTarget::Direct(kept))
            .unwrap(),
        vec!["keep".to_string()]
    );
}

#[test]
fn job_specs_come_back_from_the_store_alone() {
    let temp = TempDir::new().unwrap();

    {
        let control = Control::open(temp.path()).unwrap();
        control.create_job(job_spec("digest", "hash")).unwrap();
        control.create_job(job_spec("join", "concat")).unwrap();
        control.trigger_job(JobId::from("digest")).unwrap();
    }

    let control = reopen_without_database(temp.path());

    assert_eq!(
        control.job_log.rebuild().unwrap().heads_rebuilt,
        0,
        "the table-based rebuild found events in a database that was deleted"
    );

    let report = control.rebuild_jobs_from_store().unwrap();
    assert_eq!(report.heads_rebuilt, 2, "{:?}", report);
    assert_eq!(report.events_found, 2, "{:?}", report);

    let mut jobs: Vec<String> = control
        .job_log
        .list_jobs()
        .unwrap()
        .into_iter()
        .map(|j| j.spec.job_id.to_string())
        .collect();
    jobs.sort();
    assert_eq!(jobs, vec!["digest", "join"]);

    let digest = control
        .job_log
        .get_job(&JobId::from("digest"))
        .unwrap()
        .unwrap();
    assert_eq!(digest.spec.code_ref, "hash");
    assert_eq!(digest.spec.declared_outputs, vec!["out".to_string()]);
    // Runs live only in the database, so the run history is genuinely gone.
    // Recording zero is the honest answer; claiming one would desynchronise
    // the next run's ID from the runs table.
    assert_eq!(digest.trigger_count, 0);
}

/// Recovery has to be idempotent, and it must not fight the incremental path:
/// after a store rebuild, ordinary updates keep working from the recovered
/// sequence rather than restarting it.
#[test]
fn a_recovered_log_keeps_being_appended_to() {
    let temp = TempDir::new().unwrap();

    let v1 = {
        let control = Control::open(temp.path()).unwrap();
        let v1 = control.store.put_chunk(b"one", None).unwrap();
        control.pointer_log.create("p", v1.clone()).unwrap();
        v1
    };

    let control = reopen_without_database(temp.path());
    control.rebuild_pointers_from_store().unwrap();

    // Running it twice changes nothing.
    let again = control.rebuild_pointers_from_store().unwrap();
    assert_eq!(again.heads_rebuilt, 1);
    assert!(again.skipped.is_empty(), "{:?}", again.skipped);
    assert_eq!(control.pointer_log.resolve("p").unwrap(), v1);

    let v2 = control.store.put_chunk(b"two", None).unwrap();
    let (seq, prev) = control.pointer_log.update("p", v2.clone()).unwrap();
    assert_eq!(seq, 2, "the recovered head's sequence was not carried over");
    assert_eq!(prev, v1);
    assert_eq!(control.pointer_log.resolve("p").unwrap(), v2);
    assert_eq!(control.pointer_log.history("p", 1..3).unwrap().len(), 2);
}

/// A store scan identifies events by strict CBOR decode, which is a much
/// stronger filter than the collector's field sniffing but is still a guess.
/// Ordinary content must not be mistaken for a log, and a chain that does not
/// validate must be skipped and *counted*, not silently dropped.
#[test]
fn ordinary_content_is_not_mistaken_for_an_event_log() {
    let temp = TempDir::new().unwrap();

    {
        let control = Control::open(temp.path()).unwrap();
        for i in 0..20 {
            control
                .store
                .put_chunk(format!("just some bytes {i}").as_bytes(), None)
                .unwrap();
        }
        // CBOR that is structurally a map, and JSON, and an entry — none of
        // which is a pointer or pin event.
        control
            .store
            .put_chunk(br#"{"seq":1,"pin_id":"nope"}"#, None)
            .unwrap();
        control
            .store
            .put_entry(&dag_core::Entry::with_payload(b"payload".to_vec()))
            .unwrap();

        let cid = control.store.put_chunk(b"real target", None).unwrap();
        control.pointer_log.create("real", cid).unwrap();
    }

    let control = reopen_without_database(temp.path());

    let pointers = control.rebuild_pointers_from_store().unwrap();
    assert_eq!(pointers.events_found, 1, "{:?}", pointers);
    assert_eq!(pointers.heads_rebuilt, 1);
    assert_eq!(control.pointer_log.list_pointers().unwrap(), vec!["real"]);

    let pins = control.rebuild_pins_from_store().unwrap();
    assert_eq!(pins.events_found, 0, "{:?}", pins);
    assert_eq!(pins.heads_rebuilt, 0);
    assert!(control.pin_log.list().unwrap().is_empty());
}

/// A chain with a hole in it is not a chain. Recovering its head would claim a
/// history the store cannot support, so the pointer is skipped and named.
#[test]
fn a_chain_with_a_missing_link_is_skipped_and_reported() {
    let temp = TempDir::new().unwrap();

    let seq2_cid = {
        let control = Control::open(temp.path()).unwrap();
        let v1 = control.store.put_chunk(b"one", None).unwrap();
        let v2 = control.store.put_chunk(b"two", None).unwrap();
        let v3 = control.store.put_chunk(b"three", None).unwrap();
        control.pointer_log.create("gappy", v1).unwrap();
        control.pointer_log.update("gappy", v2).unwrap();
        control.pointer_log.update("gappy", v3).unwrap();

        let good = control.store.put_chunk(b"solid", None).unwrap();
        control.pointer_log.create("intact", good).unwrap();

        control
            .pointer_log
            .event_cids()
            .unwrap()
            .into_iter()
            .find(|(id, seq, _)| id == "gappy" && *seq == 2)
            .unwrap()
            .2
    };

    // Lose the middle event's bytes, as a partial restore would.
    {
        use dag_storage::GcCapableStore;
        let control = Control::open(temp.path()).unwrap();
        control.store.delete_chunk(&seq2_cid).unwrap();
    }

    let control = reopen_without_database(temp.path());
    let report = control.rebuild_pointers_from_store().unwrap();

    assert_eq!(report.heads_rebuilt, 1, "{:?}", report);
    assert_eq!(report.events_skipped, 2, "{:?}", report);
    assert!(
        report.skipped.iter().any(|s| s.contains("gappy")),
        "the broken chain was dropped without saying so: {:?}",
        report.skipped
    );
    assert_eq!(control.pointer_log.list_pointers().unwrap(), vec!["intact"]);
    control.rebuild_pins_from_store().unwrap();
    assert!(
        !control.is_recovered().unwrap(),
        "a partial pointer recovery closed the GC gate"
    );
}

/// Recovery must never rewrite history that is already filed. If the events
/// table disagrees with the store about what sits at a sequence number, that
/// is divergence, and the store scan refuses it exactly as `import_event` does.
#[test]
fn recovery_refuses_to_overwrite_a_divergent_mapping() {
    let source = TempDir::new().unwrap();
    let dest = TempDir::new().unwrap();

    // A pointer named "shared" exists in both directories, with different
    // histories. Move the source's event bytes into the destination's store
    // without filing them, then rebuild from the store there.
    let control_src = Control::open(source.path()).unwrap();
    let control_dest = Control::open(dest.path()).unwrap();

    let a = control_src.store.put_chunk(b"source value", None).unwrap();
    control_src.pointer_log.create("shared", a).unwrap();

    let b = control_dest.store.put_chunk(b"dest value", None).unwrap();
    control_dest
        .pointer_log
        .create("shared", b.clone())
        .unwrap();

    for (_, _, cid) in control_src.pointer_log.event_cids().unwrap() {
        let bytes = control_src.store.get_chunk(&cid).unwrap();
        control_dest.store.put_chunk(&bytes, None).unwrap();
    }

    let report = control_dest.rebuild_pointers_from_store().unwrap();
    assert_eq!(report.heads_rebuilt, 0, "{:?}", report);
    assert!(
        report.skipped.iter().any(|s| s.contains("shared")),
        "{:?}",
        report.skipped
    );
    // The destination kept its own history.
    assert_eq!(control_dest.pointer_log.resolve("shared").unwrap(), b);
}
