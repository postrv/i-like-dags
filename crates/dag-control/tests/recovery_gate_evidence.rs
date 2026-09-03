//! The recovery gate closes on evidence, and retention refuses what it
//! cannot enumerate.
//!
//! Both properties were false: a partial table rebuild followed by collection
//! could delete an entire directory whose `control.redb` had been lost, and
//! one unreadable entry inside a pinned subtree dropped everything below it
//! from the protected set.

use dag_control::{Control, ControlError, GcRequest, JobEvent};
use dag_core::{ContentStore, Entry, Link, PinScope, PinTarget};
use dag_storage::GcCapableStore;

fn aged(control: &Control, cid: &dag_core::Cid) {
    let hour_ago = filetime::FileTime::from_system_time(
        std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
    );
    filetime::set_file_mtime(control.store.chunk_path(cid), hour_ago).unwrap();
}

/// A table rebuild that recovers nothing over a *non-empty* store must not
/// close the gate. That is the signature of a lost `control.redb`, and
/// collecting against it means collecting against an empty protected set.
#[test]
fn a_rebuild_that_recovered_nothing_over_a_full_store_does_not_close_the_gate() {
    let dir = tempfile::tempdir().unwrap();

    // A deployment with content, a pointer and a pin.
    let precious = {
        let control = Control::open(dir.path()).unwrap();
        let pinned = control
            .store
            .put_chunk(b"the pinned artifact", None)
            .unwrap();
        let named = control
            .store
            .put_chunk(b"the named artifact", None)
            .unwrap();
        control.pointer_log.create("release", named).unwrap();
        control
            .pin_log
            .create(
                "hold",
                PinTarget::Direct(pinned.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        pinned
    };

    // Lose control.redb; data/ survives, as it does on a restore that
    // forgot the database or a disk that lost one file.
    std::fs::remove_file(dir.path().join("control.redb")).unwrap();

    let control = Control::open(dir.path()).unwrap();
    let pointers = control.rebuild_pointers().unwrap();
    let pins = control.rebuild_pins(false).unwrap();
    assert_eq!(pointers, 0, "setup: the table really is empty");
    assert_eq!(pins.heads_rebuilt, 0);

    assert!(
        !control.is_recovered().unwrap(),
        "a rebuild that recovered nothing over a full store closed the gate"
    );

    // And collection is therefore refused rather than running with an empty
    // protected set.
    let err = control.run_gc(&GcRequest::default()).unwrap_err();
    assert!(
        matches!(err, ControlError::NotRecovered),
        "expected the gate to hold, got {err}"
    );
    assert!(control.store.has_chunk(&precious).unwrap());
}

#[test]
fn ordinary_content_cannot_silently_become_recovered_control_authority() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();

    let target = control
        .store
        .put_chunk(b"attacker-selected head", None)
        .unwrap();
    let event = dag_core::PointerEvent::create_event("planted", target, 1);
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&event, &mut payload).unwrap();
    control
        .store
        .put_entry(&Entry::with_payload(payload))
        .unwrap();

    let refusal = control.recover().unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("--trust-unfiled-control-events"),
        "unsigned ordinary content was not surfaced as an explicit trust decision: {refusal}"
    );
    assert!(
        control.pointer_log.resolve("planted").is_err(),
        "default recovery promoted a content writer into pointer authority"
    );
    assert!(
        !control.is_recovered().unwrap(),
        "the durable GC gate must remain closed after the refusal"
    );
}

/// Lost-database recovery refuses to promote unsigned stored bytes by default;
/// the explicit offline trust decision reads the events out of `data/`, closes
/// the gate, and rebuilds every derived index collection consults.
#[test]
fn recover_reads_the_store_closes_the_gate_and_rebuilds_the_indexes() {
    let dir = tempfile::tempdir().unwrap();

    let (pinned, named, sig) = {
        let control = Control::open(dir.path()).unwrap();
        let pinned = control.store.put_chunk(b"pinned", None).unwrap();
        let named = control.store.put_chunk(b"named", None).unwrap();
        control
            .pointer_log
            .create("release", named.clone())
            .unwrap();
        control
            .pin_log
            .create(
                "hold",
                PinTarget::Direct(pinned.clone()),
                PinScope::Global,
                None,
                None,
            )
            .unwrap();
        // A signature over pinned content: collection protects it only via
        // the signature index, which no recovery path used to rebuild.
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let sig = control
            .signature_log
            .sign(&pinned, None, serde_json::json!({}), &key)
            .unwrap();
        (pinned, named, sig)
    };

    std::fs::remove_file(dir.path().join("control.redb")).unwrap();
    let control = Control::open(dir.path()).unwrap();

    let refusal = control.recover().unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("--trust-unfiled-control-events"),
        "lost-database recovery silently trusted ordinary content: {refusal}"
    );
    assert!(!control.is_recovered().unwrap());

    let report = control
        .recover_with_limits_trusting_store_control_events(
            dag_control::DEFAULT_RECOVERY_MAX_OBJECTS,
            dag_control::DEFAULT_RECOVERY_MAX_BYTES,
        )
        .unwrap();
    assert!(report.recovered, "recover did not close the gate");
    assert!(report.pointer_events_adopted > 0, "{report:?}");
    assert!(report.pin_events_adopted > 0, "{report:?}");
    assert_eq!(
        report.signatures_indexed, 1,
        "the signature index was not rebuilt: {report:?}"
    );

    // Now collection runs, and keeps everything it should — including the
    // signature, which is only reachable through the index recover restored.
    for cid in [&pinned, &named, &sig] {
        aged(&control, cid);
    }
    control.run_gc(&GcRequest::default()).unwrap();
    assert!(
        control.store.has_chunk(&pinned).unwrap(),
        "pinned collected"
    );
    assert!(control.store.has_chunk(&named).unwrap(), "named collected");
    assert!(
        control.store.has_chunk(&sig).unwrap(),
        "the signature over pinned content was collected"
    );
}

/// An entry inside a pinned subtree that cannot be read means the children
/// are *unknown*, not absent. Collection must refuse, exactly as it does at
/// the expansion ceiling — not silently protect the readable prefix.
#[test]
fn an_unreadable_entry_in_a_pinned_subtree_refuses_collection() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();

    let leaf = control
        .store
        .put_chunk(b"the leaf that matters", None)
        .unwrap();
    let mid = control
        .store
        .put_entry(&Entry {
            payload: Vec::new(),
            links: vec![Link {
                name: None,
                target: leaf.clone(),
            }],
            meta: None,
        })
        .unwrap();
    let root = control
        .store
        .put_entry(&Entry {
            payload: Vec::new(),
            links: vec![Link {
                name: None,
                target: mid.clone(),
            }],
            meta: None,
        })
        .unwrap();

    control
        .pin_log
        .create(
            "hold",
            PinTarget::Subtree {
                root: root.clone(),
                max_depth: None,
            },
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    // Age before removing permissions: an unreadable file cannot have its
    // mtime set either.
    for cid in [&leaf, &mid, &root] {
        aged(&control, cid);
    }

    // Make the interior entry unreadable — permissions, EIO, a bad sector.
    // The integrity scanner has a whole category for this, so it is not
    // hypothetical.
    let mid_path = control.store.chunk_path(&mid);
    let mut perms = std::fs::metadata(&mid_path).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o000);
    }
    std::fs::set_permissions(&mid_path, perms).unwrap();

    let err = control.run_gc(&GcRequest::default()).unwrap_err();
    match &err {
        ControlError::RetentionUnreadable { pin_id, cid } => {
            assert_eq!(pin_id, "GC pointer/pin/active-work roots (shared closure)");
            assert_eq!(cid, &mid.to_hex());
        }
        other => panic!("expected a refusal naming the unreadable entry, got {other}"),
    }
    // The remedy is in the message, and nothing was deleted.
    assert!(err.to_string().contains("cannot read"), "{err}");
    assert!(control.store.has_chunk(&leaf).unwrap(), "leaf collected");

    // Restore readability and collection proceeds, keeping the whole subtree.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&mid_path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&mid_path, perms).unwrap();
    }
    control.run_gc(&GcRequest::default()).unwrap();
    for cid in [&leaf, &mid, &root] {
        assert!(control.store.has_chunk(cid).unwrap(), "{cid} collected");
    }
}

/// Recovery is a durable protocol, not a sequence of optimistic flags. A
/// failure in its final safety-relevant phase must close collection across a
/// process restart even if earlier phases already replaced their tables.
#[test]
fn a_late_recovery_failure_holds_the_gate_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let control = Control::open(dir.path()).unwrap();
        control.recovery_state.mark_complete_for_test().unwrap();

        let event = JobEvent::Triggered {
            reason: "historical event without a job identity".into(),
            ts: 1,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();

        let error = control.recover().unwrap_err();
        assert!(
            matches!(error, ControlError::RecoveryIncomplete { .. }),
            "expected the late job phase to refuse, got {error}"
        );
        assert!(!control.is_recovered().unwrap());
    }

    let reopened = Control::open(dir.path()).unwrap();
    assert!(
        !reopened.is_recovered().unwrap(),
        "the durable in-progress marker was lost across reopen"
    );
    assert!(matches!(
        reopened.run_gc(&GcRequest::default()).unwrap_err(),
        ControlError::NotRecovered
    ));
}

/// A corrupt object cannot be classified as irrelevant to recovery. The
/// inventory read fails after the durable marker is set, so the old recovery
/// verdict must not survive either the error or a reopen.
#[test]
fn an_unreadable_recovery_object_invalidates_the_old_verdict_durably() {
    let dir = tempfile::tempdir().unwrap();
    {
        let control = Control::open(dir.path()).unwrap();
        control.recovery_state.mark_complete_for_test().unwrap();
        let cid = control.store.put_chunk(b"recover me", None).unwrap();
        std::fs::write(control.store.chunk_path(&cid), b"corrupt bytes").unwrap();

        let error = control.recover().unwrap_err();
        assert!(
            error.to_string().contains("mismatch"),
            "unexpected corruption error: {error}"
        );
        assert!(!control.is_recovered().unwrap());
    }

    let reopened = Control::open(dir.path()).unwrap();
    assert!(!reopened.is_recovered().unwrap());
    assert!(matches!(
        reopened.run_gc(&GcRequest::default()).unwrap_err(),
        ControlError::NotRecovered
    ));
}

#[test]
fn recovery_inventory_ceiling_refuses_before_changing_an_existing_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();
    control.store.put_chunk(b"one", None).unwrap();
    control.store.put_chunk(b"two", None).unwrap();

    assert!(matches!(
        control.recover_with_limit(1).unwrap_err(),
        ControlError::RecoveryInventoryLimit { limit: 1 }
    ));
    assert!(
        control.is_recovered().unwrap(),
        "a preflight refusal must not begin or invalidate recovery"
    );
}

#[test]
fn recovery_byte_ceiling_refuses_before_changing_an_existing_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();
    control.store.put_chunk(b"sixsix", None).unwrap();

    assert!(matches!(
        control.recover_with_limits(10, 3).unwrap_err(),
        ControlError::RecoveryBytesLimit {
            limit: 3,
            required: 6..
        }
    ));
    assert!(
        control.is_recovered().unwrap(),
        "a byte preflight refusal must not begin or invalidate recovery"
    );
}

#[test]
fn recovery_control_row_ceiling_refuses_before_changing_an_existing_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();
    let target = control.store.put_chunk(b"target", None).unwrap();
    control.pointer_log.create("release", target).unwrap();

    assert!(matches!(
        control.recover_with_limit(1).unwrap_err(),
        ControlError::RecoveryTableLimit {
            limit: 1,
            rows: 2..
        }
    ));
    assert!(control.is_recovered().unwrap());
}

/// Content-addressed deduplication can make a later control mutation
/// database-only: both its target and exact event bytes may already exist at
/// snapshot time. Restoring that older database leaves filesystem/index CID
/// sets equal, so GC must also reconcile plausible immutable control records.
#[test]
fn a_deduplicated_future_event_in_an_old_snapshot_is_conservatively_retained() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("control-before-filing.redb");
    let (new_target, future_event_cid) = {
        let control = Control::open(dir.path()).unwrap();
        let old_target = control.store.put_chunk(b"release-v1", None).unwrap();
        control
            .pointer_log
            .create("release", old_target.clone())
            .unwrap();
        control.recover().unwrap();

        let new_target = control.store.put_chunk(b"release-v2", None).unwrap();
        let event =
            dag_core::PointerEvent::update_event("release", 2, old_target, new_target.clone(), 2);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let event_cid = control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();
        drop(control);
        std::fs::copy(dir.path().join("control.redb"), &snapshot).unwrap();
        (new_target, event_cid)
    };

    {
        let control = Control::open(dir.path()).unwrap();
        assert!(control
            .pointer_log
            .import_event("release", 2, &future_event_cid)
            .unwrap());
        control.rebuild_pointers().unwrap();
        assert_eq!(control.pointer_log.resolve("release").unwrap(), new_target);
    }

    std::fs::copy(&snapshot, dir.path().join("control.redb")).unwrap();
    let restored = Control::open(dir.path()).unwrap();
    assert!(
        restored.is_recovered().unwrap(),
        "the exact regression starts with the stale snapshot's old true flag"
    );
    let report = restored
        .run_gc(&GcRequest {
            dry_run: true,
            min_age_secs: 0,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(
        report.collected.iter().all(|item| item.cid != new_target),
        "the unfiled event's new target was offered for deletion: {report:?}"
    );
    assert!(restored.is_recovered().unwrap());
    assert!(restored.store.has_chunk(&new_target).unwrap());

    let without_log_protection = restored
        .run_gc(&GcRequest {
            dry_run: false,
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(
        without_log_protection
            .collected
            .iter()
            .all(|item| item.cid != new_target),
        "disabling log retention must not disable root correctness: {without_log_protection:?}"
    );
    assert!(restored.store.has_chunk(&future_event_cid).unwrap());
    assert!(restored.store.has_chunk(&new_target).unwrap());

    // The event is the only witness to this additional root. It must survive
    // the first destructive pass or a second pass would forget the target.
    restored
        .run_gc(&GcRequest {
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(restored.store.has_chunk(&future_event_cid).unwrap());
    assert!(restored.store.has_chunk(&new_target).unwrap());

    let refusal = restored.recover().unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("--trust-unfiled-control-events"),
        "stale-snapshot recovery silently trusted an unfiled event: {refusal}"
    );
    restored
        .recover_with_limits_trusting_store_control_events(
            dag_control::DEFAULT_RECOVERY_MAX_OBJECTS,
            dag_control::DEFAULT_RECOVERY_MAX_BYTES,
        )
        .unwrap();
    assert_eq!(restored.pointer_log.resolve("release").unwrap(), new_target);
    assert!(restored.is_recovered().unwrap());
}

/// The authoritative and conservative walks share one global budget, but
/// overlap proved by either an authoritative root or an earlier complete
/// candidate must not be charged a second time. Otherwise a later complete
/// candidate can lose only its unique descendants when the residual budget is
/// exact.
#[test]
fn complete_future_roots_reuse_all_proved_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();

    // Seven objects of authoritative closure leave three units of a ten-unit
    // global budget.
    let mut filed_root = control.store.put_chunk(b"filed-leaf", None).unwrap();
    for _ in 0..6 {
        filed_root = control
            .store
            .put_entry(&Entry::new(
                Vec::new(),
                vec![Link::unnamed(filed_root)],
                None,
            ))
            .unwrap();
    }
    control
        .pointer_log
        .create("release", filed_root.clone())
        .unwrap();

    // Candidate A adds only its wrapper because the filed root's unlimited
    // coverage is already proved.
    let candidate_a = control
        .store
        .put_entry(&Entry::new(
            Vec::new(),
            vec![Link::unnamed(filed_root)],
            None,
        ))
        .unwrap();
    let private_leaf = control
        .store
        .put_chunk(b"candidate-b-private-leaf", None)
        .unwrap();

    // Candidate validation is stable by target CID. Choose B's harmless
    // payload before storing it so A is guaranteed to run first without
    // leaving nonce attempts in the inventory.
    let candidate_b_entry = (0u64..)
        .map(|nonce| {
            Entry::new(
                nonce.to_le_bytes().to_vec(),
                vec![
                    Link::unnamed(candidate_a.clone()),
                    Link::unnamed(private_leaf.clone()),
                ],
                None,
            )
        })
        .find(|entry| {
            candidate_a.as_bytes()
                < dag_core::Cid::compute(&entry.to_bytes_cbor().unwrap()).as_bytes()
        })
        .unwrap();
    let candidate_b = control.store.put_entry(&candidate_b_entry).unwrap();
    assert!(candidate_a.as_bytes() < candidate_b.as_bytes());

    let candidate_events: Vec<_> = [
        dag_core::PointerEvent::create_event("future-a", candidate_a.clone(), 1),
        dag_core::PointerEvent::create_event("future-b", candidate_b.clone(), 1),
    ]
    .into_iter()
    .map(|event| {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap()
    })
    .collect();
    let garbage = control
        .store
        .put_chunk(b"unrelated collectable garbage", None)
        .unwrap();

    // Correct accounting is exactly 7 + 1 + 2. Without authoritative seeds,
    // A reaches the residual ceiling; without carrying A's complete proof, B
    // reaches it while scheduling the private leaf and loses that leaf.
    control.set_max_subtree_expansion(10);
    for cid in control.store.list_all_cids().unwrap() {
        aged(&control, &cid);
    }

    let report = control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .expect("overlap must consume only newly scheduled global work");
    assert!(
        report.collected.iter().any(|item| item.cid == garbage),
        "proved candidates retained unrelated inventory: {report:?}"
    );
    assert!(!control.store.has_chunk(&garbage).unwrap());
    for cid in [&candidate_a, &candidate_b, &private_leaf]
        .into_iter()
        .chain(candidate_events.iter())
    {
        assert!(
            control.store.has_chunk(cid).unwrap(),
            "complete candidate closure/witness {cid} was collected"
        );
    }

    // The candidate events are the only durable witnesses for both roots;
    // their proof and unique descendant must survive another no-system pass.
    control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(control.store.has_chunk(&private_leaf).unwrap());
}

/// Event-shaped user content is not authority by itself. A foreign mid-chain
/// event cannot nominate an absent CID and permanently brick collection.
#[test]
fn a_foreign_mid_chain_pointer_event_cannot_brick_collection() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();

    let event = dag_core::PointerEvent::update_event(
        "foreign",
        2,
        dag_core::Cid::compute(b"not a filed predecessor"),
        dag_core::Cid::compute(b"never stored"),
        1,
    );
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&event, &mut payload).unwrap();
    let event_cid = control
        .store
        .put_entry(&Entry::with_payload(payload))
        .unwrap();
    aged(&control, &event_cid);

    control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            ..GcRequest::default()
        })
        .expect("a chain gap must not become a missing retention root");
    assert!(control.is_recovered().unwrap());

    // With broad log heuristics explicitly disabled, unused foreign content
    // is collectable, and the following pass remains healthy.
    control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(!control.store.has_chunk(&event_cid).unwrap());
    control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .unwrap();
    assert!(control.is_recovered().unwrap());
}

/// A contiguous seq-1 candidate is still only a candidate. If its target DAG
/// has a missing descendant, it could not pass ordinary pointer publication
/// and must not become a strict GC root merely because its payload decodes.
#[test]
fn an_unfiled_pointer_with_an_incomplete_target_cannot_brick_collection() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();

    let missing = dag_core::Cid::compute(b"missing descendant");
    let incomplete_root = control
        .store
        .put_entry(&Entry::new(
            Vec::new(),
            vec![Link {
                name: None,
                target: missing,
            }],
            None,
        ))
        .unwrap();
    let event = dag_core::PointerEvent::create_event("foreign", incomplete_root.clone(), 1);
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&event, &mut payload).unwrap();
    let event_cid = control
        .store
        .put_entry(&Entry::with_payload(payload))
        .unwrap();
    aged(&control, &incomplete_root);
    aged(&control, &event_cid);

    control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            ..GcRequest::default()
        })
        .expect("an unpublished incomplete candidate must be ignored as a root");
    assert!(control.is_recovered().unwrap());
}

/// Ambiguous, unfiled records are not retention authority. Several wide
/// candidates can consume the conservative validation budget using links to
/// absent CIDs, but exhausting that budget must not turn the pass into a
/// whole-inventory no-op that keeps unrelated garbage forever.
#[test]
fn unfiled_candidate_budget_exhaustion_cannot_retain_unrelated_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let control = Control::open(dir.path()).unwrap();
    control.recovery_state.mark_complete_for_test().unwrap();
    let garbage = control
        .store
        .put_chunk(b"unrelated collectable garbage", None)
        .unwrap();

    let mut evidence_objects = Vec::new();
    for candidate in 0..3 {
        // Three roots schedule just over the ordinary 100,000-object work
        // budget. The first two end at a missing descendant; the third reaches
        // the remaining ceiling. Each Entry stays comfortably below 4 MiB.
        let links = (0..34_000)
            .map(|link| {
                Link::unnamed(dag_core::Cid::compute(
                    format!("missing-{candidate}-{link}").as_bytes(),
                ))
            })
            .collect();
        let root = control
            .store
            .put_entry(&Entry::new(Vec::new(), links, None))
            .unwrap();
        let event = dag_core::PointerEvent::create_event(
            format!("wide-candidate-{candidate}"),
            root.clone(),
            1,
        );
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&event, &mut payload).unwrap();
        let event_cid = control
            .store
            .put_entry(&Entry::with_payload(payload))
            .unwrap();
        evidence_objects.extend([root, event_cid]);
    }

    let default_report = control
        .run_gc(&GcRequest {
            dry_run: true,
            min_age_secs: 0,
            ..GcRequest::default()
        })
        .expect("candidate work exhaustion must remain a bounded GC pass");
    assert!(
        default_report
            .collected
            .iter()
            .any(|item| item.cid == garbage),
        "ambiguous candidates retained unrelated inventory: {default_report:?}"
    );

    let no_system_report = control
        .run_gc(&GcRequest {
            min_age_secs: 0,
            system_protection: false,
            ..GcRequest::default()
        })
        .expect("no-system GC must make the same root-correctness decision");
    assert!(
        no_system_report
            .collected
            .iter()
            .any(|item| item.cid == garbage),
        "no-system GC retained unrelated inventory: {no_system_report:?}"
    );
    assert!(!control.store.has_chunk(&garbage).unwrap());
    for cid in evidence_objects {
        assert!(
            control.store.has_chunk(&cid).unwrap(),
            "candidate root/event witness {cid} was collected"
        );
    }
}
