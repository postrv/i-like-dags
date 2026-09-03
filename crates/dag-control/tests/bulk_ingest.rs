//! `Control::bulk_ingest` — batching an ingest's fsyncs without lending out a
//! store that stays batched.
//!
//! Two things have to hold at once. The ingest must be durable and indexed by
//! the time it returns, or the CID it hands back is a lie. And no failure mode
//! — an error, a panic, a caller who keeps a reference — may leave
//! `Control::store` writing less durably than it promised everyone else.

use dag_control::Control;
use dag_core::{ContentStore, StoredContent};
use dag_storage::{DurabilityPolicy, GcCapableStore};
use std::io::Cursor;
use tempfile::TempDir;

fn control() -> (Control, TempDir) {
    let temp = TempDir::new().unwrap();
    let control = Control::open(temp.path()).unwrap();
    (control, temp)
}

/// Deterministic pseudorandom bytes, so chunk boundaries are reproducible.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The contract: what comes back is stored, durable and indexed.
#[test]
fn a_completed_ingest_is_durable_and_indexed() {
    let (control, _temp) = control();
    let data = noise(9 * 1024 * 1024, 5);

    let stored = control
        .bulk_ingest(|store| {
            dag_core::file::store_auto(
                store,
                Cursor::new(data.clone()),
                None,
                false,
                &dag_core::ChunkerConfig::default(),
            )
        })
        .unwrap();

    let StoredContent::File(report) = stored else {
        panic!("9 MiB must be chunked");
    };
    assert!(report.chunks > 1, "expected several chunks");

    // Reassembles through the *control's own* store, which never saw the
    // deferred view: the two are the same directory and the same index.
    let mut out = Vec::new();
    dag_core::file::join(control.store.as_ref(), &report.cid, &mut out).unwrap();
    assert_eq!(out, data);

    let index = control.store.get_index().unwrap();
    let indexed = index.count().unwrap();
    let on_disk = control.store.list_all_cids().unwrap().len();
    assert_eq!(
        indexed, on_disk,
        "every chunk the ingest wrote should be indexed by the time it returns"
    );
    assert!(indexed as u64 >= report.chunks);
}

/// The point of handing out a separate view rather than flipping a flag: the
/// control plane's own store keeps the durability everything else was
/// promised, during the ingest and after it.
#[test]
fn the_control_planes_store_is_never_downgraded() {
    let (control, _temp) = control();
    assert_eq!(control.store.durability(), DurabilityPolicy::Durable);

    control
        .bulk_ingest(|store| {
            assert_eq!(store.durability(), DurabilityPolicy::Deferred);
            // A write on the main store mid-ingest is still durable per chunk.
            control.store.put_chunk(b"concurrent durable write", None)?;
            assert_eq!(control.store.durability(), DurabilityPolicy::Durable);
            assert_eq!(control.store.pending_sync_count(), 0);
            store.put_chunk(b"ingested write", None)
        })
        .unwrap();

    assert_eq!(control.store.durability(), DurabilityPolicy::Durable);
    assert_eq!(control.store.pending_sync_count(), 0);
}

/// A panic mid-ingest must not downgrade anything afterwards, and must not
/// leave the index naming bytes nobody flushed.
#[test]
fn a_panic_mid_ingest_leaves_the_store_durable_and_the_index_clean() {
    let (control, _temp) = control();

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        control.bulk_ingest(|store| -> Result<(), dag_core::CoreError> {
            store.put_chunk(b"written just before the panic", None)?;
            panic!("ingest blew up");
        })
    }));
    assert!(panicked.is_err(), "the panic should have propagated");

    assert_eq!(control.store.durability(), DurabilityPolicy::Durable);
    assert_eq!(
        control.store.get_index().unwrap().count().unwrap(),
        0,
        "an interrupted ingest may leave files, but never index entries for \
         bytes it never flushed"
    );

    // And the deployment still works.
    let cid = control.store.put_chunk(b"after the panic", None).unwrap();
    assert_eq!(control.store.get_chunk(&cid).unwrap(), b"after the panic");
    assert_eq!(control.store.get_index().unwrap().count().unwrap(), 1);
}

/// An error from the closure is passed through unchanged, and settles nothing.
#[test]
fn a_failing_ingest_indexes_nothing() {
    let (control, _temp) = control();

    let err = control
        .bulk_ingest(|store| {
            store.put_chunk(b"partial work", None)?;
            Err::<(), _>(dag_core::CoreError::PreconditionFailed("giving up".into()))
        })
        .unwrap_err();
    assert!(err.to_string().contains("giving up"));

    assert_eq!(control.store.get_index().unwrap().count().unwrap(), 0);
}

/// The staging view and `Control::store` are two handles on one directory, and
/// collection consults `Control::store`'s in-flight registry. A write through
/// the staging view must be visible there, or a garbage collection running
/// alongside a bulk ingest — armed the moment `dag serve` grows a bulk route —
/// could take a just-written chunk out from under it.
#[test]
fn a_bulk_ingest_write_is_in_flight_on_the_control_store() {
    use std::time::Duration;

    let (control, _temp) = control();

    let cid = control
        .bulk_ingest(|store| store.put_chunk(b"ingested via the staging view", None))
        .unwrap();

    let recent = control.store.recently_written(Duration::from_secs(60));
    assert!(
        recent.contains(&cid),
        "a bulk-ingest write was invisible to the control store's in-flight registry"
    );
    assert!(
        control.store.is_in_flight(&cid, Duration::from_secs(60)),
        "is_in_flight must agree: the chunk the ingest just wrote is in flight"
    );
}
