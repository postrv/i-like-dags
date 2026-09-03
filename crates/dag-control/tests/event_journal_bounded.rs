//! The event journal must not grow without bound, and compacting it must
//! make the file smaller rather than larger.
//!
//! Every number these tests assert on was measured first: at HEAD, compacting
//! a 601-event journal down to 100 grew `control.redb` from 1,204,224 to
//! 9,605,120 bytes — 7.98x. The cause was the single `extract_from_if`
//! transaction: redb is copy-on-write, so one transaction that touches every
//! page in a table has to allocate a second copy of it before it can commit.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use dag_control::events::{reclaim_control_db, DEFAULT_JOURNAL_RETENTION, JOURNAL_RETENTION_ENV};
use dag_control::{Control, Event, EventBus};
use dag_core::{Cid, ContentStore};
use tempfile::tempdir;

fn db_size(dir: &Path) -> u64 {
    std::fs::metadata(dir.join("control.redb"))
        .map(|m| m.len())
        .unwrap_or(0)
}

fn journal(dir: &Path, keep: Option<u64>) -> Result<(Arc<redb::Database>, EventBus)> {
    let db = Arc::new(redb::Database::create(dir.join("control.redb"))?);
    let bus = EventBus::with_journal_retention(1024, db.clone(), keep)?;
    Ok((db, bus))
}

fn emit(bus: &EventBus, n: u64) {
    for i in 0..n {
        bus.emit(Event::PointerUpdate {
            id: format!("ptr-{i}"),
            new: Cid::compute(&i.to_be_bytes()),
            ts: 0,
        });
    }
}

/// The headline defect: compaction has to reclaim, not cost.
///
/// Driven through the journal rather than through `Control` because every
/// journal write is an fsync; the code path under test is the same one
/// `dag events compact` reaches.
#[test]
fn compaction_does_not_grow_the_file() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = journal(temp.path(), None)?;

    // 250 is deliberate: measured against HEAD's single-transaction delete,
    // a journal this small already blew the file up 15.6x, and every journal
    // write is an fsync, so a larger one buys nothing but wall clock.
    emit(&bus, 250);

    let before = db_size(temp.path());
    let report = bus.compact_keep_last(50)?;
    let after = db_size(temp.path());

    assert_eq!(report.events_deleted, 200);
    assert_eq!(report.events_kept, 50);

    // At HEAD this ratio was 7.98. Anything above 1.0 means the operator's
    // only retention lever costs disk instead of saving it.
    assert!(
        after <= before,
        "compaction grew control.redb: {before} -> {after} bytes ({:.2}x)",
        after as f64 / before as f64
    );

    Ok(())
}

/// An unattended `dag serve` writes a StorageHealth row every 15 minutes
/// forever. Without a standing cap the journal is unbounded.
#[test]
fn journal_trims_itself_to_the_retention_cap() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = journal(temp.path(), Some(100))?;

    emit(&bus, 300);

    let held = bus.replay_from(0)?;
    assert!(
        held.len() <= 150,
        "journal held {} events with a cap of 100; it is not self-trimming",
        held.len()
    );
    assert!(
        bus.earliest_seq() > 0,
        "earliest_seq should have advanced past the trimmed prefix"
    );
    assert_eq!(
        held.last().expect("journal is not empty").seq,
        299,
        "trimming must drop the oldest events, never the newest"
    );

    Ok(())
}

/// Self-trimming is worthless if the file grows anyway. redb reuses freed
/// pages, so a bounded journal should reach a plateau.
#[test]
fn a_bounded_journal_reaches_a_plateau() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = journal(temp.path(), Some(50))?;

    emit(&bus, 200);
    let plateau = db_size(temp.path());

    emit(&bus, 400);
    let later = db_size(temp.path());

    assert!(
        later <= plateau * 2,
        "journal grew {plateau} -> {later} bytes across 3x the events; \
         freed pages are not being reused"
    );

    Ok(())
}

/// Unbounded is still available for embedders who want every event.
#[test]
fn retention_can_be_disabled() -> Result<()> {
    let temp = tempdir()?;
    let (_db, bus) = journal(temp.path(), None)?;

    emit(&bus, 100);

    assert_eq!(bus.replay_from(0)?.len(), 100);
    assert_eq!(bus.earliest_seq(), 0);
    Ok(())
}

/// An unconfigured data directory has to come up bounded — that is the whole
/// point, since `dag serve` never schedules a compaction.
#[test]
#[serial_test::serial(journal_retention_env)]
fn a_default_control_plane_is_bounded() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;
    assert_eq!(
        control.event_bus.journal_retention(),
        Some(DEFAULT_JOURNAL_RETENTION)
    );
    Ok(())
}

/// The cap is a floor an operator can raise, not a ceiling imposed on them.
#[test]
#[serial_test::serial(journal_retention_env)]
fn the_environment_can_raise_or_remove_the_cap() -> Result<()> {
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(JOURNAL_RETENTION_ENV);
        }
    }
    let _guard = EnvGuard;

    for (value, expected) in [
        ("5000000", Some(5_000_000)),
        // Explicitly unbounded, for an operator who wants every event.
        ("0", None),
        // A typo in a unit file must not stop the control plane from opening.
        ("banana", Some(DEFAULT_JOURNAL_RETENTION)),
    ] {
        std::env::set_var(JOURNAL_RETENTION_ENV, value);
        let temp = tempdir()?;
        let control = Control::open(temp.path())?;
        assert_eq!(
            control.event_bus.journal_retention(),
            expected,
            "DAG_EVENT_JOURNAL_KEEP={value}"
        );
    }

    Ok(())
}

/// Deleting rows frees pages inside the file; only redb's own `compact()`
/// hands them back to the filesystem, and it needs exclusive access.
#[test]
fn reclaim_shrinks_a_database_that_has_already_bloated() -> Result<()> {
    let temp = tempdir()?;

    {
        let (_db, bus) = journal(temp.path(), None)?;
        // Measured: at 400 events there is not yet enough dead space for a
        // rewrite to win, at 600 it drops 262,144 bytes to 45,056.
        emit(&bus, 600);
        bus.compact_keep_last(25)?;
    }

    let before = db_size(temp.path());
    let report = reclaim_control_db(temp.path())?;

    assert!(report.compacted, "a mostly-dead file should be rewritten");
    assert!(
        report.bytes_after < before,
        "reclaim returned nothing: {before} -> {} bytes",
        report.bytes_after
    );
    check_reclaim_invariants(temp.path(), &report, before, 25)?;

    Ok(())
}

/// The guarantee reclaim actually makes, across shapes of database.
///
/// Deliberately not "this input declines and that one compacts": whether
/// rewriting wins is a marginal, byte-level property of redb's allocator, and
/// an earlier version of this test asserted the decision for a case sitting on
/// the boundary and failed one run in two. What must hold every time is that
/// the file never grows, the data survives, and the report matches the file.
///
/// The failure being guarded is real, and was produced by the CLI: reclaiming
/// in place left a 540,672-byte control database at 770,048 bytes, because redb
/// pre-allocates room as it closes and the fresh allocation exceeded the slack
/// that was there.
#[test]
fn reclaim_never_costs_disk() -> Result<()> {
    // Too small to be worth rewriting, and a real control plane with a store
    // and pointer log behind it. The mostly-dead case is covered above.
    let temp = tempdir()?;
    {
        let (_db, bus) = journal(temp.path(), None)?;
        emit(&bus, 50);
        bus.compact_keep_last(25)?;
    }
    let before = db_size(temp.path());
    let report = reclaim_control_db(temp.path())?;
    check_reclaim_invariants(temp.path(), &report, before, 25)?;

    let temp = tempdir()?;
    {
        let control = Control::open(temp.path())?;
        let cid = control.store.put_chunk(b"seed", None)?;
        control.pointer_log.create("ptr", cid)?;
        for i in 0..60 {
            let c = control.store.put_chunk(format!("v{i}").as_bytes(), None)?;
            control.pointer_log.update("ptr", c)?;
        }
    }
    let before = db_size(temp.path());
    let report = reclaim_control_db(temp.path())?;
    check_reclaim_invariants(temp.path(), &report, before, 61)?;

    Ok(())
}

/// Assert every invariant reclaim must hold, whichever branch it took.
fn check_reclaim_invariants(
    dir: &Path,
    report: &dag_control::ReclaimReport,
    before: u64,
    surviving_events: usize,
) -> Result<()> {
    let after = db_size(dir);

    assert!(
        after <= before,
        "reclaim grew the file: {before} -> {after} bytes for {} live",
        report.live_bytes
    );
    assert_eq!(report.bytes_before, before);
    assert_eq!(report.bytes_after, after, "report disagrees with the file");
    assert_eq!(report.bytes_reclaimed, before - after);
    assert_eq!(
        report.compacted,
        after < before,
        "`compacted` should mean exactly that the copy was kept"
    );

    // The working copy is never left behind, on either branch.
    assert!(!dir.join("control.compacting").exists());

    // And the surviving events are still readable.
    let control = Control::open(dir)?;
    assert_eq!(
        control.event_bus.replay_from(0)?.len(),
        surviving_events,
        "reclaim lost events"
    );

    Ok(())
}

/// Set a Unix mode on a path, for the permission-failure tests below.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
}

/// Restore a mode on drop so a failing assertion still lets `tempdir` clean up.
/// Best-effort: the path may already be gone (reclaim removed it), and a second
/// failure here would only mask the first.
#[cfg(unix)]
struct ModeGuard {
    path: std::path::PathBuf,
    mode: u32,
}

#[cfg(unix)]
impl Drop for ModeGuard {
    fn drop(&mut self) {
        let _ = set_mode(&self.path, self.mode);
    }
}

/// Reclaim writes its working copy beside `control.redb`. When that copy cannot
/// be created — a full or unwritable disk, reproduced here with a directory the
/// process may read and lock but not write into — reclaim must fail cleanly and
/// leave the original exactly as it was: no panic, no half-swap.
#[cfg(unix)]
#[test]
fn reclaim_errors_cleanly_when_the_working_copy_cannot_be_written() -> Result<()> {
    let temp = tempdir()?;
    {
        let (_db, bus) = journal(temp.path(), None)?;
        // Past the 256 KiB floor below which reclaim declines to copy at all;
        // otherwise that early return would mask the copy failure under test.
        emit(&bus, 600);
        bus.compact_keep_last(25)?;
    }
    let before = db_size(temp.path());
    assert!(
        before >= 256 * 1024,
        "test needs a file past the reclaim floor; got {before} bytes"
    );

    // Read-only directory: the existing control.redb stays writable, so redb can
    // open and lock it, but no new file — the scratch copy — can be created.
    let _restore = ModeGuard {
        path: temp.path().to_path_buf(),
        mode: 0o755,
    };
    set_mode(temp.path(), 0o555)?;

    let err = reclaim_control_db(temp.path())
        .expect_err("a working copy that cannot be created must error, not panic");
    assert!(
        err.to_string().contains("copy"),
        "error should name the failed copy, got: {err}"
    );

    // Original untouched and no stranded working copy — checked while the
    // directory is still 0o555, which still permits reading metadata.
    assert_eq!(
        db_size(temp.path()),
        before,
        "reclaim disturbed the original after a copy failure"
    );
    assert!(
        !temp.path().join("control.compacting").exists(),
        "a refused copy must not leave a working copy behind"
    );

    // Restore write and confirm the original still opens and replays.
    set_mode(temp.path(), 0o755)?;
    let control = Control::open(temp.path())?;
    assert_eq!(
        control.event_bus.replay_from(0)?.len(),
        25,
        "reclaim lost events from the original"
    );
    Ok(())
}

/// A path that predates this invocation must never be truncated or deleted.
/// It may be a stale copy for an operator to inspect, or a symlink planted in
/// an overly broad legacy directory. Exclusive creation makes both fail closed.
#[cfg(unix)]
#[test]
fn reclaim_preserves_a_preexisting_working_path_and_fails_closed() -> Result<()> {
    let temp = tempdir()?;
    {
        let (_db, bus) = journal(temp.path(), None)?;
        emit(&bus, 600);
        bus.compact_keep_last(25)?;
    }
    let before = db_size(temp.path());

    // Something this invocation did not create sits where its copy would go.
    let scratch = temp.path().join("control.compacting");
    let marker = b"stale working copy from an earlier crash";
    std::fs::write(&scratch, marker)?;
    let _restore = ModeGuard {
        path: scratch.clone(),
        mode: 0o644,
    };
    set_mode(&scratch, 0o444)?;

    let err = reclaim_control_db(temp.path())
        .expect_err("a copy onto an unwritable destination must error");
    assert!(
        err.to_string().contains("copy"),
        "error should name the failed copy, got: {err}"
    );

    assert_eq!(
        db_size(temp.path()),
        before,
        "reclaim disturbed the original after a copy failure"
    );
    assert_eq!(
        std::fs::read(&scratch)?,
        marker,
        "reclaim modified a working path it did not create"
    );

    let control = Control::open(temp.path())?;
    assert_eq!(
        control.event_bus.replay_from(0)?.len(),
        25,
        "reclaim lost events from the original"
    );
    Ok(())
}

/// Reclaim needs the file to itself. Saying so beats a redb-internal error.
#[test]
fn reclaim_refuses_while_the_control_plane_is_open() -> Result<()> {
    let temp = tempdir()?;
    let control = Control::open(temp.path())?;

    let err = reclaim_control_db(temp.path()).expect_err("should refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("in use") || msg.contains("locked") || msg.contains("open"),
        "unhelpful message for a locked database: {msg}"
    );

    drop(control);
    reclaim_control_db(temp.path())?;
    Ok(())
}
