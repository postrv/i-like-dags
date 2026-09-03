//! Periodic storage integrity scanning.
//!
//! `dag-storage` provides `scan_once` but deliberately does not schedule it:
//! the scanner lives below `dag-control`, so it cannot reach the event bus it
//! would need to report through. Scheduling therefore lives here, where both
//! the store and the bus are in scope, and every completed sweep becomes an
//! [`Event::StorageHealth`] that `dag events tail --filter storage` and the
//! console's event feed can see.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dag_control::{Control, Event};
use tokio::task::JoinHandle;

/// Node ID recorded against scan reports.
const NODE_ID: &str = "local";

/// Start the periodic integrity scan.
///
/// Returns a handle so the caller owns the task's lifetime; dropping it detaches
/// the scan, and aborting it stops cleanly at the next tick. The first sweep is
/// delayed by one interval so that starting the server does not immediately
/// re-hash the whole store.
pub fn spawn_integrity_scan(control: Arc<Control>, interval: Duration) -> JoinHandle<()> {
    assert!(
        !interval.is_zero(),
        "integrity scan interval must be non-zero"
    );
    tokio::spawn(async move {
        loop {
            // Delay from completion, not from the previous scheduled start.
            // Tokio intervals burst missed ticks by default; if a large-store
            // scan took longer than `interval`, that policy restarted it
            // immediately and could keep the disk permanently saturated.
            tokio::time::sleep(interval).await;

            let control = Arc::clone(&control);
            // Re-hashing the store is blocking work and must not run on a
            // runtime worker; see `crate::blocking`.
            let outcome =
                run_cancellable_blocking(move |cancelled| scan(&control, cancelled.as_ref())).await;

            match outcome {
                Ok(Ok(Some(invalid))) => {
                    if invalid > 0 {
                        tracing::warn!(invalid, "integrity scan found corrupt chunks");
                    } else {
                        tracing::debug!("integrity scan clean");
                    }
                }
                Ok(Ok(None)) => tracing::debug!("integrity scan cancelled"),
                Ok(Err(e)) => tracing::error!(error = %e, "integrity scan failed"),
                Err(e) => tracing::error!(error = %e, "integrity scan task panicked"),
            }
        }
    })
}

struct CancelBlockingOnDrop(Arc<AtomicBool>);

impl Drop for CancelBlockingOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Keep cancellation ownership in the async task while its blocking closure
/// runs. Aborting the async task drops the guard and signals the otherwise
/// uncancellable `spawn_blocking` work before Tokio detaches it.
async fn run_cancellable_blocking<T, F>(work: F) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
{
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_on_drop = CancelBlockingOnDrop(Arc::clone(&cancelled));
    let outcome = tokio::task::spawn_blocking(move || work(cancelled)).await;
    drop(cancel_on_drop);
    outcome
}

/// One sweep: re-hash everything, then announce the result.
///
/// Returns the number of corrupt chunks found.
fn scan(control: &Control, cancelled: &AtomicBool) -> anyhow::Result<Option<usize>> {
    let index = control
        .store
        .get_index()
        .ok_or_else(|| anyhow::anyhow!("store opened without an index"))?;

    let scanner = dag_storage::IntegrityScanner::with_index(
        control.store.clone(),
        index,
        Duration::from_secs(60),
    );

    // Emit on failure too, so a store that cannot be read is distinguishable
    // from one that is simply quiet.
    // The scheduler needs only aggregate health. Retaining zero per-CID
    // diagnostics keeps its memory at one fixed index page plus one chunk.
    let result =
        match scanner.scan_once_cancellable(NODE_ID, 0, || cancelled.load(Ordering::Acquire)) {
            Ok(Some(result)) => result,
            Ok(None) => return Ok(None),
            Err(e) => {
                control.event_bus.emit(Event::StorageHealth {
                    check: "integrity".to_string(),
                    ok: false,
                    ts: dag_control::now_unix(),
                });
                return Err(e.into());
            }
        };

    control.event_bus.emit(Event::StorageHealth {
        check: "integrity".to_string(),
        ok: result.invalid_chunks == 0,
        ts: dag_control::now_unix(),
    });

    Ok(Some(result.invalid_chunks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_control::test_utils::TestControl;
    use dag_core::ContentStore;

    /// The scan must announce itself on the bus — the whole point of the
    /// `StorageHealth` variant, which previously existed but was never emitted.
    #[tokio::test]
    async fn a_clean_scan_emits_a_healthy_event() -> anyhow::Result<()> {
        let tc = TestControl::new()?;
        tc.control.store.put_chunk(b"some content", None)?;

        let mut rx = tc.control.event_bus.subscribe();
        let invalid = scan(&tc.control, &AtomicBool::new(false))?;
        assert_eq!(invalid, Some(0));

        let envelope = rx.try_recv().expect("a StorageHealth event");
        match envelope.event {
            Event::StorageHealth { check, ok, .. } => {
                assert_eq!(check, "integrity");
                assert!(ok, "an intact store should report healthy");
            }
            other => panic!("expected StorageHealth, got {:?}", other),
        }
        Ok(())
    }

    /// Corruption must be reported as unhealthy rather than silently logged.
    #[tokio::test]
    async fn corruption_is_reported_as_unhealthy() -> anyhow::Result<()> {
        let tc = TestControl::new()?;
        let cid = tc.control.store.put_chunk(b"trust me", None)?;

        // Rewrite the chunk's bytes behind the store's back so the stored
        // content no longer hashes to its CID.
        let path = tc.control.store.chunk_path(&cid);
        std::fs::write(&path, b"tampered")?;

        let mut rx = tc.control.event_bus.subscribe();
        let invalid = scan(&tc.control, &AtomicBool::new(false))?;
        assert_eq!(invalid, Some(1), "the tampered chunk should be counted");

        let envelope = rx.try_recv().expect("a StorageHealth event");
        match envelope.event {
            Event::StorageHealth { ok, .. } => assert!(!ok, "corruption must report unhealthy"),
            other => panic!("expected StorageHealth, got {:?}", other),
        }
        Ok(())
    }

    /// A data directory restored from backup must report healthy.
    ///
    /// The scanner used to re-hash whatever absolute paths the index recorded,
    /// which for a restore name a directory that no longer exists. This timer
    /// therefore announced `ok: false` every fifteen minutes, for ever, about
    /// a store with nothing wrong with it.
    #[tokio::test]
    async fn a_restored_data_directory_reports_healthy() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let original = temp.path().join("original");
        let restored = temp.path().join("restored");

        {
            let control = dag_control::Control::open(&original)?;
            control.store.put_chunk(b"backed up", None)?;
            control.store.put_chunk(b"and restored", None)?;
            // Dropping the Control closes control.redb, so the directory can be
            // moved — the same state an operator's backup captures.
        }
        std::fs::rename(&original, &restored)?;

        let control = dag_control::Control::open(&restored)?;
        let mut rx = control.event_bus.subscribe();
        assert_eq!(
            scan(&control, &AtomicBool::new(false))?,
            Some(0),
            "nothing about a restore is corrupt"
        );

        match rx.try_recv().expect("a StorageHealth event").event {
            Event::StorageHealth { ok, .. } => assert!(ok, "a restored store is healthy"),
            other => panic!("expected StorageHealth, got {:?}", other),
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_async_owner_cancels_started_blocking_scan_work() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (exited_tx, exited_rx) = tokio::sync::oneshot::channel();
        let owner = tokio::spawn(run_cancellable_blocking(move |cancelled| {
            let _ = entered_tx.send(());
            while !cancelled.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let _ = exited_tx.send(());
        }));

        entered_rx.await.expect("blocking scan started");
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), exited_rx)
            .await
            .expect("detached blocking scan did not observe cancellation")
            .expect("blocking scan exited without signalling");
    }
}
