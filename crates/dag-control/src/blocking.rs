//! Running synchronous control-plane I/O from an async context.
//!
//! redb and the filesystem store are synchronous. Calling them straight from
//! an `async fn` holds a tokio worker thread for the whole duration of the
//! I/O, and since the SSE keep-alives share those workers, one slow scan
//! freezes the event stream for every connected console.
//!
//! The obvious tool, `spawn_blocking`, needs a `'static` closure — which the
//! job runner cannot give, because it borrows a `&Control` across the call.
//! Wrapping at the HTTP layer instead would mean `Handle::block_on` inside
//! `spawn_blocking`, which deadlocks under a current-thread runtime.
//!
//! [`offload`] uses `block_in_place`, which has no `'static` bound: it tells
//! the runtime this worker is about to block so the tasks queued behind it move
//! elsewhere. That is only meaningful on a multi-threaded runtime, so on a
//! current-thread one — which is what `#[tokio::test]` builds by default, and
//! where `block_in_place` panics — the closure simply runs inline. There is
//! nothing to yield to there anyway.

use tokio::runtime::{Handle, RuntimeFlavor};

/// Run blocking work without stalling the tasks queued behind it.
///
/// Use this around synchronous store or database access inside an `async fn`.
/// It is a no-op wrapper outside a runtime and on a current-thread runtime, so
/// it is always safe to call.
///
/// ```
/// use dag_control::blocking::offload;
///
/// # async fn example() -> usize {
/// // Stands in for a synchronous store read.
/// offload(|| (0..1000).sum::<usize>())
/// # }
/// ```
pub fn offload<T>(f: impl FnOnce() -> T) -> T {
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        // Current-thread runtime, or no runtime at all: run it here.
        // `block_in_place` panics on the former and is unavailable on the
        // latter, and in both cases there are no sibling workers to protect.
        _ => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_inline_on_a_current_thread_runtime_rather_than_panicking() {
        // `block_in_place` would panic here. The whole point of the flavour
        // check is that callers need not care which runtime they are on.
        assert_eq!(offload(|| 40 + 2), 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runs_on_a_multi_thread_runtime() {
        assert_eq!(offload(|| 40 + 2), 42);
    }

    #[test]
    fn runs_outside_a_runtime() {
        assert_eq!(offload(|| 40 + 2), 42);
    }

    /// The property that matters: other tasks still make progress while a
    /// worker is inside `offload`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn other_tasks_progress_while_a_worker_blocks() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let ticked = Arc::new(AtomicBool::new(false));
        let flag = ticked.clone();

        let ticker = tokio::spawn(async move {
            flag.store(true, Ordering::SeqCst);
        });

        offload(|| std::thread::sleep(std::time::Duration::from_millis(50)));

        ticker.await.unwrap();
        assert!(ticked.load(Ordering::SeqCst));
    }
}
