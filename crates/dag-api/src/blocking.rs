//! Moving synchronous control-plane work off the async runtime.
//!
//! Every handler that only calls synchronous `Control` methods goes through
//! [`on_blocking_pool`], which hands the work to the blocking pool.
//!
//! `POST /api/jobs/run` and `POST /api/usecase/seed` cannot use it: both call
//! `async` functions that `await` an adapter with blocking store I/O either
//! side of that await, so wrapping them here would mean `Handle::block_on`
//! inside `spawn_blocking` — a deadlock under a current-thread runtime.
//!
//! They are not exceptions any more. `dag_control::blocking::offload` now
//! covers their synchronous stretches from the inside, where the borrow is
//! still in scope: `dag_jobs::execute_once` offloads the job-log and manifest
//! work around its adapter call, and [`crate::scenario::seed`] offloads each
//! run of store writes between its two job runs. That is the split this module
//! always described as the correct fix — the layer that owns the blocking call
//! offloads it, rather than this one smuggling a runtime across a thread
//! boundary.

use std::sync::Arc;

use dag_control::Control;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Run a synchronous control-plane operation on the blocking pool.
///
/// redb and the filesystem store expose blocking APIs. Calling them straight
/// from a handler holds a tokio worker thread for the whole duration of the
/// I/O, so enough concurrent requests starve the runtime. That is worse than it
/// sounds here: the SSE keep-alives share those same workers, so one slow disk
/// scan stalls the event stream for every connected console at once, and the
/// consoles look frozen rather than slow.
///
/// [`Control`] is `Send + Sync` and every method takes `&self`, so handing the
/// work to another thread costs a refcount bump and no locking.
///
/// ```no_run
/// # use dag_api::{blocking::on_blocking_pool, AppState};
/// # use dag_api::error::ApiResult;
/// # async fn example(state: AppState) -> ApiResult<usize> {
/// on_blocking_pool(&state, |control| Ok(control.stats()?.chunks)).await
/// # }
/// ```
pub async fn on_blocking_pool<T, F>(state: &AppState, f: F) -> ApiResult<T>
where
    F: FnOnce(&Control) -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    let control: Arc<Control> = state.control.clone();
    // Do not queue an attacker-sized number of blocking tasks inside Tokio.
    // The permit moves into the closure and covers the entire synchronous
    // operation, including a streaming upload that waits for request bytes.
    let permit = state.try_blocking_permit()?;

    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f(&control)
    })
    .await
    {
        Ok(result) => result,
        // Without this arm a panicking closure would surface as a dropped
        // connection with no explanation on either side.
        Err(join) => Err(ApiError::from(anyhow::anyhow!(
            "control-plane task failed: {}",
            join
        ))),
    }
}

/// Run content-response setup on the blocking pool while transferring its
/// aggregate response permit safely across cancellation.
///
/// Tokio cannot cancel a `spawn_blocking` closure once it starts. Acquiring
/// the response permit only in the handler would therefore reopen admission
/// if the client disconnected while detached work still held a chunk buffer
/// or read a manifest. This helper moves the permit into that closure first,
/// then returns it with the result for the eventual response body to own.
pub(crate) async fn on_content_response_pool<T, F>(
    state: &AppState,
    operation: F,
) -> ApiResult<(T, tokio::sync::OwnedSemaphorePermit)>
where
    F: FnOnce(&Control) -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    let response_permit = state.try_content_response_permit()?;
    on_blocking_pool(state, move |control| {
        let result = operation(control)?;
        Ok((result, response_permit))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_control::test_utils::TestControl;
    use dag_core::ContentStore;
    use http_body_util::BodyExt;

    fn state() -> (TestControl, AppState) {
        let tc = TestControl::new().expect("test control");
        let control =
            Arc::new(Control::open(&tc.path().join("api")).expect("second control plane"));
        (tc, AppState::new(control))
    }

    #[tokio::test]
    async fn runs_the_closure_and_returns_its_value() {
        let (_tc, state) = state();
        let chunks = on_blocking_pool(&state, |c| Ok(c.stats()?.chunks))
            .await
            .expect("stats");
        assert_eq!(chunks, 0);
    }

    #[tokio::test]
    async fn propagates_errors_rather_than_panicking() {
        let (_tc, state) = state();
        let result = on_blocking_pool(&state, |c| {
            c.pointer_log.get_head("nope")?;
            Ok(())
        })
        .await;
        assert!(
            result.is_err(),
            "a missing pointer should surface as an error"
        );
    }

    /// A panic on the blocking pool must become a response, not a hung request.
    #[tokio::test]
    async fn a_panicking_task_becomes_an_error() {
        let (_tc, state) = state();
        let result: ApiResult<()> =
            on_blocking_pool(&state, |_| panic!("boom, deliberately")).await;
        assert!(result.is_err(), "panic should be reported, not swallowed");
    }

    #[tokio::test]
    async fn saturated_blocking_work_is_rejected_without_queueing() {
        let (_tc, mut state) = state();
        state.blocking_admission = Arc::new(tokio::sync::Semaphore::new(1));
        let held = state.try_blocking_permit().expect("first permit");

        let error = on_blocking_pool(&state, |_| Ok(())).await.unwrap_err();
        assert_eq!(error.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

        drop(held);
        on_blocking_pool(&state, |_| Ok(()))
            .await
            .expect("capacity should recover when a permit is released");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_content_handler_keeps_admission_until_detached_work_exits() {
        let (_tc, mut state) = state();
        state.content_response_admission = Arc::new(tokio::sync::Semaphore::new(1));
        let cid = state
            .control
            .store
            .put_chunk(b"route recovery", None)
            .expect("store raw chunk");

        let state_for_task = state.clone();
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release_in_task = release.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            on_content_response_pool(&state_for_task, move |_| {
                let _ = entered_tx.send(());
                let (lock, wake) = &*release_in_task;
                let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(|error| error.into_inner());
                }
                Ok(())
            })
            .await
        });

        entered_rx.await.expect("blocking content setup entered");
        task.abort();
        let _ = task.await;

        let premature = state.try_content_response_permit();
        let premature_status = premature.as_ref().err().map(ApiError::status);
        drop(premature);

        let (lock, wake) = &*release;
        *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
        wake.notify_all();

        let recovered = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(permit) = state.try_content_response_permit() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached content setup should eventually release admission");
        drop(recovered);

        assert_eq!(
            premature_status,
            Some(axum::http::StatusCode::SERVICE_UNAVAILABLE)
        );

        let query = || axum::extract::Query(crate::routes::CidQuery { cid: cid.to_hex() });
        let chunk_response =
            crate::routes::content::get_chunk(axum::extract::State(state.clone()), query())
                .await
                .expect("raw chunk route recovers");
        let chunk = chunk_response
            .into_body()
            .collect()
            .await
            .expect("raw chunk body")
            .to_bytes();
        assert_eq!(chunk.as_ref(), b"route recovery");

        let file_response =
            crate::routes::files::download(axum::extract::State(state.clone()), query())
                .await
                .expect("raw file route recovers");
        let file = file_response
            .into_body()
            .collect()
            .await
            .expect("raw file body")
            .to_bytes();
        assert_eq!(file.as_ref(), b"route recovery");
        assert_eq!(state.content_response_admission.available_permits(), 1);
    }
}
