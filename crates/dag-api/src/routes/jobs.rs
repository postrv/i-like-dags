//! Job endpoints: specs, runs, execution and adapters.

use axum::extract::{Query, State};
use axum::Json;
use dag_core::{JobId, RunStatus};
use serde::{Deserialize, Serialize};

use crate::blocking::on_blocking_pool;
use crate::error::{ApiError, ApiResult};
use crate::routes::{checked_page_limit, lookahead_limit, Page, PageBudget, DEFAULT_PAGE_LIMIT};
use crate::AppState;

const MAX_RUN_HISTORY_LIMIT: usize = dag_control::MAX_RUN_HISTORY_PAGE;

fn checked_run_limit(requested: usize) -> ApiResult<usize> {
    if !(1..=MAX_RUN_HISTORY_LIMIT).contains(&requested) {
        return Err(ApiError::bad_request(format!(
            "run limit must be between 1 and {MAX_RUN_HISTORY_LIMIT}, got {requested}"
        )));
    }
    Ok(requested)
}

/// Cursor pagination for registered jobs.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Return job IDs lexicographically after this opaque cursor.
    pub cursor: Option<String>,
    /// Number of job heads to inspect.
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

fn default_page_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

/// A registered job.
#[derive(Debug, Serialize)]
pub struct JobView {
    /// Job ID.
    pub id: String,
    /// Adapter this job dispatches to.
    pub code_ref: String,
    /// `Deterministic` or `SideEffecting`.
    pub determinism: String,
    /// Pointers resolved at trigger time.
    pub pointer_inputs: Vec<String>,
    /// Fixed CID inputs.
    pub static_inputs: Vec<String>,
    /// Output names the spec declares.
    pub declared_outputs: Vec<String>,
    /// How outputs are retained.
    pub cache_policy: String,
    /// What causes a run.
    pub trigger: String,
    /// Number of runs triggered so far.
    pub trigger_count: u64,
}

/// One execution of a job.
#[derive(Debug, Serialize)]
pub struct RunView {
    /// Run ID, unique within the job.
    pub run_id: String,
    /// Job this run belongs to.
    pub job_id: String,
    /// `Pending`, `Running`, `Succeeded` or `Failed`.
    pub status: String,
    /// Failure message, when the run failed.
    pub error: Option<String>,
    /// Outputs, keyed by declared name.
    pub outputs: Vec<OutputView>,
    /// Pointer heads this run resolved.
    pub pointer_inputs: Vec<ResolvedInputView>,
    /// Static CID inputs.
    pub static_inputs: Vec<String>,
    /// When the run started.
    pub started_at: i64,
    /// When it finished, if it has.
    pub finished_at: Option<i64>,
    /// Node that executed it.
    pub node_id: Option<String>,
    /// Filed immutable job event used by this run.
    pub revision: Option<RevisionView>,
}

#[derive(Debug, Serialize)]
pub struct RevisionView {
    pub event_cid: String,
    pub event_seq: u64,
    pub code_ref: String,
}

/// A named output CID.
#[derive(Debug, Serialize)]
pub struct OutputView {
    /// Declared output name.
    pub name: String,
    /// CID produced.
    pub cid: String,
}

/// A pointer as it was resolved for a run.
#[derive(Debug, Serialize)]
pub struct ResolvedInputView {
    /// Pointer ID.
    pub pointer_id: String,
    /// CID it resolved to.
    pub cid: String,
    /// Pointer log sequence at resolution time.
    pub seq: u64,
}

/// `GET /api/jobs`
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Page<JobView>>> {
    let limit = checked_page_limit(q.limit)?;
    if let Some(cursor) = q.cursor.as_deref() {
        dag_core::validate_job_id(cursor)?;
    }

    on_blocking_pool(&state, move |control| {
        let mut ids = control
            .job_log
            .list_job_ids_page(q.cursor.as_deref(), lookahead_limit(limit))?;
        let mut has_more = ids.len() > limit;
        ids.truncate(limit);

        let mut out = Vec::with_capacity(ids.len());
        let mut budget = PageBudget::new();
        let mut last_included = None;
        for id in ids {
            let head = control
                .job_log
                .get_job(&JobId::from(id.clone()))?
                .ok_or_else(|| {
                    ApiError::from(anyhow::anyhow!(
                        "job {:?} disappeared while its listing page was read",
                        id
                    ))
                })?;
            let view = to_job_view(head);
            if !budget.try_push(&view, &format!("job {:?}", view.id))? {
                has_more = true;
                break;
            }
            last_included = Some(id);
            out.push(view);
        }
        let next_cursor = has_more.then(|| last_included.expect("page made progress"));
        Ok(Json(Page::new(out, next_cursor)))
    })
    .await
}

/// Which runs to return.
#[derive(Debug, Deserialize)]
pub struct RunsQuery {
    /// Job ID.
    pub id: String,
    /// Maximum runs, newest first.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Return run IDs strictly below this cursor.
    pub cursor: Option<u64>,
}

fn default_limit() -> usize {
    25
}

/// `GET /api/jobs/runs?id=…`
pub async fn runs(
    State(state): State<AppState>,
    Query(q): Query<RunsQuery>,
) -> ApiResult<Json<Page<RunView>>> {
    let limit = checked_run_limit(q.limit)?;
    if q.cursor == Some(0) {
        return Err(ApiError::bad_request(
            "run cursor must be a positive integer",
        ));
    }
    on_blocking_pool(&state, move |control| {
        let mut runs = control.job_log.get_job_runs_page(
            &JobId::from(q.id),
            q.cursor,
            lookahead_limit(limit),
        )?;
        let mut has_more = runs.len() > limit;
        runs.truncate(limit);
        let mut out = Vec::with_capacity(runs.len());
        let mut budget = PageBudget::new();
        let mut last = None;
        for run in runs {
            let cursor = run.run_id.to_string();
            let view = to_run_view(run);
            if !budget.try_push(&view, &format!("job run {cursor}"))? {
                has_more = true;
                break;
            }
            last = Some(cursor);
            out.push(view);
        }
        let next_cursor = has_more.then(|| last.expect("page made progress"));
        Ok(Json(Page::new(out, next_cursor)))
    })
    .await
}

/// Request to run a job now.
#[derive(Debug, Deserialize)]
pub struct RunRequest {
    /// Job ID.
    pub id: String,
}

/// `POST /api/jobs/run`
///
/// Executes synchronously: trigger, resolve, run, record. Runs here are short
/// and the console wants the outcome, not a polling loop.
pub async fn run_once(
    State(state): State<AppState>,
    Json(req): Json<RunRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    // Execution performs several offloaded database/store phases around an
    // awaited adapter. Hold one aggregate admission slot across the complete
    // lifecycle so concurrent runs cannot bypass the same finite resource
    // budget used by the rest of the API's blocking work.
    let _permit = state.try_blocking_permit()?;
    let job_id = JobId::from(req.id.clone());
    let outcome = dag_jobs::execute_once(&state.control, &job_id).await?;

    Ok(Json(serde_json::json!({
        "job_id": req.id,
        "run_id": outcome.run_id.to_string(),
        "revision": {
            "event_cid": outcome.revision.event_cid.to_hex(),
            "event_seq": outcome.revision.event_seq,
            "code_ref": outcome.revision.code_ref,
        },
        "outputs": outcome.outputs.iter()
            .map(|(name, cid)| serde_json::json!({ "name": name, "cid": cid.to_hex() }))
            .collect::<Vec<_>>(),
    })))
}

/// `GET /api/adapters`
///
/// Each entry carries `simulated`, which the console renders: `fake_fetch` is
/// a test double and must not be presented as a peer of the real adapters.
pub async fn adapters() -> Json<Vec<dag_jobs::AdapterInfo>> {
    Json(dag_jobs::builtin_adapters())
}

fn to_run_view(run: dag_core::JobRun) -> RunView {
    let (status, error) = match &run.status {
        RunStatus::Pending => ("Pending".to_string(), None),
        RunStatus::Running => ("Running".to_string(), None),
        RunStatus::Succeeded => ("Succeeded".to_string(), None),
        RunStatus::Failed { message } => ("Failed".to_string(), Some(message.clone())),
    };

    RunView {
        run_id: run.run_id.to_string(),
        job_id: run.job_id.to_string(),
        status,
        error,
        outputs: run
            .outputs
            .iter()
            .map(|(name, cid)| OutputView {
                name: name.clone(),
                cid: cid.to_hex(),
            })
            .collect(),
        pointer_inputs: run
            .manifest
            .pointer_heads
            .iter()
            .map(|p| ResolvedInputView {
                pointer_id: p.pointer_id.clone(),
                cid: p.head_cid.to_hex(),
                seq: p.log_seq,
            })
            .collect(),
        static_inputs: run
            .manifest
            .static_inputs
            .iter()
            .map(|c| c.to_hex())
            .collect(),
        started_at: run.started_at_unix,
        finished_at: run.finished_at_unix,
        node_id: run.node_id,
        revision: run.revision.map(|revision| RevisionView {
            event_cid: revision.event_cid.to_hex(),
            event_seq: revision.event_seq,
            code_ref: revision.code_ref,
        }),
    }
}

fn to_job_view(head: dag_control::job::JobHead) -> JobView {
    JobView {
        id: head.spec.job_id.to_string(),
        code_ref: head.spec.code_ref,
        determinism: format!("{:?}", head.spec.determinism),
        pointer_inputs: head.spec.inputs.pointer_inputs,
        static_inputs: head
            .spec
            .inputs
            .static_inputs
            .iter()
            .map(|c| c.to_hex())
            .collect(),
        declared_outputs: head.spec.declared_outputs,
        cache_policy: describe_cache(&head.spec.policy.cache_outputs),
        trigger: format!("{:?}", head.spec.policy.trigger),
        trigger_count: head.trigger_count,
    }
}

fn describe_cache(policy: &dag_core::CachePolicy) -> String {
    match policy {
        dag_core::CachePolicy::None => "none".to_string(),
        dag_core::CachePolicy::Ttl { seconds } => format!("ttl:{}s", seconds),
        dag_core::CachePolicy::Pin { ttl } => match ttl {
            Some(t) => format!("pin ttl:{}s", t),
            None => "pin".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_control::test_utils::TestControl;
    use std::sync::Arc;

    #[test]
    fn run_history_response_limit_is_hard_bounded() {
        assert_eq!(checked_run_limit(25).unwrap(), 25);
        assert_eq!(
            checked_run_limit(0).unwrap_err().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            checked_run_limit(usize::MAX).unwrap_err().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn job_execution_respects_aggregate_admission() {
        let tc = TestControl::new().expect("test control");
        let mut state = AppState::new(Arc::new(tc.control));
        state.blocking_admission = Arc::new(tokio::sync::Semaphore::new(1));
        let held = state.try_blocking_permit().expect("occupy sole slot");

        let error = run_once(
            State(state.clone()),
            Json(RunRequest {
                id: "does-not-matter".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);

        drop(held);
    }
}
