//! Garbage collection, retention and recovery endpoints.

use axum::extract::{Query, State};
use axum::Json;
use dag_control::{GcRequest, RetentionStatus};
use serde::{Deserialize, Serialize};

use crate::blocking::on_blocking_pool;
use crate::error::ApiResult;
use crate::routes::parse_cid;
use crate::AppState;

/// Why a CID is (or is not) retained.
#[derive(Debug, Serialize)]
pub struct RetentionView {
    /// CID inspected.
    pub cid: String,
    /// Whether anything currently protects it.
    pub protected: bool,
    /// Pin IDs contributing retention.
    pub sources: Vec<String>,
    /// Earliest expiry among contributing pins.
    pub earliest_expiry: Option<i64>,
    /// Whether it is protected as control-plane data.
    pub system_protected: bool,
}

/// Optional node scoping for a status query.
#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    /// CID to inspect.
    pub cid: String,
    /// Also apply this node's local-scoped pins.
    pub node_id: Option<String>,
}

/// `GET /api/gc/status?cid=…`
pub async fn status(
    State(state): State<AppState>,
    Query(q): Query<StatusQuery>,
) -> ApiResult<Json<RetentionView>> {
    let cid = parse_cid(&q.cid)?;
    on_blocking_pool(&state, move |control| {
        let status = control.retention_status(&cid, q.node_id.as_deref())?;

        Ok(Json(match status {
            RetentionStatus::Unprotected => RetentionView {
                cid: q.cid,
                protected: false,
                sources: vec![],
                earliest_expiry: None,
                system_protected: false,
            },
            RetentionStatus::Protected(eff) => RetentionView {
                cid: q.cid,
                protected: true,
                sources: eff.sources,
                earliest_expiry: eff.earliest_expiry,
                system_protected: eff.is_system_protected,
            },
        }))
    })
    .await
}

/// Outcome of a collection pass.
#[derive(Debug, Serialize)]
pub struct GcReportView {
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// Chunks considered.
    pub examined: usize,
    /// Chunks deleted (or that would be, on a dry run).
    pub deleted: usize,
    /// Bytes reclaimed.
    pub bytes_freed: usize,
    /// Chunks held by pins.
    pub protected_by_pins: usize,
    /// Chunks held by the system-data policy.
    pub protected_by_system: usize,
    /// Chunks skipped for being too new.
    pub skipped_too_young: usize,
    /// Whether the finite deletion ceiling stopped this pass early.
    pub truncated: bool,
    /// Non-fatal errors encountered.
    pub errors: Vec<String>,
    /// Whether additional per-chunk errors were omitted.
    pub errors_truncated: bool,
    /// Wall-clock duration.
    pub duration_ms: u64,
}

/// Collection parameters, accepted in the query string or the JSON body.
///
/// Every field is optional; whatever is omitted takes [`GcRequest`]'s
/// default. Unknown names are refused rather than ignored — this endpoint
/// deletes data, and the failure mode strictness exists for is a misspelled
/// `dry_run` falling through to a live collection, which happened live.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcRunParams {
    /// See [`GcRequest::node_id`].
    pub node_id: Option<String>,
    /// See [`GcRequest::dry_run`].
    pub dry_run: Option<bool>,
    /// See [`GcRequest::max_delete`]. Zero is reserved for an explicit offline
    /// CLI pass and is refused over HTTP.
    pub max_delete: Option<usize>,
    /// See [`GcRequest::min_age_secs`].
    pub min_age_secs: Option<u64>,
    /// See [`GcRequest::system_protection`]. `false` is an offline-only
    /// forensic escape hatch and is refused over HTTP.
    pub system_protection: Option<bool>,
}

impl GcRunParams {
    fn is_empty(&self) -> bool {
        let Self {
            node_id,
            dry_run,
            max_delete,
            min_age_secs,
            system_protection,
        } = self;
        node_id.is_none()
            && dry_run.is_none()
            && max_delete.is_none()
            && min_age_secs.is_none()
            && system_protection.is_none()
    }

    fn into_request(self) -> GcRequest {
        let mut req = GcRequest::default();
        if let Some(v) = self.node_id {
            req.node_id = v;
        }
        if let Some(v) = self.dry_run {
            req.dry_run = v;
        }
        if let Some(v) = self.max_delete {
            req.max_delete = v;
        }
        if let Some(v) = self.min_age_secs {
            req.min_age_secs = v;
        }
        if let Some(v) = self.system_protection {
            req.system_protection = v;
        }
        req
    }
}

/// `POST /api/gc/run`
///
/// Returns 409 when the recovery gate is unmet or the finite inventory ceiling
/// is exceeded. In either case collection refuses before deleting data.
pub async fn run(
    State(state): State<AppState>,
    Query(query): Query<GcRunParams>,
    body: Option<Json<GcRunParams>>,
) -> ApiResult<Json<GcReportView>> {
    // One place or the other. When both carry parameters there are two
    // plausible readings of the caller's intent, and guessing wrong on a
    // deletion endpoint is not acceptable; an empty `{}` body next to query
    // parameters is not a conflict, just a client that always sends a body.
    let params = match body {
        Some(Json(body)) if !body.is_empty() => {
            if !query.is_empty() {
                return Err(crate::error::ApiError::bad_request(
                    "collection parameters appear in both the query string and the JSON body; \
                     put them in one place",
                ));
            }
            body
        }
        _ => query,
    };
    let req = params.into_request();
    if req.max_delete == 0 {
        return Err(crate::error::ApiError::bad_request(
            "max_delete=0 is an unbounded offline operation; use a finite HTTP ceiling",
        ));
    }
    if !req.system_protection {
        return Err(crate::error::ApiError::bad_request(
            "system_protection=false can delete recovery and audit history; it is available only through the explicit offline CLI flag",
        ));
    }

    // A collection pass stats and unlinks every unprotected chunk; on a large
    // store this is the longest-running request the API serves.
    on_blocking_pool(&state, move |control| {
        let started = std::time::Instant::now();
        let report = control.run_gc_summary(&req)?;

        Ok(Json(GcReportView {
            dry_run: report.dry_run,
            examined: report.total_chunks_examined,
            deleted: report.chunks_deleted,
            bytes_freed: report.bytes_freed,
            protected_by_pins: report.protected_by_pins,
            protected_by_system: report.protected_by_system,
            skipped_too_young: report.skipped_too_young,
            truncated: report.truncated_by_max_deletions,
            errors: report.errors,
            errors_truncated: report.errors_truncated,
            duration_ms: started.elapsed().as_millis() as u64,
        }))
    })
    .await
}

/// `GET /api/integrity` — re-hash every indexed chunk.
pub async fn integrity(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    // Re-hashes the entire store; unquestionably not runtime-thread work.
    on_blocking_pool(&state, |control| {
        let index = control
            .store
            .get_index()
            .ok_or_else(|| crate::error::ApiError::conflict("store opened without an index"))?;

        let scanner = dag_storage::IntegrityScanner::with_index(
            control.store.clone(),
            index,
            std::time::Duration::from_secs(60),
        );
        let result = scanner.scan_once("local")?;

        Ok(Json(serde_json::json!({
            "total_chunks": result.total_chunks,
            "valid_chunks": result.valid_chunks,
            "invalid_chunks": result.invalid_chunks,
            "invalid": result.reports.iter()
                .filter(|r| !r.is_valid)
                .map(|r| serde_json::json!({
                    "cid": r.cid.to_hex(),
                    "error": r.error_message.as_deref().unwrap_or("unknown"),
                }))
                .collect::<Vec<_>>(),
            "invalid_reports_truncated": result.reports_truncated,
            "invalid_report_limit": dag_storage::integrity::MAX_INTEGRITY_REPORTS,
        })))
    })
    .await
}
