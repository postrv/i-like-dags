//! Signature verification over HTTP.
//!
//! Read-only: signing needs a secret key, and key selection is a CLI concern
//! (`dag sign`). The console and API clients get the verdicts.

use axum::extract::{Query, State};
use axum::Json;
use dag_control::TrustPurpose;
use serde::{Deserialize, Serialize};

use crate::blocking::on_blocking_pool;
use crate::error::{ApiError, ApiResult};
use crate::routes::{checked_page_limit, PageBudget, DEFAULT_PAGE_LIMIT};
use crate::AppState;

/// One bounded signature-verification request.
#[derive(Debug, Deserialize)]
pub struct SignatureQuery {
    /// Hex-encoded content identifier.
    pub cid: String,
    /// Opaque insertion-order offset returned by the previous page.
    pub cursor: Option<String>,
    /// Maximum signatures to verify.
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

fn default_page_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

/// A page of verified signatures for one target.
#[derive(Debug, Serialize)]
pub struct SignaturePage {
    /// Target CID.
    pub cid: String,
    /// Verified records in this page.
    pub signatures: Vec<dag_control::SignatureStatus>,
    /// Distinct trusted keys observed in this page. This is always a safe
    /// lower bound for the target-wide count.
    pub trusted: usize,
    /// Whether `trusted` is the exact target-wide count (first and only page).
    pub trusted_complete: bool,
    /// Cursor for the next page.
    pub next_cursor: Option<String>,
    /// True exactly when `next_cursor` is present.
    pub truncated: bool,
}

/// `GET /api/signatures?cid=…` — a bounded page of signatures, verified.
///
/// Each entry reports both verdicts: `trusted` (verified against the local
/// keyring) and `valid` (self-consistent only). Consumers gating on
/// signatures must check `trusted`.
///
/// The top-level `trusted` count is of **distinct keys in this page**, not
/// signatures. `trusted_complete` is true only when that count covers the
/// whole target. On a partial page the count remains a safe lower bound: any
/// threshold it satisfies is also satisfied globally, but it may undercount.
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<SignatureQuery>,
) -> ApiResult<Json<SignaturePage>> {
    let cid = crate::routes::parse_cid(&q.cid)?;
    let limit = checked_page_limit(q.limit)?;
    let offset = q
        .cursor
        .as_deref()
        .map(|cursor| {
            cursor.parse::<usize>().map_err(|_| {
                ApiError::bad_request("invalid signature cursor: expected a non-negative integer")
            })
        })
        .transpose()?
        .unwrap_or(0);

    on_blocking_pool(&state, move |control| {
        let (sig_cids, mut has_more) = control.signature_log.list_for_page(&cid, offset, limit)?;
        let mut statuses = Vec::with_capacity(sig_cids.len());
        let mut budget = PageBudget::new();
        for sig_cid in sig_cids {
            let status =
                control
                    .signature_log
                    .verify_signature_for(&cid, &sig_cid, TrustPurpose::Verify)?;
            if !budget.try_push(
                &status,
                &format!("signature {:?}", status.signature_cid.to_hex()),
            )? {
                has_more = true;
                break;
            }
            statuses.push(status);
        }
        let trusted = dag_control::signatures::distinct_trusted_keys(&statuses);
        let next_offset = offset.saturating_add(statuses.len());
        let next_cursor = has_more.then(|| next_offset.to_string());
        Ok(Json(SignaturePage {
            cid: cid.to_hex(),
            signatures: statuses,
            trusted,
            trusted_complete: offset == 0 && !has_more,
            truncated: next_cursor.is_some(),
            next_cursor,
        }))
    })
    .await
}
