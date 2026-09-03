//! Pointer endpoints.

use axum::extract::{Query, State};
use axum::Json;
use dag_core::Cid;
use serde::{Deserialize, Serialize};

use crate::blocking::on_blocking_pool;
use crate::error::{ApiError, ApiResult};
use crate::routes::{
    checked_page_limit, lookahead_limit, parse_cid, IdQuery, Page, PageBudget, DEFAULT_PAGE_LIMIT,
};
use crate::AppState;

/// Cursor pagination for the pointer namespace.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Return IDs lexicographically after this opaque cursor.
    pub cursor: Option<String>,
    /// Number of pointer heads to inspect.
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

fn default_page_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

/// A pointer's current state.
#[derive(Debug, Serialize)]
pub struct PointerView {
    /// Pointer ID.
    pub id: String,
    /// Current sequence number; equals the number of updates.
    pub seq: u64,
    /// CID it resolves to.
    pub cid: String,
}

/// One entry in a pointer's history.
#[derive(Debug, Serialize)]
pub struct PointerEventView {
    /// Sequence number of this update.
    pub seq: u64,
    /// CID the pointer moved to.
    pub cid: String,
    /// CID it moved from; absent for the creating event.
    pub previous_cid: Option<String>,
    /// When the update was recorded.
    pub ts: i64,
}

/// `GET /api/pointers`
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Page<PointerView>>> {
    let limit = checked_page_limit(q.limit)?;
    if let Some(cursor) = q.cursor.as_deref() {
        dag_control::validate_pointer_id(cursor)?;
    }

    on_blocking_pool(&state, move |control| {
        let mut ids = control
            .pointer_log
            .list_pointers_page(q.cursor.as_deref(), lookahead_limit(limit))?;
        let mut has_more = ids.len() > limit;
        ids.truncate(limit);

        let mut out = Vec::with_capacity(ids.len());
        let mut budget = PageBudget::new();
        let mut last_included = None;
        for id in ids {
            // A listed ID and an unreadable head are contradictory views of
            // the same table. Surface corruption instead of hiding an item.
            let head = control.pointer_log.get_head(&id)?;
            let view = PointerView {
                id,
                seq: head.seq,
                cid: head.current_cid.to_hex(),
            };
            if !budget.try_push(&view, &format!("pointer {:?}", view.id))? {
                has_more = true;
                break;
            }
            last_included = Some(view.id.clone());
            out.push(view);
        }
        let next_cursor = has_more.then(|| last_included.expect("page made progress"));
        Ok(Json(Page::new(out, next_cursor)))
    })
    .await
}

/// Range selection for history.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Pointer ID.
    pub id: String,
    /// First sequence number to include.
    #[serde(default = "one")]
    pub from: u64,
    /// Exclusive upper bound; defaults to one past the current head.
    pub to: Option<u64>,
    /// Opaque continuation returned by the previous page. When present,
    /// `from` must be left at its default.
    pub cursor: Option<String>,
    /// Maximum number of events to return.
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

fn one() -> u64 {
    1
}

/// `GET /api/pointers/history?id=…`
pub async fn history(
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Page<PointerEventView>>> {
    dag_control::validate_pointer_id(&q.id)?;
    let limit = checked_page_limit(q.limit)?;
    let start = match q.cursor.as_deref() {
        Some(_) if q.from != one() => {
            return Err(ApiError::bad_request(
                "cursor and a non-default `from` cannot be combined",
            ));
        }
        Some(cursor) => cursor.parse::<u64>().map_err(|_| {
            ApiError::bad_request("invalid pointer-history cursor: expected an unsigned integer")
        })?,
        None => q.from,
    };
    if start == 0 {
        return Err(ApiError::bad_request(
            "pointer history starts at sequence 1",
        ));
    }

    on_blocking_pool(&state, move |control| {
        let head_end = control
            .pointer_log
            .get_head(&q.id)?
            .seq
            .checked_add(1)
            .ok_or_else(|| ApiError::service_unavailable("pointer sequence is exhausted"))?;
        let end = q.to.unwrap_or(head_end).min(head_end);
        if q.to.is_some_and(|to| to <= start) {
            return Err(ApiError::bad_request(format!(
                "history upper bound {end} must be greater than start {start}"
            )));
        }
        if start >= end {
            return Ok(Json(Page::new(Vec::new(), None)));
        }

        let page_end = start.saturating_add(limit as u64).min(end);
        let events = control.pointer_log.history(&q.id, start..page_end)?;
        let expected = usize::try_from(page_end - start)
            .expect("an HTTP history page is bounded by MAX_PAGE_LIMIT");
        if events.len() != expected
            || events
                .iter()
                .enumerate()
                .any(|(index, event)| event.seq != start + index as u64)
        {
            return Err(ApiError::from(anyhow::anyhow!(
                "pointer {:?} has a non-contiguous history in {}..{}; rebuild or repair the pointer log before continuing",
                q.id,
                start,
                page_end
            )));
        }
        let next_cursor = (page_end < end).then(|| page_end.to_string());

        Ok(Json(Page::new(
            events
                .into_iter()
                .map(|e| PointerEventView {
                    seq: e.seq,
                    cid: e.new.to_hex(),
                    previous_cid: e.prev.map(|c| c.to_hex()),
                    ts: e.ts,
                })
                .collect(),
            next_cursor,
        )))
    })
    .await
}

/// Request to point an ID at a CID.
#[derive(Debug, Deserialize)]
pub struct SetPointer {
    /// Pointer ID.
    pub id: String,
    /// CID to point at.
    pub cid: String,
}

/// `POST /api/pointers`
///
/// Creates the pointer if it is new, otherwise appends an update. Both are the
/// same intent — "this name now means this content" — and making the caller
/// pick would just push a race onto them.
pub async fn set(
    State(state): State<AppState>,
    Json(req): Json<SetPointer>,
) -> ApiResult<Json<PointerView>> {
    // Validate before occupying a pool thread: both checks are pure.
    dag_control::validate_pointer_id(&req.id)?;
    let cid: Cid = parse_cid(&req.cid)?;

    on_blocking_pool(&state, move |control| {
        let seq = match control.pointer_log.get_head(&req.id) {
            Ok(_) => control.pointer_log.update(&req.id, cid.clone())?.0,
            Err(dag_control::PointerError::NotFound(_)) => {
                control.pointer_log.create(&req.id, cid.clone())?;
                1
            }
            Err(error) => return Err(error.into()),
        };

        Ok(Json(PointerView {
            id: req.id,
            seq,
            cid: cid.to_hex(),
        }))
    })
    .await
}

/// `GET /api/pointers/resolve?id=…`
pub async fn resolve(
    State(state): State<AppState>,
    Query(q): Query<IdQuery>,
) -> ApiResult<Json<PointerView>> {
    on_blocking_pool(&state, move |control| {
        let head = control.pointer_log.get_head(&q.id)?;
        Ok(Json(PointerView {
            id: q.id,
            seq: head.seq,
            cid: head.current_cid.to_hex(),
        }))
    })
    .await
}
