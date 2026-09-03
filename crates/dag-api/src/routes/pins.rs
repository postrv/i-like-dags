//! Pin and retention endpoints.

use axum::extract::{Query, State};
use axum::Json;
use dag_control::now_unix;
use dag_core::{PinScope, PinState, PinTarget};
use serde::{Deserialize, Serialize};

use crate::blocking::on_blocking_pool;
use crate::error::{ApiError, ApiResult};
use crate::routes::{
    checked_page_limit, lookahead_limit, parse_cid, Page, PageBudget, DEFAULT_PAGE_LIMIT,
};
use crate::AppState;

/// Cursor pagination for pin heads.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Return IDs lexicographically after this opaque cursor.
    pub cursor: Option<String>,
    /// Number of pin heads to inspect.
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

fn default_page_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

/// A pin's current state.
#[derive(Debug, Serialize)]
pub struct PinView {
    /// Pin ID.
    pub id: String,
    /// Sequence number of the latest event.
    pub seq: u64,
    /// Whether this pin is providing retention right now.
    pub active: bool,
    /// `Active` or `Deactivated`.
    pub state: String,
    /// `global` or `local:<node>`.
    pub scope: String,
    /// CID the pin targets (the subtree root, when a subtree).
    pub target_cid: String,
    /// Whether the pin covers the target's subtree.
    pub subtree: bool,
    /// Subtree depth limit, when bounded.
    pub max_depth: Option<u32>,
    /// Absolute expiry, POSIX seconds.
    pub expires_at: Option<i64>,
    /// When the latest event was recorded.
    pub ts: i64,
    /// Recorded author, if any.
    pub author: Option<String>,
}

/// `GET /api/pins`
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Page<PinView>>> {
    let limit = checked_page_limit(q.limit)?;
    if let Some(cursor) = q.cursor.as_deref() {
        dag_control::validate_pin_id(cursor)?;
    }

    on_blocking_pool(&state, move |control| {
        let now = now_unix();
        let mut ids = control
            .pin_log
            .list_page(q.cursor.as_deref(), lookahead_limit(limit))?;
        let mut has_more = ids.len() > limit;
        ids.truncate(limit);

        let mut out = Vec::with_capacity(ids.len());
        let mut budget = PageBudget::new();
        let mut last_included = None;
        for id in ids {
            let head = control.pin_log.head(&id)?;
            let (target_cid, subtree, max_depth) = match &head.event.target {
                PinTarget::Direct(cid) => (cid.to_hex(), false, None),
                PinTarget::Subtree { root, max_depth } => (root.to_hex(), true, *max_depth),
            };
            let view = PinView {
                active: head.is_providing_retention(now),
                seq: head.event.seq,
                state: match head.event.state {
                    PinState::Active => "Active".into(),
                    PinState::Deactivated => "Deactivated".into(),
                },
                scope: match &head.event.scope {
                    PinScope::Global => "global".to_string(),
                    PinScope::Local { node_id } => format!("local:{}", node_id),
                },
                target_cid,
                subtree,
                max_depth,
                expires_at: head.event.expires_at,
                ts: head.event.ts,
                author: head.event.author.clone(),
                id,
            };
            if !budget.try_push(&view, &format!("pin {:?}", view.id))? {
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

/// Request to create a pin.
#[derive(Debug, Deserialize)]
pub struct CreatePin {
    /// Pin ID.
    pub id: String,
    /// CID to retain.
    pub cid: String,
    /// Retain everything reachable from the CID.
    #[serde(default)]
    pub subtree: bool,
    /// Bound on subtree depth.
    pub max_depth: Option<u32>,
    /// `global` (default) or `local:<node>`.
    #[serde(default = "global_scope")]
    pub scope: String,
    /// Expire the pin after this many seconds.
    pub ttl_secs: Option<i64>,
    /// Recorded as the pin's author.
    pub author: Option<String>,
}

fn global_scope() -> String {
    "global".to_string()
}
/// `POST /api/pins`
pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<CreatePin>,
) -> ApiResult<Json<serde_json::Value>> {
    dag_control::validate_pin_id(&req.id)?;
    let cid = parse_cid(&req.cid)?;

    let target = if req.subtree {
        PinTarget::Subtree {
            root: cid,
            max_depth: req.max_depth,
        }
    } else {
        PinTarget::Direct(cid)
    };

    let scope = parse_scope(&req.scope)?;
    // TTL is relative on the wire but absolute on disk (R5), and that
    // conversion is arithmetic on a caller-supplied `i64`. Unchecked, it
    // panicked a worker in debug and — with `overflow-checks` off in release —
    // wrapped silently, so a pin created with `ttl_secs: i64::MAX` returned
    // 200, listed as Active, and protected nothing. Three surfaces disagreeing
    // about one pin is worse than a refusal.
    let expires_at = req.ttl_secs.map(absolute_expiry).transpose()?;

    on_blocking_pool(&state, move |control| {
        control
            .pin_log
            .create(&req.id, target, scope, expires_at, req.author)?;

        Ok(Json(
            serde_json::json!({ "id": req.id, "expires_at": expires_at }),
        ))
    })
    .await
}

/// Request to release a pin.
#[derive(Debug, Deserialize)]
pub struct DeactivatePin {
    /// Pin ID.
    pub id: String,
    /// Recorded as the event's author.
    pub author: Option<String>,
}

/// `POST /api/pins/deactivate`
pub async fn deactivate(
    State(state): State<AppState>,
    Json(req): Json<DeactivatePin>,
) -> ApiResult<Json<serde_json::Value>> {
    on_blocking_pool(&state, move |control| {
        control.pin_log.deactivate(&req.id, req.author)?;
        Ok(Json(
            serde_json::json!({ "id": req.id, "state": "Deactivated" }),
        ))
    })
    .await
}

/// Range selection for pin history.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Pin ID.
    pub id: String,
    /// First sequence number to include.
    #[serde(default = "one")]
    pub from: u64,
    /// Exclusive upper bound; defaults to one past the current head.
    pub to: Option<u64>,
    /// Opaque continuation returned by the previous page.
    pub cursor: Option<String>,
    /// Maximum number of events to return.
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

fn one() -> u64 {
    1
}

/// `GET /api/pins/history?id=…`
pub async fn history(
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Page<dag_core::PinEvent>>> {
    dag_control::validate_pin_id(&q.id)?;
    let limit = checked_page_limit(q.limit)?;
    let start = match q.cursor.as_deref() {
        Some(_) if q.from != one() => {
            return Err(ApiError::bad_request(
                "cursor and a non-default `from` cannot be combined",
            ));
        }
        Some(cursor) => cursor.parse::<u64>().map_err(|_| {
            ApiError::bad_request("invalid pin-history cursor: expected an unsigned integer")
        })?,
        None => q.from,
    };
    if start == 0 {
        return Err(ApiError::bad_request("pin history starts at sequence 1"));
    }

    on_blocking_pool(&state, move |control| {
        let head_end = control
            .pin_log
            .head(&q.id)?
            .event
            .seq
            .checked_add(1)
            .ok_or_else(|| ApiError::service_unavailable("pin sequence is exhausted"))?;
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
        let mut events = Vec::new();
        let mut budget = PageBudget::new();
        let mut next_seq = start;
        while next_seq < page_end {
            let one_end = next_seq.saturating_add(1);
            let mut one = control.pin_log.history(&q.id, next_seq..one_end)?;
            let event = one.pop().ok_or_else(|| {
                ApiError::from(anyhow::anyhow!(
                    "pin {:?} is missing history event {}; rebuild or repair the pin log before continuing",
                    q.id,
                    next_seq
                ))
            })?;
            if event.seq != next_seq {
                return Err(ApiError::from(anyhow::anyhow!(
                    "pin {:?} history event {} decodes as sequence {}; rebuild or repair the pin log before continuing",
                    q.id,
                    next_seq,
                    event.seq
                )));
            }
            if !budget.try_push(
                &event,
                &format!("pin {:?} history event {}", q.id, next_seq),
            )? {
                break;
            }
            events.push(event);
            next_seq = one_end;
        }
        let next_cursor = (next_seq < end).then(|| next_seq.to_string());
        Ok(Json(Page::new(events, next_cursor)))
    })
    .await
}

/// Turn a relative TTL into the absolute POSIX second it expires at (R5).
///
/// A negative TTL is refused rather than quietly producing a pin that is dead
/// on arrival: `POST /api/pins` reporting success for something that retains
/// nothing is the same failure mode as the overflow, just reached politely.
fn absolute_expiry(ttl_secs: i64) -> ApiResult<i64> {
    let now = now_unix();
    if ttl_secs < 0 {
        return Err(ApiError::bad_request(format!(
            "ttl_secs {} is negative: a pin cannot expire before it is created",
            ttl_secs
        )));
    }
    now.checked_add(ttl_secs).ok_or_else(|| {
        ApiError::bad_request(format!(
            "ttl_secs {} overflows the POSIX-second timestamp: at most {} from now",
            ttl_secs,
            i64::MAX - now
        ))
    })
}

fn parse_scope(spec: &str) -> ApiResult<PinScope> {
    if spec == "global" {
        return Ok(PinScope::Global);
    }
    match spec.strip_prefix("local:") {
        Some(node) if !node.is_empty() => Ok(PinScope::Local {
            node_id: node.to_string(),
        }),
        _ => Err(ApiError::bad_request(format!(
            "invalid scope {:?}: expected `global` or `local:<NODE_ID>`",
            spec
        ))),
    }
}
