//! Endpoints for the worked example, so the console can load and verify it.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::blocking::on_blocking_pool;
use crate::error::ApiResult;
use crate::scenario::{self, SeedReport, VerifyReport};
use crate::AppState;

/// `POST /api/usecase/seed`
pub async fn seed(State(state): State<AppState>) -> ApiResult<Json<SeedReport>> {
    // Full recovery is deliberately CLI-only: it scans operator-sized state.
    Ok(Json(scenario::seed(&state.control, false).await?))
}

/// Which release to verify.
#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    /// Pointer naming the release; defaults to the example's production pointer.
    pub pointer: Option<String>,
}

/// `GET /api/usecase/verify?pointer=…`
pub async fn verify(
    State(state): State<AppState>,
    Query(q): Query<VerifyQuery>,
) -> ApiResult<Json<VerifyReport>> {
    let pointer = q
        .pointer
        .unwrap_or_else(|| scenario::PTR_PRODUCTION.to_string());
    on_blocking_pool(&state, move |control| {
        Ok(Json(scenario::verify(control, &pointer)?))
    })
    .await
}
