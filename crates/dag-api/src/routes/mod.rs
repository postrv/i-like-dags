//! HTTP handlers, grouped by subsystem.
//!
//! Entity IDs travel as query parameters rather than path segments. Pointer,
//! pin and job IDs are allowed to contain `/` — `models/fraud-detector/production`
//! is the shape the system is designed for — and a path segment cannot carry
//! one unambiguously.

pub mod content;
pub mod events;
pub mod files;
pub mod gc;
pub mod jobs;
pub mod metrics;
pub mod pins;
pub mod pointers;
pub mod scenario;
pub mod signatures;

use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};

/// Default number of records returned by a collection endpoint.
pub const DEFAULT_PAGE_LIMIT: usize = 100;

/// Absolute response-work bound for collection endpoints.
pub const MAX_PAGE_LIMIT: usize = 200;

/// Maximum encoded item bytes in one JSON collection response.
///
/// A row can itself contain user-controlled strings and arrays. Bounding only
/// the item count would still allow a small request to make the server build a
/// response hundreds of MiB large.
pub const MAX_PAGE_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Conservative space for `items`, continuation fields, punctuation and
/// numeric/string cursor encoding around the accounted item bodies.
const PAGE_ENVELOPE_JSON_BYTES: usize = 2 * 1024;

/// Streaming size counter used to budget JSON without allocating a second
/// copy of every item solely to measure it.
pub struct PageBudget {
    used: usize,
}

impl Default for PageBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl PageBudget {
    /// Reserve a little space for the envelope, then account items exactly as
    /// serde_json will encode them.
    pub fn new() -> Self {
        Self {
            used: PAGE_ENVELOPE_JSON_BYTES,
        }
    }

    /// Whether `item` fits. A later item returns `false` so the caller can
    /// expose a continuation; a first item that cannot fit is a hard 413,
    /// otherwise a cursor loop could never make progress.
    pub fn try_push<T: Serialize>(&mut self, item: &T, description: &str) -> ApiResult<bool> {
        let mut counter = JsonByteCounter::default();
        serde_json::to_writer(&mut counter, item)
            .map_err(|e| ApiError::from(anyhow::Error::from(e)))?;
        let needed = counter.bytes.saturating_add(1); // comma or closing bracket
        if self.used.saturating_add(needed) > MAX_PAGE_JSON_BYTES {
            if self.used == PAGE_ENVELOPE_JSON_BYTES {
                return Err(ApiError::payload_too_large(format!(
                    "{description} cannot fit within the {MAX_PAGE_JSON_BYTES}-byte collection response budget; repair or remove this oversized legacy record before listing this page"
                )));
            }
            return Ok(false);
        }
        self.used += needed;
        Ok(true)
    }
}

#[derive(Default)]
struct JsonByteCounter {
    bytes: usize,
}

impl std::io::Write for JsonByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A bounded page whose continuation is explicit on the wire.
///
/// Cursors are opaque to clients: ID listings use the last lexicographic ID,
/// while histories and signature lists use a numeric position. An absent
/// `next_cursor` means this page exhausted the requested collection.
#[derive(Debug, Serialize)]
pub struct Page<T> {
    /// Records in this page.
    pub items: Vec<T>,
    /// Cursor to pass on the next request, when more records exist.
    pub next_cursor: Option<String>,
    /// True exactly when `next_cursor` is present.
    pub truncated: bool,
}

impl<T> Page<T> {
    /// Construct a page and keep the continuation indicators consistent.
    pub fn new(items: Vec<T>, next_cursor: Option<String>) -> Self {
        Self {
            items,
            truncated: next_cursor.is_some(),
            next_cursor,
        }
    }
}

/// Validate a caller-selected page size rather than silently clamping it.
pub fn checked_page_limit(limit: usize) -> ApiResult<usize> {
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::bad_request(format!(
            "limit must be between 1 and {MAX_PAGE_LIMIT}, got {limit}"
        )));
    }
    Ok(limit)
}

/// Add one look-ahead record without overflowing `usize`.
pub fn lookahead_limit(limit: usize) -> usize {
    // Every caller has already passed `checked_page_limit`, but keeping this
    // helper total makes it safe to reuse independently.
    limit.saturating_add(1)
}

/// A request naming a single entity by ID.
#[derive(Debug, Deserialize)]
pub struct IdQuery {
    /// The pointer, pin or job ID.
    pub id: String,
}

/// A request naming a single CID.
#[derive(Debug, Deserialize)]
pub struct CidQuery {
    /// Hex-encoded content identifier.
    pub cid: String,
}

/// Parse a hex CID, reporting a 400 rather than a 500 on malformed input.
pub fn parse_cid(hex: &str) -> Result<dag_core::Cid, crate::error::ApiError> {
    dag_core::Cid::from_hex(hex)
        .map_err(|e| crate::error::ApiError::bad_request(format!("invalid CID {:?}: {}", hex, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn page_limits_are_rejected_instead_of_silently_clamped() {
        assert_eq!(checked_page_limit(1).unwrap(), 1);
        assert_eq!(checked_page_limit(MAX_PAGE_LIMIT).unwrap(), MAX_PAGE_LIMIT);
        assert_eq!(
            checked_page_limit(0).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            checked_page_limit(MAX_PAGE_LIMIT + 1).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn page_continuation_is_explicit() {
        let complete = Page::new(vec![1], None);
        assert!(!complete.truncated);
        let partial = Page::new(vec![1], Some("cursor".into()));
        assert!(partial.truncated);
        assert_eq!(partial.next_cursor.as_deref(), Some("cursor"));
    }

    #[test]
    fn encoded_page_budget_refuses_a_single_oversized_record() {
        let huge = "x".repeat(MAX_PAGE_JSON_BYTES);
        let error = PageBudget::new()
            .try_push(&huge, "test record")
            .unwrap_err();
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn encoded_page_budget_stops_after_progress() {
        let first = "x".repeat(MAX_PAGE_JSON_BYTES / 2);
        let second = "y".repeat(MAX_PAGE_JSON_BYTES / 2);
        let mut budget = PageBudget::new();
        assert!(budget.try_push(&first, "first").unwrap());
        assert!(!budget.try_push(&second, "second").unwrap());
    }
}
