//! `GET /metrics` — the Prometheus scrape endpoint.
//!
//! Three sections, one text body: the control plane's registry (counters and
//! latency histograms recorded as work happens), scrape-time gauges for the
//! store's current shape (whose source of truth is [`Control::stats`], not a
//! counter), and this server's own HTTP request series.
//!
//! Served at both `/metrics` (the scraper convention) and `/api/metrics`
//! (behind the same-site guard, beside every other API path).
//!
//! [`Control::stats`]: dag_control::Control::stats

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header::CONTENT_TYPE, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dag_core::metrics::{gauge, Histogram};

use crate::blocking::on_blocking_pool;
use crate::error::ApiResult;
use crate::AppState;

/// The exposition content type Prometheus expects.
pub const CONTENT_TYPE_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Requests by `(method, route, status)`, plus one latency histogram.
///
/// The route label is the *matched pattern* (`/api/chunks/{cid}`), never the
/// raw path, so cardinality is bounded by the route table. Anything the
/// router did not match — the SPA fallback, probes for paths that do not
/// exist — collapses into one `"unmatched"` cell.
#[derive(Default)]
pub struct HttpMetrics {
    requests: Mutex<HashMap<(String, String, u16), u64>>,
    duration: Histogram,
}

impl HttpMetrics {
    fn requests(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String, u16), u64>> {
        // Metrics are observational. If an unrelated panic poisoned this
        // mutex, preserve the counters that remain instead of making every
        // later request and scrape panic as well.
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn record(&self, method: &str, route: &str, status: u16, elapsed: Duration) {
        let mut requests = self.requests();
        *requests
            .entry((method.to_string(), route.to_string(), status))
            .or_insert(0) += 1;
        drop(requests);
        self.duration.observe(elapsed);
    }

    /// Render the HTTP series, sorted so scrapes are stable to diff.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP dag_http_requests_total HTTP requests served, by method, matched route and status.\n");
        out.push_str("# TYPE dag_http_requests_total counter\n");
        let mut rows: Vec<(String, u64)> = self
            .requests()
            .iter()
            .map(|((method, route, status), count)| {
                (
                    format!(
                        "dag_http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}}",
                        method, route, status
                    ),
                    *count,
                )
            })
            .collect();
        rows.sort();
        for (series, count) in rows {
            out.push_str(&series);
            out.push(' ');
            out.push_str(&count.to_string());
            out.push('\n');
        }
        out
    }

    /// The latency histogram, rendered by the caller alongside the counters.
    pub fn duration(&self) -> &Histogram {
        &self.duration
    }
}

/// A finite label set for HTTP methods.
///
/// Method tokens are attacker-controlled and HTTP permits extension methods.
/// Storing the raw token in the metrics key lets a public caller grow the map
/// forever with `X-ONE`, `X-TWO`, … even though route and status labels are
/// otherwise bounded. Standard methods retain useful labels; every extension
/// shares one bucket.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::CONNECT => "CONNECT",
        Method::DELETE => "DELETE",
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

/// Middleware recording every request into [`HttpMetrics`].
pub async fn track(State(http): State<Arc<HttpMetrics>>, request: Request, next: Next) -> Response {
    let method = method_label(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let started = std::time::Instant::now();

    let response = next.run(request).await;

    http.record(
        method,
        &route,
        response.status().as_u16(),
        started.elapsed(),
    );
    response
}

/// `GET /metrics` (and `/api/metrics`).
pub async fn scrape(
    State(state): State<AppState>,
    axum::Extension(http): axum::Extension<Arc<HttpMetrics>>,
) -> ApiResult<Response> {
    // Registry render is lock-free, but stats() walks redb — blocking pool.
    let mut body = on_blocking_pool(&state, |control| {
        let mut out = control.metrics.render();
        let stats = control.stats()?;
        gauge(
            &mut out,
            "dag_store_chunks",
            "Chunks tracked in the index.",
            stats.chunks as f64,
        );
        gauge(
            &mut out,
            "dag_store_bytes",
            "Total bytes across all stored chunks.",
            stats.bytes as f64,
        );
        gauge(
            &mut out,
            "dag_pointers",
            "Distinct pointers.",
            stats.pointers as f64,
        );
        gauge(
            &mut out,
            "dag_pins",
            "Distinct pins, any state.",
            stats.pins as f64,
        );
        gauge(
            &mut out,
            "dag_pins_active",
            "Pins currently providing retention.",
            stats.active_pins as f64,
        );
        gauge(&mut out, "dag_jobs", "Registered jobs.", stats.jobs as f64);
        gauge(
            &mut out,
            "dag_job_runs_pending",
            "Runs waiting for a worker lease.",
            stats.pending_runs as f64,
        );
        gauge(
            &mut out,
            "dag_job_runs_running",
            "Runs currently executing.",
            stats.running_runs as f64,
        );
        gauge(
            &mut out,
            "dag_job_trigger_queue",
            "Durable pointer-trigger intents waiting to become runs.",
            stats.trigger_queue as f64,
        );
        gauge(
            &mut out,
            "dag_job_trigger_dead_letters",
            "Permanent trigger failures requiring operator attention.",
            stats.trigger_dead_letters as f64,
        );
        gauge(
            &mut out,
            "dag_event_seq",
            "Latest sequence number in the event journal.",
            stats.event_seq as f64,
        );
        gauge(
            &mut out,
            "dag_recovered",
            "Whether the recovery gate is satisfied (1 = yes).",
            if stats.recovered { 1.0 } else { 0.0 },
        );
        Ok(out)
    })
    .await?;

    body.push_str(&http.render());
    body.push_str(&dag_core::metrics::render_histogram(
        "dag_http_request_seconds",
        "HTTP request wall time in seconds.",
        http.duration(),
    ));

    Ok(([(CONTENT_TYPE, CONTENT_TYPE_TEXT)], body).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_methods_share_one_bounded_metrics_bucket() {
        let metrics = HttpMetrics::default();
        for i in 0..10_000 {
            let method = Method::from_bytes(format!("X-UNIQUE-{i}").as_bytes()).unwrap();
            metrics.record(method_label(&method), "unmatched", 405, Duration::ZERO);
        }

        let rows = metrics.requests();
        assert_eq!(rows.len(), 1, "extension methods grew metric cardinality");
        assert_eq!(
            rows.get(&("OTHER".into(), "unmatched".into(), 405)),
            Some(&10_000)
        );
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::POST), "POST");
    }
}
