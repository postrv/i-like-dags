//! Zero-dependency operational metrics, rendered in Prometheus text format.
//!
//! Hand-rolled on purpose. The Prometheus exposition format is a few lines
//! of text per series, and everything recorded here is an atomic increment —
//! pulling a metrics crate (and its dependency tree) into the *data-model*
//! crate to avoid writing `fetch_add` would invert this workspace's
//! economics. There is correspondingly no cardinality machinery: every
//! series is declared as a struct field, so the set of metrics is closed,
//! reviewable, and cannot explode at runtime.
//!
//! One [`Metrics`] instance belongs to one `Control` (it is not a global —
//! two open directories in one process count separately, which is also what
//! makes the tests honest). Layers below the control plane receive it as an
//! `Arc` and record what they see; the HTTP API renders it at `/metrics`,
//! appending scrape-time gauges for the store's current shape.
//!
//! Recording is wait-free (`Relaxed` atomics); rendering takes each value
//! once with no lock. A scrape observing a torn view across *different*
//! series is inherent to that trade and harmless — each individual series
//! is monotone.

use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonically increasing count.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Add one.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Add `n`.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Upper bounds (seconds) for duration histograms, ascending.
///
/// Spans 1 ms to 10 s log-scale: chunk writes sit at the bottom, collections
/// and large syncs at the top. `+Inf` is implicit.
pub const DURATION_BUCKETS: [f64; 13] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A duration histogram over [`DURATION_BUCKETS`].
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; DURATION_BUCKETS.len()],
    /// Sum in microseconds — an integer, so it can be atomic. Rendered as
    /// seconds; the microsecond floor is far below anything measured here.
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Record one observation.
    pub fn observe(&self, duration: std::time::Duration) {
        let secs = duration.as_secs_f64();
        for (i, bound) in DURATION_BUCKETS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_micros
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Observations recorded.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Cumulative count at or below each bound, in bound order.
    ///
    /// [`Self::observe`] increments every bucket an observation fits, so the
    /// stored counts are already cumulative — the format Prometheus expects.
    fn cumulative(&self) -> [u64; DURATION_BUCKETS.len()] {
        std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed))
    }
}

/// Time a closure into `histogram`, passing the result through.
pub fn timed<T>(histogram: &Histogram, work: impl FnOnce() -> T) -> T {
    let start = std::time::Instant::now();
    let out = work();
    histogram.observe(start.elapsed());
    out
}

/// Every series the system records. One instance per open control plane.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Chunk writes accepted by the store (including deduplicated re-puts).
    pub store_put_total: Counter,
    /// Bytes offered to `put_chunk`.
    pub store_put_bytes_total: Counter,
    /// `put_chunk` wall time.
    pub store_put_seconds: Histogram,
    /// Chunk reads served.
    pub store_get_total: Counter,
    /// Bytes returned by `get_chunk`.
    pub store_get_bytes_total: Counter,
    /// `get_chunk` wall time.
    pub store_get_seconds: Histogram,

    /// Collections that ran to completion.
    pub gc_runs_total: Counter,
    /// Collections refused before deleting anything (recovery gate,
    /// incomplete retention expansion).
    pub gc_refused_total: Counter,
    /// Chunks examined across all collections.
    pub gc_examined_total: Counter,
    /// Chunks deleted across all collections.
    pub gc_deleted_total: Counter,
    /// Bytes reclaimed across all collections.
    pub gc_bytes_freed_total: Counter,
    /// Full collection wall time, including the retention refresh.
    pub gc_seconds: Histogram,

    /// Chunks this node accepted as a sync destination (directory or wire).
    pub sync_chunks_received_total: Counter,
    /// Bytes in those chunks.
    pub sync_bytes_received_total: Counter,
    /// Event mappings this node filed after validating them.
    pub sync_events_imported_total: Counter,
    /// Event mappings this node's validation refused. Not an error count —
    /// each refusal is the trust boundary holding.
    pub sync_events_refused_total: Counter,

    /// Events emitted, by kind — indexed by [`EVENT_KINDS`].
    pub events_total: [Counter; EVENT_KINDS.len()],
    /// Job runs reaching each status — indexed by [`JOB_STATUSES`].
    pub job_runs_total: [Counter; JOB_STATUSES.len()],
}

/// Label values for `dag_events_total{kind=...}`, in field order.
pub const EVENT_KINDS: [&str; 4] = ["pointer", "pin", "job", "storage"];

/// Label values for `dag_job_runs_total{status=...}`, in field order.
pub const JOB_STATUSES: [&str; 4] = ["pending", "running", "succeeded", "failed"];

impl Metrics {
    /// Counter cell for one event kind, if `kind` is known.
    pub fn event_counter(&self, kind: &str) -> Option<&Counter> {
        EVENT_KINDS
            .iter()
            .position(|k| *k == kind)
            .map(|i| &self.events_total[i])
    }

    /// Counter cell for one job-run status, if `status` is known.
    pub fn job_status_counter(&self, status: &str) -> Option<&Counter> {
        JOB_STATUSES
            .iter()
            .position(|s| *s == status)
            .map(|i| &self.job_runs_total[i])
    }

    /// Render every series in Prometheus text exposition format (0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);

        counter(
            &mut out,
            "dag_store_put_total",
            "Chunk writes accepted by the store, deduplicated re-puts included.",
            self.store_put_total.get(),
        );
        counter(
            &mut out,
            "dag_store_put_bytes_total",
            "Bytes offered to put_chunk.",
            self.store_put_bytes_total.get(),
        );
        histogram(
            &mut out,
            "dag_store_put_seconds",
            "put_chunk wall time in seconds.",
            &self.store_put_seconds,
        );
        counter(
            &mut out,
            "dag_store_get_total",
            "Chunk reads served.",
            self.store_get_total.get(),
        );
        counter(
            &mut out,
            "dag_store_get_bytes_total",
            "Bytes returned by get_chunk.",
            self.store_get_bytes_total.get(),
        );
        histogram(
            &mut out,
            "dag_store_get_seconds",
            "get_chunk wall time in seconds.",
            &self.store_get_seconds,
        );

        counter(
            &mut out,
            "dag_gc_runs_total",
            "Collections that ran to completion.",
            self.gc_runs_total.get(),
        );
        counter(
            &mut out,
            "dag_gc_refused_total",
            "Collections refused before deleting anything.",
            self.gc_refused_total.get(),
        );
        counter(
            &mut out,
            "dag_gc_examined_total",
            "Chunks examined across all collections.",
            self.gc_examined_total.get(),
        );
        counter(
            &mut out,
            "dag_gc_deleted_total",
            "Chunks deleted across all collections.",
            self.gc_deleted_total.get(),
        );
        counter(
            &mut out,
            "dag_gc_bytes_freed_total",
            "Bytes reclaimed across all collections.",
            self.gc_bytes_freed_total.get(),
        );
        histogram(
            &mut out,
            "dag_gc_seconds",
            "Full collection wall time in seconds.",
            &self.gc_seconds,
        );

        counter(
            &mut out,
            "dag_sync_chunks_received_total",
            "Chunks accepted as a sync destination.",
            self.sync_chunks_received_total.get(),
        );
        counter(
            &mut out,
            "dag_sync_bytes_received_total",
            "Bytes in chunks accepted as a sync destination.",
            self.sync_bytes_received_total.get(),
        );
        counter(
            &mut out,
            "dag_sync_events_imported_total",
            "Event mappings filed after validation.",
            self.sync_events_imported_total.get(),
        );
        counter(
            &mut out,
            "dag_sync_events_refused_total",
            "Event mappings refused by validation - the trust boundary holding.",
            self.sync_events_refused_total.get(),
        );

        labeled_counters(
            &mut out,
            "dag_events_total",
            "Events emitted, by kind.",
            "kind",
            &EVENT_KINDS,
            &self.events_total,
        );
        labeled_counters(
            &mut out,
            "dag_job_runs_total",
            "Job runs reaching each status.",
            "status",
            &JOB_STATUSES,
            &self.job_runs_total,
        );

        out
    }
}

/// One `# HELP`/`# TYPE` header pair.
fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push_str("\n# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    header(out, name, help, "counter");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// A gauge line with its headers — for scrape-time values (store shape,
/// journal position) whose source of truth lives outside the registry.
pub fn gauge(out: &mut String, name: &str, help: &str, value: f64) {
    header(out, name, help, "gauge");
    out.push_str(name);
    out.push(' ');
    // Integers render without a fraction; Prometheus accepts both.
    if value.fract() == 0.0 && value.abs() < 1e15 {
        out.push_str(&format!("{}", value as i64));
    } else {
        out.push_str(&format!("{}", value));
    }
    out.push('\n');
}

fn labeled_counters(
    out: &mut String,
    name: &str,
    help: &str,
    label: &str,
    values: &[&str],
    counters: &[Counter],
) {
    header(out, name, help, "counter");
    for (value, cell) in values.iter().zip(counters) {
        out.push_str(name);
        out.push('{');
        out.push_str(label);
        out.push_str("=\"");
        out.push_str(value);
        out.push_str("\"} ");
        out.push_str(&cell.get().to_string());
        out.push('\n');
    }
}

/// Render one histogram as its own exposition-format block — for histograms
/// owned outside the registry (the HTTP layer keeps its own).
pub fn render_histogram(name: &str, help: &str, h: &Histogram) -> String {
    let mut out = String::new();
    histogram(&mut out, name, help, h);
    out
}

fn histogram(out: &mut String, name: &str, help: &str, h: &Histogram) {
    header(out, name, help, "histogram");
    let cumulative = h.cumulative();
    for (bound, count) in DURATION_BUCKETS.iter().zip(cumulative) {
        out.push_str(name);
        out.push_str("_bucket{le=\"");
        out.push_str(&format!("{}", bound));
        out.push_str("\"} ");
        out.push_str(&count.to_string());
        out.push('\n');
    }
    let total = h.count.load(Ordering::Relaxed);
    out.push_str(name);
    out.push_str("_bucket{le=\"+Inf\"} ");
    out.push_str(&total.to_string());
    out.push('\n');
    out.push_str(name);
    out.push_str("_sum ");
    out.push_str(&format!(
        "{}",
        h.sum_micros.load(Ordering::Relaxed) as f64 / 1e6
    ));
    out.push('\n');
    out.push_str(name);
    out.push_str("_count ");
    out.push_str(&total.to_string());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn counters_accumulate_and_render_with_headers() {
        let m = Metrics::default();
        m.store_put_total.inc();
        m.store_put_total.add(2);
        m.store_put_bytes_total.add(1024);

        let text = m.render();
        assert!(text.contains("# HELP dag_store_put_total "), "{text}");
        assert!(text.contains("# TYPE dag_store_put_total counter"));
        assert!(text.contains("\ndag_store_put_total 3\n"), "{text}");
        assert!(text.contains("\ndag_store_put_bytes_total 1024\n"));
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_end_at_inf() {
        let m = Metrics::default();
        m.store_put_seconds.observe(Duration::from_micros(500)); // fits 0.001
        m.store_put_seconds.observe(Duration::from_millis(30)); // fits 0.05
        m.store_put_seconds.observe(Duration::from_secs(60)); // only +Inf

        let text = m.render();
        assert!(
            text.contains("dag_store_put_seconds_bucket{le=\"0.001\"} 1"),
            "{text}"
        );
        // Cumulative: the 30 ms observation joins the half-millisecond one.
        assert!(text.contains("dag_store_put_seconds_bucket{le=\"0.05\"} 2"));
        assert!(text.contains("dag_store_put_seconds_bucket{le=\"10\"} 2"));
        // The over-range observation appears only in +Inf and the count.
        assert!(text.contains("dag_store_put_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(text.contains("dag_store_put_seconds_count 3"));
        // Sum in seconds: 0.0005 + 0.03 + 60.
        assert!(text.contains("dag_store_put_seconds_sum 60.0305"), "{text}");
    }

    #[test]
    fn labeled_series_render_one_line_per_known_value() {
        let m = Metrics::default();
        m.event_counter("pointer").unwrap().inc();
        m.event_counter("pointer").unwrap().inc();
        m.job_status_counter("succeeded").unwrap().inc();

        let text = m.render();
        assert!(
            text.contains("dag_events_total{kind=\"pointer\"} 2"),
            "{text}"
        );
        assert!(text.contains("dag_events_total{kind=\"pin\"} 0"));
        assert!(text.contains("dag_job_runs_total{status=\"succeeded\"} 1"));
        assert!(text.contains("dag_job_runs_total{status=\"failed\"} 0"));
    }

    #[test]
    fn unknown_labels_are_refused_not_invented() {
        // The set of series is closed by design; an unknown kind cannot mint
        // a new one at runtime.
        let m = Metrics::default();
        assert!(m.event_counter("surprise").is_none());
        assert!(m.job_status_counter("exploded").is_none());
    }

    #[test]
    fn timed_passes_the_result_through_and_observes_once() {
        let m = Metrics::default();
        let answer = timed(&m.store_get_seconds, || 41 + 1);
        assert_eq!(answer, 42);
        assert_eq!(m.store_get_seconds.count(), 1);
    }

    #[test]
    fn gauge_lines_render_integers_without_a_fraction() {
        let mut out = String::new();
        gauge(&mut out, "dag_store_chunks", "Chunks held.", 7.0);
        gauge(&mut out, "dag_ratio", "A ratio.", 0.5);
        assert!(out.contains("\ndag_store_chunks 7\n"), "{out}");
        assert!(out.contains("\ndag_ratio 0.5\n"), "{out}");
        assert!(out.contains("# TYPE dag_store_chunks gauge"));
    }

    #[test]
    fn every_line_is_well_formed_exposition_text() {
        // The whole render must parse line-by-line as either a comment or a
        // `name[{labels}] value` sample — the contract a scraper depends on.
        let m = Metrics::default();
        m.store_put_seconds.observe(Duration::from_millis(3));
        m.event_counter("job").unwrap().inc();

        for line in m.render().lines() {
            if let Some(rest) = line.strip_prefix("# ") {
                assert!(
                    rest.starts_with("HELP ") || rest.starts_with("TYPE "),
                    "bad comment: {line}"
                );
                continue;
            }
            let (series, value) = line.rsplit_once(' ').expect(line);
            assert!(!series.is_empty(), "{line}");
            assert!(
                value.parse::<f64>().is_ok() || value == "+Inf",
                "unparseable value in: {line}"
            );
        }
    }
}
