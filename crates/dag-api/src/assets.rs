//! The web console, embedded in the binary.
//!
//! The console is written in TypeScript and compiled by `tsc` alone — no
//! bundler, no runtime dependencies. The emitted ES modules are committed
//! under `web/dist/`, so `cargo build` never needs Node installed; CI
//! recompiles them and fails if the checked-in output has drifted from the
//! source. `include_str!` then makes `dag serve` a single self-contained
//! binary with nothing to deploy alongside it.

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_CSS: &str = include_str!("../web/app.css");

/// Compiled console modules, served under `/js/`.
///
/// The emitted modules import each other by relative specifier (`./api.js`),
/// so they must all be reachable from the same path prefix.
const MODULES: &[(&str, &str)] = &[
    ("api.js", include_str!("../web/dist/api.js")),
    ("drawer.js", include_str!("../web/dist/drawer.js")),
    ("feed.js", include_str!("../web/dist/feed.js")),
    ("format.js", include_str!("../web/dist/format.js")),
    ("graph.js", include_str!("../web/dist/graph.js")),
    ("main.js", include_str!("../web/dist/main.js")),
    ("types.js", include_str!("../web/dist/types.js")),
    ("ui.js", include_str!("../web/dist/ui.js")),
    ("views.js", include_str!("../web/dist/views.js")),
];

/// Routes serving the console.
pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/js/{file}", get(module))
        // The console is a single page with hash-based views, but a stray deep
        // link should still land somewhere useful rather than 404.
        .fallback(get(index))
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS).into_response()
}

async fn module(axum::extract::Path(file): axum::extract::Path<String>) -> Response {
    match MODULES.iter().find(|(name, _)| *name == file) {
        Some((_, source)) => (
            [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
            *source,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no such module").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_module_imported_by_another_is_served() {
        // A missing entry here would only show up as a blank page in a
        // browser, so check the import graph closes over what we serve.
        for (name, source) in MODULES {
            for line in source.lines().filter(|l| l.contains("from './")) {
                let Some(start) = line.find("from './") else {
                    continue;
                };
                let rest = &line[start + "from './".len()..];
                let Some(end) = rest.find('\'') else { continue };
                let target = &rest[..end];
                assert!(
                    MODULES.iter().any(|(n, _)| n == &target),
                    "{} imports {}, which is not embedded",
                    name,
                    target
                );
            }
        }
    }

    #[test]
    fn index_loads_the_entry_module() {
        assert!(
            INDEX_HTML.contains("/js/main.js"),
            "index.html must load the compiled entry point"
        );
    }
}
