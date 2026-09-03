//! What a hostile web page can do to a `dag serve` on localhost.
//!
//! The server has no authentication by design (it binds loopback and warns
//! loudly otherwise), which makes the browser's own origin controls the entire
//! defence. These tests pin that defence down: a page on another origin gets
//! no read access and no state change, an operator can opt in to specific
//! origins, and content uploaded by one user cannot execute as script in the
//! console's origin when another downloads it.

use anyhow::Result;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use dag_control::test_utils::TestControl;
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

const EVIL: &str = "https://evil.example";
const FRIEND: &str = "https://console.example";

fn harness_with(options: &dag_api::ServerOptions) -> Result<(TestControl, axum::Router)> {
    let tc = TestControl::new()?;
    let control = Arc::new(dag_control::Control::open(&tc.path().join("api"))?);
    Ok((tc, dag_api::router_with(control, options)))
}

fn harness() -> Result<(TestControl, axum::Router)> {
    harness_with(&dag_api::ServerOptions::new())
}

/// What a browser sends for a cross-origin `fetch` from a page on `origin`.
fn cross_site(method: &str, uri: &str, origin: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ORIGIN, origin)
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "cors")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

/// What the browser sends for the CORS preflight that precedes it.
fn preflight(uri: &str, origin: &str) -> Request<Body> {
    Request::builder()
        .method("OPTIONS")
        .uri(uri)
        .header(header::ORIGIN, origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "cors")
        .body(Body::empty())
        .unwrap()
}

/// The console's own request: same origin, so nothing here may be affected.
fn same_origin(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::ORIGIN, "http://127.0.0.1:8080")
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Seed a real target through the same API surface the browser tests exercise.
/// Pointer and pin publication deliberately refuses dangling CIDs, so a
/// computed-but-unwritten hash is not a valid success fixture.
async fn store_chunk(app: &axum::Router, bytes: &'static [u8]) -> Result<String> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/chunks")
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    Ok(body["cid"]
        .as_str()
        .expect("chunk response has a CID")
        .to_string())
}

/// The reproduction: `CorsLayer::permissive()` answered the preflight, so the
/// mutation went through *and* the reply was readable by the attacking page.
#[tokio::test]
async fn a_hostile_origin_is_granted_nothing_by_default() -> Result<()> {
    let (_tc, app) = harness()?;

    let response = app
        .clone()
        .oneshot(preflight("/api/pointers", EVIL))
        .await?;
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "the preflight must not be approved: {:?}",
        response.headers()
    );

    // Even if the browser skipped the preflight, the request itself must not
    // change state and its body must not be readable cross-origin.
    let response = app
        .clone()
        .oneshot(cross_site("POST", "/api/pointers", EVIL))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());

    // Reads are refused for the same reason: no grant, and nothing to read.
    let response = app
        .clone()
        .oneshot(cross_site("GET", "/api/stats", EVIL))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // The destructive collection endpoint, specifically. Full recovery is an
    // offline CLI operation and is not mounted on this router.
    for uri in ["/api/gc/run"] {
        let response = app.clone().oneshot(cross_site("POST", uri, EVIL)).await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{} must not be reachable from another origin",
            uri
        );
    }
    Ok(())
}

/// The console must keep working, and so must every non-browser client — curl,
/// the CLI, any HTTP library — none of which send `Sec-Fetch-Site` at all.
#[tokio::test]
async fn the_console_and_plain_http_clients_are_unaffected() -> Result<()> {
    let (_tc, app) = harness()?;

    let cid = store_chunk(&app, b"x").await?;
    let response = app
        .clone()
        .oneshot(same_origin(
            "POST",
            "/api/pointers",
            serde_json::json!({ "id": "p", "cid": cid }),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "same-origin must work");

    // No Sec-Fetch-Site header at all: not a browser, not our problem.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // A user typing the URL or following a bookmark: `none`, not cross-site.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .header("sec-fetch-site", "none")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

/// Fetch Metadata is excellent browser evidence, but its absence is not a
/// licence to ignore an `Origin` the caller did provide. Some embedded agents
/// and older browser stacks send Origin without `Sec-Fetch-Site`.
#[tokio::test]
async fn an_explicit_foreign_origin_is_refused_when_fetch_metadata_is_absent() -> Result<()> {
    let (_tc, app) = harness()?;

    let foreign = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .header(header::HOST, "127.0.0.1:8080")
                .header(header::ORIGIN, EVIL)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

    let local = app
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .header(header::HOST, "127.0.0.1:8080")
                .header(header::ORIGIN, "http://127.0.0.1:8080")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(local.status(), StatusCode::OK);
    Ok(())
}

/// DNS rebinding keeps the browser's origin tuple unchanged while changing
/// where the hostname resolves. `Sec-Fetch-Site` is therefore truthfully
/// `same-origin`; the hostile Host authority is the remaining observable.
#[tokio::test]
async fn a_rebound_hostname_cannot_reach_the_loopback_control_plane() -> Result<()> {
    let (_tc, app) = harness()?;

    let rebound = Request::builder()
        .uri("/api/gc/run")
        .method("POST")
        .header(header::HOST, "attacker.example:8080")
        .header(header::ORIGIN, "http://attacker.example:8080")
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))?;
    let response = app.clone().oneshot(rebound).await?;
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);

    for host in [
        "localhost:8080",
        "localhost.:8080",
        "127.0.0.1:8080",
        "[::1]:8080",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .header(header::HOST, host)
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{host} must remain usable"
        );
    }
    Ok(())
}

#[tokio::test]
async fn expose_control_leaves_public_authority_policy_to_the_proxy() -> Result<()> {
    let options = dag_api::ServerOptions::new().expose_control();
    let (_tc, app) = harness_with(&options)?;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .header(header::HOST, "dag.internal.example")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

/// Embedding is available, but only as an explicit operator decision, and only
/// for the origins named — never `*`.
#[tokio::test]
async fn an_allow_listed_origin_is_granted_and_only_it() -> Result<()> {
    let options = dag_api::ServerOptions::allow_origins([FRIEND])?;
    let (_tc, app) = harness_with(&options)?;

    let response = app
        .clone()
        .oneshot(preflight("/api/pointers", FRIEND))
        .await?;
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some(FRIEND),
        "an allow-listed origin is echoed exactly, never as `*`"
    );

    let cid = store_chunk(&app, b"y").await?;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pointers")
                .header(header::ORIGIN, FRIEND)
                .header("sec-fetch-site", "cross-site")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "id": "q", "cid": cid }).to_string(),
                ))
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // Everyone else is exactly as unwelcome as before.
    let response = app
        .clone()
        .oneshot(preflight("/api/pointers", EVIL))
        .await?;
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    let response = app
        .oneshot(cross_site("POST", "/api/pointers", EVIL))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

/// `*` is the defect being fixed; it must not be expressible as an allow-list
/// entry either, and nor must a value that could not be an origin.
#[tokio::test]
async fn a_wildcard_is_not_an_allowable_origin() -> Result<()> {
    assert!(dag_api::ServerOptions::allow_origins(["*"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["console.example"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["https://a.example/path"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["https://a.example\r\nX: y"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["ftp://a.example"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["https://user@a.example"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["https://a.example?grant=yes"]).is_err());
    assert!(dag_api::ServerOptions::allow_origins(["https://a.example"]).is_ok());

    let normalized = dag_api::ServerOptions::allow_origins(["HTTPS://A.EXAMPLE:443"])?;
    assert_eq!(normalized.allowed_origins()[0], "https://a.example");
    Ok(())
}

#[tokio::test]
async fn baseline_security_headers_are_set_everywhere() -> Result<()> {
    let (_tc, app) = harness()?;

    for uri in ["/", "/app.css", "/js/main.js", "/api/health"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await?;
        let headers = response.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "{} is missing nosniff",
            uri
        );
        assert_eq!(
            headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY"),
            "{} is framable",
            uri
        );
        let csp = headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| panic!("{} has no CSP", uri));
        assert!(csp.contains("frame-ancestors 'none'"), "{}: {}", uri, csp);
        assert!(
            csp.contains("script-src 'self'") && !csp.contains("script-src 'self' 'unsafe-inline'"),
            "inline script must stay blocked: {}",
            csp
        );
    }
    Ok(())
}

/// The policy has to permit what the console actually is: external ES modules
/// and stylesheet from this origin, inline `style="…"` attributes, a `data:`
/// favicon, and same-origin `fetch`/`EventSource`. A CSP that broke the
/// console would be reverted the first time anyone loaded it.
#[tokio::test]
async fn the_policy_permits_the_console_it_ships_with() -> Result<()> {
    let (_tc, app) = harness()?;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await?;
    let csp = response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();

    for directive in [
        "script-src 'self'",                // /js/*.js are external modules
        "style-src 'self' 'unsafe-inline'", // ui.ts and graph.ts set style="…"
        "img-src 'self' data:",             // the inline SVG favicon
        "connect-src 'self'",               // fetch + EventSource
    ] {
        assert!(
            csp.contains(directive),
            "CSP lacks {:?}: {}",
            directive,
            csp
        );
    }
    Ok(())
}

/// Split a CSP header into `(directive, sources)` pairs, sources already
/// whitespace-split. Directive names are lower-cased; the CSP grammar makes
/// them case-insensitive but our policy writes them lower-case, so a rename
/// would still be caught by the membership assertions below.
fn csp_directives(csp: &str) -> std::collections::HashMap<String, Vec<String>> {
    csp.split(';')
        .filter_map(|d| {
            let mut parts = d.split_whitespace();
            let name = parts.next()?.to_ascii_lowercase();
            Some((name, parts.map(str::to_string).collect()))
        })
        .collect()
}

/// The whole policy, directive by directive, so any future weakening is a test
/// failure rather than a silent regression. This is the counterpart to
/// [`the_policy_permits_the_console_it_ships_with`]: that one guards the
/// concessions the console needs, this one guards the restrictions that make
/// the concessions safe.
#[tokio::test]
async fn the_csp_locks_every_directive_it_declares() -> Result<()> {
    let (_tc, app) = harness()?;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await?;
    let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()?
        .to_string();
    let directives = csp_directives(&csp);

    let sources = |name: &str| -> Vec<String> { directives.get(name).cloned().unwrap_or_default() };
    let assert_exact = |name: &str, expected: &[&str]| {
        assert_eq!(
            sources(name),
            expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "directive {:?} drifted in CSP: {}",
            name,
            csp
        );
    };

    // The restrictive half of the policy, exact-matched. A stray addition (a
    // wildcard, an external host, an `'unsafe-*'`) is a mismatch.
    assert_exact("default-src", &["'self'"]);
    assert_exact("object-src", &["'none'"]);
    assert_exact("base-uri", &["'none'"]);
    assert_exact("frame-ancestors", &["'none'"]);
    assert_exact("form-action", &["'self'"]);
    assert_exact("font-src", &["'self'"]);

    // Script is the directive an attacker most wants to loosen. It must be
    // exactly `'self'`: no `'unsafe-inline'` (which would re-enable stored
    // `<script>`/`onerror=`), no `'unsafe-eval'`, no `data:` (a script: data
    // URL is executable), no wildcard, no external host.
    assert_exact("script-src", &["'self'"]);

    // Style and images carry exactly the two concessions the console needs and
    // nothing more.
    assert_exact("style-src", &["'self'", "'unsafe-inline'"]);
    assert_exact("img-src", &["'self'", "data:"]);

    // Connect governs fetch and the EventSource stream; same-origin only.
    assert_exact("connect-src", &["'self'"]);

    // Nothing anywhere may name a wildcard source.
    assert!(
        !csp.contains('*'),
        "no CSP source may be a wildcard: {}",
        csp
    );
    Ok(())
}

/// The console HTML actually served must not contain anything this CSP forbids:
/// no inline `<script>` and no inline event handler, both of which
/// `script-src 'self'` (without `'unsafe-inline'`) would block. This is the
/// static half of the check the comment on the policy promises — a real
/// browser is still the only thing that proves the console *renders*, but this
/// catches the specific asset changes that would make it stop.
#[tokio::test]
async fn the_served_console_html_needs_nothing_the_csp_forbids() -> Result<()> {
    let (_tc, app) = harness()?;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await?;
    let html = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    let lower = html.to_ascii_lowercase();

    // Every <script> must have a src (external module), never inline body.
    for (i, _) in lower.match_indices("<script") {
        let tag_end = lower[i..].find('>').map(|e| i + e).unwrap_or(lower.len());
        let tag = &lower[i..tag_end];
        assert!(
            tag.contains("src="),
            "inline <script> would be blocked by script-src 'self': {}",
            tag
        );
    }

    // No inline event handlers: they are inline script under CSP.
    for handler in [
        "onclick=",
        "onload=",
        "onerror=",
        "onmouseover=",
        "onsubmit=",
    ] {
        assert!(
            !lower.contains(handler),
            "inline handler {:?} would be blocked by script-src 'self'",
            handler
        );
    }
    Ok(())
}

/// Stored XSS: the download endpoint used the *uploader's* declared content
/// type verbatim, so a `<script>` payload declared `text/html` executed on the
/// console's own origin when anyone opened it.
#[tokio::test]
async fn an_uploaded_payload_cannot_choose_to_be_html() -> Result<()> {
    let (_tc, app) = harness()?;

    let payload = b"<script>fetch('/api/gc/run',{method:'POST'})</script>";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                // `chunked` forces the manifest form, which is what records a
                // declared content type.
                .uri("/api/files?content_type=text/html&chunked=true")
                .body(Body::from(payload.to_vec()))
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        body["chunked"], true,
        "the declared type is only recorded on a manifest, so this test is \
         only meaningful if one was written"
    );
    let cid = body["cid"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/files?cid={}", cid))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()?
        .to_string();
    assert!(
        !content_type.contains("html"),
        "an uploader must not be able to pick an executable type, got {:?}",
        content_type
    );
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("attachment"),
        "downloads must not render in the console's origin"
    );
    assert_eq!(
        response.headers()["x-content-type-options"].to_str()?,
        "nosniff",
        "octet-stream is only safe if the browser is told not to sniff"
    );

    // The bytes themselves are untouched: this is a serving decision.
    let served = response.into_body().collect().await?.to_bytes();
    assert_eq!(served.as_ref(), payload);
    Ok(())
}

/// An inert declared type is still useful to the caller, so it survives — but
/// only as the canonical constant, never as the uploader's string.
#[tokio::test]
async fn inert_declared_types_survive_normalised() -> Result<()> {
    let (_tc, app) = harness()?;

    for (declared, expected) in [
        ("application/json", "application/json"),
        // Parameters are dropped rather than echoed.
        ("text/plain;charset=iso-8859-1", "text/plain"),
        // SVG is a script host, so it is not inert.
        ("image/svg+xml", "application/octet-stream"),
        ("image/png", "image/png"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/api/files?chunked=true&content_type={}",
                        urlencode(declared)
                    ))
                    .body(Body::from(format!("payload for {}", declared)))
                    .unwrap(),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "upload {}", declared);
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        assert_eq!(
            body["chunked"], true,
            "upload {} took the wrong path",
            declared
        );
        let cid = body["cid"].as_str().unwrap().to_string();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/files?cid={}", cid))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE].to_str()?,
            expected,
            "declared {:?}",
            declared
        );
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// `now_unix() + ttl` with no check: in debug this panicked a worker, and in
/// release — where `overflow-checks` was off — it wrapped, so the API returned
/// 200, `/api/pins` called the pin Active and `/api/gc/status` reported its
/// target unprotected. Three surfaces disagreeing about one pin.
#[tokio::test]
async fn a_pin_ttl_that_cannot_be_represented_is_refused() -> Result<()> {
    let (_tc, app) = harness()?;

    let cid = dag_core::Cid::compute(b"pin me").to_hex();
    for ttl in [i64::MAX, i64::MIN, -1] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/pins")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "id": format!("overflow-{}", ttl),
                            "cid": cid,
                            "ttl_secs": ttl,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "ttl_secs {} must be refused",
            ttl
        );
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        assert!(
            body["error"].as_str().unwrap().contains("ttl_secs"),
            "the error should name the offending field: {}",
            body
        );
    }

    // Nothing was recorded for any of them.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/pins")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    let pins: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert!(pins["items"].as_array().unwrap().is_empty(), "got {}", pins);
    Ok(())
}

/// A TTL that *is* representable still works, so the check has not simply
/// broken the feature.
#[tokio::test]
async fn an_ordinary_ttl_still_creates_an_expiring_pin() -> Result<()> {
    let (_tc, app) = harness()?;

    let cid = store_chunk(&app, b"pin me").await?;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/pins")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "id": "ttl-ok", "cid": cid, "ttl_secs": 3600 }).to_string(),
                ))
                .unwrap(),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert!(body["expires_at"].as_i64().unwrap() > dag_control::now_unix());
    Ok(())
}

/// A `GET /api/stats` carrying exactly one `Sec-Fetch-Site` value, and nothing
/// else that would sway the guard. State-changing routes are exercised
/// separately; `/api/stats` is a pure read, so its status reflects the guard
/// alone.
fn with_sec_fetch_site(value: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri("/api/stats");
    if let Some(value) = value {
        builder = builder.header("sec-fetch-site", value);
    }
    builder.body(Body::empty()).unwrap()
}

/// Every `Sec-Fetch-Site` value pinned to a verdict, so the guard's contract is
/// legible in one place and a future edit that flips any case is caught.
///
/// The load-bearing decisions:
///
/// * **absent** is allowed when `Origin` is also absent (curl, the CLI, an
///   HTTP library), or when an explicit Origin matches the request authority.
///   A foreign Origin is refused even without Fetch Metadata.
/// * **`same-origin`** and **`none`** are allowed: the console calling its own
///   API, and a human navigating to the URL, respectively.
/// * **`cross-site`** and **`same-site`** are refused. `same-site` matters as
///   much as `cross-site` here: on a shared localhost another origin on the
///   same registrable domain (a different port, a sibling dev server) is *not*
///   the console, and this API has no authentication to fall back on.
/// * an **unrecognised** value is refused, not allowed. A security guard in
///   front of an unauthenticated API must fail closed; a browser will only ever
///   send one of the four defined tokens, so nothing legitimate is lost.
#[tokio::test]
async fn every_sec_fetch_site_value_has_a_pinned_verdict() -> Result<()> {
    let (_tc, app) = harness()?;

    let allowed = [None, Some("same-origin"), Some("none")];
    let refused = [
        Some("cross-site"),
        Some("same-site"),
        // Values a real browser never sends, so a fail-closed guard refuses
        // them; a fail-open deny-list would wave them through.
        Some("garbage"),
        Some(""),
        Some("SAME-ORIGIN"),
        Some("cross-site, same-origin"),
    ];

    for value in allowed {
        let response = app.clone().oneshot(with_sec_fetch_site(value)).await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Sec-Fetch-Site {:?} must be allowed",
            value
        );
    }

    for value in refused {
        let response = app.clone().oneshot(with_sec_fetch_site(value)).await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Sec-Fetch-Site {:?} must be refused",
            value
        );
    }
    Ok(())
}

/// A header that is *present but not text* is not the same as one that is
/// absent, and the guard used to fold the two together: `.to_str().ok()`
/// turned unreadable bytes into `None`, which is the trusted case. A caller
/// could opt out of the guard by sending bytes instead of a value.
#[tokio::test]
async fn a_sec_fetch_site_that_is_not_text_is_refused() -> Result<()> {
    let (_tc, app) = harness()?;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .header(
                    "sec-fetch-site",
                    header::HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await?;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an unreadable Sec-Fetch-Site read as 'absent', which is the one \
         value that is trusted without a grant"
    );
    Ok(())
}

/// The guard is a middleware layer over the whole `/api` router, so coverage is
/// structural rather than per-handler. This enumerates every mutating route and
/// asserts a cross-site request to each is refused — a route added later
/// without the guard could only escape this by being mounted outside `/api`,
/// which the test also documents as the invariant to keep.
#[tokio::test]
async fn every_mutating_api_route_refuses_a_cross_site_request() -> Result<()> {
    let (_tc, app) = harness()?;

    // Every POST/PUT/DELETE route under /api. Kept in sync by hand because the
    // router does not expose its table; the assertion below is the thing that
    // makes a drift here visible.
    let mutating = [
        "/api/chunks",
        "/api/files",
        "/api/pointers",
        "/api/pins",
        "/api/pins/deactivate",
        "/api/jobs/run",
        "/api/gc/run",
        "/api/usecase/seed",
    ];

    for uri in mutating {
        let response = app.clone().oneshot(cross_site("POST", uri, EVIL)).await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{} accepted a cross-site request — is it mounted outside /api, \
             or added without the guard?",
            uri
        );
        // And the reply is not readable cross-origin either: no CORS grant.
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "{} leaked an Access-Control-Allow-Origin",
            uri
        );
    }
    Ok(())
}
