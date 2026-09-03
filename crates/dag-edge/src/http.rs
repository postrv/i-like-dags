//! Minimal native HTTP fixture for `HttpDestination` transport smoke tests.
//!
//! This module is available only with the crate's explicit `test-harness`
//! feature. It is not the Cloudflare Worker, does not implement the current
//! staged-session/atomic-publication contract, and must never be used as a
//! server or as Worker security evidence.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use dag_core::{Cid, ContentStore, ReplicaError, MAX_CHUNK_SIZE};
use serde::{Deserialize, Serialize};

use crate::auth::{bearer, token_matches};
use crate::EdgeReplica;

/// Body limit slightly above [`MAX_CHUNK_SIZE`] so a merely-oversized
/// PUT still reaches the structured 413.
const CHUNK_BODY_LIMIT: usize = MAX_CHUNK_SIZE + 64 * 1024;

/// Same batch ceiling the laptop engine uses.
pub const MISSING_BATCH: usize = 4096;

/// Router implementing the ADR-007 surface.
pub fn router(replica: Arc<EdgeReplica>) -> Router {
    Router::new()
        .route("/c/{cid}", get(get_chunk).put(put_chunk))
        .route("/sync/missing", post(missing))
        .route("/sync/flush", post(flush))
        .route("/sync/import/pointer", post(import_pointer))
        .route("/sync/import/pin", post(import_pin))
        .route("/sync/finalize", post(finalize))
        .route("/pointers", post(cas_pointer))
        .layer(axum::extract::DefaultBodyLimit::max(CHUNK_BODY_LIMIT))
        .with_state(replica)
}

fn require_token(replica: &EdgeReplica, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let offered = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer)
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    if token_matches(replica.token(), offered) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "invalid token".into()))
    }
}

fn parse_cid(hex: &str) -> Result<Cid, (StatusCode, String)> {
    Cid::from_hex(hex).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

async fn get_chunk(
    State(replica): State<Arc<EdgeReplica>>,
    Path(cid_hex): Path<String>,
) -> Result<Bytes, (StatusCode, String)> {
    let cid = parse_cid(&cid_hex)?;
    match replica.store().get_chunk(&cid) {
        Ok(bytes) => Ok(Bytes::from(bytes)),
        Err(dag_core::CoreError::ChunkNotFound(_)) => {
            Err((StatusCode::NOT_FOUND, "chunk not found".into()))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn put_chunk(
    State(replica): State<Arc<EdgeReplica>>,
    Path(cid_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    if body.len() > MAX_CHUNK_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("chunk exceeds {MAX_CHUNK_SIZE} bytes"),
        ));
    }
    let cid = parse_cid(&cid_hex)?;
    replica
        .log
        .store_chunk(&cid, &body)
        .map_err(replica_status)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct MissingRequest {
    cids: Vec<String>,
}

#[derive(Serialize)]
struct MissingResponse {
    missing: Vec<String>,
}

async fn missing(
    State(replica): State<Arc<EdgeReplica>>,
    headers: HeaderMap,
    Json(body): Json<MissingRequest>,
) -> Result<Json<MissingResponse>, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    if body.cids.len() > MISSING_BATCH {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("missing batch exceeds {MISSING_BATCH}"),
        ));
    }
    let mut asked = Vec::with_capacity(body.cids.len());
    for hex in &body.cids {
        asked.push(parse_cid(hex)?);
    }
    let missing = replica.log.missing(&asked).map_err(replica_status)?;
    Ok(Json(MissingResponse {
        missing: missing.iter().map(|c| c.to_hex()).collect(),
    }))
}

async fn flush(
    State(replica): State<Arc<EdgeReplica>>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    replica
        .store()
        .sync()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ImportRequest {
    id: String,
    seq: u64,
    cid: String,
}

#[derive(Serialize)]
struct ImportResponse {
    filed: bool,
}

async fn import_pointer(
    State(replica): State<Arc<EdgeReplica>>,
    headers: HeaderMap,
    Json(body): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    let cid = parse_cid(&body.cid)?;
    let filed = replica
        .log
        .import_pointer(&body.id, body.seq, &cid)
        .map_err(replica_status)?;
    Ok(Json(ImportResponse { filed }))
}

async fn import_pin(
    State(replica): State<Arc<EdgeReplica>>,
    headers: HeaderMap,
    Json(body): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    let cid = parse_cid(&body.cid)?;
    let filed = replica
        .log
        .import_pin(&body.id, body.seq, &cid)
        .map_err(replica_status)?;
    Ok(Json(ImportResponse { filed }))
}

#[derive(Serialize)]
struct FinalizeResponse {
    pointers: u32,
    pins: u32,
    signatures: u32,
    claims: u32,
}

async fn finalize(
    State(replica): State<Arc<EdgeReplica>>,
    headers: HeaderMap,
) -> Result<Json<FinalizeResponse>, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    let (pointers, pins) = replica.finalize();
    Ok(Json(FinalizeResponse {
        pointers,
        pins,
        signatures: 0,
        claims: 0,
    }))
}

#[derive(Deserialize)]
struct CasRequest {
    id: String,
    cid: String,
    expect_seq: u64,
}

#[derive(Serialize)]
struct CasResponse {
    seq: u64,
}

async fn cas_pointer(
    State(replica): State<Arc<EdgeReplica>>,
    headers: HeaderMap,
    Json(body): Json<CasRequest>,
) -> Result<Json<CasResponse>, (StatusCode, String)> {
    require_token(&replica, &headers)?;
    let cid = parse_cid(&body.cid)?;
    let ts = now_unix();
    let seq = replica
        .log
        .update_cas(&body.id, cid, body.expect_seq, ts)
        .map_err(replica_status)?;
    Ok(Json(CasResponse { seq }))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn replica_status(err: ReplicaError) -> (StatusCode, String) {
    match err {
        ReplicaError::Offer(e) => (StatusCode::CONFLICT, e.to_string()),
        ReplicaError::CasConflict { .. } => (StatusCode::PRECONDITION_FAILED, err.to_string()),
        ReplicaError::NotFound(id) => (StatusCode::NOT_FOUND, id),
        ReplicaError::InvalidId(msg) => (StatusCode::BAD_REQUEST, msg),
        ReplicaError::Core(dag_core::CoreError::ChunkTooLarge { .. }) => {
            (StatusCode::PAYLOAD_TOO_LARGE, err.to_string())
        }
        ReplicaError::Core(dag_core::CoreError::CidMismatch { .. }) => {
            (StatusCode::BAD_REQUEST, err.to_string())
        }
        ReplicaError::Core(dag_core::CoreError::ChunkNotFound(_)) => {
            (StatusCode::NOT_FOUND, err.to_string())
        }
        ReplicaError::Core(e) => (StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EdgeReplica;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use dag_core::pin::{PinScope, PinState, PinTarget};
    use dag_core::{Entry, PinEvent, PointerEvent};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn replica() -> Arc<EdgeReplica> {
        EdgeReplica::memory("secret")
    }

    async fn call(
        app: Router,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Body,
    ) -> (StatusCode, Bytes) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if method == "POST" || method == "PUT" {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let req = builder.body(body).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, bytes)
    }

    #[tokio::test]
    async fn get_is_public_and_put_requires_the_token() {
        let replica = replica();
        let cid = replica.store().put_chunk(b"hello", None).unwrap();
        let app = router(replica.clone());
        let (status, body) = call(
            app.clone(),
            "GET",
            &format!("/c/{}", cid.to_hex()),
            None,
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"hello");

        let (status, _) = call(
            app.clone(),
            "PUT",
            &format!("/c/{}", Cid::compute(b"x").to_hex()),
            None,
            Body::from(b"x".to_vec()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = call(
            app,
            "PUT",
            &format!("/c/{}", Cid::compute(b"x").to_hex()),
            Some("wrong"),
            Body::from(b"x".to_vec()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn put_refuses_a_cid_mismatch() {
        let replica = replica();
        let app = router(replica);
        let name = Cid::compute(b"expected").to_hex();
        let (status, body) = call(
            app,
            "PUT",
            &format!("/c/{name}"),
            Some("secret"),
            Body::from(b"actual".to_vec()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            String::from_utf8_lossy(&body).contains("CID mismatch"),
            "{}",
            String::from_utf8_lossy(&body)
        );
    }

    #[tokio::test]
    async fn import_refuses_hostile_history() {
        let replica = replica();
        let app = router(replica.clone());
        let head = Cid::compute(b"head");
        let create = PointerEvent::create_event("p", head.clone(), 1);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&create, &mut buf).unwrap();
        let event_cid = replica
            .store()
            .put_entry(&Entry::with_payload(buf))
            .unwrap();

        let body = serde_json::json!({
            "id": "p",
            "seq": 1,
            "cid": event_cid.to_hex()
        })
        .to_string();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/sync/import/pointer",
            Some("secret"),
            Body::from(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let forged = PointerEvent::update_event("p", 2, Cid::compute(b"nope"), head, 2);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&forged, &mut buf).unwrap();
        let forged_cid = replica
            .store()
            .put_entry(&Entry::with_payload(buf))
            .unwrap();
        let body = serde_json::json!({
            "id": "p",
            "seq": 2,
            "cid": forged_cid.to_hex()
        })
        .to_string();
        let (status, bytes) = call(
            app,
            "POST",
            "/sync/import/pointer",
            Some("secret"),
            Body::from(body),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            String::from_utf8_lossy(&bytes).contains("breaks the chain"),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[tokio::test]
    async fn import_refuses_a_pin_deactivation_grafted_onto_another_create() {
        let replica = replica();
        let app = router(replica.clone());
        let target = Cid::compute(b"ours");
        let ours = PinEvent {
            seq: 1,
            pin_id: "keep".into(),
            target: PinTarget::Direct(target),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Active,
            ts: 1,
            author: None,
            prev: None,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ours, &mut buf).unwrap();
        let ours_cid = replica
            .store()
            .put_entry(&Entry::with_payload(buf))
            .unwrap();
        let (status, _) = call(
            app.clone(),
            "POST",
            "/sync/import/pin",
            Some("secret"),
            Body::from(
                serde_json::json!({"id":"keep","seq":1,"cid":ours_cid.to_hex()}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let theirs = PinEvent {
            seq: 2,
            pin_id: "keep".into(),
            target: PinTarget::Direct(Cid::compute(b"theirs")),
            scope: PinScope::Global,
            expires_at: None,
            state: PinState::Deactivated,
            ts: 2,
            author: None,
            prev: Some(Cid::compute(b"not-ours")),
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&theirs, &mut buf).unwrap();
        let theirs_cid = replica
            .store()
            .put_entry(&Entry::with_payload(buf))
            .unwrap();
        let (status, bytes) = call(
            app,
            "POST",
            "/sync/import/pin",
            Some("secret"),
            Body::from(
                serde_json::json!({"id":"keep","seq":2,"cid":theirs_cid.to_hex()}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            String::from_utf8_lossy(&bytes).contains("breaks the chain"),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
