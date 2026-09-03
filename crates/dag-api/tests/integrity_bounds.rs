//! Integrity diagnostics remain honest when the complete invalid set is large.

use std::sync::Arc;

use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dag_control::test_utils::TestControl;
use dag_core::Cid;
use dag_storage::ChunkLocation;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn integrity_response_declares_truncated_diagnostics_but_keeps_full_counts() -> Result<()> {
    let tc = TestControl::new()?;
    let index = tc
        .control
        .store
        .get_index()
        .expect("test store has an index");
    let rows = dag_storage::integrity::MAX_INTEGRITY_REPORTS + 3;
    let entries = (0..rows)
        .map(|number| {
            let cid = Cid::compute(&number.to_be_bytes());
            let location = ChunkLocation {
                path: format!("/missing/{cid}"),
                length: 1,
                sha256_hash: cid.to_hex(),
            };
            (cid, location)
        })
        .collect::<Vec<_>>();
    index.insert_many(&entries)?;

    let app = dag_api::router(Arc::new(tc.control));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/integrity")
                .header("host", "localhost")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;

    assert_eq!(json["total_chunks"], rows);
    assert_eq!(json["invalid_chunks"], rows);
    assert_eq!(json["invalid_report_limit"], 1_024);
    assert_eq!(json["invalid_reports_truncated"], true);
    assert_eq!(
        json["invalid"]
            .as_array()
            .expect("invalid diagnostics")
            .len(),
        dag_storage::integrity::MAX_INTEGRITY_REPORTS
    );
    Ok(())
}
