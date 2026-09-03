//! Whole-file endpoints: bounded streaming upload and download.
//!
//! `/api/chunks` speaks in single chunks and keeps its 4 MiB ceiling; these
//! endpoints speak in *files*. An upload streams through the content-defined
//! chunker with memory bounded by the chunk size and manifest fan-out, and a
//! download streams the reassembly, re-hashing every chunk on the way out.
//! Neither buffers the file; both enforce the finite HTTP file policy below.
//!
//! ## The async↔sync seam
//!
//! The chunker is synchronous (`Read`/`Write`), and the control plane runs on
//! the blocking pool (see `crate::blocking`). Uploads bridge the request body
//! into a blocking `Read` with `SyncIoBridge`; downloads run `join` on the
//! blocking pool writing into a bounded channel that feeds the response body.
//! Backpressure and cancellation fall out of both: a slow or vanished client
//! stalls or closes the channel, which stalls or aborts the blocking task.

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::Response;
use axum::Json;
use dag_core::ContentStore;
use serde::Deserialize;
use tokio_stream::StreamExt;
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::blocking::{on_blocking_pool, on_content_response_pool};
use crate::error::{ApiError, ApiResult};
use crate::routes::{parse_cid, CidQuery};
use crate::AppState;

/// Maximum whole-file body accepted by the local HTTP control API (1 GiB).
///
/// `dag serve` is deliberately not an unbounded bulk-transfer service. The
/// limit is enforced both by request-body middleware and by the core splitter,
/// so chunked transfer encoding cannot bypass it.
pub const MAX_HTTP_FILE_BYTES: usize = 1024 * 1024 * 1024;

/// Structural policy for HTTP uploads, downloads and deep verification.
pub(crate) const HTTP_FILE_LIMITS: dag_core::FileLimits = dag_core::FileLimits {
    max_file_size: MAX_HTTP_FILE_BYTES as u64,
    max_chunks: 65_536,
    max_manifest_nodes: 8_192,
    max_links: 131_072,
    max_fetches: 131_073,
};

fn upload_body_error(error: axum::Error) -> std::io::Error {
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    loop {
        if cause.is::<tower_http::timeout::TimeoutError>() {
            return std::io::Error::new(std::io::ErrorKind::TimedOut, error);
        }
        let Some(source) = cause.source() else {
            return std::io::Error::other(error);
        };
        cause = source;
    }
}

/// Maximum bytes copied into one response-channel item. A store may return a
/// full 4 MiB chunk in one `Write::write_all` call; forwarding that call as
/// one `Bytes` value made the nominal four-item channel retain 16 MiB per
/// download. Fixed frames make its memory bound honest (4 × 64 KiB).
const RESPONSE_FRAME_BYTES: usize = 64 * 1024;

/// Content types the download endpoint will hand back as declared.
///
/// The declared type is written by whoever uploaded the file, and downloads
/// are served from the console's own origin — so echoing it verbatim let a
/// stored `<script>` payload declared `text/html` execute as the console.
/// Anything not on this list becomes `application/octet-stream`.
///
/// Two properties follow from matching against constants rather than
/// sanitising the caller's string. The served value is always one of these
/// literals, so it can carry neither active semantics nor header-injection
/// bytes — before this, a declared type containing CR/LF made
/// `Response::builder` fail and turned a download into a 500. And the list is
/// a decision anyone can audit in one glance: `image/svg+xml` is absent
/// because SVG is a script host, and `text/html` is absent because that is the
/// whole defect.
///
/// The type is preserved rather than flattened for everything because it is
/// genuinely useful to a caller saving a PNG or piping JSON, and none of these
/// can execute. It is *not* the control that makes serving safe — see
/// [`download`], which also refuses to let the browser render any of it.
const INERT_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/octet-stream",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "text/csv",
    "text/plain",
];

/// The content type to serve for a declared one, defaulting to bytes.
///
/// Parameters (`; charset=…`) are dropped rather than echoed: they are the
/// other half of the string an uploader controls, and nothing downstream needs
/// them.
fn safe_content_type(declared: Option<&str>) -> &'static str {
    let Some(declared) = declared else {
        return "application/octet-stream";
    };
    let essence = declared.split(';').next().unwrap_or("").trim();
    INERT_CONTENT_TYPES
        .iter()
        .find(|allowed| allowed.eq_ignore_ascii_case(essence))
        .copied()
        .unwrap_or("application/octet-stream")
}

/// Upload options.
///
/// Unknown names are refused rather than dropped: a parameter that does
/// nothing should say so, not let the caller believe it was honoured.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadQuery {
    /// Content type recorded for the file; overrides the request's
    /// `Content-Type` header.
    pub content_type: Option<String>,
    /// Store as a chunked file even if it would fit in one chunk.
    #[serde(default)]
    pub chunked: bool,
}

/// `POST /api/files` — store a request body up to 1 GiB.
///
/// Mirrors `dag put`: content at or under 4 MiB becomes a plain chunk,
/// anything larger a `file/v1` manifest. The response reports which, plus the
/// dedup ratio for chunked uploads.
pub async fn upload(
    State(state): State<AppState>,
    Query(q): Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> ApiResult<Json<serde_json::Value>> {
    // The declared type goes into the manifest, where it is covered by the
    // root CID — so the CLI and the API must read the same declaration or
    // the same file gets two identities (`dag put --content-type text/csv`
    // and a browser upload of the same bytes used to disagree). The
    // standard header is that declaration for every HTTP client; the query
    // parameter stays as the explicit override.
    let content_type = q.content_type.or_else(|| {
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .filter(|value| !value.is_empty())
    });

    // Body -> AsyncRead -> blocking Read. The bridge must only be used on the
    // blocking pool; on_blocking_pool is exactly that.
    let stream = body
        .into_data_stream()
        .map(|item| item.map_err(upload_body_error));
    let reader = SyncIoBridge::new(StreamReader::new(stream));

    let stored = on_blocking_pool(&state, move |control| {
        Ok(dag_core::file::store_auto_with_limits(
            control.store.as_ref(),
            reader,
            content_type,
            q.chunked,
            &dag_core::ChunkerConfig::default(),
            &HTTP_FILE_LIMITS,
        )?)
    })
    .await?;

    Ok(Json(match stored {
        dag_core::StoredContent::Chunk { cid, size } => {
            serde_json::json!({ "cid": cid.to_hex(), "size": size })
        }
        dag_core::StoredContent::File(r) => serde_json::json!({
            "cid": r.cid.to_hex(),
            "size": r.size,
            "chunked": true,
            "chunks": r.chunks,
            "new_chunks": r.new_chunks,
            "depth": r.depth,
        }),
    }))
}

/// `GET /api/files?cid=…` — the content as a file, whatever its size.
///
/// A manifest CID streams the reassembled file; a plain chunk is served
/// as-is, so callers need not know or care whether content was chunked.
/// `Content-Length` is set from the manifest, so a verification failure
/// mid-stream — which aborts the body — is detectable as truncation.
///
/// ## Why nothing here renders
///
/// This endpoint returns bytes an untrusted party put in the store, from the
/// same origin the console runs on, over an API with no authentication. So it
/// does three things rather than one, because any single one of them can be
/// undone by a browser quirk or a future edit:
///
/// * the content type comes from `INERT_CONTENT_TYPES`, never from the
///   uploader's string;
/// * `Content-Disposition: attachment` means a navigation or an `<iframe>`
///   downloads the file instead of rendering it in the console's origin —
///   which is what actually neutralises a `text/html` payload, since the type
///   allow-list only narrows what we *claim*;
/// * `X-Content-Type-Options: nosniff` (from the router's baseline headers)
///   stops the browser inferring `text/html` from the bytes anyway, which is
///   the exact hole `application/octet-stream` leaves open without it.
///
/// The console links here with a `download` attribute, so `attachment` costs
/// it nothing.
pub async fn download(
    State(state): State<AppState>,
    Query(q): Query<CidQuery>,
) -> ApiResult<Response> {
    let cid = parse_cid(&q.cid)?;

    // Resolve what we're serving before any body bytes move, so missing
    // content is a clean 404 rather than a broken stream. The aggregate
    // response permit enters the uncancellable blocking closure before this
    // read, then returns with the retained bytes/manifest information.
    let cid_probe = cid.clone();
    let ((info, raw), response_permit) = on_content_response_pool(&state, move |control| {
        let bytes = control.store.get_chunk(&cid_probe)?;
        match dag_core::file::inspect_from_bytes_with_limits(&bytes, &HTTP_FILE_LIMITS)? {
            Some(info) => Ok((Some(info), Vec::new())),
            None => Ok((None, bytes)),
        }
    })
    .await?;

    let Some(info) = info else {
        // Ordinary content: one chunk, served whole.
        let len = raw.len();
        return Response::builder()
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, len.to_string())
            .header(header::CONTENT_DISPOSITION, "attachment")
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .body(crate::admitted_bytes_body(
                Bytes::from(raw),
                response_permit,
            ))
            .map_err(|error| ApiError::from(anyhow::anyhow!("building file response: {error}")));
    };

    // A chunked file: reassemble on the blocking pool, stream through a
    // bounded channel. ChannelWriter splits store writes into 64 KiB frames,
    // so capacity 4 caps in-flight response memory at 256 KiB.
    // Hold aggregate blocking admission for the full reassembly. A slow client
    // backpressures ChannelWriter by design; without this permit, arbitrarily
    // many such responses could pin Tokio blocking threads indefinitely.
    let permit = state.try_blocking_permit()?;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let control = state.control.clone();

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut writer = ChannelWriter { tx: tx.clone() };
        if let Err(e) = dag_core::file::join_with_limits(
            control.store.as_ref(),
            &cid,
            &mut writer,
            &HTTP_FILE_LIMITS,
        ) {
            // The client sees the stream abort short of Content-Length. If it
            // is already gone, this send fails too, which is fine.
            let _ = tx.blocking_send(Err(std::io::Error::other(e.to_string())));
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(move |item| {
        // The map closure belongs to the response body, so the permit remains
        // held while the socket is backpressured and is returned on drop.
        let _response_permit = &response_permit;
        item
    });
    let body = Body::from_stream(stream);

    Response::builder()
        .header(
            header::CONTENT_TYPE,
            safe_content_type(info.content_type.as_deref()),
        )
        .header(header::CONTENT_LENGTH, info.size.to_string())
        .header(header::CONTENT_DISPOSITION, "attachment")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(body)
        .map_err(|e| ApiError::from(anyhow::anyhow!("building response: {}", e)))
}

/// A `Write` that hands each chunk to the response stream, blocking when the
/// client is slower than the store.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for frame in buf.chunks(RESPONSE_FRAME_BYTES) {
            self.tx
                .blocking_send(Ok(Bytes::copy_from_slice(frame)))
                .map_err(|_| std::io::Error::other("client disconnected"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn active_content_types_never_survive() {
        for declared in [
            "text/html",
            "TEXT/HTML",
            "text/html; charset=utf-8",
            "image/svg+xml",
            "application/xhtml+xml",
            "application/javascript",
            "text/html\r\nX-Injected: yes",
        ] {
            assert_eq!(
                safe_content_type(Some(declared)),
                "application/octet-stream",
                "{:?} must not be served as declared",
                declared
            );
        }
    }

    #[test]
    fn inert_types_survive_without_their_parameters() {
        assert_eq!(safe_content_type(Some("image/png")), "image/png");
        assert_eq!(safe_content_type(Some("IMAGE/PNG")), "image/png");
        assert_eq!(
            safe_content_type(Some("text/plain; charset=iso-8859-1")),
            "text/plain"
        );
        assert_eq!(safe_content_type(None), "application/octet-stream");
    }

    /// Every entry is served verbatim, so every entry has to be inert.
    #[test]
    fn the_allow_list_contains_nothing_that_can_execute() {
        for allowed in INERT_CONTENT_TYPES {
            assert!(
                !allowed.contains("html")
                    && !allowed.contains("xml")
                    && !allowed.contains("javascript")
                    && !allowed.contains("ecmascript"),
                "{} can host script",
                allowed
            );
        }
    }

    #[test]
    fn channel_writer_splits_large_store_writes_into_bounded_frames() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut writer = ChannelWriter { tx };
        let body = vec![7u8; RESPONSE_FRAME_BYTES * 3 + 17];

        writer.write_all(&body).unwrap();
        drop(writer);

        let mut frames = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            frames.push(frame.unwrap());
        }
        assert_eq!(frames.len(), 4);
        assert!(frames
            .iter()
            .all(|frame| frame.len() <= RESPONSE_FRAME_BYTES));
        assert_eq!(frames.iter().map(Bytes::len).sum::<usize>(), body.len());
    }
}
