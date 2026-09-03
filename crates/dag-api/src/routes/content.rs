//! Chunk, entry and DAG-graph endpoints.

use std::collections::{HashMap, HashSet, VecDeque};

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::Response;
use axum::Json;
use dag_control::Control;
use dag_core::{Cid, ContentStore, Entry};
use serde::{Deserialize, Serialize};

use crate::blocking::{on_blocking_pool, on_content_response_pool};
use crate::error::{ApiError, ApiResult};
use crate::routes::{parse_cid, CidQuery};
use crate::AppState;

/// Bytes of a payload preview returned inline with an entry.
const PREVIEW_BYTES: usize = 2048;

/// A stored chunk, described rather than transferred.
#[derive(Debug, Serialize)]
pub struct EntryView {
    /// The chunk's CID.
    pub cid: String,
    /// Byte length of the stored chunk.
    pub size: usize,
    /// True when the bytes decode as a DAG entry.
    pub is_entry: bool,
    /// Links, when this is an entry.
    pub links: Vec<LinkView>,
    /// Declared content type, when the entry carries a meta hint.
    pub content_type: Option<String>,
    /// UTF-8 preview of the payload, truncated.
    pub preview: Option<String>,
    /// Whether the preview was truncated.
    pub truncated: bool,
    /// Whether the stored bytes still hash to this CID.
    pub intact: bool,
}

/// A link from one entry to another.
#[derive(Debug, Serialize)]
pub struct LinkView {
    /// Optional link name.
    pub name: Option<String>,
    /// CID this link points at.
    pub target: String,
}

/// `GET /api/entries?cid=…`
pub async fn get_entry(
    State(state): State<AppState>,
    Query(q): Query<CidQuery>,
) -> ApiResult<Json<EntryView>> {
    let cid = parse_cid(&q.cid)?;
    on_blocking_pool(&state, move |control| Ok(Json(describe(control, &cid)?))).await
}

/// `GET /api/chunks?cid=…` — the raw bytes.
pub async fn get_chunk(
    State(state): State<AppState>,
    Query(q): Query<CidQuery>,
) -> ApiResult<Response> {
    let cid = parse_cid(&q.cid)?;
    let (bytes, permit) =
        on_content_response_pool(&state, move |control| Ok(control.store.get_chunk(&cid)?)).await?;

    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(crate::admitted_bytes_body(Bytes::from(bytes), permit))
        .map_err(|error| ApiError::from(anyhow::anyhow!("building chunk response: {error}")))
}

/// `POST /api/chunks` — store a chunk, returning its CID.
pub async fn put_chunk(
    State(state): State<AppState>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let size = body.len();
    let cid = on_blocking_pool(&state, move |control| {
        Ok(control.store.put_chunk(&body, None)?)
    })
    .await?;

    Ok(Json(
        serde_json::json!({ "cid": cid.to_hex(), "size": size }),
    ))
}

/// Query for a graph walk.
#[derive(Debug, Deserialize)]
pub struct GraphQuery {
    /// Root CID, or omit and pass `pointer` instead.
    pub cid: Option<String>,
    /// Pointer to resolve as the root.
    pub pointer: Option<String>,
    /// How many link hops to follow.
    #[serde(default = "default_depth")]
    pub depth: u32,
}

fn default_depth() -> u32 {
    4
}

/// Bound on nodes returned by a single graph walk, so a pathological DAG
/// cannot make the console unresponsive.
pub const MAX_GRAPH_NODES: usize = 500;

/// Bound on pointer heads inspected while annotating a graph.
pub const MAX_GRAPH_POINTER_LABELS: usize = 200;

/// Bound on edges emitted even when one entry contains an extreme fan-out.
pub const MAX_GRAPH_EDGES: usize = 2_000;

/// A node in the graph view.
#[derive(Debug, Serialize)]
pub struct GraphNode {
    /// CID of the node.
    pub cid: String,
    /// Distance from the root.
    pub depth: u32,
    /// Byte length.
    pub size: usize,
    /// Whether it decodes as an entry.
    pub is_entry: bool,
    /// Declared content type, if any.
    pub content_type: Option<String>,
    /// Short payload preview.
    pub preview: Option<String>,
    /// Whether the bytes still hash to the CID.
    pub intact: bool,
    /// Pointers currently resolving to this node.
    pub pointers: Vec<String>,
    /// Whether retention protects it.
    pub pinned: bool,
}

/// An edge in the graph view.
#[derive(Debug, Serialize)]
pub struct GraphEdge {
    /// Source CID.
    pub from: String,
    /// Target CID.
    pub to: String,
    /// Link name, if the link was named.
    pub name: Option<String>,
}

/// The whole walk.
#[derive(Debug, Serialize)]
pub struct GraphView {
    /// CID the walk started from.
    pub root: String,
    /// Nodes, breadth-first.
    pub nodes: Vec<GraphNode>,
    /// Edges between them.
    pub edges: Vec<GraphEdge>,
    /// True when a node or edge bound stopped topology expansion.
    pub truncated: bool,
    /// True when only the first [`MAX_GRAPH_POINTER_LABELS`] pointer heads
    /// were inspected while annotating nodes.
    pub pointer_labels_truncated: bool,
}

/// `GET /api/graph?cid=…&depth=…` or `?pointer=…`
///
/// Walks outward from the root, annotating each node with the pointers that
/// name it and whether retention protects it — the two things you need to know
/// before deleting anything.
pub async fn graph(
    State(state): State<AppState>,
    Query(q): Query<GraphQuery>,
) -> ApiResult<Json<GraphView>> {
    // The walk re-reads and re-hashes every node it touches, so it is the
    // single most I/O-heavy read in the API and the one that most needs to
    // stay off the runtime threads.
    on_blocking_pool(&state, move |control| Ok(Json(walk(control, &q)?))).await
}

/// The graph walk itself, synchronous and independent of the HTTP layer.
fn walk(control: &Control, q: &GraphQuery) -> ApiResult<GraphView> {
    let root = match (&q.cid, &q.pointer) {
        (Some(cid), _) => parse_cid(cid)?,
        (None, Some(pointer)) => control.pointer_log.resolve(pointer)?,
        (None, None) => {
            return Err(ApiError::bad_request("provide either `cid` or `pointer`"));
        }
    };

    // Reverse index so nodes can be labelled with the pointers naming them.
    let mut pointer_ids = control
        .pointer_log
        .list_pointers_page(None, MAX_GRAPH_POINTER_LABELS + 1)?;
    let pointer_labels_truncated = pointer_ids.len() > MAX_GRAPH_POINTER_LABELS;
    pointer_ids.truncate(MAX_GRAPH_POINTER_LABELS);

    let mut by_cid: HashMap<String, Vec<String>> = HashMap::new();
    for id in pointer_ids {
        // A key returned from the heads table must have a readable head. A
        // corrupt cache is a server fault, not a pointer to silently omit.
        let head = control.pointer_log.get_head(&id)?;
        by_cid
            .entry(head.current_cid.to_hex())
            .or_default()
            .push(id);
    }

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut truncated = false;

    queue.push_back((root.clone(), 0u32));
    seen.insert(root.clone());

    while let Some((cid, depth)) = queue.pop_front() {
        if nodes.len() >= MAX_GRAPH_NODES {
            truncated = true;
            break;
        }

        let hex = cid.to_hex();
        let bytes = control.store.get_chunk(&cid).ok();
        let entry = bytes
            .as_ref()
            .and_then(|b| Entry::from_bytes_cbor(b).ok())
            // A raw chunk that happens to be valid CBOR can decode to an entry
            // with nothing in it; treat that as raw content, not a DAG node.
            .filter(|e| !e.links.is_empty() || e.meta.is_some());

        nodes.push(GraphNode {
            cid: hex.clone(),
            depth,
            size: bytes.as_ref().map(|b| b.len()).unwrap_or(0),
            is_entry: entry.is_some(),
            content_type: entry
                .as_ref()
                .and_then(|e| e.meta.as_ref())
                .and_then(|m| m.content_type.clone()),
            preview: bytes
                .as_ref()
                .map(|b| preview(payload_of(&entry, b), 160).0),
            intact: bytes
                .as_ref()
                .map(|b| Cid::compute(b) == cid)
                .unwrap_or(false),
            pointers: by_cid.get(&hex).cloned().unwrap_or_default(),
            pinned: matches!(
                control.retention_status(&cid, None)?,
                dag_control::RetentionStatus::Protected(_)
            ),
        });

        if depth >= q.depth {
            continue;
        }
        if let Some(entry) = entry {
            for link in entry.links {
                if edges.len() >= MAX_GRAPH_EDGES {
                    truncated = true;
                    break;
                }
                edges.push(GraphEdge {
                    from: hex.clone(),
                    to: link.target.to_hex(),
                    name: link.name,
                });
                if seen.insert(link.target.clone()) {
                    queue.push_back((link.target, depth + 1));
                }
            }
        }
    }

    Ok(GraphView {
        root: root.to_hex(),
        nodes,
        edges,
        truncated,
        pointer_labels_truncated,
    })
}

/// Describe a single chunk, decoding it as an entry when possible.
fn describe(control: &Control, cid: &Cid) -> ApiResult<EntryView> {
    let bytes = control.store.get_chunk(cid)?;
    let entry = Entry::from_bytes_cbor(&bytes)
        .ok()
        .filter(|e| !e.links.is_empty() || e.meta.is_some());

    let (text, truncated) = preview(payload_of(&entry, &bytes), PREVIEW_BYTES);

    Ok(EntryView {
        cid: cid.to_hex(),
        size: bytes.len(),
        is_entry: entry.is_some(),
        links: entry
            .as_ref()
            .map(|e| {
                e.links
                    .iter()
                    .map(|l| LinkView {
                        name: l.name.clone(),
                        target: l.target.to_hex(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        content_type: entry
            .as_ref()
            .and_then(|e| e.meta.as_ref())
            .and_then(|m| m.content_type.clone()),
        preview: Some(text),
        truncated,
        intact: Cid::compute(&bytes) == *cid,
    })
}

/// The bytes a human wants to see: an entry's payload, or the raw chunk.
fn payload_of<'a>(entry: &'a Option<Entry>, raw: &'a [u8]) -> &'a [u8] {
    match entry {
        Some(e) => &e.payload,
        None => raw,
    }
}

/// Lossy UTF-8 preview, truncated on a character boundary.
fn preview(bytes: &[u8], limit: usize) -> (String, bool) {
    let truncated = bytes.len() > limit;
    let slice = &bytes[..bytes.len().min(limit)];
    let mut text = String::from_utf8_lossy(slice).to_string();
    if truncated {
        text.push('…');
    }
    (text, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_truncates_and_marks() {
        let (text, truncated) = preview(b"hello world", 5);
        assert_eq!(text, "hello…");
        assert!(truncated);

        let (text, truncated) = preview(b"hi", 5);
        assert_eq!(text, "hi");
        assert!(!truncated);
    }

    #[test]
    fn preview_handles_non_utf8_without_panicking() {
        let (text, _) = preview(&[0xff, 0xfe, 0x00], 8);
        assert!(!text.is_empty());
    }
}
