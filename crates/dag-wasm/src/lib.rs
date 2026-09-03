//! Thin wasm32 bindings over [`dag_core`].
//!
//! The functions here are the product thesis as an API: a tab can hash
//! bytes, decode an entry, walk a `file/v1` manifest, and check a DSSE
//! envelope, without trusting the host that served the bytes. The host
//! names a CID; the kernel checks the hash.

use dag_core::signing::{verify_envelope, Envelope};
use dag_core::{file, Cid, ContentStore, Entry, MemoryStore};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Keep browser inspection bounded even for a valid entry whose whole chunk
/// consists of links. The UI treats `links_total > links.len()` as an
/// incomplete walk; it never silently presents the prefix as the full DAG.
const BROWSER_MAX_LINKS: usize = 256;
const BROWSER_PREVIEW_CHARS: usize = 1_024;
const BROWSER_LINK_NAME_CHARS: usize = 256;

#[derive(Serialize)]
struct BrowserLink<'a> {
    name: Option<String>,
    target: &'a Cid,
}

#[derive(Serialize)]
struct BrowserEntry<'a> {
    kind: &'static str,
    payload_len: usize,
    preview: Option<String>,
    links_total: usize,
    links: Vec<BrowserLink<'a>>,
}

#[derive(Serialize)]
struct BrowserBytes {
    kind: &'static str,
    payload_len: usize,
    preview: Option<String>,
    links_total: usize,
    links: Vec<BrowserLink<'static>>,
}

fn bounded_text(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let mut value: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        value.push('…');
    }
    value
}

fn browser_preview(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .map(|text| bounded_text(text, BROWSER_PREVIEW_CHARS))
}

fn browser_entry_json(entry: &Entry) -> Result<String, String> {
    let preview = browser_preview(&entry.payload);
    let links = entry
        .links
        .iter()
        .take(BROWSER_MAX_LINKS)
        .map(|link| BrowserLink {
            name: link
                .name
                .as_deref()
                .map(|name| bounded_text(name, BROWSER_LINK_NAME_CHARS)),
            target: &link.target,
        })
        .collect();
    let view = BrowserEntry {
        kind: "entry",
        payload_len: entry.payload.len(),
        preview,
        links_total: entry.links.len(),
        links,
    };
    serde_json::to_string(&view).map_err(|e| e.to_string())
}

/// SHA-256 CID of `bytes`, lowercase hex.
pub fn compute_cid_hex(bytes: &[u8]) -> String {
    Cid::compute(bytes).to_hex()
}

/// Whether `bytes` hash to `cid_hex`.
pub fn chunk_matches(cid_hex: &str, bytes: &[u8]) -> Result<bool, String> {
    let cid = Cid::from_hex(cid_hex).map_err(|e| e.to_string())?;
    Ok(Cid::compute(bytes) == cid)
}

/// Decode a CBOR [`Entry`] to JSON (CIDs as hex).
pub fn entry_to_json(bytes: &[u8]) -> Result<String, String> {
    let entry = Entry::from_bytes_cbor(bytes).map_err(|e| e.to_string())?;
    serde_json::to_string(&entry).map_err(|e| e.to_string())
}

/// Decode a CBOR [`Entry`] for the browser without expanding a multi-megabyte
/// byte payload into a JSON number array.
///
/// This intentionally uses the exact `dag-core` decoder used by native
/// readers. A non-entry is an error; callers may then display it as an opaque
/// chunk, but must not derive links from any other source.
pub fn inspect_entry_json(bytes: &[u8]) -> Result<String, String> {
    let entry = Entry::from_bytes_cbor(bytes).map_err(|e| e.to_string())?;
    browser_entry_json(&entry)
}

/// Classify bytes with the shared Entry decoder. Parser rejection is a valid
/// opaque chunk, while serialization or bridge failures still fail closed.
pub fn inspect_chunk_json(bytes: &[u8]) -> Result<String, String> {
    match Entry::from_bytes_cbor(bytes) {
        Ok(entry) => browser_entry_json(&entry),
        Err(_) => serde_json::to_string(&BrowserBytes {
            kind: "bytes",
            payload_len: bytes.len(),
            preview: browser_preview(bytes),
            links_total: 0,
            links: Vec::new(),
        })
        .map_err(|e| e.to_string()),
    }
}

/// Verify a DSSE envelope JSON against a 32-byte Ed25519 public key (hex).
pub fn envelope_statement_json(
    envelope_json: &str,
    public_key_hex: &str,
) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(envelope_json).map_err(|e| e.to_string())?;
    let raw = hex::decode(public_key_hex).map_err(|e| e.to_string())?;
    let key_bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| e.to_string())?;
    let statement = verify_envelope(&envelope, &key).map_err(|e| e.to_string())?;
    serde_json::to_string(&statement).map_err(|e| e.to_string())
}

/// Re-hash `root_hex` and every part named by a `file/v1` manifest.
///
/// `chunks_json` is `{ "<cid hex>": "<base64 bytes>", ... }` covering the
/// root and every part. Returns `"chunk"` when the root is not a manifest
/// (the re-hash was the whole check) or a `FileInfo` JSON object.
pub fn verify_deep_json(root_hex: &str, chunks_json: &str) -> Result<String, String> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(chunks_json).map_err(|e| e.to_string())?;
    let store = MemoryStore::new();
    for (hex, value) in &map {
        let b64 = value
            .as_str()
            .ok_or_else(|| "chunk values must be base64 strings".to_string())?;
        let bytes = encode_base64_decode(b64)?;
        let expected = Cid::from_hex(hex).map_err(|e| e.to_string())?;
        let computed = store.put_chunk(&bytes, None).map_err(|e| e.to_string())?;
        if computed != expected {
            return Err(format!(
                "chunk {hex} hashes to {computed}, not the name it was given"
            ));
        }
    }
    let root = Cid::from_hex(root_hex).map_err(|e| e.to_string())?;
    match file::verify_deep(&store, &root) {
        Ok(None) => Ok("chunk".into()),
        Ok(Some(info)) => serde_json::to_string(&info).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

fn encode_base64_decode(b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())
}

/// SHA-256 CID of `bytes`, lowercase hex.
#[wasm_bindgen(js_name = compute_cid)]
pub fn compute_cid(bytes: &[u8]) -> String {
    compute_cid_hex(bytes)
}

/// Whether `bytes` hash to `cid_hex`.
#[wasm_bindgen(js_name = verify_chunk)]
pub fn verify_chunk(cid_hex: &str, bytes: &[u8]) -> Result<bool, JsError> {
    chunk_matches(cid_hex, bytes).map_err(|e| JsError::new(&e))
}

/// Decode a CBOR entry to JSON (CIDs as hex).
#[wasm_bindgen(js_name = decode_entry)]
pub fn decode_entry(bytes: &[u8]) -> Result<String, JsError> {
    entry_to_json(bytes).map_err(|e| JsError::new(&e))
}

/// Strictly decode a CBOR entry into a bounded browser inspection record.
#[wasm_bindgen(js_name = inspect_entry)]
pub fn inspect_entry(bytes: &[u8]) -> Result<String, JsError> {
    inspect_entry_json(bytes).map_err(|e| JsError::new(&e))
}

/// Classify a chunk and strictly decode it when it is a native CBOR entry.
#[wasm_bindgen(js_name = inspect_chunk)]
pub fn inspect_chunk(bytes: &[u8]) -> Result<String, JsError> {
    inspect_chunk_json(bytes).map_err(|e| JsError::new(&e))
}

/// Verify a DSSE envelope JSON against a 32-byte Ed25519 public key (hex).
#[wasm_bindgen(js_name = verify_envelope_json)]
pub fn verify_envelope_js(envelope_json: &str, public_key_hex: &str) -> Result<String, JsError> {
    envelope_statement_json(envelope_json, public_key_hex).map_err(|e| JsError::new(&e))
}

/// Re-hash a root and every part named by a `file/v1` manifest.
#[wasm_bindgen(js_name = verify_deep)]
pub fn verify_deep_js(root_hex: &str, chunks_json: &str) -> Result<String, JsError> {
    verify_deep_json(root_hex, chunks_json).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use dag_core::signing::{sign_statement, Statement};
    use dag_core::{Cid, Entry};
    use ed25519_dalek::SigningKey;

    #[test]
    fn compute_cid_matches_the_kernel() {
        assert_eq!(compute_cid_hex(b"hello"), Cid::compute(b"hello").to_hex());
    }

    #[test]
    fn verify_chunk_rejects_a_mismatch() {
        let cid = Cid::compute(b"hello").to_hex();
        assert!(chunk_matches(&cid, b"hello").unwrap());
        assert!(!chunk_matches(&cid, b"hello!").unwrap());
        assert!(chunk_matches("ab", b"hello").is_err());
    }

    #[test]
    fn decode_entry_round_trips_links() {
        let target = Cid::compute(b"leaf");
        let entry = Entry {
            payload: b"meta".to_vec(),
            links: vec![dag_core::Link {
                name: Some("leaf".into()),
                target,
            }],
            meta: None,
        };
        let json = entry_to_json(&entry.to_bytes_cbor().unwrap()).unwrap();
        let back: Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload, b"meta");
        assert_eq!(back.links[0].name.as_deref(), Some("leaf"));
    }

    #[test]
    fn browser_entry_inspection_is_bounded_and_uses_core_decoding() {
        let links = (0..(BROWSER_MAX_LINKS + 3))
            .map(|index| dag_core::Link {
                name: Some(if index == 0 {
                    "x".repeat(BROWSER_LINK_NAME_CHARS + 1)
                } else {
                    format!("child-{index}")
                }),
                target: Cid::compute(index.to_string().as_bytes()),
            })
            .collect();
        let entry = Entry {
            payload: "é".repeat(BROWSER_PREVIEW_CHARS + 1).into_bytes(),
            links,
            meta: None,
        };
        let json = inspect_entry_json(&entry.to_bytes_cbor().unwrap()).unwrap();
        let view: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(view["links_total"], BROWSER_MAX_LINKS + 3);
        assert_eq!(view["links"].as_array().unwrap().len(), BROWSER_MAX_LINKS);
        let first_name = view["links"][0]["name"].as_str().unwrap();
        assert_eq!(first_name.chars().count(), BROWSER_LINK_NAME_CHARS + 1);
        assert!(first_name.ends_with('…'));
        assert_eq!(
            view["preview"].as_str().unwrap().chars().count(),
            BROWSER_PREVIEW_CHARS + 1
        );
        assert!(view["preview"].as_str().unwrap().ends_with('…'));
        assert!(inspect_entry_json(b"not cbor").is_err());
        let raw: serde_json::Value =
            serde_json::from_str(&inspect_chunk_json(b"not cbor").unwrap()).unwrap();
        assert_eq!(raw["kind"], "bytes");
        assert_eq!(raw["links_total"], 0);
    }

    #[test]
    fn verify_envelope_json_accepts_a_real_signature() {
        let seed = [7u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let cid = Cid::compute(b"subject");
        let statement = Statement::for_cid(&cid, None, serde_json::json!({ "ok": true }));
        let envelope = sign_statement(&statement, &key).unwrap();
        let env_json = serde_json::to_string(&envelope).unwrap();
        let pub_hex = hex::encode(key.verifying_key().as_bytes());
        let out = envelope_statement_json(&env_json, &pub_hex).unwrap();
        let read: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(read["_type"], dag_core::signing::STATEMENT_TYPE);
    }

    #[test]
    fn verify_deep_over_a_plain_chunk() {
        let bytes = b"just-a-chunk";
        let cid = Cid::compute(bytes);
        let mut map = serde_json::Map::new();
        map.insert(
            cid.to_hex(),
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
        );
        let chunks = serde_json::Value::Object(map).to_string();
        assert_eq!(verify_deep_json(&cid.to_hex(), &chunks).unwrap(), "chunk");
    }
}
