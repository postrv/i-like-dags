//! In-memory [`ContentStore`]. First-class: tests, wasm verifiers, and any
//! host that does not have a filesystem.
//!
//! Gets re-hash, so a caller cannot plant bytes under the wrong CID. Puts
//! refuse anything over [`MAX_CHUNK_SIZE`]. There is no durability — a
//! process exit is a collection.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::traits::{ContentStore, MetaHint};
use crate::{Cid, CoreError, MAX_CHUNK_SIZE};

/// A [`ContentStore`] that holds chunks in a process-local map.
#[derive(Default)]
pub struct MemoryStore {
    chunks: RwLock<HashMap<Cid, Vec<u8>>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many chunks are currently held.
    pub fn len(&self) -> usize {
        self.chunks.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ContentStore for MemoryStore {
    fn put_chunk(&self, bytes: &[u8], _meta: Option<MetaHint>) -> Result<Cid, CoreError> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: bytes.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }
        let cid = Cid::compute(bytes);
        self.chunks
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cid.clone(), bytes.to_vec());
        Ok(cid)
    }

    fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError> {
        let bytes = self
            .chunks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(cid)
            .cloned()
            .ok_or_else(|| CoreError::ChunkNotFound(cid.to_hex()))?;
        let computed = Cid::compute(&bytes);
        if &computed != cid {
            return Err(CoreError::CidMismatch {
                expected: cid.clone(),
                computed,
            });
        }
        Ok(bytes)
    }

    fn has_chunk(&self, cid: &Cid) -> Result<bool, CoreError> {
        Ok(self
            .chunks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(cid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_round_trips_and_rehashes() {
        let store = MemoryStore::new();
        let cid = store.put_chunk(b"hello", None).unwrap();
        assert_eq!(store.get_chunk(&cid).unwrap(), b"hello");
        assert!(store.has_chunk(&cid).unwrap());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn oversized_put_is_refused() {
        let store = MemoryStore::new();
        let err = store
            .put_chunk(&vec![0u8; MAX_CHUNK_SIZE + 1], None)
            .unwrap_err();
        assert!(matches!(err, CoreError::ChunkTooLarge { .. }));
        assert!(store.is_empty());
    }
}
