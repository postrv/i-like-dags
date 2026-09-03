//! Process-local model of an object store keyed by CID hex.
//!
//! The deployable Worker has its own R2 implementation in TypeScript. This
//! model exercises content-addressing invariants but does not emulate R2
//! consistency, conditional writes, Durable Objects, or recovery.
//!
//! `missing` treats an object that is absent, oversized, or no longer hashes
//! to its key as missing. A torn or corrupted PUT must remain repairable by a
//! later sync rather than becoming a permanent false "already present" hole.

use std::collections::HashMap;
use std::sync::RwLock;

use dag_core::{Cid, ContentStore, CoreError, MetaHint, MAX_CHUNK_SIZE};

/// A key/value object-store abstraction used by the native model.
pub trait ObjectStore: Send + Sync {
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), CoreError>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CoreError>;
    /// `None` if the key is absent; `Some(0)` is a torn upload.
    fn size(&self, key: &str) -> Result<Option<u64>, CoreError>;
}

/// Process-local objects. A [`Self::plant_torn`] write is how tests
/// reproduce the crash-mid-PUT case.
#[derive(Default)]
pub struct MemoryObjects {
    inner: RwLock<HashMap<String, Vec<u8>>>,
}

impl MemoryObjects {
    pub fn new() -> Self {
        Self::default()
    }

    /// Plant a zero-length object under `key` — a torn upload.
    pub fn plant_torn(&self, key: &str) {
        self.inner
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), Vec::new());
    }
}

impl ObjectStore for MemoryObjects {
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), CoreError> {
        self.inner
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), bytes.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CoreError> {
        Ok(self
            .inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned())
    }

    fn size(&self, key: &str) -> Result<Option<u64>, CoreError> {
        Ok(self
            .inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .map(|b| b.len() as u64))
    }
}

/// [`ContentStore`] over an [`ObjectStore`]. Key = CID hex.
pub struct R2Store<O: ObjectStore> {
    objects: O,
}

impl<O: ObjectStore> R2Store<O> {
    pub fn new(objects: O) -> Self {
        Self { objects }
    }

    pub fn objects(&self) -> &O {
        &self.objects
    }

    fn is_missing(&self, cid: &Cid) -> Result<bool, CoreError> {
        let Some(size) = self.objects.size(&cid.to_hex())? else {
            return Ok(true);
        };
        if size > MAX_CHUNK_SIZE as u64 {
            return Ok(true);
        }
        let Some(bytes) = self.objects.get(&cid.to_hex())? else {
            // Size/get disagreement is an incomplete object-store
            // observation, never evidence that content is present.
            return Ok(true);
        };
        Ok(bytes.len() as u64 != size || Cid::compute(&bytes) != *cid)
    }
}

impl<O: ObjectStore> ContentStore for R2Store<O> {
    fn put_chunk(&self, bytes: &[u8], _meta: Option<MetaHint>) -> Result<Cid, CoreError> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: bytes.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }
        let cid = Cid::compute(bytes);
        self.objects.put(&cid.to_hex(), bytes)?;
        Ok(cid)
    }

    fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError> {
        let bytes = self
            .objects
            .get(&cid.to_hex())?
            .ok_or_else(|| CoreError::ChunkNotFound(cid.to_hex()))?;
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: bytes.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }
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
        Ok(!self.is_missing(cid)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torn_upload_is_missing_and_get_fails() {
        let objects = MemoryObjects::new();
        let cid = Cid::compute(b"full-content");
        objects.plant_torn(&cid.to_hex());
        let store = R2Store::new(objects);
        assert!(!store.has_chunk(&cid).unwrap());
        assert!(matches!(
            store.get_chunk(&cid),
            Err(CoreError::CidMismatch { .. })
        ));
    }

    #[test]
    fn put_rehashes_and_round_trips() {
        let store = R2Store::new(MemoryObjects::new());
        let cid = store.put_chunk(b"hello", None).unwrap();
        assert_eq!(store.get_chunk(&cid).unwrap(), b"hello");
        assert!(store.has_chunk(&cid).unwrap());
    }

    #[test]
    fn put_refuses_a_mismatch_by_computing_the_name() {
        // There is no put-under-wrong-cid path: the store names what it
        // hashed. A lying PUT is the HTTP layer's job (see http tests).
        let store = R2Store::new(MemoryObjects::new());
        let cid = store.put_chunk(b"a", None).unwrap();
        assert_ne!(cid, Cid::compute(b"b"));
    }

    #[test]
    fn nonempty_corruption_is_missing_so_sync_can_repair_it() {
        let objects = MemoryObjects::new();
        let cid = Cid::compute(b"expected");
        objects.put(&cid.to_hex(), b"corrupt").unwrap();
        let store = R2Store::new(objects);
        assert!(!store.has_chunk(&cid).unwrap());
        assert!(matches!(
            store.get_chunk(&cid),
            Err(CoreError::CidMismatch { .. })
        ));
        store.put_chunk(b"expected", None).unwrap();
        assert!(store.has_chunk(&cid).unwrap());
    }
}
