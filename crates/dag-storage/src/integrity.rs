use crate::ChunkIndex;
use dag_core::{Cid, ContentStore, CoreError, IntegrityReport};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Rows decoded from the index at once. A scan may cover any number of rows,
/// but its index-side working set never grows with store cardinality.
const INTEGRITY_INDEX_PAGE_SIZE: usize = 256;

/// Maximum per-chunk diagnostics retained by one completed scan.
///
/// Counts always cover the complete scan. Diagnostics are deliberately a
/// bounded sample: a store with millions of missing chunks must not allocate
/// millions of heap strings merely to say that it is unhealthy.
pub const MAX_INTEGRITY_REPORTS: usize = 1_024;

#[derive(Clone)]
pub struct IntegrityScanner<S: ContentStore> {
    store: Arc<S>,
    index: Option<Arc<ChunkIndex>>,
    scan_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub total_chunks: usize,
    pub valid_chunks: usize,
    /// Everything that did not verify: the sum of the four categories below.
    pub invalid_chunks: usize,
    /// Indexed, but the store has no such chunk. The bytes are gone; the
    /// remedy is to restore or re-fetch them.
    pub missing_chunks: usize,
    /// Present, but the bytes no longer hash to their CID. The remedy is to
    /// replace those bytes from a good copy.
    pub corrupt_chunks: usize,
    /// Bytes present and intact, but the index record disagrees about them.
    /// Nothing is lost; `dag index reindex` rebuilds the record.
    pub stale_index_entries: usize,
    /// Present, and could not be read at all — permissions or a failing disk.
    pub unreadable_chunks: usize,
    /// Bounded diagnostics for invalid chunks only.
    pub reports: Vec<IntegrityReport>,
    /// More invalid chunks were found than fit in [`Self::reports`].
    pub reports_truncated: bool,
}

impl<S: ContentStore + 'static> IntegrityScanner<S> {
    pub fn new(store: Arc<S>, scan_interval: Duration) -> Self {
        Self {
            store,
            index: None,
            scan_interval,
        }
    }

    pub fn with_index(store: Arc<S>, index: Arc<ChunkIndex>, scan_interval: Duration) -> Self {
        Self {
            store,
            index: Some(index),
            scan_interval,
        }
    }

    pub fn scan_once(&self, node_id: &str) -> Result<ScanResult, CoreError> {
        self.scan_once_cancellable(node_id, MAX_INTEGRITY_REPORTS, || false)?
            .ok_or_else(|| {
                CoreError::Backend("an uncancellable integrity scan was cancelled".into())
            })
    }

    /// Scan in bounded index pages, stopping cooperatively when requested.
    ///
    /// `report_limit` is capped at [`MAX_INTEGRITY_REPORTS`]. `Ok(None)` means
    /// cancellation was observed; partial counts are intentionally discarded
    /// so callers cannot publish an incomplete sweep as a clean result. One
    /// chunk read may finish after cancellation, but every such read is bounded
    /// by the store's maximum chunk size.
    pub fn scan_once_cancellable<F>(
        &self,
        node_id: &str,
        report_limit: usize,
        is_cancelled: F,
    ) -> Result<Option<ScanResult>, CoreError>
    where
        F: Fn() -> bool,
    {
        let Some(ref index) = self.index else {
            return Err(CoreError::PreconditionFailed(
                "No index available for scanning".to_string(),
            ));
        };

        info!("Starting integrity scan for node {}", node_id);

        let report_limit = report_limit.min(MAX_INTEGRITY_REPORTS);
        let mut reports = Vec::with_capacity(report_limit);
        let mut valid_chunks = 0;
        let mut missing_chunks = 0;
        let mut corrupt_chunks = 0;
        let mut stale_index_entries = 0;
        let mut unreadable_chunks = 0;

        let scan_row_budget = index.count()?;
        let mut visited_rows = 0usize;
        let mut after = None;
        while visited_rows < scan_row_budget {
            if is_cancelled() {
                return Ok(None);
            }
            let page_limit = (scan_row_budget - visited_rows).min(INTEGRITY_INDEX_PAGE_SIZE);
            let page = index.integrity_page_after(after.as_ref(), page_limit)?;
            if page.is_empty() {
                break;
            }

            for (cid, expected_length) in page {
                if is_cancelled() {
                    return Ok(None);
                }

                // The bytes come through the store, which derives the path
                // from its own data directory. The diagnostic path in the
                // index is deliberately never followed.
                let invalid = match self.store.get_chunk(&cid) {
                    Ok(bytes)
                        if u64::try_from(bytes.len()).map_err(|_| {
                            CoreError::Backend("chunk length does not fit u64".into())
                        })? != expected_length =>
                    {
                        checked_increment(&mut stale_index_entries, "stale index entries")?;
                        Some(format!(
                            "stale index entry: index records {expected_length} bytes, store holds {}; \
                             bytes are intact, run `dag index reindex`",
                            bytes.len()
                        ))
                    }
                    Ok(_) => {
                        checked_increment(&mut valid_chunks, "valid chunks")?;
                        None
                    }
                    // The remedies differ, so the verdicts do: absent bytes
                    // must be restored, rotted bytes replaced, and unreadable
                    // chunks point to disk or permission failures.
                    Err(CoreError::ChunkNotFound(_)) => {
                        checked_increment(&mut missing_chunks, "missing chunks")?;
                        Some(
                            "missing: indexed but not present in this store; restore it"
                                .to_string(),
                        )
                    }
                    Err(err @ (CoreError::CidMismatch { .. } | CoreError::InvalidCid(_))) => {
                        checked_increment(&mut corrupt_chunks, "corrupt chunks")?;
                        Some(format!(
                            "corrupt: stored bytes do not match their CID ({err})"
                        ))
                    }
                    Err(error) => {
                        checked_increment(&mut unreadable_chunks, "unreadable chunks")?;
                        Some(format!("unreadable: {error}"))
                    }
                };

                if let Some(error_message) = invalid {
                    if reports.len() < report_limit {
                        warn!(cid = %cid, error = %error_message, "integrity check failed");
                        reports.push(IntegrityReport {
                            cid: cid.clone(),
                            node_id: node_id.to_string(),
                            is_valid: false,
                            error_message: Some(error_message),
                        });
                    }
                }
                after = Some(cid);
                checked_increment(&mut visited_rows, "visited rows")?;
            }
        }

        if is_cancelled() {
            return Ok(None);
        }

        let invalid_chunks = checked_sum(
            [
                missing_chunks,
                corrupt_chunks,
                stale_index_entries,
                unreadable_chunks,
            ],
            "invalid chunks",
        )?;
        let total_chunks = valid_chunks.checked_add(invalid_chunks).ok_or_else(|| {
            CoreError::Backend("integrity scan total chunk count overflow".into())
        })?;

        let result = ScanResult {
            total_chunks,
            valid_chunks,
            invalid_chunks,
            missing_chunks,
            corrupt_chunks,
            stale_index_entries,
            unreadable_chunks,
            reports_truncated: invalid_chunks > reports.len(),
            reports,
        };

        info!(
            "Completed integrity scan for node {}: {} valid, {} invalid \
             ({} missing, {} corrupt, {} stale index, {} unreadable), {} total",
            node_id,
            result.valid_chunks,
            result.invalid_chunks,
            result.missing_chunks,
            result.corrupt_chunks,
            result.stale_index_entries,
            result.unreadable_chunks,
            result.total_chunks
        );

        Ok(Some(result))
    }

    /// How often a periodic scan should run.
    ///
    /// The scanner deliberately does not run itself. Scheduling lives with the
    /// caller because reporting does: the `Event` type and the bus that carries
    /// it are in `dag-control`, which sits *above* this crate, so a loop in here
    /// could never announce what it found. That is exactly how the previous
    /// background task ended up as a detached, unstoppable loop whose only
    /// output was a log line and an unfinished note to emit an event.
    pub fn scan_interval(&self) -> Duration {
        self.scan_interval
    }

    pub fn verify_chunk(&self, cid: &Cid, node_id: &str) -> Result<IntegrityReport, CoreError> {
        match self.store.get_chunk(cid) {
            Ok(bytes) => {
                let computed_cid = Cid::compute(&bytes);
                let is_valid = computed_cid == *cid;

                Ok(IntegrityReport {
                    cid: cid.clone(),
                    node_id: node_id.to_string(),
                    is_valid,
                    error_message: if is_valid {
                        None
                    } else {
                        Some(format!(
                            "CID mismatch: expected {}, computed {}",
                            cid, computed_cid
                        ))
                    },
                })
            }
            Err(e) => Ok(IntegrityReport {
                cid: cid.clone(),
                node_id: node_id.to_string(),
                is_valid: false,
                error_message: Some(format!("Failed to read chunk: {}", e)),
            }),
        }
    }
}

fn checked_increment(value: &mut usize, label: &str) -> Result<(), CoreError> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| CoreError::Backend(format!("integrity scan {label} count overflow")))?;
    Ok(())
}

fn checked_sum<const N: usize>(values: [usize; N], label: &str) -> Result<usize, CoreError> {
    values.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| CoreError::Backend(format!("integrity scan {label} count overflow")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsStore;
    use dag_core::{ContentStore, MetaHint};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    #[derive(Default)]
    struct CountingMissingStore {
        reads: AtomicUsize,
    }

    impl ContentStore for CountingMissingStore {
        fn put_chunk(&self, _bytes: &[u8], _meta: Option<MetaHint>) -> Result<Cid, CoreError> {
            Err(CoreError::PreconditionFailed(
                "counting test store is read-only".into(),
            ))
        }

        fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError> {
            self.reads.fetch_add(1, Ordering::AcqRel);
            Err(CoreError::ChunkNotFound(cid.to_hex()))
        }

        fn has_chunk(&self, _cid: &Cid) -> Result<bool, CoreError> {
            Ok(false)
        }
    }

    fn missing_scanner(
        rows: usize,
    ) -> (
        IntegrityScanner<CountingMissingStore>,
        Arc<CountingMissingStore>,
        TempDir,
    ) {
        let temp = TempDir::new().unwrap();
        let index = Arc::new(crate::ChunkIndex::new(temp.path().join("index.redb")).unwrap());
        let entries = (0..rows)
            .map(|number| {
                let cid = Cid::compute(&number.to_be_bytes());
                let location = crate::ChunkLocation {
                    path: format!("/missing/{cid}"),
                    length: 1,
                    sha256_hash: cid.to_hex(),
                };
                (cid, location)
            })
            .collect::<Vec<_>>();
        index.insert_many(&entries).unwrap();
        let store = Arc::new(CountingMissingStore::default());
        let scanner =
            IntegrityScanner::with_index(Arc::clone(&store), index, Duration::from_secs(60));
        (scanner, store, temp)
    }

    #[test]
    fn test_verify_valid_chunk() {
        let temp_dir = TempDir::new().unwrap();
        let store = Arc::new(FsStore::new(temp_dir.path()).unwrap());
        let scanner = IntegrityScanner::new(store.clone(), Duration::from_secs(60));

        let data = b"test data";
        let cid = store.put_chunk(data, None).unwrap();

        let report = scanner.verify_chunk(&cid, "test-node").unwrap();

        assert!(report.is_valid);
        assert!(report.error_message.is_none());
        assert_eq!(report.node_id, "test-node");
        assert_eq!(report.cid, cid);
    }

    #[test]
    fn test_verify_missing_chunk() {
        let temp_dir = TempDir::new().unwrap();
        let store = Arc::new(FsStore::new(temp_dir.path()).unwrap());
        let scanner = IntegrityScanner::new(store, Duration::from_secs(60));

        let fake_cid = Cid::compute(b"nonexistent");
        let report = scanner.verify_chunk(&fake_cid, "test-node").unwrap();

        assert!(!report.is_valid);
        assert!(report.error_message.is_some());
        assert_eq!(report.node_id, "test-node");
        assert_eq!(report.cid, fake_cid);
    }

    #[test]
    fn test_scan_once_with_index() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().join("data");
        let store_index_dir = temp_dir.path().join("store_index");
        let scanner_index_dir = temp_dir.path().join("scanner_index");

        let store = Arc::new(FsStore::with_index(&data_dir, &store_index_dir).unwrap());
        let index = Arc::new(crate::ChunkIndex::new(&scanner_index_dir).unwrap());
        let scanner =
            IntegrityScanner::with_index(store.clone(), index.clone(), Duration::from_secs(60));

        // Store several chunks
        let data1 = b"hello world";
        let data2 = b"foo bar";
        let data3 = b"test data";

        let cid1 = store.put_chunk(data1, None).unwrap();
        let cid2 = store.put_chunk(data2, None).unwrap();
        let cid3 = store.put_chunk(data3, None).unwrap();

        // Manually populate the scanner's index since we're using separate indices
        use crate::ChunkLocation;
        index
            .insert(
                &cid1,
                ChunkLocation {
                    path: store.chunk_path(&cid1).to_string_lossy().to_string(),
                    length: data1.len() as u64,
                    sha256_hash: cid1.to_hex(),
                },
            )
            .unwrap();
        index
            .insert(
                &cid2,
                ChunkLocation {
                    path: store.chunk_path(&cid2).to_string_lossy().to_string(),
                    length: data2.len() as u64,
                    sha256_hash: cid2.to_hex(),
                },
            )
            .unwrap();
        index
            .insert(
                &cid3,
                ChunkLocation {
                    path: store.chunk_path(&cid3).to_string_lossy().to_string(),
                    length: data3.len() as u64,
                    sha256_hash: cid3.to_hex(),
                },
            )
            .unwrap();

        // Scan should show all chunks as valid
        let result = scanner.scan_once("test-node").unwrap();
        assert_eq!(result.total_chunks, 3);
        assert_eq!(result.valid_chunks, 3);
        assert_eq!(result.invalid_chunks, 0);
        assert!(result.reports.is_empty());
        assert!(!result.reports_truncated);

        // Corrupt one file
        let chunk_path = store.chunk_path(&cid2);
        std::fs::write(&chunk_path, b"corrupted").unwrap();

        // Scan should now detect the corruption
        let result = scanner.scan_once("test-node").unwrap();
        assert_eq!(result.total_chunks, 3);
        assert_eq!(result.valid_chunks, 2);
        assert_eq!(result.invalid_chunks, 1);

        // Find the corrupted chunk report
        let corrupted_report = result.reports.iter().find(|r| r.cid == cid2).unwrap();
        assert!(!corrupted_report.is_valid);
        assert!(corrupted_report.error_message.is_some());
    }

    #[test]
    fn scan_caps_invalid_diagnostics_but_keeps_complete_counts() {
        let rows = MAX_INTEGRITY_REPORTS + 7;
        let (scanner, store, _temp) = missing_scanner(rows);

        let result = scanner
            .scan_once_cancellable("test-node", usize::MAX, || false)
            .unwrap()
            .expect("uncancelled scan");

        assert_eq!(store.reads.load(Ordering::Acquire), rows);
        assert_eq!(result.total_chunks, rows);
        assert_eq!(result.invalid_chunks, rows);
        assert_eq!(result.missing_chunks, rows);
        assert_eq!(result.reports.len(), MAX_INTEGRITY_REPORTS);
        assert!(result.reports.iter().all(|report| !report.is_valid));
        assert!(result.reports_truncated);
    }

    #[test]
    fn scan_cancellation_stops_before_the_next_bounded_chunk_read() {
        let (scanner, store, _temp) = missing_scanner(100);
        let cancellation_store = Arc::clone(&store);

        let result = scanner
            .scan_once_cancellable("test-node", MAX_INTEGRITY_REPORTS, move || {
                cancellation_store.reads.load(Ordering::Acquire) >= 3
            })
            .unwrap();

        assert!(
            result.is_none(),
            "a cancelled partial scan is not publishable"
        );
        assert_eq!(store.reads.load(Ordering::Acquire), 3);
    }

    /// `cp -R` of a data directory, the way an operator makes a backup.
    fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir_all(&from, &to)?;
            } else {
                std::fs::copy(&from, &to)?;
            }
        }
        Ok(())
    }

    /// Write a store at `root`, then close it so the redb file can be copied.
    fn seed_store(root: &std::path::Path, payloads: &[&[u8]]) -> Vec<Cid> {
        let store = FsStore::with_index(root.join("data"), root.join("index.redb")).unwrap();
        let cids = payloads
            .iter()
            .map(|p| store.put_chunk(p, None).unwrap())
            .collect();
        // Drop closes the redb database; the copy must not race a live handle.
        drop(store);
        cids
    }

    fn open_scanner(root: &std::path::Path) -> IntegrityScanner<FsStore> {
        let store =
            Arc::new(FsStore::with_index(root.join("data"), root.join("index.redb")).unwrap());
        let index = store.get_index().unwrap();
        IntegrityScanner::with_index(store, index, Duration::from_secs(60))
    }

    /// The scanner must re-hash the store it was handed.
    ///
    /// `ChunkLocation.path` is an absolute path written by whichever process
    /// stored the chunk. Verifying a *copy* next to its source therefore used
    /// to re-hash the source's files and report the copy clean — a restore
    /// that has verified nothing gets a green light.
    #[test]
    fn scan_verifies_the_copy_not_the_original_beside_it() {
        let temp = TempDir::new().unwrap();
        let original = temp.path().join("original");
        let restored = temp.path().join("restored");

        let cids = seed_store(&original, &[b"hello world", b"foo bar", b"test data"]);
        copy_dir_all(&original, &restored).unwrap();

        // Damage the copy only. The original stays byte-perfect.
        let corrupt_target = &cids[1];
        let victim = FsStore::new(restored.join("data")).unwrap();
        std::fs::write(victim.chunk_path(corrupt_target), b"rot").unwrap();

        let result = open_scanner(&restored).scan_once("test-node").unwrap();

        assert_eq!(result.total_chunks, 3);
        assert_eq!(
            result.invalid_chunks, 1,
            "the copy's damaged chunk must be found, not the original's intact one"
        );
        assert_eq!(result.corrupt_chunks, 1);
        assert_eq!(result.valid_chunks, 2);
        let report = result
            .reports
            .iter()
            .find(|r| &r.cid == corrupt_target)
            .unwrap();
        assert!(!report.is_valid);

        // And the original is still clean, verified on its own terms.
        let original_result = open_scanner(&original).scan_once("test-node").unwrap();
        assert_eq!(original_result.invalid_chunks, 0);
    }

    /// The mirror image: a byte-perfect restore whose source is gone must not
    /// be reported as totally corrupt, which would make an operator discard a
    /// good backup.
    #[test]
    fn a_restored_store_is_clean_once_its_source_is_gone() {
        let temp = TempDir::new().unwrap();
        let original = temp.path().join("original");
        let restored = temp.path().join("restored");

        seed_store(&original, &[b"alpha", b"beta", b"gamma"]);
        std::fs::rename(&original, &restored).unwrap();
        assert!(!original.exists(), "the source must really be gone");

        let result = open_scanner(&restored).scan_once("test-node").unwrap();

        assert_eq!(result.total_chunks, 3);
        assert_eq!(result.valid_chunks, 3);
        assert_eq!(result.invalid_chunks, 0);
    }

    /// A chunk that is absent needs restoring; one whose bytes have rotted
    /// needs replacing. Counting both as "invalid" hides which.
    #[test]
    fn a_missing_chunk_is_counted_apart_from_a_rotted_one() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let cids = seed_store(root, &[b"gone", b"rotten", b"fine"]);

        let store = FsStore::new(root.join("data")).unwrap();
        std::fs::remove_file(store.chunk_path(&cids[0])).unwrap();
        std::fs::write(store.chunk_path(&cids[1]), b"not what was promised").unwrap();

        let result = open_scanner(root).scan_once("test-node").unwrap();

        assert_eq!(result.total_chunks, 3);
        assert_eq!(result.valid_chunks, 1);
        assert_eq!(result.invalid_chunks, 2);
        assert_eq!(result.missing_chunks, 1, "one chunk is absent");
        assert_eq!(result.corrupt_chunks, 1, "one chunk's bytes have rotted");
        assert_eq!(
            result.invalid_chunks,
            result.missing_chunks
                + result.corrupt_chunks
                + result.stale_index_entries
                + result.unreadable_chunks,
            "the categories must account for every invalid chunk"
        );

        let missing = result.reports.iter().find(|r| r.cid == cids[0]).unwrap();
        let rotted = result.reports.iter().find(|r| r.cid == cids[1]).unwrap();
        assert_ne!(
            missing.error_message, rotted.error_message,
            "the two need different remedies, so they must read differently"
        );
    }

    /// Length is an independent check: intact bytes with a wrong index record
    /// mean the index needs rebuilding, not that the data is lost.
    #[test]
    fn intact_bytes_with_a_wrong_index_record_are_reported_as_a_stale_index() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let cids = seed_store(root, &[b"the bytes are fine"]);

        let store =
            Arc::new(FsStore::with_index(root.join("data"), root.join("index.redb")).unwrap());
        let index = store.get_index().unwrap();
        let mut location = index.get(&cids[0]).unwrap().unwrap();
        location.length += 7;
        index.insert(&cids[0], location).unwrap();

        let scanner = IntegrityScanner::with_index(store, index, Duration::from_secs(60));
        let result = scanner.scan_once("test-node").unwrap();

        assert_eq!(result.total_chunks, 1);
        assert_eq!(result.valid_chunks, 0);
        assert_eq!(result.stale_index_entries, 1);
        assert_eq!(result.corrupt_chunks, 0);
        assert_eq!(result.missing_chunks, 0);
    }
}
