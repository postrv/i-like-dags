//! What a reader is told when stored bytes no longer hash to their CID.
//!
//! Found during the 2026-08 end-to-end pass: tampering with a chunk made
//! `dag usecase verify` print `[Invalid CID format: CID mismatch: …]` — the
//! mismatch was constructed as `CoreError::InvalidCid`, whose display
//! prefix describes a *malformed CID string*, not rotted content. An
//! operator investigating corruption was pointed at CID syntax (and
//! USE_CASE.md shows the unprefixed message, so the docs and the binary
//! disagreed). A hash mismatch is its own condition and now has its own
//! variant; these tests pin the classification and the exact display the
//! docs show.

use dag_core::{Cid, ContentStore, CoreError};
use dag_storage::FsStore;
use tempfile::TempDir;

#[test]
fn a_tampered_chunk_reports_a_cid_mismatch_not_a_format_error() {
    let dir = TempDir::new().unwrap();
    let store = FsStore::new(dir.path()).unwrap();
    let cid = store.put_chunk(b"original bytes", None).unwrap();

    let hex = cid.to_hex();
    let path = dir.path().join(&hex[..2]).join(&hex[2..]);
    std::fs::write(&path, b"tampered").unwrap();

    let err = store
        .get_chunk(&cid)
        .expect_err("tampering must not read back");
    let CoreError::CidMismatch { expected, computed } = &err else {
        panic!("expected CidMismatch, got: {err:?}");
    };
    assert_eq!(*expected, cid);
    assert_eq!(*computed, Cid::compute(b"tampered"));

    let shown = err.to_string();
    assert!(
        shown.starts_with("CID mismatch: expected "),
        "the display must lead with the mismatch, got: {shown}"
    );
    assert!(
        !shown.contains("Invalid CID format"),
        "a hash mismatch is not a malformed CID string: {shown}"
    );
}

/// The race-adoption path reports the same condition the same way: a file
/// already at the CID's path whose bytes do not hash to it is a mismatch,
/// not a CID-syntax problem.
#[test]
fn a_corrupt_file_found_during_adoption_reports_a_mismatch() {
    let dir = TempDir::new().unwrap();
    let store = FsStore::new(dir.path()).unwrap();

    // Pre-plant wrong bytes at the path the put will want.
    let cid = Cid::compute(b"the real content");
    let hex = cid.to_hex();
    std::fs::create_dir_all(dir.path().join(&hex[..2])).unwrap();
    std::fs::write(dir.path().join(&hex[..2]).join(&hex[2..]), b"squatter").unwrap();

    match store.put_chunk(b"the real content", None) {
        // Either the store overwrites/adopts cleanly...
        Ok(stored) => assert_eq!(stored, cid),
        // ...or it must name the corruption as a mismatch, not a format error.
        Err(err) => {
            assert!(
                matches!(err, CoreError::CidMismatch { .. }),
                "expected CidMismatch, got: {err:?}"
            );
            assert!(!err.to_string().contains("Invalid CID format"));
        }
    }
}
