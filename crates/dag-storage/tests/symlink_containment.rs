#![cfg(unix)]

//! Filesystem trust-boundary regressions.
//!
//! A chunk path is `<data>/<two-hex shard>/<62-hex leaf>`. Neither component
//! may be a symlink: following the shard lets reads escape the store and lets
//! garbage collection unlink an arbitrary outside file. These tests keep an
//! outside sentinel alive while every public storage path encounters both an
//! intermediate and a final-component symlink.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dag_core::{Cid, ContentStore};
use dag_storage::{ChunkLocation, DurabilityPolicy, FsStore, GcCapableStore};
use tempfile::TempDir;

struct EscapeFixture {
    _temp: TempDir,
    store: FsStore,
    cid: Cid,
    outside_file: PathBuf,
    outside_bytes: Vec<u8>,
}

fn names(cid: &Cid) -> (String, String) {
    let hex = cid.to_hex();
    (hex[..2].to_owned(), hex[2..].to_owned())
}

fn indexed_store(temp: &TempDir) -> FsStore {
    FsStore::with_index(&temp.path().join("data"), &temp.path().join("index.redb")).unwrap()
}

fn record_index_row(store: &FsStore, cid: &Cid, bytes: &[u8]) {
    store
        .get_index()
        .unwrap()
        .insert(
            cid,
            ChunkLocation {
                path: store.chunk_path(cid).to_string_lossy().into_owned(),
                length: bytes.len() as u64,
                sha256_hash: cid.to_hex(),
            },
        )
        .unwrap();
}

fn shard_symlink_fixture(outside_bytes: &[u8]) -> EscapeFixture {
    let temp = TempDir::new().unwrap();
    let store = indexed_store(&temp);
    let expected = b"bytes whose canonical path is redirected";
    let cid = Cid::compute(expected);
    let (shard, leaf) = names(&cid);
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let outside_file = outside.join(leaf);
    fs::write(&outside_file, outside_bytes).unwrap();
    symlink(&outside, temp.path().join("data").join(shard)).unwrap();
    record_index_row(&store, &cid, outside_bytes);
    EscapeFixture {
        _temp: temp,
        store,
        cid,
        outside_file,
        outside_bytes: outside_bytes.to_vec(),
    }
}

fn final_symlink_fixture(outside_bytes: &[u8]) -> EscapeFixture {
    let temp = TempDir::new().unwrap();
    let store = indexed_store(&temp);
    let expected = b"bytes behind a final-component symlink";
    let cid = Cid::compute(expected);
    let (shard, leaf) = names(&cid);
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let outside_file = outside.join("sentinel");
    fs::write(&outside_file, outside_bytes).unwrap();
    let shard_path = temp.path().join("data").join(shard);
    fs::create_dir(&shard_path).unwrap();
    symlink(&outside_file, shard_path.join(leaf)).unwrap();
    record_index_row(&store, &cid, outside_bytes);
    EscapeFixture {
        _temp: temp,
        store,
        cid,
        outside_file,
        outside_bytes: outside_bytes.to_vec(),
    }
}

fn assert_sentinel_unchanged(fixture: &EscapeFixture) {
    assert_eq!(
        fs::read(&fixture.outside_file).unwrap(),
        fixture.outside_bytes,
        "an operation followed the store symlink and mutated outside data"
    );
}

fn assert_reads_and_put_refuse(fixture: &EscapeFixture, canonical_bytes: &[u8]) {
    assert!(fixture.store.get_chunk(&fixture.cid).is_err());
    assert!(fixture.store.has_chunk(&fixture.cid).is_err());
    assert!(fixture.store.put_chunk(canonical_bytes, None).is_err());
    assert_sentinel_unchanged(fixture);
}

#[test]
fn reads_adoption_and_repair_refuse_an_intermediate_shard_symlink() {
    // Wrong bytes make put take its repair path if it ever follows the link.
    let fixture = shard_symlink_fixture(b"outside sentinel must not be repaired");
    assert_reads_and_put_refuse(&fixture, b"bytes whose canonical path is redirected");
}

#[test]
fn reads_adoption_and_repair_refuse_a_final_component_symlink() {
    let fixture = final_symlink_fixture(b"outside final target must remain unchanged");
    assert_reads_and_put_refuse(&fixture, b"bytes behind a final-component symlink");
}

#[test]
fn deferred_sync_does_not_reopen_a_pending_chunk_through_a_new_symlink() {
    let temp = TempDir::new().unwrap();
    let store = indexed_store(&temp).with_durability(DurabilityPolicy::Deferred);
    let bytes = b"pending bytes";
    let cid = store.put_chunk(bytes, None).unwrap();
    let (shard, leaf) = names(&cid);
    let shard_path = temp.path().join("data").join(&shard);
    fs::remove_file(shard_path.join(&leaf)).unwrap();
    fs::remove_dir(&shard_path).unwrap();

    let outside = temp.path().join("outside-deferred");
    fs::create_dir(&outside).unwrap();
    let sentinel = outside.join(&leaf);
    let sentinel_bytes = b"outside pending sentinel";
    fs::write(&sentinel, sentinel_bytes).unwrap();
    symlink(&outside, &shard_path).unwrap();

    assert!(store.sync().is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), sentinel_bytes);
    assert!(store.get_index().unwrap().get(&cid).unwrap().is_none());
}

fn assert_single_and_batch_delete_refuse(fixture: &EscapeFixture) {
    let index = fixture.store.get_index().unwrap();
    assert!(fixture.store.delete_chunk(&fixture.cid).is_err());
    assert!(
        index.get(&fixture.cid).unwrap().is_some(),
        "single deletion cleared the index before refusing the unsafe path"
    );
    assert_sentinel_unchanged(fixture);

    let outcome = fixture
        .store
        .delete_chunks(std::slice::from_ref(&fixture.cid), Duration::ZERO);
    assert!(outcome.deleted.is_empty());
    assert_eq!(outcome.errors.len(), 1);
    assert!(
        index.get(&fixture.cid).unwrap().is_some(),
        "batch deletion cleared the index for an unsafe target"
    );
    assert_sentinel_unchanged(fixture);
}

#[test]
fn single_and_batch_gc_never_unlink_through_a_shard_symlink() {
    assert_single_and_batch_delete_refuse(&shard_symlink_fixture(
        b"outside shard sentinel survives GC",
    ));
}

#[test]
fn single_and_batch_gc_never_unlink_a_final_symlink_target() {
    assert_single_and_batch_delete_refuse(&final_symlink_fixture(
        b"outside final sentinel survives GC",
    ));
}

#[test]
fn list_and_reindex_refuse_a_symlink_and_preserve_the_old_index() {
    let fixture = shard_symlink_fixture(b"valid-or-invalid outside bytes are irrelevant");
    let index = fixture.store.get_index().unwrap();

    assert!(fixture.store.list_all_cids().is_err());
    assert!(fixture.store.reindex().is_err());
    assert!(
        index.get(&fixture.cid).unwrap().is_some(),
        "a failed inventory replaced the last usable index"
    );
    assert_sentinel_unchanged(&fixture);
}

#[test]
fn successful_reindex_atomically_removes_stale_rows() {
    let temp = TempDir::new().unwrap();
    let store = indexed_store(&temp);
    let present = store.put_chunk(b"still present", None).unwrap();
    let stale = store.put_chunk(b"removed behind the index", None).unwrap();
    let index = store.get_index().unwrap();
    assert_eq!(index.count().unwrap(), 2);

    fs::remove_file(store.chunk_path(&stale)).unwrap();
    assert_eq!(store.reindex().unwrap(), 1);
    assert!(index.get(&present).unwrap().is_some());
    assert!(index.get(&stale).unwrap().is_none());
    assert_eq!(index.count().unwrap(), 1);
}

#[test]
fn a_real_directory_at_the_final_component_is_refused_as_special() {
    let temp = TempDir::new().unwrap();
    let store = indexed_store(&temp);
    let bytes = b"directory collision";
    let cid = Cid::compute(bytes);
    let path = store.chunk_path(&cid);
    fs::create_dir_all(&path).unwrap();

    assert!(store.get_chunk(&cid).is_err());
    assert!(store.has_chunk(&cid).is_err());
    assert!(store.put_chunk(bytes, None).is_err());
    assert!(store.delete_chunk(&cid).is_err());
    assert!(Path::new(&path).is_dir());
}
