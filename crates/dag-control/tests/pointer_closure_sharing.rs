//! The pointer-head closure must be correct, cheap, and honest about its
//! ceiling.
//!
//! Collection protects everything reachable from every live pointer head. The
//! original implementation walked the graph once *per pointer* with a fresh
//! visited set, so N pointers over one shared DAG re-walked it N times — each
//! walk doing `get_links` I/O over the whole graph. These tests pin the shared
//! walk down from three sides: it returns the same set as the per-root walks
//! (correctness), it does not re-read shared structure (efficiency), and it
//! still refuses to collect against a snapshot it knows is partial (ceiling).

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use dag_control::test_utils::TestControl;
use dag_control::{Control, ControlError, GcRequest, PinLog, RetentionIndex};
use dag_core::{Cid, ContentStore, CoreError, Entry, Link, MetaHint};
use dag_storage::{FsStore, GcCapableStore};
use redb::Database;
use tempfile::TempDir;

// ---- a ContentStore that counts the one call the closure's cost is in ----

/// Wraps a store and counts `get_links`, the per-node I/O a graph walk does.
struct CountingStore {
    inner: FsStore,
    get_links_calls: AtomicUsize,
}

impl CountingStore {
    fn new(inner: FsStore) -> Self {
        Self {
            inner,
            get_links_calls: AtomicUsize::new(0),
        }
    }
    fn reset(&self) {
        self.get_links_calls.store(0, Ordering::Relaxed);
    }
    fn get_links_calls(&self) -> usize {
        self.get_links_calls.load(Ordering::Relaxed)
    }
}

impl ContentStore for CountingStore {
    fn put_chunk(&self, bytes: &[u8], meta: Option<MetaHint>) -> Result<Cid, CoreError> {
        self.inner.put_chunk(bytes, meta)
    }
    fn get_chunk(&self, cid: &Cid) -> Result<Vec<u8>, CoreError> {
        self.inner.get_chunk(cid)
    }
    fn has_chunk(&self, cid: &Cid) -> Result<bool, CoreError> {
        self.inner.has_chunk(cid)
    }
    fn get_links(&self, cid: &Cid) -> Result<Vec<Link>, CoreError> {
        self.get_links_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.get_links(cid)
    }
}

/// A chain of `len` linked entries; returns `(head, all_cids)` where following
/// links from `head` reaches every cid.
fn chain<S: ContentStore>(store: &S, len: usize) -> (Cid, Vec<Cid>) {
    let mut cids = Vec::with_capacity(len);
    let mut prev: Option<Cid> = None;
    for i in 0..len {
        let links = prev
            .take()
            .map(|p| vec![Link::new(p, None)])
            .unwrap_or_default();
        let cid = store
            .put_entry(&Entry::new(format!("node {i}").into_bytes(), links, None))
            .unwrap();
        cids.push(cid.clone());
        prev = Some(cid);
    }
    (cids.last().unwrap().clone(), cids)
}

fn retention_over(
    store: Arc<CountingStore>,
    dir: &TempDir,
    max_expansion: usize,
) -> RetentionIndex<CountingStore> {
    let db = Arc::new(Database::create(dir.path().join("control.redb")).unwrap());
    let pin_log = Arc::new(PinLog::new(store.clone(), db).unwrap());
    RetentionIndex::new(pin_log, store, max_expansion)
}

// ---- 1: the shared walk returns exactly the union of the per-root walks ----

#[test]
fn shared_closure_equals_the_union_of_per_root_closures() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(CountingStore::new(
        FsStore::new(dir.path().join("data")).unwrap(),
    ));
    let ret = retention_over(store.clone(), &dir, 1_000_000);

    // One shared chain that several roots link into, plus a private leaf each.
    let (shared_head, shared_cids) = chain(&*store, 5);
    let mut roots = Vec::new();
    let mut expected: HashSet<Cid> = shared_cids.iter().cloned().collect();
    for i in 0..3 {
        let private = store
            .put_chunk(format!("private {i}").as_bytes(), None)
            .unwrap();
        let root = store
            .put_entry(&Entry::new(
                format!("root {i}").into_bytes(),
                vec![
                    Link::new(shared_head.clone(), None),
                    Link::new(private.clone(), None),
                ],
                None,
            ))
            .unwrap();
        expected.insert(root.clone());
        expected.insert(private);
        roots.push(root);
    }

    // The old algorithm, inline: expand each root with a fresh visited set.
    let mut union = HashSet::new();
    for r in &roots {
        union.extend(ret.expand_root(r).unwrap().0);
    }

    let (shared, report) = ret.expand_roots(&roots).unwrap();
    assert!(!report.limited_by_max_expansion);
    assert_eq!(
        shared, union,
        "the shared walk must equal the union of the per-root walks"
    );
    assert_eq!(
        shared, expected,
        "and must be exactly everything reachable from the roots"
    );
    assert_eq!(report.cids_expanded, shared.len());
}

// ---- 2: the shared walk reads a shared graph once, not once per root ----

#[test]
fn shared_closure_walks_shared_structure_once_not_once_per_root() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(CountingStore::new(
        FsStore::new(dir.path().join("data")).unwrap(),
    ));
    let ret = retention_over(store.clone(), &dir, 1_000_000);

    let m = 30usize; // nodes in the shared chain
    let n = 40usize; // pointer heads, each linking into that one chain
    let (shared_head, _) = chain(&*store, m);
    let mut roots = Vec::new();
    for i in 0..n {
        roots.push(
            store
                .put_entry(&Entry::new(
                    format!("root {i}").into_bytes(),
                    vec![Link::new(shared_head.clone(), None)],
                    None,
                ))
                .unwrap(),
        );
    }

    // Cost of the per-root algorithm: each of N roots re-walks the M-node chain.
    store.reset();
    let mut union = HashSet::new();
    for r in &roots {
        union.extend(ret.expand_root(r).unwrap().0);
    }
    let per_root_calls = store.get_links_calls();

    // Cost of the shared walk.
    store.reset();
    let (shared, _) = ret.expand_roots(&roots).unwrap();
    let shared_calls = store.get_links_calls();

    assert_eq!(shared, union, "same answer, whichever way it is computed");

    // Per-root is quadratic: it re-reads the shared chain for every root.
    assert!(
        per_root_calls >= n * m,
        "sanity: the per-root algorithm really is O(N*M) ({per_root_calls} calls)"
    );
    // The shared walk is O(M + N): each root entry once, each chain node once.
    assert!(
        shared_calls <= m + 2 * n,
        "shared walk did {shared_calls} get_links calls; O(M+N) here is ~{}. \
         A per-root walk would do ~{}.",
        m + n,
        per_root_calls
    );
    assert!(
        shared_calls * 4 < per_root_calls,
        "the shared walk must be dramatically cheaper ({shared_calls} vs {per_root_calls})"
    );
}

// ---- helpers for the end-to-end GC tests ----

fn mark_recovered(control: &Control) -> Result<()> {
    control.recovery_state.mark_complete_for_test()?;
    Ok(())
}

fn request() -> GcRequest {
    GcRequest {
        node_id: "local".into(),
        dry_run: false,
        max_delete: 0,
        min_age_secs: 0,
        system_protection: true,
    }
}

// ---- 3: an upper bound on what survives — GC did not become "keep all" ----

#[test]
fn collection_keeps_exactly_the_named_content_and_the_control_plane() -> Result<()> {
    use dag_core::{Determinism, JobId, JobInput, JobPolicy, JobSpec};

    let tc = TestControl::new()?;
    mark_recovered(&tc.control)?;
    let store = &tc.control.store;

    let mut expected: HashSet<Cid> = HashSet::new();

    // (a) content reachable from a pointer (head entry + the leaf it links).
    let leaf = store.put_chunk(b"dataset leaf", None)?;
    let card = store.put_entry(&Entry::new(
        b"dataset card".to_vec(),
        vec![Link::named(leaf.clone(), "data")],
        None,
    ))?;
    tc.control
        .pointer_log
        .create("datasets/current", card.clone())?;
    expected.insert(leaf);
    expected.insert(card);

    // (b) content reachable from a pin.
    let pinned = store.put_chunk(b"held by a pin", None)?;
    tc.control.pin_log.create(
        "hold",
        dag_core::PinTarget::Direct(pinned.clone()),
        dag_core::PinScope::Global,
        None,
        Some("test".into()),
    )?;
    expected.insert(pinned);

    // (c) a job's event entry (control-plane history).
    tc.control.create_job(JobSpec {
        job_id: JobId::from("digest"),
        placement: None,
        inputs: JobInput::new(),
        determinism: Determinism::Deterministic,
        declared_outputs: vec!["out".into()],
        code_ref: "hash".into(),
        policy: JobPolicy::default(),
        config: None,
    })?;

    // (c) every control-plane event entry, from the logs that own them.
    for (_, _, cid) in tc.control.pointer_log.event_cids()? {
        expected.insert(cid);
    }
    for (_, _, cid) in tc.control.pin_log.event_cids()? {
        expected.insert(cid);
    }
    for (_, _, cid) in tc.control.job_log.event_cids()? {
        expected.insert(cid);
    }

    // (d) an orphan nobody names.
    let orphan = store.put_chunk(b"nobody names this", None)?;

    tc.control.run_gc(&request())?;

    let survivors: HashSet<Cid> = store.list_all_cids()?.into_iter().collect();
    assert!(
        !survivors.contains(&orphan),
        "the orphan is unreferenced and must be collected"
    );
    assert_eq!(
        survivors, expected,
        "survivors must be exactly (a) pointer-reachable + (b) pin-reachable + \
         (c) control-plane events — no more (retention did not become keep-all) \
         and no less"
    );
    Ok(())
}

// ---- 4: the shared walk still refuses when it hits the ceiling ----

#[test]
fn a_pointer_closure_too_large_to_expand_refuses_collection() -> Result<()> {
    let tc = TestControl::new()?;
    mark_recovered(&tc.control)?;

    // A chain longer than the ceiling, named by a pointer.
    let (root, cids) = chain(tc.control.store.as_ref(), 40);
    tc.control.pointer_log.create("big/graph", root)?;
    tc.control.set_max_subtree_expansion(10);

    let err = tc
        .control
        .run_gc(&request())
        .expect_err("collecting against a closure known to be partial is how live data dies");

    match err {
        ControlError::RetentionIncomplete {
            ref pin_id,
            max_expansion,
            ..
        } => {
            assert_eq!(
                pin_id, "GC pointer/pin/active-work roots (shared closure)",
                "a shared walk has no single guilty pointer; the condition is named honestly"
            );
            assert_eq!(max_expansion, 10);
            // The remedy must still be in the operator-facing message.
            assert!(
                err.to_string().contains("--max-subtree-expansion"),
                "the error must still name the remedy: {err}"
            );
        }
        other => panic!("expected RetentionIncomplete, got {other:?}"),
    }

    for cid in &cids {
        assert!(
            tc.control.store.has_chunk(cid)?,
            "nothing may be collected while the closure is known to be partial"
        );
    }
    Ok(())
}
