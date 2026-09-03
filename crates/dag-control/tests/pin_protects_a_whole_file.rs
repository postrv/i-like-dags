//! Pinning a file's CID must retain the file.
//!
//! `dag put` chunks anything over 4 MiB and hands back a `file/v1` manifest
//! CID without saying so — that CID *is* the name of the file, and it is the
//! only name the operator ever sees. A direct pin on it used to protect the
//! one chunk it named: the list of parts survived, the parts did not, and the
//! next collection took the artefact while `dag pin list` still showed it
//! retained. That is R6 inverted for exactly the content large enough to be
//! worth pinning.

use dag_control::test_utils::TestControl;
use dag_core::{Cid, ContentStore, PinScope, PinTarget};

/// Store `bytes` as a file and return `(manifest cid, part cids)`.
fn store_file(tc: &TestControl, bytes: Vec<u8>) -> (Cid, Vec<Cid>) {
    let stored = dag_core::file::store_auto(
        tc.control.store.as_ref(),
        std::io::Cursor::new(bytes),
        None,
        false,
        &dag_core::ChunkerConfig::default(),
    )
    .unwrap();
    let root = match stored {
        dag_core::StoredContent::File(r) => r.cid,
        dag_core::StoredContent::Chunk { cid, .. } => cid,
    };
    let parts = tc
        .control
        .store
        .get_links(&root)
        .unwrap()
        .into_iter()
        .map(|l| l.target)
        .collect();
    (root, parts)
}

#[test]
fn a_direct_pin_on_a_manifest_protects_its_parts() {
    let tc = TestControl::new().unwrap();
    let bytes: Vec<u8> = (0..(9 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    let (root, parts) = store_file(&tc, bytes);
    assert!(parts.len() > 1, "setup: the file must be chunked");

    tc.control
        .pin_log
        .create(
            "release",
            PinTarget::Direct(root.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    let protected = tc.control.retention.protected_set("local").unwrap();
    assert!(protected.contains(&root), "the manifest itself");
    for part in &parts {
        assert!(
            protected.contains(part),
            "a pin on the file's only name left part {} collectable",
            part
        );
    }

    // And the stored event says what the pin actually does, so `pin info`
    // does not describe a direct pin that behaves like a subtree one.
    let head = tc.control.pin_log.head("release").unwrap();
    assert!(
        matches!(head.event.target, PinTarget::Subtree { .. }),
        "recorded as {:?}",
        head.event.target
    );
}

/// The other half: a direct pin on ordinary content still means one chunk.
/// Widening it to "everything this decodes into" would quietly turn every
/// entry pin into a subtree pin, which is a different promise.
#[test]
fn a_direct_pin_on_a_plain_entry_still_names_one_chunk() {
    let tc = TestControl::new().unwrap();
    let leaf = tc.control.store.put_chunk(b"leaf bytes", None).unwrap();
    let entry = tc
        .control
        .store
        .put_entry(&dag_core::Entry::new(
            b"an ordinary entry".to_vec(),
            vec![dag_core::Link {
                name: Some("child".into()),
                target: leaf.clone(),
            }],
            None,
        ))
        .unwrap();

    tc.control
        .pin_log
        .create(
            "just-the-entry",
            PinTarget::Direct(entry.clone()),
            PinScope::Global,
            None,
            None,
        )
        .unwrap();

    let protected = tc.control.retention.protected_set("local").unwrap();
    assert!(protected.contains(&entry));
    assert!(
        !protected.contains(&leaf),
        "a direct pin must not have become a subtree pin"
    );
}
