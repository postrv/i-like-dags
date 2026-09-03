//! Writes a seed corpus of *valid* encodings for each target.
//!
//! Coverage-guided fuzzing from random bytes spends its early budget
//! rediscovering the shape of a CBOR map. Starting from real entries,
//! events and envelopes means the interesting mutations — a truncated
//! link list, a subject digest one nibble short, a `prev` where none
//! belongs — are one bit-flip away instead of one miracle away.
//!
//! ```bash
//! cargo +nightly run --manifest-path fuzz/Cargo.toml --bin seed_corpus
//! ```

use std::path::Path;

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("fuzz/corpus").join(target);
    std::fs::create_dir_all(&dir).expect("create corpus dir");
    std::fs::write(dir.join(name), bytes).expect("write seed");
}

fn main() {
    let cid = dag_core::Cid::compute(b"a chunk of content");
    let other = dag_core::Cid::compute(b"another chunk");

    // --- entries -----------------------------------------------------------
    let empty = dag_core::Entry {
        payload: Vec::new(),
        links: Vec::new(),
        meta: None,
    };
    let linked = dag_core::Entry {
        payload: b"a release record".to_vec(),
        links: vec![
            dag_core::Link {
                name: Some("artifact".into()),
                target: cid.clone(),
            },
            dag_core::Link {
                name: None,
                target: other.clone(),
            },
        ],
        meta: Some(dag_core::MetaHint {
            content_type: Some("application/json".into()),
            encoding: None,
        }),
    };
    for (name, entry) in [("empty", &empty), ("linked", &linked)] {
        let bytes = entry.to_bytes_cbor().expect("encode entry");
        write("entry_cbor", name, &bytes);
        // Entries are also the wrapper events arrive in.
        write("pointer_event", &format!("entry-{name}"), &bytes);
    }

    // --- pointer events ----------------------------------------------------
    let create = dag_core::PointerEvent::create_event("models/production", cid.clone(), 1_700_000_000);
    let update = dag_core::PointerEvent::update_event(
        "models/production",
        2,
        cid.clone(),
        other.clone(),
        1_700_000_100,
    );
    for (name, event) in [("create", &create), ("update", &update)] {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(event, &mut bytes).expect("encode pointer event");
        write("pointer_event", name, &bytes);
    }

    // --- pin events --------------------------------------------------------
    let direct = dag_core::PinEvent {
        seq: 1,
        pin_id: "release/v2".into(),
        target: dag_core::PinTarget::Direct(cid.clone()),
        scope: dag_core::PinScope::Global,
        importance: 10,
        expires_at: Some(1_800_000_000),
        state: dag_core::PinState::Active,
        ts: 1_700_000_000,
        author: Some("release manager".into()),
        prev: None,
    };
    let subtree = dag_core::PinEvent {
        seq: 2,
        pin_id: "release/v2".into(),
        target: dag_core::PinTarget::Subtree {
            root: other.clone(),
            max_depth: None,
        },
        scope: dag_core::PinScope::Local {
            node_id: "node-a".into(),
        },
        importance: 0,
        expires_at: None,
        state: dag_core::PinState::Deactivated,
        ts: 1_700_000_200,
        author: None,
        prev: Some(cid.clone()),
    };
    for (name, event) in [("direct", &direct), ("subtree", &subtree)] {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(event, &mut bytes).expect("encode pin event");
        write("pin_event", name, &bytes);
    }

    // --- DSSE envelopes and stored signature records -----------------------
    let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let statement = dag_core::signing::Statement::for_cid(
        &cid,
        Some("model-release".into()),
        serde_json::json!({"approved_by": "release manager"}),
    );
    let envelope = dag_core::signing::sign_statement(&statement, &key).expect("sign");
    write(
        "dsse_envelope",
        "signed",
        serde_json::to_string_pretty(&envelope)
            .expect("serialise envelope")
            .as_bytes(),
    );

    // The stored form: a signature record inside an entry, which is what the
    // store scan actually offers `record_from_bytes`.
    let record = serde_json::json!({
        "kind": dag_core::signing::SIGNATURE_KIND,
        "key_id": dag_core::signing::key_id(&key.verifying_key()),
        "public_key": hex::encode(key.verifying_key().as_bytes()),
        "envelope": envelope,
    });
    let entry = dag_core::Entry {
        payload: serde_json::to_vec(&record).expect("serialise record"),
        links: vec![dag_core::Link {
            name: Some("signs".into()),
            target: cid.clone(),
        }],
        meta: None,
    };
    write(
        "signature_record",
        "stored",
        &entry.to_bytes_cbor().expect("encode signature entry"),
    );

    println!("seed corpus written under fuzz/corpus/");
}
