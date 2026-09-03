//! Effect claims, from arbitrary bytes.
//!
//! `claim_from_bytes` is the gate in front of ADR-003 adoption and of the
//! claim index rebuild, and it runs on chunks anyone can write. Whatever it
//! returns `Some` for is treated as a self-consistent claim: its links are
//! pinned as a subtree, and its outputs may be adopted as a run's results if
//! a trusted signature also covers it.
//!
//! So this target does not merely check that the parse is total — it asserts
//! the *contract* the parse is supposed to establish, because that contract is
//! what every caller downstream is entitled to assume. A repeated output name
//! once satisfied the length check while leaving a second, undeclared link
//! unexamined; the bijection assertion below is that defect written as a
//! property.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((claim, entry)) = dag_control::effects::claim_from_bytes(data) else {
        return;
    };

    // It said yes, so all of this must hold.
    assert_eq!(
        claim.outputs.len(),
        entry.links.len(),
        "accepted a claim whose output count disagrees with its links"
    );

    // Output names are distinct. Without this the counts above stop meaning
    // what they look like they mean.
    let mut names = std::collections::BTreeSet::new();
    for (name, _) in &claim.outputs {
        assert!(
            names.insert(name.as_str()),
            "accepted a claim that names the output {name:?} twice"
        );
    }

    // Every declared output is covered by a link that agrees on both name and
    // target...
    for (name, cid_hex) in &claim.outputs {
        let cid = dag_core::Cid::from_hex(cid_hex)
            .expect("accepted a claim whose output is not a well-formed CID");
        assert_eq!(cid.as_bytes().len(), dag_core::CID_LEN);
        assert!(
            entry
                .links
                .iter()
                .any(|l| l.name.as_deref() == Some(name.as_str()) && l.target == cid),
            "accepted a claim whose output {name:?} has no matching link"
        );
    }

    // ...and, the half that matters for retention, *every link* is something
    // the claim declares. A link that rides along unexamined is arbitrary
    // content given a subtree pin by an attestation that never mentions it.
    for link in &entry.links {
        let name = link
            .name
            .as_deref()
            .expect("accepted a claim carrying an unnamed link");
        assert!(
            claim
                .outputs
                .iter()
                .any(|(n, hex)| n == name
                    && dag_core::Cid::from_hex(hex).is_ok_and(|c| c == link.target)),
            "accepted a claim with a link {name:?} that no output declares"
        );
    }

    // The accessor every caller uses must agree with the payload.
    let outputs = dag_control::effects::claim_outputs(&claim)
        .expect("a claim that parsed could not yield its outputs");
    assert_eq!(outputs.len(), claim.outputs.len());
});
