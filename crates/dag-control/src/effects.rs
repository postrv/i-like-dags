//! Attested effect claims (ADR-003).
//!
//! An effect claim is a stored entry saying "this effect key produced these
//! outputs". Signed with the existing DSSE machinery and pinned as a
//! subtree, it travels with `dag sync` like any other content — which turns
//! the effect cache from private job state into shareable, checkable
//! provenance. A receiving side may *adopt* a claim's outputs instead of
//! executing, but only when a keyring-trusted signature covers the claim
//! (invariant J7): no trusted key, no adoption, no change from today.

use std::collections::{HashMap, HashSet};

use dag_core::{
    validate_job_id, Cid, CoreError, EffectKey, Entry, Link, MetaHint, MAX_CHUNK_SIZE,
    MAX_JOB_DECLARED_OUTPUTS, MAX_JOB_NAME_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::integration::EffectClaimSink;
use crate::{Control, Result};

/// Payload `kind` for effect-claim entries.
pub const EFFECT_CLAIM_KIND: &str = "effect-claim/v1";

/// Content-type hint recorded on claim entries.
pub const EFFECT_CLAIM_CONTENT_TYPE: &str = "application/vnd.dag.effect-claim+json";

/// Largest JSON payload accepted for one effect claim.
///
/// This comfortably contains the maximum 256 outputs with maximum-length
/// names while preventing a schema-shaped chunk from making JSON decoding
/// retain an otherwise arbitrary 4 MiB object graph.
pub const MAX_EFFECT_CLAIM_PAYLOAD_BYTES: usize = 256 * 1024;

/// Largest output set accepted in one effect claim.
pub const MAX_EFFECT_CLAIM_OUTPUTS: usize = MAX_JOB_DECLARED_OUTPUTS;

/// The JSON payload of a claim entry.
///
/// Outputs are duplicated between the payload (the signed statement of
/// record) and the entry's named links (what makes the outputs reachable
/// for pinning, sync and GC). [`claim_from_bytes`] refuses an entry whose
/// two halves disagree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectClaim {
    /// Always [`EFFECT_CLAIM_KIND`].
    pub kind: String,
    /// Hex of [`EffectKey::to_binary_key`].
    pub effect_key: String,
    /// (output name, output CID hex), sorted by name.
    pub outputs: Vec<(String, String)>,
}

/// Build the claim entry for `key` producing `outputs`.
///
/// Deterministic: the same key and outputs always encode to the same entry,
/// so re-attesting is a storage no-op and the claim CID is stable across
/// builders that agree.
pub fn claim_entry(key: &EffectKey, outputs: &[(String, Cid)]) -> Entry {
    let mut sorted: Vec<(String, Cid)> = outputs.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let claim = EffectClaim {
        kind: EFFECT_CLAIM_KIND.to_string(),
        effect_key: hex::encode(key.to_binary_key()),
        outputs: sorted
            .iter()
            .map(|(name, cid)| (name.clone(), cid.to_hex()))
            .collect(),
    };
    let payload = serde_json::to_vec(&claim).expect("claim serialization should not fail");

    let links = sorted
        .into_iter()
        .map(|(name, cid)| Link::named(cid, &name))
        .collect();

    Entry::new(
        payload,
        links,
        Some(MetaHint {
            content_type: Some(EFFECT_CLAIM_CONTENT_TYPE.to_string()),
            encoding: None,
        }),
    )
}

/// Decode a stored claim entry, if that is what the bytes are.
///
/// Returns `None` for anything that is not a well-formed claim — including
/// an entry whose payload and links disagree about the outputs, which is
/// how a hand-crafted entry would smuggle unreferenced (uncollectable or
/// unsynced) output CIDs past the payload's readers.
pub fn claim_from_bytes(bytes: &[u8]) -> Option<(EffectClaim, Entry)> {
    if bytes.len() > MAX_CHUNK_SIZE {
        return None;
    }
    let entry = Entry::from_bytes_cbor(bytes).ok()?;
    if entry.payload.len() > MAX_EFFECT_CLAIM_PAYLOAD_BYTES
        || entry.links.len() > MAX_EFFECT_CLAIM_OUTPUTS
    {
        return None;
    }
    let claim: EffectClaim = serde_json::from_slice(&entry.payload).ok()?;
    if claim.kind != EFFECT_CLAIM_KIND {
        return None;
    }
    if claim.outputs.len() > MAX_EFFECT_CLAIM_OUTPUTS || claim.outputs.len() != entry.links.len() {
        return None;
    }

    // The textual key is part of signed provenance, but the lookup uses its
    // binary form. Require a canonical encoding of a structurally valid
    // EffectKey (including the JobId contract) before either side can act on
    // the claim.
    let key_bytes = hex::decode(&claim.effect_key).ok()?;
    let effect_key = EffectKey::from_binary_key(&key_bytes).ok()?;
    validate_job_id(effect_key.job_id.as_ref()).ok()?;
    if effect_key.to_binary_key() != key_bytes || hex::encode(&key_bytes) != claim.effect_key {
        return None;
    }

    // Build each side once. Distinct named links plus equal cardinality make
    // the comparison an exact bijection in O(outputs + links), rather than
    // repeatedly scanning every link for every declared output.
    let mut links_by_name: HashMap<&str, &Cid> = HashMap::with_capacity(entry.links.len());
    for link in &entry.links {
        let name = link.name.as_deref()?;
        if !valid_output_name(name) || links_by_name.insert(name, &link.target).is_some() {
            return None;
        }
    }

    let mut output_names = HashSet::with_capacity(claim.outputs.len());
    for (name, cid_hex) in &claim.outputs {
        if !valid_output_name(name) || !output_names.insert(name.as_str()) {
            return None;
        }
        let cid = Cid::from_hex(cid_hex).ok()?;
        let link_target = links_by_name.get(name.as_str())?;
        if *link_target != &cid {
            return None;
        }
    }
    Some((claim, entry))
}

fn valid_output_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_JOB_NAME_BYTES && !name.chars().any(char::is_control)
}

/// Parse a claim's outputs back into `(name, Cid)` pairs.
pub fn claim_outputs(claim: &EffectClaim) -> Result<Vec<(String, Cid)>, CoreError> {
    claim
        .outputs
        .iter()
        .map(|(name, hex)| {
            let cid = Cid::from_hex(hex)
                .map_err(|e| CoreError::Deserialization(format!("claim output cid: {}", e)))?;
            Ok((name.clone(), cid))
        })
        .collect()
}

/// An [`EffectClaimSink`] that attests through a [`Control`] with a loaded
/// signing key. Constructed by whoever holds the key — the CLI behind
/// `--attest-key`, or an embedding build tool.
pub struct EffectAttester<'a> {
    control: &'a Control,
    key: ed25519_dalek::SigningKey,
}

impl<'a> EffectAttester<'a> {
    pub fn new(control: &'a Control, key: ed25519_dalek::SigningKey) -> Self {
        Self { control, key }
    }
}

impl EffectClaimSink for EffectAttester<'_> {
    fn record(&self, key: &EffectKey, outputs: &[(String, Cid)]) -> Result<()> {
        self.control.attest_effect(key, outputs, &self.key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::JobId;

    fn key() -> EffectKey {
        EffectKey::new(
            JobId::from("job".to_string()),
            Cid::compute(b"manifest"),
            "spec".to_string(),
        )
    }

    #[test]
    fn claim_entries_are_deterministic_and_order_insensitive() {
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"b");
        let one = claim_entry(&key(), &[("x".into(), a.clone()), ("y".into(), b.clone())]);
        let two = claim_entry(&key(), &[("y".into(), b), ("x".into(), a)]);
        assert_eq!(one.to_bytes_cbor().unwrap(), two.to_bytes_cbor().unwrap());
    }

    #[test]
    fn claims_round_trip_through_bytes() {
        let a = Cid::compute(b"a");
        let entry = claim_entry(&key(), &[("x".into(), a.clone())]);
        let bytes = entry.to_bytes_cbor().unwrap();

        let (claim, _) = claim_from_bytes(&bytes).expect("well-formed claim");
        assert_eq!(claim.effect_key, hex::encode(key().to_binary_key()));
        assert_eq!(claim_outputs(&claim).unwrap(), vec![("x".to_string(), a)]);
    }

    #[test]
    fn claims_accept_an_order_independent_exact_named_link_bijection() {
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"b");
        let mut entry = claim_entry(&key(), &[("x".into(), a.clone()), ("y".into(), b.clone())]);
        entry.links.reverse();

        let (claim, _) = claim_from_bytes(&entry.to_bytes_cbor().unwrap()).unwrap();
        assert_eq!(
            claim_outputs(&claim).unwrap(),
            vec![("x".to_string(), a), ("y".to_string(), b)]
        );
    }

    #[test]
    fn a_claim_whose_links_disagree_with_its_payload_is_refused() {
        let a = Cid::compute(b"a");
        let mut entry = claim_entry(&key(), &[("x".into(), a)]);
        // Redirect the link away from what the payload states.
        entry.links[0].target = Cid::compute(b"elsewhere");
        assert!(claim_from_bytes(&entry.to_bytes_cbor().unwrap()).is_none());
    }

    /// A claim is pinned as a subtree, so every link in it gets retention.
    /// Repeating one output name made the length check pass while a second,
    /// undeclared link went unexamined — arbitrary content retained by an
    /// attestation that never mentions it, and adopted outputs carrying a
    /// duplicated name.
    #[test]
    fn a_claim_that_repeats_an_output_name_is_refused() {
        let a = Cid::compute(b"a");
        let smuggled = Cid::compute(b"along for the ride");

        let mut entry = claim_entry(&key(), &[("x".into(), a.clone())]);
        entry.links.push(dag_core::Link {
            name: Some("y".into()),
            target: smuggled,
        });

        // Payload says "x" twice: two outputs, two links, every output covered.
        let mut claim: EffectClaim = serde_json::from_slice(&entry.payload).unwrap();
        claim.outputs.push(("x".to_string(), a.to_hex()));
        entry.payload = serde_json::to_vec(&claim).unwrap();

        assert!(claim_from_bytes(&entry.to_bytes_cbor().unwrap()).is_none());
    }

    #[test]
    fn a_claim_with_an_unnamed_or_duplicate_named_link_is_refused() {
        let a = Cid::compute(b"a");
        let b = Cid::compute(b"b");

        let mut unnamed = claim_entry(&key(), &[("x".into(), a.clone()), ("y".into(), b.clone())]);
        unnamed.links[1].name = None;
        assert!(claim_from_bytes(&unnamed.to_bytes_cbor().unwrap()).is_none());

        let mut duplicate = claim_entry(&key(), &[("x".into(), a), ("y".into(), b)]);
        duplicate.links[1].name = Some("x".to_string());
        assert!(claim_from_bytes(&duplicate.to_bytes_cbor().unwrap()).is_none());
    }

    #[test]
    fn a_claim_with_an_invalid_effect_key_is_refused() {
        let output = Cid::compute(b"output");
        let mut malformed = claim_entry(&key(), &[("x".into(), output.clone())]);
        let mut claim: EffectClaim = serde_json::from_slice(&malformed.payload).unwrap();
        claim.effect_key = "not-hex".to_string();
        malformed.payload = serde_json::to_vec(&claim).unwrap();
        assert!(claim_from_bytes(&malformed.to_bytes_cbor().unwrap()).is_none());

        let invalid_job = EffectKey::new(
            JobId::from(""),
            Cid::compute(b"manifest"),
            "spec".to_string(),
        );
        let invalid_job_claim = claim_entry(&invalid_job, &[("x".into(), output)]);
        assert!(claim_from_bytes(&invalid_job_claim.to_bytes_cbor().unwrap()).is_none());
    }

    #[test]
    fn claims_enforce_payload_and_output_bounds() {
        let valid_key = hex::encode(key().to_binary_key());
        let oversized_payload = serde_json::to_vec(&serde_json::json!({
            "kind": EFFECT_CLAIM_KIND,
            "effect_key": valid_key,
            "outputs": [],
            "padding": "x".repeat(MAX_EFFECT_CLAIM_PAYLOAD_BYTES),
        }))
        .unwrap();
        assert!(oversized_payload.len() > MAX_EFFECT_CLAIM_PAYLOAD_BYTES);
        let oversized = Entry::new(oversized_payload, Vec::new(), None);
        assert!(claim_from_bytes(&oversized.to_bytes_cbor().unwrap()).is_none());

        let outputs: Vec<(String, Cid)> = (0..=MAX_EFFECT_CLAIM_OUTPUTS)
            .map(|index| {
                (
                    format!("output-{index}"),
                    Cid::compute(index.to_string().as_bytes()),
                )
            })
            .collect();
        let too_many = claim_entry(&key(), &outputs);
        assert!(claim_from_bytes(&too_many.to_bytes_cbor().unwrap()).is_none());
    }

    #[test]
    fn non_claims_decode_to_none() {
        assert!(claim_from_bytes(b"not cbor at all").is_none());
        let entry = Entry::new(b"{}".to_vec(), vec![], None);
        assert!(claim_from_bytes(&entry.to_bytes_cbor().unwrap()).is_none());
    }
}
