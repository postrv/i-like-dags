//! Signatures over CIDs: who vouches for content, not just what it is.
//!
//! Content addressing proves bytes haven't changed since they were addressed;
//! it says nothing about who published them. This module adds that layer:
//! Ed25519 signatures over [DSSE] envelopes whose payload is an [in-toto
//! Statement], the format the SLSA/supply-chain ecosystem already speaks. A
//! CID *is* a SHA-256 digest, so it drops directly into a Statement's
//! `subject.digest.sha256` — external in-toto tooling can verify these
//! envelopes with no knowledge of this system.
//!
//! [DSSE]: https://github.com/secure-systems-lab/dsse
//! [in-toto Statement]: https://in-toto.io/Statement/v1
//!
//! ## Signatures are content
//!
//! A signature is stored as an ordinary entry: payload = a `signature/v1`
//! record carrying the DSSE envelope, links = one `signs` link to the target
//! CID. That makes signatures reachable (a subtree pin over a signature
//! retains what it signs), collectable (unpinned signatures are garbage like
//! anything else), and tamper-evident (the signature entry has a CID too).
//!
//! ## Trust model
//!
//! The envelope embeds the signer's public key, which supports exactly one
//! claim: *internal validity* — the envelope is self-consistent. Whether the
//! key is *trusted* is a separate question answered by a local keyring (see
//! `dag-control`'s `SignatureLog`), and trusted verification is always
//! performed against the keyring's copy of the key, never the embedded one —
//! otherwise an attacker could claim any key ID and "verify" against their
//! own key. There is no PKI and no transparency log here; the keyring is the
//! trust root, and distributing it is deliberately out of scope.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Cid, ContentStore, CoreError, Entry, Link, MetaHint, MAX_CHUNK_SIZE};

/// Payload `kind` for a stored signature entry.
pub const SIGNATURE_KIND: &str = "signature/v1";
/// `MetaHint::content_type` recorded on signature entries.
pub const SIGNATURE_CONTENT_TYPE: &str = "application/vnd.dag.signature+json";
/// Largest JSON payload accepted for a stored signature record.
///
/// Signature predicates may legitimately occupy almost a whole chunk, so
/// this retains the store's existing 4 MiB compatibility contract while
/// making the parser's allocation ceiling explicit.
pub const MAX_SIGNATURE_RECORD_PAYLOAD_BYTES: usize = MAX_CHUNK_SIZE;
/// Maximum co-signatures accepted in one DSSE envelope.
///
/// Verification tests each signature cryptographically. Without a finite
/// cardinality ceiling, one otherwise bounded 4 MiB record can turn a single
/// verification or recovery classification into tens of thousands of
/// Ed25519 operations.
pub const MAX_DSSE_SIGNATURES: usize = 64;
/// Maximum encoded DSSE statement carried inside a stored record.
pub const MAX_DSSE_ENCODED_PAYLOAD_BYTES: usize = MAX_CHUNK_SIZE;
/// Maximum advisory key-ID or base64 signature field in one DSSE signature.
pub const MAX_DSSE_SIGNATURE_FIELD_BYTES: usize = 512;
/// Maximum payload-type string. The verifier requires the much shorter exact
/// in-toto media type, but this bound also keeps invalid-record reporting safe.
pub const MAX_DSSE_PAYLOAD_TYPE_BYTES: usize = 256;
/// Maximum subjects in a verified in-toto statement.
pub const MAX_STATEMENT_SUBJECTS: usize = 256;
/// Maximum digest algorithms recorded for one subject.
pub const MAX_SUBJECT_DIGESTS: usize = 16;
/// Maximum human name, predicate-type, digest key, or digest value string.
pub const MAX_STATEMENT_STRING_BYTES: usize = 2 * 1024;
/// The in-toto statement type this module produces.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// DSSE payload type for in-toto statements.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// Default predicate type for a bare "I vouch for this content" signature.
pub const DEFAULT_PREDICATE_TYPE: &str = "https://ilikedags.dev/attestation/signed-content/v1";

/// A key's identifier: the hex SHA-256 of its 32 raw public-key bytes.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// DSSE Pre-Authentication Encoding.
///
/// `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`,
/// lengths in ASCII decimal. This is the byte string that is actually signed;
/// getting it wrong silently breaks interop, which is why it has a golden
/// test against the spec's worked example.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 24);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// One subject of an in-toto statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// Human-oriented name; optional in spirit, empty string when unnamed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Digest set. For this system always `{"sha256": <cid hex>}`.
    pub digest: std::collections::BTreeMap<String, String>,
}

/// An in-toto Statement (v1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

impl Statement {
    /// A statement whose single subject is `cid`.
    pub fn for_cid(cid: &Cid, name: Option<String>, predicate: serde_json::Value) -> Self {
        Self::for_cid_with_type(cid, name, predicate, DEFAULT_PREDICATE_TYPE)
    }

    /// A statement whose single subject is `cid`, carrying a caller-chosen
    /// `predicateType`.
    ///
    /// `predicateType` is what external supply-chain verifiers dispatch on —
    /// it is how a SLSA Provenance statement is told from an SPDX document or
    /// a test result. Hardcoding it to this project's own URI meant the
    /// envelopes were structurally in-toto but could never be *anything* an
    /// existing verifier recognised.
    pub fn for_cid_with_type(
        cid: &Cid,
        name: Option<String>,
        predicate: serde_json::Value,
        predicate_type: &str,
    ) -> Self {
        let mut digest = std::collections::BTreeMap::new();
        digest.insert("sha256".to_string(), cid.to_hex());
        Self {
            statement_type: STATEMENT_TYPE.to_string(),
            subject: vec![Subject { name, digest }],
            predicate_type: predicate_type.to_string(),
            predicate,
        }
    }

    /// The sha256 subject digests as CIDs, in order.
    pub fn subject_cids(&self) -> Vec<Cid> {
        self.subject
            .iter()
            .filter_map(|s| s.digest.get("sha256"))
            .filter_map(|hex| Cid::from_hex(hex).ok())
            .collect()
    }
}

/// One signature within a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    /// Identifier of the signing key — advisory per DSSE; trust decisions
    /// must resolve it through a keyring, never take it at face value.
    pub keyid: String,
    /// Base64 Ed25519 signature over the PAE.
    pub sig: String,
}

/// A DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Base64 of the serialized statement.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

/// The payload of a stored `signature/v1` entry: the envelope, plus the
/// public key so internal validity is checkable without any keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRecord {
    pub kind: String,
    /// Hex SHA-256 of the public key (matches `envelope.signatures[0].keyid`).
    pub key_id: String,
    /// Hex of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    /// The DSSE envelope, verbatim — extractable for external tooling.
    pub envelope: Envelope,
}

/// Sign a statement, producing a single-signature envelope.
pub fn sign_statement(statement: &Statement, key: &SigningKey) -> Result<Envelope, CoreError> {
    validate_statement_resource_bounds(statement)?;
    let payload = serde_json::to_vec(statement)
        .map_err(|e| CoreError::Serialization(format!("statement: {}", e)))?;
    let signature = key.sign(&pae(PAYLOAD_TYPE, &payload));

    Ok(Envelope {
        payload: BASE64.encode(&payload),
        payload_type: PAYLOAD_TYPE.to_string(),
        signatures: vec![EnvelopeSignature {
            keyid: key_id(&key.verifying_key()),
            sig: BASE64.encode(signature.to_bytes()),
        }],
    })
}

/// Verify an envelope against a specific public key.
///
/// Returns the decoded statement on success. The key is the caller's choice —
/// pass the keyring's copy for a trust decision, or the embedded copy for an
/// internal-validity check — and that distinction is the heart of the trust
/// model, so this function deliberately does not pick for you.
///
/// Verification is **strict** ([`VerifyingKey::verify_strict`]): it rejects
/// small-order public keys and small-order `R` values. The permissive
/// cofactorless check that Ed25519 libraries have historically shipped
/// accepts signatures under a small-order key for *any* message, which here
/// would mean a signature nobody could have produced reading as authorship.
/// Signatures this system emits are unaffected — strictness only removes
/// forgeries.
pub fn verify_envelope(envelope: &Envelope, key: &VerifyingKey) -> Result<Statement, CoreError> {
    validate_envelope_resource_bounds(envelope)?;
    // What was signed is `PAE(payloadType, payload)`, so `payloadType` is
    // *inside* the signed bytes — but it is also chosen by whoever built the
    // envelope, and this used to take it as given. A key that signs
    // attestations in some other context therefore transplanted here: its
    // envelope verified (correctly, over its own type), the payload was then
    // read as an in-toto statement, and serde's leniency about unknown fields
    // did the rest. Pin the type this system speaks, which is what the DSSE
    // and in-toto specs say it is.
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(CoreError::Deserialization(format!(
            "envelope payloadType is {:?}, not {:?}: this is not an in-toto envelope",
            envelope.payload_type, PAYLOAD_TYPE
        )));
    }

    let payload = BASE64
        .decode(&envelope.payload)
        .map_err(|e| CoreError::Deserialization(format!("envelope payload: {}", e)))?;

    if envelope.signatures.is_empty() {
        return Err(CoreError::Deserialization(
            "envelope has no signatures".into(),
        ));
    }

    // Every signature, not just the first. A DSSE envelope is explicitly a
    // *set* of signatures over one payload, so co-signing is the normal way
    // two parties vouch for one artefact — and examining only `signatures[0]`
    // meant our key's signature counted only when it happened to be listed
    // first. `keyid` is a hint from the envelope and is not consulted: the
    // arithmetic decides.
    let signed = pae(&envelope.payload_type, &payload);
    let verified = envelope.signatures.iter().any(|signature| {
        let Ok(raw) = BASE64.decode(&signature.sig) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(raw) else {
            return false;
        };
        key.verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_ok()
    });
    if !verified {
        return Err(CoreError::InvalidCid(
            "no signature in the envelope verifies against key".into(),
        ));
    }

    let statement: Statement = serde_json::from_slice(&payload)
        .map_err(|e| CoreError::Deserialization(format!("statement: {}", e)))?;
    validate_statement_resource_bounds(&statement)?;

    // `_type` is the statement's own declaration of what it is, and the same
    // argument applies: a signed document of another shape that happens to
    // carry `subject` and `predicateType` would otherwise read as a v1
    // in-toto statement about this content.
    if statement.statement_type != STATEMENT_TYPE {
        return Err(CoreError::Deserialization(format!(
            "statement _type is {:?}, not {:?}",
            statement.statement_type, STATEMENT_TYPE
        )));
    }

    Ok(statement)
}

fn validate_envelope_resource_bounds(envelope: &Envelope) -> Result<(), CoreError> {
    if envelope.payload.len() > MAX_DSSE_ENCODED_PAYLOAD_BYTES {
        return Err(CoreError::Deserialization(format!(
            "DSSE encoded payload is {} bytes, above the {MAX_DSSE_ENCODED_PAYLOAD_BYTES}-byte safety limit",
            envelope.payload.len()
        )));
    }
    if envelope.payload_type.len() > MAX_DSSE_PAYLOAD_TYPE_BYTES {
        return Err(CoreError::Deserialization(format!(
            "DSSE payloadType is {} bytes, above the {MAX_DSSE_PAYLOAD_TYPE_BYTES}-byte safety limit",
            envelope.payload_type.len()
        )));
    }
    if envelope.signatures.len() > MAX_DSSE_SIGNATURES {
        return Err(CoreError::Deserialization(format!(
            "DSSE envelope has {} signatures, above the {MAX_DSSE_SIGNATURES}-signature safety limit",
            envelope.signatures.len()
        )));
    }
    for signature in &envelope.signatures {
        if signature.keyid.len() > MAX_DSSE_SIGNATURE_FIELD_BYTES
            || signature.sig.len() > MAX_DSSE_SIGNATURE_FIELD_BYTES
        {
            return Err(CoreError::Deserialization(format!(
                "DSSE signature key ID and value must each be at most {MAX_DSSE_SIGNATURE_FIELD_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_statement_resource_bounds(statement: &Statement) -> Result<(), CoreError> {
    if statement.subject.len() > MAX_STATEMENT_SUBJECTS {
        return Err(CoreError::Deserialization(format!(
            "in-toto statement has {} subjects, above the {MAX_STATEMENT_SUBJECTS}-subject safety limit",
            statement.subject.len()
        )));
    }
    if statement.statement_type.len() > MAX_STATEMENT_STRING_BYTES
        || statement.predicate_type.len() > MAX_STATEMENT_STRING_BYTES
    {
        return Err(CoreError::Deserialization(format!(
            "in-toto statement type strings must be at most {MAX_STATEMENT_STRING_BYTES} bytes"
        )));
    }
    for subject in &statement.subject {
        if subject
            .name
            .as_ref()
            .is_some_and(|name| name.len() > MAX_STATEMENT_STRING_BYTES)
            || subject.digest.len() > MAX_SUBJECT_DIGESTS
            || subject.digest.iter().any(|(algorithm, digest)| {
                algorithm.len() > MAX_STATEMENT_STRING_BYTES
                    || digest.len() > MAX_STATEMENT_STRING_BYTES
            })
        {
            return Err(CoreError::Deserialization(format!(
                "in-toto subject exceeds the name or {MAX_SUBJECT_DIGESTS}-digest safety limit"
            )));
        }
    }
    Ok(())
}

/// Sign `target` and store the signature as an entry linking to it.
///
/// Returns the signature entry's CID. The entry's `signs` link is what makes
/// the signature part of the graph — walkable, pinnable, collectable.
pub fn sign_cid<S: ContentStore + ?Sized>(
    store: &S,
    target: &Cid,
    name: Option<String>,
    predicate: serde_json::Value,
    key: &SigningKey,
) -> Result<Cid, CoreError> {
    sign_cid_with_type(store, target, name, predicate, DEFAULT_PREDICATE_TYPE, key)
}

/// [`sign_cid`], with a caller-chosen `predicateType`.
pub fn sign_cid_with_type<S: ContentStore + ?Sized>(
    store: &S,
    target: &Cid,
    name: Option<String>,
    predicate: serde_json::Value,
    predicate_type: &str,
    key: &SigningKey,
) -> Result<Cid, CoreError> {
    // Refuse to sign content we cannot read: a signature over an absent CID
    // is an attestation nobody could have checked.
    let bytes = store.get_chunk(target)?;
    let computed = Cid::compute(&bytes);
    if computed != *target {
        return Err(CoreError::InvalidCid(format!(
            "refusing to sign {}: stored bytes hash to {}",
            target, computed
        )));
    }

    let statement = Statement::for_cid_with_type(target, name, predicate, predicate_type);
    let envelope = sign_statement(&statement, key)?;

    let record = SignatureRecord {
        kind: SIGNATURE_KIND.to_string(),
        key_id: key_id(&key.verifying_key()),
        public_key: hex::encode(key.verifying_key().as_bytes()),
        envelope,
    };
    let payload = serde_json::to_vec(&record)
        .map_err(|e| CoreError::Serialization(format!("signature record: {}", e)))?;

    let entry = Entry::new(
        payload,
        vec![Link::named(target.clone(), "signs")],
        Some(MetaHint {
            content_type: Some(SIGNATURE_CONTENT_TYPE.to_string()),
            encoding: None,
        }),
    );
    store.put_entry(&entry)
}

/// Import an externally-produced DSSE envelope as a stored signature entry.
///
/// The other half of `dag signatures --out-dir`: an envelope minted by some
/// other holder of this format — another dag deployment, a CI signer, any
/// tool emitting Ed25519 DSSE over in-toto v1 — becomes an ordinary
/// `signature/v1` entry, walkable and verifiable exactly like a local one.
///
/// Nothing is stored until the whole gauntlet passes:
///
/// - the signature verifies (strictly) against `public_key` — a caller must
///   *have* a key it checks out under, because storing an unverifiable blob
///   in a provenance store is how a provenance store stops meaning anything;
/// - the payload parses as an in-toto v1 statement naming **exactly one**
///   sha256 subject, which is the CID the `signs` link will point at;
/// - that CID matches `expect_target` when the caller states one;
/// - the target's bytes are present and hash-intact locally, the same rule
///   `sign_cid` applies — an attestation over content this store cannot
///   produce is not evidence of anything here.
///
/// The embedded key in the stored record is `public_key`, so `verify`
/// reports the imported signature `valid`; whether it is *trusted* remains,
/// as ever, the local keyring's call. Ed25519 only — an ECDSA envelope
/// (cosign's default) fails verification and is refused with the DSSE
/// signature error, not silently stored.
///
/// Returns the signature entry's CID and the target it covers.
pub fn import_envelope<S: ContentStore + ?Sized>(
    store: &S,
    envelope: Envelope,
    public_key: &VerifyingKey,
    expect_target: Option<&Cid>,
) -> Result<(Cid, Cid), CoreError> {
    let statement = verify_envelope(&envelope, public_key)?;

    let subjects = statement.subject_cids();
    let target = match subjects.as_slice() {
        [one] => one.clone(),
        [] => {
            return Err(CoreError::Deserialization(
                "statement names no sha256 subject; nothing to link the signature to".into(),
            ))
        }
        many => {
            return Err(CoreError::Deserialization(format!(
                "statement names {} sha256 subjects; import links a signature to exactly one",
                many.len()
            )))
        }
    };

    if let Some(expected) = expect_target {
        if &target != expected {
            return Err(CoreError::InvalidCid(format!(
                "envelope covers {}, not the requested {}",
                target, expected
            )));
        }
    }

    // The same refusal `sign_cid` makes, for the same reason.
    let bytes = store.get_chunk(&target)?;
    let computed = Cid::compute(&bytes);
    if computed != target {
        return Err(CoreError::InvalidCid(format!(
            "refusing to import a signature over {}: stored bytes hash to {}",
            target, computed
        )));
    }

    let record = SignatureRecord {
        kind: SIGNATURE_KIND.to_string(),
        key_id: key_id(public_key),
        public_key: hex::encode(public_key.as_bytes()),
        envelope,
    };
    let payload = serde_json::to_vec(&record)
        .map_err(|e| CoreError::Serialization(format!("signature record: {}", e)))?;

    let entry = Entry::new(
        payload,
        vec![Link::named(target.clone(), "signs")],
        Some(MetaHint {
            content_type: Some(SIGNATURE_CONTENT_TYPE.to_string()),
            encoding: None,
        }),
    );
    let sig_cid = store.put_entry(&entry)?;
    Ok((sig_cid, target))
}

/// Decode a stored signature entry, if that is what the bytes are.
pub fn record_from_bytes(bytes: &[u8]) -> Option<(SignatureRecord, Entry)> {
    // Callers also use this parser while inspecting filesystem inventory.
    // Reject an oversized raw chunk before CBOR can allocate from attacker-
    // controlled lengths, even when the bytes did not enter through a store
    // implementation that enforces invariant I2.
    if bytes.len() > MAX_CHUNK_SIZE {
        return None;
    }
    let entry = Entry::from_bytes_cbor(bytes).ok()?;
    if entry.payload.len() > MAX_SIGNATURE_RECORD_PAYLOAD_BYTES {
        return None;
    }
    let record: SignatureRecord = serde_json::from_slice(&entry.payload).ok()?;
    if record.kind != SIGNATURE_KIND {
        return None;
    }
    if record.key_id.len() > MAX_DSSE_SIGNATURE_FIELD_BYTES
        || record.public_key.len() > MAX_DSSE_SIGNATURE_FIELD_BYTES
        || validate_envelope_resource_bounds(&record.envelope).is_err()
    {
        return None;
    }
    // A signature record covers exactly one target. Accepting additional
    // links turns a schema-shaped record into an arbitrary fan-out root for
    // recovery, sync, pinning and GC.
    if entry.links.len() != 1 || entry.links[0].name.as_deref() != Some("signs") {
        return None;
    }
    Some((record, entry))
}

/// Parse a hex public key into a verifying key.
///
/// Small-order ("weak") points are refused here rather than at verification
/// time, so no call site can hold one: a key whose order divides 8 admits
/// forged signatures over arbitrary content, so it is not a key at all — it
/// is a way of claiming to have signed something. Refusing it at parse time
/// also keeps it out of the keyring.
pub fn verifying_key_from_hex(hex_key: &str) -> Result<VerifyingKey, CoreError> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .map_err(|e| CoreError::Deserialization(format!("public key hex: {}", e)))?
        .try_into()
        .map_err(|_| CoreError::Deserialization("public key is not 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CoreError::Deserialization(format!("public key: {}", e)))?;
    if key.is_weak() {
        return Err(CoreError::PreconditionFailed(
            "public key is a small-order Ed25519 point: signatures under it prove nothing".into(),
        ));
    }
    Ok(key)
}

/// The Ed25519 SubjectPublicKeyInfo (SPKI) DER prefix, RFC 8410 §10.1:
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00 || key } }`.
/// Ed25519 keys carry no algorithm parameters, so the whole structure is this
/// fixed twelve-byte header followed by the 32 raw public-key bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A verifying key as PKIX/SPKI DER — the 44-byte "public key" encoding that
/// `openssl`, `cosign` and the supply-chain ecosystem read, as opposed to
/// this system's raw 32-byte form.
pub fn public_key_spki_der(key: &VerifyingKey) -> [u8; 44] {
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&ED25519_SPKI_PREFIX);
    der[12..].copy_from_slice(key.as_bytes());
    der
}

/// A verifying key as a PKIX PEM (`-----BEGIN PUBLIC KEY-----`).
///
/// This is the other half of external consumability: `dag signatures` exports
/// the DSSE envelope, and this exports the key it was signed with, in the one
/// format an external verifier accepts without hand-assembling DER. Body lines
/// are wrapped at 64 characters, as PEM readers expect.
pub fn public_key_pem(key: &VerifyingKey) -> String {
    let b64 = BASE64.encode(public_key_spki_der(key));
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        // `line` is ASCII base64 by construction.
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn parseable_record_entry(links: Vec<Link>) -> Entry {
        let record = SignatureRecord {
            kind: SIGNATURE_KIND.to_string(),
            key_id: "test-key".to_string(),
            public_key: hex::encode([7u8; 32]),
            envelope: Envelope {
                payload: BASE64.encode(b"{}"),
                payload_type: PAYLOAD_TYPE.to_string(),
                signatures: Vec::new(),
            },
        };
        Entry::new(serde_json::to_vec(&record).unwrap(), links, None)
    }

    #[test]
    fn stored_signature_records_require_exactly_one_signs_link() {
        let target = Cid::compute(b"target");
        let valid = parseable_record_entry(vec![Link::named(target.clone(), "signs")]);
        assert!(record_from_bytes(&valid.to_bytes_cbor().unwrap()).is_some());

        let no_links = parseable_record_entry(Vec::new());
        assert!(record_from_bytes(&no_links.to_bytes_cbor().unwrap()).is_none());

        let wrong_name = parseable_record_entry(vec![Link::named(target.clone(), "covers")]);
        assert!(record_from_bytes(&wrong_name.to_bytes_cbor().unwrap()).is_none());

        let unnamed = parseable_record_entry(vec![Link::unnamed(target.clone())]);
        assert!(record_from_bytes(&unnamed.to_bytes_cbor().unwrap()).is_none());

        let fanout = parseable_record_entry(vec![
            Link::named(target, "signs"),
            Link::named(Cid::compute(b"smuggled"), "signs"),
        ]);
        assert!(record_from_bytes(&fanout.to_bytes_cbor().unwrap()).is_none());
    }

    #[test]
    fn stored_signature_parser_refuses_oversized_input_before_cbor_decode() {
        let oversized = vec![0u8; MAX_CHUNK_SIZE + 1];
        assert!(record_from_bytes(&oversized).is_none());
    }

    #[test]
    fn dsse_signature_fan_in_is_bounded_before_cryptographic_work() {
        let key = test_key(23);
        let statement = Statement::for_cid(&Cid::compute(b"target"), None, serde_json::json!({}));
        let mut envelope = sign_statement(&statement, &key).unwrap();
        envelope.signatures = vec![envelope.signatures[0].clone(); MAX_DSSE_SIGNATURES + 1];

        assert!(matches!(
            verify_envelope(&envelope, &key.verifying_key()),
            Err(CoreError::Deserialization(message)) if message.contains("safety limit")
        ));

        let record = SignatureRecord {
            kind: SIGNATURE_KIND.to_string(),
            key_id: key_id(&key.verifying_key()),
            public_key: hex::encode(key.verifying_key().as_bytes()),
            envelope,
        };
        let entry = Entry::new(
            serde_json::to_vec(&record).unwrap(),
            vec![Link::named(Cid::compute(b"target"), "signs")],
            None,
        );
        assert!(record_from_bytes(&entry.to_bytes_cbor().unwrap()).is_none());
    }

    #[test]
    fn statement_subject_fan_out_is_bounded_before_signing() {
        let key = test_key(24);
        let mut statement =
            Statement::for_cid(&Cid::compute(b"target"), None, serde_json::json!({}));
        statement.subject = vec![statement.subject[0].clone(); MAX_STATEMENT_SUBJECTS + 1];
        assert!(matches!(
            sign_statement(&statement, &key),
            Err(CoreError::Deserialization(message)) if message.contains("subject safety limit")
        ));
    }

    /// The spec's own worked example — the one place interop can silently
    /// break.
    #[test]
    fn pae_matches_the_dsse_spec_example() {
        let encoded = pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            encoded,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = test_key(1);
        let cid = Cid::compute(b"some content");
        let statement = Statement::for_cid(&cid, Some("model.bin".into()), serde_json::json!({}));

        let envelope = sign_statement(&statement, &key).unwrap();
        let decoded = verify_envelope(&envelope, &key.verifying_key()).unwrap();

        assert_eq!(decoded.subject_cids(), vec![cid]);
        assert_eq!(decoded.subject[0].name.as_deref(), Some("model.bin"));
        assert_eq!(envelope.signatures[0].keyid, key_id(&key.verifying_key()));
    }

    #[test]
    fn a_tampered_payload_fails_verification() {
        let key = test_key(2);
        let cid = Cid::compute(b"original");
        let statement = Statement::for_cid(&cid, None, serde_json::json!({}));
        let mut envelope = sign_statement(&statement, &key).unwrap();

        // Swap the subject for different content, keeping the signature.
        let other = Statement::for_cid(
            &Cid::compute(b"attacker content"),
            None,
            serde_json::json!({}),
        );
        envelope.payload = BASE64.encode(serde_json::to_vec(&other).unwrap());

        assert!(verify_envelope(&envelope, &key.verifying_key()).is_err());
    }

    #[test]
    fn the_wrong_key_fails_verification() {
        let key = test_key(3);
        let statement = Statement::for_cid(&Cid::compute(b"x"), None, serde_json::json!({}));
        let envelope = sign_statement(&statement, &key).unwrap();

        let other = test_key(4);
        assert!(verify_envelope(&envelope, &other.verifying_key()).is_err());
    }

    /// A key that signs in some other context must not have its work read as
    /// an in-toto statement about content here. The signature below is
    /// genuine — over a *different* `payloadType`, which is inside the signed
    /// bytes and was previously taken as given.
    #[test]
    fn an_envelope_of_another_payload_type_is_refused() {
        let key = test_key(11);
        let statement = Statement::for_cid(&Cid::compute(b"x"), None, serde_json::json!({}));
        let payload = serde_json::to_vec(&statement).unwrap();
        let foreign = "application/vnd.dev.cosign.simplesigning.v1+json";

        let envelope = Envelope {
            payload: BASE64.encode(&payload),
            payload_type: foreign.to_string(),
            signatures: vec![EnvelopeSignature {
                keyid: key_id(&key.verifying_key()),
                sig: BASE64.encode(key.sign(&pae(foreign, &payload)).to_bytes()),
            }],
        };

        let err = verify_envelope(&envelope, &key.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("payloadType"), "{err}");
    }

    /// And the statement's own `_type`: a signed document carrying `subject`
    /// and `predicateType` is not thereby an in-toto v1 statement.
    #[test]
    fn a_statement_of_another_type_is_refused() {
        let key = test_key(12);
        let mut statement = Statement::for_cid(&Cid::compute(b"x"), None, serde_json::json!({}));
        statement.statement_type = "https://in-toto.io/Statement/v0.1".to_string();
        let envelope = sign_statement(&statement, &key).unwrap();

        let err = verify_envelope(&envelope, &key.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("_type"), "{err}");
    }

    /// DSSE envelopes carry a *set* of signatures — co-signing is how two
    /// parties vouch for one artefact. Reading only `signatures[0]` meant a
    /// key's own signature counted only when it happened to be listed first.
    #[test]
    fn a_co_signed_envelope_verifies_for_every_signer() {
        let first = test_key(13);
        let second = test_key(14);
        let statement = Statement::for_cid(&Cid::compute(b"shared"), None, serde_json::json!({}));
        let payload = serde_json::to_vec(&statement).unwrap();
        let signed = pae(PAYLOAD_TYPE, &payload);

        let envelope = Envelope {
            payload: BASE64.encode(&payload),
            payload_type: PAYLOAD_TYPE.to_string(),
            signatures: [&first, &second]
                .iter()
                .map(|k| EnvelopeSignature {
                    keyid: key_id(&k.verifying_key()),
                    sig: BASE64.encode(k.sign(&signed).to_bytes()),
                })
                .collect(),
        };

        assert!(verify_envelope(&envelope, &first.verifying_key()).is_ok());
        assert!(
            verify_envelope(&envelope, &second.verifying_key()).is_ok(),
            "the second signer's own signature did not count"
        );
        // And a third party still gets nothing.
        assert!(verify_envelope(&envelope, &test_key(15).verifying_key()).is_err());
    }

    /// A garbled signature alongside a good one must not veto it, and must
    /// not be a way to make verification error out.
    #[test]
    fn an_unparseable_signature_does_not_block_a_good_one() {
        let key = test_key(16);
        let statement = Statement::for_cid(&Cid::compute(b"y"), None, serde_json::json!({}));
        let mut envelope = sign_statement(&statement, &key).unwrap();
        envelope.signatures.insert(
            0,
            EnvelopeSignature {
                keyid: "not a key id".into(),
                sig: "!!! not base64 !!!".into(),
            },
        );

        assert!(verify_envelope(&envelope, &key.verifying_key()).is_ok());
    }

    /// The eight canonical small-order points on Curve25519, compressed. A
    /// public key that is one of these carries no authorship information:
    /// every scalar multiple of it lands back in a set of eight, so the
    /// verification equation can be satisfied without knowing any secret.
    const SMALL_ORDER_KEYS: [&str; 8] = [
        // order 1 (identity)
        "0100000000000000000000000000000000000000000000000000000000000000",
        // order 2
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // order 4
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        // order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    /// Forge a signature that the *cofactorless* verification equation
    /// `[s]B = R + [k]A` accepts for any message, using the identity as the
    /// public key: `[k]A` is the identity for every `k`, so `R = identity`
    /// with `s = 0` balances the equation without a secret existing at all.
    fn small_order_forgery(statement: &Statement) -> (VerifyingKey, Envelope) {
        let identity: [u8; 32] = hex::decode(SMALL_ORDER_KEYS[0])
            .unwrap()
            .try_into()
            .unwrap();
        let key = VerifyingKey::from_bytes(&identity).unwrap();

        let payload = serde_json::to_vec(statement).unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity); // R = identity, s = 0

        (
            key,
            Envelope {
                payload: BASE64.encode(&payload),
                payload_type: PAYLOAD_TYPE.to_string(),
                signatures: vec![EnvelopeSignature {
                    keyid: key_id(&key),
                    sig: BASE64.encode(sig),
                }],
            },
        )
    }

    /// Non-strict Ed25519 verification accepts signatures under small-order
    /// keys — an attacker picks such a key and "signs" content they have
    /// never seen. Verification here must be strict.
    #[test]
    fn a_small_order_key_cannot_forge_a_signature() {
        let statement = Statement::for_cid(
            &Cid::compute(b"content the attacker never possessed"),
            Some("model.bin".into()),
            serde_json::json!({"verdict": "accepted"}),
        );
        let (weak_key, envelope) = small_order_forgery(&statement);
        assert!(
            weak_key.is_weak(),
            "test vector must be a small-order point"
        );

        assert!(
            verify_envelope(&envelope, &weak_key).is_err(),
            "SMALL-ORDER FORGERY ACCEPTED: a signature nobody could have produced verified"
        );
    }

    /// Belt and braces: weak keys never become `VerifyingKey`s in the first
    /// place, so no call site can accidentally verify against one.
    #[test]
    fn weak_public_keys_are_refused_at_parse_time() {
        let mut checked = 0;
        for hex_key in SMALL_ORDER_KEYS {
            let bytes: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
            // Some encodings in the list may not decompress on a given
            // curve implementation; those are already unusable.
            let Ok(raw) = VerifyingKey::from_bytes(&bytes) else {
                continue;
            };
            assert!(raw.is_weak(), "{hex_key} should be a small-order point");
            assert!(
                verifying_key_from_hex(hex_key).is_err(),
                "{hex_key} is a weak key and must not parse"
            );
            checked += 1;
        }
        assert!(
            checked >= 5,
            "expected most of the small-order set to decompress, got {checked}"
        );

        // A real key still parses.
        let good = test_key(9).verifying_key();
        assert!(verifying_key_from_hex(&hex::encode(good.as_bytes())).is_ok());
    }

    /// The `SMALL_ORDER_KEYS` table lists the eight *canonical* torsion-point
    /// encodings. Small-order points also have *non-canonical* encodings —
    /// `y` in `[p, 2^255)`, which the field arithmetic reduces mod `p` before
    /// decompression — and published small-order blacklists run to fourteen
    /// entries for exactly this reason. The rejection must not depend on
    /// canonicalisation of the encoding: it hangs on [`VerifyingKey::is_weak`],
    /// which inspects the *decompressed* point's order, so a non-canonical
    /// encoding of a torsion point is caught the same as its canonical twin.
    ///
    /// This test builds the non-canonical encodings of `y = 0` (order 4) and
    /// `y = 1` (the identity) — `p` and `p+1`, each with both sign bits — and
    /// asserts every one is refused at parse time, and that a forgery signed
    /// under the non-canonical identity is rejected by `verify_envelope`.
    #[test]
    fn noncanonical_small_order_encodings_are_also_refused() {
        // p little-endian: low byte 0xed, high byte 0x7f, 0xff between.
        let mut p_le = [0xffu8; 32];
        p_le[0] = 0xed;
        p_le[31] = 0x7f;

        let mut noncanonical: Vec<[u8; 32]> = Vec::new();
        for add in [0u8, 1u8] {
            // y = p (reduces to 0) and y = p+1 (reduces to 1).
            let mut y = p_le;
            y[0] = y[0].wrapping_add(add);
            for signbit in [0x00u8, 0x80u8] {
                let mut e = y;
                e[31] |= signbit;
                noncanonical.push(e);
            }
        }

        for enc in &noncanonical {
            let hex_key = hex::encode(enc);
            // These decompress on this curve implementation, and the
            // decompressed point is small-order...
            let raw = VerifyingKey::from_bytes(enc)
                .unwrap_or_else(|e| panic!("{hex_key} should decompress: {e}"));
            assert!(
                raw.is_weak(),
                "{hex_key} decompresses to a small-order point"
            );
            // ...so the parse gate must refuse it, canonical or not.
            assert!(
                verifying_key_from_hex(&hex_key).is_err(),
                "SMALL-ORDER ENCODING ADMITTED: non-canonical {hex_key} parsed as a key"
            );
        }

        // And verify_envelope (strict) rejects the s=0/R=identity forgery even
        // when the identity is presented in its non-canonical `p+1` encoding —
        // proving the strict verifier, not just the parse gate, holds the line.
        let noncanon_identity: [u8; 32] = {
            let mut e = p_le;
            e[0] = 0xee; // p+1 -> 1
            e
        };
        let weak = VerifyingKey::from_bytes(&noncanon_identity).unwrap();
        assert!(weak.is_weak());
        let statement = Statement::for_cid(
            &Cid::compute(b"never possessed"),
            None,
            serde_json::json!({}),
        );
        let payload = serde_json::to_vec(&statement).unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&noncanon_identity); // R = identity (non-canonical), s = 0
        let envelope = Envelope {
            payload: BASE64.encode(&payload),
            payload_type: PAYLOAD_TYPE.to_string(),
            signatures: vec![EnvelopeSignature {
                keyid: key_id(&weak),
                sig: BASE64.encode(sig),
            }],
        };
        assert!(
            verify_envelope(&envelope, &weak).is_err(),
            "NON-CANONICAL SMALL-ORDER FORGERY ACCEPTED by verify_envelope"
        );
    }

    /// The PEM export has to be a real PKIX public key: the fixed Ed25519
    /// SPKI header, then the raw 32 key bytes, base64 inside the armour. An
    /// external verifier reads exactly this and nothing else.
    #[test]
    fn public_key_pem_is_wrapped_spki_der() {
        let key = test_key(5).verifying_key();

        let der = public_key_spki_der(&key);
        assert_eq!(der.len(), 44);
        assert_eq!(
            hex::encode(&der[..12]),
            "302a300506032b6570032100",
            "the RFC 8410 Ed25519 SPKI header"
        );
        assert_eq!(&der[12..], key.as_bytes(), "the raw key follows verbatim");

        let pem = public_key_pem(&key);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(
            BASE64.decode(body).unwrap(),
            der,
            "the PEM body decodes back to the SPKI DER"
        );
    }

    #[test]
    fn statements_are_valid_in_toto() {
        let cid = Cid::compute(b"artifact");
        let statement = Statement::for_cid(
            &cid,
            Some("artifact".into()),
            serde_json::json!({"note": "v1"}),
        );
        let json = serde_json::to_value(&statement).unwrap();

        // The exact field names the in-toto ecosystem expects.
        assert_eq!(json["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(json["subject"][0]["digest"]["sha256"], cid.to_hex());
        assert_eq!(json["predicateType"], DEFAULT_PREDICATE_TYPE);
        assert_eq!(json["predicate"]["note"], "v1");
    }
}
