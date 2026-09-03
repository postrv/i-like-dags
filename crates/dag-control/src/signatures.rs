//! The signature index and the local trust keyring.
//!
//! Signature entries live in the content store (see `dag_core::signing`);
//! this module maintains two derived tables over them:
//!
//! - `sig_by_target`: target CID → the signature entries covering it, so
//!   verification doesn't have to walk the world. Rebuildable by scanning
//!   the store, like every other derived table in this system.
//! - `trusted_keys`: the local keyring — key ID → public key + comment. This
//!   is the trust root. There is no PKI behind it; `dag key trust` is the
//!   act of trust, and the keyring answers for it.
//!
//! ## The verification rule that matters
//!
//! A signature names its key ID, and the stored record embeds a public key.
//! For a **trusted** verdict the signature is verified against the keyring's
//! copy of the key for that ID — never the embedded one. The embedded key
//! only supports the weaker verdict "internally valid": self-consistent, but
//! vouched for by nobody you've chosen to trust. Verifying trusted claims
//! against embedded keys would let anyone claim any key ID.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use crate::error::{ControlError, Result};
use dag_core::signing::{self, SignatureRecord};
use dag_core::{Cid, ContentStore, CoreError};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};

const SIG_BY_TARGET: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sig_by_target");
const TRUSTED_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("trusted_keys");

type RankedSignatures = BTreeMap<(u8, Vec<u8>), Cid>;
type TrustedSignatureRepresentatives = BTreeMap<Vec<u8>, (Vec<u8>, Cid)>;

/// Per-target index ceiling. Verification is cryptographic work and the
/// current on-disk index is one CBOR row, so both writers and rebuilds must
/// keep that row finite.
pub const MAX_SIGNATURES_PER_TARGET: usize = 4_096;

/// Maximum number of signature entries one retention/synchronisation closure
/// may discover.  A corrupt index can describe cycles and a hostile but valid
/// store can build an arbitrarily wide counter-signature graph; callers must
/// fail closed instead of allocating until the process is killed.
pub const MAX_SIGNATURE_CLOSURE_ENTRIES: usize = 1_000_000;

/// Refuse a corrupt or legacy index row before copying/deserializing it.
const MAX_SIGNATURE_INDEX_BYTES: usize = MAX_SIGNATURES_PER_TARGET * 96 + 64;

/// Maximum local trust roots. Trust is operator-managed primary state, but
/// list/import/recovery paths still need a finite cardinality contract.
pub const MAX_TRUSTED_KEYS: usize = 4_096;
/// Maximum encoded keyring row copied or decoded from redb.
const MAX_TRUSTED_KEY_ROW_BYTES: usize = 16 * 1024;
/// Maximum operator comment stored with one trust root.
pub const MAX_TRUSTED_KEY_COMMENT_BYTES: usize = 4 * 1024;
/// Forward-compatible unknown purposes remain inert, but their representation
/// cannot be an unbounded database or terminal-output payload.
const MAX_TRUSTED_KEY_PURPOSES: usize = 16;
const MAX_TRUSTED_KEY_PURPOSE_BYTES: usize = 128;

/// Default whole-operation ceiling for non-paged CLI/library verification and
/// export. HTTP verification is separately paged and response-budgeted.
pub const MAX_SIGNATURE_AGGREGATE_RECORDS: usize = 256;
/// Maximum stored signature bytes one non-paged operation will retain/decode.
pub const MAX_SIGNATURE_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;

fn db_err(e: impl std::fmt::Display) -> ControlError {
    ControlError::db("signature log", e)
}

/// A keyring entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    /// Hex SHA-256 of the public key.
    pub key_id: String,
    /// Hex of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    /// Operator note: whose key this is.
    pub comment: Option<String>,
    /// When trust was granted (POSIX seconds).
    pub added_at: i64,
    /// What this grant covers, as recorded purpose strings (ADR-004).
    ///
    /// Empty marks an entry written before purposes existed — when trust
    /// meant verification — and is read as exactly `["verify"]`. Strings
    /// this build does not recognise are inert: they grant nothing here,
    /// and they do not make the entry unreadable.
    #[serde(default)]
    pub purposes: Vec<String>,
}

/// What a trust grant permits — one variant per enforcement point that
/// honours the keyring (ADR-004). A purpose names a *power*, not a
/// predicate vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPurpose {
    /// Signatures by the key earn the trusted verdict in verification
    /// (`dag verify`, the signatures API).
    Verify,
    /// Effect claims signed by the key may be adopted in place of
    /// execution (ADR-003, invariant J7).
    Adopt,
}

impl TrustPurpose {
    /// The string recorded in [`TrustedKey::purposes`].
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustPurpose::Verify => "verify",
            TrustPurpose::Adopt => "adopt",
        }
    }
}

impl std::str::FromStr for TrustPurpose {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verify" => Ok(TrustPurpose::Verify),
            "adopt" => Ok(TrustPurpose::Adopt),
            other => Err(format!(
                "unknown trust purpose {:?}: expected \"verify\" or \"adopt\"",
                other
            )),
        }
    }
}

impl TrustedKey {
    /// Whether this grant covers `purpose`.
    pub fn grants(&self, purpose: TrustPurpose) -> bool {
        if self.purposes.is_empty() {
            // Pre-ADR-004 entry: granted when trust meant verification.
            return purpose == TrustPurpose::Verify;
        }
        self.purposes.iter().any(|p| p == purpose.as_str())
    }

    /// The purposes this entry actually means, legacy form resolved.
    pub fn effective_purposes(&self) -> Vec<String> {
        if self.purposes.is_empty() {
            vec![TrustPurpose::Verify.as_str().to_string()]
        } else {
            self.purposes.clone()
        }
    }
}

/// The verdict on one signature.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureStatus {
    /// CID of the signature entry itself.
    pub signature_cid: Cid,
    /// Key ID the signature claims.
    pub key_id: String,
    /// Signer comment from the keyring, when trusted.
    pub signer: Option<String>,
    /// Verified against the keyring's copy of the key, for the purpose the
    /// caller asked about (ADR-004).
    pub trusted: bool,
    /// The keyring entry's effective purposes, for display; empty when the
    /// key is not in the keyring at all.
    pub key_purposes: Vec<String>,
    /// Verified against the embedded key only — self-consistent, unvouched.
    pub valid: bool,
    /// The statement's predicate, surfaced for display.
    pub predicate: serde_json::Value,
}

/// How many *distinct* keys earned the trusted verdict in `statuses`.
///
/// Gates spelled "at least N trusted signatures" — `dag verify
/// --min-trusted N`, the signatures API's `trusted` count — are selling
/// N *independent* signers. Counting signature entries would sell that
/// guarantee to anyone holding one trusted key, who need only sign the same
/// target twice; a key restating its own opinion is one opinion. Signatures
/// stay individually reported, so nothing is hidden by the narrower count.
pub fn distinct_trusted_keys(statuses: &[SignatureStatus]) -> usize {
    distinct_keys(statuses, |s| s.trusted)
}

/// How many distinct keys produced an internally valid signature, counted
/// the same way and for the same reason as [`distinct_trusted_keys`].
pub fn distinct_valid_keys(statuses: &[SignatureStatus]) -> usize {
    distinct_keys(statuses, |s| s.valid)
}

fn distinct_keys(
    statuses: &[SignatureStatus],
    verdict: impl Fn(&SignatureStatus) -> bool,
) -> usize {
    statuses
        .iter()
        .filter(|s| verdict(s))
        .map(|s| s.key_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// Whether a stored record is a genuine signature of `target` under the
/// public key embedded in the record. The derived lookup is an accelerator,
/// not an authority: recovery must not turn merely schema-shaped user content
/// into filed evidence.
fn internally_valid_for_target(record: &SignatureRecord, target: &Cid) -> bool {
    let Ok(key) = signing::verifying_key_from_hex(&record.public_key) else {
        return false;
    };
    if signing::key_id(&key) != record.key_id {
        return false;
    }
    signature_covers_target(record, target, &key)
}

fn signature_covers_target(
    record: &SignatureRecord,
    target: &Cid,
    key: &ed25519_dalek::VerifyingKey,
) -> bool {
    signing::verify_envelope(&record.envelope, key)
        .map(|statement| statement.subject_cids().contains(target))
        .unwrap_or(false)
}

fn validate_trusted_key_entry(entry: &TrustedKey, expected_key_id: Option<&str>) -> Result<()> {
    let key = signing::verifying_key_from_hex(&entry.public_key).map_err(|error| {
        ControlError::Database(format!(
            "trusted-key row has an invalid public key: {error}"
        ))
    })?;
    let derived = signing::key_id(&key);
    if entry.key_id != derived || expected_key_id.is_some_and(|expected| expected != entry.key_id) {
        return Err(ControlError::Database(
            "trusted-key row key ID does not match its table key and public key".into(),
        ));
    }
    if entry.comment.as_ref().is_some_and(|comment| {
        comment.len() > MAX_TRUSTED_KEY_COMMENT_BYTES || comment.chars().any(char::is_control)
    }) {
        return Err(ControlError::Database(format!(
            "trusted-key comment exceeds {MAX_TRUSTED_KEY_COMMENT_BYTES} bytes or contains control characters"
        )));
    }
    if entry.purposes.len() > MAX_TRUSTED_KEY_PURPOSES
        || entry.purposes.iter().any(|purpose| {
            purpose.is_empty()
                || purpose.len() > MAX_TRUSTED_KEY_PURPOSE_BYTES
                || purpose.chars().any(char::is_control)
        })
    {
        return Err(ControlError::Database(format!(
            "trusted-key purposes exceed the {MAX_TRUSTED_KEY_PURPOSES}-item/{MAX_TRUSTED_KEY_PURPOSE_BYTES}-byte safety limits"
        )));
    }
    Ok(())
}

/// Signature index + keyring over the shared control-plane database.
pub struct SignatureLog<S: ContentStore> {
    store: Arc<S>,
    db: Arc<Database>,
    /// Serialises read-modify-write on the per-target signature lists.
    write_lock: Mutex<()>,
    /// Cross-log recovery barrier. See [`crate::MutationGate`].
    mutation_gate: crate::MutationGate,
}

/// Encoded replacement rows for the derived signature lookup.
pub(crate) struct SignatureRebuildPlan {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    count: u32,
}

/// Encoded updates for only the signature targets implicated by one sync.
/// Unlike a recovery rebuild, applying this plan never clears unrelated rows.
pub(crate) struct SignatureMergePlan {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    added: u32,
}

impl SignatureRebuildPlan {
    pub(crate) fn count(&self) -> u32 {
        self.count
    }
}

impl SignatureMergePlan {
    pub(crate) fn added(&self) -> u32 {
        self.added
    }
}

impl<S: ContentStore + 'static> SignatureLog<S> {
    /// Signature CIDs represented by the derived lookup a full recovery replaces.
    ///
    /// Counting table rows would let one target hide thousands of decoded
    /// entries behind a single unit of the recovery/GC control-state budget.
    /// A malformed legacy row is derived state and recovery must be able to
    /// replace it, so count it as one over the supported per-target maximum
    /// without attempting an unbounded decode.
    pub(crate) fn recovery_row_count(&self) -> Result<u64> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
        let mut total = 0u64;
        for row in table.range::<&[u8]>(..).map_err(db_err)? {
            let (_, value) = row.map_err(db_err)?;
            let represented = Self::decode_signature_row_unlabelled(value.value())
                .map(|signatures| signatures.len())
                .unwrap_or(MAX_SIGNATURES_PER_TARGET + 1);
            total =
                total
                    .checked_add(u64::try_from(represented).map_err(|_| {
                        ControlError::Capacity("signature index count overflow".into())
                    })?)
                    .ok_or_else(|| {
                        ControlError::Capacity("signature recovery row count overflow".into())
                    })?;
        }
        let trusted = txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
        let trusted_rows = trusted.len().map_err(db_err)?;
        total = total.checked_add(trusted_rows).ok_or_else(|| {
            ControlError::Capacity("signature/keyring recovery row count overflow".into())
        })?;
        Ok(total)
    }

    pub fn new(store: Arc<S>, db: Arc<Database>) -> Result<Self> {
        let txn = db.begin_write().map_err(db_err)?;
        txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
        txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
        txn.commit().map_err(db_err)?;

        Ok(Self {
            store,
            db,
            write_lock: Mutex::new(()),
            mutation_gate: Arc::new(RwLock::new(())),
        })
    }

    /// Use the control plane's cross-log recovery barrier.
    pub(crate) fn with_mutation_gate(mut self, gate: crate::MutationGate) -> Self {
        self.mutation_gate = gate;
        self
    }

    /// Sign `target` with `key`, store the signature entry, and index it.
    ///
    /// Returns the signature entry's CID.
    pub fn sign(
        &self,
        target: &Cid,
        name: Option<String>,
        predicate: serde_json::Value,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Cid> {
        let sig_cid = signing::sign_cid(self.store.as_ref(), target, name, predicate, key)?;
        self.index(target, &sig_cid)?;
        Ok(sig_cid)
    }

    /// Import an externally-produced DSSE envelope (see
    /// `dag_core::signing::import_envelope` for the gauntlet) and index it.
    ///
    /// `key_hex` names the public key the envelope must verify against; with
    /// `None`, every key in the keyring is tried — an envelope nobody local
    /// can vouch a key for is refused, never stored. Returns the signature
    /// entry's CID and the target it covers.
    pub fn import_envelope(
        &self,
        envelope: &signing::Envelope,
        key_hex: Option<&str>,
        expect_target: Option<&Cid>,
    ) -> Result<(Cid, Cid)> {
        let candidates: Vec<String> = match key_hex {
            Some(hex) => vec![hex.to_string()],
            None => self
                .trusted_keys()?
                .into_iter()
                .map(|k| k.public_key)
                .collect(),
        };
        if candidates.is_empty() {
            return Err(ControlError::Invalid(
                "no key to verify the envelope against: pass --key <hex>, or trust one first"
                    .into(),
            ));
        }

        let mut last_refusal: Option<CoreError> = None;
        for candidate in &candidates {
            let key = match signing::verifying_key_from_hex(candidate) {
                Ok(key) => key,
                Err(e) => {
                    last_refusal = Some(e);
                    continue;
                }
            };
            match signing::import_envelope(
                self.store.as_ref(),
                envelope.clone(),
                &key,
                expect_target,
            ) {
                Ok((sig_cid, target)) => {
                    self.index(&target, &sig_cid)?;
                    return Ok((sig_cid, target));
                }
                Err(e) => last_refusal = Some(e),
            }
        }

        Err(ControlError::Invalid(format!(
            "envelope did not verify against any of {} candidate key(s): {}",
            candidates.len(),
            last_refusal
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no usable key".into())
        )))
    }

    /// [`Self::sign`], with a caller-chosen in-toto `predicateType`.
    pub fn sign_with_type(
        &self,
        target: &Cid,
        name: Option<String>,
        predicate: serde_json::Value,
        predicate_type: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Cid> {
        let sig_cid = signing::sign_cid_with_type(
            self.store.as_ref(),
            target,
            name,
            predicate,
            predicate_type,
            key,
        )?;
        self.index(target, &sig_cid)?;
        Ok(sig_cid)
    }

    /// The stored signature records covering `target`, paired with their CIDs.
    ///
    /// This is the extraction path the record's own docs promised and nothing
    /// provided: the DSSE envelope lives inside a CBOR entry, so without this
    /// getting a `.dsse.json` for `cosign` or `slsa-verifier` meant decoding
    /// CBOR by hand. Unreadable records are skipped here — use
    /// [`Self::verify`] when you need them reported.
    pub fn records_for(&self, target: &Cid) -> Result<Vec<(Cid, signing::SignatureRecord)>> {
        let signature_cids = self.list_for(target)?;
        if signature_cids.len() > MAX_SIGNATURE_AGGREGATE_RECORDS {
            return Err(ControlError::Capacity(format!(
                "signature export for target {target} has {} records, above the {MAX_SIGNATURE_AGGREGATE_RECORDS}-record non-paged limit; use a paged API or reduce the signature set",
                signature_cids.len()
            )));
        }
        let mut out = Vec::new();
        let mut bytes_read = 0usize;
        for sig_cid in signature_cids {
            // An entry the index names but the store lost — collected before
            // signatures followed their target's retention, or any other
            // loss — is skipped like an unreadable one: this is the export
            // path, and there is nothing to export.
            let bytes = match self.store.get_chunk(&sig_cid) {
                Ok(bytes) => bytes,
                Err(CoreError::ChunkNotFound(_)) => continue,
                Err(e) => return Err(e.into()),
            };
            bytes_read = bytes_read.checked_add(bytes.len()).ok_or_else(|| {
                ControlError::Capacity("signature export byte count overflow".into())
            })?;
            if bytes_read > MAX_SIGNATURE_AGGREGATE_BYTES {
                return Err(ControlError::Capacity(format!(
                    "signature export for target {target} exceeds the {MAX_SIGNATURE_AGGREGATE_BYTES}-byte non-paged limit"
                )));
            }
            if let Some((record, _)) = signing::record_from_bytes(&bytes) {
                out.push((sig_cid, record));
            }
        }
        Ok(out)
    }

    /// Add `sig_cid` to `target`'s signature list (idempotent).
    fn index(&self, target: &Cid, sig_cid: &Cid) -> Result<()> {
        let _mutation_guard = self.mutation_gate.read().unwrap_or_else(|e| e.into_inner());
        // A panic aborts the redb transaction; the next writer re-reads the
        // row from the database, so poisoning this serialization mutex must
        // not permanently take the signature subsystem down.
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        let mut sigs = self.list_for(target)?;
        if !sigs.contains(sig_cid) {
            if sigs.len() >= MAX_SIGNATURES_PER_TARGET {
                return Err(ControlError::Capacity(format!(
                    "target {target} already has the maximum {MAX_SIGNATURES_PER_TARGET} indexed signatures"
                )));
            }
            sigs.push(sig_cid.clone());
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&sigs, &mut buf)?;

            let txn = self.db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
                table
                    .insert(target.as_bytes(), buf.as_slice())
                    .map_err(db_err)?;
            }
            txn.commit().map_err(db_err)?;
        }
        drop(guard);
        Ok(())
    }

    /// Prepare bounded, idempotent signature-index updates for one sync
    /// publication. `by_target` must already have been derived by strict
    /// decoding of the caller's bounded candidate set.
    ///
    /// A saturated row is refused rather than truncated. Sync is not
    /// recovery, and silently evicting existing evidence merely because a
    /// peer offered another record would make remote input an index-deletion
    /// capability. Recovery retains its deterministic ranking policy.
    pub(crate) fn prepare_merge_plan(
        &self,
        by_target: HashMap<Cid, Vec<Cid>>,
    ) -> Result<SignatureMergePlan> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
        let mut targets: Vec<_> = by_target.into_iter().collect();
        targets.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut rows = Vec::with_capacity(targets.len());
        let mut added = 0u32;
        for (target, mut offered) in targets {
            offered.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            offered.dedup();

            let mut merged = match table.get(target.as_bytes()).map_err(db_err)? {
                Some(value) => Self::decode_signature_row(&target, value.value())?,
                None => Vec::new(),
            };
            let mut seen: HashSet<Cid> = merged.iter().cloned().collect();
            let before = merged.len();
            for cid in offered {
                if seen.insert(cid.clone()) {
                    merged.push(cid);
                }
            }
            if merged.len() > MAX_SIGNATURES_PER_TARGET {
                return Err(ControlError::Capacity(format!(
                    "sync would give target {target} {} indexed signatures, above the {MAX_SIGNATURES_PER_TARGET}-record limit",
                    merged.len()
                )));
            }
            let newly_added = merged.len() - before;
            if newly_added == 0 {
                continue;
            }
            added = added
                .checked_add(u32::try_from(newly_added).map_err(|_| {
                    ControlError::Capacity("signature sync-merge count overflow".into())
                })?)
                .ok_or_else(|| {
                    ControlError::Capacity("signature sync-merge count overflow".into())
                })?;
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&merged, &mut encoded)?;
            if encoded.len() > MAX_SIGNATURE_INDEX_BYTES {
                return Err(ControlError::Capacity(format!(
                    "signature index for target {target} exceeds {MAX_SIGNATURE_INDEX_BYTES} bytes"
                )));
            }
            rows.push((target.as_bytes().to_vec(), encoded));
        }
        Ok(SignatureMergePlan { rows, added })
    }

    /// Apply a caller-prepared incremental signature plan inside the same
    /// transaction that publishes the corresponding sync event mappings.
    pub(crate) fn apply_merge_plan(
        &self,
        txn: &WriteTransaction,
        plan: &SignatureMergePlan,
    ) -> Result<()> {
        let mut table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
        for (target, signatures) in &plan.rows {
            table
                .insert(target.as_slice(), signatures.as_slice())
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// Signature entry CIDs covering `target`.
    pub fn list_for(&self, target: &Cid) -> Result<Vec<Cid>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
        let Some(value) = table.get(target.as_bytes()).map_err(db_err)? else {
            return Ok(Vec::new());
        };
        Self::decode_signature_row(target, value.value())
    }

    fn decode_signature_row(target: &Cid, bytes: &[u8]) -> Result<Vec<Cid>> {
        Self::decode_signature_row_unlabelled(bytes).map_err(|error| {
            ControlError::Capacity(format!(
                "signature index for target {target} is invalid: {error}; rebuild or repair the index before reading it"
            ))
        })
    }

    fn decode_signature_row_unlabelled(bytes: &[u8]) -> std::result::Result<Vec<Cid>, String> {
        if bytes.len() > MAX_SIGNATURE_INDEX_BYTES {
            return Err(format!(
                "{} bytes exceeds the {MAX_SIGNATURE_INDEX_BYTES}-byte safety limit",
                bytes.len()
            ));
        }
        let sigs: Vec<Cid> = dag_core::decode_cbor_exact(bytes)
            .map_err(|error| format!("CBOR decode failed: {error}"))?;
        if sigs.len() > MAX_SIGNATURES_PER_TARGET {
            return Err(format!(
                "{} entries exceeds the {MAX_SIGNATURES_PER_TARGET}-entry safety limit",
                sigs.len()
            ));
        }
        let mut unique = HashSet::with_capacity(sigs.len());
        if sigs.iter().any(|cid| !unique.insert(cid.clone())) {
            return Err("duplicate signature CIDs".into());
        }
        Ok(sigs)
    }

    /// Return a bounded insertion-order page of signature entry CIDs.
    pub fn list_for_page(
        &self,
        target: &Cid,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<Cid>, bool)> {
        let sigs = self.list_for(target)?;
        if offset > sigs.len() {
            return Err(ControlError::Invalid(format!(
                "signature cursor {offset} is past the end ({}) for target {target}",
                sigs.len()
            )));
        }
        let end = offset.saturating_add(limit).min(sigs.len());
        Ok((sigs[offset..end].to_vec(), end < sigs.len()))
    }

    /// Signature entry CIDs covering anything in `targets`, transitively: a
    /// counter-signature on a returned signature entry is included too.
    ///
    /// This is what lets collection keep signatures with the content they
    /// vouch for: `Control::run_gc` passes its protected set and protects
    /// what comes back. Signatures on content outside `targets` are *not*
    /// returned — evidence about collectable content is collectable with it.
    ///
    /// The index may name entries the store no longer holds; returning them
    /// is harmless (protecting an absent chunk is a no-op).
    pub fn covering(&self, targets: &HashSet<Cid>) -> Result<HashSet<Cid>> {
        self.covering_with_limit(targets, MAX_SIGNATURE_CLOSURE_ENTRIES)
    }

    /// GC-facing closure with the same aggregate work ceiling as the rest of
    /// the protected-root snapshot.
    pub(crate) fn covering_bounded(
        &self,
        targets: &HashSet<Cid>,
        limit: usize,
    ) -> Result<HashSet<Cid>> {
        self.covering_with_limit(targets, limit)
    }

    /// Target-driven breadth-first closure over counter-signatures.
    ///
    /// Each relevant row is read at most twice (once as an original target
    /// and, only if it is itself later discovered as a signature, once from
    /// the queue).  Unrelated index rows are never decoded.  This avoids both
    /// the former whole-index allocation and its repeated O(index × depth)
    /// fixpoint scans.
    fn covering_with_limit(&self, targets: &HashSet<Cid>, limit: usize) -> Result<HashSet<Cid>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;

        let mut out = HashSet::new();
        let mut pending = VecDeque::new();
        let mut work = 0usize;

        for target in targets {
            Self::enqueue_covering(&table, target, limit, &mut work, &mut out, &mut pending)?;
        }
        while let Some(signature) = pending.pop_front() {
            Self::enqueue_covering(&table, &signature, limit, &mut work, &mut out, &mut pending)?;
        }

        Ok(out)
    }

    fn enqueue_covering<T>(
        table: &T,
        target: &Cid,
        limit: usize,
        work: &mut usize,
        out: &mut HashSet<Cid>,
        pending: &mut VecDeque<Cid>,
    ) -> Result<()>
    where
        T: ReadableTable<&'static [u8], &'static [u8]>,
    {
        let Some(value) = table.get(target.as_bytes()).map_err(db_err)? else {
            return Ok(());
        };
        for signature in Self::decode_signature_row(target, value.value())? {
            if *work >= limit {
                return Err(ControlError::Capacity(format!(
                    "signature closure exceeds the {limit}-edge safety limit; collection and synchronisation are refused until the signature graph is reduced"
                )));
            }
            *work += 1;
            if out.contains(&signature) {
                continue;
            }
            if out.len() >= limit {
                return Err(ControlError::Capacity(format!(
                    "signature closure exceeds the {limit}-entry safety limit; collection and synchronisation are refused until the signature graph is reduced"
                )));
            }
            out.insert(signature.clone());
            pending.push_back(signature);
        }
        Ok(())
    }

    /// Grant trust to a public key. The key ID is derived, not taken on
    /// faith, and the grant records exactly the purposes given (ADR-004);
    /// an empty list normalises to `verify`, the narrowest useful grant.
    /// Re-granting replaces the entry: the latest explicit decision wins.
    pub fn trust_key(
        &self,
        public_key_hex: &str,
        comment: Option<String>,
        purposes: &[TrustPurpose],
    ) -> Result<TrustedKey> {
        let key = signing::verifying_key_from_hex(public_key_hex)?;
        if comment.as_ref().is_some_and(|comment| {
            comment.len() > MAX_TRUSTED_KEY_COMMENT_BYTES || comment.chars().any(char::is_control)
        }) {
            return Err(ControlError::Invalid(format!(
                "key comment must be at most {MAX_TRUSTED_KEY_COMMENT_BYTES} bytes and contain no control characters"
            )));
        }
        let mut recorded: Vec<String> = if purposes.is_empty() {
            vec![TrustPurpose::Verify.as_str().to_string()]
        } else {
            purposes.iter().map(|p| p.as_str().to_string()).collect()
        };
        recorded.sort();
        recorded.dedup();

        let entry = TrustedKey {
            key_id: signing::key_id(&key),
            public_key: hex::encode(key.as_bytes()),
            comment,
            added_at: crate::now_unix(),
            purposes: recorded,
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&entry, &mut buf)?;
        if buf.len() > MAX_TRUSTED_KEY_ROW_BYTES {
            return Err(ControlError::Capacity(format!(
                "trusted-key row exceeds {MAX_TRUSTED_KEY_ROW_BYTES} bytes"
            )));
        }

        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        {
            let txn = self.db.begin_read().map_err(db_err)?;
            let table = txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
            let exists = table
                .get(entry.key_id.as_bytes())
                .map_err(db_err)?
                .is_some();
            if !exists
                && usize::try_from(table.len().map_err(db_err)?).unwrap_or(usize::MAX)
                    >= MAX_TRUSTED_KEYS
            {
                return Err(ControlError::Capacity(format!(
                    "keyring already has the maximum {MAX_TRUSTED_KEYS} trusted keys"
                )));
            }
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
            table
                .insert(entry.key_id.as_bytes(), buf.as_slice())
                .map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        drop(guard);

        Ok(entry)
    }

    /// Revoke trust in a key. Existing signatures degrade to "valid,
    /// untrusted" — the history is untouched, only the verdict changes.
    pub fn untrust_key(&self, key_id: &str) -> Result<bool> {
        let guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let txn = self.db.begin_write().map_err(db_err)?;
        let existed = {
            let mut table = txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
            let prior = table.remove(key_id.as_bytes()).map_err(db_err)?;
            prior.is_some()
        };
        txn.commit().map_err(db_err)?;
        drop(guard);
        Ok(existed)
    }

    /// The keyring, sorted by key ID.
    pub fn trusted_keys(&self) -> Result<Vec<TrustedKey>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
        let count = usize::try_from(table.len().map_err(db_err)?).unwrap_or(usize::MAX);
        if count > MAX_TRUSTED_KEYS {
            return Err(ControlError::Capacity(format!(
                "keyring has {count} rows, above the {MAX_TRUSTED_KEYS}-key safety limit"
            )));
        }

        let mut keys = Vec::with_capacity(count);
        for item in table.range::<&[u8]>(..).map_err(db_err)? {
            let (table_key, value) = item.map_err(db_err)?;
            if value.value().len() > MAX_TRUSTED_KEY_ROW_BYTES {
                return Err(ControlError::Capacity(format!(
                    "trusted-key row exceeds {MAX_TRUSTED_KEY_ROW_BYTES} bytes"
                )));
            }
            let expected = std::str::from_utf8(table_key.value())
                .map_err(|_| ControlError::Database("trusted-key table key is not UTF-8".into()))?;
            let entry: TrustedKey = dag_core::decode_cbor_exact(value.value())
                .map_err(|error| ControlError::Codec(error.to_string()))?;
            validate_trusted_key_entry(&entry, Some(expected))?;
            keys.push(entry);
        }
        Ok(keys)
    }

    fn trusted_key(&self, key_id: &str) -> Result<Option<TrustedKey>> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = txn.open_table(TRUSTED_KEYS).map_err(db_err)?;
        let Some(value) = table.get(key_id.as_bytes()).map_err(db_err)? else {
            return Ok(None);
        };
        if value.value().len() > MAX_TRUSTED_KEY_ROW_BYTES {
            return Err(ControlError::Capacity(format!(
                "trusted-key row exceeds {MAX_TRUSTED_KEY_ROW_BYTES} bytes"
            )));
        }
        let entry: TrustedKey = dag_core::decode_cbor_exact(value.value())
            .map_err(|error| ControlError::Codec(error.to_string()))?;
        validate_trusted_key_entry(&entry, Some(key_id))?;
        Ok(Some(entry))
    }

    /// Canonical local trust keys used only to rank a bounded signature-index
    /// rebuild. Ranking verifies the envelope with the keyring copy rather
    /// than relying on the record's embedded key: those are intentionally
    /// independent verdicts, and either representation may disagree.
    fn trusted_keys_for_rebuild(&self) -> Result<HashMap<String, ed25519_dalek::VerifyingKey>> {
        let mut keys = HashMap::new();
        for entry in self.trusted_keys()? {
            // `trusted_keys` has already validated this exact public key and
            // its derived ID. Keep this conversion fallible so a future
            // validation change cannot turn recovery into an unchecked path.
            let key = signing::verifying_key_from_hex(&entry.public_key).map_err(|error| {
                ControlError::Database(format!(
                    "trusted-key row has an invalid public key during signature rebuild: {error}"
                ))
            })?;
            keys.insert(entry.key_id, key);
        }
        Ok(keys)
    }

    /// Verify every signature covering `target`, for the verification
    /// purpose — the meaning this call has always had.
    pub fn verify(&self, target: &Cid) -> Result<Vec<SignatureStatus>> {
        self.verify_for(target, TrustPurpose::Verify)
    }

    /// Verify every signature covering `target`, asking whether each is
    /// trusted **for `purpose`** (ADR-004). `trusted` in the returned
    /// statuses answers exactly that question.
    pub fn verify_for(&self, target: &Cid, purpose: TrustPurpose) -> Result<Vec<SignatureStatus>> {
        let signature_cids = self.list_for(target)?;
        if signature_cids.len() > MAX_SIGNATURE_AGGREGATE_RECORDS {
            return Err(ControlError::Capacity(format!(
                "verification for target {target} has {} signatures, above the {MAX_SIGNATURE_AGGREGATE_RECORDS}-record non-paged limit; use the paged signatures API or reduce the signature set",
                signature_cids.len()
            )));
        }
        let mut out = Vec::with_capacity(signature_cids.len());
        let mut bytes_read = 0usize;
        for sig_cid in signature_cids {
            let (status, bytes) = self.verify_signature_for_measured(target, &sig_cid, purpose)?;
            bytes_read = bytes_read.checked_add(bytes).ok_or_else(|| {
                ControlError::Capacity("signature verification byte count overflow".into())
            })?;
            if bytes_read > MAX_SIGNATURE_AGGREGATE_BYTES {
                return Err(ControlError::Capacity(format!(
                    "verification for target {target} exceeds the {MAX_SIGNATURE_AGGREGATE_BYTES}-byte non-paged limit"
                )));
            }
            out.push(status);
        }
        Ok(out)
    }

    /// Search for one trusted signature while consuming caller-owned aggregate
    /// budgets. Budget exhaustion is a safe miss: effect adoption falls back to
    /// execution rather than turning attacker-controlled evidence volume into
    /// an availability failure.
    pub(crate) fn has_trusted_signature_for_bounded(
        &self,
        target: &Cid,
        purpose: TrustPurpose,
        remaining_records: &mut usize,
        remaining_bytes: &mut usize,
    ) -> Result<bool> {
        for sig_cid in self.list_for(target)? {
            if *remaining_records == 0 || *remaining_bytes == 0 {
                return Ok(false);
            }
            *remaining_records -= 1;
            let (status, bytes) = self.verify_signature_for_measured(target, &sig_cid, purpose)?;
            if bytes > *remaining_bytes {
                *remaining_bytes = 0;
                return Ok(false);
            }
            *remaining_bytes -= bytes;
            if status.trusted {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Verify one indexed signature entry for a target.
    ///
    /// Callers obtain `sig_cid` from [`Self::list_for_page`]; keeping this
    /// primitive single-record lets a response budget stop before loading and
    /// retaining an attacker-sized page of predicates.
    pub fn verify_signature_for(
        &self,
        target: &Cid,
        sig_cid: &Cid,
        purpose: TrustPurpose,
    ) -> Result<SignatureStatus> {
        self.verify_signature_for_measured(target, sig_cid, purpose)
            .map(|(status, _)| status)
    }

    fn verify_signature_for_measured(
        &self,
        target: &Cid,
        sig_cid: &Cid,
        purpose: TrustPurpose,
    ) -> Result<(SignatureStatus, usize)> {
        // The index can outlive the entry: report loss rather than hiding it.
        let bytes = match self.store.get_chunk(sig_cid) {
            Ok(bytes) => bytes,
            Err(CoreError::ChunkNotFound(_)) => {
                return Ok((
                    SignatureStatus {
                        signature_cid: sig_cid.clone(),
                        key_id: "<missing>".into(),
                        signer: None,
                        trusted: false,
                        key_purposes: Vec::new(),
                        valid: false,
                        predicate: serde_json::Value::Null,
                    },
                    0,
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let byte_len = bytes.len();
        let Some((record, _entry)) = signing::record_from_bytes(&bytes) else {
            return Ok((
                SignatureStatus {
                    signature_cid: sig_cid.clone(),
                    key_id: "<unreadable>".into(),
                    signer: None,
                    trusted: false,
                    key_purposes: Vec::new(),
                    valid: false,
                    predicate: serde_json::Value::Null,
                },
                byte_len,
            ));
        };
        Ok((self.status_of(sig_cid, &record, target, purpose)?, byte_len))
    }

    fn status_of(
        &self,
        sig_cid: &Cid,
        record: &SignatureRecord,
        target: &Cid,
        purpose: TrustPurpose,
    ) -> Result<SignatureStatus> {
        // Trusted: the keyring's key for this ID verifies the envelope AND
        // the entry grants the purpose being asked about. The embedded key
        // plays no part in this branch.
        let keyring_entry = self.trusted_key(&record.key_id)?;
        let key_purposes = keyring_entry
            .as_ref()
            .map(|e| e.effective_purposes())
            .unwrap_or_default();
        let (trusted_grant, signer, trusted_statement) = match &keyring_entry {
            Some(entry) => match signing::verifying_key_from_hex(&entry.public_key) {
                Ok(key) => match signing::verify_envelope(&record.envelope, &key) {
                    Ok(statement) => (
                        entry.grants(purpose),
                        entry.comment.clone(),
                        Some(statement),
                    ),
                    Err(_) => (false, None, None),
                },
                Err(_) => (false, None, None),
            },
            None => (false, None, None),
        };

        // Internally valid is an independent claim: the embedded key must
        // match the record's ID and verify the envelope. A trusted keyring
        // verdict must not silently turn a mismatched embedded key into a
        // self-consistent record.
        let embedded_statement = match signing::verifying_key_from_hex(&record.public_key) {
            Ok(key) if signing::key_id(&key) == record.key_id => {
                signing::verify_envelope(&record.envelope, &key).ok()
            }
            _ => None,
        };

        // A signature over some *other* CID that ended up in this target's
        // list is not a signature of this target.
        let trusted_covers_target = trusted_statement
            .as_ref()
            .map(|s| s.subject_cids().contains(target))
            .unwrap_or(false);
        let embedded_covers_target = embedded_statement
            .as_ref()
            .map(|s| s.subject_cids().contains(target))
            .unwrap_or(false);

        let predicate = trusted_statement
            .as_ref()
            .or(embedded_statement.as_ref())
            .map(|s| s.predicate.clone())
            .unwrap_or(serde_json::Value::Null);

        Ok(SignatureStatus {
            signature_cid: sig_cid.clone(),
            key_id: record.key_id.clone(),
            signer,
            trusted: trusted_grant && trusted_covers_target,
            key_purposes,
            valid: embedded_covers_target,
            predicate,
        })
    }

    // (rebuild lives in the impl below: it needs store enumeration, which
    // only GC-capable stores provide.)
}

impl<S: ContentStore + dag_storage::GcCapableStore + 'static> SignatureLog<S> {
    /// Rebuild `sig_by_target` by scanning the complete store without an
    /// inventory ceiling.
    ///
    /// Like every derived table here, the index can be reconstructed from
    /// primary data — the signature entries themselves. Returns the number
    /// of signatures indexed. This public compatibility method is an explicit
    /// offline/embedder operation; operator-facing full recovery uses the
    /// finite object and byte ceilings on [`crate::Control::recover`].
    pub fn rebuild(&self) -> Result<u32> {
        let cids = self
            .store
            .list_all_cids()
            .map_err(|e| ControlError::db("listing store", e))?;
        self.rebuild_from_cids(&cids)
    }

    /// Rebuild from a caller-owned inventory snapshot.
    pub(crate) fn rebuild_from_cids(&self, cids: &[Cid]) -> Result<u32> {
        let _mutation_guard = self
            .mutation_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let plan = self.prepare_rebuild_plan_from_cids(cids)?;
        let count = plan.count();
        let txn = self.db.begin_write().map_err(db_err)?;
        self.apply_rebuild_plan(&txn, &plan)?;
        txn.commit().map_err(db_err)?;
        Ok(count)
    }

    /// Scan immutable signature entries and encode a replacement index.
    #[cfg(test)]
    pub(crate) fn prepare_rebuild_plan(&self) -> Result<SignatureRebuildPlan> {
        let cids = self
            .store
            .list_all_cids()
            .map_err(|e| ControlError::db("listing store", e))?;
        self.prepare_rebuild_plan_from_cids(&cids)
    }

    /// Prepare a replacement from a caller-owned inventory snapshot.
    pub(crate) fn prepare_rebuild_plan_from_cids(
        &self,
        cids: &[Cid],
    ) -> Result<SignatureRebuildPlan> {
        let trusted_keys = self.trusted_keys_for_rebuild()?;
        // target -> (stable CID bytes -> CID), accumulated before a single
        // table swap. The lookup is only an accelerator: if a content writer
        // stores more than the supported fan-in, retain a deterministic
        // bounded subset instead of making every future recovery impossible.
        let mut by_target: HashMap<Cid, RankedSignatures> = HashMap::new();
        // One representative per locally trusted key is reserved ahead of all
        // remaining slots. This prevents one prolific trusted/adopt-only key
        // from crowding every other local trust root out of a rebuilt row.
        let mut trusted_representatives: HashMap<Cid, TrustedSignatureRepresentatives> =
            HashMap::new();

        for cid in cids {
            // A read failure cannot be classified as "not a signature". It
            // may hide exactly the evidence this replacement index protects.
            let bytes = self.store.get_chunk(cid)?;
            let Some((record, entry)) = signing::record_from_bytes(&bytes) else {
                continue;
            };
            // `record_from_bytes` requires exactly this one `signs` link.
            let target = &entry.links[0].target;
            // Preserve malformed/forged records for explicit invalid-verdict
            // reporting when capacity permits, but never let them displace a
            // self-consistent signature from the bounded lookup.
            let internally_valid = internally_valid_for_target(&record, target);
            let locally_trusted = trusted_keys
                .get(&record.key_id)
                .is_some_and(|key| signature_covers_target(&record, target, key));
            let priority = if locally_trusted {
                0
            } else if internally_valid {
                1
            } else {
                2
            };
            if priority == 0 {
                let cid_bytes = cid.as_bytes().to_vec();
                trusted_representatives
                    .entry(target.clone())
                    .or_default()
                    .entry(record.key_id.as_bytes().to_vec())
                    .and_modify(|current| {
                        if cid_bytes < current.0 {
                            *current = (cid_bytes.clone(), cid.clone());
                        }
                    })
                    .or_insert((cid_bytes, cid.clone()));
            }
            let sigs = by_target.entry(target.clone()).or_default();
            sigs.insert((priority, cid.as_bytes().to_vec()), cid.clone());
            if sigs.len() > MAX_SIGNATURES_PER_TARGET {
                sigs.pop_last();
            }
        }

        let mut rows = Vec::with_capacity(by_target.len());
        let mut count = 0u32;
        for (target, sigs) in by_target {
            let mut selected = Vec::with_capacity(MAX_SIGNATURES_PER_TARGET);
            let mut seen = HashSet::with_capacity(MAX_SIGNATURES_PER_TARGET);
            if let Some(representatives) = trusted_representatives.remove(&target) {
                for (_, cid) in representatives.into_values() {
                    if selected.len() == MAX_SIGNATURES_PER_TARGET {
                        break;
                    }
                    if seen.insert(cid.clone()) {
                        selected.push(cid);
                    }
                }
            }
            for cid in sigs.into_values() {
                if selected.len() == MAX_SIGNATURES_PER_TARGET {
                    break;
                }
                if seen.insert(cid.clone()) {
                    selected.push(cid);
                }
            }
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&selected, &mut buf)?;
            let added = u32::try_from(selected.len()).map_err(|_| {
                ControlError::Capacity("signature rebuild count is exhausted".into())
            })?;
            count = count.checked_add(added).ok_or_else(|| {
                ControlError::Capacity("signature rebuild count is exhausted".into())
            })?;
            rows.push((target.as_bytes().to_vec(), buf));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(SignatureRebuildPlan { rows, count })
    }

    /// Replace the signature lookup in a caller-owned transaction.
    pub(crate) fn apply_rebuild_plan(
        &self,
        txn: &WriteTransaction,
        plan: &SignatureRebuildPlan,
    ) -> Result<()> {
        let mut table = txn.open_table(SIG_BY_TARGET).map_err(db_err)?;
        table.retain(|_, _| false).map_err(db_err)?;
        for (target, sigs) in &plan.rows {
            table
                .insert(target.as_slice(), sigs.as_slice())
                .map_err(db_err)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> (tempfile::TempDir, SignatureLog<dag_storage::FsStore>) {
        let temp = tempfile::TempDir::new().unwrap();
        let store = Arc::new(dag_storage::FsStore::new(temp.path().join("data")).unwrap());
        let db = Arc::new(Database::create(temp.path().join("control.redb")).unwrap());
        let log = SignatureLog::new(store, db).unwrap();
        (temp, log)
    }

    fn entry_with(purposes: Vec<String>) -> TrustedKey {
        TrustedKey {
            key_id: "k".into(),
            public_key: "p".into(),
            comment: None,
            added_at: 0,
            purposes,
        }
    }

    /// An entry written before ADR-004 has no purposes field. It was
    /// granted when trust meant verification, and must mean exactly that —
    /// not the wider grant ADR-003 briefly implied.
    #[test]
    fn legacy_entries_without_purposes_grant_verify_only() {
        // Old on-disk shape: a CBOR map with no `purposes` key at all.
        let mut old = Vec::new();
        ciborium::ser::into_writer(
            &serde_json::json!({
                "key_id": "k", "public_key": "p",
                "comment": null, "added_at": 0
            }),
            &mut old,
        )
        .unwrap();
        let entry: TrustedKey = ciborium::de::from_reader(old.as_slice()).unwrap();

        assert!(entry.purposes.is_empty());
        assert!(entry.grants(TrustPurpose::Verify));
        assert!(!entry.grants(TrustPurpose::Adopt));
        assert_eq!(entry.effective_purposes(), vec!["verify".to_string()]);
    }

    #[test]
    fn explicit_purposes_grant_exactly_what_they_say() {
        let verify_only = entry_with(vec!["verify".into()]);
        assert!(verify_only.grants(TrustPurpose::Verify));
        assert!(!verify_only.grants(TrustPurpose::Adopt));

        let adopt_only = entry_with(vec!["adopt".into()]);
        assert!(!adopt_only.grants(TrustPurpose::Verify));
        assert!(adopt_only.grants(TrustPurpose::Adopt));

        let both = entry_with(vec!["verify".into(), "adopt".into()]);
        assert!(both.grants(TrustPurpose::Verify));
        assert!(both.grants(TrustPurpose::Adopt));
    }

    /// A keyring written by a newer version may carry purposes this build
    /// has never heard of. They grant nothing here — deny-by-default — and
    /// they must not make the entry unreadable.
    #[test]
    fn unknown_purpose_strings_are_inert() {
        let future = entry_with(vec!["schedule".into()]);
        assert!(!future.grants(TrustPurpose::Verify));
        assert!(!future.grants(TrustPurpose::Adopt));
    }

    #[test]
    fn trust_comments_cannot_inject_terminal_control_sequences() {
        let (_temp, log) = log();
        let key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        assert!(matches!(
            log.trust_key(
                &hex::encode(key.verifying_key().as_bytes()),
                Some("builder\u{1b}[2J".into()),
                &[TrustPurpose::Verify],
            ),
            Err(ControlError::Invalid(_))
        ));
    }

    #[test]
    fn signature_rebuild_refuses_a_malformed_primary_keyring_row() {
        let (_temp, log) = log();
        let key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let key_id = signing::key_id(&key.verifying_key());
        let malformed = TrustedKey {
            key_id: key_id.clone(),
            public_key: "not-a-public-key".into(),
            comment: None,
            added_at: 0,
            purposes: vec!["verify".into()],
        };
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&malformed, &mut encoded).unwrap();
        let txn = log.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(TRUSTED_KEYS).unwrap();
            table.insert(key_id.as_bytes(), encoded.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        assert!(matches!(
            log.prepare_rebuild_plan_from_cids(&[]),
            Err(ControlError::Database(_))
        ));
    }

    fn status(key_id: &str, trusted: bool, valid: bool) -> SignatureStatus {
        SignatureStatus {
            signature_cid: Cid::compute(format!("{key_id}{trusted}{valid}").as_bytes()),
            key_id: key_id.into(),
            signer: None,
            trusted,
            key_purposes: Vec::new(),
            valid,
            predicate: serde_json::Value::Null,
        }
    }

    /// The counting rule behind `--min-trusted`: one key restating itself is
    /// one signer, however many signature entries it leaves behind.
    #[test]
    fn repeat_signatures_from_one_key_count_once() {
        let statuses = [
            status("key-a", true, true),
            status("key-a", true, true),
            status("key-a", true, true),
        ];
        assert_eq!(distinct_trusted_keys(&statuses), 1);
        assert_eq!(distinct_valid_keys(&statuses), 1);
    }

    #[test]
    fn distinct_keys_count_separately_and_untrusted_ones_do_not_count() {
        let statuses = [
            status("key-a", true, true),
            status("key-b", true, true),
            status("key-b", true, true),
            // Valid but nobody vouched for it.
            status("key-c", false, true),
            // Neither: a forgery or a signature of other content.
            status("key-d", false, false),
        ];
        assert_eq!(distinct_trusted_keys(&statuses), 2);
        assert_eq!(distinct_valid_keys(&statuses), 3);
        assert_eq!(distinct_trusted_keys(&[]), 0);
    }

    #[test]
    fn signature_id_pages_are_bounded_and_advance() {
        let (_temp, log) = log();
        let target = Cid::compute(b"target");
        let sigs = [
            Cid::compute(b"sig-1"),
            Cid::compute(b"sig-2"),
            Cid::compute(b"sig-3"),
        ];
        for sig in &sigs {
            log.index(&target, sig).unwrap();
        }

        let (first, more) = log.list_for_page(&target, 0, 2).unwrap();
        assert_eq!(first, sigs[..2]);
        assert!(more);
        let (second, more) = log.list_for_page(&target, 2, 2).unwrap();
        assert_eq!(second, sigs[2..]);
        assert!(!more);
    }

    #[test]
    fn non_paged_verification_and_export_refuse_aggregate_fan_in() {
        let (_temp, log) = log();
        let target = Cid::compute(b"target");
        for index in 0..=MAX_SIGNATURE_AGGREGATE_RECORDS {
            log.index(
                &target,
                &Cid::compute(format!("signature-{index}").as_bytes()),
            )
            .unwrap();
        }

        assert!(matches!(
            log.verify(&target),
            Err(ControlError::Capacity(_))
        ));
        assert!(matches!(
            log.records_for(&target),
            Err(ControlError::Capacity(_))
        ));
        let (page, more) = log.list_for_page(&target, 0, 10).unwrap();
        assert_eq!(page.len(), 10);
        assert!(more, "the bounded paged route must remain available");
    }

    #[test]
    fn oversized_legacy_signature_index_is_refused_before_decode() {
        let (_temp, log) = log();
        let target = Cid::compute(b"target");
        let oversized = vec![0u8; MAX_SIGNATURE_INDEX_BYTES + 1];
        let txn = log.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SIG_BY_TARGET).unwrap();
            table
                .insert(target.as_bytes(), oversized.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        assert!(matches!(
            log.list_for(&target),
            Err(ControlError::Capacity(_))
        ));
    }

    #[test]
    fn signature_index_and_keyring_rows_reject_trailing_cbor() {
        let (_temp, log) = log();
        let target = Cid::compute(b"strict target");
        log.index(&target, &Cid::compute(b"signature")).unwrap();
        let mut signature_row = {
            let txn = log.db.begin_read().unwrap();
            let table = txn.open_table(SIG_BY_TARGET).unwrap();
            table
                .get(target.as_bytes())
                .unwrap()
                .unwrap()
                .value()
                .to_vec()
        };
        signature_row.push(0xf6);
        let txn = log.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SIG_BY_TARGET).unwrap();
            table
                .insert(target.as_bytes(), signature_row.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(matches!(
            log.list_for(&target),
            Err(ControlError::Capacity(_))
        ));

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let trusted = log
            .trust_key(
                &hex::encode(signing_key.verifying_key().as_bytes()),
                None,
                &[TrustPurpose::Verify],
            )
            .unwrap();
        let mut key_row = {
            let txn = log.db.begin_read().unwrap();
            let table = txn.open_table(TRUSTED_KEYS).unwrap();
            table
                .get(trusted.key_id.as_bytes())
                .unwrap()
                .unwrap()
                .value()
                .to_vec()
        };
        key_row.push(0xff);
        let txn = log.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(TRUSTED_KEYS).unwrap();
            table
                .insert(trusted.key_id.as_bytes(), key_row.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert!(matches!(log.trusted_keys(), Err(ControlError::Codec(_))));
    }

    #[test]
    fn recovery_budget_counts_represented_signatures_and_bounds_corrupt_rows() {
        let (_temp, log) = log();
        let target = Cid::compute(b"target");
        for index in 0..3 {
            log.index(
                &target,
                &Cid::compute(format!("signature-{index}").as_bytes()),
            )
            .unwrap();
        }
        assert_eq!(log.recovery_row_count().unwrap(), 3);

        let corrupt_target = Cid::compute(b"corrupt-target");
        let oversized = vec![0u8; MAX_SIGNATURE_INDEX_BYTES + 1];
        let txn = log.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SIG_BY_TARGET).unwrap();
            table
                .insert(corrupt_target.as_bytes(), oversized.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        assert_eq!(
            log.recovery_row_count().unwrap(),
            3 + (MAX_SIGNATURES_PER_TARGET + 1) as u64
        );
    }

    #[test]
    fn signature_rebuild_deterministically_bounds_per_target_fan_in() {
        use dag_storage::GcCapableStore;

        let (_temp, log) = log();
        let target = log.store.put_chunk(b"target", None).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
        for index in 0..=MAX_SIGNATURES_PER_TARGET {
            signing::sign_cid(
                log.store.as_ref(),
                &target,
                None,
                serde_json::json!({"sequence": index}),
                &key,
            )
            .unwrap();
        }
        let trusted_key = ed25519_dalek::SigningKey::from_bytes(&[20u8; 32]);
        log.trust_key(
            &hex::encode(trusted_key.verifying_key().as_bytes()),
            None,
            &[TrustPurpose::Verify],
        )
        .unwrap();
        let unrelated_embedded_key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let statement =
            signing::Statement::for_cid(&target, None, serde_json::json!({"trusted": true}));
        let trusted_record = SignatureRecord {
            kind: signing::SIGNATURE_KIND.to_string(),
            key_id: signing::key_id(&trusted_key.verifying_key()),
            // Trust is decided with the authoritative keyring copy. This
            // deliberately makes internal validity false while retaining a
            // genuine locally trusted envelope.
            public_key: hex::encode(unrelated_embedded_key.verifying_key().as_bytes()),
            envelope: signing::sign_statement(&statement, &trusted_key).unwrap(),
        };
        let trusted_signature = log
            .store
            .put_entry(&dag_core::Entry::new(
                serde_json::to_vec(&trusted_record).unwrap(),
                vec![dag_core::Link::named(target.clone(), "signs")],
                None,
            ))
            .unwrap();

        let cids = log.store.list_all_cids().unwrap();
        let plan = log.prepare_rebuild_plan_from_cids(&cids).unwrap();
        assert_eq!(plan.count(), MAX_SIGNATURES_PER_TARGET as u32);
        assert_eq!(plan.rows.len(), 1);

        let signatures: Vec<Cid> = ciborium::de::from_reader(plan.rows[0].1.as_slice()).unwrap();
        assert_eq!(signatures.len(), MAX_SIGNATURES_PER_TARGET);
        assert_eq!(
            signatures[0], trusted_signature,
            "a keyring-verified signature must survive saturated rebuild even when its embedded key disagrees"
        );
        assert!(signatures[1..]
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes()));
    }

    #[test]
    fn covering_is_target_driven_and_ignores_unrelated_corrupt_rows() {
        let (_temp, log) = log();
        let target = Cid::compute(b"protected-target");
        let signature = Cid::compute(b"signature");
        log.index(&target, &signature).unwrap();

        // A corrupt row elsewhere in the index must neither allocate nor
        // break collection for this independent retained target.
        let unrelated = Cid::compute(b"unrelated-target");
        let oversized = vec![0u8; MAX_SIGNATURE_INDEX_BYTES + 1];
        let txn = log.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SIG_BY_TARGET).unwrap();
            table
                .insert(unrelated.as_bytes(), oversized.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        assert_eq!(
            log.covering(&HashSet::from([target])).unwrap(),
            HashSet::from([signature])
        );
    }

    #[test]
    fn covering_walks_long_counter_signature_chains_without_fixpoint_scans() {
        let (_temp, log) = log();
        let chain: Vec<Cid> = (0..513)
            .map(|index| Cid::compute(format!("signature-{index}").as_bytes()))
            .collect();
        for pair in chain.windows(2) {
            log.index(&pair[0], &pair[1]).unwrap();
        }

        let closure = log.covering(&HashSet::from([chain[0].clone()])).unwrap();
        assert_eq!(closure.len(), chain.len() - 1);
        assert!(chain[1..].iter().all(|cid| closure.contains(cid)));
    }

    #[test]
    fn covering_fails_closed_at_aggregate_closure_limit() {
        let (_temp, log) = log();
        let target = Cid::compute(b"target");
        log.index(&target, &Cid::compute(b"signature-1")).unwrap();
        log.index(&target, &Cid::compute(b"signature-2")).unwrap();

        assert!(matches!(
            log.covering_with_limit(&HashSet::from([target]), 1),
            Err(ControlError::Capacity(_))
        ));
    }

    #[test]
    fn purpose_strings_round_trip_through_parse() {
        for p in [TrustPurpose::Verify, TrustPurpose::Adopt] {
            assert_eq!(p.as_str().parse::<TrustPurpose>().unwrap(), p);
        }
        assert!("sudo".parse::<TrustPurpose>().is_err());
    }
}
