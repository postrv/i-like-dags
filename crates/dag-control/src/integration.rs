//! Integration traits for job execution
//!
//! These traits provide clean abstractions between dag-control (orchestration)
//! and dag-jobs (execution), preventing circular dependencies.

use crate::error::Result;
use dag_core::{Cid, EffectKey, PinScope, PinTarget};

/// Trait for effect cache access (abstraction over JobLog)
pub trait EffectCache: Send + Sync {
    /// Get cached outputs for an effect key
    fn get(&self, key: &EffectKey) -> Result<Option<Vec<(String, Cid)>>>;

    /// Store outputs for an effect key
    fn store(&self, key: &EffectKey, outputs: &[(String, Cid)]) -> Result<()>;
}

/// Adoption of attested effect outputs (ADR-003), abstraction over
/// [`crate::Control`].
///
/// `adopt` returns outputs only when a claim for exactly this key carries a
/// keyring-trusted signature and every claimed output is present and intact
/// (invariant J7). Anything less is `None`, and the caller executes as if
/// no claim existed.
pub trait AttestedEffects: Send + Sync {
    fn adopt(&self, key: &EffectKey) -> Result<Option<Vec<(String, Cid)>>>;
}

impl AttestedEffects for crate::Control {
    fn adopt(&self, key: &EffectKey) -> Result<Option<Vec<(String, Cid)>>> {
        self.adopt_attested(key)
    }
}

/// Publication of effect claims after a run (ADR-003).
///
/// Implemented by [`crate::effects::EffectAttester`], which holds the
/// signing key; the runner only ever sees the trait, so execution paths
/// without a key cannot attest by accident.
pub trait EffectClaimSink: Send + Sync {
    fn record(&self, key: &EffectKey, outputs: &[(String, Cid)]) -> Result<()>;
}

/// Trait for pin creation (abstraction over PinLog)
pub trait PinCreator: Send + Sync {
    /// Create a pin for output retention, unless one with this ID already exists.
    ///
    /// This is idempotent by contract. Job output pin IDs are derived from the
    /// output CID, so a repeat run of a deterministic job re-derives the same
    /// ID — and an existing pin means that exact content is already retained.
    /// Returning an error there would make any pinning job single-use.
    ///
    /// Returns `true` if a new pin was created, `false` if one already existed.
    fn ensure_pin(
        &self,
        pin_id: &str,
        target: PinTarget,
        scope: PinScope,
        ttl: Option<u64>,
    ) -> Result<bool>;
}
