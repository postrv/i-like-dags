//! The worked example: a model-release provenance ledger.
//!
//! See `docs/USE_CASE.md` for the narrative. [`seed`] builds the scenario end
//! to end; [`verify`] walks it back and re-checks it. Between them they
//! exercise every subsystem — content, entries, pointers, jobs, pins,
//! retention, recovery and events — which makes this both a demo and a smoke
//! test.
//!
//! It lives here rather than in the CLI so the HTTP API can offer the same
//! thing behind a button, and so the walk itself is testable without a shell.

use std::collections::{HashSet, VecDeque};

use anyhow::{Context, Result};
use dag_control::blocking::offload;
use dag_control::{Control, RetentionStatus};
use dag_core::{
    CachePolicy, Cid, ContentStore, Determinism, Entry, JobId, JobInput, JobPolicy, JobSpec, Link,
    MetaHint, PinScope, PinTarget, TriggerPolicy,
};
use dag_storage::GcCapableStore;
use serde::Serialize;

/// Maximum nodes read by one public worked-example verification.
pub const MAX_VERIFY_NODES: usize = 500;
/// Maximum aggregate stored bytes read by one verification (64 MiB).
pub const MAX_VERIFY_BYTES: usize = 64 * 1024 * 1024;
/// Maximum links inspected, including duplicate targets.
pub const MAX_VERIFY_LINKS: usize = 2_000;
/// Maximum distance from the selected release root.
pub const MAX_VERIFY_DEPTH: u32 = 64;

#[derive(Debug, Clone, Copy)]
struct VerifyLimits {
    nodes: usize,
    bytes: usize,
    links: usize,
    depth: u32,
}

impl VerifyLimits {
    const PUBLIC: Self = Self {
        nodes: MAX_VERIFY_NODES,
        bytes: MAX_VERIFY_BYTES,
        links: MAX_VERIFY_LINKS,
        depth: MAX_VERIFY_DEPTH,
    };
}

/// Pointer tracking the current dataset revision.
pub const PTR_DATASET: &str = "datasets/customer-transactions";
/// Pointer tracking the current training configuration.
pub const PTR_CONFIG: &str = "configs/fraud-detector";
/// Pointer tracking the current training code revision.
pub const PTR_CODE: &str = "code/fraud-detector";
/// Pointer tracking what is live in production.
pub const PTR_PRODUCTION: &str = "models/fraud-detector/production";
/// The attestation job that links a release to its inputs.
pub const JOB_ATTEST: &str = "attest-release";
/// Pin retaining the whole v2 release lineage.
pub const PIN_RELEASE: &str = "release/fraud-detector/v2";

/// What [`seed`] built.
#[derive(Debug, Clone, Serialize)]
pub struct SeedReport {
    /// Pointer naming the live release.
    pub production_pointer: String,
    /// Attestation produced by the first release.
    pub attestation_v1: String,
    /// Attestation produced after the dataset was revised.
    pub attestation_v2: String,
    /// Pointer naming the dataset.
    pub dataset_pointer: String,
    /// The attestation job's ID.
    pub job_id: String,
    /// Pin retaining the release lineage.
    pub release_pin: String,
    /// Unpinned-after-expiry scratch content, to demonstrate collection.
    pub scratch_cid: String,
    /// Chunk count after seeding.
    pub chunks: usize,
    /// Pointer count after seeding.
    pub pointers: usize,
    /// Pin count after seeding.
    pub pins: usize,
    /// Whether the recovery gate is now satisfied.
    pub recovered: bool,
}

/// Build the scenario.
///
/// Idempotent: if the example is already present this reports the existing
/// state and changes nothing. That matters because seeding deliberately walks
/// the dataset pointer through two revisions — replaying it would append a
/// third and a fourth, which is not what pressing "Load example" twice should
/// mean.
pub async fn seed(control: &Control, recover: bool) -> Result<SeedReport> {
    // The scenario is a long stretch of synchronous store and redb work with
    // two job runs in the middle. Each stretch is offloaded so it does not hold
    // a runtime worker — and so the SSE keep-alives sharing that worker keep
    // flowing while a console seeds. See dag_control::blocking.
    if let Some(existing) = offload(|| existing_seed(control))? {
        return Ok(existing);
    }

    let (dataset_card_v1, job_id) = offload(|| {
        // ① Raw artefacts, stored as immutable chunks.
        let dataset_v1 = put_text(
            control,
            "text/csv",
            "txn_id,account,amount,label\n1,acc-118,42.00,legit\n2,acc-771,9900.00,fraud\n",
        )?;
        let config_v1 = put_text(
            control,
            "application/toml",
            "[train]\nmodel = \"gbdt\"\nmax_depth = 6\nseed = 1337\n",
        )?;
        let code_v1 = put_text(
            control,
            "text/x-python",
            "def train(df, cfg):\n    return fit_gbdt(df, depth=cfg.max_depth, seed=cfg.seed)\n",
        )?;

        // ② An entry is payload + links. The card is human-readable metadata; the
        // link is what makes the raw bytes reachable by traversal.
        let dataset_card_v1 = put_entry(
            control,
            serde_json::json!({
                "kind": "dataset-card/v1",
                "name": "customer-transactions",
                "revision": "2026-Q1",
                "rows": 2,
                "pii": false,
            }),
            vec![Link::named(dataset_v1, "rows.csv")],
        )?;

        // ③ Name each input so downstream jobs can track it as it changes.
        upsert_pointer(control, PTR_DATASET, dataset_card_v1.clone())?;
        upsert_pointer(control, PTR_CONFIG, config_v1)?;
        upsert_pointer(control, PTR_CODE, code_v1)?;

        // ④ The attestation job reads those pointers and publishes what it saw.
        let job_id = JobId::from(JOB_ATTEST.to_string());
        ensure_job(
            control,
            JobSpec {
                job_id: job_id.clone(),
                placement: None,
                inputs: JobInput {
                    static_inputs: vec![],
                    pointer_inputs: vec![
                        PTR_DATASET.to_string(),
                        PTR_CONFIG.to_string(),
                        PTR_CODE.to_string(),
                    ],
                },
                determinism: Determinism::Deterministic,
                declared_outputs: vec!["attestation".to_string()],
                code_ref: "attest".to_string(),
                policy: JobPolicy {
                    // Pin what the job produces: an attestation nobody retains is
                    // an audit trail garbage collection is free to erase.
                    cache_outputs: CachePolicy::Pin { ttl: None },
                    trigger: TriggerPolicy::OnPointerUpdate,
                },
                config: None,
            },
        )?;
        control.subscribe_pointer(PTR_DATASET, job_id.clone())?;
        Ok::<_, anyhow::Error>((dataset_card_v1, job_id))
    })?;

    // ⑤ Release v1.
    let v1 = dag_jobs::execute_once(control, &job_id).await?;

    let (attestation_v1, dataset_card_v2) = offload(|| {
        let attestation_v1 = output_cid(&v1.outputs, "attestation")?;
        upsert_pointer(control, PTR_PRODUCTION, attestation_v1.clone())?;

        // ⑥ Revise the dataset; the same job now attests different inputs.
        let dataset_v2 = put_text(
        control,
        "text/csv",
        "txn_id,account,amount,label\n1,acc-118,42.00,legit\n2,acc-771,9900.00,fraud\n3,acc-402,15.50,legit\n",
    )?;
        let dataset_card_v2 = put_entry(
            control,
            serde_json::json!({
                "kind": "dataset-card/v1",
                "name": "customer-transactions",
                "revision": "2026-Q2",
                "rows": 3,
                "pii": false,
            }),
            vec![
                Link::named(dataset_v2, "rows.csv"),
                // Linking the previous card makes revision history traversable
                // from the data itself, not just from the pointer log.
                Link::named(dataset_card_v1, "supersedes"),
            ],
        )?;
        Ok::<_, anyhow::Error>((attestation_v1, dataset_card_v2))
    })?;
    upsert_pointer(control, PTR_DATASET, dataset_card_v2)?;

    let v2 = dag_jobs::execute_once(control, &job_id).await?;

    offload(|| {
        let attestation_v2 = output_cid(&v2.outputs, "attestation")?;
        upsert_pointer(control, PTR_PRODUCTION, attestation_v2.clone())?;

        // ⑦ A subtree pin on the attestation transitively protects the dataset
        // card, the raw CSV, the config and the code — everything it links.
        upsert_pin(
            control,
            PIN_RELEASE,
            PinTarget::Subtree {
                root: attestation_v2.clone(),
                max_depth: None,
            },
            None,
        )?;

        // Scratch output with a short TTL, so retention visibly expires.
        let scratch = put_text(control, "text/plain", "scratch: feature-importance dump\n")?;
        upsert_pin(
            control,
            "scratch/feature-dump",
            PinTarget::Direct(scratch.clone()),
            Some(dag_control::now_unix() + 3600),
        )?;

        // ⑧ The local CLI may explicitly run the bounded full recovery. The
        // HTTP seeder passes `false`: a convenience route must not trigger a
        // whole-store maintenance scan. Partial pointer+pin rebuilds are not
        // sufficient because collection also relies on signature, claim, and
        // job-event indexes.
        if recover && !control.is_recovered()? {
            control.recover()?;
        }

        let stats = control.stats()?;
        Ok(SeedReport {
            production_pointer: PTR_PRODUCTION.to_string(),
            attestation_v1: attestation_v1.to_hex(),
            attestation_v2: attestation_v2.to_hex(),
            dataset_pointer: PTR_DATASET.to_string(),
            job_id: JOB_ATTEST.to_string(),
            release_pin: PIN_RELEASE.to_string(),
            scratch_cid: scratch.to_hex(),
            chunks: stats.chunks,
            pointers: stats.pointers,
            pins: stats.pins,
            recovered: stats.recovered,
        })
    })
}

/// Report the already-seeded scenario, or `None` if it is not present.
///
/// Presence is decided by the production pointer resolving *and* the
/// attestation job having runs — a half-built scenario should be completed,
/// not reported as done.
fn existing_seed(control: &Control) -> Result<Option<SeedReport>> {
    let job_id = JobId::from(JOB_ATTEST.to_string());
    let Ok(production) = control.pointer_log.resolve(PTR_PRODUCTION) else {
        return Ok(None);
    };

    // Runs come back newest first; the oldest is the v1 release.
    let runs = control.job_log.get_job_runs(&job_id, None)?;
    let Some(first) = runs.last() else {
        return Ok(None);
    };
    let Some((_, attestation_v1)) = first.outputs.first() else {
        return Ok(None);
    };

    let stats = control.stats()?;
    Ok(Some(SeedReport {
        production_pointer: PTR_PRODUCTION.to_string(),
        attestation_v1: attestation_v1.to_hex(),
        attestation_v2: production.to_hex(),
        dataset_pointer: PTR_DATASET.to_string(),
        job_id: JOB_ATTEST.to_string(),
        release_pin: PIN_RELEASE.to_string(),
        scratch_cid: control
            .pin_log
            .head("scratch/feature-dump")
            .ok()
            .map(|head| match head.event.target {
                PinTarget::Direct(cid) => cid.to_hex(),
                PinTarget::Subtree { root, .. } => root.to_hex(),
            })
            .unwrap_or_default(),
        chunks: stats.chunks,
        pointers: stats.pointers,
        pins: stats.pins,
        recovered: stats.recovered,
    }))
}

/// One node in a verified provenance walk.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedNode {
    /// CID of the node.
    pub cid: String,
    /// Link name that led here; absent for the root.
    pub name: Option<String>,
    /// Distance from the release root.
    pub depth: u32,
    /// Byte length of the stored chunk.
    pub size: usize,
    /// Whether the bytes on disk still hash to this CID.
    pub intact: bool,
    /// Populated when the node could not be verified.
    pub error: Option<String>,
}

/// Result of walking a release back to its inputs.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    /// Pointer that was resolved.
    pub pointer: String,
    /// CID the pointer resolved to.
    pub root: String,
    /// Every reachable node, breadth-first from the root.
    pub nodes: Vec<VerifiedNode>,
    /// Total reachable nodes.
    pub total_nodes: usize,
    /// Nodes whose bytes still match their CID.
    pub intact: usize,
    /// Nodes that failed verification.
    pub corrupt: usize,
    /// Total bytes across the lineage.
    pub total_bytes: usize,
    /// Whether the root is currently protected from collection.
    pub retained: bool,
    /// True when every reachable node verified.
    pub verified: bool,
}

/// Walk a release back to its inputs, re-hashing every chunk on the way.
///
/// This is the claim the whole system exists to support: given only a pointer
/// name, recover the complete input set of a release and prove none of it has
/// changed since it was published.
pub fn verify(control: &Control, pointer: &str) -> Result<VerifyReport> {
    let root = control
        .pointer_log
        .resolve(pointer)
        .with_context(|| format!("resolving {}", pointer))?;

    verify_root(control, pointer, root)
}

/// Verify a release named directly by its root CID.
///
/// The regulator's question is "which model was live on 12 March", and until
/// now only the *current* head could be verified — so a historical release,
/// which is the only kind anyone asks about after the fact, had no command.
/// Pair this with `dag pointer resolve --at-seq/--as-of`.
pub fn verify_cid(control: &Control, root: &Cid) -> Result<VerifyReport> {
    verify_root(control, &root.to_hex(), root.clone())
}

fn verify_root(control: &Control, label: &str, root: Cid) -> Result<VerifyReport> {
    let nodes = walk(control, &root)?;
    let intact = nodes.iter().filter(|n| n.intact).count();
    let corrupt = nodes.len() - intact;
    let total_bytes = nodes.iter().map(|n| n.size).sum();
    let retained = matches!(
        control.retention_status(&root, None)?,
        RetentionStatus::Protected(_)
    );

    Ok(VerifyReport {
        pointer: label.to_string(),
        root: root.to_hex(),
        total_nodes: nodes.len(),
        intact,
        corrupt,
        total_bytes,
        retained,
        verified: corrupt == 0,
        nodes,
    })
}

/// Breadth-first walk of an entry's link graph, verifying each chunk.
fn walk(control: &Control, root: &Cid) -> Result<Vec<VerifiedNode>> {
    walk_with_limits(control, root, VerifyLimits::PUBLIC)
}

fn walk_with_limits(
    control: &Control,
    root: &Cid,
    limits: VerifyLimits,
) -> Result<Vec<VerifiedNode>> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut nodes = Vec::new();
    let mut bytes_read = 0usize;
    let mut links_examined = 0usize;

    queue.push_back((root.clone(), None::<String>, 0u32));
    seen.insert(root.clone());

    while let Some((cid, name, depth)) = queue.pop_front() {
        if nodes.len() >= limits.nodes {
            return Err(dag_core::CoreError::FileLimitExceeded {
                resource: "verification nodes",
                value: nodes.len().saturating_add(1) as u64,
                limit: limits.nodes as u64,
            }
            .into());
        }
        if depth > limits.depth {
            return Err(dag_core::CoreError::FileLimitExceeded {
                resource: "verification depth",
                value: u64::from(depth),
                limit: u64::from(limits.depth),
            }
            .into());
        }

        let mut node = VerifiedNode {
            cid: cid.to_hex(),
            name,
            depth,
            size: 0,
            intact: false,
            error: None,
        };

        match control.store.get_inventory_chunk_size(&cid) {
            Ok(size) => {
                bytes_read =
                    bytes_read
                        .checked_add(size)
                        .ok_or(dag_core::CoreError::FileLimitExceeded {
                            resource: "verification bytes",
                            value: u64::MAX,
                            limit: limits.bytes as u64,
                        })?;
                if bytes_read > limits.bytes {
                    return Err(dag_core::CoreError::FileLimitExceeded {
                        resource: "verification bytes",
                        value: bytes_read as u64,
                        limit: limits.bytes as u64,
                    }
                    .into());
                }
                node.size = size;
            }
            Err(error) => {
                tracing::warn!(%cid, error = %error, "scenario verification could not inspect chunk");
                node.error = Some(safe_chunk_error(&error).to_string());
                nodes.push(node);
                continue;
            }
        }

        match control.store.get_chunk(&cid) {
            Ok(bytes) => {
                // The no-follow metadata preflight prevents a known-large
                // object from being read, but an external replacement can
                // change length between stat and read. Reconcile to the bytes
                // actually hashed and enforce the aggregate ceiling again.
                bytes_read = bytes_read
                    .checked_sub(node.size)
                    .and_then(|charged| charged.checked_add(bytes.len()))
                    .ok_or(dag_core::CoreError::FileLimitExceeded {
                        resource: "verification bytes",
                        value: u64::MAX,
                        limit: limits.bytes as u64,
                    })?;
                if bytes_read > limits.bytes {
                    return Err(dag_core::CoreError::FileLimitExceeded {
                        resource: "verification bytes",
                        value: bytes_read as u64,
                        limit: limits.bytes as u64,
                    }
                    .into());
                }
                node.size = bytes.len();
                // The CID *is* the hash of these bytes, so recomputing it
                // detects any change to what is on disk.
                node.intact = Cid::compute(&bytes) == cid;
                if !node.intact {
                    node.error = Some("stored bytes do not match CID".to_string());
                }

                // Only entries have links; a raw chunk simply fails to decode.
                if let Ok(entry) = Entry::from_bytes_cbor(&bytes) {
                    for link in entry.links {
                        links_examined = links_examined.checked_add(1).ok_or(
                            dag_core::CoreError::FileLimitExceeded {
                                resource: "verification links",
                                value: u64::MAX,
                                limit: limits.links as u64,
                            },
                        )?;
                        if links_examined > limits.links {
                            return Err(dag_core::CoreError::FileLimitExceeded {
                                resource: "verification links",
                                value: links_examined as u64,
                                limit: limits.links as u64,
                            }
                            .into());
                        }
                        if seen.insert(link.target.clone()) {
                            let child_depth = depth.checked_add(1).ok_or_else(|| {
                                dag_core::CoreError::FileLimitExceeded {
                                    resource: "verification depth",
                                    value: u64::MAX,
                                    limit: u64::from(limits.depth),
                                }
                            })?;
                            if child_depth > limits.depth {
                                return Err(dag_core::CoreError::FileLimitExceeded {
                                    resource: "verification depth",
                                    value: u64::from(child_depth),
                                    limit: u64::from(limits.depth),
                                }
                                .into());
                            }
                            queue.push_back((link.target, link.name, child_depth));
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%cid, error = %error, "scenario verification could not read chunk");
                node.error = Some(safe_chunk_error(&error).to_string());
            }
        }

        nodes.push(node);
    }

    Ok(nodes)
}

fn safe_chunk_error(error: &dag_core::CoreError) -> &'static str {
    match error {
        dag_core::CoreError::ChunkNotFound(_) => "chunk is missing",
        dag_core::CoreError::CidMismatch { .. } => "stored bytes do not match CID",
        dag_core::CoreError::ChunkTooLarge { .. } => "stored chunk exceeds the size limit",
        _ => "chunk could not be read",
    }
}

// ---- helpers ----------------------------------------------------------

fn put_text(control: &Control, content_type: &str, body: &str) -> Result<Cid> {
    Ok(control.store.put_chunk(
        body.as_bytes(),
        Some(MetaHint {
            content_type: Some(content_type.to_string()),
            encoding: None,
        }),
    )?)
}

fn put_entry(control: &Control, payload: serde_json::Value, links: Vec<Link>) -> Result<Cid> {
    let entry = Entry::new(
        serde_json::to_vec(&payload)?,
        links,
        Some(MetaHint {
            content_type: Some("application/json".to_string()),
            encoding: None,
        }),
    );
    Ok(control.store.put_entry(&entry)?)
}

/// Create the pointer, or move it forward if it already exists.
fn upsert_pointer(control: &Control, id: &str, cid: Cid) -> Result<()> {
    match control.pointer_log.get_head(id) {
        Ok(head) if head.current_cid == cid => Ok(()),
        Ok(_) => {
            control.pointer_log.update(id, cid)?;
            Ok(())
        }
        Err(dag_control::PointerError::NotFound(_)) => {
            control.pointer_log.create(id, cid)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Create the pin unless one with this ID already exists.
fn upsert_pin(
    control: &Control,
    id: &str,
    target: PinTarget,
    expires_at: Option<i64>,
) -> Result<()> {
    match control.pin_log.head(id) {
        Ok(_) => return Ok(()),
        Err(dag_core::PinError::PinNotFound(_)) => {}
        Err(error) => return Err(error.into()),
    }
    control.pin_log.create(
        id,
        target,
        PinScope::Global,
        expires_at,
        Some("usecase-seed".to_string()),
    )?;
    Ok(())
}

/// Register the job unless it already exists.
fn ensure_job(control: &Control, spec: JobSpec) -> Result<()> {
    if control.job_log.get_job(&spec.job_id)?.is_some() {
        return Ok(());
    }
    control.create_job(spec)?;
    Ok(())
}

fn output_cid(outputs: &[(String, Cid)], name: &str) -> Result<Cid> {
    outputs
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, cid)| cid.clone())
        .with_context(|| format!("job produced no output named {:?}", name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_control::test_utils::TestControl;

    #[tokio::test]
    async fn seed_then_verify_reports_an_intact_lineage() -> Result<()> {
        let tc = TestControl::new()?;
        let report = seed(&tc.control, true).await?;

        assert_ne!(
            report.attestation_v1, report.attestation_v2,
            "revising the dataset must change the attestation"
        );
        assert!(report.recovered, "seeding should satisfy the recovery gate");

        let verified = verify(&tc.control, PTR_PRODUCTION)?;
        assert!(verified.verified, "freshly seeded lineage must verify");
        assert!(
            verified.retained,
            "release subtree pin must protect the root"
        );
        assert_eq!(verified.corrupt, 0);
        // attestation -> {dataset card v2, config, code} -> {csv, card v1} -> csv
        assert_eq!(verified.total_nodes, 7);

        Ok(())
    }

    #[tokio::test]
    async fn seed_is_idempotent() -> Result<()> {
        let tc = TestControl::new()?;
        let first = seed(&tc.control, true).await?;
        let second = seed(&tc.control, true).await?;

        assert_eq!(first.attestation_v2, second.attestation_v2);
        assert_eq!(
            first.chunks, second.chunks,
            "re-seeding must not create new content"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verify_detects_tampered_bytes() -> Result<()> {
        use dag_storage::GcCapableStore;

        let tc = TestControl::new()?;
        seed(&tc.control, true).await?;

        // Corrupt one chunk in place, exactly as bit rot or tampering would.
        let target = tc.control.pointer_log.resolve(PTR_CONFIG)?;
        std::fs::write(tc.control.store.chunk_path(&target), b"tampered")?;

        let report = verify(&tc.control, PTR_PRODUCTION)?;
        assert!(!report.verified, "tampering must be detected");
        assert_eq!(report.corrupt, 1);
        assert!(report
            .nodes
            .iter()
            .any(|n| n.cid == target.to_hex() && !n.intact));
        assert_eq!(
            report
                .nodes
                .iter()
                .find(|node| node.cid == target.to_hex())
                .and_then(|node| node.error.as_deref()),
            Some("stored bytes do not match CID")
        );

        // Sanity: the store still lists the chunk, so this is detection by
        // hashing rather than by the file having vanished.
        assert!(tc.control.store.list_all_cids()?.contains(&target));
        Ok(())
    }

    #[test]
    fn verification_refuses_each_aggregate_walk_limit() -> Result<()> {
        fn assert_limit(error: anyhow::Error, expected: &'static str) {
            let limit = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<dag_core::CoreError>());
            assert!(matches!(
                limit,
                Some(dag_core::CoreError::FileLimitExceeded { resource, .. })
                    if *resource == expected
            ));
        }

        let tc = TestControl::new()?;
        let leaf = tc.control.store.put_chunk(b"leaf", None)?;
        let two_links = tc.control.store.put_entry(&Entry::with_links(vec![
            Link::unnamed(leaf.clone()),
            Link::unnamed(leaf.clone()),
        ]))?;

        assert_limit(
            walk_with_limits(
                &tc.control,
                &leaf,
                VerifyLimits {
                    bytes: 1,
                    ..VerifyLimits::PUBLIC
                },
            )
            .unwrap_err(),
            "verification bytes",
        );
        assert_limit(
            walk_with_limits(
                &tc.control,
                &two_links,
                VerifyLimits {
                    nodes: 1,
                    ..VerifyLimits::PUBLIC
                },
            )
            .unwrap_err(),
            "verification nodes",
        );
        assert_limit(
            walk_with_limits(
                &tc.control,
                &two_links,
                VerifyLimits {
                    links: 1,
                    ..VerifyLimits::PUBLIC
                },
            )
            .unwrap_err(),
            "verification links",
        );

        let child = tc
            .control
            .store
            .put_entry(&Entry::with_links(vec![Link::unnamed(leaf)]))?;
        let root = tc
            .control
            .store
            .put_entry(&Entry::with_links(vec![Link::unnamed(child)]))?;
        assert_limit(
            walk_with_limits(
                &tc.control,
                &root,
                VerifyLimits {
                    depth: 1,
                    ..VerifyLimits::PUBLIC
                },
            )
            .unwrap_err(),
            "verification depth",
        );
        Ok(())
    }

    #[test]
    fn public_chunk_errors_never_include_internal_io_details() {
        let error = dag_core::CoreError::Io(std::io::Error::other(
            "reading /var/lib/private-dag/data/secret",
        ));
        assert_eq!(safe_chunk_error(&error), "chunk could not be read");
    }
}
