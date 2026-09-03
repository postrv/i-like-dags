//! Validation of content closures before a control-plane root is published.
//!
//! A pointer or subtree pin is a promise that everything reachable from its
//! root remains readable.  The promise must be checked while the caller holds
//! the control mutation gate: garbage collection holds the exclusive side of
//! that gate, so validation and collection cannot pass one another unnoticed.

use dag_core::{Cid, ContentStore, CoreError};
use std::collections::{HashMap, HashSet, VecDeque};

/// How far a published reference promises reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReferenceDepth {
    /// Validate and protect only the named CID (a non-file direct pin).
    Named,
    /// Validate descendants through this many links.
    Descendants(u32),
    /// Validate the complete reachable closure (a pointer or unbounded pin).
    Unlimited,
}

impl ReferenceDepth {
    fn permits_links(self) -> bool {
        !matches!(self, Self::Named | Self::Descendants(0))
    }

    fn child(self) -> Self {
        match self {
            Self::Named | Self::Descendants(0) => Self::Named,
            Self::Descendants(depth) => Self::Descendants(depth - 1),
            Self::Unlimited => Self::Unlimited,
        }
    }

    pub(crate) fn covers(self, other: Self) -> bool {
        match (self, other) {
            (Self::Unlimited, _) => true,
            (_, Self::Unlimited) => false,
            (Self::Named | Self::Descendants(0), Self::Named | Self::Descendants(0)) => true,
            (Self::Named | Self::Descendants(0), Self::Descendants(_)) => false,
            (Self::Descendants(_), Self::Named | Self::Descendants(0)) => true,
            (Self::Descendants(left), Self::Descendants(right)) => left >= right,
        }
    }
}

/// Why a root cannot safely be published.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReferenceValidationError {
    /// The configured ceiling stopped the walk before its closure was known.
    #[error(
        "reference closure exceeds the configured ceiling of {max_expansion} objects \
         (validated {validated}); raise --max-subtree-expansion and retry"
    )]
    Limit {
        validated: usize,
        max_expansion: usize,
    },
    /// One named object or descendant was absent, corrupt, or unreadable.
    #[error("reference closure is unreadable at {cid}: {detail}")]
    Unreadable {
        cid: Cid,
        detail: String,
        /// Unique objects successfully read before the failure.
        validated: usize,
        /// Globally bounded queue work reserved by this attempt.
        work: usize,
    },
}

/// A complete validated closure and the bounded queue work it consumed.
pub(crate) struct ReferenceValidation {
    pub(crate) cids: HashSet<Cid>,
    /// The deepest coverage proved for each CID during this walk.
    pub(crate) coverage: HashMap<Cid, ReferenceDepth>,
    pub(crate) work: usize,
}

/// Validate and register every CID promised by a set of new roots.
///
/// The walk is iterative and deduplicated. `max_expansion` bounds both unique
/// CIDs and link-expansion work, so cycles, heavily shared graphs, and roots
/// reached at successively greater depths cannot produce unbounded work. A
/// limit is a refusal, never a partial success.
///
/// Every successfully read CID is passed to [`ContentStore::note_reference`]
/// before this returns. FsStore's final deletion gate therefore observes the
/// same complete closure that the caller validated.
pub(crate) fn validate_and_note_references<S, I>(
    store: &S,
    roots: I,
    max_expansion: usize,
) -> Result<HashSet<Cid>, ReferenceValidationError>
where
    S: ContentStore + ?Sized,
    I: IntoIterator<Item = (Cid, ReferenceDepth)>,
{
    validate_and_note_references_with_work(store, roots, max_expansion).map(|report| report.cids)
}

/// The work-reporting form used when several independently fallible candidate
/// roots must share one global budget.
pub(crate) fn validate_and_note_references_with_work<S, I>(
    store: &S,
    roots: I,
    max_expansion: usize,
) -> Result<ReferenceValidation, ReferenceValidationError>
where
    S: ContentStore + ?Sized,
    I: IntoIterator<Item = (Cid, ReferenceDepth)>,
{
    validate_and_note_references_with_seeded_work(store, roots, max_expansion, &HashMap::new())
}

/// Validate roots while charging only coverage not already proved by an
/// earlier complete walk.
///
/// A seed is depth-aware: a named-only proof does not suppress a later
/// descendant walk. Covered states require neither another store read nor
/// another unit of queue work, which keeps several overlapping closures under
/// one real global ceiling. The caller must add a report's coverage to later
/// seeds only after that report succeeds; errors never expose a partial proof.
pub(crate) fn validate_and_note_references_with_seeded_work<S, I>(
    store: &S,
    roots: I,
    max_expansion: usize,
    known_coverage: &HashMap<Cid, ReferenceDepth>,
) -> Result<ReferenceValidation, ReferenceValidationError>
where
    S: ContentStore + ?Sized,
    I: IntoIterator<Item = (Cid, ReferenceDepth)>,
{
    let mut scheduled: HashMap<Cid, ReferenceDepth> = HashMap::new();
    let mut root_order = Vec::new();
    for (cid, depth) in roots {
        if known_coverage
            .get(&cid)
            .is_some_and(|already| already.covers(depth))
        {
            continue;
        }
        let should_queue = scheduled
            .get(&cid)
            .is_none_or(|already| !already.covers(depth));
        if should_queue {
            if !scheduled.contains_key(&cid) {
                if scheduled.len() >= max_expansion {
                    return Err(ReferenceValidationError::Limit {
                        validated: 0,
                        max_expansion,
                    });
                }
                root_order.push(cid.clone());
            }
            scheduled.insert(cid.clone(), depth);
        }
    }

    // Queue each deduplicated root once, at the deepest requested coverage.
    // Updating a root's depth while ingesting the iterator therefore cannot
    // allocate an unbounded chain of stale queue states.
    let mut queue = VecDeque::with_capacity(root_order.len());
    for cid in root_order {
        let depth = scheduled[&cid];
        queue.push_back((cid, depth));
    }
    let mut scheduled_work = queue.len();

    let mut validated = HashSet::new();
    let mut expanded: HashMap<Cid, ReferenceDepth> = HashMap::new();

    while let Some((cid, depth)) = queue.pop_front() {
        if known_coverage
            .get(&cid)
            .is_some_and(|already| already.covers(depth))
        {
            continue;
        }
        // A deeper occurrence may have superseded this queued state.
        if scheduled.get(&cid).is_some_and(|scheduled_depth| {
            scheduled_depth.covers(depth) && *scheduled_depth != depth
        }) {
            continue;
        }
        if expanded
            .get(&cid)
            .is_some_and(|already| already.covers(depth))
        {
            continue;
        }

        if !validated.contains(&cid) && validated.len() >= max_expansion {
            return Err(ReferenceValidationError::Limit {
                validated: validated.len(),
                max_expansion,
            });
        }
        let links = match store.get_links(&cid) {
            Ok(links) => links,
            // Arbitrary chunks are legitimate leaves. `get_links` has already
            // read and CID-verified their bytes; only Entry decoding failed.
            Err(CoreError::Deserialization(_)) => Vec::new(),
            Err(error) => {
                return Err(ReferenceValidationError::Unreadable {
                    cid,
                    detail: error.to_string(),
                    validated: validated.len(),
                    work: scheduled_work,
                });
            }
        };

        store.note_reference(&cid);
        validated.insert(cid.clone());
        expanded.insert(cid, depth);

        if !depth.permits_links() {
            continue;
        }
        let child_depth = depth.child();
        for link in links {
            if known_coverage
                .get(&link.target)
                .is_some_and(|already| already.covers(child_depth))
            {
                continue;
            }
            let should_queue = scheduled
                .get(&link.target)
                .is_none_or(|already| !already.covers(child_depth));
            if should_queue {
                if !scheduled.contains_key(&link.target) && scheduled.len() >= max_expansion {
                    return Err(ReferenceValidationError::Limit {
                        validated: validated.len(),
                        max_expansion,
                    });
                }
                if scheduled_work >= max_expansion {
                    return Err(ReferenceValidationError::Limit {
                        validated: validated.len(),
                        max_expansion,
                    });
                }
                scheduled_work += 1;
                scheduled.insert(link.target.clone(), child_depth);
                queue.push_back((link.target, child_depth));
            }
        }
    }

    Ok(ReferenceValidation {
        cids: validated,
        coverage: expanded,
        work: scheduled_work,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dag_core::{ContentStore, Entry, Link};
    use dag_storage::FsStore;

    #[test]
    fn refuses_a_missing_descendant_instead_of_returning_a_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path()).unwrap();
        let missing = Cid::compute(b"not stored");
        let root = store
            .put_entry(&Entry::new(
                Vec::new(),
                vec![Link {
                    name: None,
                    target: missing.clone(),
                }],
                None,
            ))
            .unwrap();

        let error = validate_and_note_references(&store, [(root, ReferenceDepth::Unlimited)], 100)
            .unwrap_err();
        assert!(matches!(
            error,
            ReferenceValidationError::Unreadable { cid, .. } if cid == missing
        ));
    }

    #[test]
    fn a_named_reference_does_not_walk_links() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path()).unwrap();
        let missing = Cid::compute(b"not stored");
        let root = store
            .put_entry(&Entry::new(
                Vec::new(),
                vec![Link {
                    name: None,
                    target: missing,
                }],
                None,
            ))
            .unwrap();

        let validated =
            validate_and_note_references(&store, [(root.clone(), ReferenceDepth::Named)], 1)
                .unwrap();
        assert_eq!(validated, HashSet::from([root]));
    }

    #[test]
    fn the_ceiling_is_a_hard_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path()).unwrap();
        let leaf = store.put_chunk(b"leaf", None).unwrap();
        let root = store
            .put_entry(&Entry::new(
                Vec::new(),
                vec![Link {
                    name: None,
                    target: leaf,
                }],
                None,
            ))
            .unwrap();

        assert!(matches!(
            validate_and_note_references(&store, [(root, ReferenceDepth::Unlimited)], 1,),
            Err(ReferenceValidationError::Limit {
                max_expansion: 1,
                ..
            })
        ));
    }

    #[test]
    fn root_ingestion_is_bounded_and_deduplicates_depth_upgrades() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path()).unwrap();
        let first = store.put_chunk(b"first", None).unwrap();
        let second = store.put_chunk(b"second", None).unwrap();

        assert!(matches!(
            validate_and_note_references(
                &store,
                [
                    (first.clone(), ReferenceDepth::Named),
                    (second, ReferenceDepth::Named),
                ],
                1,
            ),
            Err(ReferenceValidationError::Limit {
                max_expansion: 1,
                ..
            })
        ));

        let validated = validate_and_note_references(
            &store,
            [
                (first.clone(), ReferenceDepth::Named),
                (first.clone(), ReferenceDepth::Descendants(10)),
                (first.clone(), ReferenceDepth::Unlimited),
            ],
            1,
        )
        .unwrap();
        assert_eq!(validated, HashSet::from([first]));
    }

    #[test]
    fn seeded_coverage_is_depth_aware_and_charges_only_new_states() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(dir.path()).unwrap();
        let leaf = store.put_chunk(b"leaf", None).unwrap();
        let root = store
            .put_entry(&Entry::new(
                Vec::new(),
                vec![Link::unnamed(leaf.clone())],
                None,
            ))
            .unwrap();

        // A named proof says nothing about descendants, so requesting the
        // unlimited closure still needs two units and cannot fit in one.
        let named_only = HashMap::from([(root.clone(), ReferenceDepth::Named)]);
        assert!(matches!(
            validate_and_note_references_with_seeded_work(
                &store,
                [(root.clone(), ReferenceDepth::Unlimited)],
                1,
                &named_only,
            ),
            Err(ReferenceValidationError::Limit {
                max_expansion: 1,
                ..
            })
        ));

        // Once the leaf's unlimited coverage is known, only the root is new.
        let known_leaf = HashMap::from([(leaf, ReferenceDepth::Unlimited)]);
        let report = validate_and_note_references_with_seeded_work(
            &store,
            [(root.clone(), ReferenceDepth::Unlimited)],
            1,
            &known_leaf,
        )
        .unwrap();
        assert_eq!(report.work, 1);
        assert_eq!(report.cids, HashSet::from([root.clone()]));
        assert_eq!(
            report.coverage,
            HashMap::from([(root, ReferenceDepth::Unlimited)])
        );
    }
}
