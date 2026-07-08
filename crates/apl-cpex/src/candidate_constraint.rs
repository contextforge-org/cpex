// Location: ./crates/apl-cpex/src/candidate_constraint.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Fold — combine the `restrict` constraints a request emitted (apl-core
// authoring IR) into one typed `CandidateConstraintExtension` (cpex-core
// wire type) the host router reads off the returned `Extensions`. This is
// the bridge between the pure policy language and the framework's typed
// extension slot, the same role `apply_session_taints` plays for taints.
// See docs/apl-restrict-effect-design.md §2.4/§2.5.

use apl_core::constraint::{CandidateConstraint, OnEmpty as AplOnEmpty};
use cpex_core::extensions::{CandidateConstraintExtension, OnEmpty};

use std::collections::{BTreeMap, BTreeSet};

/// Two `restrict` effects require the same `custom` label to equal two
/// different values — no backend can satisfy both. The route handler maps
/// this to a fail-closed deny (never silently drops a requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintConflict {
    pub key: String,
    pub existing: String,
    pub incoming: String,
}

impl std::fmt::Display for ConstraintConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "conflicting `restrict` custom label `{}`: `{}` vs `{}` \
             (no backend can be both)",
            self.key, self.existing, self.incoming
        )
    }
}

/// Fold a request's emitted constraints into one typed extension. Returns
/// `Ok(None)` when there is nothing to emit (no constraints, or they fold
/// to an unrestricting result). Order-independent — the input may arrive
/// in any order (constraints from parallel branches merge unsorted).
///
/// Monotone semantics (design §2.4): allow-sets **intersect**,
/// `deny_models` **union**, `max_cost_tier` ceilings **collect** into
/// `max_cost_tiers` (CPEX can't order tier names — the host reduces to the
/// min), `custom` **union**, `on_empty` takes the **strictest**
/// (`Deny` beats `Fallback`). A `custom` key required to hold two
/// different values is an unsatisfiable contradiction → `Err`.
pub fn fold_candidate_constraints(
    constraints: &[CandidateConstraint],
) -> Result<Option<CandidateConstraintExtension>, ConstraintConflict> {
    if constraints.is_empty() {
        return Ok(None);
    }

    let mut allow_models: Option<Vec<String>> = None;
    let mut allow_regions: Option<Vec<String>> = None;
    let mut allow_sites: Option<Vec<String>> = None;
    let mut deny_models: BTreeSet<String> = BTreeSet::new();
    let mut tiers: BTreeSet<String> = BTreeSet::new();
    let mut custom: BTreeMap<String, String> = BTreeMap::new();
    // Start at the least strict and tighten. A restrict with no explicit
    // policy still defaults to `Deny` (the parser default), so the fold
    // lands on `Deny` in the common case.
    let mut on_empty = OnEmpty::Fallback;

    for c in constraints {
        intersect_into(&mut allow_models, c.allow_models.as_deref());
        intersect_into(&mut allow_regions, c.allow_regions.as_deref());
        intersect_into(&mut allow_sites, c.allow_sites.as_deref());
        deny_models.extend(c.deny_models.iter().cloned());
        if let Some(tier) = &c.max_cost_tier {
            tiers.insert(tier.clone());
        }
        for (k, v) in &c.custom {
            if let Some(existing) = custom.get(k) {
                if existing != v {
                    return Err(ConstraintConflict {
                        key: k.clone(),
                        existing: existing.clone(),
                        incoming: v.clone(),
                    });
                }
            } else {
                custom.insert(k.clone(), v.clone());
            }
        }
        on_empty = strictest(on_empty, map_on_empty(c.on_empty));
    }

    let folded = CandidateConstraintExtension {
        allow_models,
        deny_models: deny_models.into_iter().collect(),
        allow_regions,
        allow_sites,
        max_cost_tiers: tiers.into_iter().collect(),
        custom,
        on_empty,
    };

    if folded.is_empty() {
        Ok(None)
    } else {
        Ok(Some(folded))
    }
}

/// The stricter of two `on_empty` policies — `Deny` beats `Fallback`.
fn strictest(a: OnEmpty, b: OnEmpty) -> OnEmpty {
    match (a, b) {
        (OnEmpty::Fallback, OnEmpty::Fallback) => OnEmpty::Fallback,
        _ => OnEmpty::Deny,
    }
}

/// Map the apl-core authoring enum to the cpex-core wire enum. Kept
/// explicit (rather than a `From`) because the two live in crates that
/// don't depend on each other.
fn map_on_empty(v: AplOnEmpty) -> OnEmpty {
    match v {
        AplOnEmpty::Deny => OnEmpty::Deny,
        AplOnEmpty::Fallback => OnEmpty::Fallback,
    }
}

/// Intersect `incoming` (a candidate's allow-set, or `None` for "no
/// constraint") into `acc`. `None` is the universe: intersecting with it
/// is a no-op, and the first `Some` seeded into a `None` accumulator
/// becomes the running set. Result is sorted + de-duplicated for a
/// deterministic blob. An empty result (`Some([])`) is retained — it means
/// "no candidate qualifies", which the host resolves via `on_empty`.
fn intersect_into(acc: &mut Option<Vec<String>>, incoming: Option<&[String]>) {
    let Some(incoming) = incoming else {
        return; // no constraint from this restrict — universe, no-op
    };
    let incoming: BTreeSet<&String> = incoming.iter().collect();
    match acc {
        None => *acc = Some(incoming.into_iter().cloned().collect()),
        Some(existing) => existing.retain(|e| incoming.contains(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c() -> CandidateConstraint {
        CandidateConstraint::default()
    }
    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }
    fn fold(cs: &[CandidateConstraint]) -> CandidateConstraintExtension {
        fold_candidate_constraints(cs).unwrap().unwrap()
    }

    #[test]
    fn empty_input_is_none() {
        assert_eq!(fold_candidate_constraints(&[]).unwrap(), None);
    }

    #[test]
    fn single_passes_through_with_default_deny() {
        let folded = fold(&[CandidateConstraint {
            allow_regions: Some(strs(&["eu"])),
            ..c()
        }]);
        assert_eq!(folded.allow_regions, Some(strs(&["eu"])));
        assert_eq!(folded.on_empty, OnEmpty::Deny);
    }

    #[test]
    fn allow_sets_intersect() {
        let folded = fold(&[
            CandidateConstraint {
                allow_models: Some(strs(&["vllm/*", "anthropic/*", "openai/*"])),
                ..c()
            },
            CandidateConstraint {
                allow_models: Some(strs(&["anthropic/*", "openai/*", "cohere/*"])),
                ..c()
            },
        ]);
        assert_eq!(folded.allow_models, Some(strs(&["anthropic/*", "openai/*"])));
    }

    #[test]
    fn unconstrained_allow_is_noop() {
        let folded = fold(&[
            CandidateConstraint {
                allow_regions: Some(strs(&["eu"])),
                ..c()
            },
            CandidateConstraint {
                deny_models: strs(&["openai/*"]),
                ..c()
            },
        ]);
        assert_eq!(folded.allow_regions, Some(strs(&["eu"])));
        assert_eq!(folded.deny_models, strs(&["openai/*"]));
    }

    #[test]
    fn empty_intersection_retained_for_on_empty() {
        let folded = fold(&[
            CandidateConstraint {
                allow_regions: Some(strs(&["eu"])),
                ..c()
            },
            CandidateConstraint {
                allow_regions: Some(strs(&["us"])),
                ..c()
            },
        ]);
        assert_eq!(folded.allow_regions, Some(vec![]));
        assert!(!folded.is_empty());
    }

    #[test]
    fn deny_sets_union() {
        let folded = fold(&[
            CandidateConstraint {
                deny_models: strs(&["openai/*"]),
                ..c()
            },
            CandidateConstraint {
                deny_models: strs(&["cohere/*", "openai/*"]),
                ..c()
            },
        ]);
        assert_eq!(folded.deny_models, strs(&["cohere/*", "openai/*"]));
    }

    #[test]
    fn cost_tiers_collect_all_distinct() {
        // Option-1 fold: CPEX can't order tiers, so emit every ceiling.
        let folded = fold(&[
            CandidateConstraint {
                max_cost_tier: Some("cheap".into()),
                ..c()
            },
            CandidateConstraint {
                max_cost_tier: Some("standard".into()),
                ..c()
            },
            CandidateConstraint {
                max_cost_tier: Some("cheap".into()),
                ..c()
            },
        ]);
        assert_eq!(folded.max_cost_tiers, strs(&["cheap", "standard"]));
    }

    #[test]
    fn custom_union() {
        let folded = fold(&[
            CandidateConstraint {
                custom: [("gpu".to_string(), "h100".to_string())].into(),
                ..c()
            },
            CandidateConstraint {
                custom: [("tenancy".to_string(), "dedicated".to_string())].into(),
                ..c()
            },
        ]);
        assert_eq!(folded.custom.get("gpu"), Some(&"h100".to_string()));
        assert_eq!(folded.custom.get("tenancy"), Some(&"dedicated".to_string()));
    }

    #[test]
    fn custom_same_key_same_value_ok() {
        let folded = fold(&[
            CandidateConstraint {
                custom: [("gpu".to_string(), "h100".to_string())].into(),
                ..c()
            },
            CandidateConstraint {
                custom: [("gpu".to_string(), "h100".to_string())].into(),
                ..c()
            },
        ]);
        assert_eq!(folded.custom.get("gpu"), Some(&"h100".to_string()));
    }

    #[test]
    fn custom_conflict_fails_closed() {
        let err = fold_candidate_constraints(&[
            CandidateConstraint {
                custom: [("gpu".to_string(), "h100".to_string())].into(),
                ..c()
            },
            CandidateConstraint {
                custom: [("gpu".to_string(), "a100".to_string())].into(),
                ..c()
            },
        ])
        .unwrap_err();
        assert_eq!(
            err,
            ConstraintConflict {
                key: "gpu".into(),
                existing: "h100".into(),
                incoming: "a100".into(),
            }
        );
    }

    #[test]
    fn on_empty_strictest_wins() {
        let folded = fold(&[
            CandidateConstraint {
                allow_regions: Some(strs(&["eu"])),
                on_empty: AplOnEmpty::Fallback,
                ..c()
            },
            CandidateConstraint {
                deny_models: strs(&["openai/*"]),
                on_empty: AplOnEmpty::Deny,
                ..c()
            },
        ]);
        assert_eq!(folded.on_empty, OnEmpty::Deny);
    }

    #[test]
    fn all_fallback_stays_fallback() {
        let folded = fold(&[
            CandidateConstraint {
                allow_regions: Some(strs(&["eu"])),
                on_empty: AplOnEmpty::Fallback,
                ..c()
            },
            CandidateConstraint {
                deny_models: strs(&["openai/*"]),
                on_empty: AplOnEmpty::Fallback,
                ..c()
            },
        ]);
        assert_eq!(folded.on_empty, OnEmpty::Fallback);
    }

    #[test]
    fn fold_is_order_independent() {
        let a = CandidateConstraint {
            allow_models: Some(strs(&["vllm/*", "anthropic/*"])),
            deny_models: strs(&["openai/*"]),
            ..c()
        };
        let b = CandidateConstraint {
            allow_models: Some(strs(&["anthropic/*", "cohere/*"])),
            max_cost_tier: Some("cheap".into()),
            ..c()
        };
        assert_eq!(
            fold_candidate_constraints(&[a.clone(), b.clone()]).unwrap(),
            fold_candidate_constraints(&[b, a]).unwrap()
        );
    }
}
