// Location: ./crates/apl-core/src/constraint.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Backend candidate-constraint IR for the `restrict` effect.
//
// `restrict` narrows the set of backends the host's router/load-balancer
// may select from — it never picks a backend (see
// docs/apl-restrict-effect-design.md). It normally does not allow/deny the
// request either; the one exception is fail-closed integrity — an
// unresolvable `deny_models` reference denies, since a deny-list cannot fail
// open (see `RestrictResolveError`). It is an accumulating
// effect in the same family as `taint`: the evaluator collects the
// constraints a route emits into `RouteDecision.constraints`, and the
// bridge (apl-cpex) folds them into a typed `CandidateConstraintExtension`
// the host reads off the returned `Extensions`. This type is the *authoring*
// IR — one constraint per `restrict` effect. It stays pure-data with no
// cpex-core dependency, matching the rest of `rules.rs`; the fold + the
// wire/extension type live at the bridge layer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::attributes::{AttributeBag, AttributeValue};

/// One backend-eligibility constraint emitted by a `restrict` effect.
///
/// Every field describes a requirement a candidate backend must satisfy;
/// the host evaluates them against each backend's labels. The shape is a
/// deliberately **simple set of typed fields plus a `custom` label map** —
/// not a general predicate language — so the host only has to run a small
/// label matcher (set membership, glob, tier compare, equality), not a
/// predicate interpreter.
///
/// All fields are optional/empty by default; an all-empty
/// `CandidateConstraint` places no restriction (see [`Self::is_empty`]).
/// Constraints are **monotone**: combining two of them (the bridge's fold)
/// can only ever shrink the eligible set (allow-sets intersect, deny-sets
/// and `custom` union), never widen it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CandidateConstraint {
    /// Candidate `model` label must be in this set (glob-matched, e.g.
    /// `"anthropic/claude-sonnet-*"`). `None` = no model allow-list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_models: Option<Vec<String>>,

    /// Candidate `model` label must NOT match any of these (glob-matched).
    /// Empty = no model deny-list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_models: Vec<String>,

    /// Candidate `region` label must be in this set (equality). `None` =
    /// no region constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_regions: Option<Vec<String>>,

    /// Candidate `site` label must be in this set (equality). `None` = no
    /// site constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sites: Option<Vec<String>>,

    /// Candidate `cost_tier` label must be ≤ this tier. The *ordering* of
    /// tiers is defined on the host (the matcher), so this stays a plain
    /// label here — CPEX passes it through without needing to know the
    /// order. `None` = no tier ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_tier: Option<String>,

    /// Arbitrary backend labels the candidate must carry, matched by plain
    /// equality (k8s `nodeSelector` semantics). The escape hatch for
    /// backend attributes without a typed field above. Empty = none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,

    /// What the host should do if the constraint prunes every candidate.
    /// Fail-closed by default (see [`OnEmpty`]).
    #[serde(default)]
    pub on_empty: OnEmpty,
}

impl CandidateConstraint {
    /// True when this constraint restricts nothing — every field is unset.
    /// The evaluator skips emitting an all-empty constraint, and it's a
    /// useful guard in tests.
    pub fn is_empty(&self) -> bool {
        self.allow_models.is_none()
            && self.deny_models.is_empty()
            && self.allow_regions.is_none()
            && self.allow_sites.is_none()
            && self.max_cost_tier.is_none()
            && self.custom.is_empty()
    }
}

/// What the host does when a constraint leaves no eligible backend.
///
/// CPEX cannot decide this itself — only the router knows which backends
/// are actually reachable/healthy at selection time — so the choice rides
/// out with the constraint. The default is fail-closed.
///
/// Mirrors `cpex_core::extensions::OnEmpty` (the bridge maps between them);
/// kept here so apl-core stays free of a cpex-core dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnEmpty {
    /// Reject the request (fail-closed). Correct for hard constraints like
    /// data sovereignty — never silently escape the region.
    #[default]
    Deny,
    /// Fall back to the unconstrained candidate set. Explicit opt-in for
    /// "prefer, but don't fail" cases.
    Fallback,
}

/// A `restrict` string-set field: either a literal set or a `data.*`/bag
/// reference resolved against the request at eval time (design §4.3). The
/// YAML shape disambiguates — a sequence is a literal, a bare scalar is a
/// reference:
///
/// ```yaml
/// allow_models: [vllm/*, anthropic/*]                    # Literal
/// allow_models: data.agents[subject.id].allowed_models   # Ref
/// ```
///
/// A reference lets one rule serve every caller — the per-agent /
/// per-tenant set lives in the [static attribute tree][crate::AttributeTree],
/// not hard-coded in the route.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringSetSpec {
    /// A `data.*` / bag path resolved to a set at eval time. A bare scalar
    /// in YAML (`allow_models: data.agents[subject.id].allowed_models`).
    Ref(String),
    /// A literal set. A YAML sequence (`allow_models: [vllm/*]`).
    Literal(Vec<String>),
}

impl StringSetSpec {
    /// Resolve to a concrete set, or `None` if a reference could not be
    /// resolved. A `Literal` always resolves (`Some`). A `Ref` looks its
    /// path up in the request bag (expanding `[...]` interpolation) and
    /// reads the `StringSet`/`String` there; a **missing key or wrong-shape
    /// value** yields `None`. A legitimately empty `StringSet` still resolves
    /// to `Some([])` — "resolved to nothing" is distinct from "couldn't
    /// resolve," and the caller ([`RestrictSpec::resolve`]) decides what each
    /// means per field.
    fn resolve(&self, bag: &AttributeBag) -> Option<Vec<String>> {
        match self {
            StringSetSpec::Literal(v) => Some(v.clone()),
            StringSetSpec::Ref(path) => {
                // Interpolation itself failed (e.g. the `[...]` key is absent).
                let key = bag.resolve_key(path)?;
                match bag.get(&key) {
                    Some(AttributeValue::StringSet(s)) => {
                        let mut v: Vec<String> = s.iter().cloned().collect();
                        v.sort();
                        Some(v)
                    },
                    Some(AttributeValue::String(s)) => Some(vec![s.clone()]),
                    // Absent, or present but not a set/string — the reference
                    // did not resolve to a usable set.
                    _ => None,
                }
            },
        }
    }
}

/// Why a `restrict` effect could not be resolved against the request bag.
///
/// Today only an unresolvable `deny_models` reference produces this — a
/// deny-list whose `data.*` source is missing or the wrong shape. An
/// allow-list fails closed by *shrinking* to the empty set (`Some([])`), a
/// value it can represent; a deny-list would have to *grow* to "deny
/// everything," which the empty vector cannot express. So an unresolvable
/// deny reference is treated as an integrity failure — the evaluator denies
/// the request rather than route it with an unknown deny-list.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "restrict: `{field}` reference `{path}` did not resolve to a set — denying \
     (a deny-list cannot fail open)"
)]
pub struct RestrictResolveError {
    /// The `restrict` field that failed to resolve (e.g. `"deny_models"`).
    pub field: &'static str,
    /// The `data.*` reference path that did not resolve.
    pub path: String,
}

/// The authoring form of a `restrict` effect. Same fields as
/// [`CandidateConstraint`], except the string-set fields may be a literal
/// **or** a `data.*` reference ([`StringSetSpec`]). The parser produces
/// this; the evaluator calls [`Self::resolve`] to turn it into a literal
/// `CandidateConstraint` before accumulating — references never reach the
/// fold or the wire. (`max_cost_tier` and `custom` are literal-only in v1.)
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RestrictSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_models: Option<StringSetSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_models: Option<StringSetSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_regions: Option<StringSetSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sites: Option<StringSetSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_tier: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
    #[serde(default)]
    pub on_empty: OnEmpty,
}

impl RestrictSpec {
    /// True when no constraint field is set. The parser rejects an empty
    /// `restrict:` on this (`on_empty` alone constrains nothing).
    pub fn is_empty(&self) -> bool {
        self.allow_models.is_none()
            && self.deny_models.is_none()
            && self.allow_regions.is_none()
            && self.allow_sites.is_none()
            && self.max_cost_tier.is_none()
            && self.custom.is_empty()
    }

    /// Resolve every `data.*` reference against the request bag, producing
    /// the literal `CandidateConstraint` the evaluator accumulates — or a
    /// [`RestrictResolveError`] if a deny-list reference could not be
    /// resolved.
    ///
    /// The two list kinds fail closed in opposite directions:
    /// * **Allow-lists** (`allow_models` / `allow_regions` / `allow_sites`):
    ///   an unresolvable reference resolves to the empty set (`Some([])`),
    ///   which qualifies no candidate. The host's `on_empty` then decides.
    /// * **Deny-lists** (`deny_models`): an unresolvable reference is an
    ///   integrity failure — a deny-list has no "empty = deny everything"
    ///   value, so we cannot safely route with an unknown one. Returns `Err`
    ///   and the evaluator denies the request.
    pub fn resolve(&self, bag: &AttributeBag) -> Result<CandidateConstraint, RestrictResolveError> {
        // Allow-lists fail closed by shrinking to empty — `None` (unresolved)
        // collapses to `Some([])`, preserving the pre-reference behavior.
        let allow_models = self
            .allow_models
            .as_ref()
            .map(|s| s.resolve(bag).unwrap_or_default());
        let allow_regions = self
            .allow_regions
            .as_ref()
            .map(|s| s.resolve(bag).unwrap_or_default());
        let allow_sites = self
            .allow_sites
            .as_ref()
            .map(|s| s.resolve(bag).unwrap_or_default());

        // A deny-list that references data cannot fail open: an unresolvable
        // reference denies the request. A literal deny-list always resolves.
        let deny_models = match self.deny_models.as_ref() {
            None => Vec::new(),
            Some(spec) => match spec.resolve(bag) {
                Some(v) => v,
                None => {
                    let path = match spec {
                        StringSetSpec::Ref(p) => p.clone(),
                        // A literal always resolves to `Some`, so this is
                        // unreachable — kept total for safety.
                        StringSetSpec::Literal(_) => String::new(),
                    };
                    return Err(RestrictResolveError {
                        field: "deny_models",
                        path,
                    });
                },
            },
        };

        Ok(CandidateConstraint {
            allow_models,
            deny_models,
            allow_regions,
            allow_sites,
            max_cost_tier: self.max_cost_tier.clone(),
            custom: self.custom.clone(),
            on_empty: self.on_empty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::AttributeBag;

    // `is_empty()` is hand-written on both `CandidateConstraint` and
    // `RestrictSpec` (and mirrored again on the cpex-core extension). A field
    // that's added to the struct but forgotten in `is_empty()` would make a
    // real restriction look empty and get silently dropped. The exhaustive
    // destructures below (no `..`) fail to compile if a field is added
    // without updating these tests, and the per-field asserts force each
    // constraint-bearing field to count toward non-emptiness.

    #[test]
    fn candidate_constraint_is_empty_covers_every_field() {
        // No `..`: adding a field breaks this until it's accounted for.
        let CandidateConstraint {
            allow_models,
            deny_models,
            allow_regions,
            allow_sites,
            max_cost_tier,
            custom,
            on_empty: _, // `on_empty` alone never makes a constraint non-empty
        } = CandidateConstraint::default();
        assert!(allow_models.is_none());
        assert!(deny_models.is_empty());
        assert!(allow_regions.is_none());
        assert!(allow_sites.is_none());
        assert!(max_cost_tier.is_none());
        assert!(custom.is_empty());
        assert!(CandidateConstraint::default().is_empty());

        // Setting any single constraint-bearing field flips `is_empty()`.
        let each: [CandidateConstraint; 6] = [
            CandidateConstraint {
                allow_models: Some(vec![]),
                ..Default::default()
            },
            CandidateConstraint {
                deny_models: vec!["x".into()],
                ..Default::default()
            },
            CandidateConstraint {
                allow_regions: Some(vec![]),
                ..Default::default()
            },
            CandidateConstraint {
                allow_sites: Some(vec![]),
                ..Default::default()
            },
            CandidateConstraint {
                max_cost_tier: Some("cheap".into()),
                ..Default::default()
            },
            CandidateConstraint {
                custom: [("k".to_string(), "v".to_string())].into(),
                ..Default::default()
            },
        ];
        for c in each {
            assert!(!c.is_empty(), "field should count toward non-empty: {c:?}");
        }
        // `on_empty` alone does not.
        assert!(CandidateConstraint {
            on_empty: OnEmpty::Fallback,
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn restrict_spec_is_empty_covers_every_field() {
        let RestrictSpec {
            allow_models,
            deny_models,
            allow_regions,
            allow_sites,
            max_cost_tier,
            custom,
            on_empty: _,
        } = RestrictSpec::default();
        assert!(allow_models.is_none());
        assert!(deny_models.is_none());
        assert!(allow_regions.is_none());
        assert!(allow_sites.is_none());
        assert!(max_cost_tier.is_none());
        assert!(custom.is_empty());
        assert!(RestrictSpec::default().is_empty());

        let lit = |s: &str| Some(StringSetSpec::Literal(vec![s.to_string()]));
        let each: [RestrictSpec; 6] = [
            RestrictSpec {
                allow_models: lit("m"),
                ..Default::default()
            },
            RestrictSpec {
                deny_models: lit("m"),
                ..Default::default()
            },
            RestrictSpec {
                allow_regions: lit("eu"),
                ..Default::default()
            },
            RestrictSpec {
                allow_sites: lit("s"),
                ..Default::default()
            },
            RestrictSpec {
                max_cost_tier: Some("cheap".into()),
                ..Default::default()
            },
            RestrictSpec {
                custom: [("k".to_string(), "v".to_string())].into(),
                ..Default::default()
            },
        ];
        for s in each {
            assert!(!s.is_empty(), "field should count toward non-empty: {s:?}");
        }
        assert!(RestrictSpec {
            on_empty: OnEmpty::Fallback,
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn nonempty_spec_resolves_to_nonempty_constraint() {
        // Cross-struct parity: a spec non-empty on any single field must
        // resolve to a constraint that is ALSO non-empty — otherwise the
        // evaluator's `if !constraint.is_empty()` guard would silently drop a
        // real restriction. Catches a field the two `is_empty()`s (or
        // `resolve()`) disagree on.
        let bag = AttributeBag::new();
        let lit = |s: &str| Some(StringSetSpec::Literal(vec![s.to_string()]));
        let specs: [RestrictSpec; 6] = [
            RestrictSpec {
                allow_models: lit("m"),
                ..Default::default()
            },
            RestrictSpec {
                deny_models: lit("m"),
                ..Default::default()
            },
            RestrictSpec {
                allow_regions: lit("eu"),
                ..Default::default()
            },
            RestrictSpec {
                allow_sites: lit("s"),
                ..Default::default()
            },
            RestrictSpec {
                max_cost_tier: Some("cheap".into()),
                ..Default::default()
            },
            RestrictSpec {
                custom: [("k".to_string(), "v".to_string())].into(),
                ..Default::default()
            },
        ];
        for spec in specs {
            assert!(!spec.is_empty(), "spec should be non-empty: {spec:?}");
            let c = spec.resolve(&bag).expect("literal spec always resolves");
            assert!(
                !c.is_empty(),
                "non-empty spec resolved to a dropped constraint: {spec:?}"
            );
        }
    }
}
