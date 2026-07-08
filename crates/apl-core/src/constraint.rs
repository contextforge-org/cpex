// Location: ./crates/apl-core/src/constraint.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Backend candidate-constraint IR for the `restrict` effect.
//
// `restrict` narrows the set of backends the host's router/load-balancer
// may select from — it never picks a backend and never allows/denies the
// request (see docs/apl-restrict-effect-design.md). It is an accumulating
// effect in the same family as `taint`: the evaluator collects the
// constraints a route emits into `RouteDecision.constraints`, and the
// bridge (apl-cpex) folds them into a typed `CandidateConstraintExtension`
// the host reads off the returned `Extensions`. This type is the *authoring*
// IR — one constraint per `restrict` effect. It stays pure-data with no
// cpex-core dependency, matching the rest of `rules.rs`; the fold + the
// wire/extension type live at the bridge layer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    /// Resolve to a concrete set. A `Literal` is returned as-is; a `Ref`
    /// looks its path up in the request bag (expanding `[...]`
    /// interpolation) and reads the `StringSet` there. An absent or
    /// non-set reference resolves to the **empty set** — fail-closed: an
    /// allow-list that didn't resolve qualifies no candidate, and the
    /// host's `on_empty` decides. A single string value is taken as a
    /// one-element set.
    fn resolve(&self, bag: &AttributeBag) -> Vec<String> {
        match self {
            StringSetSpec::Literal(v) => v.clone(),
            StringSetSpec::Ref(path) => match bag.resolve_key(path) {
                Some(key) => match bag.get(&key) {
                    Some(AttributeValue::StringSet(s)) => {
                        let mut v: Vec<String> = s.iter().cloned().collect();
                        v.sort();
                        v
                    },
                    Some(AttributeValue::String(s)) => vec![s.clone()],
                    _ => Vec::new(),
                },
                None => Vec::new(),
            },
        }
    }
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
    /// the literal `CandidateConstraint` the evaluator accumulates.
    pub fn resolve(&self, bag: &AttributeBag) -> CandidateConstraint {
        CandidateConstraint {
            allow_models: self.allow_models.as_ref().map(|s| s.resolve(bag)),
            deny_models: self
                .deny_models
                .as_ref()
                .map(|s| s.resolve(bag))
                .unwrap_or_default(),
            allow_regions: self.allow_regions.as_ref().map(|s| s.resolve(bag)),
            allow_sites: self.allow_sites.as_ref().map(|s| s.resolve(bag)),
            max_cost_tier: self.max_cost_tier.clone(),
            custom: self.custom.clone(),
            on_empty: self.on_empty,
        }
    }
}
