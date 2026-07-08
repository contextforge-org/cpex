// Location: ./crates/cpex-core/src/extensions/routing.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CandidateConstraintExtension — the backend candidate constraint the
// APL `restrict` effect produces, carried as a typed extension slot.
//
// The policy engine (apl-cpex) folds every `restrict` a request emitted
// into one of these and writes it into `Extensions.candidate_constraint`.
// The host router/load-balancer (Praxis's policy filter) reads it TYPED
// off `PipelineResult.modified_extensions` — the same in-process,
// type-shared channel `raw_credentials.delegated_tokens` rides — and
// narrows its candidate set accordingly. It is a routing directive, not
// an access decision: it never picks a backend and never allows/denies.
// See docs/apl-restrict-effect-design.md.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

/// What the host does when the constraint prunes every candidate.
///
/// The host — not CPEX — makes the empty decision, since only it knows
/// which backends are actually reachable/healthy at selection time. The
/// choice rides out with the constraint. Fail-closed by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnEmpty {
    /// Reject the request (fail-closed). Correct for hard constraints
    /// like data sovereignty — never silently escape the region.
    #[default]
    Deny,
    /// Fall back to the unconstrained candidate set. Explicit opt-in for
    /// "prefer, but don't fail" cases.
    Fallback,
}

/// The folded, request-level backend constraint emitted by APL `restrict`
/// effects. One per request; the policy engine intersects every restrict
/// that fired into this single value (allow-sets narrow, deny/custom
/// grow, tier ceilings collect, `on_empty` takes the strictest). All
/// monotone — it can only shrink the eligible set.
///
/// Field shape mirrors the authoring form (`apl_core::CandidateConstraint`)
/// with one divergence: `max_cost_tier` (one ceiling per restrict) folds
/// to `max_cost_tiers` (the *set* of ceilings). CPEX cannot order tier
/// names — that ordering is host-owned — so it emits every ceiling and
/// the host requires `cost_tier ≤ all of them`, which is `≤ min` once the
/// host applies its own tier order. See the design doc §2.5.1.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CandidateConstraintExtension {
    /// Candidate `model` must be in this set (glob-matched). `None` = no
    /// model allow-list. `Some(empty)` means nothing qualifies → the
    /// host's `on_empty` fires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_models: Option<Vec<String>>,

    /// Candidate `model` must NOT match any of these (glob-matched).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_models: Vec<String>,

    /// Candidate `region` must be in this set (equality).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_regions: Option<Vec<String>>,

    /// Candidate `site` must be in this set (equality).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_sites: Option<Vec<String>>,

    /// Every `cost_tier` ceiling emitted, de-duplicated. The host
    /// requires `cost_tier ≤` **all** of these (== `≤ min` under the
    /// host's tier order). CPEX never orders them itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub max_cost_tiers: Vec<String>,

    /// Arbitrary backend labels the candidate must carry, matched by
    /// plain equality (k8s `nodeSelector` semantics).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,

    /// What the host does when the constraint leaves no eligible backend.
    #[serde(default)]
    pub on_empty: OnEmpty,
}

impl CandidateConstraintExtension {
    /// True when nothing is constrained (every field unset). `on_empty`
    /// is ignored — on its own it restricts nothing. The policy engine
    /// skips writing an empty constraint into the extension slot.
    pub fn is_empty(&self) -> bool {
        self.allow_models.is_none()
            && self.deny_models.is_empty()
            && self.allow_regions.is_none()
            && self.allow_sites.is_none()
            && self.max_cost_tiers.is_empty()
            && self.custom.is_empty()
    }

    /// Does `backend` satisfy this constraint? This is the executable half
    /// of the seam contract (design §2.6) — the host router (Praxis) calls
    /// it per candidate to prune its eligible set, instead of
    /// reimplementing the matcher. All field semantics live here, once:
    ///
    /// - `allow_models` / `deny_models` — **glob** against the `model`
    ///   label (`anthropic/*`), not equality.
    /// - `allow_regions` / `allow_sites` — set membership (equality) on
    ///   the `region` / `site` labels.
    /// - `max_cost_tiers` — the `cost_tier` label must be `≤` **every**
    ///   ceiling. `tier_rank` maps a tier name to its order (lower =
    ///   cheaper); **the host owns that ordering** — the algorithm is
    ///   ours, the vocabulary is theirs. `≤ every ceiling` is `≤ min`.
    /// - `custom` — the backend must carry every label with an equal value.
    ///
    /// **Fail-closed** throughout: a constrained attribute the backend
    /// lacks (no `model` label under an `allow_models`, no `cost_tier`
    /// under a ceiling, an unrankable tier) excludes the backend rather
    /// than matching it. An empty constraint accepts everything.
    ///
    /// This is per-backend and does **not** apply `on_empty` — that is the
    /// caller's decision once it knows the surviving set is empty (only
    /// the router knows reachability). See [`Self::on_empty`].
    ///
    /// ```
    /// use std::collections::BTreeMap;
    /// use cpex_core::extensions::routing::CandidateConstraintExtension;
    ///
    /// let c = CandidateConstraintExtension {
    ///     allow_regions: Some(vec!["eu".into()]),
    ///     ..Default::default()
    /// };
    /// let eu: BTreeMap<String, String> = [("region".into(), "eu".into())].into();
    /// let us: BTreeMap<String, String> = [("region".into(), "us".into())].into();
    /// assert!(c.accepts(&eu, |_| None));
    /// assert!(!c.accepts(&us, |_| None));
    /// ```
    pub fn accepts(
        &self,
        backend: &impl BackendLabels,
        tier_rank: impl Fn(&str) -> Option<u32>,
    ) -> bool {
        // allow_models: the model must glob-match at least one pattern.
        if let Some(allow) = &self.allow_models {
            match backend.label(LABEL_MODEL) {
                Some(m) if allow.iter().any(|pat| glob_match(pat, m)) => {},
                _ => return false,
            }
        }
        // deny_models: the model must not glob-match any pattern.
        if let Some(m) = backend.label(LABEL_MODEL) {
            if self.deny_models.iter().any(|pat| glob_match(pat, m)) {
                return false;
            }
        }
        // allow_regions / allow_sites: equality set membership.
        if let Some(allow) = &self.allow_regions {
            match backend.label(LABEL_REGION) {
                Some(r) if allow.iter().any(|x| x == r) => {},
                _ => return false,
            }
        }
        if let Some(allow) = &self.allow_sites {
            match backend.label(LABEL_SITE) {
                Some(s) if allow.iter().any(|x| x == s) => {},
                _ => return false,
            }
        }
        // max_cost_tiers: cost_tier must rank ≤ every ceiling.
        if !self.max_cost_tiers.is_empty() {
            let Some(bt) = backend.label(LABEL_COST_TIER) else {
                return false;
            };
            let Some(backend_rank) = tier_rank(bt) else {
                return false; // unrankable backend tier — fail closed
            };
            for ceiling in &self.max_cost_tiers {
                match tier_rank(ceiling) {
                    Some(ceiling_rank) if backend_rank <= ceiling_rank => {},
                    _ => return false, // exceeds ceiling, or ceiling unrankable
                }
            }
        }
        // custom: every required label present with an equal value.
        for (k, v) in &self.custom {
            match backend.label(k) {
                Some(bv) if bv == v => {},
                _ => return false,
            }
        }
        true
    }
}

/// Well-known backend label keys the typed constraint fields match
/// against. Everything else in a backend's label set is `custom`.
pub const LABEL_MODEL: &str = "model";
pub const LABEL_REGION: &str = "region";
pub const LABEL_SITE: &str = "site";
pub const LABEL_COST_TIER: &str = "cost_tier";

/// A backend's labels, looked up by key — the input to
/// [`CandidateConstraintExtension::accepts`]. Implemented for the standard
/// string maps; a host whose backend labels live elsewhere implements it
/// directly (one method, no allocation).
pub trait BackendLabels {
    /// The value of label `key`, or `None` if the backend has no such label.
    fn label(&self, key: &str) -> Option<&str>;
}

impl BackendLabels for BTreeMap<String, String> {
    fn label(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl BackendLabels for HashMap<String, String> {
    fn label(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

/// Match `text` against a glob `pattern` where `*` matches any run of
/// characters (including empty). No other metacharacters — model ids are
/// the use case (`anthropic/*`, `*/claude-sonnet-4`, `vllm/*`). Operates
/// on bytes (model ids are ASCII); linear time with single-star backtrack.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Backtrack point: the last `*` seen and the text index to resume from.
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            resume = ti;
            pi += 1; // try matching `*` against zero chars first
        } else if let Some(s) = star {
            // Mismatch after a `*` — let the `*` swallow one more char.
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    // Trailing `*`s match the empty remainder.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_empty_true_for_default() {
        assert!(CandidateConstraintExtension::default().is_empty());
    }

    #[test]
    fn is_empty_ignores_on_empty() {
        let c = CandidateConstraintExtension {
            on_empty: OnEmpty::Fallback,
            ..Default::default()
        };
        assert!(c.is_empty());
    }

    #[test]
    fn empty_intersection_is_not_empty() {
        // Some([]) is a real (impossible) constraint, not "unset".
        let c = CandidateConstraintExtension {
            allow_regions: Some(vec![]),
            ..Default::default()
        };
        assert!(!c.is_empty());
    }

    #[test]
    fn json_omits_empty_fields() {
        let c = CandidateConstraintExtension {
            allow_regions: Some(vec!["eu".into()]),
            ..Default::default()
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "allow_regions": ["eu"], "on_empty": "deny" })
        );
    }

    #[test]
    fn json_roundtrips() {
        let c = CandidateConstraintExtension {
            allow_models: Some(vec!["vllm/*".into()]),
            deny_models: vec!["openai/*".into()],
            max_cost_tiers: vec!["cheap".into(), "standard".into()],
            custom: [("gpu".to_string(), "h100".to_string())].into(),
            on_empty: OnEmpty::Fallback,
            ..Default::default()
        };
        let back: CandidateConstraintExtension =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(c, back);
    }

    // ----- glob_match -----

    #[test]
    fn glob_exact_and_star() {
        assert!(glob_match("anthropic/claude-4", "anthropic/claude-4"));
        assert!(!glob_match("anthropic/claude-4", "anthropic/claude-5"));
        assert!(glob_match("*", "anything/at-all"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_prefix_suffix_middle() {
        assert!(glob_match("anthropic/*", "anthropic/claude-sonnet-4"));
        assert!(!glob_match("anthropic/*", "openai/gpt-4"));
        assert!(glob_match("*/claude-sonnet-4", "anthropic/claude-sonnet-4"));
        assert!(glob_match("anthropic/*-4", "anthropic/claude-sonnet-4"));
        assert!(!glob_match("anthropic/*-4", "anthropic/claude-sonnet-5"));
    }

    #[test]
    fn glob_star_matches_empty_run() {
        assert!(glob_match("vllm/*", "vllm/"));
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "axxbxxc"));
        assert!(!glob_match("a*b*c", "axxb")); // missing trailing c
    }

    // ----- accepts -----

    fn backend(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// cheap < standard < premium.
    fn rank(t: &str) -> Option<u32> {
        match t {
            "cheap" => Some(0),
            "standard" => Some(1),
            "premium" => Some(2),
            _ => None,
        }
    }

    #[test]
    fn empty_constraint_accepts_everything() {
        let c = CandidateConstraintExtension::default();
        assert!(c.accepts(&backend(&[("region", "eu")]), rank));
        assert!(c.accepts(&backend(&[]), rank));
    }

    #[test]
    fn allow_models_globs() {
        let c = CandidateConstraintExtension {
            allow_models: Some(vec!["anthropic/*".into(), "vllm/*".into()]),
            ..Default::default()
        };
        assert!(c.accepts(&backend(&[("model", "anthropic/claude-4")]), rank));
        assert!(c.accepts(&backend(&[("model", "vllm/llama")]), rank));
        assert!(!c.accepts(&backend(&[("model", "openai/gpt-4")]), rank));
        // No model label under an allow_models → excluded (fail-closed).
        assert!(!c.accepts(&backend(&[("region", "eu")]), rank));
    }

    #[test]
    fn deny_models_globs() {
        let c = CandidateConstraintExtension {
            deny_models: vec!["openai/*".into()],
            ..Default::default()
        };
        assert!(!c.accepts(&backend(&[("model", "openai/gpt-4")]), rank));
        assert!(c.accepts(&backend(&[("model", "anthropic/claude-4")]), rank));
        // No model label → not denied → passes.
        assert!(c.accepts(&backend(&[("region", "eu")]), rank));
    }

    #[test]
    fn allow_regions_equality() {
        let c = CandidateConstraintExtension {
            allow_regions: Some(vec!["eu".into()]),
            ..Default::default()
        };
        assert!(c.accepts(&backend(&[("region", "eu")]), rank));
        assert!(!c.accepts(&backend(&[("region", "us")]), rank));
        assert!(!c.accepts(&backend(&[]), rank)); // no region → excluded
    }

    #[test]
    fn max_cost_tiers_ceiling() {
        let c = CandidateConstraintExtension {
            max_cost_tiers: vec!["standard".into()],
            ..Default::default()
        };
        assert!(c.accepts(&backend(&[("cost_tier", "cheap")]), rank)); // 0 <= 1
        assert!(c.accepts(&backend(&[("cost_tier", "standard")]), rank)); // 1 <= 1
        assert!(!c.accepts(&backend(&[("cost_tier", "premium")]), rank)); // 2 > 1
        assert!(!c.accepts(&backend(&[]), rank)); // no cost_tier → excluded
    }

    #[test]
    fn max_cost_tiers_multiple_is_the_min() {
        // Backend must be ≤ every ceiling → ≤ min(cheap, standard) = cheap.
        let c = CandidateConstraintExtension {
            max_cost_tiers: vec!["cheap".into(), "standard".into()],
            ..Default::default()
        };
        assert!(c.accepts(&backend(&[("cost_tier", "cheap")]), rank));
        assert!(!c.accepts(&backend(&[("cost_tier", "standard")]), rank)); // > cheap
    }

    #[test]
    fn unrankable_tier_fails_closed() {
        let c = CandidateConstraintExtension {
            max_cost_tiers: vec!["standard".into()],
            ..Default::default()
        };
        // Backend tier the host can't rank → excluded, not matched.
        assert!(!c.accepts(&backend(&[("cost_tier", "mystery")]), rank));
    }

    #[test]
    fn custom_labels_equality() {
        let c = CandidateConstraintExtension {
            custom: [("gpu".to_string(), "h100".to_string())].into(),
            ..Default::default()
        };
        assert!(c.accepts(&backend(&[("gpu", "h100")]), rank));
        assert!(!c.accepts(&backend(&[("gpu", "a100")]), rank)); // wrong value
        assert!(!c.accepts(&backend(&[("region", "eu")]), rank)); // label absent
    }

    #[test]
    fn all_fields_must_pass_together() {
        let c = CandidateConstraintExtension {
            allow_regions: Some(vec!["eu".into()]),
            deny_models: vec!["openai/*".into()],
            max_cost_tiers: vec!["standard".into()],
            custom: [("gpu".to_string(), "h100".to_string())].into(),
            ..Default::default()
        };
        // Satisfies everything.
        assert!(c.accepts(
            &backend(&[
                ("region", "eu"),
                ("model", "anthropic/claude-4"),
                ("cost_tier", "cheap"),
                ("gpu", "h100"),
            ]),
            rank
        ));
        // One field off (region) → rejected.
        assert!(!c.accepts(
            &backend(&[
                ("region", "us"),
                ("model", "anthropic/claude-4"),
                ("cost_tier", "cheap"),
                ("gpu", "h100"),
            ]),
            rank
        ));
    }

    #[test]
    fn accepts_works_with_hashmap_labels() {
        let c = CandidateConstraintExtension {
            allow_regions: Some(vec!["eu".into()]),
            ..Default::default()
        };
        let labels: std::collections::HashMap<String, String> =
            [("region".to_string(), "eu".to_string())].into();
        assert!(c.accepts(&labels, rank));
    }
}
