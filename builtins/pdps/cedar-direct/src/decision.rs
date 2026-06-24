// Location: ./builtins/pdps/cedar-direct/src/decision.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Translation from `cedar_policy::Response` into `apl_core::PdpDecision`.
//
// What we preserve:
//
//   - `decision`     — Allow ↔ Deny. One-to-one.
//   - `diagnostics`  — the set of policy IDs that *determined* the
//                      decision (not "matched" — Cedar's `reason()` is
//                      the policies whose effect produced the outcome).
//                      Operators who annotated their policies with
//                      `@id("...")` get meaningful identifiers; without
//                      annotations they get `policy0`, `policy1`, ….
//   - `rule_source`  — first policy ID from `diagnostics`. Becomes the
//                      violation code on Deny so audit logs / wire
//                      errors say "denied via owner-override" rather
//                      than "cedar.deny."
//
// What we drop (for now):
//
//   - Obligations — Cedar 4.10 doesn't have first-class obligations.
//     Policy annotations could carry them (`@obligation(...)`) but
//     wiring the annotation vocabulary is deferred — see
//     `docs/specs/cedar-context-contract.md`.
//
// # Fail-closed on evaluation errors
//
// Cedar's `Response::diagnostics().errors()` lists policies that errored
// during runtime evaluation (e.g. type errors in a `when` clause that
// only manifest with certain entity data). If ANY policy errored, we
// return Deny regardless of what `decision()` says — an untrusted
// decision is worse than a closed gate. The error messages flow into
// the Deny reason so operators see why.

use apl_core::evaluator::Decision;
use apl_core::step::PdpDecision;
use cedar_policy::{Decision as CedarDecision, PolicySet};

/// Translate a `cedar_policy::Response` into the APL-side `PdpDecision`.
/// Captures policy-ID attribution into `diagnostics` and, on Deny,
/// surfaces the first firing policy as the `rule_source`.
///
/// # `@id` annotation lookup
///
/// `PolicySet::from_str` assigns auto-IDs (`policy0`, `policy1`, ...);
/// authors get *meaningful* identifiers by annotating each policy with
/// `@id("my-rule")`. We resolve auto-IDs to annotation values here so
/// the rest of the system sees the names operators chose. Policies
/// without `@id` annotations keep their auto-IDs — explicit-is-better
/// fallback rather than silent translation.
pub fn translate(response: &cedar_policy::Response, policy_set: &PolicySet) -> PdpDecision {
    let diagnostics = response.diagnostics();

    let firing_policies: Vec<String> = diagnostics
        .reason()
        .map(|pid| {
            // Prefer the operator-supplied `@id("...")` annotation;
            // fall back to Cedar's auto-generated id when the policy
            // is unannotated.
            policy_set
                .policy(pid)
                .and_then(|p| p.annotation("id"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| pid.to_string())
        })
        .collect();

    let errors: Vec<String> = diagnostics
        .errors()
        .map(|e| e.to_string())
        .collect();

    // Fail-closed: any runtime evaluation error → Deny with the error
    // text so the operator sees what went wrong. Cedar's own
    // `decision()` may still say Allow when errors occurred; we override
    // because an Allow on a partially-failed evaluation isn't
    // trustworthy.
    if !errors.is_empty() {
        let reason = format!(
            "Cedar evaluation produced errors (fail-closed): {}",
            errors.join("; ")
        );
        let rule_source = firing_policies
            .first()
            .cloned()
            .unwrap_or_else(|| "cedar.evaluation_error".to_string());
        return PdpDecision {
            decision: Decision::Deny {
                reason: Some(reason),
                rule_source,
            },
            diagnostics: firing_policies,
        };
    }

    let decision = match response.decision() {
        CedarDecision::Allow => Decision::Allow,
        CedarDecision::Deny => {
            // Build a human-readable reason from the firing policies so
            // wire errors and audit logs carry attribution. First
            // policy ID becomes the violation code.
            let reason = if firing_policies.is_empty() {
                // Cedar deny with no firing policy means no `permit`
                // matched — the "default deny" case.
                "no Cedar permit policy matched the request".to_string()
            } else {
                format!("denied by Cedar policy: {}", firing_policies.join(", "))
            };
            let rule_source = firing_policies
                .first()
                .cloned()
                .unwrap_or_else(|| "cedar.default_deny".to_string());
            Decision::Deny {
                reason: Some(reason),
                rule_source,
            }
        }
    };

    PdpDecision {
        decision,
        diagnostics: firing_policies,
    }
}
