// Location: ./crates/cpex-core/src/identity/route_config.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Route-level identity configuration — the parsed shape of a
// route's `identity:` block in unified-config YAML.
//
// # Semantic note
//
// Identity binding is **hook-specific**: the `identity:` block
// binds plugins ONLY for the `identity.resolve` hook on this
// route, independent of whatever the route's `plugins:` block does.
// This matters because in APL-driven routes, the `plugins:` block
// has different meaning (it's a per-route config-override list,
// not a dispatch list — APL controls the dispatch). Identity
// needs its own binding mechanism so the meaning is unambiguous
// regardless of whether APL is annotating the route.
//
// # YAML shapes
//
// Two accepted forms parse to the same IR. The visitor / parser
// logic in `crate::config` discriminates them.
//
// ```yaml
// # List form — implicit additive, common case
// identity:
//   - corp-jwt
//   - spiffe-attestor
//
// # Object form — when the override flag is needed
// identity:
//   replace_inherited: true
//   steps:
//     - legacy-basic-auth
// ```
//
// Each step is either a bare plugin name (string) or a map with
// `name:` + optional `on_error:` / `config:`:
//
// ```yaml
// identity:
//   - corp-jwt                       # bare name
//   - name: spiffe-attestor          # map form
//     on_error: deny
//     config:
//       verify_attestation: strict
// ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A route's parsed `identity:` block. Drives dispatch of the
/// `identity.resolve` hook for the route.
///
/// `None` on a `RouteEntry` means "no identity declared for this
/// route" — `invoke_named::<IdentityHook>` will return an empty
/// entry list when filtered for this route, and the host's
/// `IdentityPayload` flows through unchanged (no resolvers fire).
///
/// Inheritance (deferred) walks `global → tags → route`
/// and merges each layer's `RouteIdentityConfig` based on
/// `replace_inherited`: when `false` (the default), the new layer's
/// steps append after the inherited ones; when `true`, the new
/// layer's steps replace the inherited list wholesale.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteIdentityConfig {
    /// Ordered list of identity steps to run. Empty list is valid:
    /// `identity: { replace_inherited: true, steps: [] }` is the
    /// "explicitly opt out of inherited identity" knob.
    pub steps: Vec<RouteIdentityStep>,

    /// When true, this block replaces any inherited identity steps
    /// instead of appending to them. Set via the object-form YAML
    /// (`identity: { replace_inherited: true, steps: [...] }`).
    /// The list-form YAML always produces `false`.
    ///
    /// Honored by the inheritance merge once that lands. Today the
    /// flag is stored without exercising its merge semantics (no
    /// inheritance to override yet at route level).
    #[serde(default, skip_serializing_if = "is_false")]
    pub replace_inherited: bool,
}

/// One step in the identity-phase pipeline. Points at a plugin
/// registered under the `identity.resolve` hook, optionally with
/// a per-call config override and an `on_error` policy that
/// controls what happens when the step fails.
///
/// # Cumulative stacking
///
/// At runtime, every step in the block runs (subject to its own
/// `on_error`). Each step's resolved `IdentityPayload` accumulates
/// — handlers contribute orthogonal slots (JWT → `subject`;
/// SPIFFE → `caller_workload`; agent resolver → `agent`) so they
/// compose without collision in the common case.
///
/// # On-error semantics
///
/// - `None` or `Some("continue")` — soft failure: the step's
///   contribution is dropped, the next step runs, and any missing
///   extensions get caught later by `require(authenticated)` /
///   `require(workload.*)` in downstream policy.
/// - `Some("deny")` — hard requirement: a failure halts the
///   request with the plugin's violation code.
///
/// Unknown strings parse as best-effort; future slices may
/// introduce typed enums.
///
/// # Per-step config override
///
/// `config_override` reuses the existing per-call override
/// pathway. When present, the framework's
/// `create_override_instance` builds a new plugin instance with
/// the merged config and dispatches into it for this route.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteIdentityStep {
    /// Plugin name — must match an entry in the top-level
    /// `plugins:` block that registers under `identity.resolve`.
    pub name: String,

    /// Optional config override applied for this step only.
    /// `None` means "use the plugin's configured defaults from the
    /// `plugins:` declaration." Stored as `serde_json::Value` to
    /// match the existing `create_override_instance` interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_override: Option<serde_json::Value>,

    /// Per-step failure handling. See type-level docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_error: Option<String>,

    /// Catch-all for any other fields a future schema version
    /// adds (timeout, priority, condition, …) — preserved so the
    /// parser doesn't reject configs targeting newer runtimes.
    #[serde(default, flatten, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

impl RouteIdentityStep {
    /// Convenience for tests / programmatic construction: build a
    /// bare step that just names a plugin with no overrides.
    pub fn bare(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

/// `#[serde(skip_serializing_if = "is_false")]` helper — keeps
/// the YAML round-trip clean by omitting the default `false`.
fn is_false(b: &bool) -> bool {
    !*b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_step_has_no_overrides() {
        let s = RouteIdentityStep::bare("corp-jwt");
        assert_eq!(s.name, "corp-jwt");
        assert!(s.config_override.is_none());
        assert!(s.on_error.is_none());
        assert!(s.extra.is_empty());
    }

    #[test]
    fn config_default_is_empty_additive() {
        let c = RouteIdentityConfig::default();
        assert!(c.steps.is_empty());
        assert!(!c.replace_inherited);
    }

    #[test]
    fn serializes_without_default_replace_inherited() {
        // `replace_inherited: false` should round-trip as absent —
        // it's the default and clutters the YAML otherwise.
        let c = RouteIdentityConfig {
            steps: vec![RouteIdentityStep::bare("corp-jwt")],
            replace_inherited: false,
        };
        let yaml = serde_yaml::to_string(&c).unwrap();
        assert!(!yaml.contains("replace_inherited"), "got: {yaml}");
        assert!(yaml.contains("corp-jwt"), "got: {yaml}");
    }

    #[test]
    fn serializes_with_explicit_replace_inherited() {
        let c = RouteIdentityConfig {
            steps: vec![RouteIdentityStep::bare("legacy-basic-auth")],
            replace_inherited: true,
        };
        let yaml = serde_yaml::to_string(&c).unwrap();
        assert!(yaml.contains("replace_inherited: true"), "got: {yaml}");
    }
}
