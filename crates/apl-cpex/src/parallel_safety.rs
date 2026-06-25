// Location: ./crates/apl-cpex/src/parallel_safety.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Route-compile-time plugin-mode validation for APL `parallel:` blocks.
//
// `apl-core::Effect::validate_parallel_purity` already rejects FieldOp /
// Delegate at the IR level — those are statically detectable without
// any plugin knowledge. Plugin calls (`Effect::Plugin { name }`) need
// a second pass because their concurrency-safety depends on each
// plugin's registered `PluginMode` — information that lives in the
// PluginManager, not the IR.
//
// Lives in apl-cpex because:
//   * apl-core can't see plugin modes (plugin-agnostic by design)
//   * The PluginManager is constructed in the host integration, not in
//     apl-core's compiler
//   * The visitor that turns YAML routes into `CompiledRoute`s is the
//     natural place to run all post-IR-level validations together
//
// # Mode rules
//
// Allowed inside `parallel:`:
//   - `Audit` — read-only by declaration
//   - `Concurrent` — explicitly designed for parallel execution
//   - `FireAndForget` — side-effects only, no return value to merge
//   - `Disabled` — skipped at runtime anyway
//
// Rejected inside `parallel:`:
//   - `Sequential` — `can_modify() == true`, would silently lose its mutation
//   - `Transform` — same as Sequential for our purposes
//
// The asymmetry exists because parallel branches each get a *cloned*
// bag and payload; any mutation a branch makes lives only inside its
// clone. Plugins authored under Sequential / Transform semantics
// reasonably assume their writes persist. Detecting the misuse at
// route-compile means the operator sees a clear error instead of a
// confusing "but my plugin ran and the bag didn't change" runtime
// surprise.

use apl_core::rules::{CompiledRoute, Effect};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::PluginMode;

/// Read-only "what mode is plugin X registered with" lookup, used by
/// the validator. A trait (rather than a `&PluginManager`) so:
///
///   * Tests can pass a small HashMap-backed mock without constructing
///     a real `PluginManager` (which requires plugin registration and
///     a bunch of cpex-core internal types).
///   * Future consumers that store plugin modes in a different shape
///     (e.g. a separate config catalogue) plug in without forcing them
///     to back the lookup with a full PluginManager.
pub trait PluginModeLookup {
    /// Returns the mode for `name`, or `None` if no plugin by that
    /// name is registered.
    fn mode_for(&self, name: &str) -> Option<PluginMode>;
}

impl PluginModeLookup for PluginManager {
    fn mode_for(&self, name: &str) -> Option<PluginMode> {
        self.get_plugin(name).map(|p| p.mode())
    }
}

/// Walk a compiled route looking for `Effect::Plugin` calls nested
/// inside any `Effect::Parallel` block, and check that each named
/// plugin's registered mode is safe for parallel execution.
///
/// Returns `Ok(())` if all plugins inside parallel blocks have safe
/// modes (or the route has no parallel blocks). On failure, returns a
/// `;`-separated list of every violation found — running a single pass
/// over the route surfaces all problems at once instead of stopping
/// at the first.
pub fn validate_parallel_plugin_modes<L: PluginModeLookup + ?Sized>(
    route: &CompiledRoute,
    registry: &L,
) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();
    for (phase_name, effects) in [
        ("policy", route.policy.as_slice()),
        ("post_policy", route.post_policy.as_slice()),
    ] {
        for (idx, effect) in effects.iter().enumerate() {
            walk_effect(
                effect,
                &format!("routes.{}.{}[{}]", route.route_key, phase_name, idx),
                false,
                registry,
                &mut errors,
            );
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Recursive traversal. `under_parallel` is true once we've descended
/// into a `Parallel` node; from then on every `Plugin` we hit gets
/// checked against the mode allowlist. Nested `Parallel`/`Sequential`
/// both keep the flag true (a sequential block inside a parallel one
/// is still ultimately running in the parallel branch's cloned state).
fn walk_effect<L: PluginModeLookup + ?Sized>(
    effect: &Effect,
    location: &str,
    under_parallel: bool,
    registry: &L,
    errors: &mut Vec<String>,
) {
    match effect {
        Effect::Plugin { name } if under_parallel => {
            check_plugin_mode(name, location, registry, errors);
        },
        Effect::Parallel(inner) => {
            for e in inner {
                walk_effect(e, location, true, registry, errors);
            }
        },
        Effect::Sequential(inner) => {
            for e in inner {
                walk_effect(e, location, under_parallel, registry, errors);
            }
        },
        Effect::When { body, .. } => {
            // A `when:` body inherits the parallel context of its
            // enclosing scope. Plugin calls inside `when:` under a
            // `parallel:` are still subject to the mode check.
            for e in body {
                walk_effect(e, location, under_parallel, registry, errors);
            }
        },
        Effect::Pdp {
            on_allow, on_deny, ..
        } => {
            for e in on_allow.iter().chain(on_deny.iter()) {
                walk_effect(e, location, under_parallel, registry, errors);
            }
        },
        // Other variants (Allow/Deny/Plugin-not-in-parallel/Delegate/
        // Taint/FieldOp) don't carry nested effects today. Note that
        // `Delegate` / `FieldOp` inside Parallel was already rejected
        // by `apl-core::Effect::validate_parallel_purity` at parse
        // time — no need to re-check here.
        _ => {},
    }
}

fn check_plugin_mode<L: PluginModeLookup + ?Sized>(
    name: &str,
    location: &str,
    registry: &L,
    errors: &mut Vec<String>,
) {
    let mode = match registry.mode_for(name) {
        Some(m) => m,
        None => {
            errors.push(format!(
                "{}: `parallel:` references unknown plugin `{}`",
                location, name
            ));
            return;
        },
    };
    if !is_safe_in_parallel(mode) {
        errors.push(format!(
            "{}: plugin `{}` has mode `{}` which can modify state; parallel \
             branches discard mutations, so this would silently lose its effect. \
             Use `sequential:` for ordered mutations or change the plugin's mode.",
            location, name, mode,
        ));
    }
}

/// Allowlist check. Centralised so the rule is documented in one
/// place and easy to find if `PluginMode` gains a new variant.
fn is_safe_in_parallel(mode: PluginMode) -> bool {
    matches!(
        mode,
        PluginMode::Audit
            | PluginMode::Concurrent
            | PluginMode::FireAndForget
            | PluginMode::Disabled
    )
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use apl_core::rules::Expression;
    use std::collections::HashMap;

    /// Test mock — a plain `HashMap<name, mode>`. Implements the
    /// lookup trait without needing the real cpex-core registry's
    /// plugin / hook registration machinery.
    struct MockLookup(HashMap<String, PluginMode>);

    impl MockLookup {
        fn new() -> Self {
            Self(HashMap::new())
        }
        fn with(mut self, name: &str, mode: PluginMode) -> Self {
            self.0.insert(name.to_string(), mode);
            self
        }
    }

    impl PluginModeLookup for MockLookup {
        fn mode_for(&self, name: &str) -> Option<PluginMode> {
            self.0.get(name).copied()
        }
    }

    fn route_with_policy(effects: Vec<Effect>) -> CompiledRoute {
        let mut r = CompiledRoute::new("test_route");
        r.policy = effects;
        r
    }

    fn rule(effects: Vec<Effect>) -> Effect {
        Effect::When {
            condition: Expression::Always,
            body: effects,
            source: "test".into(),
        }
    }

    fn parallel_plugin(name: &str) -> Effect {
        Effect::Parallel(vec![Effect::Plugin { name: name.into() }])
    }

    // --- Allowed modes ---

    #[test]
    fn audit_plugin_in_parallel_is_accepted() {
        let reg = MockLookup::new().with("audit_logger", PluginMode::Audit);
        let route = route_with_policy(vec![rule(vec![parallel_plugin("audit_logger")])]);
        assert!(validate_parallel_plugin_modes(&route, &reg).is_ok());
    }

    #[test]
    fn concurrent_plugin_in_parallel_is_accepted() {
        let reg = MockLookup::new().with("pii_scanner", PluginMode::Concurrent);
        let route = route_with_policy(vec![rule(vec![parallel_plugin("pii_scanner")])]);
        assert!(validate_parallel_plugin_modes(&route, &reg).is_ok());
    }

    #[test]
    fn fire_and_forget_in_parallel_is_accepted() {
        let reg = MockLookup::new().with("metrics", PluginMode::FireAndForget);
        let route = route_with_policy(vec![rule(vec![parallel_plugin("metrics")])]);
        assert!(validate_parallel_plugin_modes(&route, &reg).is_ok());
    }

    // --- Rejected modes ---

    #[test]
    fn sequential_plugin_in_parallel_is_rejected() {
        let reg = MockLookup::new().with("mutator", PluginMode::Sequential);
        let route = route_with_policy(vec![rule(vec![parallel_plugin("mutator")])]);
        let err = validate_parallel_plugin_modes(&route, &reg).unwrap_err();
        assert!(err.contains("mutator"), "names plugin: {}", err);
        assert!(err.contains("sequential"), "names mode: {}", err);
        assert!(err.contains("`sequential:`"), "suggests fix: {}", err);
    }

    #[test]
    fn transform_plugin_in_parallel_is_rejected() {
        let reg = MockLookup::new().with("redactor", PluginMode::Transform);
        let route = route_with_policy(vec![rule(vec![parallel_plugin("redactor")])]);
        let err = validate_parallel_plugin_modes(&route, &reg).unwrap_err();
        assert!(err.contains("transform"));
    }

    #[test]
    fn unknown_plugin_in_parallel_is_rejected() {
        let reg = MockLookup::new();
        let route = route_with_policy(vec![rule(vec![parallel_plugin("ghost")])]);
        let err = validate_parallel_plugin_modes(&route, &reg).unwrap_err();
        assert!(err.contains("unknown plugin"));
        assert!(err.contains("ghost"));
    }

    // --- Scoping: only mismatches INSIDE a parallel block are caught ---

    #[test]
    fn sequential_plugin_outside_parallel_is_allowed() {
        // The same Sequential-mode plugin is fine at the top level —
        // only its appearance INSIDE a parallel block is the problem.
        let reg = MockLookup::new().with("mutator", PluginMode::Sequential);
        let route = route_with_policy(vec![rule(vec![Effect::Plugin {
            name: "mutator".into(),
        }])]);
        assert!(validate_parallel_plugin_modes(&route, &reg).is_ok());
    }

    #[test]
    fn nested_sequential_inside_parallel_still_validates_plugins() {
        // `parallel: [sequential: [plugin(seq_mode)]]` — the sequential
        // is just a grouping construct; the plugin still runs inside
        // the parallel branch's cloned state.
        let reg = MockLookup::new().with("mutator", PluginMode::Sequential);
        let route = route_with_policy(vec![rule(vec![Effect::Parallel(vec![
            Effect::Sequential(vec![Effect::Plugin {
                name: "mutator".into(),
            }]),
        ])])]);
        let err = validate_parallel_plugin_modes(&route, &reg).unwrap_err();
        assert!(err.contains("mutator"));
    }

    // --- Diagnostics: every violation, both phases ---

    #[test]
    fn multiple_violations_all_reported() {
        // Surface every violation in one pass so the operator can fix
        // them all at once instead of one error per build cycle.
        let reg = MockLookup::new()
            .with("a", PluginMode::Sequential)
            .with("b", PluginMode::Transform);
        let route = route_with_policy(vec![rule(vec![Effect::Parallel(vec![
            Effect::Plugin { name: "a".into() },
            Effect::Plugin { name: "b".into() },
        ])])]);
        let err = validate_parallel_plugin_modes(&route, &reg).unwrap_err();
        assert!(err.contains("`a`"), "names a: {}", err);
        assert!(err.contains("`b`"), "names b: {}", err);
    }

    #[test]
    fn post_policy_phase_is_validated_too() {
        let reg = MockLookup::new().with("mutator", PluginMode::Sequential);
        let mut route = CompiledRoute::new("test_route");
        route.post_policy = vec![rule(vec![parallel_plugin("mutator")])];
        let err = validate_parallel_plugin_modes(&route, &reg).unwrap_err();
        assert!(err.contains("post_policy"));
    }
}
