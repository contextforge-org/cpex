// Location: ./crates/apl-cpex/src/dispatch_plan.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `RouteDispatchPlan` + `DispatchCache` — pre-resolved per-route plugin
// lineup that lets APL bypass cpex-core's hook-name + condition routing
// while still going through the executor's full 5-phase pipeline.
//
// # Why pre-resolve?
//
// cpex-core's `invoke_named(hook_name, ...)` resolves the lineup on
// every call: hook lookup → route/condition filter → group by mode →
// dispatch. APL routes are already authoritative lineups (the YAML's
// `routes.<r>.policy: [plugin(x), plugin(y)]` IS the plan). Re-resolving
// per call wastes work and lets cpex-core's parallel routing model
// (entity-based conditions) override APL's intent.
//
// Building once per `(route_key, snapshot_generation)` and caching turns
// dispatch into: cache lookup → pick handler by invocation context →
// call `manager.invoke_entries::<CmfHook>(&[entry], ...)`.
//
// # Override materialization
//
// When APL declares a route-level `plugins.<name>:` block that narrows
// `capabilities` or changes `on_error`, the plan creates a derived
// `PluginRef` wrapping the same plugin `Arc<dyn Plugin>` with a merged
// `TrustedConfig`. Per `feedback_override_isolation.md`: each derived
// PluginRef gets a fresh `AtomicBool` circuit breaker — failures in the
// override-context plugin don't disable the base, and vice versa.
//
// # Hook-context classification (v0)
//
// A plugin may register handlers for multiple hooks (e.g. both
// `cmf.tool_pre_invoke` for policy steps and `cmf.field_redact` for
// args/result pipelines). The plan picks one handler per invocation
// context (Step vs Field) by a naming heuristic — hook names containing
// `field`, `redact`, `scan`, or `validate` are treated as field
// handlers. When the heuristic stops being sufficient, the plugin
// declaration will gain an explicit `{step: ..., field: ...}` mapping
// form alongside the flat hook list.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use cpex_core::manager::PluginManager;
use cpex_core::plugin::OnError;
use cpex_core::registry::HookEntry;

use apl_core::pipeline::Stage;
use apl_core::plugin_decl::{EffectivePlugin, PluginRegistry};
use apl_core::rules::CompiledRoute;
use apl_core::step::Step;

/// Per-plugin pre-resolved entries for one route. `step_entry` and
/// `field_entry` are populated independently — a plugin may handle one,
/// the other, or both. Dispatch picks the appropriate slot based on the
/// `PluginInvocation` variant.
#[derive(Clone)]
pub struct RoutePluginEntry {
    pub plugin_name: String,
    /// Entry dispatched when called from `policy:` / `post_policy:`
    /// (`PluginInvocation::Step`).
    pub step_entry: Option<HookEntry>,
    /// Entry dispatched when called from `args:` / `result:` pipelines
    /// (`PluginInvocation::Field`).
    pub field_entry: Option<HookEntry>,
}

/// A route's resolved plugin lineup. One per `(route_key, generation)`
/// in the cache.
#[derive(Clone, Default)]
pub struct RouteDispatchPlan {
    pub plugins: HashMap<String, RoutePluginEntry>,
}

impl RouteDispatchPlan {
    /// Build a plan for the given route. Walks all steps + pipeline
    /// stages, collects the unique set of plugin names, resolves each
    /// against cpex-core, and applies any APL route-level overrides.
    ///
    /// Plugins referenced by APL but absent from cpex-core's registry
    /// (or absent from the APL `plugins:` block) are logged at `warn`
    /// and excluded — dispatch then fails with `PluginError::NotFound`
    /// when those plugins are invoked, which is the right behavior for
    /// surfacing config drift.
    pub async fn build(
        route: &CompiledRoute,
        registry: &PluginRegistry,
        manager: &PluginManager,
    ) -> Self {
        let mut plan = Self::default();
        for name in collect_plugin_names(route) {
            let eff = match EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
                Some(e) => e,
                None => {
                    tracing::warn!(
                        plugin = %name,
                        route = %route.route_key,
                        "APL route references plugin not in `plugins:` block — skipping",
                    );
                    continue;
                }
            };

            // Pull the three overrideable values off the effective view.
            // `EffectivePlugin` borrows from the registry / route overrides,
            // so the captures here are slice / Option<&Value> refs.
            let override_block = route.plugin_overrides.get(&name);
            let config_override = override_block.and_then(|o| o.config.as_ref());
            let caps_override: Option<std::collections::HashSet<String>> =
                if matches!(eff.capabilities, apl_core::plugin_decl::CapsView::Override(_)) {
                    Some(eff.capabilities.as_slice().iter().cloned().collect())
                } else {
                    None
                };
            let on_error_override = override_block
                .and_then(|o| o.on_error.as_deref())
                .and_then(parse_on_error);

            // Hand the override decision to cpex-core. When no overrides
            // are declared, this returns the base entries unchanged
            // (no allocation, no factory call). When only caps/on_error
            // differ, it wraps the shared base plugin in a fresh
            // `PluginRef` with merged trusted config. When config
            // differs, it invokes the factory + initializes a brand-new
            // instance with its own circuit breaker.
            let entries = manager
                .build_override_entries(
                    &name,
                    config_override,
                    caps_override.as_ref(),
                    on_error_override,
                )
                .await;
            if entries.is_empty() {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL plugin not resolvable (not registered, factory missing, \
                     or override construction failed) — skipping",
                );
                continue;
            }

            // Classify each hook as step or field via naming heuristic.
            let mut step_entry: Option<HookEntry> = None;
            let mut field_entry: Option<HookEntry> = None;
            for (hook_name, entry) in entries {
                if is_field_hook(&hook_name) {
                    if field_entry.is_none() {
                        field_entry = Some(entry);
                    }
                } else if step_entry.is_none() {
                    step_entry = Some(entry);
                }
            }

            plan.plugins.insert(
                name.clone(),
                RoutePluginEntry {
                    plugin_name: name,
                    step_entry,
                    field_entry,
                },
            );
        }
        plan
    }

    /// Look up the resolved entries for a plugin by name. None when the
    /// plugin wasn't referenced by the route (or was skipped during
    /// build due to config drift).
    pub fn get(&self, plugin_name: &str) -> Option<&RoutePluginEntry> {
        self.plugins.get(plugin_name)
    }

    /// Resolve a single plugin's entries straight off cpex-core, with
    /// no APL route-level overrides. Convenience for tests and for hosts
    /// that wire the invoker without a `CompiledRoute` in scope (e.g.
    /// adapters that invoke a single plugin imperatively). Returns
    /// `None` if cpex-core has no entries for the plugin.
    pub fn resolve_plugin(
        manager: &PluginManager,
        plugin_name: &str,
    ) -> Option<RoutePluginEntry> {
        let base_entries = manager.find_plugin_entries(plugin_name);
        if base_entries.is_empty() {
            return None;
        }
        let mut step_entry: Option<HookEntry> = None;
        let mut field_entry: Option<HookEntry> = None;
        for (hook_name, entry) in base_entries {
            if is_field_hook(&hook_name) {
                if field_entry.is_none() {
                    field_entry = Some(entry);
                }
            } else if step_entry.is_none() {
                step_entry = Some(entry);
            }
        }
        Some(RoutePluginEntry {
            plugin_name: plugin_name.to_string(),
            step_entry,
            field_entry,
        })
    }
}

/// v0 naming-heuristic for hook context classification. Hook names
/// containing any of `field`, `redact`, `scan`, `validate` are treated
/// as field handlers; everything else is a step handler. Token list
/// (not regex) is deliberate — config readers can tell at a glance how
/// a hook name will be classified.
fn is_field_hook(hook_name: &str) -> bool {
    let lc = hook_name.to_ascii_lowercase();
    ["field", "redact", "scan", "validate"]
        .iter()
        .any(|token| lc.contains(token))
}

fn parse_on_error(s: &str) -> Option<OnError> {
    match s.to_ascii_lowercase().as_str() {
        "fail" => Some(OnError::Fail),
        "ignore" => Some(OnError::Ignore),
        "disable" => Some(OnError::Disable),
        _ => None,
    }
}

/// Walk a `CompiledRoute` and return the unique plugin names referenced
/// by any `Step::Plugin` (in `policy` / `post_policy`) or `Stage::Plugin`
/// (in `args` / `result` pipelines). Insertion-ordered for build
/// determinism.
pub(crate) fn collect_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |out: &mut Vec<String>, seen: &mut HashSet<String>, name: &str| {
        if seen.insert(name.to_string()) {
            out.push(name.to_string());
        }
    };
    for step in route.policy.iter().chain(route.post_policy.iter()) {
        if let Step::Plugin { name } = step {
            push(&mut out, &mut seen, name);
        }
    }
    for fr in route.args.iter().chain(route.result.iter()) {
        for stage in &fr.pipeline.stages {
            if let Stage::Plugin { name } = stage {
                push(&mut out, &mut seen, name);
            }
        }
    }
    out
}

/// Compute the union of capabilities declared by every plugin a
/// `CompiledRoute` can dispatch to (with per-route overrides applied).
///
/// This is what the synthetic `AplRouteHandler`'s `PluginConfig.capabilities`
/// must be set to: cpex-core's executor filters the `Extensions` view
/// before invoking every plugin (including the synthetic one), so if
/// the handler has fewer capabilities than its inner plugins need,
/// downstream views get doubly-filtered and label/delegation mutations
/// fail monotonicity checks on the way back out.
///
/// Plugins missing from the registry are silently skipped — the
/// dispatch plan will log a `warn!` and surface a `NotFound` at
/// invocation time, so config drift surfaces in the right place
/// rather than as a confusing capability gap.
pub(crate) fn route_capability_union(
    route: &CompiledRoute,
    registry: &PluginRegistry,
) -> std::collections::HashSet<String> {
    let mut caps: std::collections::HashSet<String> = std::collections::HashSet::new();
    for name in collect_plugin_names(route) {
        if let Some(eff) = EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    caps
}

/// Host-owned dispatch cache. Construct once, share via `Arc<DispatchCache>`
/// across all `CmfPluginInvoker::for_request` calls so plans built for
/// one request can be reused by the next.
///
/// Cache key is the APL `route_key`. Entries pair with the cpex-core
/// snapshot generation observed at build time; a mismatch on lookup
/// triggers eviction and rebuild. v0 keys on `route_key` only —
/// entity-aware caching (entity_type/entity_name from `MetaExtension`)
/// is a follow-up when per-tenant lineup variation lands.
#[derive(Default)]
pub struct DispatchCache {
    inner: RwLock<HashMap<String, (u64, Arc<RouteDispatchPlan>)>>,
}

impl DispatchCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get-or-build a plan for the route. Read-locked fast path returns
    /// the cached plan when the generation matches; otherwise drop the
    /// read lock, rebuild, and write-lock-insert. The brief window
    /// between read-miss and write-insert may let two concurrent
    /// builders race — both produce identical plans and the second
    /// insert just overwrites the first. Cheap relative to the cost of
    /// the build itself, and avoids holding a write lock across the
    /// build call.
    ///
    /// Async because `RouteDispatchPlan::build` may invoke
    /// `PluginManager::build_override_entries`, which calls plugin
    /// factories and `initialize()` for routes that declare `config:`
    /// overrides. Routes with no overrides take a synchronous path
    /// inside the manager (no `.await` does any real work), so the
    /// async cost is zero for the common case.
    pub async fn get_or_build(
        &self,
        route: &CompiledRoute,
        registry: &PluginRegistry,
        manager: &PluginManager,
    ) -> Arc<RouteDispatchPlan> {
        let current_gen = manager.config_generation();
        {
            let r = self.inner.read().unwrap_or_else(|p| p.into_inner());
            if let Some((stored_gen, plan)) = r.get(&route.route_key) {
                if *stored_gen == current_gen {
                    return Arc::clone(plan);
                }
            }
        }
        let plan = Arc::new(RouteDispatchPlan::build(route, registry, manager).await);
        let mut w = self.inner.write().unwrap_or_else(|p| p.into_inner());
        w.insert(route.route_key.clone(), (current_gen, Arc::clone(&plan)));
        plan
    }
}
