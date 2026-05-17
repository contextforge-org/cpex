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
use cpex_core::registry::{HookEntry, PluginRef};

use apl_core::pipeline::Stage;
use apl_core::plugin_decl::{EffectivePlugin, PluginOverride, PluginRegistry};
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
    pub fn build(
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
            let base_entries = manager.find_plugin_entries(&name);
            if base_entries.is_empty() {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL plugin not registered with cpex-core — skipping",
                );
                continue;
            }

            // Materialize an override PluginRef if APL declared route-level
            // caps/on_error overrides. Shares the base `Arc<dyn Plugin>`
            // (no re-instantiation); fresh `AtomicBool` circuit breaker.
            let override_ref =
                build_override_ref(&base_entries, &eff, &route.plugin_overrides);

            let mut step_entry: Option<HookEntry> = None;
            let mut field_entry: Option<HookEntry> = None;
            for (hook_name, base_entry) in &base_entries {
                let entry = match &override_ref {
                    Some(ovr) => HookEntry {
                        plugin_ref: Arc::clone(ovr),
                        handler: Arc::clone(&base_entry.handler),
                    },
                    None => base_entry.clone(),
                };
                if is_field_hook(hook_name) {
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

/// Build a `PluginRef` with the APL route-level override merged on top
/// of cpex-core's registered config. Returns `None` when there's no
/// override block at all, or when the block declares nothing observable
/// (no caps, no on_error).
fn build_override_ref(
    base_entries: &[(String, HookEntry)],
    eff: &EffectivePlugin<'_>,
    overrides: &HashMap<String, PluginOverride>,
) -> Option<Arc<PluginRef>> {
    let ovr = overrides.get(eff.name)?;
    if ovr.capabilities.is_none() && ovr.on_error.is_none() {
        return None;
    }
    let base_ref = &base_entries.first()?.1.plugin_ref;
    let mut merged = base_ref.trusted_config().clone();
    if let Some(caps) = ovr.capabilities.as_ref() {
        merged.capabilities = caps.iter().cloned().collect();
    }
    if let Some(on_err_s) = ovr.on_error.as_deref() {
        if let Some(on_err) = parse_on_error(on_err_s) {
            merged.on_error = on_err;
        }
    }
    Some(Arc::new(PluginRef::new(
        Arc::clone(base_ref.plugin()),
        merged,
    )))
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
fn collect_plugin_names(route: &CompiledRoute) -> Vec<String> {
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
    pub fn get_or_build(
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
        let plan = Arc::new(RouteDispatchPlan::build(route, registry, manager));
        let mut w = self.inner.write().unwrap_or_else(|p| p.into_inner());
        w.insert(route.route_key.clone(), (current_gen, Arc::clone(&plan)));
        plan
    }
}
