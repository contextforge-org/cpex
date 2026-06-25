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

use cpex_core::delegation::HOOK_TOKEN_DELEGATE;
use cpex_core::elicitation::HOOK_ELICIT;
use cpex_core::hooks::{lookup_hook_metadata, HookPhase};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::OnError;
use cpex_core::registry::HookEntry;

use apl_core::pipeline::Stage;
use apl_core::plugin_decl::{EffectivePlugin, PluginRegistry};
use apl_core::rules::{CompiledRoute, Effect};

/// Per-plugin pre-resolved entries for one route. Stores ALL hook
/// entries the plugin registered (keyed by hook name) so the
/// dispatcher can pick the right one for the current context via the
/// cpex-core hook routing table (`hooks::metadata::lookup`).
///
/// Replaces the prior `step_entry` / `field_entry` slot model, which
/// used a brittle naming heuristic to classify hooks and silently
/// collapsed plugins with multiple step-context hooks (e.g. both
/// `tool_pre_invoke` and `tool_post_invoke`) to a single entry.
#[derive(Clone)]
pub struct RoutePluginEntry {
    pub plugin_name: String,
    /// All hook entries the plugin registered, keyed by hook name.
    /// Per-call overrides (route-level config / caps / on_error) are
    /// already applied via `build_override_entries` before being
    /// stored here.
    pub entries_by_hook: HashMap<String, HookEntry>,
}

impl RoutePluginEntry {
    /// Pick the entry whose registered hook matches the current
    /// dispatch context. Walks `entries_by_hook`, consults the
    /// cpex-core hook metadata table for each, returns the first
    /// matching entry.
    ///
    /// `requested_entity_type` comes from the request's
    /// `MetaExtension.entity_type` (or `None` if the dispatcher
    /// doesn't have one — in which case any hook's entity_type
    /// matches). `requested_phase` comes from the APL invocation
    /// context — `Pre` for `args:` / `policy:`, `Post` for
    /// `result:` / `post_policy:`, `Unphased` for unphased
    /// dispatchers (rare in APL).
    ///
    /// Returns `None` when the plugin has no hook matching the
    /// context — caller surfaces this as `PluginError::Dispatch`
    /// with the requested context in the message.
    pub fn pick_entry(
        &self,
        requested_entity_type: Option<&str>,
        requested_phase: HookPhase,
    ) -> Option<&HookEntry> {
        self.entries_by_hook
            .iter()
            .find(|(hook_name, _)| {
                lookup_hook_metadata(hook_name).matches(requested_entity_type, requested_phase)
            })
            .map(|(_, entry)| entry)
    }
}

/// A route's resolved plugin lineup. One per `(route_key, generation)`
/// in the cache.
///
/// `plugins` holds entries for CMF-family dispatch (policy steps,
/// pipe-chain stages). `delegation_entries` holds entries for the
/// `token.delegate` hook used by `Step::Delegate` — kept separate
/// because the hook family is different and the dispatch is
/// per-call rather than per-route-chain.
#[derive(Clone, Default)]
pub struct RouteDispatchPlan {
    pub plugins: HashMap<String, RoutePluginEntry>,
    /// Plugin name → resolved `token.delegate` hook entry for routes
    /// that declared `delegate(...)` steps. Empty when the route has
    /// no delegation. Built at plan time to avoid per-request
    /// `find_plugin_entries` lookups in the hot path.
    pub delegation_entries: HashMap<String, HookEntry>,
    /// Plugin name → resolved `elicit` hook entry for routes that
    /// declared `require_approval(...)` / `confirm(...)` / … steps. Same
    /// `name → entry` shape as `delegation_entries` — elicitation routes
    /// by plugin name, not by `(kind, channel)`. Empty when the route has
    /// no elicitation.
    pub elicitation_entries: HashMap<String, HookEntry>,
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
                },
            };

            // Pull the three overrideable values off the effective view.
            // `EffectivePlugin` borrows from the registry / route overrides,
            // so the captures here are slice / Option<&Value> refs.
            let override_block = route.plugin_overrides.get(&name);
            let config_override = override_block.and_then(|o| o.config.as_ref());
            let caps_override: Option<std::collections::HashSet<String>> = if matches!(
                eff.capabilities,
                apl_core::plugin_decl::CapsView::Override(_)
            ) {
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

            // Store every (hook_name, HookEntry) pair the plugin
            // registered. Dispatch-time entry selection (pick_entry)
            // consults cpex-core's hook routing table per hook name.
            // Replaces the prior naming heuristic.
            let mut entries_by_hook: HashMap<String, HookEntry> = HashMap::new();
            for (hook_name, entry) in entries {
                entries_by_hook.insert(hook_name, entry);
            }

            plan.plugins.insert(
                name.clone(),
                RoutePluginEntry {
                    plugin_name: name,
                    entries_by_hook,
                },
            );
        }

        // Resolve token.delegate entries for any plugins the route
        // calls via `Step::Delegate`. These don't go through the
        // step/field classification — they're a separate hook family.
        // We still apply per-call config overrides via the existing
        // `build_override_entries` pathway, threading the step's
        // `config_override` as the only override surface (Slice B
        // doesn't expose per-step caps or on_error overrides on
        // delegation entries — the on_error lives in the IR step
        // itself and is honored by the evaluator).
        for name in collect_delegate_plugin_names(route) {
            let entries = manager
                .build_override_entries(&name, None, None, None)
                .await;
            // Pick the first token.delegate entry. Per delegation-hooks
            // spec, plugins typically register one handler under the
            // single `token.delegate` hook name; multiple handlers
            // would be unusual.
            let delegate_entry = entries
                .into_iter()
                .find(|(hook_name, _)| hook_name == HOOK_TOKEN_DELEGATE);
            if let Some((_, entry)) = delegate_entry {
                plan.delegation_entries.insert(name, entry);
            } else {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL route references delegate plugin not registered under \
                     token.delegate hook — `delegate(...)` step will fail at dispatch",
                );
            }
        }

        // Resolve `elicit` entries for any plugins the route calls via an
        // elicitation verb (`require_approval(...)`, `confirm(...)`, …).
        // Same `name → entry` resolution as delegation — elicitation
        // routes by plugin name, not `(kind, channel)`.
        for name in collect_elicit_plugin_names(route) {
            let entries = manager
                .build_override_entries(&name, None, None, None)
                .await;
            let elicit_entry = entries
                .into_iter()
                .find(|(hook_name, _)| hook_name == HOOK_ELICIT);
            if let Some((_, entry)) = elicit_entry {
                plan.elicitation_entries.insert(name, entry);
            } else {
                tracing::warn!(
                    plugin = %name,
                    route = %route.route_key,
                    "APL route references elicitation plugin not registered under \
                     elicit hook — `require_approval(...)`/`confirm(...)` step will \
                     fail at dispatch",
                );
            }
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
    pub fn resolve_plugin(manager: &PluginManager, plugin_name: &str) -> Option<RoutePluginEntry> {
        let base_entries = manager.find_plugin_entries(plugin_name);
        if base_entries.is_empty() {
            return None;
        }
        let mut entries_by_hook: HashMap<String, HookEntry> = HashMap::new();
        for (hook_name, entry) in base_entries {
            entries_by_hook.insert(hook_name, entry);
        }
        Some(RoutePluginEntry {
            plugin_name: plugin_name.to_string(),
            entries_by_hook,
        })
    }
}

fn parse_on_error(s: &str) -> Option<OnError> {
    match s.to_ascii_lowercase().as_str() {
        "fail" => Some(OnError::Fail),
        "ignore" => Some(OnError::Ignore),
        "disable" => Some(OnError::Disable),
        _ => None,
    }
}

/// Recursively walk every effect node in an `Effect` tree, invoking
/// `visit` on each. Used by `collect_*_names` below to find Plugin /
/// Delegate references that may be nested inside `Effect::When`,
/// `Effect::Sequential`, `Effect::Parallel`, or `Effect::Pdp` reaction
/// lists. Pre-E4 these were flat — Step::Plugin lived directly under
/// policy: — so a simple iter() was enough; after E4 the IR is tree-
/// shaped and the same scan needs recursion.
fn walk_effects<F: FnMut(&Effect)>(effects: &[Effect], visit: &mut F) {
    for e in effects {
        visit(e);
        match e {
            Effect::When { body, .. } => walk_effects(body, visit),
            Effect::Sequential(inner) | Effect::Parallel(inner) => walk_effects(inner, visit),
            Effect::Pdp {
                on_allow, on_deny, ..
            } => {
                walk_effects(on_allow, visit);
                walk_effects(on_deny, visit);
            },
            _ => {},
        }
    }
}

/// Walk a `CompiledRoute` and return the unique delegate-plugin names
/// referenced by any `Effect::Delegate` anywhere in `policy` /
/// `post_policy` (including effects nested inside When / Sequential /
/// Parallel / Pdp reactions). Insertion-ordered for build determinism.
/// Separate from [`collect_plugin_names`] because delegate plugins
/// resolve under a different hook family (`token.delegate`) and the
/// dispatch plan keeps them in a separate map.
pub(crate) fn collect_delegate_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        if let Effect::Delegate(ds) = e {
            if seen.insert(ds.plugin_name.clone()) {
                out.push(ds.plugin_name.clone());
            }
        }
    };
    walk_effects(&route.policy, &mut visit);
    walk_effects(&route.post_policy, &mut visit);
    out
}

/// Walk a `CompiledRoute` and return the unique elicitation-plugin names
/// referenced by any `Effect::Elicit` anywhere in `policy` /
/// `post_policy` (including nested). Insertion-ordered for build
/// determinism. Separate from [`collect_plugin_names`] because
/// elicitation plugins resolve under the `elicit` hook family and the
/// plan keeps them in their own map.
pub(crate) fn collect_elicit_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        if let Effect::Elicit(es) = e {
            if seen.insert(es.plugin_name.clone()) {
                out.push(es.plugin_name.clone());
            }
        }
    };
    walk_effects(&route.policy, &mut visit);
    walk_effects(&route.post_policy, &mut visit);
    out
}

/// Walk a `CompiledRoute` and return the unique plugin names referenced
/// by any `Effect::Plugin` anywhere in `policy` / `post_policy` (including
/// nested) or `Stage::Plugin` (in `args` / `result` pipelines).
/// Insertion-ordered for build determinism.
pub(crate) fn collect_plugin_names(route: &CompiledRoute) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut visit = |e: &Effect| {
        if let Effect::Plugin { name } = e {
            if seen.insert(name.clone()) {
                out.push(name.clone());
            }
        }
    };
    walk_effects(&route.policy, &mut visit);
    walk_effects(&route.post_policy, &mut visit);
    for fr in route.args.iter().chain(route.result.iter()) {
        for stage in &fr.pipeline.stages {
            if let Stage::Plugin { name } = stage {
                if seen.insert(name.clone()) {
                    out.push(name.clone());
                }
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
    // Plugin steps (`plugin(name)` in policy / `plugin: name` in
    // args / result pipelines).
    for name in collect_plugin_names(route) {
        if let Some(eff) = EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    // Delegate steps (`delegate(name, ...)`). Without this, a
    // delegator plugin that declares `capabilities:
    // [read_inbound_credentials, write_delegated_tokens]` in YAML
    // gets those stripped at the AplRouteHandler boundary — the
    // synthetic handler doesn't union its caps in, so the executor
    // filters out the inbound bearer before DelegationPluginInvoker
    // dispatches, and the delegator handler sees an empty token.
    // Hosts WANT to express per-plugin caps in YAML rather than
    // widening the AplRouteHandler's baseline (which would leak
    // those creds to every other step in the route).
    for name in collect_delegate_plugin_names(route) {
        if let Some(eff) = EffectivePlugin::resolve(&name, registry, &route.plugin_overrides) {
            for cap in eff.capabilities.as_slice() {
                caps.insert(cap.clone());
            }
        }
    }
    // Elicitation steps (`require_approval(name, ...)`, …) — same reason
    // as delegation: an elicitation handler that declares e.g.
    // `read_subject` (to read the approver identity) must not have it
    // stripped at the AplRouteHandler boundary.
    for name in collect_elicit_plugin_names(route) {
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
