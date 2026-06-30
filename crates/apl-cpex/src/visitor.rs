// Location: ./crates/apl-cpex/src/visitor.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `AplConfigVisitor` — the cpex-core `ConfigVisitor` implementation that
// stacks the unified-config hierarchy (global → defaults → tag bundles
// → routes) into a single `CompiledRoute` per route and installs an
// [`AplRouteHandler`] for each phase via `PluginManager::annotate_route`.
//
// # Hierarchy stacking
//
// Each `visit_*` call carries a single block of raw YAML. The visitor
// finds the `apl:` sub-block (if any), compiles it to a `CompiledRoute`,
// and stashes it in interior state:
//
//   visit_global       → state.global_layer
//   visit_default      → state.default_layers[entity_type]
//   visit_policy_bundle → state.tag_layers[tag]
//   visit_route        → build effective route by layering and annotate.
//
// At `visit_route` we layer least-to-most-specific:
//
//   effective = global
//   effective.apply_layer(default_layer_for(entity_type))
//   for tag in route.meta.tags { effective.apply_layer(tag_layer(tag)) }
//   effective.apply_layer(route_apl_block)
//
// then construct one `AplRouteHandler` per phase (Pre, Post) and call
// `annotate_route` for each `(entity_type, entity_name, scope, hook)`.
//
// # Hook names per entity type
//
// Each entity type binds to its own CMF hook pair:
//
//   * `tool:`     → `cmf.tool_pre_invoke`     / `cmf.tool_post_invoke`
//   * `llm:`      → `cmf.llm_input`           / `cmf.llm_output`
//   * `prompt:`   → `cmf.prompt_pre_invoke`   / `cmf.prompt_post_invoke`
//   * `resource:` → `cmf.resource_pre_fetch`  / `cmf.resource_post_fetch`
//
// The mapping lives in [`hook_pair_for_entity`]. Hosts fire
// `mgr.invoke_named::<CmfHook>("cmf.llm_input", ...)` for LLM
// invocations; the visitor's annotation on `cmf.llm_input` for the
// matching route's entity_name is what AplRouteHandler intercepts.
//
// `tool_pre_invoke` / `tool_post_invoke` are exposed as legacy
// re-exports for callers that wired against the v0 constants — the
// per-entity dispatch is the load-bearing path now.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

use cpex_core::cmf::constants::{
    ENTITY_LLM, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL, HOOK_CMF_LLM_INPUT,
    HOOK_CMF_LLM_OUTPUT, HOOK_CMF_PROMPT_POST_INVOKE, HOOK_CMF_PROMPT_PRE_INVOKE,
    HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_TOOL_POST_INVOKE,
    HOOK_CMF_TOOL_PRE_INVOKE,
};
use cpex_core::config::RouteEntry;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::PluginConfig;
use cpex_core::visitor::{ConfigVisitor, VisitorError};

use apl_core::parser::compile_policy_block_value;
use apl_core::plugin_decl::{PluginDeclaration, PluginRegistry};
use apl_core::rules::{CompiledRoute, DenyResponse};
use apl_core::step::{PdpFactory, PdpResolver};

use crate::dispatch_plan::DispatchCache;
use crate::pdp_router::PdpRouter;
use crate::route_handler::{AplRouteHandler, Phase};
use crate::session_store::{SessionStore, SessionStoreFactory};

/// Legacy alias for the tool-family pre hook. Kept exported for
/// callers that wired against the v0 visitor constants — the
/// per-entity-type dispatch via `hook_pair_for_entity` is the
/// load-bearing path now.
pub const HOOK_PRE: &str = HOOK_CMF_TOOL_PRE_INVOKE;
/// Legacy alias for the tool-family post hook. See `HOOK_PRE`.
pub const HOOK_POST: &str = HOOK_CMF_TOOL_POST_INVOKE;

/// Resolve the (pre, post) CMF hook pair for an entity_type. Drives
/// per-entity `annotate_route` calls so an `llm:` route annotates on
/// `cmf.llm_input` / `cmf.llm_output` rather than the tool-family
/// hooks. Returns `None` for unknown entity types — the visitor logs
/// + skips those routes.
fn hook_pair_for_entity(entity_type: &str) -> Option<(&'static str, &'static str)> {
    match entity_type {
        ENTITY_TOOL => Some((HOOK_CMF_TOOL_PRE_INVOKE, HOOK_CMF_TOOL_POST_INVOKE)),
        ENTITY_LLM => Some((HOOK_CMF_LLM_INPUT, HOOK_CMF_LLM_OUTPUT)),
        ENTITY_PROMPT => Some((HOOK_CMF_PROMPT_PRE_INVOKE, HOOK_CMF_PROMPT_POST_INVOKE)),
        ENTITY_RESOURCE => Some((HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_RESOURCE_POST_FETCH)),
        _ => None,
    }
}

/// Interior state accumulated as the manager walks the visitor.
/// `plugin_registry` is populated by `visit_plugins` (called once per
/// load); the layer fields are populated as the visitor walks
/// `global` / `defaults` / `policies` / `routes`; `pdp_router` is
/// populated by both code-supplied resolvers (`register_pdp`) and
/// unified-config-driven entries under `global.apl.pdp[]` (built
/// during `visit_global`).
#[derive(Default)]
struct VisitorState {
    plugin_registry: PluginRegistry,
    global_layer: Option<CompiledRoute>,
    default_layers: HashMap<String, CompiledRoute>,
    tag_layers: HashMap<String, CompiledRoute>,
    pdp_router: PdpRouter,
}

/// APL implementation of [`cpex_core::visitor::ConfigVisitor`]. Construct
/// once per host with the shared infrastructure (dispatch cache, session
/// store, manager handle) and register with `PluginManager::register_visitor`
/// before calling `load_config_yaml`.
///
/// PDPs come from two sources, both feeding the same internal
/// [`PdpRouter`]:
///
/// 1. **Code-supplied** via `register_pdp` (or `AplOptions.pdps`) —
///    the host built the resolver in code and hands it in.
/// 2. **Config-supplied** via `global.apl.pdp[]` blocks in the unified
///    config — the visitor sees the block, looks up a factory by
///    `kind`, and constructs the resolver during `visit_global`.
///
/// Factories are registered up front by `kind` name (`"cedar-direct"`,
/// `"opa"`, …). The visitor knows nothing about specific PDP
/// backends; everything dispatches through `PdpFactory`.
pub struct AplConfigVisitor {
    state: RwLock<VisitorState>,
    dispatch_cache: Arc<DispatchCache>,
    /// Active session store. Behind a `RwLock` because a
    /// `global.apl.session_store` block can swap it during the
    /// config walk (`visit_global`), which runs before route handlers
    /// capture the store in `visit_route`. Only touched during the
    /// single-threaded config walk — never on the request hot path,
    /// where each handler holds its own cloned `Arc`.
    session_store: RwLock<Arc<dyn SessionStore>>,
    manager: Weak<PluginManager>,
    /// Baseline capabilities granted to every synthetic `AplRouteHandler`
    /// the visitor installs. Unioned with the per-route plugin
    /// capability set so APL predicates that touch extensions
    /// (`require(authenticated)` needs `read_subject`, etc.) work even
    /// when no plugins are referenced. Hosts that want strict gating
    /// can set this to an empty set.
    base_capabilities: std::collections::HashSet<String>,
    /// Factories the visitor consults when it encounters a
    /// `global.apl.pdp[]` entry. Keyed by the factory's `kind()` —
    /// matches the `kind:` field in the YAML block.
    pdp_factories: HashMap<String, Arc<dyn PdpFactory>>,
    /// Factories the visitor consults for a `global.apl.session_store`
    /// block. Keyed by the factory's `kind()`. Empty by default, in
    /// which case the constructor-supplied store (typically
    /// `MemorySessionStore`) stays active.
    session_store_factories: HashMap<String, Arc<dyn SessionStoreFactory>>,
}

impl AplConfigVisitor {
    pub fn new(
        dispatch_cache: Arc<DispatchCache>,
        session_store: Arc<dyn SessionStore>,
        manager: Weak<PluginManager>,
    ) -> Self {
        Self {
            state: RwLock::new(VisitorState::default()),
            dispatch_cache,
            session_store: RwLock::new(session_store),
            manager,
            base_capabilities: default_base_capabilities(),
            pdp_factories: HashMap::new(),
            session_store_factories: HashMap::new(),
        }
    }

    /// Register a code-supplied PDP resolver. Equivalent to declaring a
    /// PDP in the unified config but for hosts that prefer wiring
    /// resolvers in Rust. Resolvers are pushed into the internal
    /// `PdpRouter`; the first registration per dialect wins (matches
    /// `PdpRouter::register` semantics).
    pub fn register_pdp(&self, resolver: Arc<dyn PdpResolver>) {
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        state.pdp_router.register(resolver);
    }

    /// Register a PDP factory by its `kind()`. Called during
    /// `register_apl` setup; the visitor uses these to instantiate
    /// resolvers from `global.apl.pdp[]` config blocks.
    pub fn register_pdp_factory(&mut self, factory: Arc<dyn PdpFactory>) {
        self.pdp_factories
            .insert(factory.kind().to_string(), factory);
    }

    /// Register a `SessionStoreFactory` by its `kind()`. Called during
    /// `register_apl` setup; the visitor uses these to swap in the
    /// config-selected session store when it sees a
    /// `global.apl.session_store` block.
    pub fn register_session_store_factory(&mut self, factory: Arc<dyn SessionStoreFactory>) {
        self.session_store_factories
            .insert(factory.kind().to_string(), factory);
    }

    /// Parse the optional `global.apl.session_store` block and swap the
    /// active store. Looks up the factory by `kind`, builds the store,
    /// and replaces the constructor-supplied default. Runs during
    /// `visit_global` — before `visit_route` clones the store into each
    /// handler — so the selected store is the one handlers capture.
    /// Absent block → no-op (the default store stays active).
    fn build_session_store_from_config(
        &self,
        block: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let map = block.as_mapping().ok_or_else(|| {
            "global.apl.session_store must be a mapping with a `kind:` field".to_string()
        })?;
        let kind = map
            .get(serde_yaml::Value::String("kind".to_string()))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "global.apl.session_store missing required `kind:` field".to_string())?;
        let factory = self.session_store_factories.get(kind).ok_or_else(|| {
            format!(
                "global.apl.session_store declared kind='{}' but no factory is registered for that \
                 kind — host must call register_session_store_factory(...) before load_config_yaml",
                kind
            )
        })?;
        let store = factory.build(block).map_err(|e| {
            format!(
                "global.apl.session_store (kind='{}') failed to build: {}",
                kind, e
            )
        })?;
        *self
            .session_store
            .write()
            .unwrap_or_else(|p| p.into_inner()) = store;
        Ok(())
    }

    /// Replace the baseline capability set granted to every installed
    /// `AplRouteHandler`. Default covers read-only attributes APL
    /// predicates commonly touch (subject, role, labels, delegation,
    /// agent). Tighten this when the deployment's policy plugins
    /// don't need broad reads — every cap removed is one fewer
    /// extension slot a buggy predicate can leak through.
    pub fn with_base_capabilities(mut self, caps: std::collections::HashSet<String>) -> Self {
        self.base_capabilities = caps;
        self
    }

    /// Parse one entry from `global.apl.pdp[]`. Reads `kind`, dispatches
    /// to the matching factory, installs the resulting resolver into
    /// the internal `PdpRouter`. Called per entry during `visit_global`.
    ///
    /// `index` is used only for diagnostics — operators see "the third
    /// pdp entry failed" rather than a generic "a pdp entry failed."
    fn build_pdp_from_config(
        &self,
        entry: &serde_yaml::Value,
        index: usize,
    ) -> Result<(), VisitorError> {
        let map = entry.as_mapping().ok_or_else(|| {
            format!(
                "global.apl.pdp[{}] must be a mapping with a `kind:` field",
                index
            )
        })?;
        let kind = map
            .get(serde_yaml::Value::String("kind".to_string()))
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("global.apl.pdp[{}] missing required `kind:` field", index))?;
        let factory = self.pdp_factories.get(kind).ok_or_else(|| {
            format!(
                "global.apl.pdp[{}] declared kind='{}' but no factory is registered for that kind — \
                 host must call register_pdp_factory(...) before load_config_yaml",
                index, kind
            )
        })?;
        let resolver = factory.build(entry).map_err(|e| {
            format!(
                "global.apl.pdp[{}] (kind='{}') failed to build: {}",
                index, kind, e
            )
        })?;
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        state.pdp_router.register(resolver);
        Ok(())
    }
}

/// Read-only baseline for APL predicates: enough to make
/// `authenticated`, `role.*`, `perm.*`, `subject.*`, `claim.*`,
/// `subject.teams`, `security.labels`, `delegated`, `delegation.*`,
/// and `agent.*` evaluate correctly. Excludes all *write* capabilities
/// — those are granted on demand by the per-route plugin union when a
/// plugin declares `append_labels` / `append_delegation` /
/// `write_headers`.
///
/// `read_subject` alone unlocks only `subject.id` / `subject.type`;
/// roles, permissions, teams, and claims are each gated by their own
/// capability (`read_roles` / `read_permissions` / `read_teams` /
/// `read_claims`). PDP-driven policies routinely read principal.roles /
/// principal.claims, so the baseline grants all four — tightening
/// further would surprise APL authors whose `cedar:` policies suddenly
/// see empty role sets in deployments with no plugin-declared caps.
/// Hosts that want strict subject access override this via
/// `AplOptions.base_capabilities`.
fn default_base_capabilities() -> std::collections::HashSet<String> {
    [
        "read_subject",
        "read_roles",
        "read_permissions",
        "read_teams",
        "read_claims",
        "read_labels",
        "read_delegation",
        "read_agent",
        "read_meta",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl ConfigVisitor for AplConfigVisitor {
    fn name(&self) -> &str {
        "apl"
    }

    fn visit_plugins(
        &self,
        _mgr: &Arc<PluginManager>,
        plugins: &[PluginConfig],
    ) -> Result<(), VisitorError> {
        // Translate cpex-core's typed PluginConfig into apl-core's
        // PluginDeclaration. Field-for-field except `capabilities` is a
        // `HashSet` on the cpex side and a `Vec` on the apl side, and
        // `config` is wrapped in `serde_yaml::Value::Mapping` to match
        // apl-core's opaque shape. cpex-core has already validated
        // uniqueness by this point so we don't re-check.
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        state.plugin_registry.clear();
        for cfg in plugins {
            let decl = PluginDeclaration {
                name: cfg.name.clone(),
                kind: cfg.kind.clone(),
                hooks: cfg.hooks.clone(),
                capabilities: cfg.capabilities.iter().cloned().collect(),
                config: plugin_config_to_yaml(&cfg.config),
                on_error: Some(on_error_to_string(&cfg.on_error)),
                extra: HashMap::new(),
            };
            state.plugin_registry.insert(cfg.name.clone(), decl);
        }
        Ok(())
    }

    fn visit_global(
        &self,
        _mgr: &Arc<PluginManager>,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };

        // Process `apl.pdp[]` before stacking the policy/post_policy
        // layer — route handlers that reference PDPs need them
        // resolvable by the time `visit_route` runs.
        if let Some(pdp_entries) = apl_block.get("pdp").and_then(|v| v.as_sequence()) {
            for (i, entry) in pdp_entries.iter().enumerate() {
                self.build_pdp_from_config(entry, i)?;
            }
        }

        // Process an optional `global.apl.session_store` block: swap the
        // active store before `visit_route` clones it into handlers.
        if let Some(block) = apl_block.get("session_store") {
            self.build_session_store_from_config(block)?;
        }

        // The `pdp:` / `session_store:` sub-keys aren't APL DSL fields;
        // strip them before handing the block to
        // `compile_policy_block_value` so the compiler doesn't see unknown
        // keys. `compile_policy_block_value` accepts maps with `policy:` /
        // `post_policy:` / `args:` / `result:` / `plugins:` (and inert
        // fields it ignores), so a shallow strip on a clone is enough.
        let policy_only = strip_non_dsl_keys(&apl_block);
        let compiled = compile_policy_block_value("global.apl", &policy_only)
            .map_err(|e| Box::new(e) as VisitorError)?;
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .global_layer = Some(compiled);
        Ok(())
    }

    fn visit_default(
        &self,
        _mgr: &Arc<PluginManager>,
        entity_type: &str,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let source = format!("global.defaults.{}.apl", entity_type);
        warn_if_global_only_key_at_nonglobal_scope(&source, &apl_block);
        let compiled = compile_policy_block_value(&source, &apl_block)
            .map_err(|e| Box::new(e) as VisitorError)?;
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .default_layers
            .insert(entity_type.to_string(), compiled);
        Ok(())
    }

    fn visit_policy_bundle(
        &self,
        _mgr: &Arc<PluginManager>,
        tag: &str,
        yaml: &serde_yaml::Value,
    ) -> Result<(), VisitorError> {
        let Some(apl_block) = apl_subblock(yaml) else {
            return Ok(());
        };
        let source = format!("global.policies.{}.apl", tag);
        warn_if_global_only_key_at_nonglobal_scope(&source, &apl_block);
        let compiled = compile_policy_block_value(&source, &apl_block)
            .map_err(|e| Box::new(e) as VisitorError)?;
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .tag_layers
            .insert(tag.to_string(), compiled);
        Ok(())
    }

    fn visit_route(
        &self,
        mgr: &Arc<PluginManager>,
        yaml: &serde_yaml::Value,
        parsed: &RouteEntry,
    ) -> Result<(), VisitorError> {
        // Extract the route's APL block (if any) and the entity identity
        // we need for annotate_route. A route without an APL block AND
        // without inherited layers contributes nothing — skip.
        let route_apl = apl_subblock(yaml);
        let (entity_type, entity_names) = match entity_identity(parsed) {
            Some(e) => e,
            None => {
                tracing::warn!(
                    "APL visitor: route has no tool/resource/prompt/llm match — skipping",
                );
                return Ok(());
            },
        };
        if let Some(block) = &route_apl {
            warn_if_global_only_key_at_nonglobal_scope(&format!("routes.{entity_type}"), block);
        }
        let scope = parsed.meta.as_ref().and_then(|m| m.scope.clone());
        let tags: Vec<String> = parsed
            .meta
            .as_ref()
            .map(|m| m.tags.clone())
            .unwrap_or_default();

        // Snapshot the plugin registry + PDP router once outside the
        // per-entity loop. `visit_plugins` populated the registry
        // before any `visit_route` call; the router has been populated
        // by code-supplied `register_pdp` calls + `visit_global`
        // factory dispatch. Routes share both, so cloning each into an
        // `Arc` once and handing clones to each handler is cheaper than
        // re-reading the RwLock per entity. Cloning `PdpRouter` is
        // refcount bumps on each inner resolver — cheap.
        let (plugin_registry, pdp_router_arc) = {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            (
                Arc::new(state.plugin_registry.clone()),
                Arc::new(state.pdp_router.clone()) as Arc<dyn PdpResolver>,
            )
        };

        for (idx, entity_name) in entity_names.iter().enumerate() {
            // route_key is what `DispatchCache` keys on, so it must
            // disambiguate scoped vs unscoped routes for the same
            // entity — otherwise two same-named annotations share one
            // cached plan and the second's overrides leak into the first.
            let route_key = match &scope {
                Some(s) => format!("{}:{}@{}", entity_type, entity_name, s),
                None => format!("{}:{}", entity_type, entity_name),
            };
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());

            // Stack least-to-most-specific. Each apply_layer call appends
            // policy/post_policy steps and merges args/result/plugin_overrides
            // by field; the resulting CompiledRoute represents the route's
            // effective policy in evaluation order.
            let mut effective = CompiledRoute::new(&route_key);
            if let Some(layer) = state.global_layer.clone() {
                effective.apply_layer(layer);
            }
            if let Some(layer) = state.default_layers.get(entity_type).cloned() {
                effective.apply_layer(layer);
            }
            for tag in &tags {
                if let Some(layer) = state.tag_layers.get(tag).cloned() {
                    effective.apply_layer(layer);
                }
            }
            drop(state);

            if let Some(block) = &route_apl {
                let source = format!("routes.{}.apl", route_key);
                let route_layer = compile_policy_block_value(&source, block)
                    .map_err(|e| Box::new(e) as VisitorError)?;
                effective.apply_layer(route_layer);
            }

            // Route-level denial response (transpiled `denyWith`). Read from
            // the route YAML alongside the APL block; cpex-core tolerates the
            // out-of-band key. Route scope is most-specific, so set directly.
            if let Some(resp) = response_subblock(yaml, &route_key) {
                effective.response = Some(resp);
            }

            // Load-time lint, once per route: flag any APL `plugins:`
            // override declared for a plugin that no policy / delegate step
            // references. Checked on the fully-stacked `effective` route so
            // an override consumed by an inherited (global / default / tag)
            // policy is not falsely flagged. The overrides and referenced
            // names are entity-independent, so the first entity is
            // representative — guarding on `idx == 0` keeps it to one pass.
            if idx == 0 {
                warn_unreferenced_plugin_overrides(&effective);
            }

            // No layers contributed anything? Don't install a handler — the
            // route falls back to cpex-core's plugin-chain execution.
            if effective.declared_phases().is_empty() {
                continue;
            }

            // E3.1 — plugin-mode validation for `parallel:` blocks.
            // `apl-core::Effect::validate_parallel_purity` already rejected
            // FieldOp / Delegate at parse time; this pass checks that every
            // `plugin(X)` inside a `parallel:` references a plugin whose
            // mode is safe for concurrent execution (Audit / Concurrent /
            // FireAndForget). Sequential / Transform plugins would silently
            // lose their mutations inside cloned branches.
            //
            // Looks up modes through the cpex-core PluginManager (it has
            // the authoritative registration state). The lookup trait
            // is `parallel_safety::PluginModeLookup`, which
            // `PluginManager` implements.
            if let Err(msg) =
                crate::parallel_safety::validate_parallel_plugin_modes(&effective, mgr.as_ref())
            {
                let err_msg = format!("route '{}': parallel-safety: {}", route_key, msg);
                return Err(err_msg.into());
            }

            let route_arc = Arc::new(effective);

            // Resolve the entity-specific CMF hook pair. The visitor's
            // entity_identity() already filtered out unknown types, but
            // hook_pair_for_entity returning None would just skip the
            // annotation rather than crash — defense in depth.
            let (hook_pre, hook_post) = match hook_pair_for_entity(entity_type) {
                Some(pair) => pair,
                None => {
                    tracing::warn!(
                        entity_type,
                        entity_name,
                        "APL visitor: no CMF hook pair for entity_type — skipping route",
                    );
                    continue;
                },
            };

            // Snapshot the active session store (a `global.apl.session_store`
            // block in `visit_global` may have swapped it). Each handler
            // captures its own clone, so request-time dispatch never touches
            // the visitor's lock.
            let session_store = self
                .session_store
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .clone();

            // Install Pre + Post handlers. Each handler instance is bound to
            // ONE phase so the executor can pick the right entry-point off
            // the (entity_type, entity_name, scope, hook_name) key.
            install_handler(
                mgr,
                entity_type,
                entity_name,
                scope.clone(),
                hook_pre,
                Phase::Pre,
                Arc::clone(&route_arc),
                &plugin_registry,
                &self.dispatch_cache,
                &session_store,
                &self.manager,
                Some(Arc::clone(&pdp_router_arc)),
                &self.base_capabilities,
            );
            install_handler(
                mgr,
                entity_type,
                entity_name,
                scope.clone(),
                hook_post,
                Phase::Post,
                route_arc,
                &plugin_registry,
                &self.dispatch_cache,
                &session_store,
                &self.manager,
                Some(Arc::clone(&pdp_router_arc)),
                &self.base_capabilities,
            );
        }

        Ok(())
    }
}

// =====================================================================
// Helpers
// =====================================================================

#[allow(clippy::too_many_arguments)]
fn install_handler(
    mgr: &Arc<PluginManager>,
    entity_type: &str,
    entity_name: &str,
    scope: Option<String>,
    hook_name: &str,
    phase: Phase,
    route: Arc<CompiledRoute>,
    plugin_registry: &Arc<PluginRegistry>,
    dispatch_cache: &Arc<DispatchCache>,
    session_store: &Arc<dyn SessionStore>,
    manager: &Weak<PluginManager>,
    pdp: Option<Arc<dyn PdpResolver>>,
    base_capabilities: &std::collections::HashSet<String>,
) {
    // Capability gating at the synthetic-handler boundary. cpex-core's
    // executor calls `filter_extensions(&ext, &caps)` before every
    // handler invoke — including this one. If the synthetic handler
    // has fewer capabilities than its downstream plugins need, the
    // executor strips extensions on the way in (so APL predicates and
    // downstream plugins see empty views) and rejects mutations on the
    // way out (label / delegation appends fail monotonicity checks).
    //
    // Granted caps = union of every plugin's caps (with per-route
    // overrides applied) ∪ host-supplied baseline. The baseline
    // typically covers read-only attributes APL predicates touch
    // (`subject.*`, `role.*`, `delegated`, …) even when no plugins are
    // referenced.
    let mut capabilities = base_capabilities.clone();
    capabilities.extend(crate::dispatch_plan::route_capability_union(
        &route,
        plugin_registry,
    ));

    let plugin_config = PluginConfig {
        name: format!(
            "apl::{}::{}::{}",
            entity_type,
            entity_name,
            if phase == Phase::Pre { "pre" } else { "post" }
        ),
        kind: "builtin".to_string(),
        // The annotated handler covers exactly one CMF hook name.
        hooks: vec![hook_name.to_string()],
        capabilities,
        ..Default::default()
    };
    let mut handler = AplRouteHandler::new(
        plugin_config.clone(),
        route,
        phase,
        Arc::clone(plugin_registry),
        Arc::clone(dispatch_cache),
        Arc::clone(session_store),
        manager.clone(),
    );
    if let Some(pdp) = pdp {
        handler = handler.with_pdp(pdp);
    }
    mgr.annotate_route(
        entity_type.to_string(),
        entity_name.to_string(),
        scope,
        hook_name.to_string(),
        Arc::new(handler),
        plugin_config,
    );
}

/// Pick the route's entity identities from the first non-None match
/// field. v0: tool > resource > prompt > llm precedence. A list-form
/// match (`tool: [a, b]`) yields one annotation per element so each
/// request gets routed by its specific name.
fn entity_identity(route: &RouteEntry) -> Option<(&'static str, Vec<String>)> {
    if let Some(t) = &route.tool {
        return Some(("tool", names_of(t)));
    }
    if let Some(r) = &route.resource {
        return Some(("resource", names_of(r)));
    }
    if let Some(p) = &route.prompt {
        return Some(("prompt", names_of(p)));
    }
    if let Some(l) = &route.llm {
        return Some(("llm", names_of(l)));
    }
    None
}

fn names_of(sol: &cpex_core::config::StringOrList) -> Vec<String> {
    match sol {
        cpex_core::config::StringOrList::Single(p) => vec![p.as_str().to_string()],
        cpex_core::config::StringOrList::List(v) => v.clone(),
    }
}

/// Warn when an APL block carries a global-only wiring key
/// ([`GLOBAL_ONLY_NON_DSL_KEYS`]: `pdp`, `session_store`) at a scope that
/// cannot act on it. Only [`AplConfigVisitor::visit_global`] builds PDPs
/// and selects the session store (they are process-global CPEX wiring); a
/// `pdp:` / `session_store:` written under a default / policy-bundle /
/// route block is folded into the policy body and silently discarded by
/// `compile_policy_block_value`. Surfacing it here turns that quiet no-op
/// into an actionable signal. Applies to both the flat and `apl:`-wrapped
/// forms — neither is processed off the global scope.
fn warn_if_global_only_key_at_nonglobal_scope(scope: &str, apl_block: &serde_yaml::Value) {
    for key in GLOBAL_ONLY_NON_DSL_KEYS {
        if apl_block.get(key).is_some() {
            tracing::warn!(
                scope,
                key,
                "APL visitor: this key is only honored under the top-level `global:` block; \
                 the declaration at this scope is ignored",
            );
        }
    }
}

/// Load-time lint: warn when an APL `plugins:` override is declared for a
/// plugin that no `plugin(...)` / `run(...)` policy step (or `delegate(...)`
/// step) in the effective route references. The `plugins:` map only
/// *configures* a plugin — policy steps do the *activating* — so an
/// unreferenced override has no effect and is almost always a typo or a
/// leftover. Inspects the fully-stacked route, so an override consumed by an
/// inherited (global / default / tag) policy is not falsely flagged. Called
/// once per route from `visit_route` at config-load time, never per request.
fn warn_unreferenced_plugin_overrides(route: &CompiledRoute) {
    if route.plugin_overrides.is_empty() {
        return;
    }
    let mut referenced: std::collections::HashSet<String> =
        crate::dispatch_plan::collect_plugin_names(route)
            .into_iter()
            .collect();
    referenced.extend(crate::dispatch_plan::collect_delegate_plugin_names(route));
    for name in route.plugin_overrides.keys() {
        if !referenced.contains(name) {
            tracing::warn!(
                plugin = %name,
                route = %route.route_key,
                "APL `plugins:` override declared for a plugin no policy step references \
                 — the override has no effect (the `plugins:` map configures; policy steps activate)",
            );
        }
    }
}

/// APL sub-keys that are CPEX *wiring*, not policy DSL: they are honored
/// only under the top-level `global:` block (where `visit_global` acts on
/// them) and are stripped before the remainder is handed to
/// `compile_policy_block_value`, which doesn't model them. Kept as a single
/// source of truth shared by [`strip_non_dsl_keys`] and
/// [`warn_if_global_only_key_at_nonglobal_scope`].
const GLOBAL_ONLY_NON_DSL_KEYS: [&str; 2] = ["pdp", "session_store"];

/// Strip the global-only wiring sub-keys ([`GLOBAL_ONLY_NON_DSL_KEYS`])
/// from an `apl:` mapping so the remainder can be handed to
/// `compile_policy_block_value` (which doesn't model PDP / session-store
/// declarations — those are CPEX wiring concerns). Returns a clone of the
/// mapping with those keys removed; the original is left intact.
fn strip_non_dsl_keys(apl_block: &serde_yaml::Value) -> serde_yaml::Value {
    let Some(map) = apl_block.as_mapping() else {
        return apl_block.clone();
    };
    let mut cloned = map.clone();
    for key in GLOBAL_ONLY_NON_DSL_KEYS {
        cloned.remove(serde_yaml::Value::String(key.to_string()));
    }
    serde_yaml::Value::Mapping(cloned)
}

/// Bridge cpex-core's JSON-based `Option<serde_json::Value>` config slot
/// into apl-core's `Option<serde_yaml::Value>` shape. JSON is a strict
/// subset of YAML's value model so this is round-trip safe; failure
/// here would only happen if `serde_yaml::to_value` rejects a value
/// `serde_json::Value` already accepted (in practice: never).
fn plugin_config_to_yaml(cfg: &Option<serde_json::Value>) -> Option<serde_yaml::Value> {
    cfg.as_ref().and_then(|v| serde_yaml::to_value(v).ok())
}

/// Map cpex-core's `OnError` enum onto the string shape apl-core's
/// `PluginDeclaration` carries (kept stringly-typed there because the
/// APL spec also allows custom orchestrator-defined error modes).
fn on_error_to_string(on_err: &cpex_core::plugin::OnError) -> String {
    on_err.to_string()
}

/// APL keys recognized directly on a section (route / global / defaults /
/// policy-bundle) when the `apl:` wrapper is omitted. Includes the policy
/// DSL terms plus the global-only wiring keys ([`GLOBAL_ONLY_NON_DSL_KEYS`]):
/// `pdp` and `session_store` are accepted flat for parse symmetry with their
/// `apl:`-wrapped form, but only `visit_global` acts on them — at other
/// scopes they are inert and flagged by
/// [`warn_if_global_only_key_at_nonglobal_scope`].
/// `plugins` is intentionally absent here — it is shape-ambiguous (a
/// structural plugin-ref *list* vs an apl-override *map*) and handled
/// separately in [`apl_subblock`].
const FLAT_APL_KEYS: [&str; 6] = [
    "policy",
    "post_policy",
    "args",
    "result",
    "pdp",
    "session_store",
];

/// Pull a section's APL block out of its raw YAML.
///
/// The explicit `apl:` wrapper (`route -> apl -> policy`) takes
/// precedence. When it is absent, APL terms written directly on the
/// section (`route -> policy`) are accepted too: a synthetic block is
/// assembled from the recognized [`FLAT_APL_KEYS`] present on the
/// container, plus `plugins` when (and only when) it is a *mapping* —
/// the apl-override shape. A structural `plugins:` *list*
/// (`RouteEntry` / `PolicyGroup`) is left untouched. Returns `None`
/// when neither a wrapper nor any flat APL key is present — callers
/// treat that as "no contribution from this section" and move on.
fn apl_subblock(yaml: &serde_yaml::Value) -> Option<serde_yaml::Value> {
    // Explicit `apl:` wrapper wins.
    if let Some(block) = yaml.get("apl") {
        return if block.is_null() {
            None
        } else {
            Some(block.clone())
        };
    }

    // Fallback: APL terms written directly on the section, with no
    // `apl:` nesting. Copy only the unambiguous APL keys so structural
    // keys (tool / identity / defaults / ...) are never misread.
    let mut block = serde_yaml::Mapping::new();
    for key in FLAT_APL_KEYS {
        if let Some(value) = yaml.get(key) {
            block.insert(serde_yaml::Value::String(key.to_string()), value.clone());
        }
    }
    // `plugins` only in its apl-override (map) shape; a list is the
    // structural plugin-ref form and belongs to the section's own parse.
    if let Some(value) = yaml.get("plugins") {
        if value.is_mapping() {
            block.insert(
                serde_yaml::Value::String("plugins".to_string()),
                value.clone(),
            );
        }
    }

    if block.is_empty() {
        None
    } else {
        Some(serde_yaml::Value::Mapping(block))
    }
}

/// Extract a route-level `response:` block — the transpiled `denyWith`.
/// cpex-core tolerates this out-of-band key on the route; here we
/// deserialize it into a [`DenyResponse`]. A malformed block is logged
/// and skipped (best-effort) rather than failing the whole config.
fn response_subblock(yaml: &serde_yaml::Value, route_key: &str) -> Option<DenyResponse> {
    let block = yaml.get("response")?;
    if block.is_null() {
        return None;
    }
    match serde_yaml::from_value::<DenyResponse>(block.clone()) {
        Ok(resp) => Some(resp),
        Err(e) => {
            tracing::warn!(route = route_key, error = %e, "APL visitor: ignoring malformed route `response:` block");
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{apl_subblock, response_subblock};

    fn yaml(s: &str) -> serde_yaml::Value {
        serde_yaml::from_str(s).expect("valid yaml")
    }

    #[test]
    fn response_subblock_parses_denywith() {
        let v = yaml(
            "tool: \"*\"\nresponse:\n  status: 403\n  body: \"{\\\"error\\\":\\\"forbidden\\\"}\"\n  headers:\n    WWW-Authenticate: \"Bearer\"\n",
        );
        let resp = response_subblock(&v, "tool:*").expect("response present");
        assert_eq!(resp.status, Some(403));
        assert_eq!(resp.body.as_deref(), Some("{\"error\":\"forbidden\"}"));
        assert_eq!(
            resp.headers.get("WWW-Authenticate").map(String::as_str),
            Some("Bearer")
        );
    }

    #[test]
    fn response_subblock_absent_is_none() {
        let v = yaml("tool: \"*\"\npolicy:\n  - \"deny\"\n");
        assert!(response_subblock(&v, "tool:*").is_none());
    }

    #[test]
    fn apl_wrapper_is_returned_as_is() {
        let v = yaml("apl:\n  policy:\n    - \"deny\"\n");
        let block = apl_subblock(&v).expect("wrapper present");
        assert!(
            block.get("policy").is_some(),
            "wrapper block exposes policy"
        );
    }

    #[test]
    fn null_apl_wrapper_is_none() {
        let v = yaml("apl: null\n");
        assert!(
            apl_subblock(&v).is_none(),
            "explicit null apl => no contribution"
        );
    }

    #[test]
    fn flat_policy_without_wrapper_is_collected() {
        let v = yaml("tool: get_weather\npolicy:\n  - \"deny\"\n");
        let block = apl_subblock(&v).expect("flat policy recognized");
        assert!(
            block.get("policy").is_some(),
            "flat policy lifted into the block"
        );
        assert!(
            block.get("tool").is_none(),
            "structural keys must not leak into the apl block",
        );
    }

    #[test]
    fn flat_session_store_without_wrapper_is_collected() {
        // A `session_store:` written directly on `global:` (no `apl:`
        // wrapper) must be lifted into the block so `visit_global` can act
        // on it — symmetric with the `apl:`-wrapped form and with `pdp:`.
        let v = yaml("session_store:\n  kind: valkey\n  endpoint: localhost:6379\n");
        let block = apl_subblock(&v).expect("flat session_store recognized");
        let ss = block
            .get("session_store")
            .expect("session_store lifted into the block");
        assert_eq!(
            ss.get("kind").and_then(|k| k.as_str()),
            Some("valkey"),
            "the session_store mapping is preserved intact",
        );
    }

    #[test]
    fn flat_plugins_map_included_but_list_excluded() {
        // Map shape is the apl-override form → kept.
        let m = yaml("plugins:\n  audit:\n    on_error: ignore\n");
        let block = apl_subblock(&m).expect("plugins map is an apl term");
        assert!(block.get("plugins").is_some(), "plugins map is kept");

        // List shape is structural plugin-refs → not an apl block; with no
        // other APL keys present, the section contributes nothing.
        let l = yaml("plugins:\n  - audit\n");
        assert!(
            apl_subblock(&l).is_none(),
            "structural plugins list must not be treated as an apl block",
        );
    }

    #[test]
    fn section_without_apl_terms_is_none() {
        let v = yaml("tool: get_weather\n");
        assert!(
            apl_subblock(&v).is_none(),
            "no APL terms => no contribution"
        );
    }

    #[test]
    fn explicit_wrapper_wins_over_flat_keys() {
        let v = yaml("apl:\n  policy:\n    - \"allow\"\npolicy:\n  - \"deny\"\n");
        let block = apl_subblock(&v).expect("wrapper present");
        let policy = block
            .get("policy")
            .and_then(|p| p.as_sequence())
            .expect("policy sequence");
        assert_eq!(policy.len(), 1);
        assert_eq!(
            policy[0].as_str(),
            Some("allow"),
            "the explicit apl wrapper takes precedence over flat top-level keys",
        );
    }

    #[test]
    fn warn_if_global_only_key_at_nonglobal_scope_is_a_safe_noop() {
        use super::warn_if_global_only_key_at_nonglobal_scope;
        // The helper only emits a tracing event; it must never panic for
        // either global-only wiring key (`pdp` / `session_store`), or for
        // none present. (The drop semantics are exercised end-to-end; here
        // we just guard the helper's contract.)
        let with_pdp = yaml("policy:\n  - \"deny\"\npdp:\n  - kind: cel\n");
        let with_session_store = yaml("policy:\n  - \"deny\"\nsession_store:\n  kind: valkey\n");
        let without = yaml("policy:\n  - \"deny\"\n");
        warn_if_global_only_key_at_nonglobal_scope("route", &with_pdp);
        warn_if_global_only_key_at_nonglobal_scope("routes.tool", &with_session_store);
        warn_if_global_only_key_at_nonglobal_scope("global.defaults.tool.apl", &without);
    }

    #[test]
    fn unreferenced_plugin_override_is_detectable_and_lint_is_safe() {
        use super::{compile_policy_block_value, warn_unreferenced_plugin_overrides};
        // A route configures two plugins but its policy only activates one:
        // `used` is referenced by a `plugin(...)` step, `unused` is only
        // configured. The lint relies on `collect_plugin_names` seeing the
        // referenced set; verify that linkage, then that the helper runs.
        let block = yaml(
            "policy:\n  - \"plugin(used)\"\n\
             plugins:\n  used:\n    on_error: ignore\n  unused:\n    on_error: ignore\n",
        );
        let route = compile_policy_block_value("test", &block).expect("compiles");

        let referenced = crate::dispatch_plan::collect_plugin_names(&route);
        assert!(
            referenced.contains(&"used".to_string()),
            "policy step is referenced"
        );
        assert!(
            !referenced.contains(&"unused".to_string()),
            "config-only override is not a reference",
        );
        assert!(
            route.plugin_overrides.contains_key("unused"),
            "override was compiled in"
        );

        // Must not panic; it warns on `unused` and stays silent on `used`.
        warn_unreferenced_plugin_overrides(&route);
    }
}
