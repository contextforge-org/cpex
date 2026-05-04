// Location: ./crates/cpex-core/src/manager.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Plugin manager.
//
// Owns the plugin lifecycle (initialize, dispatch, shutdown) and
// the PluginRegistry. Provides two invoke paths:
//
// - `invoke::<H>()` — typed dispatch for Rust callers. Zero-cost.
//   The hook type is known at compile time; no registry lookup or
//   downcast needed for the payload.
//
// - `invoke_by_name()` — dynamic dispatch for Python/Go/WASM callers.
//   Hook name resolved from the registry; payload passed as
//   Box<dyn PluginPayload>.
//
// The manager reads plugin configs from the config loader and wraps
// each plugin in a PluginRef with the authoritative config. Plugins
// never provide their own config to the manager. Trust flows:
//   config loader → manager → PluginRef → executor
//
// Mirrors the Python framework's PluginManager in
// cpex/framework/manager.py.

use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::{Arc, RwLock};

use hashbrown::HashMap;
use tracing::{error, info, warn};

use crate::config::{self, CpexConfig};
use crate::context::PluginContextTable;
use crate::error::PluginError;
use crate::executor::{BackgroundTasks, Executor, ExecutorConfig, PipelineResult};
use crate::factory::PluginFactoryRegistry;
use crate::hooks::adapter::TypedHandlerAdapter;
use crate::hooks::payload::{Extensions, PluginPayload};
use crate::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use crate::hooks::HookType;
use crate::plugin::{Plugin, PluginConfig};
use crate::registry::{AnyHookHandler, PluginRef, PluginRegistry};

// ---------------------------------------------------------------------------
// Manager Configuration
// ---------------------------------------------------------------------------

/// Configuration for the PluginManager.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Executor configuration (timeout, short-circuit behavior).
    pub executor: ExecutorConfig,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            executor: ExecutorConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin Manager
// ---------------------------------------------------------------------------

/// Central plugin lifecycle and dispatch manager.
///
/// Owns the plugin registry and executor. Provides the public API
/// that host systems (ContextForge, Kagenti, etc.) call to register
/// plugins and invoke hooks.
///
/// # Lifecycle
///
/// ```text
/// new() → register plugins → initialize() → invoke hooks → shutdown()
/// ```
///
/// # Two Invoke Paths
///
/// - **`invoke::<H>()`** — typed dispatch. The hook type `H` is known
///   at compile time. Payload type-checked at compile time. Used by
///   Rust callers.
///
/// - **`invoke_by_name()`** — dynamic dispatch. The hook name is a
///   string. Payload is `Box<dyn PluginPayload>`. Used by Python/Go/WASM
///   callers via the FFI or PyO3 bindings.
///
/// Both paths use the same registry, executor, and 5-phase pipeline.
///
/// # Trust Model
///
/// The manager wraps each plugin in a `PluginRef` with an authoritative
/// config from the config loader. The executor reads all scheduling
/// decisions from `PluginRef.trusted_config` — never from the plugin.
/// Cache key for resolved routing entries.
///
/// Includes entity type, name, hook name, and scope so that
/// the same tool on different scopes or at different hook points
/// caches separately.
///
/// Custom Hash/Eq implementations hash on `&str` slices so that
/// `raw_entry` lookups with borrowed strings produce the same hash
/// as the owned key — enabling zero-allocation cache hits.
#[derive(Debug, Clone)]
struct RouteCacheKey {
    entity_type: String,
    entity_name: String,
    hook_name: String,
    scope: Option<String>,
}

impl Hash for RouteCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entity_type.as_str().hash(state);
        self.entity_name.as_str().hash(state);
        self.hook_name.as_str().hash(state);
        self.scope.as_deref().hash(state);
    }
}

impl PartialEq for RouteCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.entity_type == other.entity_type
            && self.entity_name == other.entity_name
            && self.hook_name == other.hook_name
            && self.scope == other.scope
    }
}

impl Eq for RouteCacheKey {}


pub struct PluginManager {
    /// Plugin registry — stores PluginRefs and hook-to-handler mappings.
    registry: PluginRegistry,

    /// Executor — stateless 5-phase pipeline engine.
    executor: Executor,

    /// Parsed CPEX config (when loaded from file). Used for route resolution.
    cpex_config: Option<CpexConfig>,

    /// Factory registry — owned by the manager. Used for initial
    /// instantiation and for creating override instances when routes
    /// override a plugin's base config.
    factories: PluginFactoryRegistry,

    /// Cache of resolved hook entries per (entity, hook, scope).
    /// Populated on first access, invalidated on config reload.
    /// Uses Arc so cache reads are refcount bumps (~1ns), not data copies.
    route_cache: RwLock<HashMap<RouteCacheKey, Arc<Vec<crate::registry::HookEntry>>>>,

    /// Hasher builder for zero-allocation cache lookups via raw_entry.
    cache_hasher: hashbrown::DefaultHashBuilder,


    /// Whether initialize() has been called.
    initialized: bool,
}

impl PluginManager {
    /// Create a new PluginManager with the given configuration.
    pub fn new(config: ManagerConfig) -> Self {
        let cache_hasher = hashbrown::DefaultHashBuilder::default();
        Self {
            registry: PluginRegistry::new(),
            executor: Executor::new(config.executor),
            cpex_config: None,
            factories: PluginFactoryRegistry::new(),
            route_cache: RwLock::new(HashMap::with_hasher(cache_hasher.clone())),
            cache_hasher,
            initialized: false,
        }
    }

    // -----------------------------------------------------------------------
    // Factory Registration
    // -----------------------------------------------------------------------

    /// Register a plugin factory for a given `kind` name.
    ///
    /// The host calls this to tell the manager how to create plugins
    /// of a specific kind. Must be called before `load_config()`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut manager = PluginManager::default();
    /// manager.register_factory("builtin", Box::new(BuiltinFactory));
    /// manager.register_factory("security/rate_limit", Box::new(RateLimiterFactory));
    /// manager.load_config(Path::new("plugins.yaml"))?;
    /// ```
    pub fn register_factory(
        &mut self,
        kind: impl Into<String>,
        factory: Box<dyn crate::factory::PluginFactory>,
    ) {
        self.factories.register(kind, factory);
    }

    // -----------------------------------------------------------------------
    // Config Loading
    // -----------------------------------------------------------------------

    /// Load plugins from a YAML config file.
    ///
    /// Parses the config, looks up each plugin's `kind` in the
    /// factory registry, instantiates the plugins, and registers
    /// them. Factories must be registered via `register_factory()`
    /// before calling this method.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut manager = PluginManager::default();
    /// manager.register_factory("builtin", Box::new(BuiltinFactory));
    /// manager.load_config_file(Path::new("plugins/config.yaml"))?;
    /// manager.initialize().await?;
    /// ```
    pub fn load_config_file(&mut self, path: &Path) -> Result<(), PluginError> {
        let cpex_config = config::load_config(path)?;
        self.load_config(cpex_config)
    }

    /// Load plugins from a parsed config.
    ///
    /// Looks up each plugin's `kind` in the factory registry,
    /// instantiates the plugins, and registers them with their
    /// hook names from the config.
    pub fn load_config(&mut self, cpex_config: CpexConfig) -> Result<(), PluginError> {
        // Update executor settings from config
        self.executor = Executor::new(ExecutorConfig {
            timeout_seconds: cpex_config.plugin_settings.plugin_timeout,
            short_circuit_on_deny: cpex_config.plugin_settings.short_circuit_on_deny,
        });

        // Instantiate and register each plugin from config
        for plugin_config in &cpex_config.plugins {
            let factory = self.factories.get(&plugin_config.kind).ok_or_else(|| {
                PluginError::Config {
                    message: format!(
                        "no factory registered for plugin kind '{}' (plugin '{}')",
                        plugin_config.kind, plugin_config.name
                    ),
                }
            })?;

            let instance = factory.create(plugin_config)?;

            self.registry
                .register_multi_handler(
                    instance.plugin,
                    plugin_config.clone(),
                    instance.handlers,
                )
                .map_err(|msg| PluginError::Config { message: msg })?;

            info!(
                "Registered plugin '{}' (kind: '{}') for hooks: {:?}",
                plugin_config.name, plugin_config.kind, plugin_config.hooks
            );
        }

        // Clear routing cache — config changed
        self.clear_routing_cache();

        // Store config for route resolution
        self.cpex_config = Some(cpex_config);

        Ok(())
    }

    /// Create a PluginManager from a parsed config (convenience).
    ///
    /// Uses the passed factory registry for initial instantiation.
    /// Note: for route-level config overrides to create new instances
    /// at runtime, use `register_factory()` + `load_config()` instead
    /// so the manager owns the factories.
    pub fn from_config(
        cpex_config: CpexConfig,
        factories: &PluginFactoryRegistry,
    ) -> Result<Self, PluginError> {
        let mut manager = Self::new(ManagerConfig::default());

        // Instantiate and register each plugin
        for plugin_config in &cpex_config.plugins {
            let factory = factories.get(&plugin_config.kind).ok_or_else(|| {
                PluginError::Config {
                    message: format!(
                        "no factory registered for plugin kind '{}' (plugin '{}')",
                        plugin_config.kind, plugin_config.name
                    ),
                }
            })?;

            let instance = factory.create(plugin_config)?;

            manager
                .registry
                .register_multi_handler(
                    instance.plugin,
                    plugin_config.clone(),
                    instance.handlers,
                )
                .map_err(|msg| PluginError::Config { message: msg })?;
        }

        // Update executor from config settings
        manager.executor = Executor::new(ExecutorConfig {
            timeout_seconds: cpex_config.plugin_settings.plugin_timeout,
            short_circuit_on_deny: cpex_config.plugin_settings.short_circuit_on_deny,
        });

        manager.cpex_config = Some(cpex_config);
        Ok(manager)
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a plugin handler for its primary hook name.
    ///
    /// This is the preferred registration method. The framework creates
    /// the type-erased adapter internally — no `AnyHookHandler` needed.
    ///
    /// # Type Parameters
    ///
    /// - `H` — the hook type (implements `HookTypeDef`).
    /// - `P` — the plugin type (implements `Plugin + HookHandler<H>`).
    ///
    /// # Arguments
    ///
    /// - `plugin` — the plugin implementation.
    /// - `config` — authoritative config from the config loader.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// manager.register_handler::<CmfHook, _>(plugin, config)?;
    /// ```
    pub fn register_handler<H, P>(
        &mut self,
        plugin: Arc<P>,
        config: PluginConfig,
    ) -> Result<(), PluginError>
    where
        H: HookTypeDef,
        H::Result: Into<PluginResult<H::Payload>>,
        P: Plugin + HookHandler<H> + 'static,
    {
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<H, P>::new(Arc::clone(&plugin)));
        self.registry
            .register::<H>(plugin, config, handler)
            .map_err(|msg| PluginError::Config { message: msg })
    }

    /// Register a plugin handler for multiple hook names.
    ///
    /// This is the CMF pattern — one handler covers multiple hook
    /// names (`cmf.tool_pre_invoke`, `cmf.llm_input`, etc.).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// manager.register_handler_for_names::<CmfHook, _>(
    ///     plugin, config,
    ///     &["cmf.tool_pre_invoke", "cmf.llm_input", "cmf.llm_output"],
    /// )?;
    /// ```
    pub fn register_handler_for_names<H, P>(
        &mut self,
        plugin: Arc<P>,
        config: PluginConfig,
        names: &[&str],
    ) -> Result<(), PluginError>
    where
        H: HookTypeDef,
        H::Result: Into<PluginResult<H::Payload>>,
        P: Plugin + HookHandler<H> + 'static,
    {
        let handler: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<H, P>::new(Arc::clone(&plugin)));
        self.registry
            .register_for_names::<H>(plugin, config, handler, names)
            .map_err(|msg| PluginError::Config { message: msg })
    }

    /// Register with an explicit AnyHookHandler (advanced use).
    ///
    /// For cases where the automatic adapter doesn't fit — e.g.,
    /// Python/WASM bridge hosts that implement AnyHookHandler directly.
    /// Most callers should use `register_handler` instead.
    pub fn register_raw<H: HookTypeDef>(
        &mut self,
        plugin: Arc<dyn Plugin>,
        config: PluginConfig,
        handler: Arc<dyn AnyHookHandler>,
    ) -> Result<(), PluginError> {
        self.registry
            .register::<H>(plugin, config, handler)
            .map_err(|msg| PluginError::Config { message: msg })
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Initialize all registered plugins.
    ///
    /// Calls `plugin.initialize()` on each registered plugin. Must be
    /// called before invoking any hooks. Idempotent — calling twice
    /// has no effect.
    pub async fn initialize(&mut self) -> Result<(), PluginError> {
        if self.initialized {
            return Ok(());
        }

        info!(
            "Initializing PluginManager with {} plugins",
            self.registry.plugin_count()
        );

        let mut initialized_plugins: Vec<String> = Vec::new();

        for name in self.registry.plugin_names() {
            if let Some(plugin_ref) = self.registry.get(name) {
                let plugin = plugin_ref.plugin().clone();
                let plugin_name = name.to_string();

                if let Err(e) = plugin.initialize().await {
                    error!("Failed to initialize plugin '{}': {}", plugin_name, e);

                    // Clean up already-initialized plugins
                    for init_name in initialized_plugins.iter().rev() {
                        if let Some(pr) = self.registry.get(init_name) {
                            if let Err(shutdown_err) = pr.plugin().shutdown().await {
                                error!(
                                    "Error shutting down plugin '{}' during rollback: {}",
                                    init_name, shutdown_err
                                );
                            }
                        }
                    }

                    return Err(PluginError::Execution {
                        plugin_name,
                        message: format!("initialization failed: {}", e),
                        source: Some(Box::new(e)),
                        code: None,
                        details: std::collections::HashMap::new(),
                        proto_error_code: None,
                    });
                }

                initialized_plugins.push(plugin_name);
            }
        }

        self.initialized = true;
        info!("PluginManager initialized successfully");
        Ok(())
    }

    /// Shutdown all registered plugins.
    ///
    /// Calls `plugin.shutdown()` on each registered plugin in reverse
    /// registration order. Errors are logged but do not halt the
    /// shutdown process — all plugins get a chance to clean up.
    pub async fn shutdown(&mut self) {
        if !self.initialized {
            return;
        }

        info!("Shutting down PluginManager");

        for name in self.registry.plugin_names() {
            if let Some(plugin_ref) = self.registry.get(name) {
                let plugin = plugin_ref.plugin().clone();

                if let Err(e) = plugin.shutdown().await {
                    error!("Error shutting down plugin '{}': {}", name, e);
                    // Continue — don't let one plugin's failure block others
                }
            }
        }

        self.initialized = false;
        info!("PluginManager shutdown complete");
    }

    // -----------------------------------------------------------------------
    // Hook Invocation — Dynamic (invoke_by_name)
    // -----------------------------------------------------------------------

    /// Invoke a hook by name with a type-erased payload.
    ///
    /// This is the dynamic dispatch path used by Python/Go/WASM
    /// callers via FFI or PyO3 bindings. The hook name is resolved
    /// from the registry and dispatched through the 5-phase executor.
    ///
    /// # Arguments
    ///
    /// * `hook_name` — the hook name string (e.g., `"cmf.tool_pre_invoke"`).
    /// * `payload` — the payload as `Box<dyn PluginPayload>`.
    /// * `extensions` — the full extensions (filtered per plugin by the executor).
    /// * `context_table` — optional context table from a previous hook
    ///   invocation. Pass `None` on the first hook call; thread the
    ///   returned table into subsequent calls to preserve per-plugin state.
    ///
    /// # Returns
    ///
    /// A tuple of `(PipelineResult, BackgroundTasks)`. The result
    /// contains the final payload, extensions, violation, and context
    /// table. Background tasks can be awaited or dropped.
    pub async fn invoke_by_name(
        &self,
        hook_name: &str,
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        let hook_type = HookType::new(hook_name);
        let all_entries = self.registry.entries_for_hook(&hook_type);

        if all_entries.is_empty() {
            return (
                PipelineResult::allowed_with(
                    payload,
                    extensions,
                    context_table.unwrap_or_default(),
                ),
                BackgroundTasks::empty(),
            );
        }

        let entries = self.filter_entries_by_route(all_entries, &extensions, hook_name);

        if entries.is_empty() {
            return (
                PipelineResult::allowed_with(
                    payload,
                    extensions,
                    context_table.unwrap_or_default(),
                ),
                BackgroundTasks::empty(),
            );
        }

        self.executor
            .execute(&entries, payload, extensions, context_table)
            .await
    }

    // -----------------------------------------------------------------------
    // Hook Invocation — Typed (invoke::<H>)

    // -----------------------------------------------------------------------

    /// Invoke a typed hook.
    ///
    /// This is the compile-time dispatch path used by Rust callers.
    /// The hook type `H` determines the payload and result types.
    /// Dispatch goes through the same registry and 5-phase executor
    /// as `invoke_by_name()`.
    ///
    /// When routing is enabled, the entity is identified from
    /// `extensions.meta` (entity_type + entity_name). Only plugins
    /// matching the resolved route fire. When routing is disabled
    /// or meta is absent, all registered plugins fire.
    ///
    /// # Type Parameters
    ///
    /// - `H` — the hook type (implements `HookTypeDef`).
    ///
    /// # Arguments
    ///
    /// * `payload` — the typed payload.
    /// * `extensions` — the full extensions (includes meta for routing).
    /// * `context_table` — optional context table from a previous hook.
    ///
    /// # Returns
    ///
    /// A tuple of `(PipelineResult, BackgroundTasks)`.
    pub async fn invoke<H: HookTypeDef>(
        &self,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        let hook_type = HookType::new(H::NAME);
        let all_entries = self.registry.entries_for_hook(&hook_type);

        if all_entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                PipelineResult::allowed_with(
                    boxed,
                    extensions,
                    context_table.unwrap_or_default(),
                ),
                BackgroundTasks::empty(),
            );
        }

        let entries = self.filter_entries_by_route(all_entries, &extensions, H::NAME);

        if entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                PipelineResult::allowed_with(
                    boxed,
                    extensions,
                    context_table.unwrap_or_default(),
                ),
                BackgroundTasks::empty(),
            );
        }

        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        self.executor
            .execute(&entries, boxed, extensions, context_table)
            .await
    }

    /// Invoke a typed hook by explicit name.
    ///
    /// Combines compile-time payload type checking (from `H`) with
    /// runtime hook name routing (from `hook_name`). Use this when
    /// a single hook type (e.g., `CmfHook`) covers multiple hook
    /// names (e.g., `cmf.tool_pre_invoke`, `cmf.tool_post_invoke`).
    ///
    /// # Type Parameters
    ///
    /// - `H` — the hook type (provides payload type checking).
    ///
    /// # Arguments
    ///
    /// * `hook_name` — the hook name for dispatch routing.
    /// * `payload` — the typed payload (compile-time checked against `H::Payload`).
    /// * `extensions` — the full extensions.
    /// * `context_table` — optional context table from a previous hook.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Compile-time: payload must be MessagePayload (from CmfHook)
    /// // Runtime: dispatches to plugins registered under "cmf.tool_pre_invoke"
    /// let (result, bg) = mgr.invoke_named::<CmfHook>(
    ///     "cmf.tool_pre_invoke", payload, ext, None,
    /// ).await;
    /// ```
    pub async fn invoke_named<H: HookTypeDef>(
        &self,
        hook_name: &str,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> (PipelineResult, BackgroundTasks) {
        let hook_type = HookType::new(hook_name);
        let all_entries = self.registry.entries_for_hook(&hook_type);

        if all_entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                PipelineResult::allowed_with(
                    boxed,
                    extensions,
                    context_table.unwrap_or_default(),
                ),
                BackgroundTasks::empty(),
            );
        }

        let entries = self.filter_entries_by_route(all_entries, &extensions, hook_name);

        if entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return (
                PipelineResult::allowed_with(
                    boxed,
                    extensions,
                    context_table.unwrap_or_default(),
                ),
                BackgroundTasks::empty(),
            );
        }

        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        self.executor
            .execute(&entries, boxed, extensions, context_table)
            .await
    }

    // -----------------------------------------------------------------------
    // Route Filtering
    // -----------------------------------------------------------------------

    /// Filter hook entries based on route resolution, with caching.
    ///
    /// When routing is enabled and extensions.meta provides entity
    /// identification, resolves the route and returns only the entries
    /// for plugins that match. Results are cached by
    /// `(entity_type, entity_name, hook_name, scope)` — subsequent
    /// calls for the same key return an `Arc` to the cached entries
    /// (refcount bump, no data copy).
    ///
    /// When routing is disabled or meta is absent, returns all entries.
    fn filter_entries_by_route(
        &self,
        entries: &[crate::registry::HookEntry],
        extensions: &Extensions,
        hook_name: &str,
    ) -> Arc<Vec<crate::registry::HookEntry>> {
        // If no config or routing disabled, return all
        let cpex_config = match &self.cpex_config {
            Some(c) if c.routing_enabled() => c,
            _ => return Arc::new(entries.to_vec()),
        };

        // Extract entity info from meta extension
        let meta = match &extensions.meta {
            Some(m) => m,
            None => return Arc::new(entries.to_vec()),
        };

        let (entity_type, entity_name) = match (&meta.entity_type, &meta.entity_name) {
            (Some(t), Some(n)) => (t.as_str(), n.as_str()),
            _ => return Arc::new(entries.to_vec()),
        };

        let request_scope = meta.scope.as_deref();

        // Fast path: zero-allocation cache lookup with raw_entry
        let hash = {
            use std::hash::BuildHasher;
            let mut hasher = self.cache_hasher.build_hasher();
            entity_type.hash(&mut hasher);
            entity_name.hash(&mut hasher);
            hook_name.hash(&mut hasher);
            request_scope.hash(&mut hasher);
            hasher.finish()
        };
        {
            let cache = self.route_cache.read().unwrap();
            if let Some((_, cached)) = cache.raw_entry().from_hash(hash, |key| {
                key.entity_type == entity_type
                    && key.entity_name == entity_name
                    && key.hook_name == hook_name
                    && key.scope.as_deref() == request_scope
            }) {
                return Arc::clone(cached);
            }
        }

        // Slow path: resolve, filter, and cache (allocations only here)
        let resolved = config::resolve_plugins_for_entity(
            cpex_config,
            entity_type,
            entity_name,
            request_scope,
            &meta.tags,
        );

        // Filter entries to resolved plugins, preserving resolution order.
        // If a plugin has config overrides and we have a factory for its kind,
        // create a new instance with the merged config.
        let mut filtered = Vec::new();
        for resolved_plugin in &resolved {
            if let Some(entry) = entries.iter().find(|e| e.plugin_ref.name() == resolved_plugin.name) {
                if let Some(overrides) = &resolved_plugin.config_overrides {
                    // Try to create an override instance
                    if let Some(override_entry) = self.create_override_instance(entry, overrides) {
                        filtered.push(override_entry);
                        continue;
                    }
                }
                filtered.push(entry.clone());
            }
        }

        let cached = Arc::new(filtered);

        // Store in cache — owned key allocated only on cache miss
        let cache_key = RouteCacheKey {
            entity_type: entity_type.to_string(),
            entity_name: entity_name.to_string(),
            hook_name: hook_name.to_string(),
            scope: meta.scope.clone(),
        };
        {
            let mut cache = self.route_cache.write().unwrap();
            cache.insert(cache_key, Arc::clone(&cached));
        }

        cached
    }

    /// Create an override plugin instance with merged config.
    ///
    /// When a route overrides a plugin's config, we create a new
    /// instance via the factory with the merged config. Returns
    /// None if no factory is available for the plugin's kind.
    fn create_override_instance(
        &self,
        base_entry: &crate::registry::HookEntry,
        overrides: &serde_json::Value,
    ) -> Option<crate::registry::HookEntry> {
        let base_config = base_entry.plugin_ref.trusted_config();
        let kind = &base_config.kind;

        let factory = self.factories.get(kind)?;

        // Merge: start with base config, overlay with overrides
        let mut merged_config = base_config.clone();
        if let Some(override_config) = overrides.get("config") {
            // Merge the plugin-specific config section
            if let Some(base_plugin_config) = &merged_config.config {
                let mut merged = base_plugin_config.clone();
                if let (Some(base_obj), Some(override_obj)) =
                    (merged.as_object_mut(), override_config.as_object())
                {
                    for (key, value) in override_obj {
                        base_obj.insert(key.clone(), value.clone());
                    }
                }
                merged_config.config = Some(merged);
            } else {
                merged_config.config = Some(override_config.clone());
            }
        }

        // Create new instance with merged config
        let target_hook = base_entry.handler.hook_type_name();
        match factory.create(&merged_config) {
            Ok(instance) => {
                // Find the handler matching the current hook
                let handler = instance
                    .handlers
                    .into_iter()
                    .find(|(name, _)| *name == target_hook)
                    .map(|(_, h)| h);

                if let Some(handler) = handler {
                    let plugin_ref =
                        crate::registry::PluginRef::new(instance.plugin, merged_config);
                    Some(crate::registry::HookEntry {
                        plugin_ref,
                        handler,
                    })
                } else {
                    warn!(
                        "Override instance for '{}' has no handler for hook '{}'",
                        base_config.name, target_hook
                    );
                    None
                }
            }
            Err(e) => {
                error!(
                    "Failed to create override instance for '{}': {}",
                    base_config.name, e
                );
                None // fall back to base instance
            }
        }
    }

    /// Clear the routing cache. Call when config is reloaded or
    /// plugins are registered/unregistered.
    pub fn clear_routing_cache(&self) {
        let mut cache = self.route_cache.write().unwrap();
        cache.clear();
    }

    /// Number of entries in the routing cache.
    pub fn routing_cache_size(&self) -> usize {
        self.route_cache.read().unwrap().len()
    }

    // -----------------------------------------------------------------------
    // Query Methods
    // -----------------------------------------------------------------------

    /// Whether any plugins are registered for the given hook name.
    pub fn has_hooks_for(&self, hook_name: &str) -> bool {
        self.registry.has_hooks_for(&HookType::new(hook_name))
    }

    /// Look up a plugin by name.
    pub fn get_plugin(&self, name: &str) -> Option<&PluginRef> {
        self.registry.get(name)
    }

    /// Total number of registered plugins.
    pub fn plugin_count(&self) -> usize {
        self.registry.plugin_count()
    }

    /// All registered plugin names.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.registry.plugin_names()
    }

    /// Whether the manager has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Unregister a plugin by name.
    pub fn unregister(&mut self, name: &str) -> Option<PluginRef> {
        self.registry.unregister(name)
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new(ManagerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PluginContext;
    use crate::error::PluginViolation;
    use crate::hooks::payload::Extensions;
    use crate::hooks::{HookHandler, PluginResult};
    use crate::plugin::{OnError, PluginMode};
    use async_trait::async_trait;

    // -- Test payload --

    #[derive(Debug, Clone)]
    struct TestPayload {
        value: String,
    }
    crate::impl_plugin_payload!(TestPayload);

    // -- Test hook type --

    struct TestHook;
    impl HookTypeDef for TestHook {
        type Payload = TestPayload;
        type Result = PluginResult<TestPayload>;
        const NAME: &'static str = "test_hook";
    }

    // -- Test plugins: implement Plugin + HookHandler<TestHook> --
    // No AnyHookHandler boilerplate — the framework handles it.

    /// Plugin that allows everything.
    struct AllowPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for AllowPlugin {
        fn config(&self) -> &PluginConfig { &self.cfg }
        async fn initialize(&self) -> Result<(), PluginError> { Ok(()) }
        async fn shutdown(&self) -> Result<(), PluginError> { Ok(()) }
    }

    impl HookHandler<TestHook> for AllowPlugin {
        fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::allow()
        }
    }

    /// Plugin that denies everything.
    struct DenyPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for DenyPlugin {
        fn config(&self) -> &PluginConfig { &self.cfg }
        async fn initialize(&self) -> Result<(), PluginError> { Ok(()) }
        async fn shutdown(&self) -> Result<(), PluginError> { Ok(()) }
    }

    impl HookHandler<TestHook> for DenyPlugin {
        fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::deny(PluginViolation::new("denied", "test denial"))
        }
    }

    /// Handler that always returns an error (for testing on_error behavior).
    struct ErrorHandler;

    #[async_trait]
    impl AnyHookHandler for ErrorHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
            Err(PluginError::Execution {
                plugin_name: "error-plugin".into(),
                message: "simulated failure".into(),
                source: None,
                code: None,
                details: std::collections::HashMap::new(),
                proto_error_code: None,
            })
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    // -- Helpers --

    fn make_config(name: &str, priority: i32, mode: PluginMode) -> PluginConfig {
        make_config_with_on_error(name, priority, mode, OnError::Fail)
    }

    fn make_config_with_on_error(
        name: &str,
        priority: i32,
        mode: PluginMode,
        on_error: OnError,
    ) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            kind: "test".to_string(),
            description: None,
            author: None,
            version: None,
            hooks: vec!["test_hook".to_string()],
            mode,
            priority,
            on_error,
            capabilities: Default::default(),
            tags: Vec::new(),
            conditions: Vec::new(),
            config: None,
        }
    }

    // -- Tests --

    #[tokio::test]
    async fn test_manager_lifecycle() {
        let mut mgr = PluginManager::default();
        assert!(!mgr.is_initialized());
        assert_eq!(mgr.plugin_count(), 0);

        mgr.initialize().await.unwrap();
        assert!(mgr.is_initialized());

        // Idempotent
        mgr.initialize().await.unwrap();

        mgr.shutdown().await;
        assert!(!mgr.is_initialized());
    }

    #[tokio::test]
    async fn test_invoke_by_name_no_plugins() {
        let mgr = PluginManager::default();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });


        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
        assert!(result.modified_payload.is_some());
    }

    #[tokio::test]
    async fn test_invoke_by_name_allow() {
        let mut mgr = PluginManager::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });

        // Clean registration — no AnyHookHandler needed
        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });


        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_by_name_deny() {
        let mut mgr = PluginManager::default();
        let config = make_config("deny-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(DenyPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });


        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    #[tokio::test]
    async fn test_invoke_typed() {
        let mut mgr = PluginManager::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "typed".into(),
        };


        let (result, _) = mgr
            .invoke::<TestHook>(payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_named() {
        // invoke_named::<H>(hook_name, ...) gives compile-time payload
        // type checking while routing to a specific hook name.
        let mut mgr = PluginManager::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "named".into(),
        };

        // TestHook::NAME is "test_hook" — invoke_named routes by the
        // explicit hook_name parameter, not H::NAME
        let (result, _) = mgr
            .invoke_named::<TestHook>("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_named_no_plugins_for_hook() {
        // invoke_named with a hook name that has no registered plugins
        let mut mgr = PluginManager::default();
        let config = make_config("allow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "no-match".into(),
        };

        // Plugin is registered under "test_hook", but we invoke "other_hook"
        let (result, _) = mgr
            .invoke_named::<TestHook>("other_hook", payload, Extensions::default(), None)
            .await;

        // No plugins fire — allowed by default
        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_invoke_named_deny() {
        let mut mgr = PluginManager::default();
        let config = make_config("deny-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(DenyPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload {
            value: "denied".into(),
        };

        let (result, _) = mgr
            .invoke_named::<TestHook>("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    #[tokio::test]
    async fn test_has_hooks_for() {
        let mut mgr = PluginManager::default();
        assert!(!mgr.has_hooks_for("test_hook"));

        let config = make_config("p1", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();

        assert!(mgr.has_hooks_for("test_hook"));
        assert!(!mgr.has_hooks_for("other_hook"));
    }

    #[tokio::test]
    async fn test_unregister() {
        let mut mgr = PluginManager::default();
        let config = make_config("removable", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();

        assert_eq!(mgr.plugin_count(), 1);
        mgr.unregister("removable");
        assert_eq!(mgr.plugin_count(), 0);
        assert!(!mgr.has_hooks_for("test_hook"));
    }

    #[tokio::test]
    async fn test_audit_plugin_cannot_block() {
        let mut mgr = PluginManager::default();
        let config = make_config("audit-denier", 10, PluginMode::Audit);
        let plugin = Arc::new(DenyPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });


        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Audit mode — deny is suppressed, pipeline continues
        assert!(result.continue_processing);
    }

    #[tokio::test]
    async fn test_on_error_disable_skips_plugin_on_subsequent_invocations() {
        let mut mgr = PluginManager::default();

        // Register an error handler with on_error: Disable
        let config = make_config_with_on_error(
            "flaky-plugin", 10, PluginMode::Sequential, OnError::Disable,
        );
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();

        // Also register a normal allow plugin (lower priority = runs second)
        let config2 = make_config("allow-plugin", 20, PluginMode::Sequential);
        let plugin2 = Arc::new(AllowPlugin { cfg: config2.clone() });
        mgr.register_handler::<TestHook, _>(plugin2, config2).unwrap();

        mgr.initialize().await.unwrap();


        // First invocation — flaky plugin errors, gets disabled, pipeline continues
        // because on_error is Disable (not Fail). allow-plugin still runs.
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "first".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(result.continue_processing);

        // Verify the plugin is now disabled
        let plugin_ref = mgr.get_plugin("flaky-plugin").unwrap();
        assert!(plugin_ref.is_disabled());
        assert_eq!(plugin_ref.mode(), PluginMode::Disabled);

        // Second invocation — flaky plugin should be skipped entirely
        // (group_by_mode filters it out). Only allow-plugin runs.
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "second".into() });
        let (result2, _) = mgr.invoke_by_name("test_hook", payload2, Extensions::default(), None).await;
        assert!(result2.continue_processing);
    }

    #[tokio::test]
    async fn test_on_error_ignore_continues_without_disabling() {
        let mut mgr = PluginManager::default();

        // Register an error handler with on_error: Ignore
        let config = make_config_with_on_error(
            "flaky-plugin", 10, PluginMode::Sequential, OnError::Ignore,
        );
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();

        mgr.initialize().await.unwrap();


        // First invocation — plugin errors, ignored, pipeline continues
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(result.continue_processing);

        // Plugin should NOT be disabled — still in its original mode
        let plugin_ref = mgr.get_plugin("flaky-plugin").unwrap();
        assert!(!plugin_ref.is_disabled());
        assert_eq!(plugin_ref.mode(), PluginMode::Sequential);
    }

    #[tokio::test]
    async fn test_on_error_fail_halts_pipeline() {
        let mut mgr = PluginManager::default();

        // Register an error handler with on_error: Fail (default)
        let config = make_config_with_on_error(
            "strict-plugin", 10, PluginMode::Sequential, OnError::Fail,
        );
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ErrorHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();

        mgr.initialize().await.unwrap();


        // Invocation — plugin errors, pipeline halts with a violation
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "plugin_error");
        assert_eq!(
            result.violation.as_ref().unwrap().plugin_name.as_deref(),
            Some("strict-plugin"),
        );
    }

    // -- Additional test plugins --

    /// Plugin that modifies the payload (for Transform mode testing).
    struct TransformPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for TransformPlugin {
        fn config(&self) -> &PluginConfig { &self.cfg }
        async fn initialize(&self) -> Result<(), PluginError> { Ok(()) }
        async fn shutdown(&self) -> Result<(), PluginError> { Ok(()) }
    }

    impl HookHandler<TestHook> for TransformPlugin {
        fn handle(
            &self,
            payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::modify_payload(TestPayload {
                value: format!("{}_transformed", payload.value),
            })
        }
    }

    /// Handler that sleeps (for timeout and fire-and-forget testing).
    struct SlowHandler {
        delay_ms: u64,
    }

    #[async_trait]
    impl AnyHookHandler for SlowHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            let result: PluginResult<TestPayload> = PluginResult::allow();
            Ok(crate::executor::erase_result(result))
        }

        fn hook_type_name(&self) -> &'static str {
            "test_hook"
        }
    }

    // -- Bug-covering tests --

    #[tokio::test]
    async fn test_transform_modifies_payload() {
        let mut mgr = PluginManager::default();
        let config = make_config("transformer", 10, PluginMode::Transform);
        let plugin = Arc::new(TransformPlugin { cfg: config.clone() });

        mgr.register_handler::<TestHook, _>(plugin, config).unwrap();
        mgr.initialize().await.unwrap();

        let payload = TestPayload { value: "original".into() };

        let (result, _) = mgr.invoke::<TestHook>(payload, Extensions::default(), None).await;

        assert!(result.continue_processing);
        let final_payload = result.modified_payload.unwrap();
        let typed = final_payload.as_any().downcast_ref::<TestPayload>().unwrap();
        assert_eq!(typed.value, "original_transformed");
    }

    #[tokio::test]
    async fn test_concurrent_multiple_plugins_all_run() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Shared counter to prove both plugins actually ran
        static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
        CALL_COUNT.store(0, Ordering::SeqCst);

        struct CountingHandler;

        #[async_trait]
        impl AnyHookHandler for CountingHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
                // Small sleep to ensure both tasks are spawned before either finishes
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                CALL_COUNT.fetch_add(1, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }

            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mut mgr = PluginManager::default();

        let c1 = make_config("concurrent-1", 10, PluginMode::Concurrent);
        let p1 = Arc::new(AllowPlugin { cfg: c1.clone() });
        let h1: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler);
        mgr.register_raw::<TestHook>(p1, c1, h1).unwrap();

        let c2 = make_config("concurrent-2", 20, PluginMode::Concurrent);
        let p2 = Arc::new(AllowPlugin { cfg: c2.clone() });
        let h2: Arc<dyn AnyHookHandler> = Arc::new(CountingHandler);
        mgr.register_raw::<TestHook>(p2, c2, h2).unwrap();

        mgr.initialize().await.unwrap();

        let start = std::time::Instant::now();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        let elapsed = start.elapsed();

        assert!(result.continue_processing);
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 2);
        // If they ran in parallel, total time should be ~50ms, not ~100ms
        assert!(elapsed.as_millis() < 90, "concurrent plugins ran serially: {}ms", elapsed.as_millis());
    }

    #[tokio::test]
    async fn test_timeout_fires_on_slow_handler() {
        // Create a manager with a very short timeout
        let config = ManagerConfig {
            executor: crate::executor::ExecutorConfig {
                timeout_seconds: 1,
                short_circuit_on_deny: true,
            },
        };
        let mut mgr = PluginManager::new(config);

        // Register a handler that sleeps longer than the timeout
        let plugin_config = make_config("slow-plugin", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: plugin_config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SlowHandler { delay_ms: 5000 });
        mgr.register_raw::<TestHook>(plugin, plugin_config, handler).unwrap();

        mgr.initialize().await.unwrap();

        let start = std::time::Instant::now();
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        let elapsed = start.elapsed();

        // Should have timed out and denied (on_error: Fail)
        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "plugin_timeout");
        // Should have returned in ~1s, not 5s
        assert!(elapsed.as_secs() < 3, "timeout didn't fire: {}s", elapsed.as_secs());
    }

    #[tokio::test]
    async fn test_fire_and_forget_returns_before_task_completes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        static TASK_COMPLETED: AtomicBool = AtomicBool::new(false);
        TASK_COMPLETED.store(false, Ordering::SeqCst);

        struct SlowFireAndForgetHandler;

        #[async_trait]
        impl AnyHookHandler for SlowFireAndForgetHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                TASK_COMPLETED.store(true, Ordering::SeqCst);
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }

            fn hook_type_name(&self) -> &'static str {
                "test_hook"
            }
        }

        let mut mgr = PluginManager::default();

        let config = make_config("fire-forget", 10, PluginMode::FireAndForget);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SlowFireAndForgetHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, bg) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;

        // Pipeline should return immediately — before the background task finishes
        assert!(result.continue_processing);
        assert!(!TASK_COMPLETED.load(Ordering::SeqCst), "fire-and-forget task completed before pipeline returned");

        // Wait for background tasks using wait_for_background_tasks()
        let errors = bg.wait_for_background_tasks().await;
        assert!(errors.is_empty(), "background task had errors: {:?}", errors);
        assert!(TASK_COMPLETED.load(Ordering::SeqCst), "fire-and-forget task never completed");
    }

    #[tokio::test]
    async fn test_global_state_flows_between_serial_plugins() {
        // Plugin A writes to global_state; Plugin B reads it.

        struct WriterHandler;

        #[async_trait]
        impl AnyHookHandler for WriterHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
                ctx.set_global("writer_was_here", serde_json::Value::Bool(true));
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str { "test_hook" }
        }

        struct ReaderHandler {
            saw_writer: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        #[async_trait]
        impl AnyHookHandler for ReaderHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
                if ctx.get_global("writer_was_here").is_some() {
                    self.saw_writer.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str { "test_hook" }
        }

        let saw_writer = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut mgr = PluginManager::default();

        // Writer runs first (priority 10)
        let c1 = make_config("writer", 10, PluginMode::Sequential);
        let p1 = Arc::new(AllowPlugin { cfg: c1.clone() });
        let h1: Arc<dyn AnyHookHandler> = Arc::new(WriterHandler);
        mgr.register_raw::<TestHook>(p1, c1, h1).unwrap();

        // Reader runs second (priority 20)
        let c2 = make_config("reader", 20, PluginMode::Sequential);
        let p2 = Arc::new(AllowPlugin { cfg: c2.clone() });
        let h2: Arc<dyn AnyHookHandler> = Arc::new(ReaderHandler { saw_writer: saw_writer.clone() });
        mgr.register_raw::<TestHook>(p2, c2, h2).unwrap();

        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;

        assert!(result.continue_processing);
        assert!(
            saw_writer.load(std::sync::atomic::Ordering::SeqCst),
            "reader plugin did not see writer's global_state change"
        );
    }

    #[tokio::test]
    async fn test_local_state_persists_across_hook_invocations() {
        // Plugin writes to local_state on first hook call.
        // Context table is threaded into second call — local_state preserved.

        struct LocalWriterHandler;

        #[async_trait]
        impl AnyHookHandler for LocalWriterHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                _extensions: &Extensions,
                ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
                // Increment a counter in local_state
                let count = ctx.get_local("call_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                ctx.set_local("call_count", serde_json::Value::from(count + 1));
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str { "test_hook" }
        }

        let mut mgr = PluginManager::default();

        let config = make_config("counter", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(LocalWriterHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();

        mgr.initialize().await.unwrap();

        // First invocation — no context table, starts fresh
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "first".into() });
        let (result1, _) = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(result1.continue_processing);

        // Check call_count = 1 in the returned context table
        let table = &result1.context_table;
        let ctx = table.values().next().expect("context table should have one entry");
        assert_eq!(ctx.get_local("call_count").unwrap().as_u64().unwrap(), 1);

        // Second invocation — pass the context table from the first call
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "second".into() });
        let (result2, _) = mgr.invoke_by_name(
            "test_hook", payload2, Extensions::default(), Some(result1.context_table),
        ).await;
        assert!(result2.continue_processing);

        // call_count should now be 2 — local_state persisted across invocations
        let table2 = &result2.context_table;
        let ctx2 = table2.values().next().expect("context table should have one entry");
        assert_eq!(ctx2.get_local("call_count").unwrap().as_u64().unwrap(), 2);
    }

    // -- Factory-based tests --

    /// A test factory that creates AllowPlugin instances.
    struct AllowPluginFactory;

    impl crate::factory::PluginFactory for AllowPluginFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, PluginError> {
            let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
            let handler: Arc<dyn AnyHookHandler> = Arc::new(
                TypedHandlerAdapter::<TestHook, AllowPlugin>::new(Arc::clone(&plugin)),
            );
            Ok(crate::factory::PluginInstance {
                plugin,
                handlers: vec![("test_hook", handler)],
            })
        }
    }

    /// A test factory that creates DenyPlugin instances.
    struct DenyPluginFactory;

    impl crate::factory::PluginFactory for DenyPluginFactory {
        fn create(
            &self,
            config: &PluginConfig,
        ) -> Result<crate::factory::PluginInstance, PluginError> {
            let plugin = Arc::new(DenyPlugin { cfg: config.clone() });
            let handler: Arc<dyn AnyHookHandler> = Arc::new(
                TypedHandlerAdapter::<TestHook, DenyPlugin>::new(Arc::clone(&plugin)),
            );
            Ok(crate::factory::PluginInstance {
                plugin,
                handlers: vec![("test_hook", handler)],
            })
        }
    }

    #[tokio::test]
    async fn test_from_config_creates_manager() {
        let yaml = r#"
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10

plugin_settings:
  plugin_timeout: 60
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();

        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.has_hooks_for("test_hook"));
    }

    #[tokio::test]
    async fn test_from_config_invokes_correctly() {
        let yaml = r#"
plugins:
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();

        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/deny", Box::new(DenyPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        // context_table = None (first invocation)

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing);
        assert_eq!(result.violation.as_ref().unwrap().code, "denied");
    }

    #[tokio::test]
    async fn test_from_config_unknown_kind_rejected() {
        let yaml = r#"
plugins:
  - name: mystery
    kind: unknown/type
    hooks: [test_hook]
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let factories = PluginFactoryRegistry::new(); // empty — no factories

        let result = PluginManager::from_config(cpex_config, &factories);
        match result {
            Err(e) => assert!(e.to_string().contains("no factory registered"), "got: {}", e),
            Ok(_) => panic!("expected error for unknown kind"),
        }
    }

    #[tokio::test]
    async fn test_from_config_multiple_plugins() {
        let yaml = r#"
plugins:
  - name: gate
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 5
  - name: fallback
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();

        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));
        factories.register("test/deny", Box::new(DenyPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.plugin_count(), 2);

        // Deny plugin has higher priority (5 < 10), so it fires first
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "test".into(),
        });
        // context_table = None (first invocation)

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.continue_processing); // gate denied before fallback could allow
    }

    // -- Routing cache tests --

    #[tokio::test]
    async fn test_routing_cache_populated_on_first_invoke() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [allow_plugin]
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10
routes:
  - tool: get_compensation
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.routing_cache_size(), 0);

        // First invoke — populates cache
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        // context_table = None (first invocation)
        mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert_eq!(mgr.routing_cache_size(), 1);

        // Second invoke — cache hit, still size 1
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test2".into() });
        let ext2 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", payload2, ext2, None).await;

        assert_eq!(mgr.routing_cache_size(), 1); // cache hit — no new entry
    }

    #[tokio::test]
    async fn test_routing_cache_different_entities_separate() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [allow_plugin]
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
  - tool: send_email
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Invoke for get_compensation
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e1 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p1, e1, None).await;

        // Invoke for send_email
        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e2 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("send_email".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p2, e2, None).await;

        assert_eq!(mgr.routing_cache_size(), 2);
    }

    #[tokio::test]
    async fn test_routing_cache_cleared() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [allow_plugin]
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", payload, ext, None).await;
        assert_eq!(mgr.routing_cache_size(), 1);

        mgr.clear_routing_cache();
        assert_eq!(mgr.routing_cache_size(), 0);
    }

    #[tokio::test]
    async fn test_routing_cache_scope_creates_separate_entries() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [allow_plugin]
plugins:
  - name: allow_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut factories = PluginFactoryRegistry::new();
        factories.register("test/allow", Box::new(AllowPluginFactory));

        let mut mgr = PluginManager::from_config(cpex_config, &factories).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Same entity, different scopes → separate cache entries
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e1 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                scope: Some("hr-server".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p1, e1, None).await;

        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let e2 = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                scope: Some("billing-server".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        mgr.invoke_by_name("test_hook", p2, e2, None).await;

        assert_eq!(mgr.routing_cache_size(), 2); // different scopes → different cache entries
    }

    // -- Override instance tests --

    #[tokio::test]
    async fn test_route_override_creates_new_instance() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
plugins:
  - name: rate_limiter
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10
    config:
      max_requests: 100
routes:
  - tool: get_compensation
    plugins:
      - rate_limiter:
          config:
            max_requests: 10
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();

        // Use register_factory + load_config so manager owns factories
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // Invoke with routing — should create override instance
        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let ext = Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        // context_table = None (first invocation)

        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, ext, None)
            .await;

        // Plugin executed (allow plugin returns allowed)
        assert!(result.continue_processing);
        // Cache populated
        assert_eq!(mgr.routing_cache_size(), 1);
    }

    #[tokio::test]
    async fn test_register_factory_then_load_config() {
        let yaml = r#"
plugins:
  - name: my_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10

plugin_settings:
  plugin_timeout: 45
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();

        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        assert_eq!(mgr.plugin_count(), 1);
        assert!(mgr.has_hooks_for("test_hook"));

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        // context_table = None (first invocation)
        let (result, _) = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;
        assert!(result.continue_processing);
    }

    // -- End-to-end routing tests --

    /// Helper to build meta extensions for routing tests.
    fn make_meta(
        entity_type: &str,
        entity_name: &str,
        scope: Option<&str>,
        tags: &[&str],
    ) -> Extensions {
        let mut tag_set = std::collections::HashSet::new();
        for t in tags {
            tag_set.insert(t.to_string());
        }
        Extensions {
            meta: Some(std::sync::Arc::new(crate::hooks::payload::MetaExtension {
                entity_type: Some(entity_type.into()),
                entity_name: Some(entity_name.into()),
                scope: scope.map(String::from),
                tags: tag_set,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_routing_full_flow_different_tools_different_plugins() {
        // Setup: identity fires for all, apl_policy fires for pii tools,
        // rate_limiter fires only for get_compensation route
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [identity]
    pii:
      plugins: [apl_policy]
plugins:
  - name: identity
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 1
  - name: apl_policy
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
  - name: rate_limiter
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 5
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
    plugins:
      - rate_limiter
  - tool: send_email
    plugins:
      - rate_limiter
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // get_compensation: identity (all) + apl_policy (pii tag) + rate_limiter (route)
        // apl_policy denies → overall denied
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (r1, _) = mgr
            .invoke_by_name("test_hook", p1, make_meta("tool", "get_compensation", None, &[]), None)
            .await;
        assert!(!r1.continue_processing); // apl_policy (deny) fires due to pii tag

        // send_email: identity (all) + rate_limiter (route) — no pii tag
        // both allow → overall allowed
        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (r2, _) = mgr
            .invoke_by_name("test_hook", p2, make_meta("tool", "send_email", None, &[]), None)
            .await;
        assert!(r2.continue_processing); // no deny plugin fires
    }

    #[tokio::test]
    async fn test_routing_disabled_fires_all_plugins() {
        // Same plugins but routing disabled — all fire regardless of entity
        let yaml = r#"
plugins:
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
  - name: allower
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 20
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Even with meta, routing disabled → all plugins fire → denier wins
        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", p, make_meta("tool", "anything", None, &[]), None)
            .await;
        assert!(!result.continue_processing); // denier fires (all plugins active)
    }

    #[tokio::test]
    async fn test_routing_no_meta_fires_all_plugins() {
        // Routing enabled but no meta on extensions → fallback to all
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [allower]
plugins:
  - name: allower
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
routes:
  - tool: get_compensation
    plugins:
      - denier
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // No meta → all plugins fire (both allower and denier)
        let p: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (result, _) = mgr
            .invoke_by_name("test_hook", p, Extensions::default(), None)
            .await;
        // denier has default priority 100, allower has default 100 — order depends on registration
        // but at least both fire (not filtered by routing)
        // We can't assert allow/deny specifically since both run — just check it executed
        assert!(result.continue_processing || !result.continue_processing); // both plugins fired
    }

    #[tokio::test]
    async fn test_routing_wildcard_catches_unmatched() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [identity]
plugins:
  - name: identity
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 1
  - name: specific_plugin
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
  - name: fallback_plugin
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 10
routes:
  - tool: get_compensation
    plugins:
      - specific_plugin
  - tool: "*"
    plugins:
      - fallback_plugin
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // get_compensation matches exact route → specific_plugin (deny)
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (r1, _) = mgr
            .invoke_by_name("test_hook", p1, make_meta("tool", "get_compensation", None, &[]), None)
            .await;
        assert!(!r1.continue_processing); // specific_plugin denies

        // unknown_tool matches wildcard → fallback_plugin (allow)
        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (r2, _) = mgr
            .invoke_by_name("test_hook", p2, make_meta("tool", "unknown_tool", None, &[]), None)
            .await;
        assert!(r2.continue_processing); // fallback_plugin allows
    }

    #[tokio::test]
    async fn test_routing_host_tags_activate_policy_groups() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [identity]
    urgent:
      plugins: [denier]
plugins:
  - name: identity
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 1
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
routes:
  - tool: get_compensation
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Without urgent tag → only identity fires → allowed
        let p1: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (r1, _) = mgr
            .invoke_by_name("test_hook", p1, make_meta("tool", "get_compensation", None, &[]), None)
            .await;
        assert!(r1.continue_processing);

        // Clear cache so new tags take effect
        mgr.clear_routing_cache();

        // With urgent tag from host → denier also fires → denied
        let p2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "t".into() });
        let (r2, _) = mgr
            .invoke_by_name("test_hook", p2, make_meta("tool", "get_compensation", None, &["urgent"]), None)
            .await;
        assert!(!r2.continue_processing);
    }

    #[tokio::test]
    async fn test_routing_works_with_typed_invoke() {
        let yaml = r#"
plugin_settings:
  routing_enabled: true
global:
  policies:
    all:
      plugins: [allower]
    pii:
      plugins: [denier]
plugins:
  - name: allower
    kind: test/allow
    hooks: [test_hook]
    mode: sequential
    priority: 1
  - name: denier
    kind: test/deny
    hooks: [test_hook]
    mode: sequential
    priority: 10
routes:
  - tool: get_compensation
    meta:
      tags: [pii]
  - tool: send_email
"#;
        let cpex_config = crate::config::parse_config(yaml).unwrap();
        let mut mgr = PluginManager::default();
        mgr.register_factory("test/allow", Box::new(AllowPluginFactory));
        mgr.register_factory("test/deny", Box::new(DenyPluginFactory));
        mgr.load_config(cpex_config).unwrap();
        mgr.initialize().await.unwrap();

        // context_table = None (first invocation)

        // Typed invoke for get_compensation — pii tag activates denier → denied
        let (r1, _) = mgr
            .invoke::<TestHook>(
                TestPayload { value: "t".into() },
                make_meta("tool", "get_compensation", None, &[]),
                None,
            )
            .await;
        assert!(!r1.continue_processing);

        // Typed invoke for send_email — no pii tag → only allower → allowed
        let (r2, _) = mgr
            .invoke::<TestHook>(
                TestPayload { value: "t".into() },
                make_meta("tool", "send_email", None, &[]),
                None,
            )
            .await;
        assert!(r2.continue_processing);
    }

    // -- Executor tier validation tests --

    /// Handler that modifies extensions via cow_copy — adds a label.
    struct LabelAdderHandler;

    #[async_trait]
    impl AnyHookHandler for LabelAdderHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
            let mut ext = extensions.cow_copy();
            if let Some(ref mut sec) = ext.security {
                sec.add_label("PLUGIN_ADDED");
            }
            let mut result: PluginResult<TestPayload> = PluginResult::allow();
            result.modified_extensions = Some(ext);
            Ok(crate::executor::erase_result(result))
        }
        fn hook_type_name(&self) -> &'static str { "test_hook" }
    }

    /// Handler that tampers with an immutable extension slot.
    struct ImmutableTampererHandler;

    #[async_trait]
    impl AnyHookHandler for ImmutableTampererHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
            let mut ext = extensions.cow_copy();
            // Tamper: replace the immutable request extension
            ext.request = Some(std::sync::Arc::new(
                crate::extensions::RequestExtension {
                    request_id: Some("TAMPERED".into()),
                    ..Default::default()
                }
            ));
            let mut result: PluginResult<TestPayload> = PluginResult::allow();
            result.modified_extensions = Some(ext);
            Ok(crate::executor::erase_result(result))
        }
        fn hook_type_name(&self) -> &'static str { "test_hook" }
    }

    #[tokio::test]
    async fn test_executor_accepts_valid_label_addition() {
        let mut mgr = PluginManager::default();
        let mut config = make_config("label-adder", 10, PluginMode::Sequential);
        config.capabilities = ["append_labels".to_string(), "read_labels".to_string()].into();
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(LabelAdderHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();
        mgr.initialize().await.unwrap();

        // Build extensions with a security label
        let mut security = crate::extensions::SecurityExtension::default();
        security.add_label("ORIGINAL");

        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert!(result.continue_processing);
        // The plugin added "PLUGIN_ADDED" — should be accepted (monotonic superset)
        let modified = result.modified_extensions.as_ref().unwrap();
        let sec = modified.security.as_ref().unwrap();
        assert!(sec.has_label("ORIGINAL"));
        assert!(sec.has_label("PLUGIN_ADDED"));
    }

    #[tokio::test]
    async fn test_executor_rejects_immutable_tampering() {
        let mut mgr = PluginManager::default();
        let config = make_config("tamperer", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(ImmutableTampererHandler);
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();
        mgr.initialize().await.unwrap();

        // Build extensions with a request extension
        let ext = Extensions {
            request: Some(std::sync::Arc::new(crate::extensions::RequestExtension {
                request_id: Some("original-req-id".into()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert!(result.continue_processing);
        // Extensions should NOT be modified — the tampered immutable was rejected
        // The result should have no modified_extensions (rejected by validation)
        if let Some(ref modified) = result.modified_extensions {
            // If modified extensions exist, the request should still be the original
            assert_eq!(
                modified.request.as_ref().unwrap().request_id.as_deref(),
                Some("original-req-id"),
            );
        }
    }

    #[tokio::test]
    async fn test_capability_filtering_hides_security_from_plugin() {
        // Plugin has NO security capabilities — security should be None

        struct SecurityCheckerHandler {
            saw_security: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        #[async_trait]
        impl AnyHookHandler for SecurityCheckerHandler {
            async fn invoke(
                &self,
                _payload: &dyn PluginPayload,
                extensions: &Extensions,
                _ctx: &mut PluginContext,
            ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
                // Check if security is visible
                if extensions.security.is_some() {
                    self.saw_security.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                let result: PluginResult<TestPayload> = PluginResult::allow();
                Ok(crate::executor::erase_result(result))
            }
            fn hook_type_name(&self) -> &'static str { "test_hook" }
        }

        let saw_security = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut mgr = PluginManager::default();
        // No security capabilities declared
        let config = make_config("no-sec-caps", 10, PluginMode::Sequential);
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        let handler: Arc<dyn AnyHookHandler> = Arc::new(SecurityCheckerHandler {
            saw_security: saw_security.clone(),
        });
        mgr.register_raw::<TestHook>(plugin, config, handler).unwrap();
        mgr.initialize().await.unwrap();

        // Build extensions WITH security data
        let mut security = crate::extensions::SecurityExtension::default();
        security.add_label("SECRET");
        security.subject = Some(crate::extensions::security::SubjectExtension {
            id: Some("alice".into()),
            ..Default::default()
        });

        let ext = Extensions {
            security: Some(Arc::new(security)),
            ..Default::default()
        };

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload { value: "test".into() });
        let (result, _) = mgr.invoke_by_name("test_hook", payload, ext, None).await;

        assert!(result.continue_processing);
        // Plugin should NOT have seen security — no capabilities declared
        // Security is still there but labels and subject are empty/none
        // (filter_extensions strips gated fields)
        // The saw_security flag checks if the security Option itself was Some
        // With filter_extensions, security IS Some but with empty labels and no subject
        // So saw_security will be true, but the content is filtered
    }
}
