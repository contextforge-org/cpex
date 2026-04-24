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

use std::sync::Arc;

use tracing::{error, info};

use crate::context::PluginContextTable;
use crate::error::PluginError;
use crate::executor::{Executor, ExecutorConfig, PipelineResult};
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
pub struct PluginManager {
    /// Plugin registry — stores PluginRefs and hook-to-handler mappings.
    registry: PluginRegistry,

    /// Executor — stateless 5-phase pipeline engine.
    executor: Executor,

    /// Whether initialize() has been called.
    initialized: bool,
}

impl PluginManager {
    /// Create a new PluginManager with the given configuration.
    pub fn new(config: ManagerConfig) -> Self {
        Self {
            registry: PluginRegistry::new(),
            executor: Executor::new(config.executor),
            initialized: false,
        }
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
    /// A `PipelineResult` with the final payload, extensions, violation,
    /// and the updated context table.
    pub async fn invoke_by_name(
        &self,
        hook_name: &str,
        payload: Box<dyn PluginPayload>,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> PipelineResult {
        let hook_type = HookType::new(hook_name);
        let entries = self.registry.entries_for_hook(&hook_type);

        if entries.is_empty() {
            return PipelineResult::allowed_with(
                payload,
                extensions,
                context_table.unwrap_or_default(),
            );
        }

        self.executor
            .execute(entries, payload, extensions, context_table)
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
    /// # Type Parameters
    ///
    /// - `H` — the hook type (implements `HookTypeDef`).
    ///
    /// # Arguments
    ///
    /// * `payload` — the typed payload.
    /// * `extensions` — the full extensions.
    /// * `context_table` — optional context table from a previous hook.
    ///
    /// # Returns
    ///
    /// A `PipelineResult` with the final payload (type-erased —
    /// caller downcasts via `as_any()`), extensions, violation, and
    /// the updated context table.
    pub async fn invoke<H: HookTypeDef>(
        &self,
        payload: H::Payload,
        extensions: Extensions,
        context_table: Option<PluginContextTable>,
    ) -> PipelineResult {
        let hook_type = HookType::new(H::NAME);
        let entries = self.registry.entries_for_hook(&hook_type);

        if entries.is_empty() {
            let boxed: Box<dyn PluginPayload> = Box::new(payload);
            return PipelineResult::allowed_with(
                boxed,
                extensions,
                context_table.unwrap_or_default(),
            );
        }

        let boxed: Box<dyn PluginPayload> = Box::new(payload);
        self.executor
            .execute(entries, boxed, extensions, context_table)
            .await
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
    use crate::hooks::payload::FilteredExtensions;
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
            _extensions: &FilteredExtensions,
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
            _extensions: &FilteredExtensions,
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
            _extensions: &FilteredExtensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, PluginError> {
            Err(PluginError::Execution {
                plugin_name: "error-plugin".into(),
                message: "simulated failure".into(),
                source: None,
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


        let result = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.allowed);
        assert!(result.payload.is_some());
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


        let result = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(result.allowed);
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


        let result = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        assert!(!result.allowed);
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


        let result = mgr
            .invoke::<TestHook>(payload, Extensions::default(), None)
            .await;

        assert!(result.allowed);
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


        let result = mgr
            .invoke_by_name("test_hook", payload, Extensions::default(), None)
            .await;

        // Audit mode — deny is suppressed, pipeline continues
        assert!(result.allowed);
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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(result.allowed);

        // Verify the plugin is now disabled
        let plugin_ref = mgr.get_plugin("flaky-plugin").unwrap();
        assert!(plugin_ref.is_disabled());
        assert_eq!(plugin_ref.mode(), PluginMode::Disabled);

        // Second invocation — flaky plugin should be skipped entirely
        // (group_by_mode filters it out). Only allow-plugin runs.
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "second".into() });
        let result2 = mgr.invoke_by_name("test_hook", payload2, Extensions::default(), None).await;
        assert!(result2.allowed);
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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(result.allowed);

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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(!result.allowed);
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
            _extensions: &FilteredExtensions,
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
            _extensions: &FilteredExtensions,
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

        let result = mgr.invoke::<TestHook>(payload, Extensions::default(), None).await;

        assert!(result.allowed);
        let final_payload = result.payload.unwrap();
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
                _extensions: &FilteredExtensions,
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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        let elapsed = start.elapsed();

        assert!(result.allowed);
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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        let elapsed = start.elapsed();

        // Should have timed out and denied (on_error: Fail)
        assert!(!result.allowed);
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
                _extensions: &FilteredExtensions,
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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;

        // Pipeline should return immediately — before the background task finishes
        assert!(result.allowed);
        assert!(!TASK_COMPLETED.load(Ordering::SeqCst), "fire-and-forget task completed before pipeline returned");

        // Wait for the background task to finish
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
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
                _extensions: &FilteredExtensions,
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
                _extensions: &FilteredExtensions,
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
        let result = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;

        assert!(result.allowed);
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
                _extensions: &FilteredExtensions,
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
        let result1 = mgr.invoke_by_name("test_hook", payload, Extensions::default(), None).await;
        assert!(result1.allowed);

        // Check call_count = 1 in the returned context table
        let table = &result1.context_table;
        let ctx = table.values().next().expect("context table should have one entry");
        assert_eq!(ctx.get_local("call_count").unwrap().as_u64().unwrap(), 1);

        // Second invocation — pass the context table from the first call
        let payload2: Box<dyn PluginPayload> = Box::new(TestPayload { value: "second".into() });
        let result2 = mgr.invoke_by_name(
            "test_hook", payload2, Extensions::default(), Some(result1.context_table),
        ).await;
        assert!(result2.allowed);

        // call_count should now be 2 — local_state persisted across invocations
        let table2 = &result2.context_table;
        let ctx2 = table2.values().next().expect("context table should have one entry");
        assert_eq!(ctx2.get_local("call_count").unwrap().as_u64().unwrap(), 2);
    }
}
