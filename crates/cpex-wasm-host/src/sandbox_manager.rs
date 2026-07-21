// Location: ./crates/cpex-wasm-host/src/sandbox_manager.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// SandboxManager — loads and invokes a single WASM plugin in a wasmtime sandbox.
// Enforces resource limits (fuel, memory, execution time) and network policy.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::p2::{default_send_request, HttpResult, WasiHttpHooks};
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

use crate::policy_loader::{build_wasi_context, ResourceLimits, SandboxPolicy};

// Generate Rust bindings from the WIT interface definition.
// This creates the `Plugin` struct with `call_handle_hook` and the WIT types.
wasmtime::component::bindgen!({
    path: "wit",
    world: "plugin",
    exports: { default: async },
});

/// Re-export WIT-generated types for use by the factory and conversions modules.
pub mod types {
    pub use super::cpex::plugin::types::*;
}

/// Intercepts outbound HTTP requests from the WASM plugin and enforces the network allow-list.
/// Only requests to explicitly allowed hosts (or their subdomains) are permitted.
struct NetworkPolicy {
    allowed_hosts: Arc<Vec<String>>,
}

impl WasiHttpHooks for NetworkPolicy {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        // Extract the target host from the request URI
        let authority = request
            .uri()
            .authority()
            .map(|a| a.host().to_string())
            .unwrap_or_default();

        // Check exact match or subdomain match (e.g., "api.example.com" matches "example.com")
        let is_allowed = self
            .allowed_hosts
            .iter()
            .any(|allowed| authority == *allowed || authority.ends_with(&format!(".{}", allowed)));

        if !is_allowed {
            return Err(ErrorCode::HttpRequestDenied.into());
        }

        Ok(default_send_request(request, config))
    }
}

/// Per-plugin state held in the wasmtime Store.
/// Contains WASI context, HTTP context, network policy, resource table, and store limits.
struct WasmPluginState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    network: NetworkPolicy,
    table: ResourceTable,
    limits: StoreLimits,
    plugin_name: String,
}

impl cpex::plugin::host_logging::Host for WasmPluginState {
    fn log(&mut self, level: cpex::plugin::host_logging::LogLevel, message: String) {
        use cpex::plugin::host_logging::LogLevel;
        match level {
            LogLevel::Trace => tracing::trace!(plugin = %self.plugin_name, "{}", message),
            LogLevel::Debug => tracing::debug!(plugin = %self.plugin_name, "{}", message),
            LogLevel::Info => tracing::info!(plugin = %self.plugin_name, "{}", message),
            LogLevel::Warn => tracing::warn!(plugin = %self.plugin_name, "{}", message),
            LogLevel::Error => tracing::error!(plugin = %self.plugin_name, "{}", message),
        }
    }
}

impl WasiView for WasmPluginState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for WasmPluginState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.network,
        }
    }
}

/// A loaded and instantiated WASM plugin, ready for invocation.
struct WasmPluginInstance {
    store: Store<WasmPluginState>,
    plugin: Plugin,
    /// Epoch ticks before the store traps (used to reset timeout per invocation)
    epoch_deadline: u64,
    /// Fuel budget per invocation (reset at the start of each call)
    fuel_per_invocation: u64,
}

/// Manages a single WASM plugin in a sandboxed wasmtime environment.
/// Enforces resource limits (fuel, memory, execution time) and network policy.
pub struct SandboxManager {
    engine: Engine,
    linker: Linker<WasmPluginState>,
    instance: Option<WasmPluginInstance>,
}

/// A shared engine + linker + epoch ticker that multiple `SandboxManager` instances
/// can use. Create one per factory, not one per plugin.
pub struct SharedEngine {
    engine: Engine,
    linker: Linker<WasmPluginState>,
}

impl SharedEngine {
    /// Create a shared engine with WASI, HTTP, and host-logging linked.
    /// Spawns a single epoch ticker thread for all plugins using this engine.
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
        cpex::plugin::host_logging::add_to_linker::<
            WasmPluginState,
            wasmtime::component::HasSelf<WasmPluginState>,
        >(&mut linker, |state| state)?;

        let engine_clone = engine.clone();
        #[allow(clippy::disallowed_methods)]
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
            engine_clone.increment_epoch();
        });

        Ok(Self { engine, linker })
    }
}

impl SandboxManager {
    /// Create a new SandboxManager with its own engine and epoch ticker.
    /// Prefer `with_shared_engine` when loading multiple plugins.
    pub fn new() -> Result<Self> {
        let shared = SharedEngine::new()?;
        Ok(Self {
            engine: shared.engine,
            linker: shared.linker,
            instance: None,
        })
    }

    /// Create a SandboxManager backed by a shared engine.
    /// All plugins sharing an engine use one epoch ticker thread.
    pub fn with_shared_engine(shared: &SharedEngine) -> Self {
        Self {
            engine: shared.engine.clone(),
            linker: shared.linker.clone(),
            instance: None,
        }
    }

    /// Load a plugin from a WASM file with the given sandbox policy.
    /// Replaces any previously loaded plugin.
    pub async fn load_wasmplugin(
        &mut self,
        wasm_path: &Path,
        sandbox_policy: Option<&SandboxPolicy>,
        plugin_name: &str,
    ) -> Result<()> {
        tracing::debug!(plugin = %plugin_name, path = %wasm_path.display(), "loading WASM plugin");
        let ctx = build_wasi_context(sandbox_policy)?;
        let default_resources = ResourceLimits::default();
        let resources = sandbox_policy
            .map(|p| &p.resources)
            .unwrap_or(&default_resources);

        // Build store limits from resource config
        let mut limits_builder = StoreLimitsBuilder::new();
        if let Some(max_mem) = resources.max_memory_bytes {
            limits_builder = limits_builder.memory_size(max_mem);
        }
        if let Some(max_instances) = resources.max_instances {
            limits_builder = limits_builder.instances(max_instances);
        }
        if let Some(max_tables) = resources.max_tables {
            limits_builder = limits_builder.tables(max_tables);
        }
        let limits = limits_builder.trap_on_grow_failure(true).build();

        let component = Component::from_file(&self.engine, wasm_path).map_err(|e| {
            anyhow::anyhow!("failed to load wasm from {}: {}", wasm_path.display(), e)
        })?;

        let mut store = Store::new(
            &self.engine,
            WasmPluginState {
                wasi: ctx.wasi_ctx,
                http: ctx.http_ctx,
                network: NetworkPolicy {
                    allowed_hosts: ctx.allowed_hosts,
                },
                table: ResourceTable::new(),
                limits,
                plugin_name: plugin_name.to_string(),
            },
        );

        // Apply memory/table limits
        store.limiter(|state| &mut state.limits);

        // Fuel is set per-invocation (reset at the start of each call) to
        // prevent long-lived plugins from silently degrading. The initial
        // budget is set here so the plugin can instantiate.
        let fuel_per_invocation = resources.max_fuel.unwrap_or(u64::MAX);
        store
            .set_fuel(fuel_per_invocation)
            .map_err(|e| anyhow::anyhow!("failed to set fuel: {}", e))?;

        // Apply execution timeout via epoch deadline.
        // Default is 5 seconds — safe for synchronous hooks. Plugins that
        // perform outbound HTTP should set a higher value explicitly.
        let epoch_deadline = resources.max_execution_time_ms.unwrap_or(5_000);
        if resources.max_execution_time_ms.is_none() {
            tracing::warn!(
                plugin = %plugin_name,
                "no explicit max_execution_time_ms configured — using default 5000ms"
            );
        }
        store.set_epoch_deadline(epoch_deadline);
        store.epoch_deadline_trap();

        let plugin = Plugin::instantiate_async(&mut store, &component, &self.linker)
            .await
            .map_err(|e| anyhow::anyhow!("failed to instantiate plugin: {}", e))?;
        tracing::debug!(plugin = %plugin_name, "plugin instantiated");

        self.instance = Some(WasmPluginInstance {
            store,
            plugin,
            epoch_deadline,
            fuel_per_invocation,
        });

        Ok(())
    }

    /// Invoke the loaded plugin's handle-hook function.
    /// Both fuel and epoch deadline are reset per invocation so each call
    /// gets a fresh budget — no silent degradation over time.
    pub async fn invoke(
        &mut self,
        hook_name: &str,
        payload: types::HookPayload,
        extensions: types::Extensions,
        ctx: types::PluginContext,
    ) -> Result<types::HookResult> {
        let instance = self.instance.as_mut().with_context(|| "no plugin loaded")?;

        // Reset fuel per invocation — each call gets a fresh budget
        instance
            .store
            .set_fuel(instance.fuel_per_invocation)
            .map_err(|e| anyhow::anyhow!("failed to reset fuel: {}", e))?;

        // Reset epoch deadline per invocation (timeout is per-call)
        instance.store.set_epoch_deadline(instance.epoch_deadline);

        let result = instance
            .plugin
            .call_handle_hook(&mut instance.store, hook_name, &payload, &extensions, &ctx)
            .await;

        result.map_err(|e| anyhow::anyhow!("plugin invocation failed: {}", e))
    }

    /// Returns whether a plugin is currently loaded.
    pub fn is_loaded(&self) -> bool {
        self.instance.is_some()
    }
}
