use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

use anyhow::{Context, Result};
use serde::Serialize;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpHooks, default_send_request};
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;

use crate::policy_loader::{build_wasi_context, SandboxConfig};

wasmtime::component::bindgen!({
    path: "wit",
    world: "plugin",
    exports: { default: async },
});

pub mod types {
    pub use super::cpex::plugin::types::*;
}

#[derive(Debug, Default)]
pub struct PluginMetrics {
    pub total_invocations: AtomicU64,
    pub total_fuel_consumed: AtomicU64,
    pub total_traps: AtomicU64,
    pub network_denials: AtomicU64,
    pub network_allowed: AtomicU64,
    pub last_fuel_consumed: AtomicU64,
}

impl PluginMetrics {
    pub fn snapshot(&self) -> PluginMetricsSnapshot {
        PluginMetricsSnapshot {
            total_invocations: self.total_invocations.load(Ordering::Relaxed),
            total_fuel_consumed: self.total_fuel_consumed.load(Ordering::Relaxed),
            total_traps: self.total_traps.load(Ordering::Relaxed),
            network_denials: self.network_denials.load(Ordering::Relaxed),
            network_allowed: self.network_allowed.load(Ordering::Relaxed),
            last_fuel_consumed: self.last_fuel_consumed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginMetricsSnapshot {
    pub total_invocations: u64,
    pub total_fuel_consumed: u64,
    pub total_traps: u64,
    pub network_denials: u64,
    pub network_allowed: u64,
    pub last_fuel_consumed: u64,
}

struct MeteredHttpHooks {
    allowed_hosts: Arc<Vec<String>>,
    metrics: Arc<PluginMetrics>,
}

impl WasiHttpHooks for MeteredHttpHooks {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        let authority = request
            .uri()
            .authority()
            .map(|a| a.host().to_string())
            .unwrap_or_default();

        let is_allowed = self.allowed_hosts.iter().any(|allowed| {
            authority == *allowed || authority.ends_with(&format!(".{}", allowed))
        });

        if !is_allowed {
            self.metrics.network_denials.fetch_add(1, Ordering::Relaxed);
            return Err(ErrorCode::HttpRequestDenied.into());
        }

        self.metrics.network_allowed.fetch_add(1, Ordering::Relaxed);
        Ok(default_send_request(request, config))
    }
}

struct PluginState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: MeteredHttpHooks,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for PluginState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for PluginState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

struct PluginInstance {
    store: Store<PluginState>,
    plugin: Plugin,
    fuel_budget: u64,
    epoch_deadline: u64,
    wasm_path: std::path::PathBuf,
    metrics: Arc<PluginMetrics>,
}

pub struct SandboxManager {
    engine: Engine,
    linker: Linker<PluginState>,
    plugins: HashMap<String, PluginInstance>,
}

impl SandboxManager {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

        // Start epoch ticker thread for timeout enforcement
        let engine_clone = engine.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
            engine_clone.increment_epoch();
        });

        Ok(Self {
            engine,
            linker,
            plugins: HashMap::new(),
        })
    }

    pub async fn load_plugin(
        &mut self,
        name: &str,
        wasm_path: &Path,
        sandbox_config: SandboxConfig,
    ) -> Result<()> {
        let ctx = build_wasi_context(&sandbox_config)?;
        let resources = &sandbox_config.resources;

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

        let component = Component::from_file(&self.engine, wasm_path)
            .map_err(|e| anyhow::anyhow!("failed to load wasm from {}: {}", wasm_path.display(), e))?;

        let metrics = Arc::new(PluginMetrics::default());

        let mut store = Store::new(
            &self.engine,
            PluginState {
                wasi: ctx.wasi_ctx,
                http: ctx.http_ctx,
                hooks: MeteredHttpHooks {
                    allowed_hosts: ctx.allowed_hosts,
                    metrics: metrics.clone(),
                },
                table: ResourceTable::new(),
                limits,
            },
        );

        // Apply memory/table limits
        store.limiter(|state| &mut state.limits);

        // Apply fuel budget (instruction count limit)
        let fuel = resources.max_fuel.unwrap_or(u64::MAX);
        store.set_fuel(fuel)
            .map_err(|e| anyhow::anyhow!("failed to set fuel: {}", e))?;

        // Apply execution timeout via epoch deadline
        // Each epoch tick is ~1ms (from ticker thread), so ms ≈ ticks
        // Use a very large default (1 hour) to avoid overflow
        let epoch_deadline = resources.max_execution_time_ms.unwrap_or(3_600_000);
        store.set_epoch_deadline(epoch_deadline);
        store.epoch_deadline_trap();

        let plugin = Plugin::instantiate_async(&mut store, &component, &self.linker)
            .await
            .map_err(|e| anyhow::anyhow!("failed to instantiate plugin '{}': {}", name, e))?;

        self.plugins.insert(
            name.to_string(),
            PluginInstance {
                store,
                plugin,
                fuel_budget: fuel,
                epoch_deadline,
                wasm_path: wasm_path.to_path_buf(),
                metrics,
            },
        );

        Ok(())
    }

    pub async fn invoke(
        &mut self,
        plugin_name: &str,
        payload: types::MessagePayload,
        extensions: types::Extensions,
        ctx: types::PluginContext,
    ) -> Result<types::PluginResult> {
        let instance = self
            .plugins
            .get_mut(plugin_name)
            .with_context(|| format!("plugin '{}' not loaded", plugin_name))?;

        // Reset fuel and epoch deadline for each invocation
        let _ = instance.store.set_fuel(instance.fuel_budget);
        instance.store.set_epoch_deadline(instance.epoch_deadline);

        instance.metrics.total_invocations.fetch_add(1, Ordering::Relaxed);

        let fuel_before = instance.store.get_fuel().unwrap_or(0);

        let result = instance
            .plugin
            .call_handle_hook(&mut instance.store, &payload, &extensions, &ctx)
            .await;

        let fuel_after = instance.store.get_fuel().unwrap_or(0);
        let fuel_used = fuel_before.saturating_sub(fuel_after);
        instance.metrics.total_fuel_consumed.fetch_add(fuel_used, Ordering::Relaxed);
        instance.metrics.last_fuel_consumed.store(fuel_used, Ordering::Relaxed);

        match result {
            Ok(r) => Ok(r),
            Err(e) => {
                instance.metrics.total_traps.fetch_add(1, Ordering::Relaxed);
                Err(anyhow::anyhow!("failed to invoke handle_hook on '{}': {}", plugin_name, e))
            }
        }
    }

    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        self.plugins
            .remove(name)
            .with_context(|| format!("plugin '{}' not loaded", name))?;
        Ok(())
    }

    /// Reload a plugin with a new sandbox policy.
    /// Destroys the old instance and creates a fresh one with the updated config.
    pub async fn reload_plugin(
        &mut self,
        name: &str,
        new_config: SandboxConfig,
    ) -> Result<()> {
        let wasm_path = self
            .plugins
            .get(name)
            .map(|inst| inst.wasm_path.clone())
            .with_context(|| format!("plugin '{}' not loaded, cannot reload", name))?;

        self.plugins.remove(name);
        self.load_plugin(name, &wasm_path, new_config).await
    }

    /// Reload all plugins from a config file.
    /// Any plugin whose config differs from current will be restarted.
    pub async fn reload_from_config(
        &mut self,
        config_path: &Path,
        wasm_dir: &Path,
    ) -> Result<()> {
        let raw = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config from {}", config_path.display()))?;
        let config: crate::policy_loader::ConfigFile = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse config from {}", config_path.display()))?;

        let new_plugin_names: Vec<String> =
            config.plugins.iter().map(|p| p.name.clone()).collect();

        // Remove plugins that are no longer in config
        let current_names: Vec<String> = self.plugins.keys().cloned().collect();
        for name in &current_names {
            if !new_plugin_names.contains(name) {
                self.plugins.remove(name);
            }
        }

        // Load or reload plugins from config
        for plugin_cfg in config.plugins {
            let wasm_path = wasm_dir.join(format!("{}.wasm", plugin_cfg.name));
            if !wasm_path.exists() {
                continue;
            }

            if self.plugins.contains_key(&plugin_cfg.name) {
                self.reload_plugin(&plugin_cfg.name, plugin_cfg.sandbox).await?;
            } else {
                self.load_plugin(&plugin_cfg.name, &wasm_path, plugin_cfg.sandbox).await?;
            }
        }

        Ok(())
    }

    pub fn list_plugins(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }

    pub fn metrics(&self, plugin_name: &str) -> Option<PluginMetricsSnapshot> {
        self.plugins.get(plugin_name).map(|inst| inst.metrics.snapshot())
    }

    pub fn all_metrics(&self) -> HashMap<String, PluginMetricsSnapshot> {
        self.plugins
            .iter()
            .map(|(name, inst)| (name.clone(), inst.metrics.snapshot()))
            .collect()
    }

    pub async fn load_from_config(
        &mut self,
        config_path: &Path,
        wasm_dir: &Path,
    ) -> Result<()> {
        let raw = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config from {}", config_path.display()))?;
        let config: crate::policy_loader::ConfigFile = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse config from {}", config_path.display()))?;

        for plugin_cfg in config.plugins {
            let wasm_path = wasm_dir.join(format!("{}.wasm", plugin_cfg.name));
            if wasm_path.exists() {
                self.load_plugin(&plugin_cfg.name, &wasm_path, plugin_cfg.sandbox)
                    .await
                    .with_context(|| format!("failed to load plugin '{}'", plugin_cfg.name))?;
            }
        }

        Ok(())
    }
}
