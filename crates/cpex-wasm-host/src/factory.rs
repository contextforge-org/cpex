// Location: ./crates/cpex-wasm-host/src/factory.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// WasmPluginFactory — bridges cpex-core's PluginFactory trait to the
// SandboxManager. Implements PluginFactory so WASM plugins can be
// registered with the PluginManager and participate in the hook pipeline.
// Each plugin gets its own SandboxManager instance (isolated engine + store).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use cpex_core::cmf::message::MessagePayload;
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::Extensions;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::payload::PluginPayload;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

use crate::conversions::{native_context_to_wit, native_extensions_to_wit, native_payload_to_wit, wit_result_to_native};
use crate::policy_loader::SandboxConfig;
use crate::sandbox_manager::SandboxManager;

// ---------------------------------------------------------------------------
// WasmPluginFactory
// ---------------------------------------------------------------------------

/// Factory that creates WASM plugin instances, each with its own SandboxManager.
/// Every plugin gets an isolated wasmtime engine and store — no contention between plugins.
pub struct WasmPluginFactory {
    wasm_dir: PathBuf,
}

impl WasmPluginFactory {
    pub fn new(wasm_dir: PathBuf) -> Self {
        Self { wasm_dir }
    }
}

impl PluginFactory for WasmPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        // Parse wasm path from kind (e.g., "wasm://plugin.wasm" → "plugin.wasm")
        let wasm_filename = config
            .kind
            .strip_prefix("wasm://")
            .ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': kind '{}' must start with 'wasm://'",
                        config.name, config.kind
                    ),
                })
            })?;

        let wasm_path = self.wasm_dir.join(wasm_filename);

        // Build sandbox config from plugin's config field.
        // Looks for a "sandbox_policy" key in config.config (the opaque JSON value).
        // If absent, deny-by-default applies (no filesystem, no network, no env vars).
        let sandbox_config = config
            .config
            .as_ref()
            .and_then(|v| v.get("sandbox_policy"))
            .and_then(|v| serde_json::from_value::<crate::policy_loader::SandboxPolicy>(v.clone()).ok())
            .map(|policy| SandboxConfig::from_policy(Some(&policy)))
            .unwrap_or_default();

        // Create a new SandboxManager for this plugin (isolated engine + store)
        let sandbox = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut mgr = SandboxManager::new()
                    .map_err(|e| format!("failed to create sandbox: {}", e))?;
                mgr.load_wasmplugin(&wasm_path, sandbox_config)
                    .await
                    .map_err(|e| format!("failed to load WASM: {}", e))?;
                Ok::<_, String>(mgr)
            })
        })
        .map_err(|e| {
            Box::new(PluginError::Config {
                message: format!("plugin '{}': {}", config.name, e),
            })
        })?;

        let sandbox = Arc::new(Mutex::new(sandbox));

        let plugin: Arc<dyn Plugin> = Arc::new(WasmBridgePlugin {
            config: config.clone(),
        });

        let handler: Arc<dyn AnyHookHandler> = Arc::new(WasmBridgeHandler {
            plugin_name: config.name.clone(),
            sandbox,
        });

        // Register handler for each hook the plugin declares
        let hooks: Vec<(&'static str, Arc<dyn AnyHookHandler>)> = config
            .hooks
            .iter()
            .map(|hook_name| {
                let leaked: &'static str = Box::leak(hook_name.clone().into_boxed_str());
                (leaked, handler.clone())
            })
            .collect();

        Ok(PluginInstance {
            plugin,
            handlers: hooks,
        })
    }
}

// ---------------------------------------------------------------------------
// WasmBridgePlugin — lifecycle wrapper
// ---------------------------------------------------------------------------

/// Implements the Plugin trait for WASM plugins. Handles lifecycle.
struct WasmBridgePlugin {
    config: PluginConfig,
}

#[async_trait]
impl Plugin for WasmBridgePlugin {
    fn config(&self) -> &PluginConfig {
        &self.config
    }

    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WasmBridgeHandler — hook dispatch through the WASM sandbox
// ---------------------------------------------------------------------------

/// Implements AnyHookHandler by converting native types to WIT,
/// invoking the WASM sandbox, and converting the result back.
/// Each handler owns its own SandboxManager — no contention with other plugins.
struct WasmBridgeHandler {
    plugin_name: String,
    sandbox: Arc<Mutex<SandboxManager>>,
}

#[async_trait]
impl AnyHookHandler for WasmBridgeHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        // Downcast the type-erased payload to MessagePayload
        let native_payload = payload
            .as_any()
            .downcast_ref::<MessagePayload>()
            .ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': payload type mismatch, expected MessagePayload",
                        self.plugin_name
                    ),
                })
            })?;

        // Convert native types → WIT types
        let wit_payload = native_payload_to_wit(native_payload);
        let wit_extensions = native_extensions_to_wit(extensions);
        let wit_ctx = native_context_to_wit(ctx);

        // Invoke the WASM plugin through its dedicated sandbox
        let wit_result = {
            let mut mgr = self.sandbox.lock().await;
            mgr.invoke(wit_payload, wit_extensions, wit_ctx)
                .await
                .map_err(|e| {
                    Box::new(PluginError::Config {
                        message: format!(
                            "plugin '{}': WASM invocation failed: {}",
                            self.plugin_name, e
                        ),
                    })
                })?
        };

        // Convert WIT result → native PluginResult, then erase for the executor
        let native_result = wit_result_to_native(wit_result);
        Ok(cpex_core::executor::erase_result(native_result))
    }

    fn hook_type_name(&self) -> &'static str {
        "cmf"
    }
}
