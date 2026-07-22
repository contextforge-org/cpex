// Location: ./crates/cpex-wasm-host/src/factory.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// WasmPluginFactory — bridges cpex-core's PluginFactory trait to the
// SandboxManager. Implements PluginFactory so WASM plugins can be
// registered with the PluginManager and participate in the hook pipeline.
// Each plugin gets its own SandboxManager instance (isolated engine + store).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::warn;

use cpex_core::cmf::message::MessagePayload;
use cpex_core::context::PluginContext;
use cpex_core::delegation::DelegationPayload;
use cpex_core::error::PluginError;
use cpex_core::extensions::{Extensions, OwnedExtensions};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::payload::PluginPayload;
use cpex_core::identity::IdentityPayload;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;

use crate::conversions::{
    native_context_to_wit, native_delegation_payload_to_wit, native_extensions_to_wit,
    native_identity_payload_to_wit, native_payload_to_wit, wit_hook_result_to_native_filtered,
};
use crate::payload_registry::PayloadSerializerRegistry;
use crate::sandbox_manager::SandboxManager;

// ---------------------------------------------------------------------------
// WasmPluginFactory
// ---------------------------------------------------------------------------

/// Factory that creates WASM plugin instances using a shared wasmtime engine.
/// All plugins from the same factory share one engine and one epoch ticker thread.
/// Each plugin gets its own Store (isolated memory, fuel, state) — no contention.
pub struct WasmPluginFactory {
    wasm_dir: PathBuf,
    registry: Arc<PayloadSerializerRegistry>,
    shared_engine: Arc<crate::sandbox_manager::SharedEngine>,
}

impl WasmPluginFactory {
    /// Create a factory with a pre-built payload registry and shared engine.
    pub fn new(wasm_dir: PathBuf, registry: Arc<PayloadSerializerRegistry>) -> Self {
        let shared_engine = Arc::new(
            crate::sandbox_manager::SharedEngine::new()
                .expect("failed to create shared wasmtime engine"),
        );
        Self {
            wasm_dir,
            registry,
            shared_engine,
        }
    }

    /// Convenience constructor that pre-registers all built-in payload types:
    /// `MessagePayload` (CMF hooks), `IdentityPayload` (identity_resolve),
    /// and `DelegationPayload` (token_delegate).
    /// Credential fields marked `#[serde(skip)]` on the identity and
    /// delegation payloads never cross the sandbox boundary.
    pub fn with_builtin_payloads(wasm_dir: PathBuf) -> Self {
        let mut registry = PayloadSerializerRegistry::new();
        registry.register::<MessagePayload>();
        registry.register::<cpex_core::identity::IdentityPayload>();
        registry.register::<cpex_core::delegation::DelegationPayload>();
        Self::new(wasm_dir, Arc::new(registry))
    }
}

impl PluginFactory for WasmPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        // Parse wasm path from kind (e.g., "wasm://plugin.wasm" → "plugin.wasm")
        let wasm_filename = config.kind.strip_prefix("wasm://").ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}': kind '{}' must start with 'wasm://'",
                    config.name, config.kind
                ),
            })
        })?;

        let wasm_path = self.wasm_dir.join(wasm_filename);

        // Extract sandbox policy from plugin's config field.
        // If absent, deny-by-default applies (no filesystem, no network, no env vars).
        let sandbox_policy = config
            .config
            .as_ref()
            .and_then(|v| v.get("sandbox_policy"))
            .and_then(|v| {
                serde_json::from_value::<crate::policy_loader::SandboxPolicy>(v.clone()).ok()
            });

        // Create a SandboxManager backed by the shared engine (one epoch thread for all plugins)
        let sandbox = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut mgr = SandboxManager::with_shared_engine(&self.shared_engine);
                mgr.load_wasmplugin(&wasm_path, sandbox_policy.as_ref(), &config.name)
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

        let timeout_ms = sandbox_policy
            .as_ref()
            .and_then(|p| p.resources.max_execution_time_ms)
            .unwrap_or(5_000);

        let plugin: Arc<dyn Plugin> = Arc::new(WasmBridgePlugin {
            config: config.clone(),
        });

        // Register a separate handler per hook so each carries its own hook_name
        let hooks: Vec<(&'static str, Arc<dyn AnyHookHandler>)> = config
            .hooks
            .iter()
            .map(|hook_name| {
                let leaked: &'static str = Box::leak(hook_name.clone().into_boxed_str());
                let handler: Arc<dyn AnyHookHandler> = Arc::new(WasmBridgeHandler {
                    plugin_name: config.name.clone(),
                    hook_name: hook_name.clone(),
                    sandbox: sandbox.clone(),
                    registry: self.registry.clone(),
                    capabilities: config.capabilities.clone(),
                    timeout_ms,
                });
                (leaked, handler)
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
    hook_name: String,
    sandbox: Arc<Mutex<SandboxManager>>,
    registry: Arc<PayloadSerializerRegistry>,
    capabilities: HashSet<String>,
    timeout_ms: u64,
}

#[async_trait]
impl AnyHookHandler for WasmBridgeHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        // Build the WIT payload: structured fast-path for known types, generic fallback via registry
        let wit_hook_payload = if let Some(cmf) = payload.as_any().downcast_ref::<MessagePayload>()
        {
            crate::sandbox_manager::types::HookPayload::Cmf(native_payload_to_wit(cmf))
        } else if let Some(identity) = payload.as_any().downcast_ref::<IdentityPayload>() {
            crate::sandbox_manager::types::HookPayload::Identity(native_identity_payload_to_wit(
                identity,
            ))
        } else if let Some(delegation) = payload.as_any().downcast_ref::<DelegationPayload>() {
            crate::sandbox_manager::types::HookPayload::Delegation(
                native_delegation_payload_to_wit(delegation),
            )
        } else if self.registry.contains_type_id(payload.as_any().type_id()) {
            let (type_name, bytes) = self.registry.serialize(payload).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': payload serialization failed: {}",
                        self.plugin_name, e
                    ),
                })
            })?;
            crate::sandbox_manager::types::HookPayload::Custom(
                crate::sandbox_manager::types::CustomPayload {
                    payload_type: type_name.to_string(),
                    payload_data: bytes,
                },
            )
        } else {
            return Err(Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}': payload type not registered in PayloadSerializerRegistry",
                    self.plugin_name,
                ),
            }));
        };

        // The executor already filters extensions by capabilities before calling
        // this handler. We convert directly — no redundant re-filtering.
        let wit_extensions = native_extensions_to_wit(extensions);
        let wit_ctx = native_context_to_wit(ctx);

        // Invoke the WASM plugin through its dedicated sandbox
        let wit_result = {
            let mut mgr = self.sandbox.lock().await;
            mgr.invoke(&self.hook_name, wit_hook_payload, wit_extensions, wit_ctx)
                .await
                .map_err(|e| classify_wasm_error(&self.plugin_name, self.timeout_ms, e))?
        };

        // Convert WIT HookResult → type-erased result fields + optional
        // context writeback. Pass `extensions` as the filtered reference so
        // hidden slots are preserved during writeback.
        let (mut erased_fields, modified_ctx) = wit_hook_result_to_native_filtered(
            wit_result,
            &self.registry,
            extensions,
            Some(extensions),
        );

        // Defense-in-depth: validate extension modifications returned by WASM
        if let Some(ref owned) = erased_fields.modified_extensions {
            if !validate_extension_modifications(
                owned,
                extensions,
                &self.capabilities,
                &self.plugin_name,
                &self.hook_name,
            ) {
                erased_fields.modified_extensions = None;
            }
        }

        if let Some(new_ctx) = modified_ctx {
            ctx.local_state = new_ctx.local_state;
            ctx.global_state = new_ctx.global_state;
        }

        Ok(Box::new(erased_fields))
    }

    fn hook_type_name(&self) -> &'static str {
        "cmf"
    }
}

// ---------------------------------------------------------------------------
// Post-invocation validation — defense-in-depth at the WASM trust boundary
// ---------------------------------------------------------------------------

/// Validate extension modifications returned by a WASM plugin.
///
/// Checks immutable tier integrity, monotonic label enforcement, and
/// write authorization. Returns `true` if the modifications should be
/// accepted, `false` if they must be rejected.
fn validate_extension_modifications(
    owned: &OwnedExtensions,
    original: &Extensions,
    capabilities: &HashSet<String>,
    plugin_name: &str,
    hook_name: &str,
) -> bool {
    // Check 1: Immutable tier — Arc pointers must be identical
    if !original.validate_immutable(owned) {
        warn!(
            "[WASM] plugin '{}' hook '{}': violated immutable tier — \
             modified an immutable extension slot. Extension changes rejected.",
            plugin_name, hook_name
        );
        return false;
    }

    // Check 2: Monotonic labels — can only add, never remove
    if capabilities.contains("read_labels") {
        if let (Some(ref orig_sec), Some(ref new_sec)) = (&original.security, &owned.security) {
            if !new_sec.labels.is_superset(&orig_sec.labels) {
                warn!(
                    "[WASM] plugin '{}' hook '{}': violated monotonic tier — \
                     removed a security label. Extension changes rejected.",
                    plugin_name, hook_name
                );
                return false;
            }
        }
    }

    // Check 3: Write authorization — reject mutations on slots without write cap
    if !capabilities.contains("write_headers") {
        if let Some(ref http_guarded) = owned.http {
            let new_http = http_guarded.read();
            let http_changed = match original.http.as_ref() {
                Some(orig) => {
                    new_http.request_headers != orig.request_headers
                        || new_http.response_headers != orig.response_headers
                },
                None => {
                    !new_http.request_headers.is_empty() || !new_http.response_headers.is_empty()
                },
            };
            if http_changed {
                warn!(
                    "[WASM] plugin '{}' hook '{}': modified HTTP headers \
                     without write_headers capability. Extension changes rejected.",
                    plugin_name, hook_name
                );
                return false;
            }
        }
    }

    if !capabilities.contains("append_labels") {
        if let Some(ref new_sec) = owned.security {
            let labels_changed = match original.security.as_ref() {
                Some(orig) => new_sec.labels.len() != orig.labels.len(),
                None => !new_sec.labels.is_empty(),
            };
            if labels_changed {
                warn!(
                    "[WASM] plugin '{}' hook '{}': modified security labels \
                     without append_labels capability. Extension changes rejected.",
                    plugin_name, hook_name
                );
                return false;
            }
        }
    }

    if !capabilities.contains("append_delegation") {
        if let Some(ref new_deleg) = owned.delegation {
            let delegation_changed = match original.delegation.as_ref() {
                Some(orig) => {
                    new_deleg.chain.len() != orig.chain.len()
                        || new_deleg.depth != orig.depth
                        || new_deleg.delegated != orig.delegated
                },
                None => new_deleg.delegated || !new_deleg.chain.is_empty(),
            };
            if delegation_changed {
                warn!(
                    "[WASM] plugin '{}' hook '{}': modified delegation \
                     without append_delegation capability. Extension changes rejected.",
                    plugin_name, hook_name
                );
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// WASM error classification — maps wasmtime errors to PluginError variants
// ---------------------------------------------------------------------------

/// Classify a wasmtime invocation error into the appropriate `PluginError`
/// variant based on the error message content.
///
/// The executor uses error variants to apply different `OnError` policies
/// and produce accurate diagnostic records. Using the correct variant
/// ensures circuit breakers, timeout logging, and error aggregation all
/// work as designed.
fn classify_wasm_error(plugin_name: &str, timeout_ms: u64, err: anyhow::Error) -> Box<PluginError> {
    let msg = err.to_string();
    let msg_lower = msg.to_lowercase();

    if msg_lower.contains("epoch deadline") {
        Box::new(PluginError::Timeout {
            plugin_name: plugin_name.to_string(),
            timeout_ms,
            proto_error_code: None,
        })
    } else if msg_lower.contains("all fuel consumed") || msg_lower.contains("fuel") {
        Box::new(PluginError::Execution {
            plugin_name: plugin_name.to_string(),
            message: format!("WASM fuel exhausted: {}", msg),
            source: None,
            code: Some("fuel_exhausted".into()),
            details: HashMap::new(),
            proto_error_code: None,
        })
    } else if msg_lower.contains("memory")
        && (msg_lower.contains("grow") || msg_lower.contains("limit"))
    {
        Box::new(PluginError::Execution {
            plugin_name: plugin_name.to_string(),
            message: format!("WASM memory limit exceeded: {}", msg),
            source: None,
            code: Some("memory_limit".into()),
            details: HashMap::new(),
            proto_error_code: None,
        })
    } else if msg_lower.contains("unreachable")
        || msg_lower.contains("wasm trap")
        || msg_lower.contains("panic")
    {
        Box::new(PluginError::Execution {
            plugin_name: plugin_name.to_string(),
            message: format!("WASM trap: {}", msg),
            source: None,
            code: Some("wasm_trap".into()),
            details: HashMap::new(),
            proto_error_code: None,
        })
    } else if msg_lower.contains("request denied") || msg_lower.contains("http_request_denied") {
        Box::new(PluginError::Execution {
            plugin_name: plugin_name.to_string(),
            message: format!("WASM network access denied: {}", msg),
            source: None,
            code: Some("network_denied".into()),
            details: HashMap::new(),
            proto_error_code: None,
        })
    } else {
        Box::new(PluginError::Execution {
            plugin_name: plugin_name.to_string(),
            message: format!("WASM invocation failed: {}", msg),
            source: None,
            code: None,
            details: HashMap::new(),
            proto_error_code: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_epoch_deadline_as_timeout() {
        let err = anyhow::anyhow!("wasm trap: epoch deadline has elapsed");
        let result = classify_wasm_error("test-plugin", 5000, err);
        match *result {
            PluginError::Timeout {
                ref plugin_name,
                timeout_ms,
                ..
            } => {
                assert_eq!(plugin_name, "test-plugin");
                assert_eq!(timeout_ms, 5000);
            },
            _ => panic!("expected Timeout, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_fuel_exhaustion() {
        let err = anyhow::anyhow!("all fuel consumed by wasm");
        let result = classify_wasm_error("test-plugin", 5000, err);
        match *result {
            PluginError::Execution { ref code, .. } => {
                assert_eq!(code.as_deref(), Some("fuel_exhausted"));
            },
            _ => panic!("expected Execution with fuel_exhausted, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_memory_limit() {
        let err = anyhow::anyhow!("memory growth failed: memory limit exceeded");
        let result = classify_wasm_error("test-plugin", 5000, err);
        match *result {
            PluginError::Execution { ref code, .. } => {
                assert_eq!(code.as_deref(), Some("memory_limit"));
            },
            _ => panic!("expected Execution with memory_limit, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_wasm_trap() {
        let err = anyhow::anyhow!("wasm trap: unreachable instruction executed");
        let result = classify_wasm_error("test-plugin", 5000, err);
        match *result {
            PluginError::Execution { ref code, .. } => {
                assert_eq!(code.as_deref(), Some("wasm_trap"));
            },
            _ => panic!("expected Execution with wasm_trap, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_network_denied() {
        let err = anyhow::anyhow!("outbound HTTP request denied: host not in allowlist");
        let result = classify_wasm_error("test-plugin", 5000, err);
        match *result {
            PluginError::Execution { ref code, .. } => {
                assert_eq!(code.as_deref(), Some("network_denied"));
            },
            _ => panic!("expected Execution with network_denied, got {:?}", result),
        }
    }

    #[test]
    fn test_classify_unknown_error_as_execution() {
        let err = anyhow::anyhow!("something unexpected happened in the component");
        let result = classify_wasm_error("test-plugin", 5000, err);
        match *result {
            PluginError::Execution {
                ref code,
                ref plugin_name,
                ..
            } => {
                assert_eq!(plugin_name, "test-plugin");
                assert!(code.is_none());
            },
            _ => panic!("expected generic Execution, got {:?}", result),
        }
    }
}
