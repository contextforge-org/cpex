// Location: ./integrations/authbridge/ffi/src/scope_tool_gate.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// scope-tool-gate — CPEX plugin that denies a tool call when the caller's
// subject permissions don't include the scope configured for that tool.
//
// Reads:
//   - extensions.security.subject.permissions  (caller's granted scopes,
//     populated by cpex-runtime's bridge from AuthBridge's
//     pctx.Identity.Scopes())
//   - extensions.mcp.tool.name                 (parsed MCP tool name,
//     populated by mcp-parser into pctx, bridged into CPEX's MCPExtension)
//
// YAML config (per-plugin under cpex-runtime's `chain:` entry):
//   - name: scope-tool-gate
//     config:
//       tool_scopes:
//         get_weather:      weather:read
//         get_compensation: hr:read
//
// Behavior:
//   - If MCP.tool is absent — allow (not a tool call we gate).
//   - If tool name has no entry in tool_scopes — allow (no policy declared).
//   - If subject.permissions contains the required scope — allow.
//   - Otherwise — deny with code `policy.forbidden`.
//
// Registers under hook `cmf.tool_pre_invoke` — cpex-runtime invokes that
// hook when AuthBridge's outbound pctx has MCP.Method == "tools/call".

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::cmf::MessagePayload;
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

/// CMF hook type — same shape every AuthBridge-targeted plugin uses.
/// Made `pub` so llm_pii_redactor (sibling module) can register against
/// the same hook type from its own factory.
pub struct CmfHook;

impl HookTypeDef for CmfHook {
    type Payload = MessagePayload;
    type Result = PluginResult<MessagePayload>;
    const NAME: &'static str = "cmf";
}

/// ScopeToolGate compiles its tool→scope map once at create time and
/// reads it on every invocation. No regex / IO at request time.
struct ScopeToolGate {
    cfg: PluginConfig,
    tool_scopes: HashMap<String, String>,
}

#[async_trait]
impl Plugin for ScopeToolGate {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for ScopeToolGate {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let tool_name = match extensions.mcp.as_ref().and_then(|m| m.tool.as_ref()) {
            Some(t) => &t.name,
            None => {
                tracing::debug!("[scope-tool-gate] no MCP tool — allow");
                return PluginResult::allow();
            }
        };

        let required_scope = match self.tool_scopes.get(tool_name) {
            Some(s) => s,
            None => {
                tracing::debug!(
                    "[scope-tool-gate] tool {} has no policy — allow",
                    tool_name
                );
                return PluginResult::allow();
            }
        };

        let permissions = extensions
            .security
            .as_ref()
            .and_then(|s| s.subject.as_ref())
            .map(|s| &s.permissions);

        let has_scope = permissions
            .map(|set| set.contains(required_scope.as_str()))
            .unwrap_or(false);

        if has_scope {
            tracing::info!(
                "[scope-tool-gate] allow tool={} scope={}",
                tool_name, required_scope
            );
            return PluginResult::allow();
        }

        tracing::warn!(
            "[scope-tool-gate] deny tool={} required={} subject_perms={:?}",
            tool_name, required_scope, permissions
        );
        let mut details = HashMap::new();
        details.insert("tool".to_string(), serde_json::Value::String(tool_name.clone()));
        details.insert(
            "required_scope".to_string(),
            serde_json::Value::String(required_scope.clone()),
        );
        PluginResult::deny(
            PluginViolation::new("policy.forbidden", "missing required scope")
                .with_details(details),
        )
    }
}

struct ScopeToolGateFactory;

impl PluginFactory for ScopeToolGateFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        // Decode tool_scopes from the plugin's opaque `config` JSON.
        // Missing or non-map → empty (plugin becomes a no-op, which is the
        // documented "no policy" behavior — better than failing the boot
        // for an empty config block).
        let tool_scopes = config
            .config
            .as_ref()
            .and_then(|v| v.get("tool_scopes"))
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();

        let plugin = Arc::new(ScopeToolGate {
            cfg: config.clone(),
            tool_scopes,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

pub fn register(manager: &mut PluginManager) {
    manager.register_factory("scope-tool-gate", Box::new(ScopeToolGateFactory));
}
