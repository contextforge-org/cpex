// Location: ./examples/go-demo/ffi/src/demo_plugins.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Generic demo plugins for the Go example.
//
// Three plugins that operate on GenericPayload (serde_json::Value),
// demonstrating identity validation, PII policy enforcement, and
// audit logging through the CPEX plugin pipeline:
//
//   - IdentityChecker: validates that a "user" field is present in
//     the payload or a subject ID exists in security extensions
//   - PiiGuard: blocks access to PII-tagged tools unless the payload
//     contains a "pii_clearance" flag
//   - AuditLogger: logs tool invocations with entity type, tool name,
//     and user (fire-and-forget mode)

use std::sync::Arc;

use async_trait::async_trait;

use praxis_policy_core::context::PluginContext;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::{PluginError, PluginViolation};
use praxis_policy_core::factory::{PluginFactory, PluginInstance};
use praxis_policy_core::hooks::adapter::TypedHandlerAdapter;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use praxis_policy_core::hooks::{register_hook_metadata, HookMetadata, HookPhase};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

use cpex_ffi::GenericPayload;

// ---------------------------------------------------------------------------
// Generic Hook Type
// ---------------------------------------------------------------------------

/// A hook type for FFI callers that send untyped map payloads.
/// The hook *name* varies at registration time (demo.tool_pre_invoke,
/// etc.) but the payload type is always GenericPayload.
pub struct GenericHook;

impl HookTypeDef for GenericHook {
    type Payload = GenericPayload;
    type Result = PluginResult<GenericPayload>;
    const NAME: &'static str = "generic";
}

/// Host hook fired before a tool runs. The `cmf.*` hooks carry a typed
/// `MessagePayload`, so a generic-map demo declares its own pair.
pub const HOOK_DEMO_TOOL_PRE_INVOKE: &str = "demo.tool_pre_invoke";

/// Host hook fired after a tool runs.
pub const HOOK_DEMO_TOOL_POST_INVOKE: &str = "demo.tool_post_invoke";

/// Describe the demo hooks to the engine. The config loader refuses a
/// `hooks:` entry it has no metadata for, so this runs before any config
/// naming them is loaded.
pub fn register_demo_hooks() {
    for (name, phase) in [
        (HOOK_DEMO_TOOL_PRE_INVOKE, HookPhase::Pre),
        (HOOK_DEMO_TOOL_POST_INVOKE, HookPhase::Post),
    ] {
        register_hook_metadata(
            name,
            HookMetadata {
                family: Some(GenericHook::NAME),
                entity_type: Some("tool"),
                phase,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Identity Checker
// ---------------------------------------------------------------------------

struct IdentityChecker {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for IdentityChecker {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<GenericHook> for IdentityChecker {
    async fn handle(
        &self,
        payload: &GenericPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<GenericPayload> {
        let user = payload.value.get("user").and_then(|v| v.as_str());

        let subject_id = extensions
            .security
            .as_ref()
            .and_then(|s| s.subject.as_ref())
            .and_then(|s| s.id.as_deref());

        match user.or(subject_id) {
            Some(u) if !u.is_empty() => {
                tracing::info!("[identity-checker] OK: user '{}' identified", u);
                PluginResult::allow()
            },
            _ => {
                tracing::warn!("[identity-checker] DENIED: no user identity");
                PluginResult::deny(PluginViolation::new(
                    "no_identity",
                    "User identity is required",
                ))
            },
        }
    }
}

pub struct IdentityCheckerFactory;

impl PluginFactory for IdentityCheckerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(IdentityChecker {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                (
                    HOOK_DEMO_TOOL_PRE_INVOKE,
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin.clone())),
                ),
                (
                    HOOK_DEMO_TOOL_POST_INVOKE,
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin)),
                ),
            ],
        })
    }
}

// ---------------------------------------------------------------------------
// PII Guard
// ---------------------------------------------------------------------------

struct PiiGuard {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for PiiGuard {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<GenericHook> for PiiGuard {
    async fn handle(
        &self,
        payload: &GenericPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<GenericPayload> {
        let has_pii_tag = extensions
            .meta
            .as_ref()
            .map(|m| m.tags.iter().any(|t| t == "pii"))
            .unwrap_or(false);

        let has_pii_label = extensions
            .security
            .as_ref()
            .map(|s| s.labels.contains(&"PII".to_string()))
            .unwrap_or(false);

        if !has_pii_tag && !has_pii_label {
            return PluginResult::allow();
        }

        let has_clearance = payload
            .value
            .get("pii_clearance")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if has_clearance {
            tracing::info!("[pii-guard] OK: PII clearance verified");
            PluginResult::allow()
        } else {
            let tool_name = payload
                .value
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            tracing::warn!(
                "[pii-guard] DENIED: PII clearance required for '{}'",
                tool_name
            );
            PluginResult::deny(PluginViolation::new(
                "pii_access_denied",
                "PII clearance required for this operation",
            ))
        }
    }
}

pub struct PiiGuardFactory;

impl PluginFactory for PiiGuardFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(PiiGuard {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                HOOK_DEMO_TOOL_PRE_INVOKE,
                Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin)),
            )],
        })
    }
}

// ---------------------------------------------------------------------------
// Audit Logger
// ---------------------------------------------------------------------------

struct AuditLogger {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<GenericHook> for AuditLogger {
    async fn handle(
        &self,
        payload: &GenericPayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<GenericPayload> {
        let tool_name = payload
            .value
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let user = payload
            .value
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("anonymous");
        let entity_type = extensions
            .meta
            .as_ref()
            .and_then(|m| m.entity_type.as_deref())
            .unwrap_or("unknown");

        tracing::info!(
            "[audit-logger] LOG: entity_type={} tool={} user={}",
            entity_type,
            tool_name,
            user,
        );
        PluginResult::allow()
    }
}

pub struct AuditLoggerFactory;

impl PluginFactory for AuditLoggerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(AuditLogger {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![
                (
                    HOOK_DEMO_TOOL_PRE_INVOKE,
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin.clone())),
                ),
                (
                    HOOK_DEMO_TOOL_POST_INVOKE,
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin)),
                ),
            ],
        })
    }
}

/// Register the demo hooks and all demo plugin factories on an engine.
pub fn register_demo_factories(engine: &PolicyEngine) {
    register_demo_hooks();
    engine.register_factory("demo/identity", Box::new(IdentityCheckerFactory));
    engine.register_factory("demo/pii", Box::new(PiiGuardFactory));
    engine.register_factory("demo/audit", Box::new(AuditLoggerFactory));
}
