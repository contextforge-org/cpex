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

use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use cpex_ffi::GenericPayload;

// ---------------------------------------------------------------------------
// Generic Hook Type
// ---------------------------------------------------------------------------

/// A hook type for FFI callers that send untyped map payloads.
/// The hook *name* varies at registration time (tool_pre_invoke, etc.)
/// but the payload type is always GenericPayload.
pub struct GenericHook;

impl HookTypeDef for GenericHook {
    type Payload = GenericPayload;
    type Result = PluginResult<GenericPayload>;
    const NAME: &'static str = "generic";
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
    fn handle(
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
            }
            _ => {
                tracing::warn!("[identity-checker] DENIED: no user identity");
                PluginResult::deny(PluginViolation::new(
                    "no_identity",
                    "User identity is required",
                ))
            }
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
                    "tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin.clone())),
                ),
                (
                    "tool_post_invoke",
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
    fn handle(
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
                "tool_pre_invoke",
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
    fn handle(
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
                    "tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin.clone())),
                ),
                (
                    "tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<GenericHook, _>::new(plugin)),
                ),
            ],
        })
    }
}

/// Register all demo plugin factories on a manager.
pub fn register_demo_factories(manager: &mut cpex_core::manager::PluginManager) {
    manager.register_factory("builtin/identity", Box::new(IdentityCheckerFactory));
    manager.register_factory("builtin/pii", Box::new(PiiGuardFactory));
    manager.register_factory("builtin/audit", Box::new(AuditLoggerFactory));
}
