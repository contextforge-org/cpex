// Location: ./crates/apl-cpex/tests/cmf_invoker_dispatch.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Integration tests for `CmfPluginInvoker` — exercises the typed
// dispatch path end-to-end against a real `cpex-core::PluginManager`
// with hand-rolled test plugins. v0 coverage:
//   - `Step` invocation against an allow-plugin → `Decision::Allow`
//   - `Step` invocation against a deny-plugin → `Decision::Deny` with
//     reason + rule_source pulled from the CPEX `PluginViolation`
//   - `Field` invocation against a modify-plugin → `Decision::Allow`
//     with `modified_value` populated from the rewritten text content
//   - Payload mutation persists across invocations (one modifying
//     plugin's output is visible to the next).

use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use cpex_core::cmf::enums::Role;
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError as CoreError, PluginViolation};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::plugin_decl::{PluginDeclaration, PluginRegistry};
use apl_core::step::{PluginInvocation, PluginInvoker};

use apl_cpex::CmfPluginInvoker;

/// Build a one-plugin APL registry — declares which CPEX hook the plugin
/// implements. The invoker reads this on dispatch instead of using the
/// pre-registry hardcoded defaults.
fn registry_with(plugin_name: &str, kind: &str, hook: &str) -> Arc<PluginRegistry> {
    let mut reg = PluginRegistry::new();
    reg.insert(
        plugin_name.to_string(),
        PluginDeclaration {
            name: plugin_name.to_string(),
            kind: kind.to_string(),
            hooks: vec![hook.to_string()],
            capabilities: Vec::new(),
            config: None,
            on_error: None,
            extra: std::collections::HashMap::new(),
        },
    );
    Arc::new(reg)
}

// ---------------------------------------------------------------------
// Test plugins — minimal CMF handlers with hard-coded behavior so the
// dispatch path is exercised without external state.
// ---------------------------------------------------------------------

struct AllowPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for AllowPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AllowPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

struct AllowPluginFactory;
impl PluginFactory for AllowPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(AllowPlugin { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

struct DenyPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for DenyPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for DenyPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(PluginViolation::new(
            "policy.forbidden",
            "test-fixture denied this call",
        ))
    }
}

struct DenyPluginFactory;
impl PluginFactory for DenyPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(DenyPlugin { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.tool_pre_invoke",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

/// Modify plugin — rewrites every Text part by appending `" [MODIFIED]"`
/// so the test can assert mutation propagation deterministically.
struct ModifyPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for ModifyPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for ModifyPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let new_content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => ContentPart::Text {
                    text: format!("{} [MODIFIED]", text),
                },
                other => other.clone(),
            })
            .collect();
        PluginResult::modify_payload(MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role,
                content: new_content,
                channel: payload.message.channel,
            },
        })
    }
}

struct ModifyPluginFactory;
impl PluginFactory for ModifyPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(ModifyPlugin { cfg: config.clone() });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.field_redact",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

// ---------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------

fn payload_with_text(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

fn empty_bag() -> AttributeBag {
    AttributeBag::new()
}

/// Build a manager, register one factory + one plugin under the given
/// kind, and return the wired manager ready for invocation.
async fn build_manager(
    factory_kind: &str,
    factory: Box<dyn PluginFactory>,
) -> Arc<PluginManager> {
    let mgr = PluginManager::default();
    mgr.register_factory(factory_kind, factory);

    let yaml = format!(
        "plugins:\n  - name: {0}\n    kind: {0}\n",
        factory_kind
    );
    let cfg = cpex_core::config::parse_config(&yaml).expect("parse_config");
    mgr.load_config(cfg).expect("load_config");
    mgr.initialize().await.expect("initialize");
    Arc::new(mgr)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[tokio::test]
async fn step_invocation_allow_returns_decision_allow() {
    let mgr = build_manager("allow-plugin", Box::new(AllowPluginFactory)).await;
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        registry_with("allow-plugin", "allow-plugin", "cmf.tool_pre_invoke"),
    );

    let outcome = invoker
        .invoke("allow-plugin", &empty_bag(), PluginInvocation::Step)
        .await
        .expect("invoke");

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.modified_value.is_none());
}

#[tokio::test]
async fn step_invocation_deny_surfaces_violation_reason_and_code() {
    let mgr = build_manager("deny-plugin", Box::new(DenyPluginFactory)).await;
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        registry_with("deny-plugin", "deny-plugin", "cmf.tool_pre_invoke"),
    );

    let outcome = invoker
        .invoke("deny-plugin", &empty_bag(), PluginInvocation::Step)
        .await
        .expect("invoke");

    match outcome.decision {
        Decision::Deny { reason, rule_source } => {
            assert_eq!(reason.as_deref(), Some("test-fixture denied this call"));
            assert_eq!(rule_source, "policy.forbidden");
        }
        other => panic!("expected Decision::Deny, got {:?}", other),
    }
}

#[tokio::test]
async fn field_invocation_modify_surfaces_modified_value_and_persists_payload() {
    let mgr = build_manager("modify-plugin", Box::new(ModifyPluginFactory)).await;
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        registry_with("modify-plugin", "modify-plugin", "cmf.field_redact"),
    );

    let bag = empty_bag();
    let value = serde_json::Value::String("hello".to_string());
    let outcome = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(outcome.decision, Decision::Allow);
    assert_eq!(
        outcome.modified_value,
        Some(serde_json::Value::String("hello [MODIFIED]".to_string()))
    );

    // Payload mutation persisted: a second invocation sees the updated
    // text as input (modifier appends [MODIFIED] each pass).
    let outcome2 = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
            },
        )
        .await
        .expect("invoke");
    assert_eq!(
        outcome2.modified_value,
        Some(serde_json::Value::String(
            "hello [MODIFIED] [MODIFIED]".to_string()
        ))
    );
}

#[tokio::test]
async fn current_payload_reflects_accumulated_mutations() {
    let mgr = build_manager("modify-plugin", Box::new(ModifyPluginFactory)).await;
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        registry_with("modify-plugin", "modify-plugin", "cmf.field_redact"),
    );

    let bag = empty_bag();
    let value = serde_json::Value::String("ignored".to_string());
    let _ = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
            },
        )
        .await
        .expect("invoke");

    let final_payload = invoker.current_payload().await;
    assert_eq!(
        final_payload.message.get_text_content(),
        "hello [MODIFIED]"
    );
}
