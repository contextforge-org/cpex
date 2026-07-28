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
use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError as CoreError, PluginViolation};
use cpex_core::extensions::{SecurityExtension, SubjectExtension};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::{HookEntry, PluginRef};

use apl_core::attributes::AttributeBag;
use apl_core::evaluator::Decision;
use apl_core::step::{PluginInvocation, PluginInvoker};

use apl_cpex::{CmfPluginInvoker, MemorySessionStore, RouteDispatchPlan};

/// Build a single-plugin RouteDispatchPlan straight off the cpex-core
/// registry — no APL CompiledRoute involved. Used by the invoker-primitive
/// tests below to exercise the plan-based dispatch path without standing
/// up a full route.
fn plan_for(
    manager: &cpex_core::manager::PluginManager,
    plugin_name: &str,
) -> Arc<RouteDispatchPlan> {
    let entry = RouteDispatchPlan::resolve_plugin(manager, plugin_name)
        .expect("plugin must be registered with the manager");
    let mut plugins = std::collections::HashMap::new();
    plugins.insert(plugin_name.to_string(), entry);
    Arc::new(RouteDispatchPlan {
        plugins,
        delegation_entries: Default::default(),
        elicitation_entries: Default::default(),
    })
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
        let plugin = Arc::new(AllowPlugin {
            cfg: config.clone(),
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
        let plugin = Arc::new(DenyPlugin {
            cfg: config.clone(),
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
        let plugin = Arc::new(ModifyPlugin {
            cfg: config.clone(),
        });
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
async fn build_manager(factory_kind: &str, factory: Box<dyn PluginFactory>) -> Arc<PluginManager> {
    let mgr = PluginManager::default();
    mgr.register_factory(factory_kind, factory);

    let yaml = format!("plugins:\n  - name: {0}\n    kind: {0}\n", factory_kind);
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
    let plan = plan_for(&mgr, "allow-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let outcome = invoker
        .invoke(
            "allow-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    assert_eq!(outcome.decision, Decision::Allow);
    assert!(outcome.modified_value.is_none());
}

#[tokio::test]
async fn step_invocation_deny_surfaces_violation_reason_and_code() {
    let mgr = build_manager("deny-plugin", Box::new(DenyPluginFactory)).await;
    let plan = plan_for(&mgr, "deny-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let outcome = invoker
        .invoke(
            "deny-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    match outcome.decision {
        Decision::Deny {
            reason,
            rule_source,
        } => {
            assert_eq!(reason.as_deref(), Some("test-fixture denied this call"));
            assert_eq!(rule_source, "policy.forbidden");
        },
        other => panic!("expected Decision::Deny, got {:?}", other),
    }
}

#[tokio::test]
async fn field_invocation_modify_surfaces_modified_value_and_persists_payload() {
    let mgr = build_manager("modify-plugin", Box::new(ModifyPluginFactory)).await;
    let plan = plan_for(&mgr, "modify-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::Value::String("hello".to_string());
    let outcome = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
                phase: apl_core::step::DispatchPhase::Pre,
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
                phase: apl_core::step::DispatchPhase::Pre,
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
    let plan = plan_for(&mgr, "modify-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let bag = empty_bag();
    let value = serde_json::Value::String("ignored".to_string());
    let _ = invoker
        .invoke(
            "modify-plugin",
            &bag,
            PluginInvocation::Field {
                name: "content",
                value: &value,
                phase: apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");

    let final_payload = invoker.current_payload().await;
    assert_eq!(final_payload.message.get_text_content(), "hello [MODIFIED]");
}

// ---------------------------------------------------------------------
// Capability gating — APL route override of `capabilities:` materializes
// a derived PluginRef wrapping the same plugin Arc with a merged
// TrustedConfig. cpex-core's executor then enforces the narrower caps
// in its single per-entry `filter_extensions` pass — no double filter,
// no second clone of security. The base plugin's circuit breaker stays
// isolated.
// ---------------------------------------------------------------------

/// Capture-plugin fixture — records the Extensions it actually receives
/// from the executor so the test can assert what survived filtering.
struct CapturePlugin {
    cfg: PluginConfig,
    captured: Arc<tokio::sync::Mutex<Option<Extensions>>>,
}

#[async_trait]
impl Plugin for CapturePlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for CapturePlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        *self.captured.lock().await = Some(extensions.clone());
        PluginResult::allow()
    }
}

struct CapturePluginFactory {
    slot: Arc<tokio::sync::Mutex<Option<Extensions>>>,
}

impl PluginFactory for CapturePluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(CapturePlugin {
            cfg: config.clone(),
            captured: self.slot.clone(),
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

/// Build a manager whose registered plugin holds the given capability
/// set (wide caps in this test — the override is supposed to narrow
/// what these caps would have allowed).
async fn build_manager_with_caps(
    factory_kind: &str,
    factory: Box<dyn PluginFactory>,
    cpex_caps: &[&str],
) -> Arc<PluginManager> {
    let mgr = PluginManager::default();
    mgr.register_factory(factory_kind, factory);
    let caps_yaml = if cpex_caps.is_empty() {
        String::new()
    } else {
        format!("    capabilities: [{}]\n", cpex_caps.join(", "))
    };
    let yaml = format!(
        "plugins:\n  - name: {0}\n    kind: {0}\n{1}",
        factory_kind, caps_yaml,
    );
    let cfg = cpex_core::config::parse_config(&yaml).expect("parse_config");
    mgr.load_config(cfg).expect("load_config");
    mgr.initialize().await.expect("initialize");
    Arc::new(mgr)
}

fn extensions_with_subject_and_labels() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label("PII");
    security.subject = Some(SubjectExtension {
        id: Some("alice".into()),
        ..Default::default()
    });
    Extensions {
        security: Some(Arc::new(security)),
        ..Default::default()
    }
}

/// Build a RoutePluginEntry that wraps the base plugin's handler with a
/// derived PluginRef carrying narrower caps — same plugin Arc, fresh
/// circuit breaker, smaller cap set. Mirrors what
/// `RouteDispatchPlan::build` does when APL declares a route-level
/// `plugins.<name>.capabilities:` override.
fn plan_with_narrowed_caps(
    manager: &PluginManager,
    plugin_name: &str,
    narrowed_caps: &[&str],
) -> Arc<apl_cpex::RouteDispatchPlan> {
    let base = manager
        .find_plugin_entries(plugin_name)
        .into_iter()
        .next()
        .expect("plugin registered");
    let (_hook_name, base_entry) = base;
    let mut merged = base_entry.plugin_ref.trusted_config().clone();
    merged.capabilities = narrowed_caps.iter().map(|s| s.to_string()).collect();
    let override_ref = Arc::new(PluginRef::new(
        Arc::clone(base_entry.plugin_ref.plugin()),
        merged,
    ));
    let entry = HookEntry {
        plugin_ref: override_ref,
        handler: Arc::clone(&base_entry.handler),
    };
    let mut plugins = std::collections::HashMap::new();
    let mut entries_by_hook = std::collections::HashMap::new();
    entries_by_hook.insert("cmf.tool_pre_invoke".to_string(), entry);
    plugins.insert(
        plugin_name.to_string(),
        apl_cpex::RoutePluginEntry {
            plugin_name: plugin_name.to_string(),
            entries_by_hook,
        },
    );
    Arc::new(apl_cpex::RouteDispatchPlan {
        plugins,
        delegation_entries: Default::default(),
        elicitation_entries: Default::default(),
    })
}

#[tokio::test]
async fn route_override_caps_narrow_what_plugin_sees() {
    // cpex-core registers the plugin with WIDE caps: read_subject AND
    // read_labels. Without an override, the plugin would see both.
    let captured = Arc::new(tokio::sync::Mutex::new(None));
    let factory = CapturePluginFactory {
        slot: captured.clone(),
    };
    let mgr = build_manager_with_caps(
        "capture-plugin",
        Box::new(factory),
        &["read_subject", "read_labels"],
    )
    .await;

    // APL route override narrows to ONLY read_subject — labels should
    // be stripped despite cpex-core having registered them.
    let plan = plan_with_narrowed_caps(&mgr, "capture-plugin", &["read_subject"]);

    let invoker = CmfPluginInvoker::for_request(
        mgr,
        extensions_with_subject_and_labels(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    let outcome = invoker
        .invoke(
            "capture-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("invoke");
    assert_eq!(outcome.decision, Decision::Allow);

    let captured = captured.lock().await.clone().expect("handler ran");
    let security = captured.security.expect("security extension present");

    // read_subject is in the narrowed set → subject still visible.
    assert!(
        security.subject.is_some(),
        "route override declared read_subject; plugin should see subject"
    );
    assert_eq!(
        security.subject.as_ref().unwrap().id.as_deref(),
        Some("alice")
    );

    // read_labels is NOT in the narrowed set → labels stripped, even
    // though cpex-core's registration would have allowed them through.
    assert!(
        security.labels.is_empty(),
        "route override dropped read_labels; labels should be empty (got {:?})",
        security.labels,
    );
}

// ---------------------------------------------------------------------
// Hook routing table regression
// ---------------------------------------------------------------------
//
// Multi-hook plugin selection bug regression: a plugin registered
// under BOTH `cmf.tool_pre_invoke` and `cmf.tool_post_invoke` must
// dispatch to the right entry per phase. Previously the
// dispatch plan classified both as "step" and arbitrary "first
// non-field wins" picked one for every dispatch — silent wrong
// routing when policy and post_policy needed different handlers.

/// Pre-side handler — returns Allow with no modification.
struct PreSideHandler {
    cfg: PluginConfig,
}
#[async_trait]
impl Plugin for PreSideHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}
impl HookHandler<CmfHook> for PreSideHandler {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

/// Post-side handler — returns Deny with a distinctive violation
/// code so the test can assert "which handler fired" from the
/// outcome alone.
struct PostSideHandler {
    cfg: PluginConfig,
}
#[async_trait]
impl Plugin for PostSideHandler {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}
impl HookHandler<CmfHook> for PostSideHandler {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::deny(cpex_core::error::PluginViolation::new(
            "test.multi_hook.post_fired",
            "post handler fired",
        ))
    }
}

/// Marker plugin held by the PluginInstance (handlers are
/// independent structs — the marker satisfies the
/// `PluginInstance.plugin` field).
struct MultiHookMarker {
    cfg: PluginConfig,
}
#[async_trait]
impl Plugin for MultiHookMarker {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

struct MultiHookPluginFactory;
impl PluginFactory for MultiHookPluginFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let marker = Arc::new(MultiHookMarker {
            cfg: config.clone(),
        });
        let pre = Arc::new(PreSideHandler {
            cfg: config.clone(),
        });
        let post = Arc::new(PostSideHandler {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: marker as Arc<dyn Plugin>,
            handlers: vec![
                (
                    "cmf.tool_pre_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(pre)),
                ),
                (
                    "cmf.tool_post_invoke",
                    Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(post)),
                ),
            ],
        })
    }
}

/// Plugin registered under both `cmf.tool_pre_invoke` and
/// `cmf.tool_post_invoke`. `PluginInvocation::Step { phase: Pre }`
/// must pick the pre-side handler; `Step { phase: Post }` must pick
/// the post-side handler. The post handler emits a distinctive
/// violation code so we can prove WHICH handler fired from the
/// outcome alone — not just that "a handler" fired.
#[tokio::test]
async fn multi_hook_plugin_dispatches_per_phase_via_routing_table() {
    let mgr = build_manager("multi-hook-plugin", Box::new(MultiHookPluginFactory)).await;
    let plan = plan_for(&mgr, "multi-hook-plugin");
    let invoker = CmfPluginInvoker::for_request(
        mgr,
        Extensions::default(),
        payload_with_text("hello"),
        plan,
        Arc::new(MemorySessionStore::new()),
    )
    .await
    .expect("for_request");

    // Pre phase — should hit pre handler → Allow.
    let pre_outcome = invoker
        .invoke(
            "multi-hook-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: apl_core::step::DispatchPhase::Pre,
            },
        )
        .await
        .expect("pre invoke");
    assert_eq!(pre_outcome.decision, Decision::Allow);

    // Post phase — should hit post handler → Deny with the
    // distinctive code. Proves the post handler ran, not the pre
    // handler (which would have returned Allow).
    let post_outcome = invoker
        .invoke(
            "multi-hook-plugin",
            &empty_bag(),
            PluginInvocation::Step {
                phase: apl_core::step::DispatchPhase::Post,
            },
        )
        .await
        .expect("post invoke");
    match post_outcome.decision {
        Decision::Deny { rule_source, .. } => {
            assert_eq!(
                rule_source, "test.multi_hook.post_fired",
                "Post phase should dispatch to the post-side handler",
            );
        },
        d => panic!("expected Deny from post handler, got {d:?}"),
    }
}
