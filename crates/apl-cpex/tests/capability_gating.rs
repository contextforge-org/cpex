// Location: ./crates/apl-cpex/tests/capability_gating.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Capability-gating end-to-end. cpex-core's executor calls
// `filter_extensions(&ext, &caps)` before every handler invoke — so the
// synthetic `AplRouteHandler` must declare a capability set wide enough
// to cover every downstream plugin it dispatches, otherwise:
//
//   - APL predicates read from a stripped attribute bag (silently wrong
//     policy decisions).
//   - Downstream plugins receive a doubly-filtered view (their own caps
//     applied on top of an already-stripped one).
//   - Write attempts (append_labels, append_delegation, write_headers)
//     fail the monotonicity check on the way back out of the handler.
//
// These tests verify the visitor computes
// `base_capabilities ∪ per-route plugin union` and sets it on the
// synthetic `PluginConfig`.

use std::sync::Arc;

use async_trait::async_trait;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError as CoreError;
use cpex_core::extensions::{MetaExtension, SecurityExtension};
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};

// =====================================================================
// Fixtures
// =====================================================================

/// Plugin that records whether it saw `security.labels` populated.
/// Used to verify that `read_labels` capability propagates through the
/// synthetic handler so the inner plugin's filtered view actually
/// contains labels.
struct LabelReader {
    cfg: PluginConfig,
    observed_labels: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for LabelReader {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for LabelReader {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let seen: Vec<String> = extensions
            .security
            .as_ref()
            .map(|s| s.labels.iter().cloned().collect())
            .unwrap_or_default();
        *self.observed_labels.lock().unwrap() = seen;
        PluginResult::allow()
    }
}

struct LabelReaderFactory {
    observed_labels: Arc<std::sync::Mutex<Vec<String>>>,
}

impl PluginFactory for LabelReaderFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(LabelReader {
            cfg: config.clone(),
            observed_labels: Arc::clone(&self.observed_labels),
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

/// Plugin that appends a label via `modify_extensions`. Used to verify
/// write-cap propagation: requires both an `append_labels` declaration
/// on the plugin AND the synthetic handler to also be granted
/// `append_labels` so the executor accepts the mutation on the way
/// back out.
struct LabelWriter {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for LabelWriter {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for LabelWriter {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let mut owned = extensions.cow_copy();
        let security = owned.security.get_or_insert_with(Default::default);
        security.add_label("APPENDED");
        PluginResult::modify_extensions(owned)
    }
}

struct LabelWriterFactory;
impl PluginFactory for LabelWriterFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(LabelWriter {
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

// =====================================================================
// Helpers
// =====================================================================

fn cmf_payload(text: &str) -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, text),
    }
}

fn meta_for_tool(name: &str) -> MetaExtension {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some("tool".to_string());
    meta.entity_name = Some(name.to_string());
    meta
}

fn extensions_with_label(label: &str) -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label(label.to_string());
    Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        security: Some(Arc::new(security)),
        ..Default::default()
    }
}

// =====================================================================
// Scenarios
// =====================================================================

/// Plugin declares `read_labels`; route references it; pre-existing
/// label `EXISTING` is set on the request extensions. The plugin must
/// observe the label — proving the synthetic `AplRouteHandler` got
/// `read_labels` from the per-route plugin union (cpex-core's filter
/// would otherwise strip security.labels at the handler boundary).
#[tokio::test]
async fn plugin_with_read_labels_sees_labels_through_apl_handler() {
    const YAML: &str = r#"
plugins:
  - name: label-reader
    kind: label-reader
    hooks: [cmf.tool_pre_invoke]
    capabilities: [read_labels]
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "plugin(label-reader)"
"#;

    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "label-reader",
        Box::new(LabelReaderFactory {
            observed_labels: Arc::clone(&observed),
        }),
    );
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: None,
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let ext = extensions_with_label("EXISTING");
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "plugin shouldn't deny: {:?}",
        result.violation
    );

    let seen = observed.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["EXISTING".to_string()],
        "plugin must observe the EXISTING label that the request carried; \
         empty means the synthetic AplRouteHandler stripped security.labels \
         because its cap union didn't include read_labels"
    );
}

/// Same plugin shape, but DON'T declare `read_labels` on the plugin
/// and set an empty `base_capabilities` so neither the per-route
/// union nor the baseline grants the cap. The plugin must NOT see
/// labels — confirms the negative case (capability gating actually
/// hides things when caps are missing).
#[tokio::test]
async fn plugin_without_read_labels_sees_stripped_view() {
    const YAML: &str = r#"
plugins:
  - name: label-reader
    kind: label-reader
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "plugin(label-reader)"
"#;

    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "label-reader",
        Box::new(LabelReaderFactory {
            observed_labels: Arc::clone(&observed),
        }),
    );
    // Strict mode: empty baseline → only per-plugin caps grant
    // anything, and the plugin declared none.
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: Some(std::collections::HashSet::new()),
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let ext = extensions_with_label("EXISTING");
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(result.continue_processing);

    let seen = observed.lock().unwrap().clone();
    assert!(
        seen.is_empty(),
        "plugin should see no labels when neither it nor the baseline \
         grants read_labels — got: {:?}",
        seen
    );
}

/// Plugin declares `append_labels` and emits a new label via
/// `modify_extensions`. The synthetic `AplRouteHandler` must also be
/// granted `append_labels` (from the per-route union) so its outer
/// modify_extensions write doesn't get rejected on the way back out.
/// After the invoke, the appended label must be visible in the final
/// extensions.
#[tokio::test]
async fn write_capabilities_propagate_through_apl_handler() {
    const YAML: &str = r#"
plugins:
  - name: label-writer
    kind: label-writer
    hooks: [cmf.tool_pre_invoke]
    capabilities: [append_labels, read_labels]
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "plugin(label-writer)"
"#;

    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory("label-writer", Box::new(LabelWriterFactory));
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        ..Default::default()
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "label-writer should allow: {:?}",
        result.violation
    );

    // The appended label should be visible on the way out via
    // `modified_extensions` — None means no plugin wrote anything,
    // which would be a failure here.
    let modified = result
        .modified_extensions
        .expect("label-writer should have modified extensions");
    let labels: Vec<String> = modified
        .security
        .as_ref()
        .map(|s| s.labels.iter().cloned().collect())
        .unwrap_or_default();
    assert!(
        labels.contains(&"APPENDED".to_string()),
        "expected APPENDED to land in final security.labels — \
         a missing label means the executor rejected the write on the \
         way out of AplRouteHandler (no append_labels cap on the synthetic). \
         Got: {:?}",
        labels
    );
}

/// Predicate-only route: no plugins, just `require(authenticated)`.
/// APL evaluates this against the attribute bag built from the
/// (capability-filtered) Extensions view the handler sees. Default
/// baseline grants `read_subject`, so `authenticated` evaluates to
/// `true` when subject is present.
#[tokio::test]
async fn predicate_only_route_uses_baseline_capabilities() {
    const YAML: &str = r#"
plugins: []
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "require(authenticated)"
"#;
    let mgr = Arc::new(PluginManager::default());
    register_apl(&mgr, AplOptions::in_process());
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    // Set subject id so `authenticated` derives true via apl-cmf.
    let mut security = SecurityExtension::default();
    security.subject = Some(cpex_core::extensions::SubjectExtension {
        id: Some("alice".to_string()),
        ..Default::default()
    });
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        security: Some(Arc::new(security)),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        result.continue_processing,
        "require(authenticated) should pass with subject.id set: violation = {:?}",
        result.violation
    );
}

/// Same predicate-only route but baseline is forcibly empty AND no
/// subject is set. With empty baseline the synthetic handler has no
/// caps, so security.subject is stripped → `authenticated` evaluates
/// false → `require(authenticated)` denies. Confirms the baseline
/// actually controls what predicates can read.
#[tokio::test]
async fn empty_baseline_strips_predicate_view() {
    const YAML: &str = r#"
plugins: []
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "require(authenticated)"
"#;
    let mgr = Arc::new(PluginManager::default());
    register_apl(
        &mgr,
        AplOptions {
            dispatch_cache: Arc::new(DispatchCache::new()),
            session_store: Arc::new(MemorySessionStore::new()),
            pdps: Vec::new(),
            pdp_factories: Vec::new(),
            session_store_factories: Vec::new(),
            base_capabilities: Some(std::collections::HashSet::new()),
        },
    );
    mgr.load_config_yaml(YAML).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");

    // Even though subject.id IS set, the empty baseline means the
    // synthetic handler can't read subject — predicate sees missing →
    // false → require denies.
    let mut security = SecurityExtension::default();
    security.subject = Some(cpex_core::extensions::SubjectExtension {
        id: Some("alice".to_string()),
        ..Default::default()
    });
    let ext = Extensions {
        meta: Some(Arc::new(meta_for_tool("get_weather"))),
        security: Some(Arc::new(security)),
        ..Default::default()
    };

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", cmf_payload("hi"), ext, None)
        .await;
    assert!(
        !result.continue_processing,
        "empty baseline should cause require(authenticated) to deny \
         even with subject set — capability gating proves it can't see"
    );
}
