// Location: ./crates/apl-cpex/tests/payload_mutation_propagation.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// A plugin mutation has to survive the whole way to the host, whichever
// part of the message it touched. These tests drive the real
// `AplRouteHandler` through `invoke_named::<CmfHook>` and assert on the
// payload the host would forward.
//
// The failure these guard against is silent and fails open: a redactor
// rewrites `ToolResult.content`, reports success, and the host forwards
// the original secret anyway. Redaction and sanitisation plugins are
// exactly the ones that mutate non-text parts, so "only text mutations
// survive" is worst in the case that matters most.
//
// Text parts are left byte-identical on purpose in most fixtures below.
// Any check that infers "was this modified?" from message text passes
// them through unchanged, which is the bug.

use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, ToolCall, ToolResult};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError as CoreError;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};

use apl_cpex::{register_apl, AplOptions, DispatchCache, MemorySessionStore};

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// Rewrites one content part and leaves the rest alone. Which part it
/// touches is chosen per instance so a single fixture covers several
/// `ContentPart` variants.
#[derive(Clone, Copy)]
enum Target {
    /// Replace the whole tool result content.
    ToolResultContent,
    /// Replace one field inside an object-shaped tool result content,
    /// leaving its siblings alone.
    ToolResultField(&'static str),
    /// Replace the `city` argument of a tool call.
    ToolCallArguments,
    /// Replace one named argument of a tool call.
    ToolCallArgument(&'static str),
    /// Replace a key inside an object-valued tool call argument.
    NestedToolCallArgument(&'static str, &'static str),
    Thinking,
    Text,
}

struct RewritePlugin {
    cfg: PluginConfig,
    target: Target,
}

#[async_trait]
impl Plugin for RewritePlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for RewritePlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let content: Vec<ContentPart> = payload
            .message
            .content
            .iter()
            .map(|part| match (self.target, part) {
                (Target::ToolResultContent, ContentPart::ToolResult { content }) => {
                    let mut next = content.clone();
                    next.content = serde_json::Value::String("[REDACTED]".to_string());
                    ContentPart::ToolResult { content: next }
                },
                (Target::ToolResultField(field), ContentPart::ToolResult { content }) => {
                    let mut next = content.clone();
                    if let Some(obj) = next.content.as_object_mut() {
                        obj.insert(
                            field.to_string(),
                            serde_json::Value::String("[REDACTED]".to_string()),
                        );
                    }
                    ContentPart::ToolResult { content: next }
                },
                (Target::ToolCallArguments, ContentPart::ToolCall { content }) => {
                    let mut next = content.clone();
                    next.arguments.insert(
                        "city".to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                    ContentPart::ToolCall { content: next }
                },
                (Target::ToolCallArgument(arg), ContentPart::ToolCall { content }) => {
                    let mut next = content.clone();
                    next.arguments.insert(
                        arg.to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                    ContentPart::ToolCall { content: next }
                },
                (Target::NestedToolCallArgument(arg, key), ContentPart::ToolCall { content }) => {
                    let mut next = content.clone();
                    if let Some(obj) = next.arguments.get_mut(arg).and_then(|v| v.as_object_mut()) {
                        obj.insert(
                            key.to_string(),
                            serde_json::Value::String("[REDACTED]".to_string()),
                        );
                    }
                    ContentPart::ToolCall { content: next }
                },
                (Target::Thinking, ContentPart::Thinking { .. }) => ContentPart::Thinking {
                    text: "[REDACTED]".to_string(),
                },
                (Target::Text, ContentPart::Text { .. }) => ContentPart::Text {
                    text: "[REDACTED]".to_string(),
                },
                (_, other) => other.clone(),
            })
            .collect();

        PluginResult::modify_payload(MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role,
                content,
                channel: payload.message.channel,
            },
        })
    }
}

struct RewriteFactory {
    target: Target,
    hook: &'static str,
}

impl PluginFactory for RewriteFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(RewritePlugin {
            cfg: config.clone(),
            target: self.target,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                self.hook,
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

/// Allows without returning a payload — the baseline for "nothing
/// changed, so nothing should be forwarded as modified".
struct NoopPlugin {
    cfg: PluginConfig,
}

#[async_trait]
impl Plugin for NoopPlugin {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for NoopPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        PluginResult::allow()
    }
}

/// Denies, so a route can mutate and then refuse in one request.
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
        PluginResult::deny(cpex_core::error::PluginViolation::new(
            "policy.forbidden",
            "test fixture denied this call",
        ))
    }
}

struct DenyFactory;

impl PluginFactory for DenyFactory {
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

struct NoopFactory {
    hook: &'static str,
}

impl PluginFactory for NoopFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<CoreError>> {
        let plugin = Arc::new(NoopPlugin {
            cfg: config.clone(),
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                self.hook,
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Wire one plugin behind an APL route on `get_weather`, with the route
/// phase and hook chosen by the caller.
async fn manager_with(
    kind: &'static str,
    factory: Box<dyn PluginFactory>,
    hook: &str,
    phase: &str,
) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(kind, factory);
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
    let yaml = format!(
        r#"
plugins:
  - name: {kind}
    kind: {kind}
    hooks: [{hook}]
routes:
  - tool: get_weather
    apl:
      {phase}:
        - "plugin({kind})"
"#
    );
    mgr.load_config_yaml(&yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

/// Wire one plugin behind a route that *also* runs a field pipeline, so
/// two editors touch the same content part in one request.
async fn manager_with_yaml(
    kind: &'static str,
    factory: Box<dyn PluginFactory>,
    yaml: &str,
) -> Arc<PluginManager> {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(kind, factory);
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
    mgr.load_config_yaml(yaml).expect("load_config_yaml");
    mgr.initialize().await.expect("initialize");
    mgr
}

/// Routes match on the request's entity type + name, so a request needs
/// tool meta for the `tool: get_weather` handler to fire at all.
fn tool_meta() -> Extensions {
    let mut meta = cpex_core::extensions::MetaExtension::default();
    meta.entity_type = Some("tool".to_string());
    meta.entity_name = Some("get_weather".to_string());
    Extensions {
        meta: Some(Arc::new(meta)),
        ..Default::default()
    }
}

fn tool_call_part(city: &str) -> ContentPart {
    ContentPart::ToolCall {
        content: ToolCall {
            tool_call_id: "tc_001".to_string(),
            name: "get_weather".to_string(),
            arguments: [("city".to_string(), serde_json::json!(city))]
                .into_iter()
                .collect(),
            namespace: None,
        },
    }
}

fn tool_result_part(content: &str) -> ContentPart {
    ContentPart::ToolResult {
        content: ToolResult {
            tool_call_id: "tc_001".to_string(),
            tool_name: "get_weather".to_string(),
            content: serde_json::Value::String(content.to_string()),
            is_error: false,
        },
    }
}

fn payload_of(role: Role, parts: Vec<ContentPart>) -> MessagePayload {
    MessagePayload {
        message: Message::with_content(role, parts),
    }
}

/// The payload the host would forward, downcast back to CMF.
fn forwarded(result: &cpex_core::executor::PipelineResult) -> MessagePayload {
    result
        .modified_payload
        .as_ref()
        .expect("an allowed pipeline always carries the final payload")
        .as_any()
        .downcast_ref::<MessagePayload>()
        .expect("cmf hooks carry MessagePayload")
        .clone()
}

fn tool_result_of(payload: &MessagePayload) -> Option<&serde_json::Value> {
    payload.message.content.iter().find_map(|part| match part {
        ContentPart::ToolResult { content } => Some(&content.content),
        _ => None,
    })
}

fn tool_arg_of(payload: &MessagePayload, key: &str) -> Option<serde_json::Value> {
    payload.message.content.iter().find_map(|part| match part {
        ContentPart::ToolCall { content } => content.arguments.get(key).cloned(),
        _ => None,
    })
}

// ---------------------------------------------------------------------
// Direct mutations reach the host, whichever part they touched
// ---------------------------------------------------------------------

/// The reported failure: a redactor rewrites only `ToolResult.content`,
/// so the message's text is untouched. The redaction must reach the host.
#[tokio::test]
async fn tool_result_redaction_reaches_the_host() {
    let mgr = manager_with(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(
        Role::Tool,
        vec![
            ContentPart::Text {
                text: "here is the result".to_string(),
            },
            tool_result_part("sk-secret-value"),
        ],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    assert!(
        result.payload_modified,
        "the plugin returned a mutation, so the pipeline must report one"
    );
    let out = forwarded(&result);
    assert_eq!(
        tool_result_of(&out),
        Some(&serde_json::Value::String("[REDACTED]".to_string())),
        "the host must receive the redacted tool result, not the original secret"
    );
    assert_eq!(
        out.message.get_text_content(),
        "here is the result",
        "fixture sanity: text is untouched, so text comparison sees no change"
    );
}

/// Same shape, on the arguments of an outgoing tool call.
#[tokio::test]
async fn tool_call_argument_rewrite_reaches_the_host() {
    let mgr = manager_with(
        "arg-redactor",
        Box::new(RewriteFactory {
            target: Target::ToolCallArguments,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(Role::User, vec![tool_call_part("London")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(
        tool_arg_of(&forwarded(&result), "city"),
        Some(serde_json::json!("[REDACTED]"))
    );
}

/// A thinking block carries no text part at all, so this is the cheapest
/// proof the fix is variant-agnostic rather than a tool-result special case.
#[tokio::test]
async fn thinking_rewrite_reaches_the_host() {
    let mgr = manager_with(
        "thought-redactor",
        Box::new(RewriteFactory {
            target: Target::Thinking,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(
        Role::Assistant,
        vec![ContentPart::Thinking {
            text: "the user's SSN is 123-45-6789".to_string(),
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(
        forwarded(&result).message.get_thinking_content().as_deref(),
        Some("[REDACTED]")
    );
}

/// The case that always worked. Kept so a future change can't fix the
/// others by breaking this one.
#[tokio::test]
async fn text_rewrite_still_reaches_the_host() {
    let mgr = manager_with(
        "text-redactor",
        Box::new(RewriteFactory {
            target: Target::Text,
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::Text {
            text: "my card is 4111 1111 1111 1111".to_string(),
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(forwarded(&result).message.get_text_content(), "[REDACTED]");
}

/// Post phase carries its own handler instance, so it needs its own proof.
#[tokio::test]
async fn tool_result_redaction_reaches_the_host_in_post_phase() {
    let mgr = manager_with(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_post_invoke",
        }),
        "cmf.tool_post_invoke",
        "post_invocation",
    )
    .await;

    let payload = payload_of(Role::Tool, vec![tool_result_part("sk-secret-value")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert_eq!(
        tool_result_of(&forwarded(&result)),
        Some(&serde_json::Value::String("[REDACTED]".to_string()))
    );
}

// ---------------------------------------------------------------------
// A pipeline edit and a plugin edit in the same request
//
// Both write to the same content part: the pipeline through
// `route_payload.args` / `.result`, the plugin through the payload
// itself. Folding the pipeline's view back in has to be per-path, or
// whichever editor is folded last wins and the other's work vanishes.
// ---------------------------------------------------------------------

/// An `args:` pipeline redacts `city` while a plugin rewrites `token` on
/// the same tool call. Both edits must reach the host.
#[tokio::test]
async fn args_pipeline_and_plugin_edits_both_survive() {
    const YAML: &str = r#"
plugins:
  - name: token-scrubber
    kind: token-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      args:
        city: "str | redact"
      pre_invocation:
        - "plugin(token-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "token-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("token"),
            hook: "cmf.tool_pre_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_string(),
                name: "get_weather".to_string(),
                arguments: [
                    ("city".to_string(), serde_json::json!("London")),
                    ("token".to_string(), serde_json::json!("sk-secret")),
                ]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    let out = forwarded(&result);
    assert_eq!(
        tool_arg_of(&out, "city"),
        Some(serde_json::json!("[REDACTED]")),
        "the pipeline's redaction must reach the host"
    );
    assert_eq!(
        tool_arg_of(&out, "token"),
        Some(serde_json::json!("[REDACTED]")),
        "the plugin's edit must not be clobbered by folding the pipeline's \
         args back in"
    );
}

/// The mirror case on the response side: a `result:` pipeline masks one
/// field while a plugin redacts another in the same tool result.
#[tokio::test]
async fn result_pipeline_and_plugin_edits_both_survive() {
    const YAML: &str = r#"
plugins:
  - name: ssn-redactor
    kind: ssn-redactor
    hooks: [cmf.tool_post_invoke]
routes:
  - tool: get_weather
    apl:
      result:
        employee_id: "str | mask(2)"
      post_invocation:
        - "plugin(ssn-redactor)"
"#;

    let mgr = manager_with_yaml(
        "ssn-redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultField("ssn"),
            hook: "cmf.tool_post_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(
        Role::Tool,
        vec![ContentPart::ToolResult {
            content: ToolResult {
                tool_call_id: "tc_001".to_string(),
                tool_name: "get_weather".to_string(),
                content: serde_json::json!({
                    "employee_id": "E12345",
                    "ssn": "123-45-6789",
                }),
                is_error: false,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_post_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    let out = forwarded(&result);
    let content = tool_result_of(&out).expect("tool result present").clone();
    assert_eq!(
        content.get("employee_id"),
        Some(&serde_json::json!("****45")),
        "the pipeline's mask must reach the host"
    );
    assert_eq!(
        content.get("ssn"),
        Some(&serde_json::json!("[REDACTED]")),
        "the plugin's redaction must not be clobbered by folding the \
         pipeline's result back in"
    );
}

/// A plugin invoked as a pipeline stage on `city` rewrites `city`. The
/// redaction must land on that argument and nowhere else — in
/// particular, the message's unrelated text must not be copied over it.
#[tokio::test]
async fn plugin_stage_rewrites_only_the_field_it_was_pointed_at() {
    const YAML: &str = r#"
plugins:
  - name: city-scrubber
    kind: city-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      args:
        city: "str | plugin(city-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "city-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("city"),
            hook: "cmf.tool_pre_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![
            ContentPart::Text {
                text: "chatter that must not become an argument".to_string(),
            },
            tool_call_part("London"),
        ],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    assert_eq!(
        tool_arg_of(&forwarded(&result), "city"),
        Some(serde_json::json!("[REDACTED]"))
    );
}

/// Two plugins, each rewriting a different part. Mutations accumulate
/// across a route's plugin chain, so the last one to run must not be the
/// only one that survives.
#[tokio::test]
async fn mutations_from_several_plugins_accumulate() {
    const YAML: &str = r#"
plugins:
  - name: result-redactor
    kind: result-redactor
    hooks: [cmf.tool_pre_invoke]
  - name: thought-redactor
    kind: thought-redactor
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "plugin(result-redactor)"
        - "plugin(thought-redactor)"
"#;

    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "result-redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
    );
    mgr.register_factory(
        "thought-redactor",
        Box::new(RewriteFactory {
            target: Target::Thinking,
            hook: "cmf.tool_pre_invoke",
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

    let payload = payload_of(
        Role::Assistant,
        vec![
            ContentPart::Thinking {
                text: "ssn is 123-45-6789".to_string(),
            },
            tool_result_part("sk-secret-value"),
        ],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    let out = forwarded(&result);
    assert_eq!(
        tool_result_of(&out),
        Some(&serde_json::Value::String("[REDACTED]".to_string())),
        "the first plugin's redaction must survive the second plugin's dispatch"
    );
    assert_eq!(
        out.message.get_thinking_content().as_deref(),
        Some("[REDACTED]"),
        "the second plugin's redaction must land too"
    );
}

/// A route that mutates and then denies must forward nothing. Half-
/// applying a denied request is worse than either outcome.
#[tokio::test]
async fn a_denied_route_forwards_no_payload() {
    const YAML: &str = r#"
plugins:
  - name: redactor
    kind: redactor
    hooks: [cmf.tool_pre_invoke]
  - name: denier
    kind: denier
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "plugin(redactor)"
        - "plugin(denier)"
"#;

    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
    );
    mgr.register_factory("denier", Box::new(DenyFactory));
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

    let payload = payload_of(Role::Tool, vec![tool_result_part("sk-secret-value")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(!result.continue_processing, "the route must deny");
    assert!(
        result.modified_payload.is_none(),
        "a denied pipeline carries no payload forward"
    );
    assert!(!result.payload_modified);
}

/// An audit-mode plugin cannot modify: the executor drops whatever
/// payload it returns. Nothing may report that mutation as applied, or
/// the host would forward a payload the framework deliberately rejected.
#[tokio::test]
async fn a_mutation_the_executor_rejects_is_not_reported() {
    const YAML: &str = r#"
plugins:
  - name: redactor
    kind: redactor
    hooks: [cmf.tool_pre_invoke]
    mode: audit
routes:
  - tool: get_weather
    apl:
      pre_invocation:
        - "plugin(redactor)"
"#;

    let mgr = manager_with_yaml(
        "redactor",
        Box::new(RewriteFactory {
            target: Target::ToolResultContent,
            hook: "cmf.tool_pre_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(Role::Tool, vec![tool_result_part("sk-secret-value")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert!(
        !result.payload_modified,
        "an audit-mode plugin's payload is discarded, so no mutation was applied"
    );
    assert_eq!(
        tool_result_of(&forwarded(&result)),
        Some(&serde_json::Value::String("sk-secret-value".to_string())),
        "and the original must be what's forwarded"
    );
}

/// An `omit` stage drops a field while a plugin rewrites another. The
/// removal has to apply to the plugin's payload, not replace it.
#[tokio::test]
async fn omit_stage_and_plugin_edit_both_survive() {
    const YAML: &str = r#"
plugins:
  - name: token-scrubber
    kind: token-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      args:
        debug: "str | omit"
      pre_invocation:
        - "plugin(token-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "token-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("token"),
            hook: "cmf.tool_pre_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_string(),
                name: "get_weather".to_string(),
                arguments: [
                    ("city".to_string(), serde_json::json!("London")),
                    ("debug".to_string(), serde_json::json!("verbose")),
                    ("token".to_string(), serde_json::json!("sk-secret")),
                ]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    let out = forwarded(&result);
    assert_eq!(tool_arg_of(&out, "debug"), None, "the omit must apply");
    assert_eq!(
        tool_arg_of(&out, "token"),
        Some(serde_json::json!("[REDACTED]")),
        "the plugin's edit must not be undone by applying the omit"
    );
    assert_eq!(
        tool_arg_of(&out, "city"),
        Some(serde_json::json!("London")),
        "an argument nobody touched must be left alone"
    );
}

/// Nested arguments: the pipeline redacts `user.ssn`, a plugin rewrites
/// `user.name`. Merging has to descend into the object rather than
/// replace it.
#[tokio::test]
async fn nested_pipeline_and_plugin_edits_both_survive() {
    const YAML: &str = r#"
plugins:
  - name: name-scrubber
    kind: name-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      args:
        user.ssn: "str | redact"
      pre_invocation:
        - "plugin(name-scrubber)"
"#;

    let mgr = manager_with_yaml(
        "name-scrubber",
        Box::new(RewriteFactory {
            target: Target::NestedToolCallArgument("user", "name"),
            hook: "cmf.tool_pre_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_string(),
                name: "get_weather".to_string(),
                arguments: [(
                    "user".to_string(),
                    serde_json::json!({"name": "Ada Lovelace", "ssn": "123-45-6789"}),
                )]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    let user = tool_arg_of(&forwarded(&result), "user").expect("user argument present");
    assert_eq!(
        user.get("ssn"),
        Some(&serde_json::json!("[REDACTED]")),
        "the pipeline's nested redaction must reach the host"
    );
    assert_eq!(
        user.get("name"),
        Some(&serde_json::json!("[REDACTED]")),
        "the plugin's edit to a sibling key must survive the merge"
    );
}

/// A plugin stage must not undo an earlier stage in its own chain.
///
/// The payload never sees a pipeline's interim edits, so the field a
/// plugin stage reads back still holds the pre-`mask` value. Treating
/// that as "the plugin's new value" hands the plaintext back to the
/// pipeline and the mask is forwarded undone — the redaction path
/// failing open, which is the whole point of this code.
#[tokio::test]
async fn a_plugin_stage_does_not_undo_an_earlier_mask_in_the_same_chain() {
    const YAML: &str = r#"
plugins:
  - name: token-scrubber
    kind: token-scrubber
    hooks: [cmf.tool_pre_invoke]
routes:
  - tool: get_weather
    apl:
      args:
        city: "str | mask(2) | plugin(token-scrubber)"
      pre_invocation:
        - "plugin(token-scrubber)"
"#;

    // The plugin rewrites `token`, never `city`. It must therefore report
    // no change for `city` and leave the mask standing.
    let mgr = manager_with_yaml(
        "token-scrubber",
        Box::new(RewriteFactory {
            target: Target::ToolCallArgument("token"),
            hook: "cmf.tool_pre_invoke",
        }),
        YAML,
    )
    .await;

    let payload = payload_of(
        Role::User,
        vec![ContentPart::ToolCall {
            content: ToolCall {
                tool_call_id: "tc_001".to_string(),
                name: "get_weather".to_string(),
                arguments: [
                    ("city".to_string(), serde_json::json!("London")),
                    ("token".to_string(), serde_json::json!("sk-secret")),
                ]
                .into_iter()
                .collect(),
                namespace: None,
            },
        }],
    );

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing, "route should allow");
    let out = forwarded(&result);
    assert_eq!(
        tool_arg_of(&out, "city"),
        Some(serde_json::json!("****on")),
        "the mask stage's output must survive the plugin stage that followed it"
    );
    assert_eq!(
        tool_arg_of(&out, "token"),
        Some(serde_json::json!("[REDACTED]")),
        "and the plugin's own edit must still reach the host"
    );
}

/// A route whose plugin allows without mutating, and which has no
/// pipelines, must not report a modification. Reporting one is harmless
/// for correctness but makes every request look modified, so the signal
/// stops meaning anything.
#[tokio::test]
async fn allow_without_mutation_reports_no_modification() {
    let mgr = manager_with(
        "noop",
        Box::new(NoopFactory {
            hook: "cmf.tool_pre_invoke",
        }),
        "cmf.tool_pre_invoke",
        "pre_invocation",
    )
    .await;

    let payload = payload_of(Role::User, vec![tool_call_part("London")]);

    let (result, _bg) = mgr
        .invoke_named::<CmfHook>("cmf.tool_pre_invoke", payload, tool_meta(), None)
        .await;

    assert!(result.continue_processing);
    assert!(!result.payload_modified);
    assert_eq!(
        tool_arg_of(&forwarded(&result), "city"),
        Some(serde_json::json!("London")),
        "an untouched request must arrive untouched"
    );
}
