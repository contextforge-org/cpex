// Location: ./crates/cpex/tests/facade.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// The facade, exercised the way a host uses it: only `cpex::` paths.

use std::sync::Arc;

use cpex::PolicyEngine;
use cpex::prelude::*;

/// Load a one-plugin config on an engine with the builtins installed and
/// return the error text (empty on success).
fn load_error_for_kind(kind: &str) -> String {
    let engine = Arc::new(PolicyEngine::default());
    cpex::install_builtins(&engine);
    let yaml =
        format!("plugins:\n  - name: probe\n    kind: {kind}\n    hooks: [cmf.tool_pre_invoke]\n");
    match engine.load_config_yaml(&yaml) {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    }
}

/// The PII scanner and audit logger are reference plugins now, not builtins,
/// so the facade must not register them.
#[test]
fn install_builtins_registers_no_pii_or_audit_kind() {
    for kind in ["validator/pii-scan", "audit/logger"] {
        let err = load_error_for_kind(kind);
        assert!(
            err.contains("no factory registered") && err.contains(kind),
            "{kind} must not be registered by install_builtins; got: {err}"
        );
    }
}

/// Denies any tool call whose message text mentions a banned word.
struct WordBlocker {
    cfg: PluginConfig,
}

impl Plugin for WordBlocker {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for WordBlocker {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        if payload.message.get_text_content().contains("banned") {
            return PluginResult::deny(PluginViolation::new(
                "facade.banned_word",
                "the payload mentions a banned word",
            ));
        }
        PluginResult::allow()
    }
}

struct WordBlockerFactory;

impl PluginFactory for WordBlockerFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(WordBlocker {
            cfg: config.clone(),
        });
        let adapter: Arc<dyn AnyHookHandler> =
            Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
        Ok(PluginInstance {
            plugin,
            handlers: vec![("cmf.tool_pre_invoke", adapter)],
        })
    }
}

const CONFIG: &str = r#"
engine_settings:
  dispatch: hooks
plugins:
  - name: word-blocker
    kind: test/word-blocker
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
"#;

async fn invoke(engine: &PolicyEngine, text: &str) -> (bool, Option<String>) {
    let payload = MessagePayload {
        message: Message::text(Role::User, text),
    };
    let (result, _background) = engine
        .invoke_by_name(
            "cmf.tool_pre_invoke",
            Box::new(payload),
            Extensions::default(),
            None,
        )
        .await;
    (result.continue_processing, result.violation.map(|v| v.code))
}

/// A config on `cmf.tool_pre_invoke` loads and dispatches through the facade,
/// with the builtins installed alongside a host-supplied factory.
#[tokio::test]
async fn cmf_tool_pre_invoke_config_loads_and_dispatches() {
    let engine = Arc::new(PolicyEngine::default());
    cpex::install_builtins(&engine);
    engine.register_factory("test/word-blocker", Box::new(WordBlockerFactory));
    engine.load_config_yaml(CONFIG).expect("config loads");
    engine.initialize().await.expect("engine initializes");

    assert!(engine.has_hooks_for("cmf.tool_pre_invoke"));

    let (allowed, violation) = invoke(&engine, "hello").await;
    assert!(allowed, "clean payload is allowed");
    assert_eq!(violation, None);

    let (allowed, violation) = invoke(&engine, "a banned word").await;
    assert!(!allowed, "banned payload is denied");
    assert_eq!(violation.as_deref(), Some("facade.banned_word"));

    engine.shutdown().await;
}
