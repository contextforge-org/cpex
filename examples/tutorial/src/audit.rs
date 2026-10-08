// Location: ./examples/tutorial/src/audit.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// A one-line audit plugin for the tutorial.
//
// Module 4 and the capstone need a side effect that runs before a denial so
// you can watch halt-on-deny keep it. CPEX ships no audit plugin of its own,
// since the record's format and destination are what a deployment replaces,
// so the harness carries this small one. It writes one JSON line per call to
// stderr and always allows.
//
// It is an ordinary host plugin, built exactly the way module 9 teaches:
// a `Plugin`, a `HookHandler<CmfHook>`, and a `PluginFactory` registered
// under a `kind` before the policy loads. Policy reaches it by name with
// `run(audit-log)`, like any other plugin.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use cpex::PolicyEngine;
use cpex::prelude::{
    CmfHook, ContentPart, Extensions, HookHandler, MessagePayload, Plugin, PluginConfig,
    PluginContext, PluginError, PluginFactory, PluginInstance, PluginResult, TypedHandlerAdapter,
};

/// The `kind` a policy declares to use this plugin.
pub const KIND: &str = "tutorial/audit-line";

/// Register the audit plugin's factory on `engine`. Call it before loading a
/// policy that declares `kind: tutorial/audit-line`.
pub fn register(engine: &Arc<PolicyEngine>) {
    engine.register_factory(KIND, Box::new(AuditLineFactory));
}

struct AuditLine {
    cfg: PluginConfig,
}

impl AuditLine {
    /// Build the record from what the plugin's capabilities let it see:
    /// the entity (`read_meta`), the subject (`read_subject`), and the call's
    /// tool name and argument keys.
    fn record(&self, payload: &MessagePayload, ext: &Extensions) -> Value {
        let mut record = Map::new();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        record.insert("ts".into(), json!(ts));
        record.insert("plugin".into(), json!(self.cfg.name));
        if let Some(meta) = &ext.meta {
            record.insert(
                "entity".into(),
                json!({ "type": meta.entity_type, "name": meta.entity_name }),
            );
        }
        if let Some(subject) = ext.security.as_ref().and_then(|s| s.subject.as_ref()) {
            let mut roles: Vec<&String> = subject.roles.iter().collect();
            roles.sort();
            record.insert(
                "subject".into(),
                json!({ "id": subject.id, "roles": roles }),
            );
        }
        for part in &payload.message.content {
            if let ContentPart::ToolCall { content } = part {
                // Argument values are left out on purpose: they can carry PII or secrets.
                let mut arg_keys: Vec<&String> = content.arguments.keys().collect();
                arg_keys.sort();
                record.insert(
                    "tool_call".into(),
                    json!({ "name": content.name, "arg_keys": arg_keys }),
                );
                break;
            }
        }
        Value::Object(record)
    }
}

#[async_trait]
impl Plugin for AuditLine {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AuditLine {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        eprintln!("{}", self.record(payload, extensions));
        PluginResult::allow()
    }
}

struct AuditLineFactory;

impl PluginFactory for AuditLineFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        let plugin = Arc::new(AuditLine {
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
