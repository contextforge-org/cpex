// Location: ./crates/apl-audit-logger/src/logger.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Map, Value};

use cpex_core::cmf::{CmfHook, ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::config::{AuditDestination, AuditLoggerConfig};

/// Observation-only CMF plugin. Builds a structured audit record
/// from the request's MessagePayload + Extensions, emits to the
/// configured destination, returns `Allow`. Never blocks.
#[derive(Debug)]
pub struct AuditLogger {
    cfg: PluginConfig,
    typed: AuditLoggerConfig,
}

impl AuditLogger {
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let typed: AuditLoggerConfig = match cfg.config.as_ref() {
            Some(raw) => serde_json::from_value(raw.clone()).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-audit-logger) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?,
            None => AuditLoggerConfig::default(),
        };
        Ok(Self { cfg, typed })
    }

    fn build_record(&self, payload: &MessagePayload, ext: &Extensions) -> Value {
        let mut record = Map::new();
        record.insert(
            "ts".into(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
        record.insert("plugin".into(), json!(self.cfg.name));
        if let Some(src) = &self.typed.source {
            record.insert("source".into(), json!(src));
        }

        // Subject — capability-filtered. Empty Subject means the
        // plugin lacks `read_subject` cap (won't happen if the
        // operator configured it correctly).
        if let Some(sec) = ext.security.as_ref() {
            if let Some(s) = &sec.subject {
                record.insert(
                    "subject".into(),
                    json!({
                        "id": s.id,
                        "roles": s.roles.iter().collect::<Vec<_>>(),
                        "teams": s.teams.iter().collect::<Vec<_>>(),
                    }),
                );
            }
            if let Some(c) = &sec.client {
                record.insert(
                    "client".into(),
                    json!({
                        "client_id": c.client_id,
                        "client_name": c.client_name,
                    }),
                );
            }
        }

        // Entity — the route's tool/prompt/resource coords.
        if let Some(meta) = ext.meta.as_ref() {
            record.insert(
                "entity".into(),
                json!({
                    "type": meta.entity_type,
                    "name": meta.entity_name,
                }),
            );
        }

        // Tool / prompt args summary — the first structured
        // content part's args, if any. Mirrors what the gateway
        // would actually forward (so audit reflects post-redact
        // state if a PII scanner ran ahead of us).
        for part in &payload.message.content {
            match part {
                ContentPart::ToolCall { content } => {
                    record.insert(
                        "tool_call".into(),
                        json!({
                            "name": content.name,
                            "tool_call_id": content.tool_call_id,
                            "args": content.arguments,
                        }),
                    );
                    break;
                }
                ContentPart::PromptRequest { content } => {
                    record.insert(
                        "prompt_request".into(),
                        json!({
                            "name": content.name,
                            "args": content.arguments,
                        }),
                    );
                    break;
                }
                _ => {}
            }
        }

        // Delegation outcomes — which audiences got tokens, with
        // what (effective, possibly narrowed) scopes. The whole
        // point of including this: it makes the audit trail show
        // "we exchanged for workday-api with scope=read_compensation",
        // which is the proof that delegation enforcement happened.
        if let Some(raw) = ext.raw_credentials.as_ref() {
            if !raw.delegated_tokens.is_empty() {
                let tokens: Vec<Value> = raw
                    .delegated_tokens
                    .iter()
                    .map(|(_key, tok)| {
                        json!({
                            "audience": tok.audience,
                            "scopes": tok.scopes,
                            "outbound_header": tok.outbound_header,
                            "expires_at": tok.expires_at.to_rfc3339_opts(
                                chrono::SecondsFormat::Secs, true,
                            ),
                        })
                    })
                    .collect();
                record.insert("delegated_tokens".into(), json!(tokens));
            }
        }

        Value::Object(record)
    }

    fn emit(&self, record: &Value) {
        match self.typed.destination {
            AuditDestination::Stderr => {
                // One JSON line — easy to grep / forward / jq through.
                eprintln!("{}", record);
            }
            AuditDestination::Tracing => {
                tracing::info!(target: "apl.audit", record = %record, "audit");
            }
        }
    }
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for AuditLogger {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let record = self.build_record(payload, ext);
        self.emit(&record);
        PluginResult::allow()
    }
}

// Silence import-unused warning if Arc isn't used elsewhere.
#[allow(dead_code)]
fn _force_link_arc(_: Arc<()>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::{Message, Role, ToolCall};
    use cpex_core::extensions::{MetaExtension, SecurityExtension, SubjectExtension};
    use cpex_core::plugin::{OnError, PluginConfig, PluginMode};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn cfg() -> PluginConfig {
        PluginConfig {
            name: "audit".into(),
            kind: "test".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            mode: PluginMode::Sequential,
            priority: 50,
            on_error: OnError::Fail,
            config: Some(serde_json::json!({ "destination": "stderr" })),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn build_record_includes_subject_entity_toolcall() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let payload = MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "1".into(),
                        name: "get_compensation".into(),
                        arguments: HashMap::from([(
                            "employee_id".to_string(),
                            serde_json::json!("EMP-001234"),
                        )]),
                        namespace: None,
                    },
                }],
            ),
        };
        let mut sec = SecurityExtension::default();
        sec.subject = Some(SubjectExtension {
            id: Some("alice@corp.com".into()),
            ..Default::default()
        });
        let mut meta = MetaExtension::default();
        meta.entity_type = Some("tool".into());
        meta.entity_name = Some("get_compensation".into());
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            meta: Some(Arc::new(meta)),
            ..Default::default()
        };

        let record = plugin.build_record(&payload, &ext);
        assert_eq!(record["subject"]["id"], "alice@corp.com");
        assert_eq!(record["entity"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["args"]["employee_id"], "EMP-001234");
        // Always-allow contract: handler returns continue_processing.
        let mut ctx = PluginContext::default();
        let r = plugin.handle(&payload, &ext, &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.violation.is_none());
    }
}
