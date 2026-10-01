// Location: ./builtins/plugins/audit-logger/src/logger.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Map, Value};

use cpex_core::audit::AuditHandler;
use cpex_core::cmf::{CmfHook, ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::decision::{DecisionLog, Verdict};
use cpex_core::effect::EffectRecord;
use cpex_core::error::PluginError;
use cpex_core::hooks::payload::{Extensions, PluginPayload};
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
                        "plugin '{}' (cpex-plugin-audit-logger) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?,
            None => AuditLoggerConfig::default(),
        };
        Ok(Self { cfg, typed })
    }

    fn build_record(&self, payload: Option<&MessagePayload>, ext: &Extensions) -> Value {
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
        for part in payload.iter().flat_map(|p| p.message.content.iter()) {
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
                },
                ContentPart::PromptRequest { content } => {
                    record.insert(
                        "prompt_request".into(),
                        json!({
                            "name": content.name,
                            "args": content.arguments,
                        }),
                    );
                    break;
                },
                _ => {},
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
            },
            AuditDestination::Tracing => {
                tracing::info!(target: "apl.audit", record = %record, "audit");
            },
        }
    }
}

#[async_trait]
impl Plugin for AuditLogger {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }

    /// Auto-attach as a decision-audit sink when run in audit-only mode (no
    /// `hooks:` listed). If the operator listed hooks, this runs as a legacy
    /// CMF post-hook handler instead and does not also auto-attach, so
    /// records aren't emitted twice.
    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        if self.cfg.hooks.is_empty() {
            Some(self)
        } else {
            None
        }
    }
}

impl HookHandler<CmfHook> for AuditLogger {
    async fn handle(
        &self,
        payload: &MessagePayload,
        ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let record = self.build_record(Some(payload), ext);
        self.emit(&record);
        PluginResult::allow()
    }
}

impl AuditLogger {
    /// Build the decision-audit record: the same fields as the CMF
    /// observation record, plus the pipeline's verdict and the ordered
    /// plugin actions. `payload` is present only when this dispatch carried
    /// a CMF `MessagePayload` (audit sinks fire for every hook family).
    fn build_decision_record(
        &self,
        payload: Option<&MessagePayload>,
        ext: &Extensions,
        decisions: &DecisionLog,
    ) -> Value {
        let mut record = self.build_record(payload, ext);
        if let Value::Object(map) = &mut record {
            let verdict = match decisions.verdict() {
                Some(Verdict::Allow) => json!("allow"),
                Some(Verdict::Deny(v)) => json!({
                    "deny": { "code": v.code, "reason": v.reason }
                }),
                None => json!("pending"),
            };
            map.insert("verdict".into(), verdict);

            let steps: Vec<Value> = decisions
                .steps()
                .iter()
                .map(|s| {
                    json!({
                        "plugin": s.plugin_name,
                        "phase": format!("{:?}", s.phase),
                        "action": format!("{:?}", s.action),
                    })
                })
                .collect();
            map.insert("decision_steps".into(), json!(steps));

            // The invocation's node identity in the decision graph: its own
            // span, the upstream call that triggered it (causal parent), and
            // the trace they share. Downstream joins these into a causal DAG.
            if let Some(span) = decisions.span() {
                map.insert(
                    "span".into(),
                    json!({
                        "trace_id": span.trace_id,
                        "span_id": span.span_id,
                        "parent_span_id": span.parent_span_id,
                    }),
                );
            }

            // Taint provenance: the labels the request arrived with vs. the
            // labels after the pipeline. Their difference is the taint this
            // node added — a taint edge in the decision graph.
            let input_labels: Vec<&String> = decisions.input_labels().iter().collect();
            let final_labels: Vec<String> = ext
                .security
                .as_ref()
                .map(|s| {
                    let mut l: Vec<String> = s.labels.iter().cloned().collect();
                    l.sort_unstable();
                    l
                })
                .unwrap_or_default();
            if !input_labels.is_empty() || !final_labels.is_empty() {
                map.insert(
                    "taint".into(),
                    json!({ "input": input_labels, "final": final_labels }),
                );
            }

            // Content-addressed provenance: the input hash (captured at entry
            // when enabled) plus this node's output hash. Gated on input_hash
            // presence — when provenance is off it is `None` and we emit
            // neither. Only digests, never content.
            if let Some(input_hash) = decisions.input_hash() {
                let output_hash = payload
                    .and_then(|p| p.audit_bytes())
                    .map(|b| cpex_core::hooks::payload::content_hash(&b));
                map.insert(
                    "content".into(),
                    json!({ "input_hash": input_hash, "output_hash": output_hash }),
                );
            }

            // Stream identity + sequences. `stream_seq` is gap-free within the
            // decision stream (a consumer proves none was dropped); the global
            // `emission_seq` orders this record against the effect records a
            // consumer merges into the same chain.
            if let Some(stream_seq) = decisions.stream_seq() {
                map.insert("epoch".into(), json!(decisions.epoch()));
                map.insert("stream_id".into(), json!(decisions.stream_id()));
                map.insert("stream_seq".into(), json!(stream_seq));
                map.insert("emission_seq".into(), json!(decisions.emission_seq()));
            }
        }
        record
    }

    /// Build an audit record for an irreversible effect: the ambient identity
    /// / delegation context from `ext` (reusing `build_record`) plus the
    /// effect's own facts and lifecycle state.
    fn build_effect_record(&self, effect: &EffectRecord, ext: &Extensions) -> Value {
        // No payload — an effect is a side-effect, not a message. The ambient
        // context (subject, delegation) still comes from `ext`.
        let mut record = self.build_record(None, ext);
        if let Value::Object(map) = &mut record {
            map.insert(
                "effect".into(),
                json!({
                    "kind": effect.kind,
                    "description": effect.description,
                    "key": effect.key,
                    "state": format!("{:?}", effect.state),
                    "caused_by": effect.plugin_name,
                    "details": effect.details,
                    "epoch": effect.epoch,
                    "stream_id": effect.stream_id,
                    "stream_seq": effect.stream_seq,
                    "emission_seq": effect.emission_seq,
                }),
            );
        }
        record
    }
}

/// Decision-audit consumer: fires at the verdict of every pipeline run —
/// including denials — with the decision log. This is the first-class path;
/// the `HookHandler<CmfHook>` impl above remains for the legacy post-hook
/// registration.
#[async_trait]
impl AuditHandler for AuditLogger {
    async fn handle(&self, payload: &dyn PluginPayload, ext: &Extensions, decisions: &DecisionLog) {
        // Downcast to the CMF payload when present; a non-CMF dispatch
        // (delegation, identity) records without the message summary.
        let msg = payload.as_any().downcast_ref::<MessagePayload>();
        let record = self.build_decision_record(msg, ext, decisions);
        self.emit(&record);
    }

    async fn on_effect(&self, effect: &EffectRecord, ext: &Extensions) {
        let record = self.build_effect_record(effect, ext);
        self.emit(&record);
    }

    fn name(&self) -> &str {
        &self.cfg.name
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

        let record = plugin.build_record(Some(&payload), &ext);
        assert_eq!(record["subject"]["id"], "alice@corp.com");
        assert_eq!(record["entity"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["name"], "get_compensation");
        assert_eq!(record["tool_call"]["args"]["employee_id"], "EMP-001234");
        // Always-allow contract: handler returns continue_processing.
        let mut ctx = PluginContext::default();
        let r =
            <AuditLogger as HookHandler<CmfHook>>::handle(&plugin, &payload, &ext, &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.violation.is_none());
    }

    #[test]
    fn decision_record_includes_verdict_and_steps() {
        use cpex_core::decision::PluginAction;
        use cpex_core::error::PluginViolation;

        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.record("cedar-pdp", PluginMode::Sequential, PluginAction::Denied);
        log.finalize(Verdict::Deny(PluginViolation::new(
            "missing_permission",
            "not allowed",
        )));

        // No CMF payload on this dispatch — the record still carries the verdict.
        let record = plugin.build_decision_record(None, &Extensions::default(), &log);
        assert_eq!(record["verdict"]["deny"]["code"], "missing_permission");
        assert_eq!(record["decision_steps"][0]["plugin"], "cedar-pdp");
        assert_eq!(record["decision_steps"][0]["action"], "Denied");
        // No span was set on this log → no span field emitted.
        assert!(record.get("span").is_none());
    }

    #[test]
    fn decision_record_includes_span_when_set() {
        use cpex_core::decision::Span;

        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_span(Span::for_request(Some("trace-abc"), Some("upstream-span")));
        log.finalize(Verdict::Allow);

        let record = plugin.build_decision_record(None, &Extensions::default(), &log);
        assert_eq!(record["span"]["trace_id"], "trace-abc");
        assert_eq!(record["span"]["parent_span_id"], "upstream-span");
        assert!(record["span"]["span_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn decision_record_includes_taint_delta() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_input_labels(vec!["PII".into()]); // the request arrived carrying PII
        log.finalize(Verdict::Allow);

        // Final state: the pipeline added `secret`.
        let mut sec = SecurityExtension::default();
        sec.labels.insert("PII".into());
        sec.labels.insert("secret".into());
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        };

        let record = plugin.build_decision_record(None, &ext, &log);
        assert_eq!(record["taint"]["input"], serde_json::json!(["PII"]));
        assert_eq!(
            record["taint"]["final"],
            serde_json::json!(["PII", "secret"])
        );
    }

    #[test]
    fn decision_record_includes_content_hashes_when_captured() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_input_hash(Some("sha256:deadbeef".into()));
        log.finalize(Verdict::Allow);

        // No payload on this dispatch → output_hash is null, input present.
        let record = plugin.build_decision_record(None, &Extensions::default(), &log);
        assert_eq!(record["content"]["input_hash"], "sha256:deadbeef");
        assert!(record["content"]["output_hash"].is_null());
    }

    #[test]
    fn decision_record_includes_stream_and_sequences() {
        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.set_stream(1_700_000_000, "decision".into(), 7, 42);
        log.finalize(Verdict::Allow);

        let record = plugin.build_decision_record(None, &Extensions::default(), &log);
        assert_eq!(record["epoch"], 1_700_000_000u64);
        assert_eq!(record["stream_id"], "decision");
        assert_eq!(record["stream_seq"], 7);
        assert_eq!(record["emission_seq"], 42);
    }

    #[test]
    fn no_content_field_without_input_hash() {
        // Provenance off (input_hash None) → no content field at all.
        let plugin = AuditLogger::new(cfg()).unwrap();
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);
        let record = plugin.build_decision_record(None, &Extensions::default(), &log);
        assert!(record.get("content").is_none());
    }

    #[test]
    fn effect_record_carries_effect_and_ambient_identity() {
        use cpex_core::effect::EffectRecord;

        let plugin = AuditLogger::new(cfg()).unwrap();

        // Ambient context: a subject in extensions.
        let mut sec = SecurityExtension::default();
        sec.subject = Some(SubjectExtension {
            id: Some("alice@corp.com".into()),
            ..Default::default()
        });
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            ..Default::default()
        };

        let effect = EffectRecord::prepared("token_mint", "exchange for workday-api", "k-1")
            .with_detail("audience", "workday-api");

        let record = plugin.build_effect_record(&effect, &ext);
        // The effect's own facts…
        assert_eq!(record["effect"]["kind"], "token_mint");
        assert_eq!(record["effect"]["state"], "Prepared");
        assert_eq!(record["effect"]["details"]["audience"], "workday-api");
        // …alongside ambient identity from ext (the reason we pass ext):
        assert_eq!(record["subject"]["id"], "alice@corp.com");
    }
}
