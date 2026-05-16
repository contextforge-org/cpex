// Location: ./integrations/authbridge/ffi/src/llm_pii_redactor.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// llm-pii-redactor — CPEX plugin that scans the LLM prompt text for
// configured PII regexes and replaces matches with [REDACTED:<name>].
//
// Reads / writes:
//   - payload.message.content[*] (CMF message — the LLM prompt text, built
//     by cpex-runtime's bridge from pctx.Extensions.Inference.Messages)
//   - On match: returns PluginResult::modify_payload(...) with the
//     rewritten payload. cpex-runtime then re-serializes that into the
//     outbound LLM JSON body and calls pctx.SetBody, which auto-emits
//     a modify-action Invocation + body-mutation/event.
//
// YAML config:
//   - name: llm-pii-redactor
//     config:
//       patterns:
//         email: '\b[\w.+-]+@[\w-]+\.[\w.-]+\b'
//         ssn:   '\b\d{3}-\d{2}-\d{4}\b'
//
// Each `<name>: <regex>` entry redacts matches to `[REDACTED:<name>]`.
// Compilation happens once at factory create-time; per-request cost is
// just the regex scan.
//
// Registers under hook `cmf.llm_input` — cpex-runtime invokes that hook
// when AuthBridge's outbound pctx has Extensions.Inference populated.

use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::cmf::{ContentPart, Message, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::factory::{PluginFactory, PluginInstance};
use cpex_core::hooks::adapter::TypedHandlerAdapter;
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{Plugin, PluginConfig};
use regex::Regex;

use crate::scope_tool_gate::CmfHook;

/// A single named pattern. `name` becomes part of the redaction marker
/// (`[REDACTED:<name>]`) so operators can tell which rule fired from a
/// body diff alone.
struct CompiledPattern {
    name: String,
    re: Regex,
}

struct LlmPiiRedactor {
    cfg: PluginConfig,
    patterns: Vec<CompiledPattern>,
}

#[async_trait]
impl Plugin for LlmPiiRedactor {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for LlmPiiRedactor {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        if self.patterns.is_empty() {
            return PluginResult::allow();
        }

        // Walk content parts. We only rewrite Text/Thinking parts (the
        // ones that carry inspectable strings); structured parts like
        // tool_call/resource pass through untouched.
        let mut mutated = false;
        let mut new_content: Vec<ContentPart> = Vec::with_capacity(payload.message.content.len());
        for part in &payload.message.content {
            match part {
                ContentPart::Text { text } => {
                    let (redacted, changed) = redact(text, &self.patterns);
                    if changed {
                        mutated = true;
                    }
                    new_content.push(ContentPart::Text { text: redacted });
                }
                ContentPart::Thinking { text } => {
                    let (redacted, changed) = redact(text, &self.patterns);
                    if changed {
                        mutated = true;
                    }
                    new_content.push(ContentPart::Thinking { text: redacted });
                }
                other => new_content.push(other.clone()),
            }
        }

        if !mutated {
            tracing::debug!("[llm-pii-redactor] no matches — allow");
            return PluginResult::allow();
        }

        tracing::info!("[llm-pii-redactor] redacted PII matches in LLM prompt");
        let new_payload = MessagePayload {
            message: Message {
                schema_version: payload.message.schema_version.clone(),
                role: payload.message.role.clone(),
                content: new_content,
                channel: payload.message.channel.clone(),
            },
        };
        PluginResult::modify_payload(new_payload)
    }
}

/// Apply every compiled pattern to `text` in order. Returns the
/// possibly-rewritten string and a flag indicating whether anything
/// changed (so the caller can skip the payload-clone when no rule fired).
fn redact(text: &str, patterns: &[CompiledPattern]) -> (String, bool) {
    let mut current = text.to_string();
    let mut changed = false;
    for p in patterns {
        let replacement = format!("[REDACTED:{}]", p.name);
        let after = p.re.replace_all(&current, replacement.as_str()).into_owned();
        if after != current {
            changed = true;
            current = after;
        }
    }
    (current, changed)
}

struct LlmPiiRedactorFactory;

impl PluginFactory for LlmPiiRedactorFactory {
    fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
        // Decode `patterns: { name: regex }` map from the opaque config.
        // Missing → empty (plugin becomes a no-op). Invalid regex → fail
        // the boot loudly (better than silently never redacting).
        let mut compiled: Vec<CompiledPattern> = Vec::new();
        if let Some(map) = config
            .config
            .as_ref()
            .and_then(|v| v.get("patterns"))
            .and_then(|v| v.as_object())
        {
            for (name, raw) in map.iter() {
                let pattern = raw.as_str().ok_or_else(|| {
                    Box::new(PluginError::Config {
                        message: format!(
                            "llm-pii-redactor: patterns.{} must be a string",
                            name
                        ),
                    })
                })?;
                let re = Regex::new(pattern).map_err(|e| {
                    Box::new(PluginError::Config {
                        message: format!(
                            "llm-pii-redactor: patterns.{} is not a valid regex: {}",
                            name, e
                        ),
                    })
                })?;
                compiled.push(CompiledPattern { name: name.clone(), re });
            }
        }

        tracing::info!(
            "[llm-pii-redactor] compiled {} pattern(s): {:?}",
            compiled.len(),
            compiled.iter().map(|p| &p.name).collect::<Vec<_>>()
        );

        let plugin = Arc::new(LlmPiiRedactor {
            cfg: config.clone(),
            patterns: compiled,
        });
        Ok(PluginInstance {
            plugin: plugin.clone(),
            handlers: vec![(
                "cmf.llm_input",
                Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin)),
            )],
        })
    }
}

pub fn register(manager: &mut PluginManager) {
    manager.register_factory("llm-pii-redactor", Box::new(LlmPiiRedactorFactory));
}
