// Location: ./crates/apl-pii-scanner/src/scanner.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;

use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::hooks::payload::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::config::{PiiPattern, PiiScanMode, PiiScannerConfig};

/// CMF plugin that walks the message's ToolCall / PromptRequest /
/// ResourceRef arguments and tests each string value against the
/// configured PII patterns.
#[derive(Debug)]
pub struct PiiScanner {
    cfg: PluginConfig,
    typed: PiiScannerConfig,
    /// Compiled regexes paired with the pattern name (for violation
    /// attribution). Compiled once at construction; matched per call.
    patterns: Vec<(String, Regex)>,
}

impl PiiScanner {
    pub fn new(cfg: PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = cfg.config.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}' (apl-pii-scanner) requires a `config:` block",
                    cfg.name
                ),
            })
        })?;
        let typed: PiiScannerConfig =
            serde_json::from_value(raw.clone()).map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}' (apl-pii-scanner) config parse failed: {e}",
                        cfg.name
                    ),
                })
            })?;

        let patterns = compile_patterns(&typed.detect, &cfg.name)?;
        Ok(Self { cfg, typed, patterns })
    }

    /// Scan every string value in the message's structured content
    /// (ToolCall.arguments, PromptRequest.arguments) plus any text
    /// parts. Returns the name of the first matching pattern, or
    /// `None` if no match. The pattern name flows into the violation
    /// code so audit logs say `pii.detected: ssn` rather than
    /// generic `pii.detected`.
    fn first_match(&self, message: &Message) -> Option<&str> {
        for part in &message.content {
            match part {
                ContentPart::ToolCall { content } => {
                    for v in content.arguments.values() {
                        if let Some(name) = self.match_value(v) {
                            return Some(name);
                        }
                    }
                }
                ContentPart::PromptRequest { content } => {
                    for v in content.arguments.values() {
                        if let Some(name) = self.match_value(v) {
                            return Some(name);
                        }
                    }
                }
                ContentPart::Text { text } => {
                    if let Some(name) = self.match_str(text) {
                        return Some(name);
                    }
                }
                _ => {} // images / video / audio / etc. — out of scope for v0
            }
        }
        None
    }

    fn match_value(&self, v: &Value) -> Option<&str> {
        match v {
            Value::String(s) => self.match_str(s),
            // Numbers / bools can't carry PII patterns. Arrays /
            // objects could be walked recursively in a future
            // version; for now we only flag flat string fields,
            // which covers the common LLM tool-call shape.
            _ => None,
        }
    }

    fn match_str(&self, s: &str) -> Option<&str> {
        for (name, re) in &self.patterns {
            if re.is_match(s) {
                return Some(name);
            }
        }
        None
    }

    /// Rewrite the message's content: replace any string value that
    /// matches a pattern with `[PII]`. Used in `redact` mode.
    fn redact_message(&self, message: &mut Message) {
        for part in message.content.iter_mut() {
            match part {
                ContentPart::ToolCall { content } => {
                    for v in content.arguments.values_mut() {
                        self.redact_value(v);
                    }
                }
                ContentPart::PromptRequest { content } => {
                    for v in content.arguments.values_mut() {
                        self.redact_value(v);
                    }
                }
                ContentPart::Text { text } => {
                    if self.match_str(text).is_some() {
                        *text = "[PII]".to_string();
                    }
                }
                _ => {}
            }
        }
    }

    fn redact_value(&self, v: &mut Value) {
        if let Value::String(s) = v {
            if self.match_str(s).is_some() {
                *v = Value::String("[PII]".to_string());
            }
        }
    }
}

fn compile_patterns(
    patterns: &[PiiPattern],
    plugin_name: &str,
) -> Result<Vec<(String, Regex)>, Box<PluginError>> {
    let mut out = Vec::with_capacity(patterns.len());
    for p in patterns {
        let (name, re_str) = match p {
            PiiPattern::Ssn => ("ssn", r"\b\d{3}-\d{2}-\d{4}\b".to_string()),
            PiiPattern::CreditCard => (
                "credit_card",
                // 13-19 digit sequences with optional spaces / hyphens
                // every 4 digits. Liberal — Luhn validation would
                // tighten this but isn't needed for the demo signal.
                r"\b(?:\d[ -]?){13,19}\b".to_string(),
            ),
            PiiPattern::Email => (
                "email",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string(),
            ),
            PiiPattern::Custom { name, regex } => (name.as_str(), regex.clone()),
        };
        let re = Regex::new(&re_str).map_err(|e| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{plugin_name}' (apl-pii-scanner): pattern '{name}' \
                     failed to compile: {e}"
                ),
            })
        })?;
        out.push((name.to_string(), re));
    }
    Ok(out)
}

#[async_trait]
impl Plugin for PiiScanner {
    fn config(&self) -> &PluginConfig {
        &self.cfg
    }
}

impl HookHandler<CmfHook> for PiiScanner {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _ext: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let hit = self.first_match(&payload.message);
        match (hit, self.typed.mode) {
            (None, _) => PluginResult::allow(),
            (Some(pattern_name), PiiScanMode::Deny) => {
                PluginResult::deny(PluginViolation::new(
                    "pii.detected",
                    format!(
                        "PII pattern '{pattern_name}' detected in request \
                         args — refusing to forward to downstream"
                    ),
                ))
            }
            (Some(_), PiiScanMode::Redact) => {
                let mut updated = payload.clone();
                self.redact_message(&mut updated.message);
                PluginResult::modify_payload(updated)
            }
        }
    }
}

// Silence unused-import in case a feature is added later that needs
// Arc — kept for parity with how other crates structure their imports.
#[allow(dead_code)]
fn _force_link_arc(_: Arc<()>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::{Role, ToolCall};
    use cpex_core::plugin::{OnError, PluginConfig, PluginMode};
    use serde_json::json;
    use std::collections::HashMap;

    fn cfg(detect: Vec<PiiPattern>, mode: PiiScanMode) -> PluginConfig {
        let cfg_json = serde_json::to_value(PiiScannerConfig { detect, mode }).unwrap();
        PluginConfig {
            name: "pii-scan".into(),
            kind: "test".into(),
            hooks: vec!["cmf.tool_pre_invoke".into()],
            mode: PluginMode::Sequential,
            priority: 10,
            on_error: OnError::Fail,
            config: Some(cfg_json),
            ..Default::default()
        }
    }

    fn message_with_args(args: HashMap<String, serde_json::Value>) -> MessagePayload {
        MessagePayload {
            message: Message::with_content(
                Role::User,
                vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "1".into(),
                        name: "send_email".into(),
                        arguments: args,
                        namespace: None,
                    },
                }],
            ),
        }
    }

    #[tokio::test]
    async fn ssn_in_args_denied() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = message_with_args(HashMap::from([
            ("body".to_string(), json!("Her SSN is 555-12-3456")),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing, "should deny");
        let v = r.violation.expect("violation present");
        assert_eq!(v.code, "pii.detected");
        assert!(v.reason.contains("ssn"));
    }

    #[tokio::test]
    async fn clean_args_allowed() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Deny)).unwrap();
        let payload = message_with_args(HashMap::from([
            ("body".to_string(), json!("Quarterly compensation review summary.")),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(r.continue_processing);
        assert!(r.modified_payload.is_none());
    }

    #[tokio::test]
    async fn redact_mode_rewrites_value() {
        let p = PiiScanner::new(cfg(vec![PiiPattern::Ssn], PiiScanMode::Redact)).unwrap();
        let payload = message_with_args(HashMap::from([
            ("body".to_string(), json!("555-12-3456")),
            ("subject".to_string(), json!("payroll question")),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(r.continue_processing, "redact allows; doesn't deny");
        let modified = r.modified_payload.expect("payload was modified");
        let args = match &modified.message.content[0] {
            ContentPart::ToolCall { content } => &content.arguments,
            _ => panic!("expected ToolCall"),
        };
        assert_eq!(args["body"], json!("[PII]"));
        // Untouched fields preserved.
        assert_eq!(args["subject"], json!("payroll question"));
    }

    #[tokio::test]
    async fn custom_pattern() {
        let p = PiiScanner::new(cfg(
            vec![PiiPattern::Custom {
                name: "internal_id".into(),
                regex: r"^INT-[A-Z0-9]{6}$".into(),
            }],
            PiiScanMode::Deny,
        ))
        .unwrap();
        let payload = message_with_args(HashMap::from([
            ("ref".to_string(), json!("INT-ABC123")),
        ]));
        let mut ctx = PluginContext::default();
        let r = p.handle(&payload, &Extensions::default(), &mut ctx).await;
        assert!(!r.continue_processing);
        let v = r.violation.expect("violation present");
        assert!(v.reason.contains("internal_id"));
    }
}
