// Location: ./crates/cpex-core/src/cmf/message.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CMF Message — canonical message representation.
//
// A Message is the storage and wire format for a single turn in a
// conversation. It preserves structure exactly as the LLM or
// framework sent it.
//
// Extensions are NOT part of the Message. They are passed separately
// to handlers via the framework's Extensions type. This allows
// extensions to be shared across payload types and avoids copying
// the message when extensions change.
//
// Mirrors the Python Message in cpex/framework/cmf/message.py.

use serde::{Deserialize, Serialize};

use super::content::*;
use super::enums::{Channel, Role};
use crate::hooks::trait_def::PluginResult;

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// Canonical CMF message representing a single turn in a conversation.
///
/// All content is carried as typed ContentPart variants. Extensions
/// (identity, security, HTTP, agent context) are passed separately
/// to handlers — not inside the message.
///
/// Mirrors the Python `Message` in `cpex/framework/cmf/message.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Who is speaking.
    pub role: Role,

    /// List of typed content parts (multimodal).
    #[serde(default)]
    pub content: Vec<ContentPart>,

    /// Optional output classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
}

fn default_schema_version() -> String {
    super::constants::SCHEMA_VERSION.to_string()
}

impl Message {
    /// Create a simple text message.
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            schema_version: super::constants::SCHEMA_VERSION.to_string(),
            role,
            content: vec![ContentPart::Text { text: text.into() }],
            channel: None,
        }
    }

    /// Extract all text content from the message.
    ///
    /// Concatenates text from all `Text` content parts.
    pub fn get_text_content(&self) -> String {
        let mut texts = Vec::new();
        for part in &self.content {
            if let ContentPart::Text { text } = part {
                texts.push(text.as_str());
            }
        }
        texts.join("")
    }

    /// Extract thinking/reasoning content if present.
    pub fn get_thinking_content(&self) -> Option<String> {
        let mut texts = Vec::new();
        for part in &self.content {
            if let ContentPart::Thinking { text } = part {
                texts.push(text.as_str());
            }
        }
        if texts.is_empty() {
            None
        } else {
            Some(texts.join(""))
        }
    }

    /// Get all tool calls in this message.
    pub fn get_tool_calls(&self) -> Vec<&ToolCall> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::ToolCall { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all tool results in this message.
    pub fn get_tool_results(&self) -> Vec<&ToolResult> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::ToolResult { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Whether this message contains any tool calls.
    pub fn is_tool_call(&self) -> bool {
        self.content
            .iter()
            .any(|p| matches!(p, ContentPart::ToolCall { .. }))
    }

    /// Whether this message contains any tool results.
    pub fn is_tool_result(&self) -> bool {
        self.content
            .iter()
            .any(|p| matches!(p, ContentPart::ToolResult { .. }))
    }

    /// Get all embedded resources in this message.
    pub fn get_resources(&self) -> Vec<&Resource> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Resource { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all resource references in this message.
    pub fn get_resource_refs(&self) -> Vec<&ResourceReference> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::ResourceRef { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all resource URIs (both embedded and references).
    pub fn get_all_resource_uris(&self) -> Vec<&str> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Resource { content } => Some(content.uri.as_str()),
                ContentPart::ResourceRef { content } => Some(content.uri.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Whether this message contains any resources or resource references.
    pub fn has_resources(&self) -> bool {
        self.content.iter().any(|p| {
            matches!(
                p,
                ContentPart::Resource { .. } | ContentPart::ResourceRef { .. }
            )
        })
    }

    /// Get all prompt requests in this message.
    pub fn get_prompt_requests(&self) -> Vec<&PromptRequest> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::PromptRequest { content } => Some(content),
                _ => None,
            })
            .collect()
    }

    /// Get all prompt results in this message.
    pub fn get_prompt_results(&self) -> Vec<&PromptResult> {
        self.content
            .iter()
            .filter_map(|part| match part {
                ContentPart::PromptResult { content } => Some(content),
                _ => None,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// MessagePayload — PluginPayload wrapper
// ---------------------------------------------------------------------------

/// CMF Message wrapped as a PluginPayload for hook dispatch.
///
/// This is the payload type for all `cmf.*` hooks. Plugins that
/// handle CMF hooks implement `HookHandler<CmfHook>` and receive
/// `&MessagePayload` in their handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    /// The CMF message.
    pub message: Message,
}

crate::impl_plugin_payload!(MessagePayload);

// ---------------------------------------------------------------------------
// CmfHook — Hook Type Definition
// ---------------------------------------------------------------------------

crate::define_hook! {
    /// CMF message evaluation hook.
    ///
    /// Plugins implement `HookHandler<CmfHook>` and register under
    /// one or more `cmf.*` hook names (e.g., `cmf.tool_pre_invoke`,
    /// `cmf.llm_input`). The same handler covers all CMF hook points.
    CmfHook, "cmf" => {
        payload: MessagePayload,
        result: PluginResult<MessagePayload>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::payload::PluginPayload;
    use crate::hooks::trait_def::HookTypeDef;

    #[test]
    fn test_message_text_helper() {
        let msg = Message::text(Role::User, "What is the weather?");
        assert_eq!(msg.get_text_content(), "What is the weather?");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.schema_version, "2.0");
    }

    #[test]
    fn test_message_multi_part_text() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Hello ".into(),
                },
                ContentPart::Text {
                    text: "world!".into(),
                },
            ],
            channel: None,
        };
        assert_eq!(msg.get_text_content(), "Hello world!");
    }

    #[test]
    fn test_message_thinking_content() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Thinking {
                    text: "Let me think...".into(),
                },
                ContentPart::Text {
                    text: "Here's my answer.".into(),
                },
            ],
            channel: Some(Channel::Final),
        };
        assert_eq!(
            msg.get_thinking_content(),
            Some("Let me think...".to_string())
        );
        assert_eq!(msg.get_text_content(), "Here's my answer.");
    }

    #[test]
    fn test_message_tool_calls() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Text {
                    text: "Let me check.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "get_weather".into(),
                        arguments: [("city".to_string(), serde_json::json!("London"))].into(),
                        namespace: None,
                    },
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_002".into(),
                        name: "get_time".into(),
                        arguments: [("timezone".to_string(), serde_json::json!("UTC"))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: None,
        };
        assert!(msg.is_tool_call());
        assert!(!msg.is_tool_result());
        let calls = msg.get_tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "get_weather");
        assert_eq!(calls[1].name, "get_time");
    }

    #[test]
    fn test_message_tool_results() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Tool,
            content: vec![ContentPart::ToolResult {
                content: ToolResult {
                    tool_call_id: "tc_001".into(),
                    tool_name: "get_weather".into(),
                    content: serde_json::json!({"temp": 20}),
                    is_error: false,
                },
            }],
            channel: None,
        };
        assert!(msg.is_tool_result());
        assert!(!msg.is_tool_call());
        let results = msg.get_tool_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool_name, "get_weather");
    }

    #[test]
    fn test_message_resources() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Resource {
                    content: Resource {
                        resource_request_id: "rr_001".into(),
                        uri: "file:///data.txt".into(),
                        name: Some("Data File".into()),
                        description: None,
                        resource_type: super::super::enums::ResourceType::File,
                        content: Some("file contents".into()),
                        blob: None,
                        mime_type: None,
                        size_bytes: None,
                        annotations: std::collections::HashMap::new(),
                        version: None,
                    },
                },
                ContentPart::ResourceRef {
                    content: ResourceReference {
                        resource_request_id: "rr_002".into(),
                        uri: "db://users/42".into(),
                        name: None,
                        resource_type: super::super::enums::ResourceType::Database,
                        range_start: None,
                        range_end: None,
                        selector: None,
                    },
                },
            ],
            channel: None,
        };
        assert!(msg.has_resources());
        assert_eq!(msg.get_resources().len(), 1);
        assert_eq!(msg.get_resource_refs().len(), 1);
        let uris = msg.get_all_resource_uris();
        assert_eq!(uris.len(), 2);
        assert!(uris.contains(&"file:///data.txt"));
        assert!(uris.contains(&"db://users/42"));
    }

    #[test]
    fn test_message_no_resources() {
        let msg = Message::text(Role::User, "Hello");
        assert!(!msg.has_resources());
        assert!(msg.get_resources().is_empty());
    }

    #[test]
    fn test_message_serde_roundtrip() {
        let msg = Message {
            schema_version: "2.0".into(),
            role: Role::Assistant,
            content: vec![
                ContentPart::Thinking {
                    text: "Analyzing...".into(),
                },
                ContentPart::Text {
                    text: "Here's the answer.".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_001".into(),
                        name: "search".into(),
                        arguments: [("q".to_string(), serde_json::json!("rust"))].into(),
                        namespace: None,
                    },
                },
            ],
            channel: Some(Channel::Final),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.role, Role::Assistant);
        assert_eq!(deserialized.schema_version, "2.0");
        assert_eq!(deserialized.channel, Some(Channel::Final));
        assert_eq!(deserialized.content.len(), 3);
        assert_eq!(deserialized.get_text_content(), "Here's the answer.");
        assert_eq!(deserialized.get_tool_calls().len(), 1);
    }

    #[test]
    fn test_message_payload_as_plugin_payload() {
        let payload = MessagePayload {
            message: Message::text(Role::User, "Hello"),
        };

        // Test clone_boxed
        let boxed: Box<dyn PluginPayload> = Box::new(payload.clone());
        let cloned = boxed.clone_boxed();

        // Test as_any downcast
        let downcasted = cloned
            .as_any()
            .downcast_ref::<MessagePayload>()
            .expect("should downcast to MessagePayload");
        assert_eq!(downcasted.message.get_text_content(), "Hello");
    }

    #[test]
    fn test_cmf_hook_type_def() {
        assert_eq!(CmfHook::NAME, "cmf");
    }

    #[test]
    fn test_message_default_schema_version() {
        let json = r#"{"role":"user","content":[]}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.schema_version, "2.0");
    }
}
