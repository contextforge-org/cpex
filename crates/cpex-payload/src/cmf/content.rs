// Location: ./crates/cpex-core/src/cmf/content.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CMF domain objects and ContentPart hierarchy.
//
// Domain objects (ToolCall, Resource, etc.) are standalone structs
// reusable outside of message content parts. ContentPart is a tagged
// enum that wraps them for message serialization.
//
// Mirrors the Python types in cpex/framework/cmf/message.py.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::enums::ResourceType;
use super::message::Message;

// ---------------------------------------------------------------------------
// Domain Objects
// ---------------------------------------------------------------------------

/// Normalized tool/function invocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique request correlation ID.
    pub tool_call_id: String,
    /// Tool name.
    pub name: String,
    /// Arguments as a JSON-serializable map.
    #[serde(default)]
    pub arguments: HashMap<String, serde_json::Value>,
    /// Optional namespace for namespaced tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Result from tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Correlation ID linking to the corresponding tool call.
    pub tool_call_id: String,
    /// Name of the tool that was executed.
    pub tool_name: String,
    /// Result content (any JSON-serializable value).
    #[serde(default)]
    pub content: serde_json::Value,
    /// Whether the result represents an error.
    #[serde(default)]
    pub is_error: bool,
}

/// Embedded resource with content (MCP).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resource {
    /// Unique request correlation ID.
    pub resource_request_id: String,
    /// Unique identifier in URI format.
    pub uri: String,
    /// Human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What this resource contains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The kind of resource.
    pub resource_type: ResourceType,
    /// Text content if embedded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Binary content if embedded (base64 in JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<Vec<u8>>,
    /// MIME type of content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Size information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Metadata (classification, retention, etc.).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, serde_json::Value>,
    /// Version tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Resource {
    /// Whether content or blob is embedded.
    pub fn is_embedded(&self) -> bool {
        self.content.is_some() || self.blob.is_some()
    }

    /// Get text content if available.
    pub fn get_text_content(&self) -> Option<&str> {
        self.content.as_deref()
    }
}

/// Lightweight resource reference without embedded content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReference {
    /// Correlation ID linking to the originating resource request.
    pub resource_request_id: String,
    /// Resource URI.
    pub uri: String,
    /// Human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Type of resource.
    pub resource_type: ResourceType,
    /// Line number or byte offset for partial references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_start: Option<u64>,
    /// End of range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_end: Option<u64>,
    /// CSS/XPath/JSONPath selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

/// Prompt template invocation request (MCP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRequest {
    /// Request ID for correlation.
    pub prompt_request_id: String,
    /// Prompt template name.
    pub name: String,
    /// Arguments to pass to the template.
    #[serde(default)]
    pub arguments: HashMap<String, serde_json::Value>,
    /// Source server for multi-server scenarios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}

/// Rendered prompt template result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptResult {
    /// ID of the corresponding prompt request.
    pub prompt_request_id: String,
    /// Name of the prompt that was rendered.
    pub prompt_name: String,
    /// Rendered messages (prompts produce messages).
    #[serde(default)]
    pub messages: Vec<Message>,
    /// Single text result for simple prompts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Whether rendering failed.
    #[serde(default)]
    pub is_error: bool,
    /// Error details if rendering failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Media Source Types
// ---------------------------------------------------------------------------

/// Image source data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSource {
    /// Source type: "url" or "base64".
    #[serde(rename = "type")]
    pub source_type: String,
    /// URL or base64-encoded string.
    pub data: String,
    /// MIME type (e.g., image/jpeg).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// Video source data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoSource {
    /// Source type: "url" or "base64".
    #[serde(rename = "type")]
    pub source_type: String,
    /// URL or base64-encoded string.
    pub data: String,
    /// MIME type (e.g., video/mp4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Audio source data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioSource {
    /// Source type: "url" or "base64".
    #[serde(rename = "type")]
    pub source_type: String,
    /// URL or base64-encoded string.
    pub data: String,
    /// MIME type (e.g., audio/mp3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Document source data (PDF, Word, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSource {
    /// Source type: "url" or "base64".
    #[serde(rename = "type")]
    pub source_type: String,
    /// URL or base64-encoded string.
    pub data: String,
    /// MIME type (e.g., application/pdf).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Document title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

// ---------------------------------------------------------------------------
// ContentPart — Tagged Enum
// ---------------------------------------------------------------------------

/// A typed content part in a CMF message.
///
/// Discriminated by the `content_type` field. Each variant wraps
/// either a text string or a domain object.
///
/// Mirrors the Python `ContentPartUnion` discriminated union in
/// `cpex/framework/cmf/message.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "content_type")]
pub enum ContentPart {
    /// Plain text content.
    #[serde(rename = "text")]
    Text { text: String },

    /// Chain-of-thought reasoning.
    #[serde(rename = "thinking")]
    Thinking { text: String },

    /// Tool/function invocation request.
    #[serde(rename = "tool_call")]
    ToolCall { content: ToolCall },

    /// Result from tool execution.
    #[serde(rename = "tool_result")]
    ToolResult { content: ToolResult },

    /// Embedded resource with content.
    #[serde(rename = "resource")]
    Resource { content: Resource },

    /// Lightweight resource reference.
    #[serde(rename = "resource_ref")]
    ResourceRef { content: ResourceReference },

    /// Prompt template invocation request.
    #[serde(rename = "prompt_request")]
    PromptRequest { content: PromptRequest },

    /// Rendered prompt template result.
    #[serde(rename = "prompt_result")]
    PromptResult { content: PromptResult },

    /// Image content.
    #[serde(rename = "image")]
    Image { content: ImageSource },

    /// Video content.
    #[serde(rename = "video")]
    Video { content: VideoSource },

    /// Audio content.
    #[serde(rename = "audio")]
    Audio { content: AudioSource },

    /// Document content.
    #[serde(rename = "document")]
    Document { content: DocumentSource },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_content_part_serde() {
        let json = r#"{"content_type":"text","text":"Hello, world!"}"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::Text { text } => assert_eq!(text, "Hello, world!"),
            _ => panic!("expected Text variant"),
        }
        let roundtrip = serde_json::to_string(&part).unwrap();
        let part2: ContentPart = serde_json::from_str(&roundtrip).unwrap();
        match part2 {
            ContentPart::Text { text } => assert_eq!(text, "Hello, world!"),
            _ => panic!("expected Text variant"),
        }
    }

    #[test]
    fn test_tool_call_content_part_serde() {
        let json = r#"{
            "content_type": "tool_call",
            "content": {
                "tool_call_id": "tc_001",
                "name": "get_weather",
                "arguments": {"city": "London"}
            }
        }"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::ToolCall { content } => {
                assert_eq!(content.name, "get_weather");
                assert_eq!(content.tool_call_id, "tc_001");
                assert_eq!(content.arguments["city"], "London");
            }
            _ => panic!("expected ToolCall variant"),
        }
    }

    #[test]
    fn test_tool_result_content_part_serde() {
        let json = r#"{
            "content_type": "tool_result",
            "content": {
                "tool_call_id": "tc_001",
                "tool_name": "get_weather",
                "content": {"temp": 20, "unit": "C"},
                "is_error": false
            }
        }"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::ToolResult { content } => {
                assert_eq!(content.tool_name, "get_weather");
                assert!(!content.is_error);
            }
            _ => panic!("expected ToolResult variant"),
        }
    }

    #[test]
    fn test_resource_content_part_serde() {
        let json = r#"{
            "content_type": "resource",
            "content": {
                "resource_request_id": "rr_001",
                "uri": "file:///data.txt",
                "resource_type": "file",
                "content": "Hello from file"
            }
        }"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::Resource { content } => {
                assert_eq!(content.uri, "file:///data.txt");
                assert!(content.is_embedded());
                assert_eq!(content.get_text_content(), Some("Hello from file"));
            }
            _ => panic!("expected Resource variant"),
        }
    }

    #[test]
    fn test_resource_ref_content_part_serde() {
        let json = r#"{
            "content_type": "resource_ref",
            "content": {
                "resource_request_id": "rr_002",
                "uri": "db://users/42",
                "resource_type": "database"
            }
        }"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::ResourceRef { content } => {
                assert_eq!(content.uri, "db://users/42");
                assert_eq!(content.resource_type, ResourceType::Database);
            }
            _ => panic!("expected ResourceRef variant"),
        }
    }

    #[test]
    fn test_image_content_part_serde() {
        let json = r#"{
            "content_type": "image",
            "content": {
                "type": "url",
                "data": "https://example.com/photo.jpg",
                "media_type": "image/jpeg"
            }
        }"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::Image { content } => {
                assert_eq!(content.source_type, "url");
                assert_eq!(content.data, "https://example.com/photo.jpg");
            }
            _ => panic!("expected Image variant"),
        }
    }

    #[test]
    fn test_prompt_request_content_part_serde() {
        let json = r#"{
            "content_type": "prompt_request",
            "content": {
                "prompt_request_id": "pr_001",
                "name": "summarize",
                "arguments": {"text": "Long document..."}
            }
        }"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::PromptRequest { content } => {
                assert_eq!(content.name, "summarize");
            }
            _ => panic!("expected PromptRequest variant"),
        }
    }

    #[test]
    fn test_thinking_content_part_serde() {
        let json = r#"{"content_type":"thinking","text":"Let me analyze..."}"#;
        let part: ContentPart = serde_json::from_str(json).unwrap();
        match &part {
            ContentPart::Thinking { text } => assert_eq!(text, "Let me analyze..."),
            _ => panic!("expected Thinking variant"),
        }
    }

    #[test]
    fn test_tool_call_construction() {
        let tc = ToolCall {
            tool_call_id: "tc_001".into(),
            name: "search".into(),
            arguments: [("query".to_string(), serde_json::json!("rust"))].into(),
            namespace: None,
        };
        assert_eq!(tc.name, "search");
        assert_eq!(tc.arguments["query"], "rust");
    }

    #[test]
    fn test_resource_is_embedded() {
        let embedded = Resource {
            resource_request_id: "rr_001".into(),
            uri: "file:///data.txt".into(),
            name: None,
            description: None,
            resource_type: ResourceType::File,
            content: Some("data".into()),
            blob: None,
            mime_type: None,
            size_bytes: None,
            annotations: HashMap::new(),
            version: None,
        };
        assert!(embedded.is_embedded());

        let not_embedded = Resource {
            resource_request_id: "rr_002".into(),
            uri: "file:///other.txt".into(),
            name: None,
            description: None,
            resource_type: ResourceType::File,
            content: None,
            blob: None,
            mime_type: None,
            size_bytes: None,
            annotations: HashMap::new(),
            version: None,
        };
        assert!(!not_embedded.is_embedded());
    }
}
