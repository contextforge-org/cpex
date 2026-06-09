// Location: ./crates/cpex-core/src/cmf/enums.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CMF enums — Role, Channel, ContentType, ResourceType.
//
// Mirrors the Python enums in cpex/framework/cmf/message.py.
// All use snake_case serialization to match Python string values.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

/// Identifies WHO is speaking in a conversation turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// System-level instructions.
    System,
    /// Developer-provided instructions.
    Developer,
    /// Human user input.
    User,
    /// LLM/agent response.
    Assistant,
    /// Tool execution result.
    Tool,
}

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// Classifies the kind of output a message represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Intermediate analytical output (chain-of-thought).
    Analysis,
    /// Meta-level observations about the task.
    Commentary,
    /// Terminal response intended for delivery.
    Final,
}

// ---------------------------------------------------------------------------
// ContentType
// ---------------------------------------------------------------------------

/// Discriminator for the typed ContentPart hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    /// Plain text content.
    Text,
    /// Chain-of-thought reasoning.
    Thinking,
    /// Tool/function invocation request.
    ToolCall,
    /// Result from tool execution.
    ToolResult,
    /// Embedded resource with content (MCP).
    Resource,
    /// Lightweight resource reference without embedded content.
    ResourceRef,
    /// Prompt template invocation request (MCP).
    PromptRequest,
    /// Rendered prompt template result.
    PromptResult,
    /// Image content (URL or base64).
    Image,
    /// Video content (URL or base64).
    Video,
    /// Audio content (URL or base64).
    Audio,
    /// Document content (PDF, Word, etc.).
    Document,
}

// ---------------------------------------------------------------------------
// ResourceType
// ---------------------------------------------------------------------------

/// Type of resource being referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// File-system resource.
    #[default]
    File,
    /// Binary large object.
    Blob,
    /// Generic URI-addressable resource.
    Uri,
    /// Database entity.
    Database,
    /// API endpoint.
    Api,
    /// In-memory or ephemeral resource.
    Memory,
    /// Produced artifact (generated output, build result).
    Artifact,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serde_roundtrip() {
        let role = Role::Assistant;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"assistant\"");
        let deserialized: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Role::Assistant);
    }

    #[test]
    fn test_channel_serde_roundtrip() {
        let channel = Channel::Final;
        let json = serde_json::to_string(&channel).unwrap();
        assert_eq!(json, "\"final\"");
        let deserialized: Channel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Channel::Final);
    }

    #[test]
    fn test_content_type_serde_roundtrip() {
        let ct = ContentType::ToolCall;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"tool_call\"");
        let deserialized: ContentType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ContentType::ToolCall);
    }

    #[test]
    fn test_content_type_resource_ref() {
        let ct = ContentType::ResourceRef;
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"resource_ref\"");
    }

    #[test]
    fn test_content_type_prompt_variants() {
        let req = ContentType::PromptRequest;
        let res = ContentType::PromptResult;
        assert_eq!(serde_json::to_string(&req).unwrap(), "\"prompt_request\"");
        assert_eq!(serde_json::to_string(&res).unwrap(), "\"prompt_result\"");
    }

    #[test]
    fn test_resource_type_serde_roundtrip() {
        let rt = ResourceType::Database;
        let json = serde_json::to_string(&rt).unwrap();
        assert_eq!(json, "\"database\"");
        let deserialized: ResourceType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ResourceType::Database);
    }

    #[test]
    fn test_all_roles_deserialize() {
        for (s, expected) in &[
            ("\"system\"", Role::System),
            ("\"developer\"", Role::Developer),
            ("\"user\"", Role::User),
            ("\"assistant\"", Role::Assistant),
            ("\"tool\"", Role::Tool),
        ] {
            let role: Role = serde_json::from_str(s).unwrap();
            assert_eq!(role, *expected);
        }
    }
}
