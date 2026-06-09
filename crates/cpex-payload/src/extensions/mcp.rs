// Location: ./crates/cpex-core/src/extensions/mcp.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MCPExtension — tool, resource, or prompt metadata.
// Mirrors cpex/framework/extensions/mcp.py.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// MCP tool metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolMetadata {
    /// Tool name.
    pub name: String,

    /// Human-readable title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Tool description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Input JSON schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,

    /// Output JSON schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,

    /// Source server ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,

    /// Tool namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Tool annotations.
    #[serde(default)]
    pub annotations: HashMap<String, serde_json::Value>,
}

/// MCP resource metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMetadata {
    /// Resource URI.
    pub uri: String,

    /// Human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Resource description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// MIME type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Source server ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,

    /// Resource annotations.
    #[serde(default)]
    pub annotations: HashMap<String, serde_json::Value>,
}

/// MCP prompt metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptMetadata {
    /// Prompt name.
    pub name: String,

    /// Prompt description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Prompt arguments schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<serde_json::Value>>,

    /// Source server ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,

    /// Prompt annotations.
    #[serde(default)]
    pub annotations: HashMap<String, serde_json::Value>,
}

/// MCP-specific metadata extension.
///
/// Carries tool, resource, or prompt metadata for the entity
/// being processed. Immutable — set by the host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MCPExtension {
    /// Tool metadata (if this message involves a tool).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolMetadata>,

    /// Resource metadata (if this message involves a resource).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceMetadata>,

    /// Prompt metadata (if this message involves a prompt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<PromptMetadata>,
}
