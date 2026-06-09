// Location: ./crates/cpex-core/src/extensions/agent.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// AgentExtension — session, conversation, agent lineage.
// Mirrors cpex/framework/extensions/agent.py.

use serde::{Deserialize, Serialize};

/// Conversation history context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationContext {
    /// Recent conversation history (lightweight summaries).
    #[serde(default)]
    pub history: Vec<serde_json::Value>,

    /// LLM-generated summary of the conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Detected topics in the conversation.
    #[serde(default)]
    pub topics: Vec<String>,
}

/// Agent execution context extension.
///
/// Carries session tracking, conversation context, multi-agent
/// lineage, and the original user/agent input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentExtension {
    /// Original user/agent input that triggered this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,

    /// Broad user/agent session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Specific dialogue/task identifier within a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,

    /// Position within the conversation (0-indexed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<u32>,

    /// Identifier of the agent that produced this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// If spawned by another agent, the parent's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent_id: Option<String>,

    /// Optional conversation context with history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<ConversationContext>,
}
