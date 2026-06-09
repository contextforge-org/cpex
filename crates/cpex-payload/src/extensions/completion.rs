// Location: ./crates/cpex-core/src/extensions/completion.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CompletionExtension — LLM completion information.
// Mirrors cpex/framework/extensions/completion.py.

use serde::{Deserialize, Serialize};

/// Why the model stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Natural end of message.
    End,
    /// Complete response (Harmony format).
    Return,
    /// Tool/function invocation.
    Call,
    /// Hit token limit.
    MaxTokens,
    /// Hit custom stop sequence.
    StopSequence,
}

/// Token usage statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Input tokens consumed.
    #[serde(default)]
    pub input_tokens: u32,

    /// Output tokens generated.
    #[serde(default)]
    pub output_tokens: u32,

    /// Total tokens (input + output).
    #[serde(default)]
    pub total_tokens: u32,
}

/// LLM completion information.
///
/// Immutable — set after the LLM responds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompletionExtension {
    /// Why the model stopped generating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,

    /// Token usage statistics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenUsage>,

    /// Model identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Raw response format (chatml, harmony, gemini, anthropic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_format: Option<String>,

    /// Creation timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    /// Response latency in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}
