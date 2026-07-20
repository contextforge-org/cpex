// Location: ./crates/cpex-core/src/hooks/prompts.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy prompt-lifecycle payloads.
//
// These mirror the Python framework's `cpex/framework/hooks/prompts.py`
// (`PromptPrehookPayload`, `PromptPosthookPayload`) so the isolated Python
// plugin host can send correctly-typed payloads for the bare (legacy) hook
// names `prompt_pre_fetch` / `prompt_post_fetch`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PromptPrehookPayload
// ---------------------------------------------------------------------------

/// Payload for the legacy `prompt_pre_fetch` hook.
///
/// Mirrors Python `PromptPrehookPayload`: `prompt_id` is required; `args`
/// is optional (Python defaults it to an empty dict of `str -> str`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptPrehookPayload {
    /// The prompt identifier.
    pub prompt_id: String,
    /// The prompt template arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
}

crate::impl_plugin_payload!(PromptPrehookPayload);

// ---------------------------------------------------------------------------
// PromptPosthookPayload
// ---------------------------------------------------------------------------

/// Payload for the legacy `prompt_post_fetch` hook.
///
/// Mirrors Python `PromptPosthookPayload`: `prompt_id` and `result` are both
/// required (`result` is `Any` on the Python side → `serde_json::Value`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptPosthookPayload {
    /// The prompt identifier.
    pub prompt_id: String,
    /// The rendered prompt result.
    pub result: serde_json::Value,
}

crate::impl_plugin_payload!(PromptPosthookPayload);
