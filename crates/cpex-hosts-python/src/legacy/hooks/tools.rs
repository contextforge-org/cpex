// Location: ./crates/cpex-hosts-python/src/legacy/hooks/tools.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy tool-lifecycle payloads.
//
// These mirror the Python framework's `cpex/framework/hooks/tools.py`
// (`ToolPreInvokePayload`, `ToolPostInvokePayload`) so the isolated Python
// plugin host can send correctly-typed payloads for the bare (legacy) hook
// names `tool_pre_invoke` / `tool_post_invoke`. Field names and optionality
// match the Python pydantic models exactly so `model_validate` succeeds on
// the worker side.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ToolPreInvokePayload
// ---------------------------------------------------------------------------

/// Payload for the legacy `tool_pre_invoke` hook.
///
/// Mirrors Python `ToolPreInvokePayload`: `name` is required; `args` and
/// `headers` are optional (Python defaults `args` to an empty dict via
/// `Field(default_factory=dict)`, so omitting it is accepted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPreInvokePayload {
    /// The tool name.
    pub name: String,
    /// The tool arguments for invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
    /// HTTP pass-through headers (`HttpHeaderPayload` is a `dict[str, str]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

cpex_core::impl_plugin_payload!(ToolPreInvokePayload);

// ---------------------------------------------------------------------------
// ToolPostInvokePayload
// ---------------------------------------------------------------------------

/// Payload for the legacy `tool_post_invoke` hook.
///
/// Mirrors Python `ToolPostInvokePayload`: `name` and `result` are both
/// required (`result` is `Any` on the Python side → `serde_json::Value`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPostInvokePayload {
    /// The tool name.
    pub name: String,
    /// The tool invocation result.
    pub result: serde_json::Value,
}

cpex_core::impl_plugin_payload!(ToolPostInvokePayload);
