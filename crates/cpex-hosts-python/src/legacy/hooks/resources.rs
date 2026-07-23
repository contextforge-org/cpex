// Location: ./crates/cpex-hosts-python/src/legacy/hooks/resources.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy resource-lifecycle payloads.
//
// These mirror the Python framework's `cpex/framework/hooks/resources.py`
// (`ResourcePreFetchPayload`, `ResourcePostFetchPayload`) so the isolated
// Python plugin host can send correctly-typed payloads for the bare (legacy)
// hook names `resource_pre_fetch` / `resource_post_fetch`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ResourcePreFetchPayload
// ---------------------------------------------------------------------------

/// Payload for the legacy `resource_pre_fetch` hook.
///
/// Mirrors Python `ResourcePreFetchPayload`: `uri` is required; `metadata`
/// is optional (Python defaults it to an empty dict).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePreFetchPayload {
    /// The resource URI.
    pub uri: String,
    /// Optional metadata for the resource request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

cpex_core::impl_plugin_payload!(ResourcePreFetchPayload);

// ---------------------------------------------------------------------------
// ResourcePostFetchPayload
// ---------------------------------------------------------------------------

/// Payload for the legacy `resource_post_fetch` hook.
///
/// Mirrors Python `ResourcePostFetchPayload`: `uri` and `content` are both
/// required (`content` is `Any` on the Python side → `serde_json::Value`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePostFetchPayload {
    /// The resource URI.
    pub uri: String,
    /// The fetched resource content.
    pub content: serde_json::Value,
}

cpex_core::impl_plugin_payload!(ResourcePostFetchPayload);
