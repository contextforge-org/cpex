// Location: ./crates/cpex-core/src/extensions/request.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// RequestExtension — execution environment and tracing.
// Mirrors cpex/framework/extensions/request.py.

use serde::{Deserialize, Serialize};

/// Execution environment and request tracing.
///
/// Immutable — set by the host before invoking the hook.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestExtension {
    /// Deployment environment (e.g., "production", "staging").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Unique request identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Request timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    /// Distributed trace ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Span ID within the trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
}
