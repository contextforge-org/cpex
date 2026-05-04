// Location: ./crates/cpex-core/src/error.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Error types for the CPEX plugin framework.
//
// Provides structured error types for plugin execution failures,
// policy violations, timeouts, and configuration errors. Mirrors
// the Python framework's PluginError, PluginViolation, and
// PluginViolationError types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Plugin Errors
// ---------------------------------------------------------------------------

/// Top-level error type for the CPEX framework.
///
/// Covers plugin execution failures, policy violations, timeouts,
/// and configuration issues. Each variant carries enough context
/// for the caller to log, report, or recover.
///
/// Mirrors the Python framework's `PluginErrorModel` with:
/// - `code` — business-logic error code (e.g., `"rate_limit_exceeded"`)
/// - `details` — structured diagnostic data for logging
/// - `proto_error_code` — protocol-level error code for the host to
///   map back to the wire format (MCP JSON-RPC, HTTP status, etc.)
#[derive(Debug, Error)]
pub enum PluginError {
    /// A plugin raised an execution error.
    #[error("plugin '{plugin_name}' failed: {message}")]
    Execution {
        plugin_name: String,
        message: String,
        /// Business-logic error code (e.g., `"invalid_token"`).
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        /// Business-logic error code set by the plugin.
        code: Option<String>,
        /// Structured diagnostic data for logging or debugging.
        details: HashMap<String, serde_json::Value>,
        /// Protocol-level error code for the host to map to the wire
        /// format. MCP: JSON-RPC codes (e.g., -32603). HTTP: status
        /// codes. The host interprets this; CPEX just carries it.
        proto_error_code: Option<i64>,
    },

    /// A plugin exceeded its execution timeout.
    #[error("plugin '{plugin_name}' timed out after {timeout_ms}ms")]
    Timeout {
        plugin_name: String,
        timeout_ms: u64,
        /// Protocol-level error code for the host.
        proto_error_code: Option<i64>,
    },

    /// A plugin returned a policy violation (deny).
    #[error("plugin '{plugin_name}' denied: {}", violation.reason)]
    Violation {
        plugin_name: String,
        violation: PluginViolation,
    },

    /// Configuration parsing or validation failed.
    #[error("configuration error: {message}")]
    Config { message: String },

    /// A hook type was not found in the registry.
    #[error("unknown hook type: {hook_type}")]
    UnknownHook { hook_type: String },
}

// ---------------------------------------------------------------------------
// Plugin Violations
// ---------------------------------------------------------------------------

/// Structured policy violation returned by a plugin that denies execution.
///
/// Carries a machine-readable code, human-readable reason, and optional
/// diagnostic details. Corresponds to the Python `PluginViolation` type.
///
/// # Examples
///
/// ```
/// use cpex_core::error::PluginViolation;
///
/// let v = PluginViolation::new("missing_permission", "User lacks pii_access");
/// assert_eq!(v.code, "missing_permission");
/// assert_eq!(v.reason, "User lacks pii_access");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginViolation {
    /// Machine-readable violation identifier (e.g., `"missing_permission"`).
    pub code: String,

    /// Short human-readable reason for the denial.
    pub reason: String,

    /// Optional detailed explanation.
    pub description: Option<String>,

    /// Structured diagnostic data for logging or debugging.
    pub details: HashMap<String, serde_json::Value>,

    /// Name of the plugin that produced the violation.
    /// Set by the framework after the plugin returns, not by the plugin itself.
    pub plugin_name: Option<String>,

    /// Protocol-level error code for the host to map to the wire format.
    /// MCP: JSON-RPC codes (e.g., -32603). HTTP: status codes (e.g., 403).
    /// Set by the plugin; the host interprets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto_error_code: Option<i64>,
}

impl PluginViolation {
    /// Create a new violation with a code and reason.
    pub fn new(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
            description: None,
            details: HashMap::new(),
            plugin_name: None,
            proto_error_code: None,
        }
    }

    /// Attach a detailed description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Attach structured diagnostic details.
    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = details;
        self
    }

    /// Attach a protocol-level error code.
    pub fn with_proto_error_code(mut self, code: i64) -> Self {
        self.proto_error_code = Some(code);
        self
    }
}

impl std::fmt::Display for PluginViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.reason)
    }
}
