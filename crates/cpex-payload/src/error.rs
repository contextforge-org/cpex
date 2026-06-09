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

impl PluginError {
    /// Box this error for use in `Result<T, Box<PluginError>>`.
    ///
    /// Public APIs return `Result<T, Box<PluginError>>` rather than
    /// `Result<T, Box<PluginError>>` because the enum is large (~184 bytes
    /// — `details: HashMap` and the `source: Box<dyn Error>` push it
    /// well past clippy's `result_large_err` threshold). Boxing keeps
    /// `Result<T, _>` pointer-sized on the success path; the
    /// allocation only happens on the error path.
    ///
    /// `.boxed()` is sugar for `Box::new(...)` that reads better at
    /// construction sites: `PluginError::Config { ... }.boxed()`.
    /// `?` already calls `From::from`, and `From<T> for Box<T>` is
    /// built into std, so existing `?` chains keep working.
    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

// ---------------------------------------------------------------------------
// Plugin Error Record
// ---------------------------------------------------------------------------

/// A `Clone`-able, serialization-friendly snapshot of a `PluginError`.
///
/// Used in `PipelineResult.errors` to surface execution failures from
/// `on_error: ignore` / `on_error: disable` plugins to the caller —
/// previously those errors were only logged via `tracing::warn!` and
/// were invisible to programmatic consumers (agents, dashboards,
/// retry logic).
///
/// `PluginError` itself can't be `Clone` because of its
/// `Box<dyn std::error::Error + Send + Sync>` source field, and that
/// field doesn't survive serialization anyway. `PluginErrorRecord`
/// flattens the five enum variants into a single shape — the
/// `From<&PluginError>` impl handles the variant-to-fields mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginErrorRecord {
    pub plugin_name: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto_error_code: Option<i64>,
}

/// Forward `&Box<PluginError>` to the `&PluginError` impl.
///
/// Public APIs return `Result<T, Box<PluginError>>` (see
/// `PluginError::boxed`), which means error-handling code in the
/// pipeline (e.g., `Ok(Err(e))` inside `executor::run_*_phase`) holds
/// `e: Box<PluginError>`. This blanket forward keeps existing
/// `(&e).into()` call sites working without forcing every caller to
/// write `(&*e).into()` after the boxing migration.
impl From<&Box<PluginError>> for PluginErrorRecord {
    fn from(e: &Box<PluginError>) -> Self {
        PluginErrorRecord::from(e.as_ref())
    }
}

impl From<&PluginError> for PluginErrorRecord {
    fn from(e: &PluginError) -> Self {
        match e {
            PluginError::Execution {
                plugin_name,
                message,
                code,
                details,
                proto_error_code,
                ..
            } => Self {
                plugin_name: plugin_name.clone(),
                message: message.clone(),
                code: code.clone(),
                details: details.clone(),
                proto_error_code: *proto_error_code,
            },
            PluginError::Timeout {
                plugin_name,
                timeout_ms,
                proto_error_code,
            } => Self {
                plugin_name: plugin_name.clone(),
                message: format!("plugin timed out after {}ms", timeout_ms),
                code: Some("timeout".into()),
                details: HashMap::new(),
                proto_error_code: *proto_error_code,
            },
            PluginError::Violation {
                plugin_name,
                violation,
            } => Self {
                plugin_name: plugin_name.clone(),
                message: format!("plugin denied: {}", violation.reason),
                code: Some(violation.code.clone()),
                details: violation.details.clone(),
                proto_error_code: violation.proto_error_code,
            },
            PluginError::Config { message } => Self {
                plugin_name: String::new(),
                message: message.clone(),
                code: Some("config".into()),
                details: HashMap::new(),
                proto_error_code: None,
            },
            PluginError::UnknownHook { hook_type } => Self {
                plugin_name: String::new(),
                message: format!("unknown hook type: {}", hook_type),
                code: Some("unknown_hook".into()),
                details: HashMap::new(),
                proto_error_code: None,
            },
        }
    }
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
