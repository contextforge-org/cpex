// Location: ./crates/cpex-hosts-python/src/error.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Host-internal errors and their mapping to `cpex_core::error::PluginError`.
//
// The host distinguishes failure modes the executor cannot see — a venv that
// would not build, a worker that died mid-flight, a task over the size cap —
// so operators get an actionable reason. At the trait boundary each maps to a
// `PluginError`, and the *executor* applies the configured error policy
// (fail / ignore / disable). The host never implements that policy itself.

use std::fmt;

use cpex_core::error::PluginError;

/// A failure inside the host, before or around the plugin's own logic.
#[derive(Debug)]
pub enum HostError {
    /// The plugin's configuration cannot support a venv (no plugin dirs, an
    /// unusable class name).
    Config { message: String },

    /// Building the virtualenv or installing its requirements failed.
    VenvBuild { message: String },

    /// The worker subprocess could not be launched.
    WorkerStart { message: String },

    /// The worker process is gone — reader EOF, or a non-zero exit — while a
    /// request was outstanding. Distinct from a timeout: there is nothing
    /// left to wait for.
    WorkerDied { message: String },

    /// No response arrived within the per-invocation timeout.
    Timeout { timeout_secs: u64 },

    /// The serialized task exceeded the configured `max_content_size`. Caught
    /// before the write, so nothing was sent.
    TaskTooLarge { size: usize, limit: usize },

    /// The worker returned a structured error response for this request.
    WorkerError { message: String },

    /// A payload or response could not be serialized or parsed.
    ///
    /// The message must never carry payload *values* — see the note on
    /// `Self::redacted_detail`.
    Protocol { message: String },

    /// A credential-bearing hook could not be served safely, so the host
    /// failed closed rather than dispatching without the token.
    ///
    /// The message never contains token material.
    Credential { message: String },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config { message } => write!(f, "configuration error: {message}"),
            Self::VenvBuild { message } => write!(f, "venv build failed: {message}"),
            Self::WorkerStart { message } => write!(f, "worker failed to start: {message}"),
            Self::WorkerDied { message } => write!(f, "worker process died: {message}"),
            Self::Timeout { timeout_secs } => {
                write!(f, "worker did not respond within {timeout_secs}s")
            },
            Self::TaskTooLarge { size, limit } => write!(
                f,
                "serialized task is {size} bytes, over the {limit}-byte max_content_size"
            ),
            Self::WorkerError { message } => write!(f, "worker returned an error: {message}"),
            Self::Protocol { message } => write!(f, "protocol error: {message}"),
            Self::Credential { message } => write!(f, "credential error: {message}"),
        }
    }
}

impl std::error::Error for HostError {}

impl HostError {
    /// Short, stable code for the `PluginError::Execution.code` field, so a
    /// host can branch on the failure mode without string-matching messages.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config { .. } => "config",
            Self::VenvBuild { .. } => "venv_build_failed",
            Self::WorkerStart { .. } => "worker_start_failed",
            Self::WorkerDied { .. } => "worker_died",
            Self::Timeout { .. } => "timeout",
            Self::TaskTooLarge { .. } => "task_too_large",
            Self::WorkerError { .. } => "worker_error",
            Self::Protocol { .. } => "protocol_error",
            Self::Credential { .. } => "credential_error",
        }
    }

    /// Convert to the framework error type for a named plugin.
    ///
    /// A timeout becomes `PluginError::Timeout` so the executor's existing
    /// timeout accounting applies; a config fault becomes
    /// `PluginError::Config`; everything else is an `Execution` error the
    /// executor routes through the plugin's `on_error` policy.
    pub fn into_plugin_error(self, plugin_name: &str) -> Box<PluginError> {
        match self {
            Self::Timeout { timeout_secs } => PluginError::Timeout {
                plugin_name: plugin_name.to_string(),
                timeout_ms: timeout_secs.saturating_mul(1000),
                proto_error_code: None,
            }
            .boxed(),

            Self::Config { ref message } => PluginError::Config {
                message: format!("plugin '{plugin_name}' (isolated_venv): {message}"),
            }
            .boxed(),

            other => {
                let code = other.code();
                PluginError::Execution {
                    plugin_name: plugin_name.to_string(),
                    message: other.to_string(),
                    source: None,
                    code: Some(code.to_string()),
                    details: Default::default(),
                    proto_error_code: None,
                }
                .boxed()
            },
        }
    }
}
