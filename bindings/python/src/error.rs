// Location: ./bindings/python/src/error.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Maps Rust PluginError variants to Python exception types (R2, KD9).

use cpex_core::error::PluginError;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::PyErr;

/// Convert a `Box<PluginError>` into the appropriate Python exception.
///
/// Mapping (per C2, KD9):
///   Config / UnknownHook → `ValueError`   (config/conversion failures)
///   Timeout              → `TimeoutError`
///   Execution / other    → `RuntimeError`
///
/// Note: `PluginError::Violation` is unreachable on the `invoke_by_name`
/// path — denials surface as `PipelineResult { continue_processing: false,
/// violation: Some(...) }`, never as an `Err`. Kept here as a defensive
/// catch-all that maps to `RuntimeError`.
#[allow(clippy::boxed_local)]
pub fn plugin_error_to_pyerr(e: Box<PluginError>) -> PyErr {
    match *e {
        PluginError::Config { message } => {
            PyValueError::new_err(format!("cpex config error: {message}"))
        },
        PluginError::UnknownHook { hook_type } => {
            PyValueError::new_err(format!("cpex unknown hook type: {hook_type}"))
        },
        PluginError::Timeout {
            plugin_name,
            timeout_ms,
            ..
        } => PyTimeoutError::new_err(format!(
            "cpex plugin '{plugin_name}' timed out after {timeout_ms}ms"
        )),
        // Violation is dead on the invoke_by_name path (KD9); treat defensively.
        PluginError::Violation {
            plugin_name,
            violation,
        } => PyRuntimeError::new_err(format!(
            "cpex plugin '{plugin_name}' denied: {}",
            violation.reason
        )),
        PluginError::Execution {
            plugin_name,
            message,
            ..
        } => PyRuntimeError::new_err(format!(
            "cpex plugin '{plugin_name}' execution error: {message}"
        )),
    }
}
