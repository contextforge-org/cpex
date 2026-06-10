// Location: ./crates/cpex-python/src/error.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Error conversion from Rust to Python exceptions.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use cpex_core::error::PluginError;

/// Convert a Rust PluginError to a Python exception.
///
/// Maps different error variants to appropriate Python exception types:
/// - Config errors → ValueError
/// - Execution errors → RuntimeError
/// - Timeout errors → RuntimeError
/// - Violation errors → RuntimeError
/// - Unknown hook → ValueError
pub fn plugin_error_to_pyerr(err: &PluginError) -> PyErr {
    match err {
        PluginError::Config { message } => {
            PyValueError::new_err(format!("Config error: {}", message))
        }
        PluginError::Execution {
            plugin_name,
            message,
            code,
            ..
        } => {
            let code_str = code.as_deref().unwrap_or("unknown");
            PyRuntimeError::new_err(format!(
                "Plugin '{}' execution failed [{}]: {}",
                plugin_name, code_str, message
            ))
        }
        PluginError::Timeout {
            plugin_name,
            timeout_ms,
            ..
        } => PyRuntimeError::new_err(format!(
            "Plugin '{}' timed out after {}ms",
            plugin_name, timeout_ms
        )),
        PluginError::Violation {
            plugin_name,
            violation,
        } => PyRuntimeError::new_err(format!(
            "Plugin '{}' violation: {}",
            plugin_name, violation.reason
        )),
        PluginError::UnknownHook { hook_type } => {
            PyValueError::new_err(format!("Unknown hook type: {}", hook_type))
        }
    }
}

/// Convert a boxed PluginError to a Python exception.
pub fn boxed_plugin_error_to_pyerr(err: &Box<PluginError>) -> PyErr {
    plugin_error_to_pyerr(err.as_ref())
}

// Made with Bob
