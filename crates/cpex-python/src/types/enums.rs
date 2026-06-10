// Location: ./crates/cpex-python/src/types/enums.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// PyO3 enum wrappers for PluginMode and OnError.

use pyo3::prelude::*;

use cpex_core::plugin::{OnError, PluginMode};

/// Python wrapper for PluginMode enum.
///
/// Execution modes determine scheduling behavior and authority:
/// - SEQUENTIAL: serial, chained, blocking + modifying
/// - TRANSFORM: serial, chained, modifying only
/// - AUDIT: serial, observe-only
/// - CONCURRENT: parallel, blocking only
/// - FIRE_AND_FORGET: background, no blocking/modifying
/// - DISABLED: plugin skipped
#[pyclass(name = "PluginMode")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PyPluginMode {
    inner: PluginMode,
}

#[pymethods]
impl PyPluginMode {
    #[classattr]
    const SEQUENTIAL: &'static str = "sequential";
    
    #[classattr]
    const TRANSFORM: &'static str = "transform";
    
    #[classattr]
    const AUDIT: &'static str = "audit";
    
    #[classattr]
    const CONCURRENT: &'static str = "concurrent";
    
    #[classattr]
    const FIRE_AND_FORGET: &'static str = "fire_and_forget";
    
    #[classattr]
    const DISABLED: &'static str = "disabled";

    /// Create from string value.
    #[staticmethod]
    fn from_str(value: &str) -> PyResult<Self> {
        let inner = match value {
            "sequential" => PluginMode::Sequential,
            "transform" => PluginMode::Transform,
            "audit" => PluginMode::Audit,
            "concurrent" => PluginMode::Concurrent,
            "fire_and_forget" => PluginMode::FireAndForget,
            "disabled" => PluginMode::Disabled,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid plugin mode: {}", value),
                ))
            }
        };
        Ok(Self { inner })
    }

    /// Convert to string value.
    fn to_str(&self) -> &'static str {
        match self.inner {
            PluginMode::Sequential => "sequential",
            PluginMode::Transform => "transform",
            PluginMode::Audit => "audit",
            PluginMode::Concurrent => "concurrent",
            PluginMode::FireAndForget => "fire_and_forget",
            PluginMode::Disabled => "disabled",
            _ => "unknown",
        }
    }

    /// Whether this mode allows blocking the pipeline.
    fn can_block(&self) -> bool {
        self.inner.can_block()
    }

    /// Whether this mode allows modifying the payload.
    fn can_modify(&self) -> bool {
        self.inner.can_modify()
    }

    /// Whether the framework waits for this plugin to complete.
    fn is_awaited(&self) -> bool {
        self.inner.is_awaited()
    }

    fn __str__(&self) -> &'static str {
        self.to_str()
    }

    fn __repr__(&self) -> String {
        format!("PluginMode('{}')", self.to_str())
    }
}

impl From<PluginMode> for PyPluginMode {
    fn from(inner: PluginMode) -> Self {
        Self { inner }
    }
}

impl From<PyPluginMode> for PluginMode {
    fn from(py_mode: PyPluginMode) -> Self {
        py_mode.inner
    }
}

impl PyPluginMode {
    /// Get string representation (Rust-side method).
    pub fn as_str(&self) -> &'static str {
        match self.inner {
            PluginMode::Sequential => "sequential",
            PluginMode::Transform => "transform",
            PluginMode::Audit => "audit",
            PluginMode::Concurrent => "concurrent",
            PluginMode::FireAndForget => "fire_and_forget",
            PluginMode::Disabled => "disabled",
            _ => "unknown",
        }
    }
}

/// Python wrapper for OnError enum.
///
/// Error handling behavior when a plugin fails:
/// - FAIL: pipeline halts and error propagates
/// - IGNORE: error logged, pipeline continues
/// - DISABLE: plugin auto-disabled after error
#[pyclass(name = "OnError")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PyOnError {
    inner: OnError,
}

#[pymethods]
impl PyOnError {
    #[classattr]
    const FAIL: &'static str = "fail";
    
    #[classattr]
    const IGNORE: &'static str = "ignore";
    
    #[classattr]
    const DISABLE: &'static str = "disable";

    /// Create from string value.
    #[staticmethod]
    fn from_str(value: &str) -> PyResult<Self> {
        let inner = match value {
            "fail" => OnError::Fail,
            "ignore" => OnError::Ignore,
            "disable" => OnError::Disable,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Invalid on_error value: {}", value),
                ))
            }
        };
        Ok(Self { inner })
    }

    /// Convert to string value.
    fn to_str(&self) -> &'static str {
        match self.inner {
            OnError::Fail => "fail",
            OnError::Ignore => "ignore",
            OnError::Disable => "disable",
            _ => "unknown",
        }
    }

    fn __str__(&self) -> &'static str {
        self.to_str()
    }

    fn __repr__(&self) -> String {
        format!("OnError('{}')", self.to_str())
    }
}

impl From<OnError> for PyOnError {
    fn from(inner: OnError) -> Self {
        Self { inner }
    }
}

impl From<PyOnError> for OnError {
    fn from(py_error: PyOnError) -> Self {
        py_error.inner
    }
}

// Made with Bob
