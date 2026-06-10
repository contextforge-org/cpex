// Location: ./crates/cpex-python/src/types/result.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Python bindings for PluginResult.
//!
//! Provides a non-generic Python wrapper for the Rust PluginResult<P> type.
//! Since Python doesn't have generics, we store the payload as PyObject.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use cpex_core::error::PluginViolation;

/// Python wrapper for PluginResult.
///
/// Represents the decision a plugin makes about a hook invocation:
/// - Allow: continue processing (no changes or with modifications)
/// - Deny: halt the pipeline with a violation
///
/// # Examples (Python)
///
/// ```python
/// # Allow with no changes
/// result = PluginResult.allow()
///
/// # Deny with violation
/// result = PluginResult.deny("forbidden", "Access denied")
///
/// # Modify payload
/// modified_payload = payload.model_copy(update={"field": "new_value"})
/// result = PluginResult.modify_payload(modified_payload)
/// ```
#[pyclass(name = "PluginResult")]
#[derive(Clone)]
pub struct PyPluginResult {
    /// Whether the pipeline should continue processing.
    continue_processing: bool,
    
    /// Modified payload (if any).
    modified_payload: Option<PyObject>,
    
    /// Modified extensions (if any) - stored as dict.
    modified_extensions: Option<PyObject>,
    
    /// Violation details (if denied).
    violation_code: Option<String>,
    violation_reason: Option<String>,
    
    /// Optional metadata.
    metadata: Option<PyObject>,
}

#[pymethods]
impl PyPluginResult {
    /// Create an allow result (no changes).
    #[staticmethod]
    fn allow() -> Self {
        Self {
            continue_processing: true,
            modified_payload: None,
            modified_extensions: None,
            violation_code: None,
            violation_reason: None,
            metadata: None,
        }
    }

    /// Create a deny result with violation.
    ///
    /// Args:
    ///     code: Violation code (e.g., "forbidden", "invalid_input")
    ///     reason: Human-readable reason for denial
    #[staticmethod]
    fn deny(code: String, reason: String) -> Self {
        Self {
            continue_processing: false,
            modified_payload: None,
            modified_extensions: None,
            violation_code: Some(code),
            violation_reason: Some(reason),
            metadata: None,
        }
    }

    /// Create a result with modified payload.
    ///
    /// Args:
    ///     payload: Modified payload object
    #[staticmethod]
    fn modify_payload(payload: PyObject) -> Self {
        Self {
            continue_processing: true,
            modified_payload: Some(payload),
            modified_extensions: None,
            violation_code: None,
            violation_reason: None,
            metadata: None,
        }
    }

    /// Create a result with modified extensions.
    ///
    /// Args:
    ///     extensions: Modified extensions dict
    #[staticmethod]
    fn modify_extensions(extensions: PyObject) -> Self {
        Self {
            continue_processing: true,
            modified_payload: None,
            modified_extensions: Some(extensions),
            violation_code: None,
            violation_reason: None,
            metadata: None,
        }
    }

    /// Create a result with both modified payload and extensions.
    ///
    /// Args:
    ///     payload: Modified payload object
    ///     extensions: Modified extensions dict
    #[staticmethod]
    fn modify(payload: PyObject, extensions: PyObject) -> Self {
        Self {
            continue_processing: true,
            modified_payload: Some(payload),
            modified_extensions: Some(extensions),
            violation_code: None,
            violation_reason: None,
            metadata: None,
        }
    }

    /// Whether this result represents a denial.
    #[getter]
    fn is_denied(&self) -> bool {
        !self.continue_processing
    }

    /// Whether this result carries a modified payload.
    #[getter]
    fn is_payload_modified(&self) -> bool {
        self.modified_payload.is_some()
    }

    /// Whether this result carries modified extensions.
    #[getter]
    fn is_extensions_modified(&self) -> bool {
        self.modified_extensions.is_some()
    }

    /// Get the continue_processing flag.
    #[getter]
    fn continue_processing(&self) -> bool {
        self.continue_processing
    }

    /// Get the modified payload (if any).
    #[getter]
    fn modified_payload(&self, py: Python) -> Option<PyObject> {
        self.modified_payload.as_ref().map(|obj| obj.clone_ref(py))
    }

    /// Get the modified extensions (if any).
    #[getter]
    fn modified_extensions(&self, py: Python) -> Option<PyObject> {
        self.modified_extensions.as_ref().map(|obj| obj.clone_ref(py))
    }

    /// Get the violation code (if denied).
    #[getter]
    fn violation_code(&self) -> Option<String> {
        self.violation_code.clone()
    }

    /// Get the violation reason (if denied).
    #[getter]
    fn violation_reason(&self) -> Option<String> {
        self.violation_reason.clone()
    }

    /// Get the metadata (if any).
    #[getter]
    fn metadata(&self, py: Python) -> Option<PyObject> {
        self.metadata.as_ref().map(|obj| obj.clone_ref(py))
    }

    /// Set metadata.
    #[setter]
    fn set_metadata(&mut self, metadata: Option<PyObject>) {
        self.metadata = metadata;
    }

    /// String representation.
    fn __repr__(&self) -> String {
        if self.is_denied() {
            format!(
                "PluginResult(denied, code='{}', reason='{}')",
                self.violation_code.as_deref().unwrap_or("unknown"),
                self.violation_reason.as_deref().unwrap_or("no reason")
            )
        } else if self.is_payload_modified() && self.is_extensions_modified() {
            "PluginResult(allow, modified_payload=True, modified_extensions=True)".to_string()
        } else if self.is_payload_modified() {
            "PluginResult(allow, modified_payload=True)".to_string()
        } else if self.is_extensions_modified() {
            "PluginResult(allow, modified_extensions=True)".to_string()
        } else {
            "PluginResult(allow)".to_string()
        }
    }

    /// String conversion.
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl PyPluginResult {
    /// Create from Rust PluginViolation (for deny results).
    pub fn from_violation(violation: PluginViolation) -> Self {
        Self::deny(violation.code, violation.reason)
    }

    /// Check if this is an allow result.
    pub fn is_allow(&self) -> bool {
        self.continue_processing
    }
}

// Made with Bob
