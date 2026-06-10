// Location: ./crates/cpex-python/src/types/extensions.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Python bindings for Extensions container.
//!
//! This is a simplified wrapper for Phase 2. Full extension type wrappers
//! (HttpExtension, SecurityExtension, etc.) will be added in later phases.

use cpex_core::extensions::Extensions;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Python wrapper for Extensions container.
///
/// Extensions is a typed container for all message extensions, with slots
/// for request metadata, security labels, HTTP headers, delegation chains, etc.
///
/// All slots are Arc-wrapped for zero-copy sharing. Plugins receive read-only
/// access via `&Extensions`. To modify, plugins call `cow_copy()` which returns
/// an `OwnedExtensions` with mutable slots cloned out.
///
/// This Phase 2 wrapper provides basic introspection. Full extension type
/// wrappers will be added in Phase 3.
#[pyclass(name = "Extensions")]
pub struct PyExtensions {
    pub(crate) inner: Extensions,
}

#[pymethods]
impl PyExtensions {
    /// Create a new empty Extensions container.
    #[new]
    fn new() -> Self {
        Self {
            inner: Extensions::default(),
        }
    }

    /// Check if the request extension is present.
    #[getter]
    fn has_request(&self) -> bool {
        self.inner.request.is_some()
    }

    /// Check if the agent extension is present.
    #[getter]
    fn has_agent(&self) -> bool {
        self.inner.agent.is_some()
    }

    /// Check if the HTTP extension is present.
    #[getter]
    fn has_http(&self) -> bool {
        self.inner.http.is_some()
    }

    /// Check if the security extension is present.
    #[getter]
    fn has_security(&self) -> bool {
        self.inner.security.is_some()
    }

    /// Check if the delegation extension is present.
    #[getter]
    fn has_delegation(&self) -> bool {
        self.inner.delegation.is_some()
    }

    /// Check if the raw_credentials extension is present.
    #[getter]
    fn has_raw_credentials(&self) -> bool {
        self.inner.raw_credentials.is_some()
    }

    /// Check if the MCP extension is present.
    #[getter]
    fn has_mcp(&self) -> bool {
        self.inner.mcp.is_some()
    }

    /// Check if the completion extension is present.
    #[getter]
    fn has_completion(&self) -> bool {
        self.inner.completion.is_some()
    }

    /// Check if the provenance extension is present.
    #[getter]
    fn has_provenance(&self) -> bool {
        self.inner.provenance.is_some()
    }

    /// Check if the LLM extension is present.
    #[getter]
    fn has_llm(&self) -> bool {
        self.inner.llm.is_some()
    }

    /// Check if the framework extension is present.
    #[getter]
    fn has_framework(&self) -> bool {
        self.inner.framework.is_some()
    }

    /// Check if the meta extension is present.
    #[getter]
    fn has_meta(&self) -> bool {
        self.inner.meta.is_some()
    }

    /// Check if custom extensions are present.
    #[getter]
    fn has_custom(&self) -> bool {
        self.inner.custom.is_some()
    }

    /// Get custom extensions as a dictionary (if present).
    ///
    /// Returns:
    ///     Dictionary of custom extension data, or None if not present
    fn get_custom(&self, py: Python) -> PyResult<Option<PyObject>> {
        if let Some(ref custom) = self.inner.custom {
            let dict = PyDict::new_bound(py);
            for (k, v) in custom.as_ref().iter() {
                let py_value = serde_json::to_string(v)
                    .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        format!("Failed to serialize custom value: {}", e)
                    ))?;
                dict.set_item(k, py_value)?;
            }
            Ok(Some(dict.into()))
        } else {
            Ok(None)
        }
    }

    /// Get a summary of which extension slots are populated.
    ///
    /// Returns:
    ///     Dictionary mapping slot names to boolean presence flags
    fn slot_summary(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);
        dict.set_item("request", self.inner.request.is_some())?;
        dict.set_item("agent", self.inner.agent.is_some())?;
        dict.set_item("http", self.inner.http.is_some())?;
        dict.set_item("security", self.inner.security.is_some())?;
        dict.set_item("delegation", self.inner.delegation.is_some())?;
        dict.set_item("raw_credentials", self.inner.raw_credentials.is_some())?;
        dict.set_item("mcp", self.inner.mcp.is_some())?;
        dict.set_item("completion", self.inner.completion.is_some())?;
        dict.set_item("provenance", self.inner.provenance.is_some())?;
        dict.set_item("llm", self.inner.llm.is_some())?;
        dict.set_item("framework", self.inner.framework.is_some())?;
        dict.set_item("meta", self.inner.meta.is_some())?;
        dict.set_item("custom", self.inner.custom.is_some())?;
        Ok(dict.into())
    }

    fn __repr__(&self) -> String {
        let mut slots = Vec::new();
        if self.inner.request.is_some() { slots.push("request"); }
        if self.inner.agent.is_some() { slots.push("agent"); }
        if self.inner.http.is_some() { slots.push("http"); }
        if self.inner.security.is_some() { slots.push("security"); }
        if self.inner.delegation.is_some() { slots.push("delegation"); }
        if self.inner.raw_credentials.is_some() { slots.push("raw_credentials"); }
        if self.inner.mcp.is_some() { slots.push("mcp"); }
        if self.inner.completion.is_some() { slots.push("completion"); }
        if self.inner.provenance.is_some() { slots.push("provenance"); }
        if self.inner.llm.is_some() { slots.push("llm"); }
        if self.inner.framework.is_some() { slots.push("framework"); }
        if self.inner.meta.is_some() { slots.push("meta"); }
        if self.inner.custom.is_some() { slots.push("custom"); }

        if slots.is_empty() {
            "Extensions(empty)".to_string()
        } else {
            format!("Extensions({})", slots.join(", "))
        }
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

// Conversion traits for Rust ↔ Python bridge
impl From<Extensions> for PyExtensions {
    fn from(inner: Extensions) -> Self {
        Self { inner }
    }
}

impl From<PyExtensions> for Extensions {
    fn from(py_ext: PyExtensions) -> Self {
        py_ext.inner
    }
}

// Made with Bob
