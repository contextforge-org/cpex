// Location: ./crates/cpex-python/src/types/payload.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Python bindings for payload types.
//!
//! Phase 3 implementation: Simplified wrappers using JSON serialization
//! for Message content. Full ContentPart wrappers can be added later.

use cpex_core::cmf::{Message, MessagePayload};
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Python wrapper for MessagePayload.
///
/// MessagePayload is the unified payload type for all CMF hooks
/// (cmf.tool_*, cmf.llm_*, cmf.prompt_*, cmf.resource_*).
///
/// For Phase 3, the Message is serialized to JSON for Python access.
/// Future phases can add typed ContentPart wrappers.
#[pyclass(name = "MessagePayload")]
#[derive(Clone)]
pub struct PyMessagePayload {
    pub(crate) inner: MessagePayload,
}

#[pymethods]
impl PyMessagePayload {
    /// Create a new MessagePayload from a JSON dictionary.
    ///
    /// Args:
    ///     message_dict: Dictionary representing the Message structure
    ///
    /// Returns:
    ///     New MessagePayload instance
    #[new]
    fn new(py: Python, message_dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        // Use Python's json module to convert dict to JSON string
        let json_module = py.import_bound("json")?;
        let dumps = json_module.getattr("dumps")?;
        let json_str: String = dumps.call1((message_dict,))?.extract()?;
        
        // Deserialize to Message
        let message: Message = serde_json::from_str(&json_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Failed to deserialize message: {}", e)
            ))?;
        
        Ok(Self {
            inner: MessagePayload { message },
        })
    }

    /// Get the message as a JSON dictionary.
    ///
    /// Returns:
    ///     Dictionary representation of the Message
    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let json_str = serde_json::to_string(&self.inner.message)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Failed to serialize message: {}", e)
            ))?;
        
        let json_module = py.import_bound("json")?;
        let loads = json_module.getattr("loads")?;
        let dict = loads.call1((json_str,))?;
        Ok(dict.into())
    }

    /// Create a copy of this payload (copy-on-write semantics).
    ///
    /// Returns:
    ///     New MessagePayload instance with cloned data
    fn model_copy(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    /// Get the schema version.
    #[getter]
    fn schema_version(&self) -> String {
        self.inner.message.schema_version.clone()
    }

    /// Get the role as a string.
    #[getter]
    fn role(&self) -> String {
        format!("{:?}", self.inner.message.role).to_lowercase()
    }

    /// Get the channel as a string (if present).
    #[getter]
    fn channel(&self) -> Option<String> {
        self.inner.message.channel.map(|c| format!("{:?}", c).to_lowercase())
    }

    /// Get the number of content parts.
    #[getter]
    fn content_count(&self) -> usize {
        self.inner.message.content.len()
    }

    /// Extract all text content from the message.
    ///
    /// Returns:
    ///     Concatenated text from all Text content parts
    fn get_text_content(&self) -> String {
        self.inner.message.get_text_content()
    }

    /// Extract thinking/reasoning content if present.
    ///
    /// Returns:
    ///     Thinking content or None
    fn get_thinking_content(&self) -> Option<String> {
        self.inner.message.get_thinking_content()
    }

    /// Whether this message contains any tool calls.
    fn is_tool_call(&self) -> bool {
        self.inner.message.is_tool_call()
    }

    /// Whether this message contains any tool results.
    fn is_tool_result(&self) -> bool {
        self.inner.message.is_tool_result()
    }

    /// Whether this message contains any resources or resource references.
    fn has_resources(&self) -> bool {
        self.inner.message.has_resources()
    }

    /// Get all resource URIs (both embedded and references).
    ///
    /// Returns:
    ///     List of resource URI strings
    fn get_all_resource_uris(&self) -> Vec<String> {
        self.inner.message.get_all_resource_uris()
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "MessagePayload(role={}, content_parts={}, has_resources={})",
            self.role(),
            self.content_count(),
            self.has_resources()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

// Conversion traits for Rust ↔ Python bridge
impl From<MessagePayload> for PyMessagePayload {
    fn from(inner: MessagePayload) -> Self {
        Self { inner }
    }
}

impl From<PyMessagePayload> for MessagePayload {
    fn from(py_payload: PyMessagePayload) -> Self {
        py_payload.inner
    }
}

// Made with Bob
