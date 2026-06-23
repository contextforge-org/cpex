// Location: ./bindings/python/src/wrappers/cmf.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed wrappers for the full CMF message model: Message, ContentPart (all 12
// variants), and the domain / media source structs.

use cpex_core::cmf::{
    AudioSource, ContentPart, DocumentSource, ImageSource, Message, PromptRequest, PromptResult,
    Resource, ResourceReference, Role, ToolCall, ToolResult, VideoSource,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;
use std::collections::HashMap;

use super::{enum_from_str, enum_to_string};

// ---------------------------------------------------------------------------
// Domain / media structs — serde-bridge wrappers (kwargs ctor + to_dict)
// ---------------------------------------------------------------------------

serde_wrapper!(PyToolResult, "ToolResult", ToolResult,
    native: [tool_call_id, tool_name, is_error],
    convert: [content]);
serde_wrapper!(PyResource, "Resource", Resource,
    native: [resource_request_id, uri, name, description, content, mime_type, size_bytes, version],
    convert: [resource_type, blob, annotations]);
serde_wrapper!(PyResourceReference, "ResourceReference", ResourceReference,
    native: [resource_request_id, uri, name, range_start, range_end, selector],
    convert: [resource_type]);
serde_wrapper!(PyPromptRequest, "PromptRequest", PromptRequest,
    native: [prompt_request_id, name, server_id],
    convert: [arguments]);
serde_wrapper!(PyPromptResult, "PromptResult", PromptResult,
    native: [prompt_request_id, prompt_name, content, is_error, error_message],
    convert: []); // `messages` is a handle getter below

#[pymethods]
impl PyPromptResult {
    /// Rendered messages as typed `Message` handles.
    #[getter]
    fn messages(&self) -> Vec<PyMessage> {
        self.inner
            .messages
            .iter()
            .map(|m| PyMessage { inner: m.clone() })
            .collect()
    }
}
serde_wrapper!(PyImageSource, "ImageSource", ImageSource,
    native: [source_type, data, media_type], convert: []);
serde_wrapper!(PyVideoSource, "VideoSource", VideoSource,
    native: [source_type, data, media_type, duration_ms], convert: []);
serde_wrapper!(PyAudioSource, "AudioSource", AudioSource,
    native: [source_type, data, media_type, duration_ms], convert: []);
serde_wrapper!(PyDocumentSource, "DocumentSource", DocumentSource,
    native: [source_type, data, media_type, title], convert: []);

// ---------------------------------------------------------------------------
// ToolCall — bespoke (arguments dict ergonomics + typed getters)
// ---------------------------------------------------------------------------

/// A tool/function invocation request. `arguments` is a JSON-compatible dict.
#[pyclass(name = "ToolCall", frozen)]
pub struct PyToolCall {
    pub(crate) inner: ToolCall,
}

#[pymethods]
impl PyToolCall {
    #[new]
    #[pyo3(signature = (name, arguments=None, tool_call_id=None, namespace=None))]
    fn new(
        py: Python<'_>,
        name: String,
        arguments: Option<&Bound<'_, PyAny>>,
        tool_call_id: Option<String>,
        namespace: Option<String>,
    ) -> PyResult<Self> {
        let arguments: HashMap<String, Value> = match arguments {
            None => HashMap::new(),
            Some(obj) => match crate::conversions::pyobj_to_json_value(py, obj, 0)? {
                Value::Object(map) => map.into_iter().collect(),
                _ => return Err(PyValueError::new_err("cpex: ToolCall arguments must be a dict")),
            },
        };
        Ok(Self {
            inner: ToolCall {
                tool_call_id: tool_call_id.unwrap_or_default(),
                name,
                arguments,
                namespace,
            },
        })
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[getter]
    fn tool_call_id(&self) -> String {
        self.inner.tool_call_id.clone()
    }

    #[getter]
    fn namespace(&self) -> Option<String> {
        self.inner.namespace.clone()
    }

    #[getter]
    fn arguments<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let v = serde_json::to_value(&self.inner.arguments).unwrap_or(Value::Null);
        crate::conversions::json_value_to_pyobj(py, &v)
    }
}

// ---------------------------------------------------------------------------
// ContentPart — typed factories + variant read-back
// ---------------------------------------------------------------------------

/// A typed CMF content part. Construct via the factory classmethods rather than
/// a raw enum tag; read the discriminant via `.kind`.
#[pyclass(name = "ContentPart", frozen)]
pub struct PyContentPart {
    pub(crate) inner: ContentPart,
}

#[pymethods]
impl PyContentPart {
    #[staticmethod]
    fn text(text: String) -> Self {
        Self { inner: ContentPart::Text { text } }
    }
    #[staticmethod]
    fn thinking(text: String) -> Self {
        Self { inner: ContentPart::Thinking { text } }
    }
    #[staticmethod]
    fn tool_call(call: PyRef<PyToolCall>) -> Self {
        Self { inner: ContentPart::ToolCall { content: call.inner.clone() } }
    }
    #[staticmethod]
    fn tool_result(r: PyRef<PyToolResult>) -> Self {
        Self { inner: ContentPart::ToolResult { content: r.inner.clone() } }
    }
    #[staticmethod]
    fn resource(r: PyRef<PyResource>) -> Self {
        Self { inner: ContentPart::Resource { content: r.inner.clone() } }
    }
    #[staticmethod]
    fn resource_ref(r: PyRef<PyResourceReference>) -> Self {
        Self { inner: ContentPart::ResourceRef { content: r.inner.clone() } }
    }
    #[staticmethod]
    fn prompt_request(r: PyRef<PyPromptRequest>) -> Self {
        Self { inner: ContentPart::PromptRequest { content: r.inner.clone() } }
    }
    #[staticmethod]
    fn prompt_result(r: PyRef<PyPromptResult>) -> Self {
        Self { inner: ContentPart::PromptResult { content: r.inner.clone() } }
    }
    #[staticmethod]
    fn image(s: PyRef<PyImageSource>) -> Self {
        Self { inner: ContentPart::Image { content: s.inner.clone() } }
    }
    #[staticmethod]
    fn video(s: PyRef<PyVideoSource>) -> Self {
        Self { inner: ContentPart::Video { content: s.inner.clone() } }
    }
    #[staticmethod]
    fn audio(s: PyRef<PyAudioSource>) -> Self {
        Self { inner: ContentPart::Audio { content: s.inner.clone() } }
    }
    #[staticmethod]
    fn document(s: PyRef<PyDocumentSource>) -> Self {
        Self { inner: ContentPart::Document { content: s.inner.clone() } }
    }

    /// The content_type discriminant, e.g. "text", "tool_call".
    #[getter]
    fn kind(&self) -> PyResult<String> {
        // Serialize the tagged enum and read its content_type field.
        let v = serde_json::to_value(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("cpex: {e}")))?;
        Ok(v.get("content_type")
            .and_then(|c| c.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// Plain-text body for `text` / `thinking` parts; `None` otherwise.
    #[getter]
    fn as_text(&self) -> Option<String> {
        match &self.inner {
            ContentPart::Text { text } | ContentPart::Thinking { text } => Some(text.clone()),
            _ => None,
        }
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let v = serde_json::to_value(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("cpex: {e}")))?;
        crate::conversions::json_value_to_pyobj(py, &v)
    }
}

// ---------------------------------------------------------------------------
// Message — frozen handle with typed construction + read-back
// ---------------------------------------------------------------------------

/// Typed CMF message. Immutable from Python (frozen pyclass).
#[pyclass(name = "Message", frozen)]
pub struct PyMessage {
    pub(crate) inner: Message,
}

#[pymethods]
impl PyMessage {
    /// `Message(role="user", text="hello")` or
    /// `Message(role="assistant", content=[ContentPart.tool_call(tc)])`.
    #[new]
    #[pyo3(signature = (role, text=None, content=None, channel=None))]
    fn new(
        role: &str,
        text: Option<&str>,
        content: Option<Vec<PyRef<PyContentPart>>>,
        channel: Option<&str>,
    ) -> PyResult<Self> {
        let role: Role = enum_from_str(role, "Role")?;
        let mut inner = if let Some(parts) = content {
            Message::with_content(role, parts.iter().map(|p| p.inner.clone()).collect())
        } else if let Some(t) = text {
            Message::text(role, t)
        } else {
            Message::with_content(role, Vec::new())
        };
        if let Some(c) = channel {
            inner.channel = Some(enum_from_str(c, "Channel")?);
        }
        Ok(Self { inner })
    }

    #[getter]
    fn role(&self) -> PyResult<String> {
        enum_to_string(&self.inner.role)
    }

    #[getter]
    fn schema_version(&self) -> String {
        self.inner.schema_version.clone()
    }

    #[getter]
    fn channel(&self) -> PyResult<Option<String>> {
        match &self.inner.channel {
            None => Ok(None),
            Some(c) => Ok(Some(enum_to_string(c)?)),
        }
    }

    /// Concatenated text of all text content parts.
    #[getter]
    fn text(&self) -> String {
        self.inner.get_text_content()
    }

    /// Typed content parts (read-back as `ContentPart` handles).
    #[getter]
    fn content(&self) -> Vec<PyContentPart> {
        self.inner
            .content
            .iter()
            .map(|c| PyContentPart { inner: c.clone() })
            .collect()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let v = serde_json::to_value(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("cpex: {e}")))?;
        crate::conversions::json_value_to_pyobj(py, &v)
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "Message(role={:?}, parts={})",
            enum_to_string(&self.inner.role)?,
            self.inner.content.len()
        ))
    }
}
