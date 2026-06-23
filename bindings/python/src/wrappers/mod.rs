// Location: ./bindings/python/src/wrappers/mod.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Typed PyO3 *wrapper* layer (handles, not dicts) for the full CMF + extension
// model plus the Identity / Delegation payloads.
//
// Each #[pyclass] holds the REAL Rust object. Two construction styles coexist:
//
//   * Bespoke wrappers (Message, ContentPart, SecurityExtension, ...) expose
//     ergonomic typed constructors, typed getters, and invariant-preserving
//     methods (e.g. add_label with no remove, backed by MonotonicSet).
//
//   * The `serde_wrapper!` macro generates the long-tail wrappers: a kwargs
//     constructor that deserializes through serde (schema-validated at the
//     boundary), a `to_dict()` reader, and `__repr__`. Zero per-field
//     boilerplate; complete field coverage.
//
// On `invoke_hook` these wrappers take the zero-serialization path: we
// `extract()` the handle and clone the inner Rust struct straight into the
// payload / Extensions — no PyObject->Value->typed double pass.

use std::sync::Arc;

use cpex_core::cmf::MessagePayload;
use cpex_core::extensions::Extensions;
use cpex_core::hooks::payload::PluginPayload;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::Serialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// serde_wrapper! — generates a typed handle with kwargs construction + to_dict
// ---------------------------------------------------------------------------

/// Generate a `#[pyclass]` over a serde-(de)serializable core type.
///
/// Provides:
///   * `__new__(**kwargs)` — deserialize a kwargs dict into the core type
///     (schema-validated; unknown/invalid fields raise `ValueError`).
///   * `to_dict()` — serde projection back to a plain Python dict.
///   * `__repr__`.
///   * a `#[getter]` for each listed field — typed attribute access
///     (`obj.field`). Fields are split into two buckets:
///       - `native`: converted straight to a Python object via pyo3's
///         `IntoPyObject` (scalars, strings, `Vec<scalar>`,
///         `HashMap<String,String>`, sets, `Option<those>`). **No serde.**
///       - `convert`: types pyo3 can't convert natively (`serde_json::Value`,
///         enums, `DateTime`, nested structs). These go through a *single-field*
///         serde projection — enums become strings, `Value` becomes its dynamic
///         Python shape, nested structs become dicts. Per-field (not
///         whole-struct) so `None` optionals read back as `None`.
///
/// The wrapper is immutable from Python (no setters). Additional bespoke
/// getters (e.g. returning a nested *handle* instead of a dict) can be added in
/// a separate `#[pymethods]` block (enabled by the `multiple-pymethods` feature).
macro_rules! serde_wrapper {
    ($PyName:ident, $py_name:literal, $Core:ty,
        native: [$($n:ident),* $(,)?],
        convert: [$($c:ident),* $(,)?]) => {
        #[pyclass(name = $py_name, frozen)]
        pub struct $PyName {
            pub(crate) inner: $Core,
        }

        #[pymethods]
        impl $PyName {
            #[new]
            #[pyo3(signature = (**kwargs))]
            fn new(
                py: pyo3::Python<'_>,
                kwargs: Option<&pyo3::Bound<'_, pyo3::types::PyDict>>,
            ) -> pyo3::PyResult<Self> {
                let value = match kwargs {
                    None => serde_json::Value::Object(Default::default()),
                    Some(d) => $crate::conversions::pyobj_to_json_value(py, d.as_any(), 0)?,
                };
                let inner: $Core = serde_json::from_value(value).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        concat!("cpex: invalid ", $py_name, ": {}"),
                        e
                    ))
                })?;
                Ok(Self { inner })
            }

            /// Read all fields as a plain dict (serde projection).
            fn to_dict<'py>(
                &self,
                py: pyo3::Python<'py>,
            ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
                let v = serde_json::to_value(&self.inner).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "cpex: serialize failed: {}",
                        e
                    ))
                })?;
                $crate::conversions::json_value_to_pyobj(py, &v)
            }

            fn __repr__(&self) -> String {
                concat!($py_name, "(...)").to_string()
            }

            // Native getters — direct pyo3 conversion, no serialization.
            $(
                #[getter]
                fn $n<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
                    use pyo3::IntoPyObjectExt;
                    self.inner.$n.clone().into_bound_py_any(py)
                }
            )*

            // Convert getters — single-field serde for dynamic/enum/nested types.
            $(
                #[getter]
                fn $c<'py>(
                    &self,
                    py: pyo3::Python<'py>,
                ) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
                    let v = serde_json::to_value(&self.inner.$c).map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "cpex: serialize failed: {}",
                            e
                        ))
                    })?;
                    $crate::conversions::json_value_to_pyobj(py, &v)
                }
            )*
        }
    };
}

pub mod cmf;
pub mod extensions;
pub mod payloads;

pub use cmf::{
    PyAudioSource, PyContentPart, PyDocumentSource, PyImageSource, PyMessage, PyPromptRequest,
    PyPromptResult, PyResource, PyResourceReference, PyToolCall, PyToolResult, PyVideoSource,
};
pub use extensions::{
    PyAgentExtension, PyAuthorizationDetail, PyClientExtension, PyCompletionExtension,
    PyConversationContext, PyDelegationExtension, PyDelegationHop, PyExtensions,
    PyFrameworkExtension, PyHttpExtension, PyLLMExtension, PyMCPExtension, PyMetaExtension,
    PyPromptMetadata, PyProvenanceExtension, PyRequestExtension, PyResourceMetadata,
    PySecurityExtension, PySubjectExtension, PyTokenUsage, PyToolMetadata, PyWorkloadIdentity,
};
pub use payloads::{PyDelegationPayload, PyIdentityPayload};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Serialize an enum to its serde string form (used for typed enum getters).
pub(crate) fn enum_to_string<T: Serialize>(v: &T) -> PyResult<String> {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => Ok(s),
        _ => Err(PyValueError::new_err("cpex: enum did not serialize to a string")),
    }
}

/// Deserialize a serde enum from a string (used for typed enum constructors).
pub(crate) fn enum_from_str<T: serde::de::DeserializeOwned>(s: &str, what: &str) -> PyResult<T> {
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| PyValueError::new_err(format!("cpex: '{s}' is not a valid {what}")))
}

// ---------------------------------------------------------------------------
// Zero-serialization ingress for invoke_hook
// ---------------------------------------------------------------------------

/// If `payload` is a wrapped CMF / Identity / Delegation handle, build the
/// matching `Box<dyn PluginPayload>` by cloning the inner Rust struct — no
/// PyObject->Value->typed conversion. Returns `None` so the caller falls back
/// to the dict path for legacy callers.
pub fn try_wrapped_payload(payload: &Bound<'_, PyAny>) -> Option<Box<dyn PluginPayload>> {
    if let Ok(m) = payload.extract::<PyRef<PyMessage>>() {
        return Some(Box::new(MessagePayload {
            message: m.inner.clone(),
        }));
    }
    if let Ok(i) = payload.extract::<PyRef<PyIdentityPayload>>() {
        return Some(Box::new(i.inner.clone()));
    }
    if let Ok(d) = payload.extract::<PyRef<PyDelegationPayload>>() {
        return Some(Box::new(d.inner.clone()));
    }
    None
}

/// If `extensions` is a wrapped `Extensions` container (or a bare
/// `SecurityExtension` for convenience), clone it into an `Extensions` with no
/// conversion. Returns `None` for the dict fallback path.
pub fn try_wrapped_extensions(extensions: &Bound<'_, PyAny>) -> Option<Extensions> {
    if let Ok(e) = extensions.extract::<PyRef<PyExtensions>>() {
        return Some(e.inner.clone());
    }
    if let Ok(s) = extensions.extract::<PyRef<PySecurityExtension>>() {
        return Some(Extensions {
            security: Some(Arc::new(s.inner.clone())),
            ..Default::default()
        });
    }
    None
}
