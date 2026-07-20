// Location: ./bindings/python/src/result.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// `PyPipelineResult` — read-only Python view of `cpex_core::PipelineResult`.
//
// Mirrors the field set of `PipelineResult` exactly. All fields are read-only
// getters; no setters are exposed.
//
// If the modified_payload could not be serialised back to a Python dict the
// caller appends a synthetic `PluginErrorRecord` to `errors` (#8);
// `modified_payload` is exposed as `None` in that case — mirrors the pattern
// at `crates/cpex-ffi/src/lib.rs:877`.

use std::collections::HashMap;

use cpex_core::error::PluginErrorRecord;
use cpex_core::executor::PipelineResult;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

use crate::conversions::{json_value_to_pyobj, serialize_payload};

#[pyclass(name = "PipelineResult")]
pub struct PyPipelineResult {
    pub continue_processing: bool,
    pub modified_payload: Option<Value>,
    pub modified_extensions: Option<Value>,
    pub violation: Option<Value>,
    pub errors: Vec<Value>,
    pub metadata: Option<Value>,
    pub context_table: Value,
}

#[pymethods]
impl PyPipelineResult {
    #[getter]
    fn continue_processing(&self) -> bool {
        self.continue_processing
    }

    #[getter]
    fn modified_payload<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        match &self.modified_payload {
            None => Ok(None),
            Some(v) => {
                let obj = json_value_to_pyobj(py, v)?;
                Ok(Some(obj.cast_into::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "cpex: modified_payload is not a dict",
                    )
                })?))
            },
        }
    }

    #[getter]
    fn modified_extensions<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        match &self.modified_extensions {
            None => Ok(None),
            Some(v) => {
                let obj = json_value_to_pyobj(py, v)?;
                Ok(Some(obj.cast_into::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyRuntimeError::new_err(
                        "cpex: modified_extensions is not a dict",
                    )
                })?))
            },
        }
    }

    #[getter]
    fn violation<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        match &self.violation {
            None => Ok(None),
            Some(v) => {
                let obj = json_value_to_pyobj(py, v)?;
                Ok(Some(obj.cast_into::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyRuntimeError::new_err("cpex: violation is not a dict")
                })?))
            },
        }
    }

    #[getter]
    fn errors<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.errors
            .iter()
            .map(|v| {
                let obj = json_value_to_pyobj(py, v)?;
                obj.cast_into::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyRuntimeError::new_err("cpex: error entry is not a dict")
                })
            })
            .collect()
    }

    #[getter]
    fn metadata<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        match &self.metadata {
            None => Ok(None),
            Some(v) => {
                let obj = json_value_to_pyobj(py, v)?;
                Ok(Some(obj.cast_into::<PyDict>().map_err(|_| {
                    pyo3::exceptions::PyRuntimeError::new_err("cpex: metadata is not a dict")
                })?))
            },
        }
    }

    #[getter]
    fn context_table<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let obj = json_value_to_pyobj(py, &self.context_table)?;
        obj.cast_into::<PyDict>().map_err(|_| {
            pyo3::exceptions::PyRuntimeError::new_err("cpex: context_table is not a dict")
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "PipelineResult(continue_processing={}, violation={}, errors={})",
            self.continue_processing,
            if self.violation.is_some() {
                "Some(...)"
            } else {
                "None"
            },
            self.errors.len(),
        )
    }
}

/// Convert a `PipelineResult` from the Rust runtime into `PyPipelineResult`.
///
/// If `modified_payload` is present but cannot be serialised, a synthetic
/// `PluginErrorRecord` is appended to `errors` and `modified_payload` is
/// exposed as `None` — mirrors cpex-ffi's behaviour at lib.rs:877 (#8).
pub fn pipeline_result_to_py(mut result: PipelineResult) -> PyResult<PyPipelineResult> {
    // Serialise modified_payload; on failure emit a synthetic error record.
    let modified_payload_value: Option<Value> = match result.modified_payload.take() {
        None => None,
        Some(p) => match serialize_payload(p.as_ref()) {
            Some(v) => Some(v),
            None => {
                tracing::warn!("cpex-python: modified payload could not be serialised; dropping");
                result.errors.push(PluginErrorRecord {
                    plugin_name: "<py>".to_string(),
                    message: "modified payload could not be serialised across the PyO3 boundary"
                        .to_string(),
                    code: Some("py_serialize_error".to_string()),
                    details: HashMap::new(),
                    proto_error_code: None,
                });
                None
            },
        },
    };

    let modified_extensions_value: Option<Value> = result
        .modified_extensions
        .map(|ext| serde_json::to_value(&ext))
        .transpose()
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cpex: modified_extensions serialization failed: {e}"
            ))
        })?;

    let violation_value: Option<Value> = result
        .violation
        .map(|v| serde_json::to_value(&v))
        .transpose()
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cpex: violation serialization failed: {e}"
            ))
        })?;

    let errors_value: Vec<Value> = result
        .errors
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "cpex: errors serialization failed: {e}"
            ))
        })?;

    let context_table_value = serde_json::to_value(&result.context_table).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "cpex: context_table serialization failed: {e}"
        ))
    })?;

    Ok(PyPipelineResult {
        continue_processing: result.continue_processing,
        modified_payload: modified_payload_value,
        modified_extensions: modified_extensions_value,
        violation: violation_value,
        errors: errors_value,
        metadata: result.metadata,
        context_table: context_table_value,
    })
}
