// Location: ./crates/cpex-python/src/conversions.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Conversion utilities for Python ↔ Rust data structures.
//!
//! Provides bidirectional conversion between Python dicts and Rust types
//! (Extensions, PluginContextTable, PipelineResult) using JSON serialization.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use cpex_core::cmf::MessagePayload;
use cpex_core::context::PluginContextTable;
use cpex_core::delegation::DelegationPayload;
use cpex_core::executor::PipelineResult;
use cpex_core::hooks::payload::{Extensions, PluginPayload};
use cpex_core::identity::IdentityPayload;

/// Convert Python dict to Extensions.
///
/// Uses JSON serialization for Phase 4. Future optimization can use
/// direct field access for better performance.
///
/// # Arguments
///
/// * `py` - Python GIL token
/// * `dict` - Optional Python dictionary containing extensions data
///
/// # Returns
///
/// Extensions struct (default if None)
pub fn dict_to_extensions(py: Python, dict: Option<&Bound<PyDict>>) -> PyResult<Extensions> {
    let Some(dict) = dict else {
        return Ok(Extensions::default());
    };

    // Use JSON serialization
    let json_module = py.import_bound("json")?;
    let dumps = json_module.getattr("dumps")?;
    let json_str: String = dumps.call1((dict,))?.extract()?;

    let extensions: Extensions = serde_json::from_str(&json_str).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Failed to deserialize extensions: {}",
            e
        ))
    })?;

    Ok(extensions)
}

/// Convert Extensions to Python dict.
///
/// # Arguments
///
/// * `py` - Python GIL token
/// * `extensions` - Extensions struct to convert
///
/// # Returns
///
/// Python dictionary
pub fn extensions_to_dict(py: Python, extensions: &Extensions) -> PyResult<PyObject> {
    let json_str = serde_json::to_string(extensions).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Failed to serialize extensions: {}",
            e
        ))
    })?;

    let json_module = py.import_bound("json")?;
    let loads = json_module.getattr("loads")?;
    let dict = loads.call1((json_str,))?;
    Ok(dict.into())
}

/// Convert Python dict to PluginContextTable.
///
/// # Arguments
///
/// * `py` - Python GIL token
/// * `dict` - Optional Python dictionary containing context table data
///
/// # Returns
///
/// Optional PluginContextTable (None if input is None)
pub fn dict_to_context_table(
    py: Python,
    dict: Option<&Bound<PyDict>>,
) -> PyResult<Option<PluginContextTable>> {
    let Some(dict) = dict else {
        return Ok(None);
    };

    // Use JSON serialization
    let json_module = py.import_bound("json")?;
    let dumps = json_module.getattr("dumps")?;
    let json_str: String = dumps.call1((dict,))?.extract()?;

    let table: PluginContextTable = serde_json::from_str(&json_str).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Failed to deserialize context table: {}",
            e
        ))
    })?;

    Ok(Some(table))
}

/// Convert PluginContextTable to Python dict.
///
/// # Arguments
///
/// * `py` - Python GIL token
/// * `table` - PluginContextTable to convert
///
/// # Returns
///
/// Python dictionary
pub fn context_table_to_dict(py: Python, table: &PluginContextTable) -> PyResult<PyObject> {
    let json_str = serde_json::to_string(table).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Failed to serialize context table: {}",
            e
        ))
    })?;

    let json_module = py.import_bound("json")?;
    let loads = json_module.getattr("loads")?;
    let dict = loads.call1((json_str,))?;
    Ok(dict.into())
}

/// Convert a boxed PluginPayload back to Python dict.
///
/// Attempts to downcast to known payload types (MessagePayload,
/// IdentityPayload, DelegationPayload) and serialize to dict.
///
/// # Arguments
///
/// * `py` - Python GIL token
/// * `payload` - Boxed trait object implementing PluginPayload
///
/// # Returns
///
/// Python dictionary representation of the payload
pub fn payload_to_dict(py: Python, payload: &Box<dyn PluginPayload>) -> PyResult<PyObject> {
    // Try downcasting to known types
    if let Some(msg_payload) = payload.as_any().downcast_ref::<MessagePayload>() {
        // Convert MessagePayload to dict
        let json_str = serde_json::to_string(&msg_payload.message).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to serialize MessagePayload: {}",
                e
            ))
        })?;

        let json_module = py.import_bound("json")?;
        let loads = json_module.getattr("loads")?;
        return Ok(loads.call1((json_str,))?.into());
    }

    if let Some(identity_payload) = payload.as_any().downcast_ref::<IdentityPayload>() {
        // Convert IdentityPayload to dict
        let json_str = serde_json::to_string(identity_payload).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to serialize IdentityPayload: {}",
                e
            ))
        })?;

        let json_module = py.import_bound("json")?;
        let loads = json_module.getattr("loads")?;
        return Ok(loads.call1((json_str,))?.into());
    }

    if let Some(delegation_payload) = payload.as_any().downcast_ref::<DelegationPayload>() {
        // Convert DelegationPayload to dict
        let json_str = serde_json::to_string(delegation_payload).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to serialize DelegationPayload: {}",
                e
            ))
        })?;

        let json_module = py.import_bound("json")?;
        let loads = json_module.getattr("loads")?;
        return Ok(loads.call1((json_str,))?.into());
    }

    // Unknown payload type - return empty dict with error info
    let dict = PyDict::new_bound(py);
    dict.set_item("_error", "Unknown payload type")?;
    dict.set_item("_type", format!("{:?}", payload))?;
    Ok(dict.into())
}

/// Convert PipelineResult to Python tuple.
///
/// Returns a 5-tuple: (payload_dict, extensions_dict, context_table_dict, blocked, violation_dict)
///
/// # Arguments
///
/// * `py` - Python GIL token
/// * `result` - PipelineResult from hook execution
///
/// # Returns
///
/// Python tuple with result components
pub fn pipeline_result_to_python(py: Python, result: PipelineResult) -> PyResult<PyObject> {
    // Convert payload back to dict (if present)
    let payload_dict = if let Some(payload) = result.modified_payload {
        payload_to_dict(py, &payload)?
    } else {
        // No payload - return empty dict
        PyDict::new_bound(py).into()
    };

    // Convert extensions to dict (if modified)
    let extensions_dict = if let Some(extensions) = result.modified_extensions {
        extensions_to_dict(py, &extensions)?
    } else {
        // No modifications - return empty dict
        PyDict::new_bound(py).into()
    };

    // Convert context table to dict
    let context_dict = context_table_to_dict(py, &result.context_table)?;

    // Check for violation
    let blocked = !result.continue_processing;
    let violation_dict: Option<PyObject> = if let Some(v) = result.violation {
        // Convert violation to dict
        let json_str = serde_json::to_string(&v).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to serialize violation: {}",
                e
            ))
        })?;

        let json_module = py.import_bound("json")?;
        let loads = json_module.getattr("loads")?;
        Some(loads.call1((json_str,))?.into())
    } else {
        None
    };

    // Return tuple: (payload, extensions, context_table, blocked, violation)
    Ok((payload_dict, extensions_dict, context_dict, blocked, violation_dict).into_py(py))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extensions_default() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let ext = dict_to_extensions(py, None).unwrap();
            // Should be default Extensions
            assert!(ext.security.is_none());
        });
    }

    #[test]
    fn test_context_table_none() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let table = dict_to_context_table(py, None).unwrap();
            assert!(table.is_none());
        });
    }
}

// Made with Bob