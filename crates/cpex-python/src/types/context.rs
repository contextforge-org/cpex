// Location: ./crates/cpex-python/src/types/context.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Python bindings for PluginContext and PluginContextTable.

use cpex_core::context::{PluginContext, PluginContextTable};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Python wrapper for PluginContext.
///
/// Per-plugin, per-invocation execution context with:
/// - `local_state`: Private to this plugin, this invocation
/// - `global_state`: Shared across all plugins in the pipeline
#[pyclass(name = "PluginContext")]
#[derive(Clone)]
pub struct PyPluginContext {
    pub(crate) inner: PluginContext,
}

#[pymethods]
impl PyPluginContext {
    /// Create a new empty plugin context.
    #[new]
    fn new() -> Self {
        Self {
            inner: PluginContext::new(),
        }
    }

    /// Get a value from local state.
    ///
    /// Args:
    ///     key: The key to look up
    ///
    /// Returns:
    ///     The value if found, None otherwise
    fn get_local(&self, py: Python, key: &str) -> PyResult<Option<PyObject>> {
        Ok(self
            .inner
            .get_local(key)
            .map(|v| json_to_python(py, v))
            .transpose()?)
    }

    /// Set a value in local state.
    ///
    /// Args:
    ///     key: The key to set
    ///     value: The value to store (must be JSON-serializable)
    fn set_local(&mut self, py: Python, key: String, value: PyObject) -> PyResult<()> {
        let json_value = python_to_json(py, value)?;
        self.inner.set_local(key, json_value);
        Ok(())
    }

    /// Get a value from global state.
    ///
    /// Args:
    ///     key: The key to look up
    ///
    /// Returns:
    ///     The value if found, None otherwise
    fn get_global(&self, py: Python, key: &str) -> PyResult<Option<PyObject>> {
        Ok(self
            .inner
            .get_global(key)
            .map(|v| json_to_python(py, v))
            .transpose()?)
    }

    /// Set a value in global state.
    ///
    /// Args:
    ///     key: The key to set
    ///     value: The value to store (must be JSON-serializable)
    fn set_global(&mut self, py: Python, key: String, value: PyObject) -> PyResult<()> {
        let json_value = python_to_json(py, value)?;
        self.inner.set_global(key, json_value);
        Ok(())
    }

    /// Get the local state as a dictionary.
    #[getter]
    fn local_state(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);
        for (k, v) in &self.inner.local_state {
            dict.set_item(k, json_to_python(py, v)?)?;
        }
        Ok(dict.into())
    }

    /// Get the global state as a dictionary.
    #[getter]
    fn global_state(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);
        for (k, v) in &self.inner.global_state {
            dict.set_item(k, json_to_python(py, v)?)?;
        }
        Ok(dict.into())
    }

    fn __repr__(&self) -> String {
        format!(
            "PluginContext(local_keys={}, global_keys={})",
            self.inner.local_state.len(),
            self.inner.global_state.len()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Python wrapper for PluginContextTable.
///
/// Threaded execution state carried from one hook invocation to the next
/// within a single request lifecycle.
#[pyclass(name = "PluginContextTable")]
pub struct PyPluginContextTable {
    pub(crate) inner: PluginContextTable,
}

#[pymethods]
impl PyPluginContextTable {
    /// Create an empty context table.
    #[new]
    fn new() -> Self {
        Self {
            inner: PluginContextTable::new(),
        }
    }

    /// Build a PluginContext for the given plugin, removing its stored
    /// local_state from the table.
    ///
    /// Args:
    ///     plugin_id: UUID string of the plugin
    ///
    /// Returns:
    ///     A new PluginContext with the plugin's local state
    fn take_context(&mut self, plugin_id: &str) -> PyResult<PyPluginContext> {
        let uuid = Uuid::parse_str(plugin_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid UUID: {}", e)))?;
        Ok(PyPluginContext {
            inner: self.inner.take_context(uuid),
        })
    }

    /// Build a PluginContext for the given plugin without mutating the table.
    ///
    /// Args:
    ///     plugin_id: UUID string of the plugin
    ///
    /// Returns:
    ///     A snapshot of the plugin's context
    fn snapshot_context(&self, plugin_id: &str) -> PyResult<PyPluginContext> {
        let uuid = Uuid::parse_str(plugin_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid UUID: {}", e)))?;
        Ok(PyPluginContext {
            inner: self.inner.snapshot_context(uuid),
        })
    }

    /// Commit a plugin's context back into the table.
    ///
    /// Args:
    ///     plugin_id: UUID string of the plugin
    ///     context: The plugin's modified context
    fn store_context(&mut self, plugin_id: &str, context: PyPluginContext) -> PyResult<()> {
        let uuid = Uuid::parse_str(plugin_id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid UUID: {}", e)))?;
        self.inner.store_context(uuid, context.inner);
        Ok(())
    }

    /// Number of plugins with stored local_state in the table.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Whether the table holds no per-plugin local_state.
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the global state as a dictionary.
    #[getter]
    fn global_state(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);
        for (k, v) in &self.inner.global_state {
            dict.set_item(k, json_to_python(py, v)?)?;
        }
        Ok(dict.into())
    }

    fn __repr__(&self) -> String {
        format!(
            "PluginContextTable(plugins={}, global_keys={})",
            self.inner.len(),
            self.inner.global_state.len()
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

// ---------------------------------------------------------------------------
// Helper functions for JSON ↔ Python conversion
// ---------------------------------------------------------------------------

/// Convert a serde_json::Value to a Python object.
fn json_to_python(py: Python, value: &Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.to_object(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.to_object(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.to_object(py))
            } else {
                Ok(n.to_string().to_object(py))
            }
        }
        Value::String(s) => Ok(s.to_object(py)),
        Value::Array(arr) => {
            let list = pyo3::types::PyList::empty_bound(py);
            for item in arr {
                list.append(json_to_python(py, item)?)?;
            }
            Ok(list.into())
        }
        Value::Object(obj) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in obj {
                dict.set_item(k, json_to_python(py, v)?)?;
            }
            Ok(dict.into())
        }
    }
}

/// Convert a Python object to a serde_json::Value.
fn python_to_json(py: Python, obj: PyObject) -> PyResult<Value> {
    let obj_ref = obj.bind(py);

    if obj_ref.is_none() {
        Ok(Value::Null)
    } else if let Ok(b) = obj_ref.extract::<bool>() {
        Ok(Value::Bool(b))
    } else if let Ok(i) = obj_ref.extract::<i64>() {
        Ok(Value::Number(i.into()))
    } else if let Ok(f) = obj_ref.extract::<f64>() {
        Ok(serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    } else if let Ok(s) = obj_ref.extract::<String>() {
        Ok(Value::String(s))
    } else if let Ok(list) = obj_ref.downcast::<pyo3::types::PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(python_to_json(py, item.to_object(py))?);
        }
        Ok(Value::Array(arr))
    } else if let Ok(dict) = obj_ref.downcast::<pyo3::types::PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key = k.extract::<String>()?;
            map.insert(key, python_to_json(py, v.to_object(py))?);
        }
        Ok(Value::Object(map))
    } else {
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Value must be JSON-serializable (None, bool, int, float, str, list, dict)",
        ))
    }
}

// Conversion traits for Rust ↔ Python bridge
impl From<PluginContext> for PyPluginContext {
    fn from(inner: PluginContext) -> Self {
        Self { inner }
    }
}

impl From<PyPluginContext> for PluginContext {
    fn from(py_ctx: PyPluginContext) -> Self {
        py_ctx.inner
    }
}

impl From<PluginContextTable> for PyPluginContextTable {
    fn from(inner: PluginContextTable) -> Self {
        Self { inner }
    }
}

impl From<PyPluginContextTable> for PluginContextTable {
    fn from(py_table: PyPluginContextTable) -> Self {
        py_table.inner
    }
}

// Made with Bob
