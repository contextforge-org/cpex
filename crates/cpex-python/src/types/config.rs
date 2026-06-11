// Location: ./crates/cpex-python/src/types/config.rs
// Copyright (c) 2024-2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Bob (AI Assistant)

//! Python bindings for CPEX configuration types.
//!
//! Wraps Rust config structs (PluginConfig, etc.) for Python access.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashSet;

use cpex_core::plugin::{PluginConfig, PluginMode, OnError};

use super::enums::{PyPluginMode, PyOnError};

/// Python wrapper for PluginConfig.
///
/// Provides read-only access to plugin configuration from Python.
/// This is the configuration as declared in YAML and loaded by the manager.
#[pyclass(name = "PluginConfig")]
#[derive(Clone)]
pub struct PyPluginConfig {
    inner: PluginConfig,
}

#[pymethods]
impl PyPluginConfig {
    /// Get the plugin name.
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    /// Get the plugin kind (builtin, native://, wasm://, python://, external).
    #[getter]
    fn kind(&self) -> String {
        self.inner.kind.clone()
    }

    /// Get the plugin description (if any).
    #[getter]
    fn description(&self) -> Option<String> {
        self.inner.description.clone()
    }

    /// Get the plugin author (if any).
    #[getter]
    fn author(&self) -> Option<String> {
        self.inner.author.clone()
    }

    /// Get the plugin version (if any).
    #[getter]
    fn version(&self) -> Option<String> {
        self.inner.version.clone()
    }

    /// Get the list of hook names this plugin handles.
    #[getter]
    fn hooks(&self) -> Vec<String> {
        self.inner.hooks.clone()
    }

    /// Get the plugin execution mode.
    #[getter]
    fn mode(&self) -> PyPluginMode {
        self.inner.mode.into()
    }

    /// Get the plugin priority (lower executes first).
    #[getter]
    fn priority(&self) -> i32 {
        self.inner.priority
    }

    /// Get the error handling behavior.
    #[getter]
    fn on_error(&self) -> PyOnError {
        self.inner.on_error.into()
    }

    /// Get the declared capabilities as a set.
    #[getter]
    fn capabilities(&self, py: Python) -> PyResult<Py<PyList>> {
        let list = PyList::empty_bound(py);
        for cap in &self.inner.capabilities {
            list.append(cap.clone())?;
        }
        Ok(list.unbind())
    }

    /// Get the plugin tags.
    #[getter]
    fn tags(&self) -> Vec<String> {
        self.inner.tags.clone()
    }

    /// Get the plugin-specific config as a Python dict (if any).
    #[getter]
    fn config(&self, py: Python) -> PyResult<Option<Py<PyDict>>> {
        match &self.inner.config {
            Some(value) => {
                // Convert serde_json::Value to Python dict
                let dict = PyDict::new_bound(py);
                if let serde_json::Value::Object(map) = value {
                    for (k, v) in map {
                        let py_value = json_value_to_py(py, v)?;
                        dict.set_item(k, py_value)?;
                    }
                }
                Ok(Some(dict.unbind()))
            }
            None => Ok(None),
        }
    }

    /// String representation.
    fn __repr__(&self) -> String {
        let mode: PyPluginMode = self.inner.mode.into();
        format!(
            "PluginConfig(name='{}', kind='{}', mode='{}', priority={})",
            self.inner.name,
            self.inner.kind,
            mode.as_str(),
            self.inner.priority
        )
    }

    /// String conversion.
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl PyPluginConfig {
    /// Create from Rust PluginConfig.
    pub fn new(config: PluginConfig) -> Self {
        Self { inner: config }
    }

    /// Get reference to inner config.
    pub fn inner(&self) -> &PluginConfig {
        &self.inner
    }
}

impl From<PluginConfig> for PyPluginConfig {
    fn from(config: PluginConfig) -> Self {
        Self::new(config)
    }
}

impl From<PyPluginConfig> for PluginConfig {
    fn from(py_config: PyPluginConfig) -> Self {
        py_config.inner
    }
}

/// Helper to convert serde_json::Value to Python object.
fn json_value_to_py(py: Python, value: &serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_py(py)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(s) => Ok(s.into_py(py)),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty_bound(py);
            for item in arr {
                list.append(json_value_to_py(py, item)?)?;
            }
            Ok(list.into_py(py))
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_value_to_py(py, v)?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

// Made with Bob
