// Location: ./bindings/python/src/manager.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// `PyPluginManager` — PyO3 wrapper around `cpex_core::PluginManager` (R1, R3, KD4).
//
// Construction is synchronous; lifecycle methods (`initialize`, `shutdown`,
// `invoke_hook`) are returned as Python awaitables via `future_into_py`.
//
// The design sketch in the plan:
//   [GIL held]   convert payload/extensions/context under GIL
//   [GIL release] future_into_py with timeout + catch_unwind
//   [GIL re-acq.] pipeline_result_to_py
//
// BackgroundTasks are dropped (not awaited per call); fire-and-forget tasks
// run on the manager's TaskTracker and are drained by `shutdown()` (KD4).

use std::sync::Arc;
use std::time::Duration;

use cpex_core::context::PluginContextTable;
use cpex_core::extensions::Extensions;
use cpex_core::manager::PluginManager;
use pyo3::exceptions::{PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;

use crate::builtins::register_builtin_factories;
use crate::conversions::{
    context_table_from_value, extensions_from_value, pyobj_to_json_value, resolve_payload,
};
use crate::error::plugin_error_to_pyerr;
use crate::result::pipeline_result_to_py;

/// Wall-clock timeout for every async call through the PyO3 boundary.
/// Mirrors `FFI_WALL_CLOCK_TIMEOUT` in cpex-ffi (KD7).
const PY_WALL_CLOCK_TIMEOUT: Duration = Duration::from_secs(60);

#[pyclass(name = "PluginManager")]
pub struct PyPluginManager {
    inner: Arc<PluginManager>,
}

#[pymethods]
impl PyPluginManager {
    /// Create a new `PluginManager` from a YAML config file path.
    ///
    /// Synchronous construction — no Python event loop needed.
    ///
    /// Steps (order is load-bearing for APL Weak upgrade):
    ///   1. `PluginManager::default()` → `Arc`
    ///   2. `register_builtin_factories(&arc)` — factories + APL visitor on
    ///      the same Arc that load_config_yaml will reference
    ///   3. Read config file → `load_config_yaml(&arc, yaml)` — APL visitor
    ///      Weak upgrades here
    ///
    /// Raises `ValueError` on missing file, IO error, YAML parse error,
    /// or config validation error.
    #[new]
    fn new(config_path: &str) -> PyResult<Self> {
        let yaml = std::fs::read_to_string(config_path).map_err(|e| {
            PyValueError::new_err(format!(
                "cpex: cannot read config file '{config_path}': {e}"
            ))
        })?;

        let manager = Arc::new(PluginManager::default());
        register_builtin_factories(&manager);
        manager
            .load_config_yaml(&yaml)
            .map_err(plugin_error_to_pyerr)?;

        Ok(Self { inner: manager })
    }

    /// Initialize all registered plugins.
    ///
    /// Must be called before any `invoke_hook` call.
    /// Returns an awaitable (coroutine).
    fn initialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let result = tokio::time::timeout(PY_WALL_CLOCK_TIMEOUT, async move {
                manager.initialize().await.map_err(plugin_error_to_pyerr)
            })
            .await;

            match result {
                Ok(inner_result) => inner_result,
                Err(_elapsed) => Err(PyTimeoutError::new_err(
                    "cpex: PluginManager::initialize timed out",
                )),
            }
        })
    }

    /// Shut down all registered plugins and drain fire-and-forget tasks (KD4).
    ///
    /// Returns an awaitable (coroutine).
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let result = tokio::time::timeout(PY_WALL_CLOCK_TIMEOUT, async move {
                manager.shutdown().await;
                Ok::<(), PyErr>(())
            })
            .await;

            match result {
                Ok(inner_result) => inner_result,
                Err(_elapsed) => Err(PyTimeoutError::new_err(
                    "cpex: PluginManager::shutdown timed out",
                )),
            }
        })
    }

    /// Invoke a hook by name.
    ///
    /// Args:
    ///   hook_name: str — e.g. `"cmf.tool_pre_invoke"` or any custom name.
    ///   payload:   dict — converted via direct PyObject↔serde_json traversal
    ///              (no Python `json` module).
    ///   extensions: dict | None — optional cpex Extensions fields.
    ///   context_table: dict | None — optional PluginContextTable to thread
    ///              through for stateful plugins.
    ///
    /// Returns an awaitable that resolves to `PipelineResult`.
    ///
    /// Raises:
    ///   `ValueError`     — payload/extensions/context conversion failure,
    ///                      or depth > 128.
    ///   `RuntimeError`   — plugin execution error or panic at the boundary.
    ///   `TimeoutError`   — wall-clock timeout exceeded (KD7).
    #[pyo3(signature = (hook_name, payload, extensions=None, context_table=None))]
    fn invoke_hook<'py>(
        &self,
        py: Python<'py>,
        hook_name: &str,
        payload: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
        context_table: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // --- GIL held: convert all arguments ---
        let payload_value = pyobj_to_json_value(py, payload, 0)?;
        let rust_payload = resolve_payload(hook_name, payload_value)?;

        let ext_value = match extensions {
            None => serde_json::Value::Object(Default::default()),
            Some(o) => pyobj_to_json_value(py, o, 0)?,
        };
        let rust_extensions: Extensions = extensions_from_value(ext_value)?;

        let ctx_value = match context_table {
            None => serde_json::Value::Null,
            Some(o) => pyobj_to_json_value(py, o, 0)?,
        };
        let rust_context: Option<PluginContextTable> = context_table_from_value(ctx_value)?;

        let manager = Arc::clone(&self.inner);
        let hook_name = hook_name.to_string();

        // --- GIL released: async execution with wall-clock timeout (KD7) ---
        // Panics inside invoke_by_name propagate as task aborts on the tokio
        // runtime — the outer timeout ensures we never block indefinitely.
        future_into_py(py, async move {
            let result = tokio::time::timeout(PY_WALL_CLOCK_TIMEOUT, async move {
                let (pipeline_result, _bg_tasks) = manager
                    .invoke_by_name(&hook_name, rust_payload, rust_extensions, rust_context)
                    .await;
                // _bg_tasks dropped here; fire-and-forget tasks keep running
                // on the manager's TaskTracker and are drained by shutdown() (KD4).
                pipeline_result_to_py(pipeline_result)
            })
            .await;

            match result {
                Ok(inner_result) => inner_result,
                Err(_elapsed) => Err(PyTimeoutError::new_err(format!(
                    "cpex: invoke_hook timed out after {}s",
                    PY_WALL_CLOCK_TIMEOUT.as_secs(),
                ))),
            }
        })
    }
}
