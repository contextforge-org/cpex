// Location: ./crates/cpex-python/src/manager.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// PyPluginManager — PyO3 wrapper for cpex_core::PluginManager.

use std::path::Path;
use std::sync::Arc;

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use cpex_core::manager::PluginManager as CorePluginManager;

use crate::conversions::{
    dict_to_context_table, dict_to_extensions, pipeline_result_to_python,
};
use crate::error::boxed_plugin_error_to_pyerr;
use crate::payload_registry::PayloadRegistry;

// Global payload registry initialized once
static PAYLOAD_REGISTRY: Lazy<PayloadRegistry> = Lazy::new(|| PayloadRegistry::new());

/// Rust-backed plugin manager with 5-phase execution.
///
/// This is a PyO3 wrapper around `cpex_core::PluginManager` that provides
/// a Python-friendly API matching the pure Python implementation in
/// `cpex.framework.manager.PluginManager`.
///
/// # Lifecycle
///
/// ```python
/// # Sync construction - loads and validates config
/// manager = PluginManager("config.yaml")
///
/// # Async initialization - calls plugin.initialize() on all plugins
/// await manager.initialize()
///
/// # Invoke hooks
/// result, contexts = await manager.invoke_hook(
///     "prompt_pre_fetch",
///     {"prompt_id": "123", "name": "test"},
///     {"request_id": "456"}
/// )
///
/// # Shutdown
/// await manager.shutdown()
/// ```
///
/// # Execution Phases
///
/// The manager executes plugins in 5 phases:
/// - SEQUENTIAL: serial, chained, blocking + modifying
/// - TRANSFORM: serial, chained, modifying only
/// - AUDIT: serial, observe-only
/// - CONCURRENT: parallel, blocking only
/// - FIRE_AND_FORGET: background, no blocking/modifying
#[pyclass(name = "PluginManager")]
pub struct PyPluginManager {
    /// Inner Rust plugin manager.
    inner: Arc<CorePluginManager>,
}

#[pymethods]
impl PyPluginManager {
    /// Create a new plugin manager from a YAML config file.
    ///
    /// This is a synchronous operation that loads and validates the config
    /// but does not initialize plugins. Call `initialize()` after construction.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the YAML configuration file
    ///
    /// # Returns
    ///
    /// A new PluginManager instance
    ///
    /// # Raises
    ///
    /// * `ValueError` - If the config file is invalid or cannot be parsed
    ///
    /// # Example
    ///
    /// ```python
    /// manager = PluginManager("plugins/config.yaml")
    /// await manager.initialize()
    /// ```
    #[new]
    fn new(config_path: &str) -> PyResult<Self> {
        // Create the core manager
        let manager = Arc::new(CorePluginManager::default());

        // Load the config file
        let path = Path::new(config_path);
        manager
            .load_config_file(path)
            .map_err(|e| boxed_plugin_error_to_pyerr(&e))?;

        Ok(Self { inner: manager })
    }

    /// Initialize all plugins asynchronously.
    ///
    /// This must be called after construction and before invoking any hooks.
    /// It calls the `initialize()` method on each plugin.
    ///
    /// # Returns
    ///
    /// None
    ///
    /// # Raises
    ///
    /// * `RuntimeError` - If plugin initialization fails
    ///
    /// # Example
    ///
    /// ```python
    /// manager = PluginManager("config.yaml")
    /// await manager.initialize()
    /// ```
    fn initialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.inner);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            manager
                .initialize()
                .await
                .map_err(|e| boxed_plugin_error_to_pyerr(&e))?;
            Ok(())
        })
    }

    /// Invoke a hook with the given payload.
    ///
    /// Executes all registered plugins for the hook in 5-phase order:
    /// SEQUENTIAL → TRANSFORM → AUDIT → CONCURRENT → FIRE_AND_FORGET
    ///
    /// # Arguments
    ///
    /// * `hook_name` - Name of the hook to invoke (e.g., "cmf.tool_pre_invoke")
    /// * `payload` - Payload dictionary (converted to appropriate type based on hook)
    /// * `extensions` - Optional extensions dictionary
    /// * `context_table` - Optional context table from previous invocation
    ///
    /// # Returns
    ///
    /// Tuple of (payload_dict, extensions_dict, context_table_dict, blocked, violation_dict)
    ///
    /// # Raises
    ///
    /// * `ValueError` - If hook name is unknown or payload is invalid
    /// * `RuntimeError` - If plugin execution fails
    ///
    /// # Example
    ///
    /// ```python
    /// payload, ext, ctx, blocked, violation = await manager.invoke_hook(
    ///     "cmf.tool_pre_invoke",
    ///     {"schema_version": "1.0", "role": "user", "content": [...]},
    ///     {},  # extensions
    ///     None  # context_table
    /// )
    /// ```
    fn invoke_hook<'py>(
        &self,
        py: Python<'py>,
        hook_name: &str,
        payload: &Bound<'py, PyDict>,
        extensions: Option<&Bound<'py, PyDict>>,
        context_table: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.inner);
        let hook_name = hook_name.to_string();

        // Convert inputs while holding GIL
        let payload_box = PAYLOAD_REGISTRY.convert(&hook_name, py, payload)?;
        let extensions_struct = dict_to_extensions(py, extensions)?;
        let context_table_opt = dict_to_context_table(py, context_table)?;

        // Release GIL and call Rust async function
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Call the core manager
            let (result, _background_tasks) = manager
                .invoke_by_name(&hook_name, payload_box, extensions_struct, context_table_opt)
                .await;

            // Convert result back to Python (requires GIL)
            Python::with_gil(|py| pipeline_result_to_python(py, result))
        })
    }

    /// Shutdown all plugins asynchronously.
    ///
    /// This calls the `shutdown()` method on each plugin and waits for
    /// all background tasks to complete.
    ///
    /// # Returns
    ///
    /// None
    ///
    /// # Example
    ///
    /// ```python
    /// await manager.shutdown()
    /// ```
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.inner);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            manager.shutdown().await;
            Ok(())
        })
    }

    /// String representation of the manager.
    fn __repr__(&self) -> String {
        format!("<PluginManager at {:p}>", self.inner.as_ref())
    }
}

// Made with Bob
