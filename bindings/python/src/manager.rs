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
//   [GIL release] future_into_py with timeout + tokio::spawn panic isolation
//   [GIL re-acq.] pipeline_result_to_py
//
// BackgroundTasks are dropped (not awaited per call); fire-and-forget tasks
// run on the manager's TaskTracker and are drained by `shutdown()` (KD4).

use std::sync::Arc;
use std::time::Duration;

use cpex_core::context::PluginContextTable;
use cpex_core::extensions::Extensions;
use cpex_core::manager::PluginManager;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
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
        // future_into_py catches panics via tokio's JoinHandle and converts them
        // to pyo3_async_runtimes.RustPanic (a PyException subclass). To keep the
        // documented interface consistent — the docstring promises RuntimeError —
        // we spawn invoke_by_name as an isolated tokio task and intercept the
        // JoinError::is_panic() case ourselves, converting it to RuntimeError.
        // This mirrors cpex-ffi's run_safely/catch_unwind pattern at the async
        // boundary.
        future_into_py(
            py,
            invoke_with_timeout(
                manager,
                hook_name,
                rust_payload,
                rust_extensions,
                rust_context,
                PY_WALL_CLOCK_TIMEOUT,
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Async helper — extracted so tests can inject a short timeout
// ---------------------------------------------------------------------------

/// Drives a single `invoke_by_name` call with an isolated tokio task (panic
/// capture) and a wall-clock timeout, returning a Python-compatible result.
///
/// Extracted from `invoke_hook` so the test module can pass a short timeout
/// without touching `PY_WALL_CLOCK_TIMEOUT`.
pub(crate) async fn invoke_with_timeout(
    manager: Arc<PluginManager>,
    hook_name: String,
    rust_payload: Box<dyn cpex_core::hooks::payload::PluginPayload>,
    rust_extensions: Extensions,
    rust_context: Option<PluginContextTable>,
    timeout: Duration,
) -> PyResult<crate::result::PyPipelineResult> {
    let result = tokio::time::timeout(timeout, async move {
        // Spawn onto the runtime so a panicking plugin task is isolated:
        // its JoinHandle carries the panic payload rather than unwinding
        // through pyo3_async_runtimes' dispatch infrastructure.
        // The async block moves all owned values in so the future is
        // 'static, as required by tokio::spawn.
        match tokio::spawn(async move {
            manager
                .invoke_by_name(&hook_name, rust_payload, rust_extensions, rust_context)
                .await
        })
        .await
        {
            Ok((pipeline_result, _bg_tasks)) => pipeline_result_to_py(pipeline_result),
            Err(join_err) if join_err.is_panic() => {
                let payload = join_err.into_panic();
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("unknown panic");
                Err(PyRuntimeError::new_err(format!(
                    "cpex: plugin panicked: {msg}"
                )))
            },
            Err(_cancelled) => Err(PyRuntimeError::new_err("cpex: plugin task was cancelled")),
        }
    })
    .await;

    match result {
        Ok(inner_result) => inner_result,
        Err(_elapsed) => Err(PyTimeoutError::new_err(format!(
            "cpex: invoke_hook timed out after {}s",
            timeout.as_secs(),
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// These tests exercise the tokio::spawn + JoinError::is_panic() panic-catching
// path without requiring a live Python interpreter. They run under plain
// `cargo test -p cpex-python` (cdylibs produce a separate test binary that
// doesn't link against libpython).
//
// The test mirrors the FFI crate's `cpex_invoke_returns_rc_panic_when_plugin_panics`
// pattern: register a plugin that unconditionally panics, invoke it, verify the
// panic is caught and surfaced as a JoinError rather than aborting the process.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::Extensions;
    use cpex_core::hooks::payload::PluginPayload;
    use cpex_core::hooks::trait_def::HookTypeDef;
    use cpex_core::hooks::PluginResult;
    use cpex_core::manager::PluginManager;
    use std::time::Duration;

    use cpex_core::plugin::{Plugin, PluginConfig, PluginMode};

    // A minimal payload type for test dispatch — must match the hook's
    // associated Payload type so the executor's typed-adapter downcast finds
    // the handler.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct TestPayload {
        value: String,
    }
    cpex_core::impl_plugin_payload!(TestPayload);

    struct PanicHook;
    impl HookTypeDef for PanicHook {
        type Payload = TestPayload;
        type Result = PluginResult<TestPayload>;
        const NAME: &'static str = "test.panic_hook";
    }

    struct BlockHook;
    impl HookTypeDef for BlockHook {
        type Payload = TestPayload;
        type Result = PluginResult<TestPayload>;
        const NAME: &'static str = "test.block_hook";
    }

    struct PanickingPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for PanickingPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl cpex_core::hooks::HookHandler<PanicHook> for PanickingPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            panic!("simulated panic from PanickingPlugin");
        }
    }

    /// A plugin that sleeps forever — exercises the wall-clock timeout path.
    struct BlockingPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for BlockingPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl cpex_core::hooks::HookHandler<BlockHook> for BlockingPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            PluginResult::allow()
        }
    }

    fn build_blocking_manager() -> Arc<PluginManager> {
        let manager = Arc::new(PluginManager::default());
        let cfg = PluginConfig {
            name: "blocker".into(),
            kind: "test".into(),
            hooks: vec!["test.block_hook".into()],
            mode: PluginMode::Sequential,
            ..Default::default()
        };
        let plugin = Arc::new(BlockingPlugin { cfg: cfg.clone() });
        manager
            .register_handler::<BlockHook, _>(plugin, cfg)
            .expect("register");
        manager
    }

    fn build_panicking_manager() -> Arc<PluginManager> {
        let manager = Arc::new(PluginManager::default());
        let cfg = PluginConfig {
            name: "panicker".into(),
            kind: "test".into(),
            hooks: vec!["test.panic_hook".into()],
            mode: PluginMode::Sequential,
            ..Default::default()
        };
        let plugin = Arc::new(PanickingPlugin { cfg: cfg.clone() });
        manager
            .register_handler::<PanicHook, _>(plugin, cfg)
            .expect("register");
        manager
    }

    /// The `tokio::spawn` in `invoke_hook` must catch a panicking plugin and
    /// surface `JoinError::is_panic()` rather than aborting the process or
    /// leaking the panic to the pyo3_async_runtimes dispatch task.
    ///
    /// This is the Rust-level regression test for the panic-isolation
    /// guarantee; the Python-level guarantee is that `invoke_hook` raises
    /// `RuntimeError` rather than `pyo3_async_runtimes.RustPanic`.
    #[tokio::test]
    async fn invoke_on_panicking_plugin_returns_join_error_is_panic() {
        let manager = build_panicking_manager();
        manager.initialize().await.expect("initialize");

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "trigger".into(),
        });
        let hook_name = "test.panic_hook".to_string();
        let manager2 = Arc::clone(&manager);

        let join_result = tokio::spawn(async move {
            manager2
                .invoke_by_name(&hook_name, payload, Extensions::default(), None)
                .await
        })
        .await;

        assert!(
            join_result.is_err(),
            "spawned task should have failed due to panic"
        );
        let join_err = join_result.unwrap_err();
        assert!(
            join_err.is_panic(),
            "JoinError should report is_panic()=true, not a cancellation"
        );

        // Verify the panic message is extractable — this is the same downcast
        // logic used in invoke_hook to build the RuntimeError message.
        let payload = join_err.into_panic();
        let msg = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("unknown panic");
        assert!(
            msg.contains("simulated panic"),
            "panic message should propagate, got: {msg}"
        );
    }

    /// The wall-clock timeout in `invoke_with_timeout` fires when a plugin
    /// holds the thread past the deadline. This test verifies the underlying
    /// mechanism: `tokio::time::timeout` with a 1 ms deadline on a future that
    /// sleeps for 1 hour returns `Err(Elapsed)`.
    ///
    /// We test at this level — below `invoke_with_timeout` — because
    /// constructing a `PyErr` (e.g. `PyTimeoutError::new_err`) requires a live
    /// Python interpreter, which is unavailable in pure `cargo test` runs.
    /// The production mapping from `Elapsed` → `PyTimeoutError` is trivial and
    /// tested end-to-end by the Python test suite.
    #[tokio::test]
    async fn blocking_plugin_future_is_cancelled_by_short_timeout() {
        let manager = build_blocking_manager();
        manager.initialize().await.expect("initialize");

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "trigger".into(),
        });

        // Drive invoke_by_name directly under a 1 ms tokio::time::timeout,
        // bypassing invoke_with_timeout so no PyErr is constructed.
        let result = tokio::time::timeout(
            Duration::from_millis(1),
            tokio::spawn(async move {
                manager
                    .invoke_by_name("test.block_hook", payload, Extensions::default(), None)
                    .await
            }),
        )
        .await;

        assert!(
            result.is_err(),
            "timeout should have fired before the plugin completed"
        );
    }
}
