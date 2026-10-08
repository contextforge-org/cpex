// Location: ./bindings/python/src/manager.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// `PyPolicyEngine`: PyO3 wrapper around `praxis_policy_core::engine::PolicyEngine`,
// exposed to Python as `cpex.PolicyEngine` (and the `cpex.PluginManager`
// alias).
//
// Construction is synchronous; lifecycle methods (`initialize`, `shutdown`,
// `invoke_hook`, `refresh_secrets`) are returned as Python awaitables via
// `future_into_py`.
//
// Call shape:
//   [GIL held]    convert payload/extensions/context under the GIL
//   [GIL released] future_into_py with timeout + tokio::spawn panic isolation
//   [GIL re-acq.] pipeline_result_to_py
//
// BackgroundTasks are dropped (not awaited per call); fire-and-forget tasks
// run on the engine's TaskTracker and are drained by `shutdown()`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use praxis_policy_core::context::PluginContextTable;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::extensions::Extensions;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDateTime, PyTzInfo};
use pyo3_async_runtimes::tokio::future_into_py;

use crate::builtins;
use crate::conversions::{
    context_table_from_value, extensions_from_value, pyobj_to_json_value, resolve_payload,
};
use crate::error::plugin_error_to_pyerr;
use crate::result::pipeline_result_to_py;
use crate::secrets::Refresh;

/// Wall-clock timeout for every async call through the PyO3 boundary.
/// Mirrors `FFI_WALL_CLOCK_TIMEOUT` in cpex-ffi.
const PY_WALL_CLOCK_TIMEOUT: Duration = Duration::from_secs(60);

#[pyclass(name = "PolicyEngine")]
pub struct PyPolicyEngine {
    inner: Arc<PolicyEngine>,
    /// Whether builtins, the transport and the secret providers are
    /// installed. Install runs once per engine.
    installed: AtomicBool,
    /// Set by `shutdown()`. PPE's shutdown is terminal, so every later
    /// call that would drive the engine raises instead.
    shut_down: Arc<AtomicBool>,
}

impl PyPolicyEngine {
    /// Raise `RuntimeError` when `shutdown()` already ran.
    fn ensure_live(&self, op: &str) -> PyResult<()> {
        if self.shut_down.load(Ordering::Acquire) {
            return Err(PyRuntimeError::new_err(format!(
                "cpex: cannot call {op}() after shutdown(); create a new PolicyEngine"
            )));
        }
        Ok(())
    }
}

#[pymethods]
impl PyPolicyEngine {
    /// Create a new `PolicyEngine` from a YAML config file path.
    ///
    /// Synchronous construction; no Python event loop needed.
    ///
    /// Steps (order is load-bearing for the APL visitor's `Weak` upgrade):
    ///   1. `PolicyEngine::default()` into an `Arc`
    ///   2. install builtins, the HTTP transport and the secret providers
    ///      on that same `Arc`
    ///   3. read the file and `load_config_yaml` it
    ///
    /// `allow_private_destinations` (keyword only, default `False`) lets
    /// builtins that perform HTTP (JWKS fetch, OAuth delegation, CIBA,
    /// Vault) reach private, loopback and link-local addresses. Off, such
    /// requests are refused and the builtin reports its egress-denied
    /// code. No policy document can turn this on.
    ///
    /// Raises `ValueError` on missing file, IO error, YAML parse error,
    /// or config validation error (including an unknown plugin kind).
    #[new]
    #[pyo3(signature = (config_path, *, allow_private_destinations = false))]
    fn new(config_path: &str, allow_private_destinations: bool) -> PyResult<Self> {
        let yaml = std::fs::read_to_string(config_path).map_err(|e| {
            PyValueError::new_err(format!(
                "cpex: cannot read config file '{config_path}': {e}"
            ))
        })?;

        let engine = Self {
            inner: Arc::new(PolicyEngine::default()),
            installed: AtomicBool::new(false),
            shut_down: Arc::new(AtomicBool::new(false)),
        };
        builtins::install(&engine.inner, &engine.installed, allow_private_destinations);
        engine
            .inner
            .load_config_yaml(&yaml)
            .map_err(plugin_error_to_pyerr)?;

        Ok(engine)
    }

    /// Initialize all registered plugins and resolve declared secrets.
    ///
    /// Must be called before any `invoke_hook` call.
    /// Returns an awaitable (coroutine).
    fn initialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_live("initialize")?;
        let engine = Arc::clone(&self.inner);
        future_into_py(py, async move {
            let result = tokio::time::timeout(PY_WALL_CLOCK_TIMEOUT, async move {
                engine.initialize().await.map_err(plugin_error_to_pyerr)
            })
            .await;

            match result {
                Ok(inner_result) => inner_result,
                Err(_elapsed) => Err(PyTimeoutError::new_err(
                    "cpex: PolicyEngine::initialize timed out",
                )),
            }
        })
    }

    /// Shut down all registered plugins and drain fire-and-forget tasks.
    ///
    /// Terminal: later `initialize`, `invoke_hook` and `refresh_secrets`
    /// calls raise `RuntimeError`. A second `shutdown()` is a no-op.
    /// Returns an awaitable (coroutine).
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let engine = Arc::clone(&self.inner);
        let already = self.shut_down.swap(true, Ordering::AcqRel);
        future_into_py(py, async move {
            if already {
                return Ok(());
            }
            let result = tokio::time::timeout(PY_WALL_CLOCK_TIMEOUT, async move {
                engine.shutdown().await;
                Ok::<(), PyErr>(())
            })
            .await;

            match result {
                Ok(inner_result) => inner_result,
                Err(_elapsed) => Err(PyTimeoutError::new_err(
                    "cpex: PolicyEngine::shutdown timed out",
                )),
            }
        })
    }

    /// Invoke a hook by name.
    ///
    /// Args:
    ///   hook_name: str, e.g. `"cmf.tool_pre_invoke"` or any custom name.
    ///   payload:   dict, converted via direct PyObject to serde_json
    ///              traversal (no Python `json` module).
    ///   extensions: dict | None, optional cpex Extensions fields. Under
    ///              the default `dispatch: policy`, `meta.entity_type` and
    ///              `meta.entity_name` select the route.
    ///   context_table: dict | None, optional PluginContextTable to thread
    ///              through for stateful plugins.
    ///
    /// Returns an awaitable that resolves to `PipelineResult`.
    ///
    /// Raises:
    ///   `ValueError`     payload/extensions/context conversion failure,
    ///                    or depth > 128.
    ///   `RuntimeError`   plugin execution error, panic at the boundary,
    ///                    or a call after `shutdown()`.
    ///   `TimeoutError`   wall-clock timeout exceeded.
    #[pyo3(signature = (hook_name, payload, extensions=None, context_table=None))]
    fn invoke_hook<'py>(
        &self,
        py: Python<'py>,
        hook_name: &str,
        payload: &Bound<'_, PyAny>,
        extensions: Option<&Bound<'_, PyAny>>,
        context_table: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_live("invoke_hook")?;
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

        let engine = Arc::clone(&self.inner);
        let hook_name = hook_name.to_string();

        // GIL released: async execution with wall-clock timeout.
        // future_into_py catches panics via tokio's JoinHandle and converts them
        // to pyo3_async_runtimes.RustPanic (a PyException subclass). To keep the
        // documented interface consistent (the docstring promises RuntimeError)
        // we spawn invoke_by_name as an isolated tokio task and intercept the
        // JoinError::is_panic() case ourselves, converting it to RuntimeError.
        // This mirrors cpex-ffi's run_safely/catch_unwind pattern at the async
        // boundary.
        future_into_py(
            py,
            invoke_with_timeout(
                engine,
                hook_name,
                rust_payload,
                rust_extensions,
                rust_context,
                PY_WALL_CLOCK_TIMEOUT,
            ),
        )
    }

    /// Re-read every declared secret (renewing a Vault token when due).
    ///
    /// Returns an awaitable resolving to a dict:
    ///
    ///   {"updated": [str], "unchanged": int,
    ///    "failed": [{"secret": str, "provider": str, "kind": str,
    ///                "message": str}]}
    ///
    /// `kind` is one of `config`, `reference`, `not_found`, `malformed`,
    /// `backend` or `other`. A failed re-read is listed, not raised; the
    /// value keeps its last-good bytes. An engine with no `secrets:` block,
    /// or not yet initialized, returns an empty report.
    ///
    /// Raises `RuntimeError` after `shutdown()` and `TimeoutError` past
    /// the wall-clock timeout.
    fn refresh_secrets<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_live("refresh_secrets")?;
        let engine = Arc::clone(&self.inner);
        future_into_py(py, async move {
            match tokio::time::timeout(PY_WALL_CLOCK_TIMEOUT, engine.refresh_secrets()).await {
                Ok(report) => {
                    // Log only the names and the failure class. The full
                    // message stays in the report returned to Python.
                    for failure in &report.failed {
                        tracing::warn!(
                            secret = %failure.secret,
                            provider = %failure.provider,
                            kind = crate::secrets::error_kind(&failure.source),
                            "cpex-python: secret refresh failed"
                        );
                    }
                    Ok(Refresh::from(report))
                },
                Err(_elapsed) => Err(PyTimeoutError::new_err(
                    "cpex: PolicyEngine::refresh_secrets timed out",
                )),
            }
        })
    }

    /// When `provider` last re-read all of its values without a failure,
    /// as a timezone-aware UTC `datetime`, or `None`.
    ///
    /// `None` means the provider's most recent refresh failed, the name is
    /// not a declared provider, or secrets are not resolved yet.
    /// Initialization counts as the first success. Synchronous.
    fn secrets_last_success<'py>(
        &self,
        py: Python<'py>,
        provider: &str,
    ) -> PyResult<Option<Bound<'py, PyDateTime>>> {
        let Some(at) = self.inner.secrets_last_success(provider) else {
            return Ok(None);
        };
        let utc = PyTzInfo::utc(py)?.to_owned();
        let seconds = at.timestamp_millis() as f64 / 1000.0;
        PyDateTime::from_timestamp(py, seconds, Some(&utc)).map(Some)
    }
}

/// Drives a single `invoke_by_name` call with an isolated tokio task (panic
/// capture) and a wall-clock timeout, returning a Python-compatible result.
///
/// Extracted from `invoke_hook` so the test module can pass a short timeout
/// without touching `PY_WALL_CLOCK_TIMEOUT`.
pub(crate) async fn invoke_with_timeout(
    manager: Arc<PolicyEngine>,
    hook_name: String,
    rust_payload: Box<dyn praxis_policy_core::hooks::payload::PluginPayload>,
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
    use praxis_policy_core::context::PluginContext;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::extensions::Extensions;
    use praxis_policy_core::hooks::PluginResult;
    use praxis_policy_core::hooks::payload::PluginPayload;
    use praxis_policy_core::hooks::trait_def::HookTypeDef;
    use std::time::Duration;

    use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};

    // A minimal payload type for test dispatch; must match the hook's
    // associated Payload type so the executor's typed-adapter downcast finds
    // the handler.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct TestPayload {
        value: String,
    }
    praxis_policy_core::impl_plugin_payload!(TestPayload);

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

    impl praxis_policy_core::hooks::HookHandler<PanicHook> for PanickingPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            panic!("simulated panic from PanickingPlugin");
        }
    }

    /// A plugin that sleeps forever; exercises the wall-clock timeout path.
    struct BlockingPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for BlockingPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    impl praxis_policy_core::hooks::HookHandler<BlockHook> for BlockingPlugin {
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

    fn build_blocking_manager() -> Arc<PolicyEngine> {
        let manager = Arc::new(PolicyEngine::default());
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

    fn build_panicking_manager() -> Arc<PolicyEngine> {
        let manager = Arc::new(PolicyEngine::default());
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

    /// A panicking plugin must not abort the process or unwind into the
    /// pyo3_async_runtimes dispatch task. PPE contains the panic in its
    /// executor and reports it as a denial with code `plugin_panic`; the
    /// `tokio::spawn` in `invoke_with_timeout` stays as the backstop for a
    /// panic outside the executor.
    #[tokio::test]
    async fn invoke_on_panicking_plugin_is_contained_by_the_engine() {
        let manager = build_panicking_manager();
        manager.initialize().await.expect("initialize");

        let payload: Box<dyn PluginPayload> = Box::new(TestPayload {
            value: "trigger".into(),
        });
        let hook_name = "test.panic_hook".to_string();
        let manager2 = Arc::clone(&manager);

        let (result, _bg) = tokio::spawn(async move {
            manager2
                .invoke_by_name(&hook_name, payload, Extensions::default(), None)
                .await
        })
        .await
        .expect("the engine contains the panic; the task must not fail");

        assert!(!result.continue_processing, "a panic must deny");
        let violation = result.violation.expect("the panic is reported");
        assert_eq!(violation.code, "plugin_panic");
    }

    /// The wall-clock timeout in `invoke_with_timeout` fires when a plugin
    /// holds the thread past the deadline. This test verifies the underlying
    /// mechanism: `tokio::time::timeout` with a 1 ms deadline on a future that
    /// sleeps for 1 hour returns `Err(Elapsed)`.
    ///
    /// We test at this level (below `invoke_with_timeout`) because
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
