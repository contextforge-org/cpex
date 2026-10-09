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
//
// `initialize` and `shutdown` share one lifecycle lock (see `Lifecycle`), so
// a shutdown waits for an in-flight initialize instead of finding nothing to
// tear down while that initialize goes on to start plugins.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use praxis_policy_core::context::PluginContextTable;
use praxis_policy_core::engine::PolicyEngine;
use praxis_policy_core::error::PluginError;
use praxis_policy_core::extensions::Extensions;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDateTime, PyTzInfo};
use pyo3_async_runtimes::tokio::{future_into_py, future_into_py_with_locals, get_current_locals};
use tokio::task::JoinHandle;

use crate::conversions::{
    context_table_from_value, extensions_from_value, pyobj_to_json_value, reject_removed_hook,
    resolve_payload,
};
use crate::error::plugin_error_to_pyerr;
use crate::result::pipeline_result_to_py;
use crate::secrets::Refresh;

/// Wall-clock timeout for every async call through the PyO3 boundary.
/// Mirrors `FFI_WALL_CLOCK_TIMEOUT` in cpex-ffi.
const PY_WALL_CLOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a lifecycle call failed, before it is mapped to a Python exception.
/// Kept free of `PyErr` so the lifecycle logic is testable without an
/// interpreter.
#[derive(Debug)]
pub(crate) enum LifecycleError {
    /// `shutdown()` has started; the engine takes no more lifecycle calls.
    ShutDown,
    /// The wall-clock timeout elapsed.
    Timeout,
    /// The engine panicked; the message is the panic payload.
    Panicked(String),
    /// The engine reported an error.
    Engine(Box<PluginError>),
}

/// The engine plus the state that orders `initialize` and `shutdown`.
///
/// Both hold `lock` for their whole run, and both run their engine call in
/// a spawned task that owns the lock guard. A timeout or a cancelled
/// awaitable therefore never drops PPE's `initialize` or `shutdown` part
/// way: the task finishes and only then lets the next lifecycle call in.
#[derive(Clone)]
pub(crate) struct Lifecycle {
    engine: Arc<PolicyEngine>,
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Set when `shutdown()` is called, or when an
    /// initialize timeout begins its rollback. Every later call that would
    /// drive the engine is refused.
    shutdown_started: Arc<AtomicBool>,
    /// Set once `PolicyEngine::shutdown` has completed. A later shutdown
    /// is then a no-op; until then a timed-out shutdown can be retried.
    shut_down: Arc<AtomicBool>,
}

impl Lifecycle {
    pub(crate) fn new(engine: Arc<PolicyEngine>) -> Self {
        Self {
            engine,
            lock: Arc::new(tokio::sync::Mutex::new(())),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            shut_down: Arc::new(AtomicBool::new(false)),
        }
    }

    fn is_shutting_down(&self) -> bool {
        self.shutdown_started.load(Ordering::Acquire)
    }

    /// Initialize the engine, waiting for any lifecycle call in flight.
    ///
    /// On timeout the initialize keeps running in its task; once it ends,
    /// the engine is shut down to roll back the plugins it started, and the
    /// engine is terminal from the moment the timeout fires.
    pub(crate) async fn initialize(&self, timeout: Duration) -> Result<(), LifecycleError> {
        let guard = match tokio::time::timeout(timeout, Arc::clone(&self.lock).lock_owned()).await {
            Ok(guard) => guard,
            Err(_elapsed) => return Err(LifecycleError::Timeout),
        };
        if self.is_shutting_down() {
            return Err(LifecycleError::ShutDown);
        }
        let engine = Arc::clone(&self.engine);
        let mut work = tokio::spawn(async move {
            let result = engine.initialize().await;
            (result, guard)
        });
        match tokio::time::timeout(timeout, &mut work).await {
            Ok(Ok((result, _guard))) => result.map_err(LifecycleError::Engine),
            Ok(Err(join_err)) => Err(join_error(join_err)),
            Err(_elapsed) => {
                self.shutdown_started.store(true, Ordering::Release);
                let engine = Arc::clone(&self.engine);
                let shut_down = Arc::clone(&self.shut_down);
                tokio::spawn(async move {
                    // Keep the lock through the rollback so a concurrent
                    // shutdown() waits for it rather than running beside it.
                    if let Ok((_result, _guard)) = work.await {
                        engine.shutdown().await;
                        shut_down.store(true, Ordering::Release);
                    }
                });
                Err(LifecycleError::Timeout)
            },
        }
    }

    /// Start shutdown before returning an awaitable to Python. The task owns
    /// the work, so dropping or cancelling the awaitable cannot undo it.
    fn start_shutdown(&self, runtime: &tokio::runtime::Handle) -> JoinHandle<()> {
        self.shutdown_started.store(true, Ordering::Release);
        let lock = Arc::clone(&self.lock);
        let engine = Arc::clone(&self.engine);
        let shut_down = Arc::clone(&self.shut_down);
        runtime.spawn(async move {
            let _guard = lock.lock_owned().await;
            if shut_down.load(Ordering::Acquire) {
                return;
            }
            engine.shutdown().await;
            shut_down.store(true, Ordering::Release);
        })
    }

    /// Await a shutdown task, without cancelling it on timeout or cancellation.
    async fn await_shutdown(work: JoinHandle<()>, timeout: Duration) -> Result<(), LifecycleError> {
        match tokio::time::timeout(timeout, work).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(join_err)) => Err(join_error(join_err)),
            Err(_elapsed) => Err(LifecycleError::Timeout),
        }
    }

    /// Shut the engine down, waiting for an in-flight initialize first.
    /// A second call after a completed shutdown is a no-op. A timed-out
    /// shutdown keeps running; a retry waits for it.
    pub(crate) async fn shutdown(&self, timeout: Duration) -> Result<(), LifecycleError> {
        let work = self.start_shutdown(&tokio::runtime::Handle::current());
        Self::await_shutdown(work, timeout).await
    }

    /// Re-read every declared secret in an isolated task, so a panicking
    /// provider surfaces as [`LifecycleError::Panicked`].
    pub(crate) async fn refresh_secrets(
        &self,
        timeout: Duration,
    ) -> Result<praxis_policy_core::secrets::RefreshReport, LifecycleError> {
        let engine = Arc::clone(&self.engine);
        let work = tokio::spawn(async move { engine.refresh_secrets().await });
        match tokio::time::timeout(timeout, work).await {
            Ok(Ok(report)) => Ok(report),
            Ok(Err(join_err)) => Err(join_error(join_err)),
            Err(_elapsed) => Err(LifecycleError::Timeout),
        }
    }
}

/// Map a failed spawned task to a [`LifecycleError`].
fn join_error(join_err: tokio::task::JoinError) -> LifecycleError {
    if join_err.is_panic() {
        LifecycleError::Panicked(panic_message(join_err))
    } else {
        LifecycleError::Panicked("task was cancelled".to_owned())
    }
}

/// The text of a panic payload, or `"unknown panic"`.
fn panic_message(join_err: tokio::task::JoinError) -> String {
    let payload = join_err.into_panic();
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_owned())
}

/// Map a [`LifecycleError`] from operation `op` to the documented Python
/// exception.
fn lifecycle_error_to_pyerr(err: LifecycleError, op: &str) -> PyErr {
    match err {
        LifecycleError::ShutDown => shut_down_error(op),
        LifecycleError::Timeout => {
            PyTimeoutError::new_err(format!("cpex: PolicyEngine::{op} timed out"))
        },
        LifecycleError::Panicked(msg) => {
            PyRuntimeError::new_err(format!("cpex: PolicyEngine::{op} panicked: {msg}"))
        },
        LifecycleError::Engine(e) => plugin_error_to_pyerr(e),
    }
}

fn shut_down_error(op: &str) -> PyErr {
    PyRuntimeError::new_err(format!(
        "cpex: cannot call {op}() after shutdown(); create a new PolicyEngine"
    ))
}

#[pyclass(name = "PolicyEngine")]
pub struct PyPolicyEngine {
    inner: Arc<PolicyEngine>,
    lifecycle: Lifecycle,
}

impl PyPolicyEngine {
    /// Raise `RuntimeError` when `shutdown()` already started.
    fn ensure_live(&self, op: &str) -> PyResult<()> {
        if self.lifecycle.is_shutting_down() {
            return Err(shut_down_error(op));
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

        let inner = Arc::new(PolicyEngine::default());
        cpex::host::install_host_defaults(&inner, allow_private_destinations);
        inner
            .load_config_yaml(&yaml)
            .map_err(plugin_error_to_pyerr)?;

        Ok(Self {
            lifecycle: Lifecycle::new(Arc::clone(&inner)),
            inner,
        })
    }

    /// Initialize all registered plugins and resolve declared secrets.
    ///
    /// Must be called before any `invoke_hook` call.
    /// Starts when called; await the returned future for its result.
    ///
    /// Raises `RuntimeError` once `shutdown()` has been called, including a
    /// shutdown that raced with this call's scheduled work.
    /// Raises `TimeoutError` past the wall-clock timeout; the engine then
    /// shuts itself down once the stalled initialize ends, and is terminal.
    fn initialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_live("initialize")?;
        let lifecycle = self.lifecycle.clone();
        future_into_py(py, async move {
            lifecycle
                .initialize(PY_WALL_CLOCK_TIMEOUT)
                .await
                .map_err(|e| lifecycle_error_to_pyerr(e, "initialize"))
        })
    }

    /// Shut down all registered plugins and drain fire-and-forget tasks.
    ///
    /// Waits for an `initialize()` in flight, then shuts the engine down.
    /// Terminal from the call itself: later
    /// `initialize`, `invoke_hook` and `refresh_secrets` calls raise
    /// `RuntimeError`. A second `shutdown()` after one completed is a
    /// no-op. One that raised `TimeoutError` can be retried; the retry
    /// waits for the first to finish.
    /// Starts the shutdown task before returning its awaitable. Dropping or
    /// cancelling the awaitable does not cancel the shutdown task.
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        // Resolve the Python event loop before starting teardown, so a call
        // without an awaitable-capable loop cannot shut down the engine and
        // then fail to return a way to observe its result.
        let locals = get_current_locals(py)?;
        let work = self
            .lifecycle
            .start_shutdown(pyo3_async_runtimes::tokio::get_runtime().handle());
        future_into_py_with_locals(py, locals, async move {
            Lifecycle::await_shutdown(work, PY_WALL_CLOCK_TIMEOUT)
                .await
                .map_err(|e| lifecycle_error_to_pyerr(e, "shutdown"))
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
    ///   `ValueError`     a hook name removed in 0.3 (the message names
    ///                    its replacement), an `identity.resolve` payload
    ///                    that sets a resolver output field,
    ///                    payload/extensions/context conversion failure,
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
        reject_removed_hook(hook_name)?;
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
    /// Raises `RuntimeError` after `shutdown()` or when a secret provider
    /// panics, and `TimeoutError` past the wall-clock timeout.
    fn refresh_secrets<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_live("refresh_secrets")?;
        let lifecycle = self.lifecycle.clone();
        future_into_py(py, async move {
            let report = lifecycle
                .refresh_secrets(PY_WALL_CLOCK_TIMEOUT)
                .await
                .map_err(|e| lifecycle_error_to_pyerr(e, "refresh_secrets"))?;
            // Log only the names and the failure class. The full message
            // stays in the report returned to Python.
            for failure in &report.failed {
                tracing::warn!(
                    secret = %failure.secret,
                    provider = %failure.provider,
                    kind = cpex::host::secret_error_kind(&failure.source),
                    "cpex-python: secret refresh failed"
                );
            }
            Ok(Refresh::from(report))
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
            Err(join_err) if join_err.is_panic() => Err(PyRuntimeError::new_err(format!(
                "cpex: plugin panicked: {}",
                panic_message(join_err)
            ))),
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

// Lifecycle ordering, without a Python interpreter: the logic returns
// `LifecycleError`, which only the pymethods map to `PyErr`.
#[cfg(test)]
mod lifecycle_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use praxis_policy_core::context::PluginContext;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::error::PluginError;
    use praxis_policy_core::extensions::Extensions;
    use praxis_policy_core::hooks::PluginResult;
    use praxis_policy_core::hooks::trait_def::HookTypeDef;
    use praxis_policy_core::plugin::{Plugin, PluginConfig, PluginMode};

    use super::{Lifecycle, LifecycleError, join_error};

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct TestPayload;
    praxis_policy_core::impl_plugin_payload!(TestPayload);

    struct SlowHook;
    impl HookTypeDef for SlowHook {
        type Payload = TestPayload;
        type Result = PluginResult<TestPayload>;
        const NAME: &'static str = "test.slow_hook";
    }

    /// Takes `init_delay` to initialize and counts its initializations and
    /// shutdowns.
    struct SlowPlugin {
        cfg: PluginConfig,
        init_delay: Duration,
        inits: Arc<AtomicUsize>,
        shutdowns: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for SlowPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }

        async fn initialize(&self) -> Result<(), Box<PluginError>> {
            tokio::time::sleep(self.init_delay).await;
            self.inits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), Box<PluginError>> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl praxis_policy_core::hooks::HookHandler<SlowHook> for SlowPlugin {
        async fn handle(
            &self,
            _payload: &TestPayload,
            _extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> PluginResult<TestPayload> {
            PluginResult::allow()
        }
    }

    struct Probe {
        lifecycle: Lifecycle,
        engine: Arc<PolicyEngine>,
        inits: Arc<AtomicUsize>,
        shutdowns: Arc<AtomicUsize>,
    }

    fn probe(init_delay: Duration) -> Probe {
        let engine = Arc::new(PolicyEngine::default());
        let cfg = PluginConfig {
            name: "slow".into(),
            kind: "test".into(),
            hooks: vec![SlowHook::NAME.into()],
            mode: PluginMode::Sequential,
            ..Default::default()
        };
        let inits = Arc::new(AtomicUsize::new(0));
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let plugin = Arc::new(SlowPlugin {
            cfg: cfg.clone(),
            init_delay,
            inits: Arc::clone(&inits),
            shutdowns: Arc::clone(&shutdowns),
        });
        engine
            .register_handler::<SlowHook, _>(plugin, cfg)
            .expect("register");
        Probe {
            lifecycle: Lifecycle::new(Arc::clone(&engine)),
            engine,
            inits,
            shutdowns,
        }
    }

    const LONG: Duration = Duration::from_secs(10);

    /// Wait until a lifecycle call holds the lock, so the test's next call
    /// is known to arrive while it is in flight.
    async fn wait_for_lock_held(lifecycle: &Lifecycle) {
        while lifecycle.lock.try_lock().is_ok() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// A shutdown that arrives while initialize is in flight waits for it,
    /// then tears the started plugins down.
    #[tokio::test]
    async fn shutdown_waits_for_an_in_flight_initialize() {
        let p = probe(Duration::from_millis(100));
        let init = {
            let lifecycle = p.lifecycle.clone();
            tokio::spawn(async move { lifecycle.initialize(LONG).await })
        };
        wait_for_lock_held(&p.lifecycle).await;
        p.lifecycle.shutdown(LONG).await.expect("shutdown");

        init.await.expect("join").expect("initialize");
        assert_eq!(p.inits.load(Ordering::SeqCst), 1);
        assert_eq!(p.shutdowns.load(Ordering::SeqCst), 1);
        assert!(!p.engine.is_initialized());

        // A second shutdown is a no-op; initialize is refused.
        p.lifecycle.shutdown(LONG).await.expect("second shutdown");
        assert_eq!(p.shutdowns.load(Ordering::SeqCst), 1);
        assert!(matches!(
            p.lifecycle.initialize(LONG).await,
            Err(LifecycleError::ShutDown)
        ));
    }

    #[tokio::test]
    async fn started_shutdown_survives_a_dropped_awaitable() {
        let p = probe(Duration::ZERO);
        p.lifecycle.initialize(LONG).await.expect("initialize");

        let work = p
            .lifecycle
            .start_shutdown(&tokio::runtime::Handle::current());
        assert!(p.lifecycle.is_shutting_down(), "terminal at call time");
        drop(work);

        tokio::time::timeout(LONG, async {
            while p.shutdowns.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached shutdown completes");
        assert!(!p.engine.is_initialized());
        p.lifecycle.shutdown(LONG).await.expect("retry is a no-op");
        assert_eq!(p.shutdowns.load(Ordering::SeqCst), 1);
    }

    /// An initialize that times out is rolled back once it ends, and the
    /// engine is terminal.
    #[tokio::test]
    async fn initialize_timeout_rolls_back() {
        let p = probe(Duration::from_millis(100));
        assert!(matches!(
            p.lifecycle.initialize(Duration::from_millis(10)).await,
            Err(LifecycleError::Timeout)
        ));
        assert!(p.lifecycle.is_shutting_down());

        // shutdown() waits for the rollback and finds nothing left to do.
        p.lifecycle.shutdown(LONG).await.expect("shutdown");
        assert_eq!(p.inits.load(Ordering::SeqCst), 1);
        assert_eq!(p.shutdowns.load(Ordering::SeqCst), 1);
        assert!(!p.engine.is_initialized());
    }

    /// A shutdown that times out waiting can be retried, and the retry
    /// runs the shutdown exactly once.
    #[tokio::test]
    async fn timed_out_shutdown_can_be_retried() {
        let p = probe(Duration::from_millis(100));
        let init = {
            let lifecycle = p.lifecycle.clone();
            tokio::spawn(async move { lifecycle.initialize(LONG).await })
        };
        wait_for_lock_held(&p.lifecycle).await;
        assert!(matches!(
            p.lifecycle.shutdown(Duration::from_millis(10)).await,
            Err(LifecycleError::Timeout)
        ));

        p.lifecycle.shutdown(LONG).await.expect("retried shutdown");
        init.await.expect("join").expect("initialize");
        assert_eq!(p.shutdowns.load(Ordering::SeqCst), 1);
        assert!(!p.engine.is_initialized());
    }

    /// A panic in a spawned lifecycle task maps to `Panicked` with the
    /// payload text, the path refresh_secrets uses for a provider panic.
    #[tokio::test]
    async fn a_task_panic_maps_to_panicked() {
        let join_err = tokio::spawn(async { panic!("provider exploded") })
            .await
            .expect_err("the task panics");
        match join_error(join_err) {
            LifecycleError::Panicked(msg) => assert_eq!(msg, "provider exploded"),
            other => panic!("expected Panicked, got {other:?}"),
        }
    }
}
