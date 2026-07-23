// Location: ./crates/cpex-hosts-python/src/isolated/adapter.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// IsolatedPythonPluginAdapter — Plugin lifecycle + AnyHookHandler dispatch.
//
// Wraps a WorkerProcess and drives it with JSON-lines tasks over the
// same protocol as Python's VenvProcessCommunicator / worker.py.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cpex_core::{
    context::PluginContext,
    error::PluginError,
    hooks::payload::{Extensions, PluginPayload},
    plugin::{Plugin, PluginConfig},
    registry::AnyHookHandler,
};
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;

use super::payload::HookPayloadRegistry;
use super::subprocess::WorkerProcess;
use super::venv::VenvManager;

const INVOKE_TIMEOUT_SECS: u64 = 30;

/// Subprocess-isolated Python plugin adapter.
///
/// One instance wraps one Python plugin class running in a dedicated
/// worker.py subprocess. The same `Arc<IsolatedPythonPluginAdapter>` is
/// registered as the handler for every hook name in `config.hooks`.
pub struct IsolatedPythonPluginAdapter {
    pub config: PluginConfig,
    venv_manager: VenvManager,
    worker: Mutex<Option<WorkerProcess>>,
    registry: Arc<HookPayloadRegistry>,
    class_name: String,
    plugin_dirs: Vec<String>,
    /// Explicit `worker.py` override. When `None`, the worker is resolved from
    /// the venv's installed `cpex` framework at `initialize()` time.
    worker_script: Option<std::path::PathBuf>,
}

impl IsolatedPythonPluginAdapter {
    pub fn new(
        config: PluginConfig,
        venv_manager: VenvManager,
        registry: Arc<HookPayloadRegistry>,
        class_name: String,
        plugin_dirs: Vec<String>,
        worker_script: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            config,
            venv_manager,
            worker: Mutex::new(None),
            registry,
            class_name,
            plugin_dirs,
            worker_script,
        }
    }

    fn safe_config(&self) -> serde_json::Value {
        // Serialize PluginConfig to JSON, omitting private/secret fields.
        // We use serde_json::to_value on the whole config; the Python worker
        // receives this as the `config` string (JSON-encoded).
        serde_json::to_value(&self.config).unwrap_or(serde_json::Value::Null)
    }

    /// Invoke a named hook on the worker subprocess.
    async fn invoke_hook(
        &self,
        hook_name: &str,
        payload: &dyn PluginPayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        let payload_json = self
            .registry
            .payload_to_json(hook_name, payload)
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: e.to_string(),
                })
            })?;

        // Build context in Python's PluginContext schema:
        //   { state: {}, global_context: { request_id: "..." }, metadata: {} }
        // The Rust PluginContext uses local_state/global_state which is a
        // different schema — map it explicitly so worker.py can validate it.
        let context_json = serde_json::json!({
            "state": ctx.local_state,
            "global_context": {
                "request_id": Uuid::new_v4().to_string(),
                "state": ctx.global_state,
            },
            "metadata": {},
        });

        let task = serde_json::json!({
            "task_type": "load_and_run_hook",
            "plugin_dirs": self.plugin_dirs,
            "class_name": self.class_name,
            "config": serde_json::to_string(&self.safe_config()).unwrap_or_default(),
            "hook_type": hook_name,
            "plugin_name": self.config.name,
            "payload": payload_json,
            "context": context_json,
        });

        let guard = self.worker.lock().await;
        let worker = guard.as_ref().ok_or_else(|| {
            Box::new(PluginError::Config {
                message: format!(
                    "plugin '{}': worker not started — call initialize() first",
                    self.config.name
                ),
            })
        })?;

        let timeout = Duration::from_secs(INVOKE_TIMEOUT_SECS);
        let response = worker.send_task(task, timeout).await.map_err(|e| {
            Box::new(PluginError::Config {
                message: format!("plugin '{}': worker error: {}", self.config.name, e),
            })
        })?;

        debug!(
            plugin = %self.config.name,
            hook = hook_name,
            "received worker response"
        );

        let erased = self
            .registry
            .json_to_erased(hook_name, response)
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': failed to decode worker response: {:?}",
                        self.config.name, e
                    ),
                })
            })?;

        Ok(Box::new(erased))
    }
}

#[async_trait]
impl Plugin for IsolatedPythonPluginAdapter {
    fn config(&self) -> &PluginConfig {
        &self.config
    }

    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        info!(plugin = %self.config.name, "initializing isolated Python plugin");
        self.venv_manager.ensure_venv().await.map_err(|e| {
            Box::new(PluginError::Config {
                message: format!("plugin '{}': venv error: {}", self.config.name, e),
            })
        })?;

        let python_exe = self.venv_manager.python_executable();

        // Resolve worker.py from the venv's installed cpex framework unless an
        // explicit override was configured. The framework arrives in the venv
        // transitively via the plugin's requirements, so there is no reliable
        // project-relative path to the worker.
        let worker_script = match &self.worker_script {
            Some(path) => path.clone(),
            None => super::factory::resolve_worker_script(&python_exe).ok_or_else(|| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': could not locate '{}' in venv {:?} — is cpex installed \
                         there (via the plugin's requirements)?",
                        self.config.name,
                        super::factory::WORKER_MODULE,
                        self.venv_manager.venv_path,
                    ),
                })
            })?,
        };

        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let worker = WorkerProcess::spawn(&python_exe, &worker_script, &cwd)
            .await
            .map_err(|e| {
                Box::new(PluginError::Config {
                    message: format!(
                        "plugin '{}': failed to spawn worker: {}",
                        self.config.name, e
                    ),
                })
            })?;

        *self.worker.lock().await = Some(worker);
        info!(plugin = %self.config.name, "worker subprocess started");
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        info!(plugin = %self.config.name, "shutting down isolated Python plugin");
        let mut guard = self.worker.lock().await;
        if let Some(worker) = guard.take() {
            worker.shutdown(5).await;
        }
        Ok(())
    }
}

/// An `AnyHookHandler` bound to a specific hook name.
///
/// Each hook name in `config.hooks` gets its own `BoundHookHandler`
/// wrapping the same `Arc<IsolatedPythonPluginAdapter>`. The handler's
/// `hook_type_name()` returns the pre-bound name.
pub struct BoundHookHandler {
    adapter: Arc<IsolatedPythonPluginAdapter>,
    hook_name: &'static str,
}

impl BoundHookHandler {
    pub fn new(adapter: Arc<IsolatedPythonPluginAdapter>, hook_name: &'static str) -> Self {
        Self { adapter, hook_name }
    }
}

#[async_trait]
impl AnyHookHandler for BoundHookHandler {
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        self.adapter
            .invoke_hook(self.hook_name, payload, extensions, ctx)
            .await
    }

    fn hook_type_name(&self) -> &'static str {
        self.hook_name
    }
}
