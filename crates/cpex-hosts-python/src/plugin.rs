// Location: ./crates/cpex-hosts-python/src/plugin.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// `IsolatedPythonPlugin` — the plugin object the factory produces, and
// `PythonHookAdapter` — the per-hook handler that drives one invocation.
//
// The plugin owns the venv manager and the worker client and implements the
// lifecycle half of the contract (initialize / shutdown). The adapter
// implements `AnyHookHandler` directly rather than going through
// `TypedHandlerAdapter`: that adapter downcasts to one fixed payload type,
// but this host forwards whatever payload arrives, serialized, to a worker
// that reconstructs it on the Python side. The concrete type is not known at
// Rust compile time, so there is nothing to downcast to.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use cpex_core::{
    context::PluginContext,
    error::PluginError,
    extensions::Extensions,
    hooks::payload::PluginPayload,
    plugin::{Plugin, PluginConfig},
    registry::AnyHookHandler,
};
use serde::Deserialize;

use crate::error::HostError;
use crate::venv::VenvManager;
use crate::worker::WorkerClient;
use crate::{conversion, credentials};

/// Default cap on the serialized size of one outbound task, in bytes.
///
/// Mirrors `client.py`'s `max_content_size` default. The bound exists so a
/// pathological payload fails fast on this side rather than after the worker
/// has already buffered it.
const DEFAULT_MAX_CONTENT_SIZE: usize = 10_000_000;

/// Default per-invocation timeout, in seconds.
///
/// Mirrors `venv_comm.py`'s `send_task` default. A plugin entry may override
/// it; absent both, the executor's global `plugin_settings.plugin_timeout`
/// still bounds the call from outside.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Path to the worker script, relative to the venv's installed `cpex`.
///
/// The worker ships inside the venv via the plugin's `cpex` dependency, so
/// the host does not carry a copy of it.
const DEFAULT_SCRIPT_PATH: &str = "cpex/framework/isolated/worker.py";

/// Directory, relative to the project root, holding installed Python plugins.
///
/// This is the sole source of the worker's `sys.path` entries and of the
/// directory the venv is built under. It is *not* configurable per plugin: a
/// `plugin_dirs:` key inside a plugin's `config:` block is ignored (see
/// `VenvConfig`), as is the top-level `plugin_dirs:` YAML key, which
/// `cpex_core` already parses and discards.
///
/// # Why a fixed default rather than a config key
///
/// `cpex plugin install` writes the plugin into `<project root>/plugins/` and
/// builds its venv there. Both the Python CLI and this host therefore already
/// agree on the location; making it configurable only creates a way for the
/// two to disagree, and the failure mode is an import error inside the worker
/// at invoke time, far from the config that caused it.
pub const DEFAULT_PLUGIN_DIR: &str = "plugins";

/// The project root the `plugins` directory is resolved against.
///
/// The process working directory. That is not an arbitrary choice: the
/// worker's own `ALLOWED_PLUGIN_DIRS` allowlist accepts `os.getcwd()`, and the
/// worker inherits this host's cwd, so a directory resolved this way is
/// importable by construction. Anchoring anywhere else would produce paths the
/// worker rejects.
fn project_root() -> PathBuf {
    // A cwd that cannot be read is not recoverable here, and returning a
    // relative path keeps the failure legible: the venv layout error names
    // `plugins`, which is what an operator would look for.
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// The plugin directory list the worker and venv layout both use.
///
/// One entry: `<project root>/plugins`. Absolute, so the value does not shift
/// if something later changes the process cwd between `initialize()` and an
/// invocation.
fn default_plugin_dirs() -> Vec<String> {
    vec![project_root()
        .join(DEFAULT_PLUGIN_DIR)
        .display()
        .to_string()]
}

/// Global-state key a host can set to propagate its own request id into the
/// worker's `GlobalContext.request_id`.
///
/// The Rust `PluginContext` has no dedicated request-id field, but the Python
/// `GlobalContext` requires one. Reading it from global state lets a gateway
/// that tracks request ids keep them consistent across the boundary.
pub const GLOBAL_REQUEST_ID_KEY: &str = "request_id";

/// Venv-relevant settings, parsed from a plugin entry's opaque `config` map.
///
/// `PluginConfig` has no fields for a class name, a content-size cap, or a
/// per-plugin timeout — those are host-specific, so they live in the
/// free-form `config` value and are parsed here.
///
/// # `plugin_dirs` is deliberately absent
///
/// A `plugin_dirs:` key in this block is **ignored**, as is the top-level
/// `plugin_dirs:` YAML key. Plugin directories are not configurable: the host
/// always uses `<project root>/plugins`, which is where `cpex plugin install`
/// puts them. See `DEFAULT_PLUGIN_DIR`. Serde ignores unknown fields, so an
/// existing config that still carries the key parses without error — the value
/// simply has no effect.
#[derive(Debug, Clone, Deserialize)]
pub struct VenvConfig {
    /// Fully-qualified Python class implementing the plugin, e.g.
    /// `my_pkg.filters.PiiFilter`. Required: the worker needs it to import
    /// and instantiate the plugin, and the venv cache is keyed on it.
    pub class_name: String,

    /// Requirements file to install into the venv, relative to the package
    /// root. Optional — a plugin installed by FQN conversion gets its
    /// dependencies from the install channel, not a requirements file, and
    /// then the manifest version plus hash is the sole cache signal.
    #[serde(default)]
    pub requirements_file: Option<String>,

    /// Worker script path inside the venv. Defaults to the framework's
    /// `worker.py`; overridable for tests and for a host that vendors its own.
    #[serde(default = "default_script_path")]
    pub script_path: String,

    /// Cap on one serialized outbound task, in bytes.
    #[serde(default = "default_max_content_size")]
    pub max_content_size: usize,

    /// Per-invocation timeout, in seconds. Falls back to the framework
    /// default when absent.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_script_path() -> String {
    DEFAULT_SCRIPT_PATH.to_string()
}

fn default_max_content_size() -> usize {
    DEFAULT_MAX_CONTENT_SIZE
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

impl VenvConfig {
    /// Parse the venv settings out of a plugin entry's `config` map.
    ///
    /// A missing or malformed `class_name` is a config error, not a panic —
    /// the manager surfaces it against the plugin name at load time.
    pub fn from_plugin_config(config: &PluginConfig) -> Result<Self, Box<PluginError>> {
        let raw = config
            .config
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));

        serde_json::from_value(raw).map_err(|e| {
            PluginError::Config {
                message: format!(
                    "plugin '{}' (isolated_venv): invalid `config:` block — {}. \
                     `class_name` is required (the fully-qualified Python class, \
                     e.g. my_pkg.filters.PiiFilter)",
                    config.name, e
                ),
            }
            .boxed()
        })
    }
}

/// A Python plugin running out-of-process in its own virtualenv.
pub struct IsolatedPythonPlugin {
    /// The authoritative config entry, kept for `Plugin::config()`.
    config: PluginConfig,

    /// Venv settings parsed from the entry's `config` map.
    venv_config: VenvConfig,

    /// Directories the worker prepends to `sys.path`, and under whose first
    /// entry the venv is built.
    ///
    /// Host-owned rather than config-derived: `<project root>/plugins`, per
    /// `DEFAULT_PLUGIN_DIR`. Held here rather than recomputed per invocation so
    /// the value stays fixed for the plugin's lifetime even if the process cwd
    /// changes after construction.
    plugin_dirs: Vec<String>,

    /// Builds and caches the venv. `None` only when the layout cannot be
    /// resolved (an empty dir list, or a `class_name` with no package
    /// segment), which is valid solely for a `worker_override` test setup.
    venv: Option<VenvManager>,

    /// The live worker, populated by `initialize()`.
    worker: tokio::sync::RwLock<Option<Arc<WorkerClient>>>,

    /// Absolute worker-script path that bypasses venv resolution. Tests point
    /// this at a stub; production leaves it unset and resolves from the venv.
    worker_override: Option<PathBuf>,

    /// Working directory for the worker process.
    ///
    /// Defaults to the host's own cwd, matching `venv_comm.py`'s
    /// `cwd=os.getcwd()`. This is load-bearing twice over: the worker's
    /// `ALLOWED_PLUGIN_DIRS` allowlist accepts `os.getcwd()`, so a plugin dir
    /// outside it is rejected outright; and a plugin's relative-path side
    /// effects land here.
    worker_cwd: Option<PathBuf>,
}

impl IsolatedPythonPlugin {
    /// Build a plugin from its config entry, parsing the venv settings.
    pub fn from_config(config: &PluginConfig) -> Result<Self, Box<PluginError>> {
        let venv_config = VenvConfig::from_plugin_config(config)?;

        // Not read from the config block — see `DEFAULT_PLUGIN_DIR`. A
        // `plugin_dirs:` key there (or at the YAML top level) is ignored;
        // warning about one is the factory's job, since it can name the plugin.
        let plugin_dirs = default_plugin_dirs();

        // A layout that will not resolve leaves the venv absent. That is a
        // config error in production, but the failure belongs in
        // `initialize()` rather than here: the factory should still hand back a
        // named plugin the manager can report against.
        let venv = VenvManager::new(
            &plugin_dirs,
            &venv_config.class_name,
            venv_config.requirements_file.as_deref(),
            config.version.as_deref(),
        )
        .ok();

        Ok(Self {
            config: config.clone(),
            venv_config,
            plugin_dirs,
            venv,
            worker: tokio::sync::RwLock::new(None),
            worker_override: None,
            worker_cwd: None,
        })
    }

    /// The resolved plugin directories — `<project root>/plugins`.
    pub fn plugin_dirs(&self) -> &[String] {
        &self.plugin_dirs
    }

    /// Run the worker with an explicit working directory.
    ///
    /// Production leaves this unset and inherits the host's cwd. Tests set it
    /// so their scratch plugin dir falls inside the worker's
    /// `ALLOWED_PLUGIN_DIRS` (which accepts `os.getcwd()`), and so a plugin's
    /// marker files land somewhere the test can find and clean up.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_worker_cwd(mut self, cwd: PathBuf) -> Self {
        self.worker_cwd = Some(cwd);
        self
    }

    /// Point the plugin at explicit plugin directories, replacing the
    /// `<project root>/plugins` default.
    ///
    /// Test-only seam. Production has no override by design — the directory is
    /// fixed so the host and `cpex plugin install` cannot disagree. The e2e
    /// tests scaffold a plugin into a temp dir and need the venv built there
    /// rather than in the developer's real `plugins/`, which a test must not
    /// touch.
    ///
    /// Rebuilds the venv manager, since the layout is derived from these dirs.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_plugin_dirs(mut self, dirs: Vec<String>) -> Self {
        self.venv = VenvManager::new(
            &dirs,
            &self.venv_config.class_name,
            self.venv_config.requirements_file.as_deref(),
            self.config.version.as_deref(),
        )
        .ok();
        self.plugin_dirs = dirs;
        self
    }

    /// Point the plugin at an explicit worker script, skipping venv build and
    /// script resolution.
    ///
    /// Test-only seam: the adapter tests need to exercise dispatch against a
    /// stub worker without paying for a real venv, and the credential tests
    /// need a worker that reports exactly what it received.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_worker_override(mut self, script: PathBuf) -> Self {
        self.worker_override = Some(script);
        self
    }

    /// The parsed venv settings.
    pub fn venv_config(&self) -> &VenvConfig {
        &self.venv_config
    }

    /// The live worker's retained stderr, for leak assertions in tests.
    ///
    /// Returns an empty vector when no worker is running.
    #[cfg(any(test, feature = "testing"))]
    pub async fn worker_stderr(&self) -> Vec<String> {
        match self.worker.read().await.as_ref() {
            Some(worker) => worker.stderr_lines().await,
            None => Vec::new(),
        }
    }

    /// The live worker, or a plugin error when `initialize()` has not run.
    async fn worker(&self) -> Result<Arc<WorkerClient>, Box<PluginError>> {
        self.worker.read().await.clone().ok_or_else(|| {
            HostError::WorkerStart {
                message: "plugin has no worker — initialize() did not run or it failed".into(),
            }
            .into_plugin_error(&self.config.name)
        })
    }

    /// Build the `load_and_run_hook` task for one invocation.
    ///
    /// The field names and encodings are the protocol contract with
    /// `worker.py`: `config` is a JSON *string* the worker `json.loads`es into
    /// `PluginConfig(**config_raw)`, and `context` is the worker's own
    /// `{state, global_context, metadata}` shape rather than the Rust
    /// `PluginContext` layout.
    fn build_task(
        &self,
        hook_name: &str,
        payload: serde_json::Value,
        ctx: &PluginContext,
    ) -> Result<serde_json::Value, HostError> {
        // The worker constructs a Python `PluginConfig` from this, so it must
        // carry that model's field names — not this host's venv settings.
        let config_json = serde_json::json!({
            "name": self.config.name,
            "kind": self.config.kind,
            "hooks": self.config.hooks,
            "config": self.config.config.clone().unwrap_or(serde_json::Value::Null),
        });
        let config_string =
            serde_json::to_string(&config_json).map_err(|e| HostError::Protocol {
                message: format!("could not serialize the plugin config for the worker: {e}"),
            })?;

        // Prefer a request id the pipeline already put in global state, so a
        // plugin's logs correlate with the gateway's. `PluginContext` has no
        // dedicated field for one, so fall back to a fresh UUID rather than
        // sending a placeholder that would collide across requests.
        let request_id = ctx
            .get_global(GLOBAL_REQUEST_ID_KEY)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Ok(serde_json::json!({
            "task_type": crate::worker::TASK_LOAD_AND_RUN_HOOK,
            "plugin_dirs": self.plugin_dirs,
            "class_name": self.venv_config.class_name,
            "config": config_string,
            "hook_type": hook_name,
            "plugin_name": self.config.name,
            "payload": payload,
            "context": {
                // `local_state` is this plugin's private slice; `global_state`
                // is the pipeline-wide map the worker exposes as
                // `global_context`.
                "state": ctx.local_state,
                "global_context": {
                    // `request_id` is the one *required* field on the Python
                    // `GlobalContext`; omitting it fails Pydantic validation
                    // inside the worker before the plugin is ever called. The
                    // Rust `PluginContext` carries no request id, so one is
                    // synthesized per invocation — a plugin that correlates
                    // logs by request id still gets a stable, unique value for
                    // the call.
                    "request_id": request_id,
                    "state": ctx.global_state,
                },
                "metadata": {},
            },
        }))
    }
}

#[async_trait]
impl Plugin for IsolatedPythonPlugin {
    fn config(&self) -> &PluginConfig {
        &self.config
    }

    /// Build the venv (or reuse a cached one) and launch the worker.
    ///
    /// Heavy setup lives here rather than on the invoke path: the manager
    /// awaits this once per plugin, with rollback on failure.
    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        let to_plugin_error = |e: HostError| e.into_plugin_error(&self.config.name);

        // With an override the worker script is given outright, so neither a
        // venv nor script resolution is needed — but the interpreter still is.
        let (python, script) = match self.worker_override.as_ref() {
            Some(script) => (which_python3().map_err(to_plugin_error)?, script.clone()),
            None => {
                let venv = self.venv.as_ref().ok_or_else(|| {
                    to_plugin_error(HostError::Config {
                        message: format!(
                            "could not resolve a venv layout under {} — check that `class_name` \
                             ('{}') begins with a package segment",
                            self.plugin_dirs.join(", "),
                            self.venv_config.class_name,
                        ),
                    })
                })?;

                venv.ensure().await.map_err(to_plugin_error)?;
                let script = crate::worker::resolve_worker_script(
                    &venv.layout().venv_path,
                    &self.venv_config.script_path,
                )
                .map_err(to_plugin_error)?;

                (venv.python_executable(), script)
            },
        };

        // Matching `venv_comm.py`'s `cwd=os.getcwd()`. The worker's
        // ALLOWED_PLUGIN_DIRS allowlist accepts its own cwd, so inheriting the
        // host's is what lets a plugin dir declared relative to the gateway be
        // importable at all.
        let worker = WorkerClient::spawn(
            &python,
            &script,
            self.worker_cwd.as_deref(),
            self.venv_config.max_content_size,
            self.venv_config.timeout_secs,
        )
        .await
        .map_err(to_plugin_error)?;

        *self.worker.write().await = Some(Arc::new(worker));
        Ok(())
    }

    /// Stop the worker, killing it if it will not exit on its own.
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        let worker = self.worker.write().await.take();
        if let Some(worker) = worker {
            worker
                .shutdown()
                .await
                .map_err(|e| e.into_plugin_error(&self.config.name))?;
        }
        Ok(())
    }
}

/// Resolve an absolute `python3` from PATH.
///
/// `WorkerClient::spawn` takes an interpreter path rather than doing a PATH
/// lookup, so the override path needs one. Production goes through the venv's
/// own interpreter and never calls this.
fn which_python3() -> Result<PathBuf, HostError> {
    let candidates = [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
    ];
    if let Some(found) = candidates.iter().map(Path::new).find(|p| p.exists()) {
        return Ok(found.to_path_buf());
    }

    // Fall back to asking the shell, which honors PATH (pyenv, conda, nix).
    let output = std::process::Command::new("sh")
        .args(["-c", "command -v python3"])
        .output()
        .map_err(|e| HostError::WorkerStart {
            message: format!("could not look up python3: {e}"),
        })?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(HostError::WorkerStart {
            message: "python3 was not found on PATH".into(),
        });
    }
    Ok(PathBuf::from(path))
}

/// Handler for one hook of one Python plugin.
///
/// Holds the hook name because a single plugin object serves every hook it
/// declared, and the worker needs to be told which one to run.
pub struct PythonHookAdapter {
    plugin: Arc<IsolatedPythonPlugin>,
    hook_name: &'static str,
}

impl PythonHookAdapter {
    pub fn new(plugin: Arc<IsolatedPythonPlugin>, hook_name: &'static str) -> Self {
        Self { plugin, hook_name }
    }
}

#[async_trait]
impl AnyHookHandler for PythonHookAdapter {
    /// Serialize, send, and convert one hook invocation.
    ///
    /// Every failure returns a `PluginError` and stops there — the *executor*
    /// applies the plugin's configured `on_error` policy (fail / ignore /
    /// disable). This host deliberately does not interpret that policy itself;
    /// doing so would double-apply it.
    async fn invoke(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
        let plugin_name = &self.plugin.config.name;
        let to_plugin_error = |e: HostError| e.into_plugin_error(plugin_name);

        let payload_json = conversion::serialize_payload(payload).map_err(to_plugin_error)?;
        let mut task = self
            .plugin
            .build_task(self.hook_name, payload_json, ctx)
            .map_err(to_plugin_error)?;

        // Raw credentials, for the two hooks that carry them and only for a
        // plugin that declared the matching capability. Fails closed.
        credentials::attach_credential(
            &mut task,
            self.hook_name,
            extensions,
            &self.plugin.config.capabilities,
        )
        .map_err(to_plugin_error)?;

        // The capability-filtered extensions, so a 3-arg
        // `(payload, context, extensions)` hook sees out-of-process what it
        // would see in-process. Attaches nothing when no slot is visible.
        crate::extensions::attach_extensions(&mut task, extensions).map_err(to_plugin_error)?;

        let worker = self.plugin.worker().await?;
        let response = worker.send_task(task).await.map_err(to_plugin_error)?;

        // State the worker sends back is merged into the caller's context
        // before the result is returned, so a plugin's context writes survive.
        apply_context_deltas(&response, ctx);

        // `extensions` is passed back in so the returned-extensions path can
        // reuse the inbound `Arc`s for immutable slots and read the write
        // tokens the executor issued. The executor's copy-on-write merge then
        // validates the result against the mutability tiers.
        let fields = conversion::response_to_result(self.hook_name, response, extensions)
            .map_err(to_plugin_error)?;
        Ok(Box::new(fields))
    }

    fn hook_type_name(&self) -> &'static str {
        self.hook_name
    }
}

/// Merge worker-returned context state back into the mutable plugin context.
///
/// The worker returns the context under the same `{state, global_context}`
/// shape it received. Merging rather than replacing is deliberate: a plugin
/// that touched one key must not blank out the rest of the pipeline's state.
fn apply_context_deltas(response: &serde_json::Value, ctx: &mut PluginContext) {
    let Some(context) = response.get("context") else {
        return;
    };

    if let Some(state) = context.get("state").and_then(|v| v.as_object()) {
        for (key, value) in state {
            ctx.local_state.insert(key.clone(), value.clone());
        }
    }

    if let Some(global) = context
        .get("global_context")
        .and_then(|g| g.get("state"))
        .and_then(|v| v.as_object())
    {
        for (key, value) in global {
            ctx.global_state.insert(key.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::TempDir;

    use super::*;

    fn config_with(value: serde_json::Value) -> PluginConfig {
        PluginConfig {
            name: "py-plugin".into(),
            kind: crate::factory::KIND.into(),
            hooks: vec!["tool_pre_invoke".into()],
            config: Some(value),
            ..Default::default()
        }
    }

    #[test]
    fn full_config_block_deserializes_every_field() {
        let cfg = VenvConfig::from_plugin_config(&config_with(serde_json::json!({
            "class_name": "my_pkg.filters.PiiFilter",
            "requirements_file": "requirements.txt",
            "plugin_dirs": ["./plugins", "./vendor"],
            "script_path": "custom/worker.py",
            "max_content_size": 2048,
            "timeout_secs": 5,
        })))
        .expect("a fully populated block parses");

        assert_eq!(cfg.class_name, "my_pkg.filters.PiiFilter");
        assert_eq!(cfg.requirements_file.as_deref(), Some("requirements.txt"));
        assert_eq!(cfg.script_path, "custom/worker.py");
        assert_eq!(cfg.max_content_size, 2048);
        assert_eq!(cfg.timeout_secs, 5);
        // The block above also carries `plugin_dirs`, which is no longer a
        // field — an unknown key must parse harmlessly rather than error, so
        // an existing config keeps loading.
    }

    #[test]
    fn absent_optionals_fall_back_to_documented_defaults() {
        let cfg = VenvConfig::from_plugin_config(&config_with(serde_json::json!({
            "class_name": "my_pkg.Minimal",
        })))
        .expect("class_name alone is a valid block");

        // These three defaults are the contract with `client.py` /
        // `venv_comm.py` — a drift here changes behavior silently.
        assert_eq!(
            cfg.max_content_size, 10_000_000,
            "matches client.py's max_content_size"
        );
        assert_eq!(
            cfg.timeout_secs, 30,
            "matches venv_comm.py's send_task timeout"
        );
        assert_eq!(cfg.script_path, "cpex/framework/isolated/worker.py");

        assert!(
            cfg.requirements_file.is_none(),
            "no requirements file is valid"
        );
    }

    #[test]
    fn missing_class_name_errors() {
        let err = VenvConfig::from_plugin_config(&config_with(serde_json::json!({
            "plugin_dirs": ["./plugins"],
        })))
        .expect_err("class_name is required");

        assert!(matches!(*err, PluginError::Config { .. }));
        assert!(err.to_string().contains("class_name"));
    }

    #[test]
    fn absent_config_block_errors_rather_than_panicking() {
        let cfg = PluginConfig {
            name: "no-config".into(),
            kind: crate::factory::KIND.into(),
            hooks: vec!["tool_pre_invoke".into()],
            config: None,
            ..Default::default()
        };

        let err = VenvConfig::from_plugin_config(&cfg)
            .expect_err("an absent block cannot supply class_name");
        assert!(matches!(*err, PluginError::Config { .. }));
    }

    /// The plugin dir a config with no usable `plugin_dirs` anywhere resolves
    /// to: `<cwd>/plugins`.
    fn expected_default_dir() -> String {
        std::env::current_dir()
            .unwrap()
            .join("plugins")
            .display()
            .to_string()
    }

    #[test]
    fn plugin_dirs_default_to_plugins_at_the_project_root() {
        // Neither key is set anywhere, which is the shape the host now expects.
        let plugin = IsolatedPythonPlugin::from_config(&config_with(serde_json::json!({
            "class_name": "my_pkg.Minimal",
        })))
        .expect("class_name alone is a valid block");

        assert_eq!(
            plugin.plugin_dirs(),
            [expected_default_dir()],
            "the host supplies the plugin dir; the config no longer can"
        );
        // Absolute, so a later cwd change cannot move the venv out from under
        // a running plugin.
        assert!(
            Path::new(&plugin.plugin_dirs()[0]).is_absolute(),
            "the resolved dir must be absolute: {:?}",
            plugin.plugin_dirs()
        );
    }

    #[test]
    fn a_plugin_dirs_key_in_the_config_block_is_ignored() {
        // The key an existing config still carries. It must not steer the host,
        // and it must not fail the parse either — an operator upgrading should
        // see the warning (emitted by the factory) rather than a load error.
        let plugin = IsolatedPythonPlugin::from_config(&config_with(serde_json::json!({
            "class_name": "my_pkg.Minimal",
            "plugin_dirs": ["/somewhere/else", "/and/here"],
        })))
        .expect("an ignored key must not fail the parse");

        assert_eq!(
            plugin.plugin_dirs(),
            [expected_default_dir()],
            "`plugin_dirs` in the config block must be ignored"
        );
    }

    #[test]
    fn the_top_level_plugin_dirs_key_is_also_ignored() {
        // `cpex plugin install` writes the key here. cpex_core parses and
        // discards it; this pins that it does not reach the host either.
        let yaml = r#"
plugin_dirs: ["./top-level-dirs"]
plugins:
  - name: py-plugin
    kind: isolated_venv
    hooks: [tool_pre_invoke]
    config:
      class_name: my_pkg.Minimal
"#;
        let cpex_config: cpex_core::config::CpexConfig =
            serde_yaml::from_str(yaml).expect("valid YAML");
        assert_eq!(
            cpex_config.plugin_dirs,
            vec!["./top-level-dirs"],
            "the top-level key still parses — it is simply not the host's source"
        );

        let plugin =
            IsolatedPythonPlugin::from_config(&cpex_config.plugins[0]).expect("config parses");
        assert_eq!(
            plugin.plugin_dirs(),
            [expected_default_dir()],
            "the top-level key must not steer the host's plugin dir"
        );
    }

    #[test]
    fn the_resolved_plugin_dir_is_what_the_worker_receives() {
        // The dir has to reach the worker's `sys.path`, not just the venv
        // layout — otherwise the venv is built in the right place and the
        // import still fails.
        let plugin = IsolatedPythonPlugin::from_config(&config_with(serde_json::json!({
            "class_name": "my_pkg.Minimal",
            "plugin_dirs": ["/ignored"],
        })))
        .expect("parses");

        let task = plugin
            .build_task(
                "tool_pre_invoke",
                serde_json::json!({"name": "t"}),
                &PluginContext::new(),
            )
            .expect("task builds");

        assert_eq!(
            task["plugin_dirs"],
            serde_json::json!([expected_default_dir()]),
            "the worker must be told the resolved dir, not the ignored one"
        );
    }

    // --- adapter dispatch ---------------------------------------------------

    /// A stub worker that answers `load_and_run_hook` with a canned result and
    /// records the task it received.
    ///
    /// Behavior is driven by a marker file so a single script covers every
    /// case: the test writes `mode` next to the script before invoking.
    const ADAPTER_STUB: &str = r#"
import json, os, sys

here = os.path.dirname(os.path.abspath(__file__))

def mode():
    try:
        with open(os.path.join(here, "mode")) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "allow"

while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    task = json.loads(line)
    rid = task.get("request_id", "unknown")

    if task.get("task_type") == "shutdown":
        print(json.dumps({"status": "success", "request_id": rid}), flush=True)
        break

    # Record the task so the test can assert on what the host actually sent.
    with open(os.path.join(here, "last_task.json"), "w") as f:
        json.dump(task, f)

    m = mode()
    if m == "deny":
        response = {
            "continue_processing": False,
            "violation": {"code": "PII_DETECTED", "reason": "email in args", "details": {"field": "q"}},
        }
    elif m == "error":
        response = {"status": "error", "message": "the plugin raised ValueError"}
    elif m == "context":
        response = {
            "continue_processing": True,
            "context": {"state": {"seen": 1}, "global_context": {"state": {"shared": "yes"}}},
        }
    elif m == "modify":
        response = {
            "continue_processing": True,
            "modified_payload": {"name": "search", "args": {"q": "[REDACTED]"}},
        }
    else:
        response = {"continue_processing": True}

    response["request_id"] = rid
    print(json.dumps(response), flush=True)
"#;

    /// Build a plugin wired to the adapter stub, plus its scratch dir.
    async fn adapter_plugin(
        hooks: &[&str],
        capabilities: &[&str],
    ) -> (TempDir, Arc<IsolatedPythonPlugin>) {
        let dir = TempDir::new();
        let script = dir.path().join("adapter_stub.py");
        std::fs::write(&script, ADAPTER_STUB).unwrap();

        let config = PluginConfig {
            name: "py-plugin".into(),
            kind: crate::factory::KIND.into(),
            hooks: hooks.iter().map(|h| (*h).to_string()).collect(),
            capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
            config: Some(serde_json::json!({ "class_name": "my_pkg.Plugin" })),
            ..Default::default()
        };

        let plugin = Arc::new(
            IsolatedPythonPlugin::from_config(&config)
                .expect("config parses")
                .with_worker_override(script),
        );
        plugin.initialize().await.expect("the stub worker launches");
        (dir, plugin)
    }

    fn set_mode(dir: &TempDir, mode: &str) {
        std::fs::write(dir.path().join("mode"), mode).unwrap();
    }

    fn last_task(dir: &TempDir) -> serde_json::Value {
        let raw = std::fs::read_to_string(dir.path().join("last_task.json"))
            .expect("the stub recorded a task");
        serde_json::from_str(&raw).expect("recorded task is JSON")
    }

    /// Invoke a hook through the adapter and return the erased result fields.
    async fn invoke(
        plugin: &Arc<IsolatedPythonPlugin>,
        hook: &'static str,
        payload: &dyn PluginPayload,
        ctx: &mut PluginContext,
    ) -> Result<cpex_core::executor::ErasedResultFields, Box<PluginError>> {
        let adapter = PythonHookAdapter::new(Arc::clone(plugin), hook);
        let erased = adapter.invoke(payload, &Extensions::default(), ctx).await?;
        Ok(cpex_core::executor::extract_erased(erased)
            .expect("the adapter returns ErasedResultFields"))
    }

    #[tokio::test]
    async fn an_invoke_round_trips_and_returns_allow() {
        if crate::testing::skip_without_python3("an_invoke_round_trips_and_returns_allow") {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "allow");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            args: Some(std::collections::HashMap::from([(
                "q".into(),
                serde_json::json!("rust"),
            )])),
            headers: None,
        };
        let mut ctx = PluginContext::new();
        let fields = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .expect("the round trip succeeds");

        assert!(fields.continue_processing);
        assert!(fields.violation.is_none());

        // The task the worker received must carry the protocol contract.
        let task = last_task(&dir);
        assert_eq!(task["task_type"], "load_and_run_hook");
        assert_eq!(task["hook_type"], "tool_pre_invoke");
        assert_eq!(task["plugin_name"], "py-plugin");
        assert_eq!(task["class_name"], "my_pkg.Plugin");
        assert_eq!(task["payload"]["name"], "search");
        assert_eq!(task["payload"]["args"]["q"], "rust");

        // `config` is a JSON *string* the worker json.loads()es — not an object.
        let config_str = task["config"]
            .as_str()
            .expect("config must be a JSON string");
        let config: serde_json::Value = serde_json::from_str(config_str).unwrap();
        assert_eq!(config["name"], "py-plugin");

        plugin.shutdown().await.expect("shuts down");
    }

    #[tokio::test]
    async fn a_deny_response_becomes_a_deny_result_with_its_violation() {
        if crate::testing::skip_without_python3(
            "a_deny_response_becomes_a_deny_result_with_its_violation",
        ) {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "deny");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();
        let fields = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .expect("a deny is a successful invocation that returns a deny");

        assert!(!fields.continue_processing);
        let violation = fields.violation.expect("a deny must carry its violation");
        assert_eq!(violation.code, "PII_DETECTED");
        assert_eq!(violation.reason, "email in args");
        assert_eq!(violation.details["field"], "q");

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_worker_error_surfaces_as_a_plugin_error_for_the_executor_to_police() {
        // The host returns the error and stops. Applying the on_error policy is
        // the executor's job — doing it here would double-apply it.
        if crate::testing::skip_without_python3(
            "a_worker_error_surfaces_as_a_plugin_error_for_the_executor_to_police",
        ) {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "error");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();
        let Err(err) = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx).await else {
            panic!("a worker error response must not read as success");
        };

        match *err {
            PluginError::Execution {
                ref plugin_name,
                ref code,
                ref message,
                ..
            } => {
                assert_eq!(plugin_name, "py-plugin");
                assert_eq!(code.as_deref(), Some("worker_error"));
                assert!(
                    message.contains("ValueError"),
                    "the plugin's message should survive: {message}"
                );
            },
            ref other => panic!("expected an Execution error, got {other:?}"),
        }

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn context_deltas_are_written_back_into_the_plugin_context() {
        if crate::testing::skip_without_python3(
            "context_deltas_are_written_back_into_the_plugin_context",
        ) {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "context");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();
        ctx.set_local("preexisting", serde_json::json!("kept"));

        invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .unwrap();

        assert_eq!(ctx.get_local("seen"), Some(&serde_json::json!(1)));
        assert_eq!(ctx.get_global("shared"), Some(&serde_json::json!("yes")));
        assert_eq!(
            ctx.get_local("preexisting"),
            Some(&serde_json::json!("kept")),
            "deltas merge — a plugin touching one key must not blank the rest"
        );

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_modified_payload_comes_back_as_the_hooks_typed_payload() {
        if crate::testing::skip_without_python3(
            "a_modified_payload_comes_back_as_the_hooks_typed_payload",
        ) {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "modify");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();
        let fields = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .unwrap();

        let modified = fields.modified_payload.expect("the modification survives");
        let typed = modified
            .as_any()
            .downcast_ref::<crate::legacy::ToolPreInvokePayload>()
            .expect("must come back as the tool payload or the executor's downcast fails");
        assert_eq!(typed.args.as_ref().unwrap()["q"], "[REDACTED]");

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_cmf_hook_sends_the_message_payload_shape() {
        if crate::testing::skip_without_python3("a_cmf_hook_sends_the_message_payload_shape") {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["cmf.tool_pre_invoke"], &[]).await;
        set_mode(&dir, "allow");

        let payload = cpex_core::cmf::MessagePayload {
            message: cpex_core::cmf::Message::text(cpex_core::cmf::Role::User, "hello"),
        };
        let mut ctx = PluginContext::new();
        invoke(&plugin, "cmf.tool_pre_invoke", &payload, &mut ctx)
            .await
            .unwrap();

        let task = last_task(&dir);
        assert_eq!(task["hook_type"], "cmf.tool_pre_invoke");
        assert_eq!(
            task["payload"]["message"]["role"], "user",
            "a cmf hook must send the CMF message payload, not the generic wrapper"
        );

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invoking_before_initialize_is_a_plugin_error_not_a_panic() {
        let config = PluginConfig {
            name: "uninitialized".into(),
            kind: crate::factory::KIND.into(),
            hooks: vec!["tool_pre_invoke".into()],
            config: Some(serde_json::json!({ "class_name": "my_pkg.Plugin" })),
            ..Default::default()
        };
        let plugin = Arc::new(IsolatedPythonPlugin::from_config(&config).unwrap());

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();
        let Err(err) = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx).await else {
            panic!("dispatch without a worker cannot succeed");
        };
        assert!(matches!(*err, PluginError::Execution { .. }));
    }

    #[tokio::test]
    async fn a_credential_capability_attaches_the_dto_on_an_identity_hook() {
        // Ties the capability gate to real dispatch: the DTO must reach the
        // worker's task, on the contract's field name.
        if crate::testing::skip_without_python3(
            "a_credential_capability_attaches_the_dto_on_an_identity_hook",
        ) {
            return;
        }
        use cpex_core::extensions::raw_credentials::{
            RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
        };

        let (dir, plugin) =
            adapter_plugin(&["identity_resolve"], &["read_inbound_credentials"]).await;
        set_mode(&dir, "allow");

        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("E2E-SECRET-TOKEN", "Authorization", TokenKind::Jwt),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let payload = crate::legacy::IdentityResolvePayload::default();
        let mut ctx = PluginContext::new();
        let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "identity_resolve");
        adapter
            .invoke(&payload, &extensions, &mut ctx)
            .await
            .expect("dispatch succeeds");

        let task = last_task(&dir);
        assert_eq!(task["credential"]["inbound"]["token"], "E2E-SECRET-TOKEN");
        assert_eq!(task["credential"]["inbound"]["kind"], "jwt");

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn no_capability_means_no_credential_reaches_the_worker() {
        if crate::testing::skip_without_python3(
            "no_capability_means_no_credential_reaches_the_worker",
        ) {
            return;
        }
        use cpex_core::extensions::raw_credentials::{
            RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
        };

        // Same hook, same request — this plugin simply declared nothing.
        let (dir, plugin) = adapter_plugin(&["identity_resolve"], &[]).await;
        set_mode(&dir, "allow");

        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("E2E-SECRET-TOKEN", "Authorization", TokenKind::Jwt),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let payload = crate::legacy::IdentityResolvePayload::default();
        let mut ctx = PluginContext::new();
        let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "identity_resolve");
        adapter
            .invoke(&payload, &extensions, &mut ctx)
            .await
            .unwrap();

        let task = last_task(&dir);
        assert!(task.get("credential").is_none(), "no credential field");
        assert!(
            !serde_json::to_string(&task)
                .unwrap()
                .contains("E2E-SECRET-TOKEN"),
            "no token bytes anywhere in the task the worker received"
        );

        plugin.shutdown().await.unwrap();
    }

    #[test]
    fn unknown_config_keys_are_tolerated() {
        // Plugin `config:` blocks are shared with the Python side, which reads
        // keys this host does not model. Rejecting them would break configs
        // that work under the Python CLI.
        let cfg = VenvConfig::from_plugin_config(&config_with(serde_json::json!({
            "class_name": "my_pkg.Minimal",
            "some_python_only_setting": true,
        })))
        .expect("extra keys belong to the Python plugin, not this host");
        assert_eq!(cfg.class_name, "my_pkg.Minimal");
    }
}
