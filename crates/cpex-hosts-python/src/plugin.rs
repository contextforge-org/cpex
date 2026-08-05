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

/// How many times a dead worker may be respawned before the plugin gives up.
///
/// Bounded rather than unlimited: a worker that dies on every launch is a
/// broken plugin (a bad dependency pin, a syntax error, an import that raises),
/// and retrying it forever converts a fast, legible failure into an
/// indefinitely wedged hook that hammers the machine. Three attempts covers the
/// case respawn exists for — a worker killed by an OOM reaper, a crash inside
/// one plugin invocation — without papering over a plugin that cannot start.
const MAX_RESPAWN_ATTEMPTS: u32 = 3;

/// Base delay before the first respawn attempt.
///
/// Doubled per attempt (100ms, 200ms, 400ms). The backoff exists so a worker
/// that dies immediately on launch cannot spin the host in a tight
/// spawn/crash loop; the values stay small because a live request is waiting
/// behind them and the executor's own timeout is still running.
const RESPAWN_BACKOFF_BASE_MS: u64 = 100;

/// Interval after which a plugin that has exhausted its respawn budget is
/// allowed to try again.
///
/// Without this, one bad patch of the worker's environment would permanently
/// poison the plugin for the process's lifetime, even after the underlying
/// cause is fixed. With it, a plugin that has been failing settles into one
/// retry per minute rather than either hammering or staying dead forever.
const RESPAWN_BUDGET_RESET_SECS: u64 = 60;

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

/// Capability names the Python `Capability` enum models
/// (`cpex/framework/extensions/tiers.py`).
///
/// This is deliberately a mirror of the *other* side's vocabulary rather than
/// this host's own. `PluginConfig`'s `capabilities` validator raises on any name
/// it does not recognize, and that happens during config construction inside the
/// worker, so an unrecognized name is a dead hook rather than a narrower view.
/// See [`IsolatedPythonPlugin::worker_capabilities`].
///
/// The host's vocabulary is the superset: `read_all`, `read_client`,
/// `read_workload`, `read_inbound_credentials`, and `read_delegated_tokens` have
/// no Python counterpart yet and are intentionally absent here. When the Python
/// enum grows one, adding it here is what lets it cross the boundary.
const WORKER_KNOWN_CAPABILITIES: &[&str] = &[
    "read_subject",
    "read_roles",
    "read_teams",
    "read_claims",
    "read_permissions",
    "read_agent",
    "read_headers",
    "write_headers",
    "read_labels",
    "append_labels",
    "read_delegation",
    "append_delegation",
];

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

    /// Respawn bookkeeping for a worker that dies after a successful
    /// `initialize()`.
    respawn: tokio::sync::Mutex<RespawnState>,
}

/// How many respawns this plugin has spent, and when the budget last reset.
///
/// Held behind its own mutex rather than folded into the worker lock so the
/// accounting survives the worker slot being replaced, and so two concurrent
/// invocations that both notice the same death cooperate: the first through
/// respawns, the second finds a live worker and spends nothing.
#[derive(Debug)]
struct RespawnState {
    /// Respawn attempts spent since the last budget reset.
    attempts: u32,
    /// When the budget was last reset, for the [`RESPAWN_BUDGET_RESET_SECS`]
    /// window. `None` until the first respawn.
    window_started: Option<std::time::Instant>,
}

impl RespawnState {
    fn new() -> Self {
        Self {
            attempts: 0,
            window_started: None,
        }
    }

    /// Reserve one respawn attempt, or report the budget is spent.
    ///
    /// Resets the counter first when the window has elapsed, so a plugin that
    /// failed hard an hour ago is not still being punished for it.
    fn try_reserve(&mut self) -> Option<u32> {
        let now = std::time::Instant::now();
        let expired = self
            .window_started
            .is_some_and(|s| now.duration_since(s).as_secs() >= RESPAWN_BUDGET_RESET_SECS);

        if expired {
            self.attempts = 0;
            self.window_started = None;
        }

        if self.attempts >= MAX_RESPAWN_ATTEMPTS {
            return None;
        }

        self.attempts += 1;
        self.window_started.get_or_insert(now);
        Some(self.attempts)
    }

    /// Return the budget to full after a respawn that produced a live worker.
    fn record_success(&mut self) {
        self.attempts = 0;
        self.window_started = None;
    }
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
            respawn: tokio::sync::Mutex::new(RespawnState::new()),
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

    /// Launch a worker process for this plugin.
    ///
    /// The single path both `initialize()` and the respawn take, which is what
    /// makes a respawned worker indistinguishable from the original: same
    /// interpreter, same script, same cwd, same content cap, same timeout. The
    /// security posture is preserved by construction rather than by a second
    /// copy of the setup that could drift — the capability and credential
    /// handshake is applied per invocation in `PythonHookAdapter::invoke`
    /// against `self.config.capabilities`, so a fresh worker is gated by exactly
    /// the same declared capabilities as the one it replaced. There is no
    /// "degraded" or "retry" mode that relaxes it.
    async fn launch_worker(&self) -> Result<WorkerClient, HostError> {
        // With an override the worker script is given outright, so neither a
        // venv nor script resolution is needed — but the interpreter still is.
        let (python, script) = match self.worker_override.as_ref() {
            Some(script) => (which_python3()?, script.clone()),
            None => {
                let venv = self.venv.as_ref().ok_or_else(|| HostError::Config {
                    message: format!(
                        "could not resolve a venv layout under {} — check that `class_name` \
                         ('{}') begins with a package segment",
                        self.plugin_dirs.join(", "),
                        self.venv_config.class_name,
                    ),
                })?;

                venv.ensure().await?;
                let script = crate::worker::resolve_worker_script(
                    &venv.layout().venv_path,
                    &self.venv_config.script_path,
                )?;

                (venv.python_executable(), script)
            },
        };

        // Matching `venv_comm.py`'s `cwd=os.getcwd()`. The worker's
        // ALLOWED_PLUGIN_DIRS allowlist accepts its own cwd, so inheriting the
        // host's is what lets a plugin dir declared relative to the gateway be
        // importable at all.
        WorkerClient::spawn(
            &python,
            &script,
            self.worker_cwd.as_deref(),
            self.venv_config.max_content_size,
            self.venv_config.timeout_secs,
        )
        .await
    }

    /// The live worker, respawning it when the previous one has died.
    ///
    /// A worker can die between invocations — an OOM kill, a segfault in a
    /// native dependency, a plugin that calls `sys.exit`. Before this, the
    /// plugin stayed permanently broken: every later invocation found the dead
    /// `WorkerClient` still in the slot and failed against it, so one crash
    /// disabled the plugin for the lifetime of the process.
    ///
    /// Respawn is bounded ([`MAX_RESPAWN_ATTEMPTS`]) and backed off, and a
    /// plugin that exhausts its budget returns a typed `WorkerStart` error
    /// rather than retrying forever.
    async fn worker(&self) -> Result<Arc<WorkerClient>, Box<PluginError>> {
        let to_plugin_error = |e: HostError| e.into_plugin_error(&self.config.name);

        // The common path: a worker exists and is alive. No lock beyond the
        // read, so a healthy invocation pays nothing for the respawn machinery.
        if let Some(worker) = self.worker.read().await.clone() {
            if worker.is_alive() {
                return Ok(worker);
            }
        } else {
            // Never initialized is not a respawn case — respawning here would
            // paper over a lifecycle bug (or an initialize() that failed and
            // was rolled back) by silently starting a worker the manager does
            // not know about.
            return Err(to_plugin_error(HostError::WorkerStart {
                message: "plugin has no worker — initialize() did not run or it failed".into(),
            }));
        }

        self.respawn_worker().await
    }

    /// Replace a dead worker, under the respawn lock.
    ///
    /// Split out so the happy path in `worker()` stays lock-free. Holding the
    /// respawn mutex across the relaunch serializes concurrent invocations that
    /// all noticed the same death: the first respawns, the rest re-check and
    /// find a live worker without spending budget.
    async fn respawn_worker(&self) -> Result<Arc<WorkerClient>, Box<PluginError>> {
        let to_plugin_error = |e: HostError| e.into_plugin_error(&self.config.name);
        let mut respawn = self.respawn.lock().await;

        // Re-check under the lock. A concurrent invocation may already have
        // done the work while this one waited.
        if let Some(worker) = self.worker.read().await.clone() {
            if worker.is_alive() {
                return Ok(worker);
            }
        }

        let Some(attempt) = respawn.try_reserve() else {
            tracing::error!(
                plugin = %self.config.name,
                max_attempts = MAX_RESPAWN_ATTEMPTS,
                "worker died and the respawn budget is exhausted; giving up"
            );
            return Err(to_plugin_error(HostError::WorkerStart {
                message: format!(
                    "worker died and could not be respawned after {MAX_RESPAWN_ATTEMPTS} attempts \
                     — the plugin's worker is failing to start (check its venv and dependencies)"
                ),
            }));
        };

        // Exponential: 100ms, 200ms, 400ms. Applied *before* the spawn so a
        // worker that dies instantly on launch cannot spin a tight loop.
        let backoff = std::time::Duration::from_millis(
            RESPAWN_BACKOFF_BASE_MS.saturating_mul(1 << (attempt - 1)),
        );
        tracing::warn!(
            plugin = %self.config.name,
            attempt,
            max_attempts = MAX_RESPAWN_ATTEMPTS,
            backoff_ms = backoff.as_millis(),
            "worker is dead; respawning"
        );
        tokio::time::sleep(backoff).await;

        // Reap the corpse before replacing it, so the old process and its I/O
        // tasks are not left behind on every respawn.
        if let Some(dead) = self.worker.write().await.take() {
            if let Err(e) = dead.shutdown().await {
                tracing::debug!(plugin = %self.config.name, "reaping the dead worker: {e}");
            }
        }

        // Same launch path as `initialize()` — see `launch_worker`.
        let worker = Arc::new(self.launch_worker().await.map_err(to_plugin_error)?);
        *self.worker.write().await = Some(Arc::clone(&worker));

        // Deliberately *not* `record_success()` here.
        //
        // `is_alive()` reflects the reader task's last observation, and a worker
        // that dies at import time has not necessarily been observed yet — it
        // reports alive for the moment right after spawn. Resetting the budget
        // on that would let a crash-looping worker refill its allowance on every
        // attempt and retry forever, which is exactly what the bound exists to
        // prevent. The budget is instead reset by the passage of time
        // (`RESPAWN_BUDGET_RESET_SECS`), so recovery is still possible once the
        // underlying cause is fixed, and by a *successful invocation* through
        // `note_worker_healthy`, which is proof the worker answered rather than
        // merely proof it launched.
        tracing::info!(
            plugin = %self.config.name,
            attempt,
            "worker respawned; awaiting proof it can serve a request"
        );

        Ok(worker)
    }

    /// Mark the worker healthy after it has actually answered a request.
    ///
    /// Called from the adapter on a successful round trip. A completed
    /// invocation is the only evidence that distinguishes a worker that started
    /// from a worker that works, so it — not a successful spawn — is what
    /// returns the respawn budget to full.
    async fn note_worker_healthy(&self) {
        let mut respawn = self.respawn.lock().await;
        if respawn.attempts > 0 {
            respawn.record_success();
        }
    }

    /// The declared capabilities, reduced to the ones the worker's
    /// `PluginConfig` model will accept.
    ///
    /// The Python model's `capabilities` validator *raises* on a name its
    /// `Capability` enum does not know, and Pydantic validation happens while
    /// the worker is constructing the config — before the plugin is ever
    /// called. This host's capability vocabulary is the larger of the two
    /// (`read_client`, `read_workload`, `read_all`, and the two
    /// `raw_credentials` caps have no Python counterpart yet), so forwarding
    /// the set verbatim would take down every hook of any plugin declaring one
    /// of them.
    ///
    /// Dropping the unknown names is safe in the direction that matters:
    /// the extensions the worker receives were already filtered by the
    /// executor, so a dropped capability can only make the worker's
    /// re-filter *more* restrictive, never less. A slot this host chose not to
    /// send cannot be recovered by a capability string. The reverse — keeping an
    /// unknown name — trades a possibly-narrower view for a dead worker.
    fn worker_capabilities(&self) -> Vec<String> {
        let (known, unknown): (Vec<String>, Vec<String>) = self
            .config
            .capabilities
            .iter()
            .cloned()
            .partition(|c| WORKER_KNOWN_CAPABILITIES.contains(&c.as_str()));

        if !unknown.is_empty() {
            // Worth a line: it means this host's vocabulary has grown past the
            // installed framework's, and a plugin declaring one of these sees a
            // narrower view out-of-process than it would in-process.
            tracing::warn!(
                plugin = %self.config.name,
                dropped = ?unknown,
                "the installed cpex framework does not model these capabilities; \
                 omitting them from the worker's config so it can still validate"
            );
        }

        known
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
        //
        // `capabilities` has to travel even though this host already applies the
        // executor's filtered view: the Python manager re-filters against
        // `plugin_ref.capabilities` before it calls a 3-arg hook
        // (`cpex/framework/manager.py`, `_execute_with_timeout`). Omitting the
        // field left that set empty, so the second filter stripped every gated
        // slot the first one had just allowed — a 3-arg plugin saw
        // `security.labels` empty and `http` as `None` no matter what it
        // declared. The two filters are now given the same input, so the second
        // one is idempotent rather than destructive.
        let config_json = serde_json::json!({
            "name": self.config.name,
            "kind": self.config.kind,
            "hooks": self.config.hooks,
            "capabilities": self.worker_capabilities(),
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
        let worker = self
            .launch_worker()
            .await
            .map_err(|e| e.into_plugin_error(&self.config.name))?;

        *self.worker.write().await = Some(Arc::new(worker));
        Ok(())
    }

    /// Stop the worker, killing it if it will not exit on its own.
    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        let worker = self.worker.write().await.take();
        let result = match worker {
            Some(worker) => worker
                .shutdown()
                .await
                .map_err(|e| e.into_plugin_error(&self.config.name)),
            None => Ok(()),
        };

        // Give up this plugin's claim on the (possibly shared) venv, so a later
        // rebuild is not permanently downgraded to an in-place update by a stale
        // owner entry. Best-effort: a registry write failure must not turn a
        // clean shutdown into an error, since the venv itself is fine.
        if let Some(venv) = self.venv.as_ref() {
            if let Err(e) = venv.release_owner().await {
                tracing::warn!(
                    plugin = %self.config.name,
                    "could not release the venv owner claim: {e}"
                );
            }
        }

        result
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

        // A completed round trip is the only proof a (possibly respawned) worker
        // actually serves requests, so it is what returns the respawn budget.
        self.plugin.note_worker_healthy().await;

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

    /// Parse the `config` field, which travels as a JSON *string*.
    fn worker_config(task: &serde_json::Value) -> serde_json::Value {
        serde_json::from_str(task["config"].as_str().expect("config is a string"))
            .expect("the worker's config parses")
    }

    /// Build a task for a plugin declaring `capabilities`.
    fn task_for_capabilities(capabilities: &[&str]) -> serde_json::Value {
        let mut config = config_with(serde_json::json!({"class_name": "my_pkg.Minimal"}));
        config.capabilities = capabilities.iter().map(|c| (*c).to_string()).collect();

        IsolatedPythonPlugin::from_config(&config)
            .expect("parses")
            .build_task(
                "tool_pre_invoke",
                serde_json::json!({"name": "t"}),
                &PluginContext::new(),
            )
            .expect("task builds")
    }

    #[test]
    fn declared_capabilities_reach_the_workers_config() {
        // The Python manager re-filters extensions against the capabilities in
        // *its* config before calling a 3-arg hook. Send none and that filter
        // runs against an empty set, stripping every gated slot the executor
        // just allowed — which is how a plugin declaring `read_labels` ended up
        // seeing an empty label set out-of-process.
        let config = worker_config(&task_for_capabilities(&["read_labels", "append_labels"]));

        let mut sent: Vec<&str> = config["capabilities"]
            .as_array()
            .expect("capabilities is an array")
            .iter()
            .map(|c| c.as_str().expect("a string"))
            .collect();
        sent.sort_unstable();

        assert_eq!(
            sent,
            ["append_labels", "read_labels"],
            "the worker must be told what the plugin declared"
        );
    }

    #[test]
    fn a_capability_the_python_model_rejects_is_not_forwarded() {
        // `PluginConfig`'s validator raises on an unknown capability, and it
        // does so while the worker builds the config — before the plugin runs.
        // So forwarding a host-only name costs every hook of that plugin, not
        // just the slot it gates. Dropping it can only narrow the view, which
        // the executor's own filter has already done.
        let config = worker_config(&task_for_capabilities(&["read_labels", "read_client"]));

        assert_eq!(
            config["capabilities"],
            serde_json::json!(["read_labels"]),
            "a name the installed framework cannot validate must be dropped, \
             not sent and not escalated into a task failure"
        );
    }

    #[test]
    fn a_plugin_declaring_nothing_sends_an_empty_capability_list() {
        // The field is always present so the worker's config shape does not
        // depend on whether anything was declared; an empty list and an absent
        // field mean the same thing to Pydantic, and the explicit one is easier
        // to read off the wire when diagnosing a filtering question.
        let config = worker_config(&task_for_capabilities(&[]));

        assert_eq!(
            config["capabilities"],
            serde_json::json!([]),
            "no capabilities is an empty list, not a missing field"
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

    # ...and which process served it, so a respawn test can prove the request
    # was answered by a *new* worker rather than by the original recovering.
    with open(os.path.join(here, "last_pid"), "w") as f:
        f.write(str(os.getpid()))

    m = mode()

    # `die` exits without replying, which is how a test kills the worker so the
    # *next* invocation has a dead one to respawn.
    if m == "die":
        sys.exit(9)

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

    // --- dead-worker respawn ------------------------------------------------

    fn last_pid(dir: &TempDir) -> u32 {
        std::fs::read_to_string(dir.path().join("last_pid"))
            .expect("the stub recorded its pid")
            .trim()
            .parse()
            .expect("pid is numeric")
    }

    /// Wait until the client has observed the worker's death.
    ///
    /// `is_alive()` flips when the reader task sees EOF, which is asynchronous
    /// with respect to the process exiting. Polling for it keeps the respawn
    /// tests deterministic without a blind sleep.
    async fn await_worker_death(plugin: &Arc<IsolatedPythonPlugin>) {
        for _ in 0..200 {
            let alive = plugin
                .worker
                .read()
                .await
                .as_ref()
                .is_some_and(|w| w.is_alive());
            if !alive {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("the worker never registered as dead");
    }

    #[tokio::test]
    async fn a_dead_worker_is_respawned_on_the_next_invocation() {
        // Pre-fix, one crash disabled the plugin for the life of the process:
        // the dead WorkerClient stayed in the slot and every later invocation
        // failed against it. This asserts recovery, and asserts it came from a
        // genuinely new process rather than the old one somehow answering.
        if crate::testing::skip_without_python3("a_dead_worker_is_respawned_on_the_next_invocation")
        {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "allow");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();

        // A healthy round trip establishes the original worker's pid.
        invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .expect("the first invocation succeeds");
        let original_pid = last_pid(&dir);

        // Kill it: the stub exits without replying.
        set_mode(&dir, "die");
        let _ = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx).await;
        await_worker_death(&plugin).await;

        // The next invocation must respawn and succeed rather than reporting a
        // permanently broken plugin.
        set_mode(&dir, "allow");
        let fields = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .expect("a dead worker must be replaced, not left broken");
        assert!(fields.continue_processing);

        let new_pid = last_pid(&dir);
        assert_ne!(
            original_pid, new_pid,
            "the request must be served by a respawned process"
        );

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_respawned_worker_receives_the_same_capability_handshake() {
        // The security rail. A respawned worker must be gated by exactly the
        // capabilities the original was — never a weaker set, and never a
        // "recovery mode" that skips the gate. Both directions are asserted
        // against one respawn: the declared capability still delivers its
        // credential, and an undeclared slot still delivers nothing.
        if crate::testing::skip_without_python3(
            "a_respawned_worker_receives_the_same_capability_handshake",
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
            RawInboundToken::new("RESPAWN-SECRET", "Authorization", TokenKind::Jwt),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let payload = crate::legacy::IdentityResolvePayload::default();
        let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "identity_resolve");

        let mut ctx = PluginContext::new();
        adapter
            .invoke(&payload, &extensions, &mut ctx)
            .await
            .expect("the first dispatch succeeds");
        let original_pid = last_pid(&dir);
        assert_eq!(
            last_task(&dir)["credential"]["inbound"]["token"],
            "RESPAWN-SECRET"
        );

        set_mode(&dir, "die");
        let mut ctx = PluginContext::new();
        let _ = adapter.invoke(&payload, &extensions, &mut ctx).await;
        await_worker_death(&plugin).await;

        // Same hook, same declared capability, new process.
        set_mode(&dir, "allow");
        let mut ctx = PluginContext::new();
        adapter
            .invoke(&payload, &extensions, &mut ctx)
            .await
            .expect("dispatch succeeds against the respawned worker");

        assert_ne!(original_pid, last_pid(&dir), "a new process served it");
        let task = last_task(&dir);
        assert_eq!(
            task["credential"]["inbound"]["token"], "RESPAWN-SECRET",
            "the respawned worker must get the same credential handshake"
        );
        assert_eq!(task["credential"]["inbound"]["kind"], "jwt");

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_respawned_worker_gets_no_credential_it_did_not_declare() {
        // The fail-closed half: a plugin with no declared capability must not
        // pick one up by virtue of having been respawned.
        if crate::testing::skip_without_python3(
            "a_respawned_worker_gets_no_credential_it_did_not_declare",
        ) {
            return;
        }
        use cpex_core::extensions::raw_credentials::{
            RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
        };

        let (dir, plugin) = adapter_plugin(&["identity_resolve"], &[]).await;
        set_mode(&dir, "allow");

        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("MUST-NOT-LEAK", "Authorization", TokenKind::Jwt),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let payload = crate::legacy::IdentityResolvePayload::default();
        let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "identity_resolve");

        let mut ctx = PluginContext::new();
        adapter
            .invoke(&payload, &extensions, &mut ctx)
            .await
            .unwrap();

        set_mode(&dir, "die");
        let mut ctx = PluginContext::new();
        let _ = adapter.invoke(&payload, &extensions, &mut ctx).await;
        await_worker_death(&plugin).await;

        set_mode(&dir, "allow");
        let mut ctx = PluginContext::new();
        adapter
            .invoke(&payload, &extensions, &mut ctx)
            .await
            .expect("dispatch succeeds after respawn");

        let task = last_task(&dir);
        assert!(
            task.get("credential").is_none(),
            "respawn must not widen the capability gate"
        );
        assert!(
            !serde_json::to_string(&task)
                .unwrap()
                .contains("MUST-NOT-LEAK"),
            "no token bytes may reach a worker that declared nothing"
        );

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_worker_that_will_not_stay_up_gives_up_with_a_typed_error() {
        // The anti-loop rail. A worker that dies on every launch must surface a
        // typed error after a bounded number of attempts rather than retrying
        // forever. Pointing the override at a script that always exits makes
        // every respawn produce a corpse.
        if crate::testing::skip_without_python3(
            "a_worker_that_will_not_stay_up_gives_up_with_a_typed_error",
        ) {
            return;
        }
        let dir = TempDir::new();
        let script = dir.path().join("always_dies.py");
        // Exits at import, before reading a task — so every spawn dies.
        std::fs::write(
            &script,
            "import sys\nprint('fatal: dependency missing', file=sys.stderr, flush=True)\nsys.exit(1)\n",
        )
        .unwrap();

        let config = PluginConfig {
            name: "crash-loop".into(),
            kind: crate::factory::KIND.into(),
            hooks: vec!["tool_pre_invoke".into()],
            config: Some(serde_json::json!({ "class_name": "my_pkg.Plugin" })),
            ..Default::default()
        };
        let plugin = Arc::new(
            IsolatedPythonPlugin::from_config(&config)
                .expect("config parses")
                .with_worker_override(script),
        );
        // The process *starts* (then dies), so initialize succeeds — this is
        // exactly the shape a bad dependency pin produces.
        plugin.initialize().await.expect("the process launches");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };

        // Drive invocations until one reports the budget is spent. The bound is
        // what is under test: without it this loop never terminates.
        let started = std::time::Instant::now();
        let mut gave_up = None;
        for _ in 0..(MAX_RESPAWN_ATTEMPTS + 4) {
            let mut ctx = PluginContext::new();
            let Err(err) = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx).await else {
                panic!("a worker that always dies cannot serve a request");
            };
            let message = err.to_string();
            if message.contains("could not be respawned") {
                gave_up = Some(message);
                break;
            }
        }

        let message = gave_up
            .expect("a permanently failing worker must give up with an error, not retry forever");
        assert!(
            message.contains(&MAX_RESPAWN_ATTEMPTS.to_string()),
            "the error should name the attempt bound: {message}"
        );

        // The backoff is bounded too — giving up must not take minutes.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "giving up took too long: {:?}",
            started.elapsed()
        );

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn respawn_is_not_attempted_before_initialize() {
        // Respawn must not paper over a lifecycle bug by starting a worker the
        // manager never asked for: an uninitialized plugin still errors.
        let config = PluginConfig {
            name: "uninitialized".into(),
            kind: crate::factory::KIND.into(),
            hooks: vec!["tool_pre_invoke".into()],
            config: Some(serde_json::json!({ "class_name": "my_pkg.Plugin" })),
            ..Default::default()
        };
        let plugin = Arc::new(IsolatedPythonPlugin::from_config(&config).unwrap());

        let Err(err) = plugin.worker().await else {
            panic!("a plugin with no worker must not silently spawn one");
        };
        let message = err.to_string();
        assert!(
            message.contains("initialize()"),
            "the error should name the lifecycle gap: {message}"
        );
        assert!(
            plugin.worker.read().await.is_none(),
            "no worker was started"
        );
    }

    #[tokio::test]
    async fn concurrent_invocations_share_one_respawn() {
        // Several hooks of one plugin can be in flight at once (the executor
        // dispatches parallel-phase plugins concurrently). They must not each
        // spend respawn budget on the same death and start competing workers.
        if crate::testing::skip_without_python3("concurrent_invocations_share_one_respawn") {
            return;
        }
        let (dir, plugin) = adapter_plugin(&["tool_pre_invoke"], &[]).await;
        set_mode(&dir, "allow");

        let payload = crate::legacy::ToolPreInvokePayload {
            name: "search".into(),
            ..Default::default()
        };
        let mut ctx = PluginContext::new();
        invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .unwrap();

        set_mode(&dir, "die");
        let _ = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx).await;
        await_worker_death(&plugin).await;
        set_mode(&dir, "allow");

        // Four concurrent invocations against one dead worker.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let plugin = Arc::clone(&plugin);
            handles.push(tokio::spawn(async move {
                let payload = crate::legacy::ToolPreInvokePayload {
                    name: "search".into(),
                    ..Default::default()
                };
                let mut ctx = PluginContext::new();
                invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
                    .await
                    .map(|f| f.continue_processing)
            }));
        }

        for handle in handles {
            assert!(handle.await.unwrap().expect("each invocation recovers"));
        }

        // One respawn served all four, so the budget is intact — a second
        // independent death must still be recoverable.
        set_mode(&dir, "die");
        let mut ctx = PluginContext::new();
        let _ = invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx).await;
        await_worker_death(&plugin).await;
        set_mode(&dir, "allow");

        let mut ctx = PluginContext::new();
        invoke(&plugin, "tool_pre_invoke", &payload, &mut ctx)
            .await
            .expect("budget was not exhausted by the concurrent respawn");

        plugin.shutdown().await.unwrap();
    }

    #[test]
    fn the_respawn_budget_is_bounded_then_resets_with_time() {
        // Unit-level pin on the accounting, so the bound and the reset window
        // are covered without spawning processes.
        let mut state = RespawnState::new();
        for expected in 1..=MAX_RESPAWN_ATTEMPTS {
            assert_eq!(state.try_reserve(), Some(expected));
        }
        assert_eq!(
            state.try_reserve(),
            None,
            "the budget must be bounded, not unlimited"
        );

        // A successful invocation refills it.
        state.record_success();
        assert_eq!(state.try_reserve(), Some(1));

        // ...and so does the passage of the reset window, so a plugin is not
        // poisoned for the life of the process once its cause is fixed.
        let mut state = RespawnState::new();
        while state.try_reserve().is_some() {}
        state.window_started = Some(
            std::time::Instant::now()
                - std::time::Duration::from_secs(RESPAWN_BUDGET_RESET_SECS + 1),
        );
        assert_eq!(
            state.try_reserve(),
            Some(1),
            "an elapsed window must restore the budget"
        );
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
