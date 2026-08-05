// Location: ./crates/cpex-hosts-python/tests/isolated_venv_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// End-to-end: Rust manager → venv → real `worker.py` → Python plugin → back.
//
// The unit tests cover each layer against a stub worker. These prove the whole
// path against the *real* framework worker, which is the only thing that can
// catch a field-name disagreement between this host's task JSON and what
// `worker.py` actually reads.
//
// # Requirements, and why these are `#[ignore]`d
//
// Two things must be present: a `python3`, and a `cpex` Python source tree to
// install into the venv. Neither is guaranteed on an arbitrary machine, so these
// tests are `#[ignore]`d: a default `cargo test` reports them as *ignored*
// rather than claiming a pass for a body that never ran. That distinction is the
// point — an early-returning test that prints "SKIP" still counts as `ok` in
// cargo's summary, which is how a suite comes to report safety it has not
// verified.
//
// Run them with `make test-python-e2e`, which sets `CPEX_REQUIRE_PYTHON_E2E=1`.
// Under that variable an unmet prerequisite panics instead of skipping, so the
// lane that is supposed to have a complete environment cannot go quiet.
//
// The framework source is discovered rather than assumed: `cpex` on PyPI is
// behind this branch (its `worker.py` predates the credential field), so the
// tests install from a local checkout of the Python side. Set
// `CPEX_PYTHON_SOURCE` to point at one; otherwise a sibling checkout is tried.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpex_core::context::PluginContext;
use cpex_core::extensions::Extensions;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;
use cpex_hosts_python::factory::KIND;
use cpex_hosts_python::legacy::ToolPreInvokePayload;
use cpex_hosts_python::plugin::{IsolatedPythonPlugin, PythonHookAdapter};
use cpex_hosts_python::testing::{
    prebuild_venv, python_source, scaffold_plugin, skip, skip_without_python3, TempDir,
};

/// A Python plugin that marks the filesystem when its hook body runs, so the
/// test can prove the plugin *executed* rather than merely that a response
/// came back shaped like a success.
const FIXTURE_PLUGIN: &str = r#"
import os

from cpex.framework.base import Plugin
from cpex.framework.models import PluginResult, PluginViolation


class MarkerPlugin(Plugin):
    """Writes a marker file, then allows — or denies when args say to."""

    def __init__(self, config):
        super().__init__(config)

    async def tool_pre_invoke(self, payload, context):
        with open(os.path.join(os.getcwd(), "marker.txt"), "w") as f:
            f.write(f"ran:{payload.name}")

        args = payload.args or {}
        if args.get("q") == "DENY-ME":
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="denied by fixture",
                    description="the fixture was asked to deny",
                    code="FIXTURE_DENY",
                    details={"arg": "q"},
                ),
            )
        return PluginResult(continue_processing=True)
"#;

/// Skip guard: returns `Some(source)` when the path is exercisable.
fn require_environment(test_name: &str) -> Option<PathBuf> {
    if skip_without_python3(test_name) {
        return None;
    }
    match python_source() {
        Ok(source) => Some(source),
        Err(reason) => {
            skip(test_name, &reason);
            None
        },
    }
}

/// Full setup: scaffold the plugin, pre-build its venv, return the plugin dir.
///
/// Returns `None` (after printing why) when the venv cannot be built, so the
/// caller skips rather than fails.
fn setup(dir: &TempDir, source: &Path, test_name: &str) -> Option<PathBuf> {
    let plugin_dir = scaffold_plugin(dir, source, "fixture_pkg", "marker_plugin", FIXTURE_PLUGIN);
    match prebuild_venv(&plugin_dir, source, FIXTURE_CLASS, "fixture_pkg") {
        Ok(()) => Some(plugin_dir),
        Err(reason) => {
            skip(
                test_name,
                &format!("could not prepare the plugin venv — {reason}"),
            );
            None
        },
    }
}

/// Fully-qualified class name of the fixture plugin.
const FIXTURE_CLASS: &str = "fixture_pkg.marker_plugin.MarkerPlugin";

/// Build the plugin config the manager would load from YAML.
///
/// No `plugin_dirs` here: the host ignores that key and always resolves
/// `<project root>/plugins`. These tests scaffold into a temp dir instead and
/// point the plugin at it via `with_plugin_dirs`, so a test run never builds a
/// venv in the developer's real `plugins/`.
fn plugin_config(hooks: &[&str], capabilities: &[&str]) -> PluginConfig {
    PluginConfig {
        name: "fixture-marker".into(),
        kind: KIND.into(),
        hooks: hooks.iter().map(|h| (*h).to_string()).collect(),
        capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
        version: Some("1.0.0".into()),
        config: Some(serde_json::json!({
            "class_name": FIXTURE_CLASS,
            "requirements_file": "requirements.txt",
            // Generous: a cold venv build plus a pip install of the framework
            // is minutes, and the hook call itself follows in the same window.
            "timeout_secs": 300,
        })),
        ..Default::default()
    }
}

/// Build the plugin under test: config + the scaffolded temp plugin dir + the
/// worker cwd both e2e assertions depend on.
fn plugin_for(
    config: &PluginConfig,
    plugin_dir: &Path,
    worker_cwd: &Path,
) -> Arc<IsolatedPythonPlugin> {
    Arc::new(
        IsolatedPythonPlugin::from_config(config)
            .expect("config parses")
            .with_plugin_dirs(vec![plugin_dir.display().to_string()])
            .with_worker_cwd(worker_cwd.to_path_buf()),
    )
}

/// Invoke a hook through the adapter and return the erased result.
async fn invoke(
    plugin: &Arc<IsolatedPythonPlugin>,
    hook: &'static str,
    payload: &ToolPreInvokePayload,
) -> Result<cpex_core::executor::ErasedResultFields, String> {
    let adapter = PythonHookAdapter::new(Arc::clone(plugin), hook);
    let mut ctx = PluginContext::new();
    let erased = adapter
        .invoke(payload, &Extensions::default(), &mut ctx)
        .await
        .map_err(|e| e.to_string())?;
    Ok(cpex_core::executor::extract_erased(erased).expect("adapter returns ErasedResultFields"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn legacy_tool_pre_invoke_round_trips_through_the_real_worker() {
    // The plan's primary acceptance example: clean args return
    // continue_processing = true with no violation, and the plugin's hook body
    // demonstrably ran (its marker file exists at the worker's cwd).
    let Some(source) =
        require_environment("legacy_tool_pre_invoke_round_trips_through_the_real_worker")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "legacy_tool_pre_invoke_round_trips_through_the_real_worker",
    ) else {
        return;
    };
    let config = plugin_config(&["tool_pre_invoke"], &[]);

    let plugin = plugin_for(&config, &plugin_dir, dir.path());
    plugin
        .initialize()
        .await
        .expect("the cached venv is reused and the worker starts");

    let payload = ToolPreInvokePayload {
        name: "search".into(),
        args: Some(std::collections::HashMap::from([(
            "q".into(),
            serde_json::json!("clean query"),
        )])),
        headers: None,
    };

    let fields = invoke(&plugin, "tool_pre_invoke", &payload)
        .await
        .expect("the hook round-trips");

    assert!(fields.continue_processing, "clean args must be allowed");
    assert!(fields.violation.is_none(), "an allow carries no violation");

    // The marker proves the plugin's own hook body executed — a response can
    // be shaped like an allow without the plugin ever having run. It lands in
    // the worker's cwd, which is this test's scratch dir.
    let marker = dir.path().join("marker.txt");
    assert!(
        marker.is_file(),
        "the plugin hook body did not run — no marker at {}",
        marker.display()
    );
    let contents = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(
        contents, "ran:search",
        "the marker should record the payload the plugin saw"
    );

    plugin.shutdown().await.expect("the worker shuts down");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_real_plugin_deny_surfaces_as_a_deny_result() {
    // Proves the deny path through the real framework, not just a stub that
    // emits a hand-written violation envelope.
    let Some(source) = require_environment("a_real_plugin_deny_surfaces_as_a_deny_result") else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "a_real_plugin_deny_surfaces_as_a_deny_result",
    ) else {
        return;
    };
    let config = plugin_config(&["tool_pre_invoke"], &[]);

    let plugin = plugin_for(&config, &plugin_dir, dir.path());
    plugin.initialize().await.expect("initializes");

    let payload = ToolPreInvokePayload {
        name: "search".into(),
        args: Some(std::collections::HashMap::from([(
            "q".into(),
            serde_json::json!("DENY-ME"),
        )])),
        headers: None,
    };

    let fields = invoke(&plugin, "tool_pre_invoke", &payload)
        .await
        .expect("a deny is a successful round trip");

    assert!(!fields.continue_processing);
    let violation = fields.violation.expect("a deny carries its violation");
    assert_eq!(violation.code, "FIXTURE_DENY");
    assert_eq!(violation.reason, "denied by fixture");
    assert_eq!(violation.details["arg"], "q");

    plugin.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_cmf_hook_is_rejected_cleanly_by_a_framework_that_has_no_cmf_hooks() {
    // The plan asks for a CMF round-trip here. It is not achievable against
    // this framework version, and the reason is worth pinning rather than
    // omitting: the Python hook registry knows only the legacy names —
    // `get_result_type("cmf.tool_pre_invoke")` returns None, and
    // `json_to_payload` raises "No payload defined for hook cmf.tool_pre_invoke".
    // No `cmf.*` hook is registered anywhere in `cpex/framework/hooks/`.
    //
    // So the CMF path cannot be proven end to end until the Python side
    // registers those hooks. What *is* provable, and asserted here, is that
    // this host does its half correctly: it serializes the CMF message payload
    // (not the generic wrapper — verified in the conversion and adapter unit
    // tests), and the worker's rejection surfaces as a clean plugin error
    // rather than a hang, a crash, or a silent allow. The last of those is the
    // one that would matter in production: a CMF hook that quietly returned
    // "allow" would bypass policy.
    let Some(source) =
        require_environment("a_cmf_hook_is_rejected_cleanly_by_a_framework_that_has_no_cmf_hooks")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "a_cmf_hook_is_rejected_cleanly_by_a_framework_that_has_no_cmf_hooks",
    ) else {
        return;
    };
    let config = plugin_config(&["cmf.tool_pre_invoke"], &[]);

    let plugin = plugin_for(&config, &plugin_dir, dir.path());
    plugin.initialize().await.expect("initializes");

    let payload = cpex_core::cmf::MessagePayload {
        message: cpex_core::cmf::Message::text(cpex_core::cmf::Role::User, "what is the weather?"),
    };
    let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "cmf.tool_pre_invoke");
    let mut ctx = PluginContext::new();
    let result = adapter
        .invoke(&payload, &Extensions::default(), &mut ctx)
        .await;

    let Err(err) = result else {
        panic!(
            "a framework with no cmf hooks must not report success — a silent allow on a CMF hook \
             would bypass policy"
        );
    };
    let message = err.to_string();
    assert!(
        message.contains("cmf.tool_pre_invoke") || message.to_lowercase().contains("payload"),
        "the error should explain that the hook is unknown to the framework: {message}"
    );

    // Still healthy: one rejected hook must not poison the worker.
    assert!(
        plugin.shutdown().await.is_ok(),
        "the worker should survive a rejected hook and shut down cleanly"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_second_run_reuses_the_cached_venv() {
    // The cached-venv-reuse acceptance example, end to end: the second
    // initialize must not rebuild or reinstall. Observed through the venv
    // manager's own verdict, which is what gates the reinstall.
    let Some(source) = require_environment("a_second_run_reuses_the_cached_venv") else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, "a_second_run_reuses_the_cached_venv") else {
        return;
    };
    let config = plugin_config(&["tool_pre_invoke"], &[]);

    let first = plugin_for(&config, &plugin_dir, dir.path());
    first
        .initialize()
        .await
        .expect("first initialize builds the venv");
    first.shutdown().await.unwrap();

    // A fresh plugin object against the same directories: the venv on disk is
    // the only thing carried over.
    let second = plugin_for(&config, &plugin_dir, dir.path());

    let venv = cpex_hosts_python::VenvManager::new(
        &[plugin_dir.display().to_string()],
        FIXTURE_CLASS,
        Some("requirements.txt"),
        Some("1.0.0"),
    )
    .expect("layout resolves");
    assert_eq!(
        venv.cache_verdict(),
        cpex_hosts_python::CacheVerdict::Valid,
        "the venv built by the first run must be a cache hit for the second"
    );

    // And the second run still works off that cached venv.
    second
        .initialize()
        .await
        .expect("second initialize reuses the venv");
    let payload = ToolPreInvokePayload {
        name: "search".into(),
        ..Default::default()
    };
    let fields = invoke(&second, "tool_pre_invoke", &payload)
        .await
        .expect("still works");
    assert!(fields.continue_processing);

    second.shutdown().await.unwrap();
}
