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

use cpex_hosts_python::factory::KIND;
use cpex_hosts_python::legacy::ToolPreInvokePayload;
use cpex_hosts_python::plugin::{IsolatedPythonPlugin, PythonHookAdapter};
use cpex_hosts_python::testing::{
    TEMP_DIR_KIND, TempDir, TempDirFactory, prebuild_venv, python_source, scaffold_plugin, skip,
    skip_without_python3,
};
use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use praxis_policy_core::context::PluginContext;
use praxis_policy_core::extensions::Extensions;
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::plugin::{Plugin, PluginConfig};
use praxis_policy_core::registry::AnyHookHandler;

/// A Python plugin that marks the filesystem when its hook body runs, so the
/// test can prove the plugin *executed* rather than merely that a response
/// came back shaped like a success.
const FIXTURE_PLUGIN: &str = r#"
import os

from cpex.framework.base import Plugin
from cpex.framework.models import PluginResult, PluginViolation


class MarkerPlugin(Plugin):
    """Writes a marker file, then allows, denies, or rewrites args.

    A 0.1.x-style plugin: it implements only the legacy `tool_pre_invoke` with
    the typed `ToolPreInvokePayload`. Its config block's `mode` picks the
    behavior: `gate` (the default) denies `q == "DENY-ME"`, and `rewrite`
    replaces `q == "REWRITE-ME"` with `"rewritten"`.
    """

    def __init__(self, config):
        super().__init__(config)

    async def tool_pre_invoke(self, payload, context):
        with open(os.path.join(os.getcwd(), "marker.txt"), "w") as f:
            f.write(f"ran:{payload.name}")

        args = payload.args or {}
        # Per plugin instance, so a chain of two can be told apart.
        with open(os.path.join(os.getcwd(), f"saw-{self.name}.txt"), "w") as f:
            f.write(f"{payload.name}:{args.get('q')}")

        mode = (self._config.config or {}).get("mode", "gate")
        if mode == "rewrite" and args.get("q") == "REWRITE-ME":
            rewritten = payload.model_copy(update={"args": {**args, "q": "rewritten"}})
            return PluginResult(continue_processing=True, modified_payload=rewritten)
        if mode == "gate" and args.get("q") == "DENY-ME":
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
    payload: &dyn PluginPayload,
) -> Result<praxis_policy_core::executor::ErasedResultFields, String> {
    let adapter = PythonHookAdapter::new(Arc::clone(plugin), hook);
    let mut ctx = PluginContext::new();
    let erased = adapter
        .invoke(payload, &Extensions::default(), &mut ctx)
        .await
        .map_err(|e| e.to_string())?;
    Ok(praxis_policy_core::executor::extract_erased(erased)
        .expect("adapter returns ErasedResultFields"))
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

/// A CMF tool call for `search` with one argument, between two unrelated
/// parts, so an engine round trip can show those parts survive the shim.
fn cmf_tool_call(q: &str) -> MessagePayload {
    MessagePayload {
        message: Message::with_content(
            Role::Assistant,
            vec![
                ContentPart::Text {
                    text: "calling search".into(),
                },
                ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "call-e2e-1".into(),
                        name: "search".into(),
                        arguments: std::collections::HashMap::from([(
                            "q".into(),
                            serde_json::json!(q),
                        )]),
                        namespace: None,
                    },
                },
                ContentPart::Thinking {
                    text: "unrelated reasoning".into(),
                },
            ],
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn legacy_plugins_on_cmf_tool_pre_invoke_rewrite_and_deny_through_the_engine() {
    // The 0.1.x worker registers no `cmf.*` hook and the fixture implements only
    // the legacy `tool_pre_invoke`. Through the legacy payload shim both still
    // run on PPE's `cmf.tool_pre_invoke`, in a real two-plugin pipeline: a
    // rewriter (priority 10) modifies args, and a gate (priority 20) sees the
    // rewritten args and denies on its own trigger.
    let test = "legacy_plugins_on_cmf_tool_pre_invoke_rewrite_and_deny_through_the_engine";
    let Some(source) = require_environment(test) else {
        return;
    };
    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, test) else {
        return;
    };

    use praxis_policy_core::config::{DispatchMode, EngineSettings, PolicyConfig};
    use praxis_policy_core::engine::{PolicyEngine, PolicyEngineConfig};

    let entry = |name: &str, mode: &str, priority: i32| {
        let mut config = plugin_config(&["cmf.tool_pre_invoke"], &[]);
        config.name = name.into();
        config.kind = TEMP_DIR_KIND.into();
        config.priority = priority;
        config.config.as_mut().unwrap()["mode"] = serde_json::json!(mode);
        config
    };

    let engine = PolicyEngine::new(PolicyEngineConfig::default());
    engine.register_factory(
        TEMP_DIR_KIND,
        Box::new(TempDirFactory {
            plugin_dir: plugin_dir.clone(),
            worker_cwd: dir.path().to_path_buf(),
        }),
    );
    engine
        .load_config(PolicyConfig {
            plugins: vec![entry("rewriter", "rewrite", 10), entry("gate", "gate", 20)],
            engine_settings: EngineSettings {
                dispatch: DispatchMode::Hooks,
                ..Default::default()
            },
            ..Default::default()
        })
        .expect("cmf.tool_pre_invoke is a PPE hook, so no host hook registration is needed");
    engine
        .initialize()
        .await
        .expect("the cached venv is reused and both workers start");

    // --- the rewrite maps back onto the CMF message --------------------------
    let original = cmf_tool_call("REWRITE-ME");
    let (result, _bg) = engine
        .invoke_by_name(
            "cmf.tool_pre_invoke",
            Box::new(original.clone()),
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        result.errors.is_empty(),
        "plugin errors: {:?}",
        result.errors
    );
    assert!(
        result.continue_processing,
        "violation: {:?}",
        result.violation
    );

    let modified = result
        .modified_payload
        .as_ref()
        .expect("the rewriter's modification survives the pipeline");
    let message = modified
        .as_any()
        .downcast_ref::<MessagePayload>()
        .expect("a cmf hook's modification comes back as a MessagePayload");
    let mut expected = serde_json::to_value(&original).unwrap();
    expected["message"]["content"][1]["content"]["arguments"]["q"] = serde_json::json!("rewritten");
    assert_eq!(
        serde_json::to_value(message).unwrap(),
        expected,
        "only the tool call's args change; every other part and field survives"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("saw-gate.txt")).unwrap(),
        "search:rewritten",
        "the gate, behind the rewriter, must see the rewritten args"
    );

    // --- a legacy deny passes through unchanged ------------------------------
    let (result, _bg) = engine
        .invoke_by_name(
            "cmf.tool_pre_invoke",
            Box::new(cmf_tool_call("DENY-ME")),
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        result.errors.is_empty(),
        "plugin errors: {:?}",
        result.errors
    );
    assert!(!result.continue_processing, "the gate must deny");
    let violation = result
        .violation
        .as_ref()
        .expect("a deny carries its violation");
    assert_eq!(violation.code, "FIXTURE_DENY");
    assert_eq!(violation.reason, "denied by fixture");
    assert_eq!(violation.details["arg"], "q");

    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_cmf_message_the_shim_cannot_represent_fails_closed() {
    // A `cmf.tool_pre_invoke` message with no tool call has no legacy
    // `ToolPreInvokePayload` to become. The host must refuse it with an error
    // naming the hook and the plugin, not send the worker something it would
    // misread and not report an allow: a silent allow on a CMF hook would
    // bypass policy.
    let test = "a_cmf_message_the_shim_cannot_represent_fails_closed";
    let Some(source) = require_environment(test) else {
        return;
    };
    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, test) else {
        return;
    };
    let config = plugin_config(&["cmf.tool_pre_invoke"], &[]);

    let plugin = plugin_for(&config, &plugin_dir, dir.path());
    plugin.initialize().await.expect("initializes");

    let payload = MessagePayload {
        message: Message::text(Role::User, "what is the weather?"),
    };
    let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "cmf.tool_pre_invoke");
    let mut ctx = PluginContext::new();
    let Err(err) = adapter
        .invoke(&payload, &Extensions::default(), &mut ctx)
        .await
    else {
        panic!("an unrepresentable cmf message must not report success");
    };
    let message = err.to_string();
    assert!(
        message.contains("cmf.tool_pre_invoke"),
        "names the hook: {message}"
    );
    assert!(
        message.contains("fixture-marker"),
        "names the plugin: {message}"
    );
    assert!(
        message.contains("no tool_call content part"),
        "says why: {message}"
    );
    assert!(
        !dir.path().join("marker.txt").exists(),
        "the plugin must not have run"
    );

    // The worker is untouched and still serves a representable message.
    let fields = invoke(&plugin, "cmf.tool_pre_invoke", &cmf_tool_call("clean"))
        .await
        .expect("a tool call message round-trips");
    assert!(fields.continue_processing);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("marker.txt")).unwrap(),
        "ran:search"
    );

    assert!(
        plugin.shutdown().await.is_ok(),
        "the worker should shut down cleanly"
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
