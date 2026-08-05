// Location: ./crates/cpex-hosts-python/tests/extensions_merge_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// End-to-end: extensions delivered to, and returned from, an out-of-process
// Python plugin — with the mutability tiers enforced by the real executor.
//
// # Why these go through `PluginManager` rather than the adapter alone
//
// The unit tests in `src/extensions.rs` cover the wire shape and every *deny*
// outcome. They cannot cover the accept outcomes, and that is by design:
// `http`, `security`, and `delegation` writes are gated by a `WriteToken`, and
// `WriteToken::new()` is `pub(crate)` to `cpex-core`. This crate cannot mint
// one even in a test — which is exactly the property that makes the gate
// trustworthy.
//
// The only legitimate source of a token is the executor, which mints one per
// plugin from that plugin's declared capabilities. So the accept side has to be
// driven through a real pipeline: register the Python plugin with a capability
// set, invoke the hook, and assert on the merged `Extensions` that come back in
// `PipelineResult`. That also means these tests exercise the thing the plan
// actually promises — the executor's copy-on-write merge validating the return —
// instead of a host-local imitation of it.
//
// # Two layers, two requirements
//
// The inbound-shape test needs nothing but this crate: it drives the adapter's
// task-building step and inspects the JSON. The round-trip tests need a real
// worker, so they need python3, a `cpex` Python checkout, and a `worker.py` that
// actually consumes the `extensions` field. Those two are `#[ignore]`d and run
// by `make test-python-e2e`, so a default `cargo test` reports them as ignored
// instead of passing a body that never executed.
//
// # A double-filter these tests caught, and where the fix landed
//
// The two worker-backed tests below used to fail, and the symptom is worth
// recording because nothing in either process was individually wrong.
//
// The 3-arg hook received `security` with an *empty* label set and `http` as
// `None` — byte-identical to what filtering produces for a plugin with **no**
// capabilities, even though this plugin declares `read_labels` + `read_headers`
// + `append_labels`. The executor's filter was correct, `to_wire` was correct
// (the inbound-shape test above pins it), and `reconstruct_extensions` rebuilt
// the label faithfully from the JSON the host actually sent.
//
// The loss happened one layer further in. `cpex/framework/manager.py`'s
// `_execute_with_timeout` re-filters extensions against
// `plugin_ref.capabilities` before invoking a 3-arg hook — reasonably, since
// in-process that is the only filter there is. But `build_task` did not send a
// `capabilities` field, so the worker's `PluginConfig` defaulted it to an empty
// frozenset and the second filter stripped every gated slot the first had just
// allowed. Two correct filters, composed, deleted the channel.
//
// The host now forwards the declared capabilities so both filters see the same
// input and the second is idempotent. It forwards only the names the Python
// `Capability` enum models: that validator *raises* on an unknown name, during
// config construction inside the worker, so a name like `read_client` (host-only
// today) would be a dead hook rather than a narrower view. See
// `IsolatedPythonPlugin::worker_capabilities`.
//
// # Still open, on the Python side: every header is dropped
//
// This framework's `HttpExtension` models a single `headers` field, while the
// host sends `request_headers`/`response_headers` per the wire contract.
// Pydantic drops unknown keys silently, so *every* header the host sends is
// discarded with no error — confirmed directly: `model_validate` on
// `{"request_headers": {...}}` yields `headers={}`.
//
// That is a gap in the Python model, not in this host, so it is not fixed here.
// The fixture reads whichever attribute exists and records `HTTP_SLOT_EMPTY`,
// which keeps the mismatch visible in the verdict instead of letting it read as
// a clean run. The security assertion still holds either way, and holds for the
// stronger reason: the label proves the channel is live, so an empty header map
// is evidence of the model gap rather than of a dead channel.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpex_core::extensions::{Extensions, HttpExtension, SecurityExtension};
use cpex_core::plugin::PluginConfig;
use cpex_hosts_python::extensions::{EXTENSIONS_FIELD, MODIFIED_EXTENSIONS_FIELD};
use cpex_hosts_python::factory::KIND;
use cpex_hosts_python::testing::{
    prebuild_venv, python_source, scaffold_plugin, skip, skip_without_python3,
    worker_delivers_extensions, TempDir,
};

/// Fully-qualified class name of the fixture plugin.
const FIXTURE_CLASS: &str = "ext_pkg.extensions_plugin.ExtensionsAwarePlugin";

/// A label the host puts on the inbound extensions. Distinctive so the fixture
/// can assert it saw the real thing rather than a default-constructed object.
const INBOUND_LABEL: &str = "E2E-INBOUND-LABEL-7b21";

/// The label the fixture appends, to exercise the monotonic tier.
const APPENDED_LABEL: &str = "E2E-APPENDED-LABEL-c93f";

/// A 3-arg plugin: it reads the inbound extensions and appends a label.
///
/// The existing isolated fixtures are all 2-arg, so none of them can observe
/// this channel at all. The 3-arg `(payload, context, extensions)` signature is
/// the form `_accepts_extensions` detects in `cpex/framework/base.py`.
///
/// It records what it saw to a file rather than returning it, so the inbound
/// assertions do not depend on the return path also working.
const FIXTURE_PLUGIN: &str = r#"
import os

from cpex.framework.base import Plugin
from cpex.framework.models import PluginResult

INBOUND_LABEL = "E2E-INBOUND-LABEL-7b21"
APPENDED_LABEL = "E2E-APPENDED-LABEL-c93f"


class ExtensionsAwarePlugin(Plugin):
    """Reports the extensions it received, then appends a security label."""

    def __init__(self, config):
        super().__init__(config)

    async def tool_pre_invoke(self, payload, context, extensions):
        # A 2-arg plugin would never get here; the framework only forwards
        # extensions to hooks whose signature accepts them.
        if extensions is None:
            verdict = "NO_EXTENSIONS"
        else:
            labels = set()
            if extensions.security is not None:
                labels = set(extensions.security.labels or [])
            saw_label = INBOUND_LABEL in labels

            # Sensitive headers must never arrive over this channel.
            #
            # The Rust host serializes `request_headers`/`response_headers`, but
            # this framework's HttpExtension models a single `headers` field, and
            # pydantic drops unknown keys silently — so the slot can arrive
            # present-but-empty. Read whichever attribute this build actually
            # exposes instead of assuming one: hardcoding the wrong name turns a
            # header leak into an AttributeError, which is a crash rather than
            # the security assertion this test is here to make.
            headers = {}
            slot_empty = False
            if extensions.http is not None:
                for attr in ("request_headers", "headers"):
                    if hasattr(extensions.http, attr):
                        headers = dict(getattr(extensions.http, attr) or {})
                        break
                slot_empty = not headers

            lowered = {k.lower() for k in headers}
            leaked = lowered & {"authorization", "cookie", "x-api-key"}
            verdict = "GOT_LABEL" if saw_label else "NO_LABEL"
            if leaked:
                verdict += f";LEAKED={sorted(leaked)}"
            if "x-request-id" in lowered:
                verdict += ";GOT_SAFE_HEADER"
            elif slot_empty:
                # The host sent a safe header; nothing arrived. Recorded so the
                # host/worker field-name mismatch stays visible in the verdict
                # rather than looking like a clean run.
                verdict += ";HTTP_SLOT_EMPTY"

        marker = os.path.join(os.getcwd(), "extensions_verdict.txt")
        with open(marker, "w") as f:
            f.write(verdict)

        # Append a label. `Extensions` is frozen, so modification means a new
        # instance via model_copy — the framework's documented pattern.
        modified = None
        if extensions is not None and extensions.security is not None:
            new_labels = list(extensions.security.labels or []) + [APPENDED_LABEL]
            new_security = extensions.security.model_copy(update={"labels": new_labels})
            modified = extensions.model_copy(update={"security": new_security})

        return PluginResult(continue_processing=True, modified_extensions=modified)
"#;

/// Skip guard for the worker-backed tests.
fn require_worker(test_name: &str) -> Option<PathBuf> {
    if skip_without_python3(test_name) {
        return None;
    }
    let source = match python_source() {
        Ok(source) => source,
        Err(reason) => {
            skip(test_name, &reason);
            return None;
        },
    };
    if !worker_delivers_extensions(&source) {
        skip(
            test_name,
            &format!(
                "the cpex source at {} has a worker.py that does not deliver the \
                 `{EXTENSIONS_FIELD}` field to execute_plugin — the inbound channel has no \
                 consumer there yet",
                source.display()
            ),
        );
        return None;
    }
    Some(source)
}

/// Scaffold the fixture and pre-build its venv.
fn setup(dir: &TempDir, source: &Path, test_name: &str) -> Option<PathBuf> {
    let plugin_dir = scaffold_plugin(dir, source, "ext_pkg", "extensions_plugin", FIXTURE_PLUGIN);
    match prebuild_venv(&plugin_dir, source, FIXTURE_CLASS, "ext_pkg") {
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

/// Inbound extensions: a label to read, a safe header, and three that must be
/// stripped before they reach another process.
fn inbound_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label(INBOUND_LABEL);

    let mut http = HttpExtension::default();
    http.set_request_header("Authorization", "Bearer must-not-travel");
    http.set_request_header("Cookie", "session=must-not-travel");
    http.set_request_header("X-API-Key", "must-not-travel");
    http.set_request_header("X-Request-Id", "req-e2e-1");

    Extensions {
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        ..Default::default()
    }
}

/// The legacy `tool_pre_invoke` hook, as a type the manager can dispatch.
///
/// `invoke_named` is generic over `HookTypeDef` to recover the payload type for
/// the typed handler path. The Python host registers type-erased handlers, so
/// only the payload type matters here — it must match what the adapter
/// serializes, which is this crate's `legacy::ToolPreInvokePayload`.
struct ToolPreInvoke;

impl cpex_core::hooks::trait_def::HookTypeDef for ToolPreInvoke {
    type Payload = cpex_hosts_python::legacy::ToolPreInvokePayload;
    type Result =
        cpex_core::hooks::trait_def::PluginResult<cpex_hosts_python::legacy::ToolPreInvokePayload>;
    const NAME: &'static str = "tool_pre_invoke";
}

fn plugin_config(capabilities: &[&str]) -> PluginConfig {
    PluginConfig {
        name: "extensions-aware".into(),
        kind: KIND.into(),
        hooks: vec!["tool_pre_invoke".into()],
        capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
        version: Some("1.0.0".into()),
        config: Some(serde_json::json!({
            "class_name": FIXTURE_CLASS,
            "requirements_file": "requirements.txt",
            "timeout_secs": 300,
        })),
        ..Default::default()
    }
}

// =====================================================================
// Inbound wire shape — no worker required
// =====================================================================

#[test]
fn the_inbound_task_carries_visible_slots_without_sensitive_headers() {
    // Drives the host's task-building step directly. This is the contract
    // `worker.py` will read, so it is worth pinning independently of whether a
    // worker exists yet to consume it.
    let mut task = serde_json::json!({"task_type": "load_and_run_hook"});
    cpex_hosts_python::extensions::attach_extensions(&mut task, &inbound_extensions())
        .expect("the filtered view serializes");

    let wire = task
        .get(EXTENSIONS_FIELD)
        .expect("the extensions field is attached")
        .as_object()
        .expect("it is an object");

    let labels = wire["security"]["labels"]
        .as_array()
        .expect("labels is an array");
    assert!(
        labels.iter().any(|l| l.as_str() == Some(INBOUND_LABEL)),
        "the inbound label must reach the worker: {labels:?}"
    );

    let headers = wire["http"]["request_headers"]
        .as_object()
        .expect("request_headers is an object");
    for name in headers.keys() {
        let lowered = name.to_ascii_lowercase();
        assert!(
            !matches!(lowered.as_str(), "authorization" | "cookie" | "x-api-key"),
            "sensitive header '{name}' must not cross the process boundary"
        );
    }
    assert_eq!(
        headers.get("X-Request-Id").and_then(|v| v.as_str()),
        Some("req-e2e-1"),
        "a non-sensitive header still travels"
    );

    let serialized = serde_json::to_string(&task).expect("the task serializes");
    assert!(
        !serialized.contains("must-not-travel"),
        "no sensitive header value may appear anywhere in the task JSON"
    );
}

#[test]
fn a_plugin_without_read_labels_gets_no_security_slot() {
    // The host serializes the *filtered* view, so capability filtering the
    // executor already did is what determines slot visibility. Simulate the
    // filtered result: no security slot in, none out.
    let filtered = Extensions {
        http: Some(Arc::new(HttpExtension::default())),
        ..Default::default()
    };

    let mut task = serde_json::json!({});
    cpex_hosts_python::extensions::attach_extensions(&mut task, &filtered)
        .expect("serializing a filtered view");

    let wire = task[EXTENSIONS_FIELD].as_object().expect("an object");
    assert!(
        !wire.contains_key("security"),
        "a slot the plugin's capabilities excluded must stay excluded"
    );
}

// =====================================================================
// Return path — tier enforcement through the real executor
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn an_appended_label_survives_the_merge_when_the_capability_is_declared() {
    // The monotonic accept case, end to end. `append_labels` makes the executor
    // mint a labels write token, the host honors the returned `security`, and
    // the executor's `before ⊆ after` check accepts the addition.
    let test = "an_appended_label_survives_the_merge_when_the_capability_is_declared";
    let Some(source) = require_worker(test) else {
        return;
    };
    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, test) else {
        return;
    };

    let (verdict, merged) = run_pipeline(
        &dir,
        &plugin_dir,
        &["read_labels", "append_labels", "read_headers"],
    )
    .await;

    assert!(
        verdict.starts_with("GOT_LABEL"),
        "the 3-arg hook must receive the inbound extensions; got: {verdict}"
    );
    assert!(
        !verdict.contains("LEAKED"),
        "no sensitive header may reach the plugin: {verdict}"
    );

    let security = merged
        .security
        .as_ref()
        .expect("security survives the merge");
    assert!(
        security.has_label(APPENDED_LABEL),
        "the plugin's additive label must survive the monotonic merge"
    );
    assert!(
        security.has_label(INBOUND_LABEL),
        "the original label must still be there"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn an_appended_label_is_dropped_without_the_capability() {
    // Same fixture, same return value — but no `append_labels`, so the executor
    // mints no token and the host drops the write. The pipeline's labels are
    // unchanged.
    let test = "an_appended_label_is_dropped_without_the_capability";
    let Some(source) = require_worker(test) else {
        return;
    };
    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, test) else {
        return;
    };

    let (verdict, merged) = run_pipeline(&dir, &plugin_dir, &["read_labels", "read_headers"]).await;

    assert!(
        verdict.starts_with("GOT_LABEL"),
        "reading is still allowed by read_labels; got: {verdict}"
    );

    let security = merged.security.as_ref().expect("security slot present");
    assert!(
        !security.has_label(APPENDED_LABEL),
        "a label append without `append_labels` must not land"
    );
    assert!(
        security.has_label(INBOUND_LABEL),
        "and the inbound label is untouched"
    );
}

/// A factory that builds the real Python plugin against a scaffolded temp dir.
///
/// `IsolatedVenvFactory` deliberately ignores a `plugin_dirs` key in the
/// `config:` block — the host always resolves `<project root>/plugins`, and the
/// factory warns and drops the key rather than appearing to honour it. That is
/// the right production behaviour, and it is covered by the factory's own unit
/// tests, so it must not be relaxed to suit a test.
///
/// But it leaves these tests no config-only way to redirect the venv, and a run
/// that built into the repository's real `plugins/` would be both destructive
/// and dependent on developer-machine state. The temp-dir overrides are
/// builder-only (`with_plugin_dirs` / `with_worker_cwd`) by design, so this
/// factory applies them and hands the manager the finished plugin. Everything
/// downstream — capability filtering, write-token minting, the copy-on-write
/// merge — is the real manager path, which is what these tests exist to cover.
mod temp_dir_factory {
    use std::path::PathBuf;
    use std::sync::Arc;

    use cpex_core::error::PluginError;
    use cpex_core::factory::{PluginFactory, PluginInstance};
    use cpex_core::plugin::PluginConfig;
    use cpex_hosts_python::plugin::{IsolatedPythonPlugin, PythonHookAdapter};

    /// Distinct from `factory::KIND` so registering this never shadows the real
    /// factory for any other test in the binary.
    pub const KIND: &str = "isolated_venv_temp_dir";

    pub struct TempDirFactory {
        pub plugin_dir: PathBuf,
        pub worker_cwd: PathBuf,
    }

    impl PluginFactory for TempDirFactory {
        fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            let plugin = Arc::new(
                IsolatedPythonPlugin::from_config(config)?
                    .with_plugin_dirs(vec![self.plugin_dir.display().to_string()])
                    .with_worker_cwd(self.worker_cwd.clone()),
            );

            let handlers: Vec<_> = config
                .hooks
                .iter()
                .map(
                    |hook| -> (&'static str, Arc<dyn cpex_core::registry::AnyHookHandler>) {
                        let leaked: &'static str = Box::leak(hook.clone().into_boxed_str());
                        (
                            leaked,
                            Arc::new(PythonHookAdapter::new(Arc::clone(&plugin), leaked)),
                        )
                    },
                )
                .collect();

            Ok(PluginInstance { plugin, handlers })
        }
    }
}

/// Register the Python plugin on `tool_pre_invoke`, run one pipeline pass, and
/// return the fixture's recorded verdict plus the merged extensions.
///
/// Going through `PluginManager` is the point: it is what filters extensions per
/// capability, mints the write tokens, and runs the copy-on-write merge that
/// validates the plugin's return.
async fn run_pipeline(
    dir: &TempDir,
    plugin_dir: &Path,
    capabilities: &[&str],
) -> (String, Extensions) {
    use cpex_core::config::CpexConfig;
    use cpex_core::manager::{ManagerConfig, PluginManager};

    let mut config = plugin_config(capabilities);
    // The temp-dir redirection rides on the factory (see `temp_dir_factory`),
    // not on a config key the host ignores.
    config.kind = temp_dir_factory::KIND.into();

    let manager = PluginManager::new(ManagerConfig::default());
    manager.register_factory(
        temp_dir_factory::KIND,
        Box::new(temp_dir_factory::TempDirFactory {
            plugin_dir: plugin_dir.to_path_buf(),
            worker_cwd: dir.path().to_path_buf(),
        }),
    );
    manager
        .load_config(CpexConfig {
            plugins: vec![config],
            ..Default::default()
        })
        .expect("the config loads");
    manager
        .initialize()
        .await
        .expect("the venv is reused and the worker starts");

    let inbound = inbound_extensions();
    let (result, _bg) = manager
        .invoke_named::<ToolPreInvoke>(
            "tool_pre_invoke",
            cpex_hosts_python::legacy::ToolPreInvokePayload::default(),
            inbound.clone(),
            None,
        )
        .await;

    manager.shutdown().await;

    let verdict = std::fs::read_to_string(dir.path().join("extensions_verdict.txt"))
        .unwrap_or_else(|e| panic!("the plugin recorded no verdict: {e}"));

    // `modified_extensions` is `None` when the pipeline merged nothing — which
    // is itself a meaningful outcome here (a dropped write). Fall back to the
    // inbound view so callers can assert "unchanged" without special-casing.
    let merged = result.modified_extensions.unwrap_or(inbound);
    (verdict, merged)
}

// =====================================================================
// Tier enforcement through the real executor, without a Python worker
// =====================================================================
//
// The worker-backed tests above skip until the Python branch lands. These cover
// the same merge with a Rust handler standing in for the worker: it calls the
// *production* `owned_from_returned_slot` on a canned response, so the code
// under test is identical — only the subprocess is replaced. That lets the
// accept-side tier outcomes be verified now, with write tokens minted by the
// executor from real declared capabilities.

mod fake_worker {
    use std::sync::Arc;

    use async_trait::async_trait;
    use cpex_core::context::PluginContext;
    use cpex_core::error::PluginError;
    use cpex_core::executor::ErasedResultFields;
    use cpex_core::extensions::Extensions;
    use cpex_core::factory::{PluginFactory, PluginInstance};
    use cpex_core::hooks::PluginPayload;
    use cpex_core::plugin::{Plugin, PluginConfig};
    use cpex_core::registry::AnyHookHandler;
    use serde_json::Value;

    /// Kind name for the stand-in factory.
    pub const KIND: &str = "fake-worker";

    /// A plugin whose handler returns a fixed worker-shaped response.
    pub struct FakeWorkerPlugin {
        cfg: PluginConfig,
    }

    #[async_trait]
    impl Plugin for FakeWorkerPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    /// Handler that feeds a canned response through the production parser.
    pub struct FakeWorkerHandler {
        /// The `modified_extensions` JSON a worker would have returned.
        pub response: Value,
    }

    #[async_trait]
    impl AnyHookHandler for FakeWorkerHandler {
        async fn invoke(
            &self,
            _payload: &dyn PluginPayload,
            extensions: &Extensions,
            _ctx: &mut PluginContext,
        ) -> Result<Box<dyn std::any::Any + Send + Sync>, Box<PluginError>> {
            // The real thing: same function the Python adapter calls, same
            // inbound view the executor filtered and tokenized.
            let modified_extensions =
                cpex_hosts_python::extensions::owned_from_returned_slot(&self.response, extensions)
                    .expect("the canned response parses");

            Ok(Box::new(ErasedResultFields {
                continue_processing: true,
                modified_payload: None,
                modified_extensions,
                violation: None,
            }))
        }

        fn hook_type_name(&self) -> &'static str {
            "tool_pre_invoke"
        }
    }

    /// Factory reading the canned response out of the plugin's own config.
    pub struct FakeWorkerFactory;

    impl PluginFactory for FakeWorkerFactory {
        fn create(&self, config: &PluginConfig) -> Result<PluginInstance, Box<PluginError>> {
            let response = config
                .config
                .as_ref()
                .and_then(|c| c.get("response"))
                .cloned()
                .unwrap_or(Value::Null);

            Ok(PluginInstance {
                plugin: Arc::new(FakeWorkerPlugin {
                    cfg: config.clone(),
                }),
                handlers: vec![(
                    "tool_pre_invoke",
                    Arc::new(FakeWorkerHandler { response }) as Arc<dyn AnyHookHandler>,
                )],
            })
        }
    }
}

/// Run one pipeline pass against the stand-in worker.
///
/// `response` is the `modified_extensions` value a real worker would return.
/// Returns the post-merge extensions the executor accepted.
async fn merge_through_executor(
    capabilities: &[&str],
    response: serde_json::Value,
) -> Option<Extensions> {
    use cpex_core::config::CpexConfig;
    use cpex_core::manager::{ManagerConfig, PluginManager};

    let config = PluginConfig {
        name: "fake-worker".into(),
        kind: fake_worker::KIND.into(),
        hooks: vec!["tool_pre_invoke".into()],
        capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
        version: Some("1.0.0".into()),
        config: Some(serde_json::json!({"response": response})),
        ..Default::default()
    };

    let manager = PluginManager::new(ManagerConfig::default());
    manager.register_factory(fake_worker::KIND, Box::new(fake_worker::FakeWorkerFactory));
    manager
        .load_config(CpexConfig {
            plugins: vec![config],
            ..Default::default()
        })
        .expect("the config loads");
    manager.initialize().await.expect("the plugin initializes");

    let (result, _bg) = manager
        .invoke_named::<ToolPreInvoke>(
            "tool_pre_invoke",
            cpex_hosts_python::legacy::ToolPreInvokePayload::default(),
            inbound_extensions(),
            None,
        )
        .await;

    manager.shutdown().await;
    result.modified_extensions
}

#[tokio::test(flavor = "multi_thread")]
async fn a_label_append_is_accepted_with_append_labels() {
    // The monotonic accept path, through the executor's real merge. This is the
    // case the unit tests structurally cannot reach: the token comes from the
    // declared capability.
    let merged = merge_through_executor(
        &["read_labels", "append_labels"],
        serde_json::json!({"security": {"labels": [INBOUND_LABEL, APPENDED_LABEL]}}),
    )
    .await
    .expect("the append is a real modification");

    let security = merged.security.as_ref().expect("security survives");
    assert!(
        security.has_label(APPENDED_LABEL),
        "an additive label change must be accepted by the monotonic tier"
    );
    assert!(
        security.has_label(INBOUND_LABEL),
        "the pre-existing label must remain"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_label_removal_is_rejected_by_the_monotonic_tier() {
    // `before ⊆ after` fails, so the executor rejects the whole return and the
    // pipeline keeps the original labels.
    let merged = merge_through_executor(
        &["read_labels", "append_labels"],
        serde_json::json!({"security": {"labels": []}}),
    )
    .await;

    if let Some(merged) = merged {
        let security = merged.security.as_ref().expect("security present");
        assert!(
            security.has_label(INBOUND_LABEL),
            "a label removal must not strip the pipeline's labels"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custom_change_is_accepted_as_mutable() {
    let merged = merge_through_executor(
        &["read_labels"],
        serde_json::json!({"custom": {"verdict": "clean"}}),
    )
    .await
    .expect("a custom write is a modification");

    let custom = merged.custom.as_ref().expect("custom survives the merge");
    assert_eq!(
        custom.get("verdict").and_then(|v| v.as_str()),
        Some("clean"),
        "the mutable tier is accepted as-is"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_immutable_slot_does_not_poison_the_merge() {
    // A plugin returning an `agent` it was never given must not cause the
    // executor to reject the whole return — the host drops the forged slot
    // before the merge sees it, so the legitimate `custom` write still lands.
    let merged = merge_through_executor(
        &["read_labels"],
        serde_json::json!({
            "agent": {"agent_id": "forged"},
            "custom": {"verdict": "clean"}
        }),
    )
    .await
    .expect("the custom write still counts as a modification");

    assert_eq!(
        merged
            .custom
            .as_ref()
            .expect("custom survives")
            .get("verdict")
            .and_then(|v| v.as_str()),
        Some("clean"),
        "the immutable-tier violation must not take the valid write down with it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_write_is_accepted_only_with_write_headers() {
    // Guarded tier, both sides. With the capability the header lands; without
    // it, the write is dropped.
    let with_cap = merge_through_executor(
        &["read_headers", "write_headers"],
        serde_json::json!({"http": {"request_headers": {"X-Added": "1"}}}),
    )
    .await
    .expect("an authorized header write is a modification");

    assert_eq!(
        with_cap
            .http
            .as_ref()
            .expect("http survives")
            .get_request_header("X-Added"),
        Some("1"),
        "write_headers authorizes the guarded write"
    );

    let without_cap = merge_through_executor(
        &["read_headers"],
        serde_json::json!({"http": {"request_headers": {"X-Added": "1"}}}),
    )
    .await;

    let leaked = without_cap
        .as_ref()
        .and_then(|m| m.http.as_ref())
        .and_then(|h| h.get_request_header("X-Added"));
    assert!(
        leaked.is_none(),
        "without write_headers the guarded write must not land"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_returned_sensitive_header_never_reenters_the_pipeline() {
    // Symmetry with the outbound strip: a plugin must not be able to inject a
    // credential header back into the pipeline through its return value.
    let merged = merge_through_executor(
        &["read_headers", "write_headers"],
        serde_json::json!({"http": {"request_headers": {
            "Authorization": "Bearer injected",
            "X-Fine": "yes"
        }}}),
    )
    .await
    .expect("the header write is a modification");

    let http = merged.http.as_ref().expect("http survives");
    assert!(
        http.get_request_header("Authorization").is_none(),
        "an injected credential header must be stripped on the way back"
    );
    assert_eq!(
        http.get_request_header("X-Fine"),
        Some("yes"),
        "the benign header still lands"
    );
}

/// The return field name is a contract with the Python `PluginResult` model.
///
/// `worker.py` serializes a `PluginResult`, whose `modified_extensions` field
/// already exists (`cpex/framework/models.py`) and is the same one the
/// in-process manager accumulates. Pinning it here means a rename on either side
/// fails a test instead of silently dropping every plugin's extension writes.
#[test]
fn the_return_field_matches_the_python_plugin_result_model() {
    assert_eq!(MODIFIED_EXTENSIONS_FIELD, "modified_extensions");
    assert_eq!(EXTENSIONS_FIELD, "extensions");
}
