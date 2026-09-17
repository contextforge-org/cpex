// Location: ./crates/cpex-hosts-python/tests/config_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// End-to-end through the *manager*: load `plugins/config.yaml`, register the
// `isolated_venv` factory, and invoke hooks on cpex-test-plugin —
// `tool_pre_invoke`, plus the two credential-adjacent hooks `identity_resolve`
// and `token_delegate`.
//
// # What this covers that `isolated_venv_e2e.rs` does not
//
// The other e2e tests build an `IsolatedPythonPlugin` directly and call its
// adapter, which skips two layers a real gateway goes through: YAML → factory
// → registry, and `PluginManager::invoke_by_name` → executor → adapter. This
// one drives both, against a plugin installed the way an operator installs one
// (`cpex plugin install`, not a scaffolded fixture). So it is the test that
// catches a config-shape or dispatch-wiring break that a direct adapter call
// would not see.
//
// `tool_pre_invoke` also carries populated `Extensions`, which makes this the
// only test that drives the extensions channel against an installer-written
// config — one that declares `capabilities: []`. `extensions_merge_e2e.rs` owns
// the observation and merge behaviour with a 3-arg fixture and explicit
// capability sets; what is unique here is the real config's no-capability path.
//
// # Why it is `#[ignore]`
//
// It depends on state this repo does not create: an installed plugin with a
// built venv under `plugins/`. See the setup comment on the test itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpex_core::extensions::{
    AgentExtension, Extensions, HttpExtension, RequestExtension, SecurityExtension,
};
use cpex_core::hooks::types::hook_names;
use cpex_core::manager::PluginManager;
use cpex_hosts_python::factory::{IsolatedVenvFactory, KIND};
use cpex_hosts_python::legacy::{
    IdentityResolvePayload, TokenDelegatePayload, ToolPreInvokePayload,
};
use cpex_hosts_python::plugin::IsolatedPythonPlugin;
use cpex_hosts_python::testing::{skip, skip_without_python3};

/// Plugin name in `plugins/config.yaml`.
const PLUGIN_NAME: &str = "cpex-test-plugin";

/// Marker `TestPlugin.identity_resolve` writes when `raw_token` arrives with a
/// non-empty secret value — evidence the field survived the wire as a populated
/// `SecretStr` rather than as `None` or an empty string.
const IDENTITY_RAW_TOKEN_MARKER: &str = "identity_resolve_raw_token";

/// Marker `TestPlugin.token_delegate` writes when `bearer_token` arrives with a
/// non-empty secret value. See [`IDENTITY_RAW_TOKEN_MARKER`].
const TOKEN_DELEGATE_BEARER_MARKER: &str = "token_delegate_bearer_token";

/// A security label on the inbound extensions. Distinctive so an assertion on it
/// cannot pass against a default-constructed `Extensions`.
const INBOUND_LABEL: &str = "CONFIG-E2E-LABEL-4f18";

/// A header value that must never cross the process boundary. Asserted by
/// absence from the serialized task, so it has to be unique enough that a match
/// anywhere in the JSON is conclusive.
const SENSITIVE_HEADER_VALUE: &str = "Bearer config-e2e-must-not-travel";

/// The repository root — `plugins/config.yaml` and the installed plugin's
/// `plugin_dirs` are both relative to it.
fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../cpex/crates/cpex-hosts-python
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the manifest dir has a crates/<crate> ancestry")
        .to_path_buf()
}

/// Skip guard: `Some(config_path)` when the installed-plugin fixture is present.
///
/// Every branch prints why it skipped — a silent no-op is indistinguishable
/// from a pass in `cargo test` output otherwise.
fn require_installed_plugin(test_name: &str) -> Option<PathBuf> {
    if skip_without_python3(test_name) {
        return None;
    }

    let root = repo_root();
    let config_path = root.join("plugins").join("config.yaml");
    if !config_path.is_file() {
        skip(
            test_name,
            &format!(
                "no {} — install the plugin first (see the setup comment)",
                config_path.display()
            ),
        );
        return None;
    }

    // The venv the worker runs in. Its absence means the plugin was never
    // installed, and the host would try a cold build from the plugin's
    // requirements.txt (two git clones) inside the test.
    let venv = root
        .join("plugins")
        .join("cpex_test_plugin")
        .join(".venv")
        .join("bin")
        .join("python");
    if !venv.is_file() {
        skip(
            test_name,
            &format!(
                "no venv at {} — run `cpex plugin --type test-pypi install \
                 \"cpex-test-plugin@>=0.2.0\"` first",
                venv.display()
            ),
        );
        return None;
    }

    Some(config_path)
}

/// Remove a stale `.<name>` marker and return its path.
///
/// The plugin's hooks each write `.<method_name>` at the worker's cwd, and the
/// two credential hooks write a second `.<method_name>_<field>` when their
/// redacting field arrives non-empty. Clearing first is what makes a marker
/// evidence of *this* run rather than a previous one.
fn clear_marker(root: &Path, name: &str) -> PathBuf {
    let marker = root.join(format!(".{name}"));
    let _ = std::fs::remove_file(&marker);
    marker
}

/// Assert a hook body ran, then remove the marker so the next run starts clean.
fn assert_marker_written(marker: &Path, description: &str) {
    let touched = marker.is_file();
    let _ = std::fs::remove_file(marker);
    assert!(
        touched,
        "expected TestPlugin.{description} to create {} — the hook body did not run",
        marker.display()
    );
}

/// Assert a result is the unconditional allow every `TestPlugin` hook returns.
///
/// `errors` is checked first: a worker that failed to start or a hook the
/// framework rejected surfaces there rather than as a deny, so checking the
/// allow first would point the failure message at the wrong layer.
fn assert_allowed(result: &cpex_core::executor::PipelineResult, hook_name: &str) {
    assert!(
        result.errors.is_empty(),
        "the pipeline recorded plugin errors on {hook_name}: {:?}",
        result.errors
    );
    assert!(
        result.continue_processing,
        "TestPlugin.{hook_name} returns continue_processing=True unconditionally: violation={:?}",
        result.violation
    );
    assert!(
        result.violation.is_none(),
        "an allow carries no violation on {hook_name}: {:?}",
        result.violation
    );
}

/// A populated `Extensions` spanning the three filter behaviours a plugin with
/// `capabilities: []` can exhibit, so one fixture exercises all of them:
///
/// * `request` / `custom` — unrestricted immutable slots. `filter_extensions`
///   copies these through regardless of capabilities, so they are the slots that
///   actually reach a plugin declaring none.
/// * `agent` / `http` — capability-gated slots. `cpex-test-plugin` declares
///   `capabilities: []` in `plugins/config.yaml`, so the executor strips both
///   before the host ever serializes. Including them is the point: it proves the
///   gate holds on the real installer-written config rather than on a config a
///   test constructed to have no gated data in the first place.
/// * `security` — gated per sub-field. The slot survives, `labels` does not.
///
/// The `Authorization` header is a second, independent guard: `attach_extensions`
/// strips sensitive headers on the way out, so even a config that *did* declare
/// `read_headers` must not put this value on the wire.
fn inbound_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.add_label(INBOUND_LABEL);
    security.classification = Some("internal".to_string());
    security.auth_method = Some("jwt".to_string());

    let mut http = HttpExtension::default();
    http.set_request_header("Authorization", SENSITIVE_HEADER_VALUE);
    http.set_request_header("X-Request-Id", "req-config-e2e-1");
    http.method = Some("POST".to_string());
    http.path = Some("/rpc/tools/invoke".to_string());

    Extensions {
        request: Some(Arc::new(RequestExtension {
            environment: Some("test".to_string()),
            request_id: Some("req-config-e2e-1".to_string()),
            trace_id: Some("trace-config-e2e-1".to_string()),
            ..Default::default()
        })),
        agent: Some(Arc::new(AgentExtension {
            session_id: Some("session-config-e2e".to_string()),
            agent_id: Some("agent-config-e2e".to_string()),
            turn: Some(3),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        custom: Some(Arc::new(HashMap::from([(
            "config_e2e".to_string(),
            serde_json::json!({"source": "config_e2e.rs"}),
        )]))),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Setup
//
// The plugin must be installed under the repo root, which builds
// `plugins/cpex_test_plugin/.venv` and writes `plugins/config.yaml`:
//
//   cpex plugin --type test-pypi install "cpex-test-plugin@>=0.2.0"
//
// Then:
//
//   cargo test -p cpex-hosts-python --test config_e2e -- --ignored --nocapture
//
// Note the first run may rebuild the venv even though one exists: the Python
// CLI writes its cache metadata as `.venv_metadata.json`, while this host keys
// that filename per class (see the comment in `venv.rs::VenvLayout::resolve`).
// It is a cache hit on every run after.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires cpex-test-plugin installed under plugins/ with a built venv"]
async fn config_yaml_dispatches_tool_pre_invoke_to_the_installed_plugin() {
    let test_name = "config_yaml_dispatches_tool_pre_invoke_to_the_installed_plugin";
    let Some(config_path) = require_installed_plugin(test_name) else {
        return;
    };
    let root = repo_root();

    // The process cwd is the project root the host resolves `plugins` against,
    // and it is also the worker's cwd — whose ALLOWED_PLUGIN_DIRS allowlist
    // accepts it, and where the plugin's marker file lands. So this one call
    // sets both, and they cannot disagree.
    std::env::set_current_dir(&root).expect("cd to the repo root");

    // The plugin's `tool_pre_invoke` writes `.tool_pre_invoke` at the worker's
    // cwd. Remove any stale copy so its existence proves *this* run executed
    // the hook body rather than a previous one.
    let marker = clear_marker(&root, hook_names::TOOL_PRE_INVOKE);

    // Loaded straight from disk with no patching: the whole point is that a
    // config.yaml as written by `cpex plugin install` works as-is.
    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(IsolatedVenvFactory));
    manager
        .load_config_file(&config_path)
        .expect("plugins/config.yaml loads with the isolated_venv factory registered");

    // A config that loaded but registered nothing would make every assertion
    // below vacuous: `invoke_by_name` short-circuits to an allow when no plugin
    // is on the hook, so the "clean input is allowed" checks would pass with no
    // Python involved at all.
    assert!(
        manager.has_hooks_for(hook_names::TOOL_PRE_INVOKE),
        "no plugin registered on {} — check that config.yaml still declares \
         kind: {KIND} and that hook",
        hook_names::TOOL_PRE_INVOKE
    );
    assert!(
        manager.plugin_names().iter().any(|n| n == PLUGIN_NAME),
        "expected '{PLUGIN_NAME}' among the loaded plugins, got {:?}",
        manager.plugin_names()
    );

    manager
        .initialize()
        .await
        .expect("the venv resolves and the worker starts");

    // `tool_pre_invoke` carries the native Pydantic shape the Python plugin
    // expects — `name` plus `args` — not the generic wrapper.
    let payload = ToolPreInvokePayload {
        name: "test_tool".to_string(),
        args: Some(HashMap::from([(
            "query".to_string(),
            serde_json::json!("hello world"),
        )])),
        headers: None,
    };

    // Populated extensions rather than `Extensions::default()`. The default is
    // the one input that cannot fail: with every slot `None`,
    // `attach_extensions` writes no field at all, so the whole inbound channel
    // is untested and the assertions below hold vacuously. Passing real slots
    // through the installer-written config is what makes this test cover the
    // channel — see `inbound_extensions` for what each slot is there to prove.
    let inbound = inbound_extensions();

    let (result, _background) = manager
        .invoke_by_name(
            hook_names::TOOL_PRE_INVOKE,
            Box::new(payload),
            inbound.clone(),
            None,
        )
        .await;

    manager.shutdown().await;

    assert_allowed(&result, hook_names::TOOL_PRE_INVOKE);

    // The marker proves the plugin's hook body ran. Without it, a response
    // shaped like an allow is indistinguishable from the manager's
    // no-plugins-registered short circuit.
    //
    // Combined with the populated extensions above, it is also the assertion
    // that carries the most weight here: the worker received a task with an
    // `extensions` field, deserialized it, and still ran the hook. A slot shape
    // the worker's Pydantic models reject surfaces as a validation error in
    // `errors` and no marker — which is precisely the break a `default()` input
    // could never detect.
    assert_marker_written(&marker, hook_names::TOOL_PRE_INVOKE);

    // `modified_extensions` on an allowed pipeline is the *final* extensions
    // view, not a "something changed" signal — `PipelineResult::allowed_with`
    // always populates it with whatever the pipeline ended up holding. So the
    // meaningful assertion is that the view came back unchanged.
    //
    // Unchanged is the correct outcome for two independent reasons, and this is
    // the only place the real installer-written config pins either: the plugin
    // declares `capabilities: []`, so the executor strips every gated slot before
    // the host serializes; and its `tool_pre_invoke(payload, context)` is 2-arg,
    // so the framework forwards no extensions to the hook body at all. A plugin
    // that receives nothing has nothing to write back.
    //
    // Note this is the *pipeline's* view, not the filtered one the plugin saw —
    // the executor filters per plugin and merges writes back into the unfiltered
    // original, so a stripped slot reappearing here is expected and correct.
    let returned = result
        .modified_extensions
        .as_ref()
        .expect("an allowed pipeline always carries its final extensions view");
    assert!(
        returned.agent.is_some() && returned.request.is_some() && returned.http.is_some(),
        "the pipeline's own view keeps the slots it started with; per-plugin \
         filtering must not mutate it"
    );
    assert!(
        returned
            .security
            .as_ref()
            .is_some_and(|s| s.has_label(INBOUND_LABEL)),
        "a plugin that never received `security.labels` cannot have dropped the \
         pipeline's label"
    );
    assert_eq!(
        returned.custom.as_deref(),
        inbound.custom.as_deref(),
        "no plugin wrote `custom`, so it must survive the pipeline byte-for-byte"
    );

    // What the plugin *would* have seen, computed with the same production
    // filter the executor ran. Asserting on this rather than on the worker's
    // observations is deliberate: the installed plugin's hooks are 2-arg, so it
    // has no way to report what arrived, and `extensions_merge_e2e.rs` owns the
    // 3-arg observation path with a purpose-built fixture. This keeps the
    // capability contract pinned against the real installer-written config.
    let filtered = cpex_core::extensions::filter_extensions(&inbound, &Default::default());
    assert!(
        filtered.agent.is_none(),
        "`agent` is capability-gated and this config declares none, so it must \
         not reach the plugin"
    );
    assert!(
        filtered.http.is_none(),
        "`http` is capability-gated and this config declares none, so it must \
         not reach the plugin"
    );
    assert!(
        !filtered
            .security
            .as_ref()
            .expect("the security slot survives; its gated sub-fields do not")
            .has_label(INBOUND_LABEL),
        "`security.labels` is gated under `read_labels`, which this config does \
         not declare"
    );
    assert!(
        filtered.request.is_some(),
        "`request` is unrestricted — stripping it would silently starve every \
         plugin of request context"
    );

    // The outbound sensitive-header strip, on the path a real gateway takes.
    // This holds for a second, independent reason beyond the capability filter
    // above: `attach_extensions` scrubs these regardless of what the plugin
    // declares, so the assertion stays meaningful if this config ever gains
    // `read_headers`.
    let mut task = serde_json::json!({"task_type": "load_and_run_hook"});
    cpex_hosts_python::extensions::attach_extensions(&mut task, &inbound)
        .expect("the inbound view serializes");
    let wire = serde_json::to_string(&task).expect("the task serializes");
    assert!(
        !wire.contains(SENSITIVE_HEADER_VALUE),
        "no credential header value may appear anywhere in the task JSON: {wire}"
    );
}

/// The two credential-adjacent hooks dispatch through the same config → factory
/// → registry → executor → worker path as `tool_pre_invoke`.
///
/// # Why these two are worth their own test
///
/// `identity_resolve` and `token_delegate` are the only hooks the host treats
/// specially: `is_credential_hook` singles them out, and their payloads carry
/// redacting fields (`raw_token`, `bearer_token`) that no other hook has. That
/// makes them the two most likely to break in a way `tool_pre_invoke` cannot
/// detect — a payload-kind mapping that falls through to `PayloadKind::Generic`,
/// for instance, still round-trips as an allow, so only a marker file
/// distinguishes a real dispatch from a silent no-op. The plugin writes two
/// markers per credential hook: one for the hook body, one for the redacting
/// field arriving non-empty. This test asserts both.
///
/// No `capabilities` are declared in `plugins/config.yaml`, so the host attaches
/// no `credential` object here. This is the no-credential path: the hooks
/// dispatch on payload shape alone. `credential_e2e.rs` covers the gated
/// plaintext channel.
///
/// Both hooks run in one test because they share the manager, the worker, and
/// the setup cost — a second `#[ignore]` test would double a venv-backed
/// startup to assert the same wiring.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires cpex-test-plugin installed under plugins/ with a built venv"]
async fn config_yaml_dispatches_identity_resolve_and_token_delegate_to_the_installed_plugin() {
    let test_name =
        "config_yaml_dispatches_identity_resolve_and_token_delegate_to_the_installed_plugin";
    let Some(config_path) = require_installed_plugin(test_name) else {
        return;
    };
    let root = repo_root();

    // Sets the project root the host resolves `plugins` against and the worker's
    // cwd at once — see the comment in the test above.
    std::env::set_current_dir(&root).expect("cd to the repo root");

    let identity_marker = clear_marker(&root, hook_names::IDENTITY_RESOLVE);
    let delegate_marker = clear_marker(&root, hook_names::TOKEN_DELEGATE);

    // Each credential hook writes a *second* marker when its redacting field
    // arrives non-empty (`.identity_resolve_raw_token`,
    // `.token_delegate_bearer_token`). Both payloads below populate that field,
    // so both land on every run — clear them here and assert them below, or the
    // test leaves them behind in the working tree.
    let identity_field_marker = clear_marker(&root, IDENTITY_RAW_TOKEN_MARKER);
    let delegate_field_marker = clear_marker(&root, TOKEN_DELEGATE_BEARER_MARKER);

    let manager = Arc::new(PluginManager::default());
    manager.register_factory(KIND, Box::new(IsolatedVenvFactory));
    manager
        .load_config_file(&config_path)
        .expect("plugins/config.yaml loads with the isolated_venv factory registered");

    // Without these, both invocations below short-circuit to an allow with no
    // Python involved, and every assertion that follows would be vacuous.
    for hook in [hook_names::IDENTITY_RESOLVE, hook_names::TOKEN_DELEGATE] {
        assert!(
            manager.has_hooks_for(hook),
            "no plugin registered on {hook} — check that config.yaml still lists it under \
             `hooks:` for a kind: {KIND} plugin"
        );
    }
    assert!(
        manager.plugin_names().iter().any(|n| n == PLUGIN_NAME),
        "expected '{PLUGIN_NAME}' among the loaded plugins, got {:?}",
        manager.plugin_names()
    );

    manager
        .initialize()
        .await
        .expect("the venv resolves and the worker starts");

    // `identity_resolve` mirrors Python's `IdentityPayload`. `raw_token` is a
    // `SecretStr` there and carries a placeholder on the wire — the plaintext
    // would ride the separate capability-gated `credential` object, which this
    // config declares no capability for.
    let identity_payload = IdentityResolvePayload {
        raw_token: "<redacted>".to_string(),
        source: "bearer".to_string(),
        headers: HashMap::from([("Authorization".to_string(), "<redacted>".to_string())]),
        client_host: Some("10.0.0.1".to_string()),
        client_port: Some(8443),
    };

    let (identity_result, _background) = manager
        .invoke_by_name(
            hook_names::IDENTITY_RESOLVE,
            Box::new(identity_payload),
            Extensions::default(),
            None,
        )
        .await;

    // `token_delegate` mirrors `DelegationPayload`. `target_type` and
    // `auth_enforced_by` are left to their defaults so the worker's Pydantic
    // model has to supply them — an omitted-field mismatch surfaces as a
    // validation error in `errors`, not as a deny.
    //
    // `bearer_token` carries a mock value rather than staying `None`: on the
    // Python side it is a `SecretStr | None`, so a populated field exercises the
    // `SecretStr` coercion in the worker's model reconstruction that a `None`
    // leaves untested. The value is deliberately not a real credential — this
    // config declares no capability, so the plaintext channel (`credential`)
    // is absent and only this redacting field is in play. `credential_e2e.rs`
    // covers the gated plaintext path.
    let delegate_payload = TokenDelegatePayload {
        target_name: "billing-api".to_string(),
        target_audience: Some("https://billing.internal".to_string()),
        required_permissions: vec!["invoices:read".to_string()],
        bearer_token: Some("mock-bearer-token".to_string()),
        ..Default::default()
    };

    let (delegate_result, _background) = manager
        .invoke_by_name(
            hook_names::TOKEN_DELEGATE,
            Box::new(delegate_payload),
            Extensions::default(),
            None,
        )
        .await;

    manager.shutdown().await;

    assert_allowed(&identity_result, hook_names::IDENTITY_RESOLVE);
    assert_allowed(&delegate_result, hook_names::TOKEN_DELEGATE);

    // The markers are what separate a real dispatch from an allow-shaped no-op:
    // a hook that never reached the plugin still comes back as an allow, so
    // without these the assertions above would pass on a silent no-op.
    assert_marker_written(&identity_marker, hook_names::IDENTITY_RESOLVE);
    assert_marker_written(&delegate_marker, hook_names::TOKEN_DELEGATE);

    // And these prove the redacting fields survived the round trip as populated
    // `SecretStr`s. A payload-kind mapping that fell through to
    // `PayloadKind::Generic` would drop them to `None`, which the hook markers
    // above cannot detect — the hook body still runs either way.
    assert_marker_written(
        &identity_field_marker,
        "identity_resolve (non-empty raw_token)",
    );
    assert_marker_written(
        &delegate_field_marker,
        "token_delegate (non-empty bearer_token)",
    );
}

/// An installer-generated config resolves `plugins` at the project root with no
/// patching, and neither `plugin_dirs` key steers it.
///
/// Needs no venv and no python3, so unlike the test above it runs on every
/// `cargo test`. This is the regression guard for the gap that used to require a
/// shim here: a config shaped exactly as `cpex plugin install` writes it must
/// load *and* resolve to the right directory.
#[test]
fn an_installer_generated_config_resolves_plugins_at_the_project_root() {
    // The shape `cpex plugin install` generates: plugin_dirs at the top level,
    // absent from the plugin's own config block. Plus a per-plugin
    // `plugin_dirs` pointing somewhere bogus, to prove neither key wins.
    let yaml = r#"
plugin_dirs:
  - /top/level/ignored
plugins:
  - name: cpex-test-plugin
    kind: isolated_venv
    hooks: [tool_pre_invoke]
    version: 0.2.1
    config:
      class_name: cpex_test_plugin.plugin.TestPlugin
      requirements_file: requirements.txt
      plugin_dirs: ["/per/plugin/ignored"]
"#;

    let config = cpex_core::config::parse_config(yaml).expect("valid config");

    // Both keys still parse — they are simply not the host's source.
    assert_eq!(config.plugin_dirs, vec!["/top/level/ignored".to_string()]);

    let plugin = IsolatedPythonPlugin::from_config(&config.plugins[0])
        .expect("an ignored plugin_dirs key must not fail the load");

    let expected = std::env::current_dir()
        .unwrap()
        .join(cpex_hosts_python::DEFAULT_PLUGIN_DIR)
        .display()
        .to_string();
    assert_eq!(
        plugin.plugin_dirs(),
        [expected],
        "the host must resolve <project root>/plugins, ignoring both config keys"
    );
}
