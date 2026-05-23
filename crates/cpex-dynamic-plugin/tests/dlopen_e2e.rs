// Location: ./crates/cpex-dynamic-plugin/tests/dlopen_e2e.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// End-to-end test for `DynamicPluginFactory` against a real cdylib.
//
// Exercises the full slice: the example plugin (compiled as a
// cdylib by cargo via the dev-dep edge) → `DynamicPluginFactory`
// dlopens it → registration handshake → `PluginInstance`
// construction → invoke via `PluginManager` → assert outcome.
//
// This is the load-bearing "the unsafe glue actually works"
// test. The unit tests in `host.rs` cover the kind-string parser
// in isolation; this test wires through libloading + the entry
// point + Box::from_raw + handler dispatch end-to-end.
//
// # Why the file requires `--features host`
//
// `DynamicPluginFactory` lives behind the `host` feature flag in
// cpex-dynamic-plugin. The integration test is automatically
// included when running `cargo test --features host`. Plain
// `cargo test` (default features only) skips this file's tests
// because the `DynamicPluginFactory` symbol isn't visible.

#![cfg(feature = "host")]

use std::path::PathBuf;
use std::sync::Arc;

use cpex_core::cmf::enums::Role;
use cpex_core::cmf::{CmfHook, Message, MessagePayload};
use cpex_core::extensions::Extensions;
use cpex_core::manager::PluginManager;
use cpex_core::plugin::{OnError, PluginConfig, PluginMode};

use cpex_dynamic_plugin::DynamicPluginFactory;

/// Name of the allow-gate example plugin crate. Cargo turns
/// hyphens into underscores when forming the artifact filename.
const EXAMPLE_CRATE: &str = "cpex_dynamic_plugin_example";

/// Name of the multi-handler example plugin crate. Registers two
/// handlers: pre-invoke allow + post-invoke deny.
const MULTI_HANDLER_CRATE: &str = "cpex_dynamic_plugin_multi_handler_example";

/// Locate a cdylib in the workspace target directory by crate
/// name. Uses `CARGO_MANIFEST_DIR` (the cpex-dynamic-plugin
/// crate's dir, set by cargo at test build time) and walks up to
/// the workspace root. Profile defaults to `debug`; tests run
/// `cargo test` which is the debug profile.
fn cdylib_path(crate_name: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR = <ws>/crates/cpex-dynamic-plugin
    // Walk up two levels to get to <ws>.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // <ws>/
        .expect("workspace root reachable from CARGO_MANIFEST_DIR")
        .to_path_buf();

    // Profile: `cargo test --release` would put it in `release/`,
    // but the default `cargo test` is `debug/`. Detect via the
    // `PROFILE` env var if set, else default debug.
    let profile = option_env!("PROFILE").unwrap_or("debug");

    // Filename: `lib<crate>.dylib` on macOS, `lib<crate>.so` on
    // Linux, `<crate>.dll` on Windows. `DLL_PREFIX` is "lib" on
    // unix and "" on windows; `DLL_SUFFIX` is the right thing
    // per-OS.
    let filename = format!(
        "{prefix}{crate_name}{suffix}",
        prefix = std::env::consts::DLL_PREFIX,
        crate_name = crate_name,
        suffix = std::env::consts::DLL_SUFFIX,
    );

    workspace_root
        .join("target")
        .join(profile)
        .join(filename)
}

/// Build the `kind:` string for a workspace cdylib. The dev-dep
/// edge from cpex-dynamic-plugin to the example plugins guarantees
/// cargo has built the cdylib before this test runs.
fn cdylib_kind(crate_name: &str) -> String {
    let path = cdylib_path(crate_name);
    assert!(
        path.exists(),
        "plugin cdylib not found at {} — \
         the dev-dependency on {} should have triggered the build. \
         Try `cargo test -p cpex-dynamic-plugin --features host`",
        path.display(),
        crate_name,
    );
    format!("lib:{}", path.display())
}

fn example_kind() -> String {
    cdylib_kind(EXAMPLE_CRATE)
}

/// Build a `PluginConfig` referencing the example plugin via the
/// URL-shaped kind, with the operator's own plugin config
/// (a no-op `{}` for the example).
fn example_plugin_config() -> PluginConfig {
    PluginConfig {
        name: "example".into(),
        kind: example_kind(),
        hooks: vec!["cmf.tool_pre_invoke".into()],
        mode: PluginMode::Sequential,
        priority: 10,
        on_error: OnError::Fail,
        config: Some(serde_json::json!({})),
        ..Default::default()
    }
}

#[tokio::test]
async fn factory_loads_example_cdylib_and_executor_invokes_it() {
    // 1. Set up a manager + register the dynamic-plugin factory
    //    under scheme "lib".
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory_scheme("lib", Box::new(DynamicPluginFactory::new()));

    // 2. Build the plugin config that points at the example cdylib
    //    and load it via the standard factory-driven path. We use
    //    register_handler under the hood via a small helper rather
    //    than going through load_config_yaml — that path needs a
    //    full YAML; we already have a typed PluginConfig.
    //
    //    The factory's `create()` is what dlopens the library,
    //    binds to cpex_plugin_create, calls it, and produces a
    //    PluginInstance. We then hand that PluginInstance's
    //    handlers to the manager via register_raw.
    let cfg = example_plugin_config();

    // The most direct path that exercises the factory: ask the
    // manager to load a config containing the plugin. We build a
    // minimal YAML and feed it.
    let yaml = format!(
        r#"
plugins:
  - name: {name}
    kind: "{kind}"
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    config: {{}}
"#,
        name = cfg.name,
        kind = cfg.kind,
    );
    let parsed = cpex_core::config::parse_config(&yaml)
        .expect("YAML parses into CpexConfig");
    mgr.load_config(parsed)
        .expect("load_config_yaml should succeed against the example cdylib");
    mgr.initialize().await.unwrap();

    // 3. Dispatch a CMF message through the manager. The example
    //    plugin's handler is `PluginResult::allow()` — pipeline
    //    should continue.
    let payload = MessagePayload {
        message: Message::text(Role::User, "hello dynamic plugin"),
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload,
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "dynamic plugin's allow-gate should let the pipeline continue: \
         violation = {:?}",
        result.violation,
    );

    // The example plugin doesn't mutate payload or extensions, but
    // the executor returns the (possibly Box'd) original payload
    // via `modified_payload`. Just confirm it's there.
    assert!(result.modified_payload.is_some());
}

#[tokio::test]
async fn factory_reports_friendly_error_when_library_missing() {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory_scheme("lib", Box::new(DynamicPluginFactory::new()));

    let yaml = r#"
plugins:
  - name: missing
    kind: "lib:/dev/null/definitely-not-a-real-cdylib.dylib"
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    config: {}
"#;
    let parsed = cpex_core::config::parse_config(yaml)
        .expect("YAML parses into CpexConfig");
    let err = mgr
        .load_config(parsed)
        .expect_err("missing cdylib should fail config load");
    let msg = format!("{err}");
    assert!(
        msg.contains("dlopen") || msg.contains("failed to") || msg.to_lowercase().contains("not"),
        "expected a dlopen-related error message, got: {msg}",
    );
}

#[tokio::test]
async fn factory_rejects_wrong_scheme_in_kind() {
    // The factory is registered for scheme "lib"; a kind starting
    // with "wasm:" can't reach the factory at all — the registry's
    // get() returns None and the manager reports "no factory".
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory_scheme("lib", Box::new(DynamicPluginFactory::new()));

    let yaml = r#"
plugins:
  - name: wrong-scheme
    kind: "wasm:/path/to/foo.wasm"
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    config: {}
"#;
    let parsed = cpex_core::config::parse_config(yaml)
        .expect("YAML parses into CpexConfig");
    let err = mgr
        .load_config(parsed)
        .expect_err("unregistered scheme should fail config load");
    let msg = format!("{err}");
    assert!(
        msg.contains("no factory") || msg.contains("wasm"),
        "expected a no-factory diagnostic, got: {msg}",
    );
}

// --------------------------------------------------------------------
// Multi-handler + multi-plugin tests.
//
// These tests exercise two aspects of the loader that the single-
// handler happy path can't cover:
//
//   1. A cdylib that registers MORE THAN ONE handler with distinct
//      hook names. We need to confirm the host wires each handler
//      to its declared hook (not collapsed onto one) AND that the
//      `#handler` URL fragment correctly filters down to a single
//      handler when the operator wants only one.
//   2. TWO DIFFERENT cdylibs loaded simultaneously by the same
//      PluginManager. We need to confirm that two `Box::leak`ed
//      Library handles + two separate registrations don't step on
//      each other (separate vtables, separate Arcs, separate
//      handler maps).
//
// The multi-handler example registers:
//   * cmf.tool_pre_invoke  → AllowOnPre  → continue_processing=true
//   * cmf.tool_post_invoke → DenyOnPost  → continue_processing=false
//                                         violation.code =
//                                         "test.multi_handler.post_deny"
//
// The verdict + violation code is the test's signal for "which
// handler ran".
// --------------------------------------------------------------------

/// Multi-handler cdylib loaded WITHOUT a fragment should register
/// both handlers, each under its declared hook name. Invoking
/// `cmf.tool_pre_invoke` should hit the allow path; invoking
/// `cmf.tool_post_invoke` should hit the deny path with the
/// distinctive violation code.
#[tokio::test]
async fn multi_handler_no_fragment_registers_both() {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory_scheme("lib", Box::new(DynamicPluginFactory::new()));

    // Note: `hooks:` declares BOTH hook names so the registry binds
    // both handlers. The cdylib produces a PluginRegistration with
    // two `(hook_name, handler)` pairs; the host filters by `hooks:`
    // and by URL fragment. With no fragment and both hooks listed,
    // both handlers are wired.
    let kind = cdylib_kind(MULTI_HANDLER_CRATE);
    let yaml = format!(
        r#"
plugins:
  - name: multi
    kind: "{kind}"
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    config: {{}}
"#,
    );
    let parsed = cpex_core::config::parse_config(&yaml)
        .expect("YAML parses into CpexConfig");
    mgr.load_config(parsed).expect("multi-handler cdylib loads");
    mgr.initialize().await.unwrap();

    // Pre-invoke → allow.
    let pre_payload = MessagePayload {
        message: Message::text(Role::User, "pre"),
    };
    let (pre_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            pre_payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        pre_result.continue_processing,
        "AllowOnPre should allow pre-invoke; got violation={:?}",
        pre_result.violation,
    );

    // Post-invoke → deny with the distinctive code. This proves the
    // post-handler ran (not the pre-handler bound to the wrong hook).
    let post_payload = MessagePayload {
        message: Message::text(Role::User, "post"),
    };
    let (post_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_post_invoke",
            post_payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        !post_result.continue_processing,
        "DenyOnPost should deny post-invoke",
    );
    let violation = post_result
        .violation
        .expect("deny should carry a violation");
    assert_eq!(
        violation.code, "test.multi_handler.post_deny",
        "violation code identifies the post-handler as the one that fired",
    );
}

/// With a `#cmf.tool_pre_invoke` fragment in the kind, the host
/// should filter the cdylib's registered handlers down to just the
/// pre-invoke one. Even if the operator lists `cmf.tool_post_invoke`
/// in `hooks:`, no handler should be wired there because the
/// fragment filtered the post-handler out of the registration.
#[tokio::test]
async fn multi_handler_with_fragment_filters_to_one() {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory_scheme("lib", Box::new(DynamicPluginFactory::new()));

    let kind = format!(
        "{}#cmf.tool_pre_invoke",
        cdylib_kind(MULTI_HANDLER_CRATE),
    );
    // Only list the pre hook — the fragment already filtered out
    // the post handler, so listing post here would just fail the
    // load with "no handler for hook".
    let yaml = format!(
        r#"
plugins:
  - name: multi-filtered
    kind: "{kind}"
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    config: {{}}
"#,
    );
    let parsed = cpex_core::config::parse_config(&yaml)
        .expect("YAML parses into CpexConfig");
    mgr.load_config(parsed)
        .expect("fragment-filtered cdylib loads");
    mgr.initialize().await.unwrap();

    // Pre still allows.
    let payload = MessagePayload {
        message: Message::text(Role::User, "pre"),
    };
    let (result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "pre handler is the only one present and should allow",
    );

    // Post should have NO handler — invoking the hook is a no-op
    // (no plugins subscribed). Manager returns a continue verdict
    // by default. Confirm we don't accidentally see the post-deny
    // violation that would mean the fragment filter failed.
    let post_payload = MessagePayload {
        message: Message::text(Role::User, "post"),
    };
    let (post_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_post_invoke",
            post_payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        post_result.continue_processing,
        "with no post handler wired, the post hook should be a no-op",
    );
    assert!(
        post_result.violation.is_none(),
        "fragment filter failed: post-deny handler fired anyway. \
         violation = {:?}",
        post_result.violation,
    );
}

/// Two distinct cdylibs loaded into the SAME PluginManager. Each
/// is built independently, each is `Box::leak`ed by the host, and
/// both contribute to the hook pipelines without interfering with
/// each other.
///
/// We load:
///   * `cpex-dynamic-plugin-example`              → allow on pre
///   * `cpex-dynamic-plugin-multi-handler-example` → allow on pre +
///                                                   deny on post
///
/// On `cmf.tool_pre_invoke` both plugins fire and both allow, so
/// the pipeline continues. On `cmf.tool_post_invoke` only the
/// multi-handler plugin is wired (the example plugin doesn't
/// subscribe to it) and we get the deny verdict. This proves the
/// two libraries coexist without symbol clashes or shared state.
#[tokio::test]
async fn multiple_dynamic_plugins_coexist_in_one_manager() {
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory_scheme("lib", Box::new(DynamicPluginFactory::new()));

    let single_kind = cdylib_kind(EXAMPLE_CRATE);
    let multi_kind = cdylib_kind(MULTI_HANDLER_CRATE);
    let yaml = format!(
        r#"
plugins:
  - name: single
    kind: "{single_kind}"
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    config: {{}}
  - name: multi
    kind: "{multi_kind}"
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    mode: sequential
    priority: 20
    on_error: fail
    config: {{}}
"#,
    );
    let parsed = cpex_core::config::parse_config(&yaml)
        .expect("YAML parses into CpexConfig");
    mgr.load_config(parsed)
        .expect("two distinct cdylibs load into one manager");
    mgr.initialize().await.unwrap();

    // Both plugins subscribe to pre-invoke. Both allow → pipeline
    // continues. If either Library got unloaded prematurely (drop-
    // order hazard), invoking through the vtable would segfault
    // here — the test reaching the assert means both libraries are
    // still mapped.
    let pre_payload = MessagePayload {
        message: Message::text(Role::User, "pre"),
    };
    let (pre_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_pre_invoke",
            pre_payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        pre_result.continue_processing,
        "both pre-invoke handlers should allow; got violation={:?}",
        pre_result.violation,
    );

    // Only multi subscribes to post-invoke, and it denies. The fact
    // that the single plugin's library hasn't trampled multi's
    // registration is what we're confirming.
    let post_payload = MessagePayload {
        message: Message::text(Role::User, "post"),
    };
    let (post_result, _bg) = mgr
        .invoke_named::<CmfHook>(
            "cmf.tool_post_invoke",
            post_payload,
            Extensions::default(),
            None,
        )
        .await;
    assert!(
        !post_result.continue_processing,
        "multi's post-deny handler should fire even with a second \
         cdylib also loaded",
    );
    let violation = post_result
        .violation
        .expect("deny should carry a violation");
    assert_eq!(violation.code, "test.multi_handler.post_deny");
}
