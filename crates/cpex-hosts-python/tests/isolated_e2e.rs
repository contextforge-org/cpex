// Location: ./crates/cpex-hosts-python/tests/isolated_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// End-to-end integration test: load a real Python plugin class through the
// Rust PluginManager using `kind: "isolated_venv"` config.
//
// Requirements: Python 3.11+ must be in PATH and cpex must be importable.
// Tests are skipped gracefully when Python is absent.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use cpex_core::{
    cmf::{constants::HOOK_CMF_TOOL_PRE_INVOKE, enums::Role, Message, MessagePayload},
    hooks::payload::Extensions,
    manager::PluginManager,
};
use cpex_hosts_python::{HookPayloadRegistry, IsolatedPythonPluginAdapterFactory, KIND};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn make_factory() -> IsolatedPythonPluginAdapterFactory {
    // No worker_script override: the adapter resolves worker.py from the
    // installed cpex framework inside each plugin's venv.
    IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default())
}

fn plugin_yaml(class_name: &str, hook: &str, on_error: &str, mode: &str) -> String {
    let fix = fixtures_dir();
    format!(
        r#"
plugins:
  - name: test-plugin
    kind: "{kind}"
    hooks: ["{hook}"]
    mode: {mode}
    priority: 10
    on_error: {on_error}
    config:
      class_name: "{class_name}"
      requirements_file: "{req}"
      plugin_dirs:
        - "{fix}"
      venv_path: "{venv}"
"#,
        kind = KIND,
        class_name = class_name,
        hook = hook,
        mode = mode,
        on_error = on_error,
        req = fix.join("requirements.txt").display(),
        fix = fix.display(),
        venv = fix.join(".venv").display(),
    )
}

fn cpex_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../cpex/crates/cpex-hosts-python
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Write a requirements.txt with the absolute cpex install path.
/// This avoids pip's inconsistent relative-path resolution inside `-r` files.
fn write_requirements_txt() {
    let req_path = fixtures_dir().join("requirements.txt");
    let _cpex = cpex_root();
    // TODO: replace this with cpex>=0.1.1,<0.2 when pr https://github.com/contextforge-org/cpex/pull/113 is merged into 0.1.x
    std::fs::write(
        &req_path,
        "git+https://github.com/contextforge-org/cpex.git@feat/python_plugin_compat_0.1.x",
    )
    .expect("failed to write requirements.txt");
}

fn tool_payload() -> MessagePayload {
    MessagePayload {
        message: Message::text(Role::User, "test message"),
    }
}

fn make_manager(class_name: &str, on_error: &str) -> Arc<PluginManager> {
    write_requirements_txt();
    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(KIND, Box::new(make_factory()));
    let yaml = plugin_yaml(class_name, HOOK_CMF_TOOL_PRE_INVOKE, on_error, "sequential");
    mgr.load_config_yaml(&yaml)
        .expect("load_config_yaml failed");
    mgr
}

// ---------------------------------------------------------------------------
// AC-8: Plugin loaded via `kind: "isolated_venv://echo_plugin.EchoPlugin"`
// and invoked successfully (allow result).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn echo_plugin_allow_result() {
    if !python3_available() {
        eprintln!("SKIP: python3 not in PATH");
        return;
    }

    let mgr = make_manager("echo_plugin.EchoPlugin", "fail");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(tool_payload()),
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "echo plugin should allow: violation={:?}",
        result.violation
    );

    mgr.shutdown().await;
}

// ---------------------------------------------------------------------------
// AC-9: Second invocation reuses the venv.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_invocation_reuses_venv() {
    if !python3_available() {
        eprintln!("SKIP: python3 not in PATH");
        return;
    }

    let fix = fixtures_dir();
    let venv_path = fix.join(".venv");

    let mgr = make_manager("echo_plugin.EchoPlugin", "fail");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(tool_payload()),
            Extensions::default(),
            None,
        )
        .await;
    assert!(result.continue_processing);

    assert!(venv_path.exists(), "venv should be created by initialize()");

    // Second manager pointing at same venv should reuse it.
    let mgr2 = make_manager("echo_plugin.EchoPlugin", "fail");
    mgr2.initialize().await.unwrap();
    let (result2, _bg2) = mgr2
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(tool_payload()),
            Extensions::default(),
            None,
        )
        .await;
    assert!(result2.continue_processing);

    mgr.shutdown().await;
    mgr2.shutdown().await;
}

// ---------------------------------------------------------------------------
// AC-5: Python exception → on_error:fail propagates error to caller.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_plugin_on_error_fail_stops_pipeline() {
    if !python3_available() {
        eprintln!("SKIP: python3 not in PATH");
        return;
    }

    let mgr = make_manager("echo_plugin.ErrorPlugin", "fail");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(tool_payload()),
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        !result.continue_processing || result.violation.is_some(),
        "error plugin with on_error:fail should stop processing or set violation"
    );

    mgr.shutdown().await;
}

// ---------------------------------------------------------------------------
// AC-6: Plugin without initialize/shutdown methods works without crashing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_lifecycle_plugin_works() {
    if !python3_available() {
        eprintln!("SKIP: python3 not in PATH");
        return;
    }

    let mgr = make_manager("echo_plugin.NoLifecyclePlugin", "fail");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(tool_payload()),
            Extensions::default(),
            None,
        )
        .await;
    assert!(result.continue_processing);

    mgr.shutdown().await;
}

// ---------------------------------------------------------------------------
// AC-10: manager.shutdown() terminates the worker process within 5s.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shutdown_terminates_worker_within_timeout() {
    if !python3_available() {
        eprintln!("SKIP: python3 not in PATH");
        return;
    }

    let mgr = make_manager("echo_plugin.EchoPlugin", "fail");
    mgr.initialize().await.unwrap();

    let (result, _bg) = mgr
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(tool_payload()),
            Extensions::default(),
            None,
        )
        .await;
    assert!(result.continue_processing);

    let start = std::time::Instant::now();
    mgr.shutdown().await;
    assert!(
        start.elapsed().as_secs() < 10,
        "shutdown took too long: {:?}",
        start.elapsed()
    );
}
