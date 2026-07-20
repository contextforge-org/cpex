// Location: ./crates/cpex-hosts-python/tests/config_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// End-to-end test: load PluginManager from plugins/config.yaml and invoke
// tool_pre_invoke on cpex-test-plugin.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use cpex_core::{
    hooks::payload::Extensions,
    hooks::tools::ToolPreInvokePayload,
    hooks::types::hook_names,
    manager::PluginManager,
};
use cpex_hosts_python::{HookPayloadRegistry, IsolatedPythonPluginAdapterFactory, KIND};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../cpex/crates/cpex-hosts-python
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Load config from plugins/config.yaml and invoke tool_pre_invoke on cpex-test-plugin.
//
// To run this test, the cpex-test-plugin must be installed at the project root and with the
// tests/fixtures/.venv as the active environment (run, "cargo test -p cpex-hosts-python --test isolated_e2e"
// to initialize the venv and then "source tests/fixtures/.venv/bin/activate" to activate it):
//
// cpex plugin --type test-pypi install "cpex-test-plugin@>=0.2.0"
//
// Then run the test using this command:
//
// cargo test -p cpex-hosts-python --test config_e2e -- --ignored
//
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn cpex_test_plugin_tool_pre_invoke() {
    if !python3_available() {
        eprintln!("SKIP: python3 not in PATH");
        return;
    }

    let root = repo_root();
    std::env::set_current_dir(&root).expect("failed to cd to repo root");
    let config_path = root.join("plugins").join("config.yaml");

    // The cpex-test-plugin's tool_pre_invoke touches this file (relative to the
    // worker cwd, which we set to the repo root). Remove any stale copy so the
    // assertion below proves *this* run executed the plugin's hook body.
    let touch_file = root.join(".tool_pre_invoke");
    let _ = std::fs::remove_file(&touch_file);

    // No worker_script override: worker.py is resolved from the installed
    // cpex framework inside the plugin's venv.
    let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default());

    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(KIND, Box::new(factory));
    mgr.load_config_file(&config_path)
        .expect("failed to load plugins/config.yaml");

    mgr.initialize().await.expect("initialize failed");

    // Legacy tool_pre_invoke carries a ToolPreInvokePayload (name + args), the
    // native payload shape the Python plugins expect. Use clean, non-PII args
    // so the PII filter allows the request.
    let payload = ToolPreInvokePayload {
        name: "test_tool".to_string(),
        args: Some(serde_json::json!({ "query": "hello world" })),
        headers: None,
    };

    let (result, _bg) = mgr
        .invoke_by_name(
            hook_names::TOOL_PRE_INVOKE,
            Box::new(payload),
            Extensions::default(),
            None,
        )
        .await;

    mgr.shutdown().await;

    // The plugins allow a clean (non-PII) request.
    assert!(
        result.continue_processing,
        "tool_pre_invoke should allow clean input: violation={:?}",
        result.violation
    );
    assert!(
        result.violation.is_none(),
        "no violation expected for clean input: {:?}",
        result.violation
    );

    // Prove the plugin's hook body actually ran (not a silent pass-through):
    // cpex-test-plugin.tool_pre_invoke writes this file at the worker cwd.
    let touched = touch_file.exists();
    let _ = std::fs::remove_file(&touch_file);
    assert!(
        touched,
        "expected cpex-test-plugin to create {:?} — the hook body did not run",
        touch_file
    );
}
