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
    cmf::{Message, MessagePayload, constants::HOOK_CMF_TOOL_PRE_INVOKE, enums::Role},
    hooks::payload::Extensions,
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

fn worker_script_path() -> PathBuf {
    repo_root()
        .join("cpex")
        .join("framework")
        .join("isolated")
        .join("worker.py")
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
// To run this test, the cpex-test-plugin must be installed via:
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

    let factory = IsolatedPythonPluginAdapterFactory::new(HookPayloadRegistry::default())
        .with_worker_script(worker_script_path());

    let mgr = Arc::new(PluginManager::default());
    mgr.register_factory(KIND, Box::new(factory));
    mgr.load_config_file(&config_path)
        .expect("failed to load plugins/config.yaml");

    mgr.initialize().await.expect("initialize failed");

    let payload = MessagePayload {
        message: Message::text(Role::User, "test invocation"),
    };

    let (result, _bg) = mgr
        .invoke_by_name(
            HOOK_CMF_TOOL_PRE_INVOKE,
            Box::new(payload),
            Extensions::default(),
            None,
        )
        .await;

    assert!(
        result.continue_processing,
        "cpex-test-plugin tool_pre_invoke should allow: violation={:?}",
        result.violation
    );

    mgr.shutdown().await;
}
