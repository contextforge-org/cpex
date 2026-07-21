// Location: ./crates/cpex-wasm-host/tests/test_policy_loader.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Integration tests for policy_loader.
// Validates that the sandbox policy in config/config.yaml deserializes correctly
// and matches the expected deny-all posture with resource limits.

use std::path::Path;

use cpex_wasm_host::policy_loader::SandboxPolicy;

/// Helper: reads config.yaml and extracts the sandbox_policy for a named plugin.
fn load_sandbox_policy_from_config(plugin_name: &str) -> SandboxPolicy {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.yaml");
    let raw = std::fs::read_to_string(&config_path).expect("failed to read config.yaml");
    let config: serde_yaml::Value = serde_yaml::from_str(&raw).expect("failed to parse YAML");

    let plugin = config["plugins"]
        .as_sequence()
        .expect("plugins should be a list")
        .iter()
        .find(|p| p["name"].as_str() == Some(plugin_name))
        .unwrap_or_else(|| panic!("plugin '{}' not found in config", plugin_name));

    let sandbox_value = plugin["config"]["sandbox_policy"].clone();
    serde_yaml::from_value(sandbox_value).expect("failed to deserialize sandbox_policy")
}

#[test]
fn config_file_is_valid_yaml() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.yaml");
    let raw = std::fs::read_to_string(&config_path).expect("failed to read config.yaml");
    let _: serde_yaml::Value = serde_yaml::from_str(&raw).expect("config.yaml is not valid YAML");
}

#[test]
fn config_has_plugins_list() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.yaml");
    let raw = std::fs::read_to_string(&config_path).expect("failed to read config.yaml");
    let config: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();

    let plugins = config["plugins"]
        .as_sequence()
        .expect("plugins should be a list");
    assert!(!plugins.is_empty(), "plugins list should not be empty");
}

#[test]
fn identity_checker_plugin_exists_with_correct_kind() {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.yaml");
    let raw = std::fs::read_to_string(&config_path).expect("failed to read config.yaml");
    let config: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();

    let plugin = config["plugins"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|p| p["name"].as_str() == Some("identity-checker"))
        .expect("identity-checker plugin not found");

    assert_eq!(plugin["kind"].as_str(), Some("wasm://plugin.wasm"));
}

#[test]
fn sandbox_policy_allowed_network_is_empty() {
    let policy = load_sandbox_policy_from_config("identity-checker");
    assert!(policy.allowed_network.is_empty());
}

#[test]
fn sandbox_policy_allowed_env_is_empty() {
    let policy = load_sandbox_policy_from_config("identity-checker");
    assert!(policy.allowed_env.is_empty());
}

#[test]
fn sandbox_policy_allowed_filesystem_is_empty() {
    let policy = load_sandbox_policy_from_config("identity-checker");
    assert!(policy.allowed_filesystem.is_empty());
}

#[test]
fn sandbox_policy_resource_limits() {
    let policy = load_sandbox_policy_from_config("identity-checker");

    assert_eq!(policy.resources.max_memory_bytes, Some(10_485_760));
    assert_eq!(policy.resources.max_fuel, Some(1_000_000_000));
    assert_eq!(policy.resources.max_execution_time_ms, Some(5000));
    assert_eq!(policy.resources.max_instances, Some(10));
    assert_eq!(policy.resources.max_tables, Some(10));
}

#[test]
fn sandbox_policy_deserializes_to_same_type_used_by_factory() {
    let policy = load_sandbox_policy_from_config("identity-checker");
    let json = serde_json::to_value(&policy).expect("SandboxPolicy should serialize to JSON");

    let roundtripped: SandboxPolicy =
        serde_json::from_value(json).expect("SandboxPolicy should roundtrip through JSON");

    assert_eq!(roundtripped.allowed_network, policy.allowed_network);
    assert_eq!(roundtripped.allowed_env, policy.allowed_env);
    assert_eq!(
        roundtripped.resources.max_memory_bytes,
        policy.resources.max_memory_bytes
    );
}
