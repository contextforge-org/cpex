// Location: ./crates/cpex-wasm-host/src/policy_loader.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// PolicyLoader — defines the SandboxPolicy schema and builds a WASI context
// from it. The sandbox policy controls what host resources a WASM plugin can
// access: filesystem paths, network hosts, and environment variables.
// When no policy is provided (or all lists are empty), the plugin runs in a
// fully locked-down sandbox with no access to the outside world.

use std::{path::Path, sync::Arc};

use anyhow::Result;
use serde::Deserialize;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder};
use wasmtime_wasi_http::WasiHttpCtx;

/// Declarative sandbox policy deserialized from the plugin's config.sandbox_policy YAML key.
/// Controls filesystem, network, and environment access for the WASM plugin.
/// All fields default to empty/deny — a missing or empty policy means full lockdown.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct SandboxPolicy {
    /// Directories/files the plugin may access (empty = no filesystem access)
    #[serde(default)]
    pub allowed_filesystem: Vec<FilesystemRule>,
    /// Host names the plugin may make outbound HTTP requests to (empty = no network)
    #[serde(default)]
    pub allowed_network: Vec<String>,
    /// Environment variable names the plugin may read from the host (empty = no env access)
    #[serde(default)]
    pub allowed_env: Vec<String>,
    /// Resource limits (memory, fuel, execution time) for the WASM store
    #[serde(default)]
    pub resources: ResourceLimits,
}

/// Resource limits enforced on the WASM store.
/// None means unlimited (wasmtime defaults apply).
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct ResourceLimits {
    /// Maximum linear memory the plugin can allocate (bytes)
    #[serde(default)]
    pub max_memory_bytes: Option<usize>,
    /// Maximum instructions (fuel units) the plugin can execute across all invocations
    #[serde(default)]
    pub max_fuel: Option<u64>,
    /// Maximum wall-clock time for a single invocation (milliseconds)
    #[serde(default)]
    pub max_execution_time_ms: Option<u64>,
    /// Maximum number of WASM module instances
    #[serde(default)]
    pub max_instances: Option<usize>,
    /// Maximum number of WASM tables
    #[serde(default)]
    pub max_tables: Option<usize>,
}


/// A single filesystem access rule — grants access to a directory or file with a permission level.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct FilesystemRule {
    /// Directory path to preopen into the WASM sandbox
    #[serde(default)]
    pub dir: Option<String>,
    /// File path (its parent directory is preopened)
    #[serde(default)]
    pub file: Option<String>,
    /// Permission level: "read" or "write"/"mutate"
    pub permission: String,
}

/// The constructed WASI + HTTP context ready to be installed into a wasmtime Store.
pub struct PluginWasiContext {
    pub wasi_ctx: WasiCtx,
    pub http_ctx: WasiHttpCtx,
    /// Network allow-list passed to the NetworkPolicy hook for outbound HTTP filtering
    pub allowed_hosts: Arc<Vec<String>>,
}

/// Builds a WASI context from the given sandbox policy.
/// Preopens filesystem paths, injects allowed env vars, and captures the network allow-list.
/// If sandbox_policy is None, the context grants no host access (full lockdown).
pub fn build_wasi_context(sandbox_policy: Option<&SandboxPolicy>) -> Result<PluginWasiContext> {
    let mut builder = WasiCtxBuilder::new();

    if let Some(policy) = sandbox_policy {
        for rule in &policy.allowed_filesystem {
            let (dir_perms, file_perms) = match rule.permission.as_str() {
                "read" => (DirPerms::READ, FilePerms::READ),
                "write" | "mutate" => (
                    DirPerms::READ | DirPerms::MUTATE,
                    FilePerms::READ | FilePerms::WRITE,
                ),
                other => anyhow::bail!("unknown filesystem permission: {}", other),
            };

            if let Some(dir) = &rule.dir {
                builder
                    .preopened_dir(dir, dir, dir_perms, file_perms)
                    .map_err(|e| anyhow::anyhow!("failed to preopen dir '{}': {}", dir, e))?;
            } else if let Some(file) = &rule.file {
                let parent = Path::new(file)
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("file '{}' has no parent directory", file))?;
                builder
                    .preopened_dir(
                        parent,
                        parent.to_string_lossy().as_ref(),
                        dir_perms,
                        file_perms,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("failed to preopen parent dir for file '{}': {}", file, e)
                    })?;
            }
        }

        for key in &policy.allowed_env {
            if let Ok(val) = std::env::var(key) {
                builder.env(key, &val);
            }
        }
    }

    builder.inherit_stdio();

    let wasi_ctx = builder.build();
    let http_ctx = WasiHttpCtx::new();
    let allowed_hosts = Arc::new(
        sandbox_policy
            .map(|p| p.allowed_network.clone())
            .unwrap_or_default(),
    );

    Ok(PluginWasiContext {
        wasi_ctx,
        http_ctx,
        allowed_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_sandbox_policy_from_config_file() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.yaml");
        let raw = fs::read_to_string(&config_path).expect("failed to read config file");
        let config: serde_yaml::Value = serde_yaml::from_str(&raw).expect("failed to parse YAML");

        let sandbox_policy_value = config["plugins"][0]["config"]["sandbox_policy"].clone();
        let policy: SandboxPolicy = serde_yaml::from_value(sandbox_policy_value)
            .expect("failed to deserialize sandbox_policy");

        assert!(policy.allowed_filesystem.is_empty());
        assert!(policy.allowed_network.is_empty());
        assert!(policy.allowed_env.is_empty());
        assert_eq!(policy.resources.max_memory_bytes, Some(10485760));
        assert_eq!(policy.resources.max_fuel, Some(1000000000));
        assert_eq!(policy.resources.max_execution_time_ms, Some(5000));
        assert_eq!(policy.resources.max_instances, Some(10));
        assert_eq!(policy.resources.max_tables, Some(10));
    }

    #[test]
    fn test_deserialize_sandbox_policy() {
        let yaml = r#"
allowed_filesystem:
  - dir: /tmp/data
    permission: "read"
allowed_network:
  - "httpbin.org"
allowed_env:
  - "API_KEY"
resources:
  max_memory_bytes: 10485760
  max_fuel: 1000000000
"#;
        let policy: SandboxPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.allowed_network, vec!["httpbin.org"]);
        assert_eq!(policy.allowed_env, vec!["API_KEY"]);
        assert_eq!(policy.allowed_filesystem.len(), 1);
        assert_eq!(policy.resources.max_memory_bytes, Some(10485760));
        assert_eq!(policy.resources.max_fuel, Some(1000000000));
    }

    #[test]
    fn test_default_sandbox_policy_denies_all() {
        let policy = SandboxPolicy::default();
        assert!(policy.allowed_filesystem.is_empty());
        assert!(policy.allowed_network.is_empty());
        assert!(policy.allowed_env.is_empty());
        assert!(policy.resources.max_memory_bytes.is_none());
    }

    #[test]
    fn test_no_policy_builds_context_with_no_filesystem() {
        let ctx = build_wasi_context(None);
        assert!(ctx.is_ok(), "no-policy context should build successfully");
        let ctx = ctx.unwrap();
        assert!(ctx.allowed_hosts.is_empty());
    }

    #[test]
    fn test_empty_policy_builds_context_with_no_filesystem() {
        let policy = SandboxPolicy::default();
        let ctx = build_wasi_context(Some(&policy));
        assert!(ctx.is_ok());
        let ctx = ctx.unwrap();
        assert!(ctx.allowed_hosts.is_empty());
    }

    #[test]
    fn test_nonexistent_directory_fails_to_preopen() {
        let policy = SandboxPolicy {
            allowed_filesystem: vec![FilesystemRule {
                dir: Some("/nonexistent_path_that_does_not_exist_xyz".to_string()),
                file: None,
                permission: "read".to_string(),
            }],
            ..Default::default()
        };
        let result = build_wasi_context(Some(&policy));
        assert!(
            result.is_err(),
            "preopening a non-existent directory should fail"
        );
    }

    #[test]
    fn test_invalid_permission_rejected() {
        let policy = SandboxPolicy {
            allowed_filesystem: vec![FilesystemRule {
                dir: Some("/tmp".to_string()),
                file: None,
                permission: "execute".to_string(),
            }],
            ..Default::default()
        };
        let result = build_wasi_context(Some(&policy));
        assert!(
            result.is_err(),
            "invalid permission 'execute' should be rejected"
        );
    }

    #[test]
    fn test_network_allowlist_populated_from_policy() {
        let policy = SandboxPolicy {
            allowed_network: vec![
                "api.internal.svc".to_string(),
                "auth.example.com".to_string(),
            ],
            ..Default::default()
        };
        let ctx = build_wasi_context(Some(&policy)).unwrap();
        assert_eq!(ctx.allowed_hosts.len(), 2);
        assert!(ctx.allowed_hosts.contains(&"api.internal.svc".to_string()));
        assert!(ctx.allowed_hosts.contains(&"auth.example.com".to_string()));
    }
}
