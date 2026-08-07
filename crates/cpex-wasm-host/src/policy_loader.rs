// Location: ./crates/cpex-wasm-host/src/policy_loader.rs
// Copyright 2026
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

/// A single network access rule — grants outbound HTTP access to one host pattern
/// with optional constraints on port, scheme, and HTTP method.
///
/// | Field | Default | Meaning |
/// |-------|---------|---------|
/// | `host` | (required) | Exact hostname or `*.example.com` wildcard. Exact match only unless the pattern starts with `*.`. |
/// | `ports` | `[]` (any) | If non-empty, only the listed port numbers are allowed. Default port (80/443) is inferred from scheme when the URI has none. |
/// | `schemes` | `["https"]` | Allowed URI schemes. Default is HTTPS-only. Set `[http, https]` to allow both. |
/// | `methods` | `[]` (any) | If non-empty, only the listed HTTP methods are allowed (case-insensitive). |
///
/// Examples:
/// ```yaml
/// # HTTPS-only on port 443, any method (typical API)
/// - host: "api.example.com"
///
/// # Explicit constraints
/// - host: "*.internal.svc"
///   ports: [8080, 8443]
///   schemes: [http, https]
///   methods: [GET, POST]
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
pub struct NetworkRule {
    /// Hostname to match. Use `*.example.com` to match all subdomains of `example.com`.
    /// A plain `example.com` matches that host exactly — subdomains are not implicitly included.
    pub host: String,
    /// Allowed port numbers. Empty means any port is permitted.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Allowed URI schemes. Defaults to `["https"]` if omitted.
    #[serde(default = "default_schemes")]
    pub schemes: Vec<String>,
    /// Allowed HTTP methods (case-insensitive). Empty means any method is permitted.
    #[serde(default)]
    pub methods: Vec<String>,
}

fn default_schemes() -> Vec<String> {
    vec!["https".to_string()]
}

impl Default for NetworkRule {
    fn default() -> Self {
        Self {
            host: String::new(),
            ports: Vec::new(),
            schemes: default_schemes(),
            methods: Vec::new(),
        }
    }
}

/// Declarative sandbox policy deserialized from the plugin's config.sandbox_policy YAML key.
/// Controls filesystem, network, and environment access for the WASM plugin.
/// All fields default to empty/deny — a missing or empty policy means full lockdown.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct SandboxPolicy {
    /// Directories/files the plugin may access (empty = no filesystem access)
    #[serde(default)]
    pub allowed_filesystem: Vec<FilesystemRule>,
    /// Outbound HTTP rules. Each entry specifies a host pattern and optional
    /// constraints on port, scheme, and HTTP method. Empty = no network access.
    #[serde(default)]
    pub allowed_network: Vec<NetworkRule>,
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
    /// Permission level controlling what the plugin can do within this path.
    ///
    /// | Value | DirPerms | FilePerms | Description |
    /// |-------|----------|-----------|-------------|
    /// | `read-only` | READ | READ | List and read; no modifications |
    /// | `full-access` | READ+MUTATE | READ+WRITE | Full access within the preopen |
    /// | `drop-box` | MUTATE | WRITE | create_dir/delete only; file I/O denied (open_at requires DirPerms::READ) |
    /// | `fixed-mutable` | READ | READ+WRITE | Read files; FilePerms::WRITE has no effect — wasmtime's open_at requires DirPerms::MUTATE for any write regardless |
    /// | `list-only` | READ | (empty) | Enumerate filenames only; cannot open file contents |
    /// | `private-scratch` | MUTATE | READ+WRITE | Full file I/O within the preopen; list_dir denied (DirPerms::READ absent) |
    pub permission: String,
}

/// The constructed WASI + HTTP context ready to be installed into a wasmtime Store.
pub struct PluginWasiContext {
    pub wasi_ctx: WasiCtx,
    pub http_ctx: WasiHttpCtx,
    /// Network rules passed to the NetworkPolicy hook for outbound HTTP filtering
    pub allowed_hosts: Arc<Vec<NetworkRule>>,
}

/// Maps a permission string to the corresponding (DirPerms, FilePerms) flags.
/// Only the 6 named scenarios are accepted; unknown values are rejected.
pub fn resolve_permission(permission: &str) -> Result<(DirPerms, FilePerms)> {
    match permission {
        "read-only" => Ok((DirPerms::READ, FilePerms::READ)),
        "full-access" => Ok((
            DirPerms::READ | DirPerms::MUTATE,
            FilePerms::READ | FilePerms::WRITE,
        )),
        "drop-box" => Ok((DirPerms::MUTATE, FilePerms::WRITE)),
        "fixed-mutable" => Ok((DirPerms::READ, FilePerms::READ | FilePerms::WRITE)),
        "list-only" => Ok((DirPerms::READ, FilePerms::empty())),
        "private-scratch" => Ok((
            DirPerms::MUTATE,
            FilePerms::READ | FilePerms::WRITE,
        )),
        other => anyhow::bail!(
            "unknown filesystem permission: '{}'. Valid values: \
             read-only, full-access, drop-box, fixed-mutable, list-only, private-scratch",
            other
        ),
    }
}

/// Builds a WASI context from the given sandbox policy.
/// Preopens filesystem paths, injects allowed env vars, and captures the network allow-list.
/// If sandbox_policy is None, the context grants no host access (full lockdown).
pub fn build_wasi_context(sandbox_policy: Option<&SandboxPolicy>) -> Result<PluginWasiContext> {
    let mut builder = WasiCtxBuilder::new();

    if let Some(policy) = sandbox_policy {
        for rule in &policy.allowed_filesystem {
            let (dir_perms, file_perms) = resolve_permission(rule.permission.as_str())?;

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
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config_policy_test_fixture.yaml");
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
    permission: "read-only"
allowed_network:
  - host: "httpbin.org"
allowed_env:
  - "API_KEY"
resources:
  max_memory_bytes: 10485760
  max_fuel: 1000000000
"#;
        let policy: SandboxPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.allowed_network.len(), 1);
        assert_eq!(policy.allowed_network[0].host, "httpbin.org");
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
                permission: "read-only".to_string(),
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
                NetworkRule { host: "api.internal.svc".to_string(), ..Default::default() },
                NetworkRule { host: "auth.example.com".to_string(), ..Default::default() },
            ],
            ..Default::default()
        };
        let ctx = build_wasi_context(Some(&policy)).unwrap();
        assert_eq!(ctx.allowed_hosts.len(), 2);
        assert!(ctx.allowed_hosts.iter().any(|r| r.host == "api.internal.svc"));
        assert!(ctx.allowed_hosts.iter().any(|r| r.host == "auth.example.com"));
    }

    #[test]
    fn test_network_rule_default_scheme_is_https() {
        let rule = NetworkRule { host: "example.com".to_string(), ..Default::default() };
        assert_eq!(rule.schemes, vec!["https"]);
    }

    #[test]
    fn test_network_rule_empty_ports_means_any_port() {
        let rule = NetworkRule { host: "example.com".to_string(), ..Default::default() };
        assert!(rule.ports.is_empty());
    }

    #[test]
    fn test_network_rule_empty_methods_means_any_method() {
        let rule = NetworkRule { host: "example.com".to_string(), ..Default::default() };
        assert!(rule.methods.is_empty());
    }

    #[test]
    fn test_network_rule_wildcard_host_parses() {
        let yaml = r#"host: "*.example.com""#;
        let rule: NetworkRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.host, "*.example.com");
        assert_eq!(rule.schemes, vec!["https"]);
    }

    #[test]
    fn test_network_rule_full_deserialization() {
        let yaml = r#"
host: "*.internal.svc"
ports: [8080, 8443]
schemes: [http, https]
methods: [GET, POST]
"#;
        let rule: NetworkRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.host, "*.internal.svc");
        assert_eq!(rule.ports, vec![8080, 8443]);
        assert_eq!(rule.schemes, vec!["http", "https"]);
        assert_eq!(rule.methods, vec!["GET", "POST"]);
    }

    #[test]
    fn test_network_rule_schemes_override_default() {
        let yaml = r#"
host: "api.example.com"
schemes: [http, https]
"#;
        let rule: NetworkRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.schemes, vec!["http", "https"]);
    }

    #[test]
    fn test_resolve_permission_read_only() {
        let (d, f) = resolve_permission("read-only").unwrap();
        assert_eq!(d, DirPerms::READ);
        assert_eq!(f, FilePerms::READ);
    }

    #[test]
    fn test_resolve_permission_full_access() {
        let (d, f) = resolve_permission("full-access").unwrap();
        assert_eq!(d, DirPerms::READ | DirPerms::MUTATE);
        assert_eq!(f, FilePerms::READ | FilePerms::WRITE);
    }

    #[test]
    fn test_resolve_permission_drop_box() {
        let (d, f) = resolve_permission("drop-box").unwrap();
        assert_eq!(d, DirPerms::MUTATE);
        assert_eq!(f, FilePerms::WRITE);
    }

    #[test]
    fn test_resolve_permission_fixed_mutable() {
        let (d, f) = resolve_permission("fixed-mutable").unwrap();
        assert_eq!(d, DirPerms::READ);
        assert_eq!(f, FilePerms::READ | FilePerms::WRITE);
    }

    #[test]
    fn test_resolve_permission_list_only() {
        let (d, f) = resolve_permission("list-only").unwrap();
        assert_eq!(d, DirPerms::READ);
        assert_eq!(f, FilePerms::empty());
    }

    #[test]
    fn test_resolve_permission_private_scratch() {
        let (d, f) = resolve_permission("private-scratch").unwrap();
        assert_eq!(d, DirPerms::MUTATE);
        assert_eq!(f, FilePerms::READ | FilePerms::WRITE);
    }

    #[test]
    fn test_resolve_permission_unknown_rejected() {
        assert!(resolve_permission("execute").is_err());
        assert!(resolve_permission("admin").is_err());
        assert!(resolve_permission("read").is_err());
        assert!(resolve_permission("write").is_err());
        assert!(resolve_permission("mutate").is_err());
        assert!(resolve_permission("").is_err());
    }

    #[test]
    fn test_resolve_permission_error_lists_valid_values() {
        let err = resolve_permission("bogus").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("read-only"));
        assert!(msg.contains("full-access"));
        assert!(msg.contains("drop-box"));
        assert!(msg.contains("fixed-mutable"));
        assert!(msg.contains("list-only"));
        assert!(msg.contains("private-scratch"));
    }

    #[test]
    fn test_build_wasi_context_with_drop_box_permission() {
        let policy = SandboxPolicy {
            allowed_filesystem: vec![FilesystemRule {
                dir: Some("/tmp".to_string()),
                file: None,
                permission: "drop-box".to_string(),
            }],
            ..Default::default()
        };
        assert!(build_wasi_context(Some(&policy)).is_ok());
    }

    #[test]
    fn test_build_wasi_context_with_fixed_mutable_permission() {
        let policy = SandboxPolicy {
            allowed_filesystem: vec![FilesystemRule {
                dir: Some("/tmp".to_string()),
                file: None,
                permission: "fixed-mutable".to_string(),
            }],
            ..Default::default()
        };
        assert!(build_wasi_context(Some(&policy)).is_ok());
    }

    #[test]
    fn test_build_wasi_context_with_list_only_permission() {
        let policy = SandboxPolicy {
            allowed_filesystem: vec![FilesystemRule {
                dir: Some("/tmp".to_string()),
                file: None,
                permission: "list-only".to_string(),
            }],
            ..Default::default()
        };
        assert!(build_wasi_context(Some(&policy)).is_ok());
    }

    #[test]
    fn test_build_wasi_context_with_private_scratch_permission() {
        let policy = SandboxPolicy {
            allowed_filesystem: vec![FilesystemRule {
                dir: Some("/tmp".to_string()),
                file: None,
                permission: "private-scratch".to_string(),
            }],
            ..Default::default()
        };
        assert!(build_wasi_context(Some(&policy)).is_ok());
    }
}
