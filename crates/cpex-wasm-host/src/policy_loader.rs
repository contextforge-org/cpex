use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use serde::Deserialize;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder};
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpHooks, default_send_request};
use wasmtime_wasi_http::WasiHttpCtx;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub sandbox_policy: Option<SandboxPolicy>,
    #[serde(flatten)]
    _extra: serde_yaml::Value,
}

/// Raw sandbox policy as defined in config YAML.
/// When this is `None` on a plugin, deny-by-default applies:
/// no filesystem, no network, no env vars are granted.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct SandboxPolicy {
    #[serde(default)]
    pub allowed_filesystem: Vec<FilesystemRule>,
    #[serde(default)]
    pub allowed_network: Vec<String>,
    #[serde(default)]
    pub allowed_env: Vec<String>,
    #[serde(default)]
    pub resources: ResourceLimits,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub resources: ResourceLimits,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub allowed_filesystem: Vec<FilesystemRule>,
    #[serde(default)]
    pub allowed_network: Vec<String>,
    #[serde(default)]
    pub allowed_env: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct ResourceLimits {
    #[serde(default)]
    pub max_memory_bytes: Option<usize>,
    #[serde(default)]
    pub max_fuel: Option<u64>,
    #[serde(default)]
    pub max_execution_time_ms: Option<u64>,
    #[serde(default)]
    pub max_instances: Option<usize>,
    #[serde(default)]
    pub max_tables: Option<usize>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: None,
            max_fuel: None,
            max_execution_time_ms: None,
            max_instances: None,
            max_tables: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct FilesystemRule {
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    pub permission: String,
}

impl SandboxConfig {
    /// Build a `SandboxConfig` from an optional `SandboxPolicy`.
    /// If the policy is `None`, returns a deny-by-default config
    /// (no filesystem, no network, no env vars).
    pub fn from_policy(policy: Option<&SandboxPolicy>) -> Self {
        match policy {
            None => Self::default(),
            Some(sp) => Self {
                version: "wasm-p2".to_string(),
                policy: PolicyConfig {
                    allowed_filesystem: sp.allowed_filesystem.clone(),
                    allowed_network: sp.allowed_network.clone(),
                    allowed_env: sp.allowed_env.clone(),
                },
                resources: sp.resources.clone(),
            },
        }
    }
}

impl PluginConfig {
    /// Returns the resolved `SandboxConfig` for this plugin.
    /// If `sandbox_policy` is absent, deny-by-default is applied.
    pub fn sandbox_config(&self) -> SandboxConfig {
        SandboxConfig::from_policy(self.sandbox_policy.as_ref())
    }

    /// Extract the wasm filename from the `kind` field.
    /// Expected format: "wasm/<filename>.wasm"
    /// Returns `None` if kind is absent or doesn't start with "wasm/".
    pub fn wasm_filename(&self) -> Option<&str> {
        self.kind.as_deref().and_then(|k| k.strip_prefix("wasm/"))
    }
}

pub fn load_plugin_sandbox_config(
    path: impl AsRef<Path>,
    plugin_name: &str,
) -> Result<SandboxConfig> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy config from {}", path.display()))?;
    let config: ConfigFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse YAML policy config from {}", path.display()))?;

    config
        .plugins
        .iter()
        .find(|plugin| plugin.name == plugin_name)
        .map(|plugin| plugin.sandbox_config())
        .with_context(|| format!("plugin '{}' not found in policy config", plugin_name))
}

pub fn load_all_plugins_config(path: impl AsRef<Path>) -> Result<Vec<PluginConfig>> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config from {}", path.display()))?;
    let config: ConfigFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse YAML config from {}", path.display()))?;
    Ok(config.plugins)
}

pub struct PluginWasiContext {
    pub wasi_ctx: WasiCtx,
    pub http_ctx: WasiHttpCtx,
    pub allowed_hosts: Arc<Vec<String>>,
}

pub fn build_wasi_context(sandbox: &SandboxConfig) -> Result<PluginWasiContext> {
    let mut builder = WasiCtxBuilder::new();

    // Filesystem: preopen directories/files based on policy
    for rule in &sandbox.policy.allowed_filesystem {
        let (dir_perms, file_perms) = match rule.permission.as_str() {
            "read" => (DirPerms::READ, FilePerms::READ),
            "write" | "mutate" => (DirPerms::READ | DirPerms::MUTATE, FilePerms::READ | FilePerms::WRITE),
            other => anyhow::bail!("unknown filesystem permission: {}", other),
        };

        if let Some(dir) = &rule.dir {
            builder
                .preopened_dir(dir, dir, dir_perms, file_perms)
                .map_err(|e| anyhow::anyhow!("failed to preopen dir '{}': {}", dir, e))?;
        } else if let Some(file) = &rule.file {
            let parent = Path::new(file)
                .parent()
                .with_context(|| format!("file '{}' has no parent directory", file))?;
            builder
                .preopened_dir(parent, parent.to_string_lossy().as_ref(), dir_perms, file_perms)
                .map_err(|e| anyhow::anyhow!("failed to preopen parent dir for file '{}': {}", file, e))?;
        }
    }

    // Environment: pass only allowed env vars from host
    for key in &sandbox.policy.allowed_env {
        if let Ok(val) = std::env::var(key) {
            builder.env(key, &val);
        }
    }

    builder.inherit_stdio();

    let wasi_ctx = builder.build();

    // HTTP: wasi:http context for outgoing requests
    // The allowed_hosts list is used at request-send time to gate outgoing HTTP
    let http_ctx = WasiHttpCtx::new();
    let allowed_hosts = Arc::new(sandbox.policy.allowed_network.clone());

    Ok(PluginWasiContext {
        wasi_ctx,
        http_ctx,
        allowed_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_with_sandbox_policy() {
        let yaml = r#"
plugins:
  - name: identity-checker
    kind: wasm/identity_checker.wasm
    hooks: [cmf.tool_pre_invoke]
    mode: sequential
    priority: 10
    on_error: fail
    capabilities:
      - read_labels
    sandbox_policy:
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

  - name: audit-logger
    kind: wasm/audit_logger.wasm
    hooks: [cmf.tool_post_invoke]
    mode: audit
    priority: 100
    on_error: ignore
    capabilities:
      - read_headers
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.plugins.len(), 2);

        // identity-checker: has sandbox_policy → capabilities granted
        let ic = &config.plugins[0];
        assert_eq!(ic.name, "identity-checker");
        assert_eq!(ic.wasm_filename(), Some("identity_checker.wasm"));
        let sandbox = ic.sandbox_config();
        assert_eq!(sandbox.policy.allowed_network, vec!["httpbin.org"]);
        assert_eq!(sandbox.policy.allowed_env, vec!["API_KEY"]);
        assert_eq!(sandbox.policy.allowed_filesystem.len(), 1);
        assert_eq!(sandbox.resources.max_memory_bytes, Some(10485760));
        assert_eq!(sandbox.resources.max_fuel, Some(1000000000));

        // audit-logger: no sandbox_policy → deny-by-default
        let al = &config.plugins[1];
        assert_eq!(al.name, "audit-logger");
        assert_eq!(al.wasm_filename(), Some("audit_logger.wasm"));
        let sandbox = al.sandbox_config();
        assert!(sandbox.policy.allowed_network.is_empty());
        assert!(sandbox.policy.allowed_env.is_empty());
        assert!(sandbox.policy.allowed_filesystem.is_empty());
        assert!(sandbox.resources.max_memory_bytes.is_none());
        assert!(sandbox.resources.max_fuel.is_none());
    }

    #[test]
    fn test_parse_real_config_file() {
        let sandbox = load_plugin_sandbox_config("config/config.yaml", "identity-checker").unwrap();
        assert_eq!(sandbox.policy.allowed_network, vec!["httpbin.org"]);
        assert_eq!(sandbox.policy.allowed_env, vec!["PLUGIN_API_KEY"]);
        assert_eq!(sandbox.resources.max_memory_bytes, Some(10485760));

        // audit-logger has no sandbox_policy → deny-by-default
        let sandbox = load_plugin_sandbox_config("config/config.yaml", "audit-logger").unwrap();
        assert!(sandbox.policy.allowed_network.is_empty());
        assert!(sandbox.policy.allowed_env.is_empty());
        assert!(sandbox.policy.allowed_filesystem.is_empty());
    }

    #[test]
    fn test_non_wasm_plugin_has_no_wasm_filename() {
        let yaml = r#"
plugins:
  - name: native-plugin
    kind: builtin/native-thing
"#;
        let config: ConfigFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.plugins[0].wasm_filename(), None);
    }
}

pub struct PolicyHttpHooks {
    pub allowed_hosts: Arc<Vec<String>>,
}

impl WasiHttpHooks for PolicyHttpHooks {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        let authority = request
            .uri()
            .authority()
            .map(|a| a.host().to_string())
            .unwrap_or_default();

        let is_allowed = self.allowed_hosts.iter().any(|allowed| {
            authority == *allowed || authority.ends_with(&format!(".{}", allowed))
        });

        if !is_allowed {
            return Err(ErrorCode::HttpRequestDenied.into());
        }

        Ok(default_send_request(request, config))
    }
}
