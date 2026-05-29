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
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub policy: PolicyConfig,
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
pub struct FilesystemRule {
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    pub permission: String,
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
        .into_iter()
        .find(|plugin| plugin.name == plugin_name)
        .map(|plugin| plugin.sandbox)
        .with_context(|| format!("plugin '{}' not found in policy config", plugin_name))
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

