use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

pub struct AuditLoggerPlugin;

impl Default for AuditLoggerPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for AuditLoggerPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "audit-logger".to_string(),
            kind: "wasm://audit-logger.wasm".to_string(),
            hooks: vec![
                "cmf.tool_pre_invoke".to_string(),
                "cmf.tool_post_invoke".to_string(),
            ],
            ..Default::default()
        })
    }

    async fn initialize(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), Box<PluginError>> {
        Ok(())
    }
}

impl HookHandler<CmfHook> for AuditLoggerPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let is_result = payload.message.is_tool_result();
        let phase = if is_result { "POST" } else { "PRE" };

        let tool_name = if is_result {
            payload
                .message
                .get_tool_results()
                .first()
                .map(|tr| tr.tool_name.as_str())
                .unwrap_or("unknown")
        } else {
            payload
                .message
                .get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("unknown")
        };

        eprint!("[WASM:audit-logger] AUDIT[{}]: tool='{}' ", phase, tool_name);

        if let Some(ref security) = extensions.security {
            let labels: Vec<&String> = security.labels.iter().collect();
            eprint!("labels={:?} ", labels);
        }

        if let Some(ref http) = extensions.http {
            if let Some(req_id) = http.get_header("X-Request-ID") {
                eprint!("request_id='{}' ", req_id);
            }
        }

        if is_result {
            let is_error = payload
                .message
                .get_tool_results()
                .first()
                .map(|tr| tr.is_error)
                .unwrap_or(false);
            eprint!("error={} ", is_error);
        }

        eprintln!();
        PluginResult::allow()
    }
}
