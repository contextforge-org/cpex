use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::guarded::Guarded;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct HeaderInjectorPlugin;

impl Default for HeaderInjectorPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for HeaderInjectorPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "header-injector".to_string(),
            kind: "wasm://header-injector.wasm".to_string(),
            hooks: vec!["cmf.tool_pre_invoke".to_string()],
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

impl HookHandler<CmfHook> for HeaderInjectorPlugin {
    async fn handle(
        &self,
        _payload: &MessagePayload,
        extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        cpex_log!(debug, "processing hook, http_headers={}",
            extensions.http.as_ref().map(|h| h.request_headers.len()).unwrap_or(0));

        let mut modified = extensions.cow_copy();

        if let Some(ref mut sec) = modified.security {
            sec.add_label("PROCESSED");
        }

        let mut http = extensions
            .http
            .as_ref()
            .map(|h| (**h).clone())
            .unwrap_or_default();
        http.set_header("X-Processed-By", "header-injector");
        modified.http = Some(Guarded::new(http));

        cpex_log!(info, "injected header 'X-Processed-By' and label 'PROCESSED'");

        PluginResult::modify_extensions(modified)
    }
}
