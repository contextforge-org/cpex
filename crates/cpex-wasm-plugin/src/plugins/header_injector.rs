use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::extensions::guarded::Guarded;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

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
        if let Some(ref http) = extensions.http {
            eprintln!(
                "[WASM:header-injector] HTTP visible: {} headers",
                http.request_headers.len()
            );
        }

        if let Some(ref security) = extensions.security {
            if security.subject.is_some() {
                eprintln!("[WASM:header-injector] WARNING: Subject visible (unexpected!)");
            } else {
                eprintln!("[WASM:header-injector] Subject: not visible (correct — no read_subject)");
            }
        }

        let mut modified = extensions.cow_copy();

        if let Some(ref mut sec) = modified.security {
            sec.add_label("PROCESSED");
            eprintln!("[WASM:header-injector] Added label 'PROCESSED'");
        }

        let mut http = extensions
            .http
            .as_ref()
            .map(|h| (**h).clone())
            .unwrap_or_default();
        http.set_header("X-Processed-By", "header-injector");
        modified.http = Some(Guarded::new(http));
        eprintln!("[WASM:header-injector] Injected header 'X-Processed-By'");

        PluginResult::modify_extensions(modified)
    }
}
