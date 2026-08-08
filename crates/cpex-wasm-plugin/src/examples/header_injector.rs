// Location: ./crates/cpex-wasm-plugin/src/examples/header_injector.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya


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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::cmf::{CmfHook, ContentPart, Message, MessagePayload, Role, ToolCall};
    use cpex_core::context::PluginContext;
    use cpex_core::extensions::container::Extensions;
    use cpex_core::extensions::http::HttpExtension;
    use cpex_core::extensions::security::SecurityExtension;
    use cpex_core::hooks::trait_def::{HookHandler, PluginResult};

    use super::HeaderInjectorPlugin;

    fn tool_call_payload(name: &str) -> MessagePayload {
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: format!("tc_{}", name),
                        name: name.into(),
                        arguments: Default::default(),
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    #[tokio::test]
    async fn test_injects_header_and_label() {
        let mut sec = SecurityExtension::default();
        sec.add_label("PII");
        let mut http = HttpExtension::default();
        http.set_header("Authorization", "Bearer token");
        let ext = Extensions {
            security: Some(Arc::new(sec)),
            http: Some(Arc::new(http)),
            ..Default::default()
        };
        let payload = tool_call_payload("fetch-data");
        let mut ctx = PluginContext::default();
        let result: PluginResult<_> =
            <HeaderInjectorPlugin as HookHandler<CmfHook>>::handle(
                &HeaderInjectorPlugin, &payload, &ext, &mut ctx,
            ).await;
        assert!(result.continue_processing, "expected ALLOW");
        assert!(result.modified_extensions.is_some(), "expected modified extensions");
        let modified = result.modified_extensions.as_ref().unwrap();
        assert!(modified.security.as_ref().unwrap().has_label("PROCESSED"));
        assert!(modified.security.as_ref().unwrap().has_label("PII"));
        let h = modified.http.as_ref().unwrap().read();
        assert_eq!(
            h.request_headers.get("X-Processed-By").map(|s| s.as_str()),
            Some("header-injector")
        );
    }
}
