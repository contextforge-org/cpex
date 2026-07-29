// Location: ./crates/cpex-wasm-plugin/src/examples/net_http_test.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Test plugin for network policy enforcement (port / scheme / method).
// Reads "url" and "method" arguments from the ToolCall and attempts a real
// WASI HTTP outgoing request. The host's WasiHttpHooks intercepts the call
// and either allows or denies it based on the NetworkRule in SandboxPolicy.
//
// The plugin writes "http_result" into local_state:
//   "allowed"  — request was sent (may or may not have received a response)
//   "denied"   — WasiHttpHooks returned HttpRequestDenied before the wire


use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;
use crate::wasi::http::outgoing_handler;
use crate::wasi::http::types::{
    Headers, Method, OutgoingRequest, RequestOptions, Scheme,
};

pub struct NetHttpTestPlugin;

impl Default for NetHttpTestPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for NetHttpTestPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "net-http-test".to_string(),
            kind: "wasm://net-http-test.wasm".to_string(),
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

fn extract_arg(payload: &MessagePayload, key: &str) -> Option<String> {
    payload.message.content.iter().find_map(|part| {
        if let ContentPart::ToolCall { content } = part {
            content.arguments.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
        } else {
            None
        }
    })
}

impl HookHandler<CmfHook> for NetHttpTestPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let url = extract_arg(payload, "url").unwrap_or_else(|| "https://example.com/".to_string());
        let method_str = extract_arg(payload, "method").unwrap_or_else(|| "GET".to_string());

        cpex_log!(info, "net-http-test: {} {}", method_str, url);

        // Parse scheme, authority, and path from the URL manually — no std URL parser in WASM.
        let (scheme, rest) = if let Some(s) = url.strip_prefix("https://") {
            (Scheme::Https, s)
        } else if let Some(s) = url.strip_prefix("http://") {
            (Scheme::Http, s)
        } else {
            ctx.set_local("http_result", serde_json::json!("bad_url"));
            return PluginResult::allow();
        };

        let (authority, path_and_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };

        let method = match method_str.to_uppercase().as_str() {
            "GET" => Method::Get,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "PATCH" => Method::Patch,
            other => Method::Other(other.to_string()),
        };

        let headers = Headers::new();
        let req = OutgoingRequest::new(headers);
        req.set_method(&method).ok();
        req.set_scheme(Some(&scheme)).ok();
        req.set_authority(Some(authority)).ok();
        req.set_path_with_query(Some(path_and_query)).ok();

        // send() calls WasiHttpHooks::send_request on the host — this is where
        // port/scheme/method enforcement happens.
        match outgoing_handler::handle(req, None::<RequestOptions>) {
            Ok(_future_response) => {
                ctx.set_local("http_result", serde_json::json!("allowed"));
                cpex_log!(info, "net-http-test: request allowed by host policy");
            }
            Err(e) => {
                let reason = format!("{:?}", e);
                ctx.set_local("http_result", serde_json::json!("denied"));
                ctx.set_local("http_error", serde_json::json!(reason));
                cpex_log!(info, "net-http-test: request denied — {}", reason);
            }
        }

        PluginResult::allow()
    }
}
