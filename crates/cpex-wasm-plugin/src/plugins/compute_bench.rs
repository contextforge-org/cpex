// Location: ./crates/cpex-wasm-plugin/src/plugins/compute_bench.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// ComputeBenchPlugin — WASM plugin that performs real computation.
//
// Used for benchmarking WASM vs native performance on identical workloads:
// JSON parsing, string manipulation, and hash computation. The native
// benchmark does the exact same operations so the comparison isolates
// the runtime difference (not the workload difference).

use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

pub struct ComputeBenchPlugin;

impl Default for ComputeBenchPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for ComputeBenchPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "compute-bench".to_string(),
            kind: "wasm://compute-bench.wasm".to_string(),
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

impl HookHandler<CmfHook> for ComputeBenchPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // 1. JSON parsing — serialize tool call arguments to a string
        let args_json = payload
            .message
            .get_tool_calls()
            .first()
            .map(|tc| serde_json::to_string(&tc.arguments).unwrap_or_default())
            .unwrap_or_default();

        // 2. String manipulation — build a summary from payload + extensions
        let mut summary = String::with_capacity(256);
        summary.push_str("tool=");
        summary.push_str(
            payload
                .message
                .get_tool_calls()
                .first()
                .map(|tc| tc.name.as_str())
                .unwrap_or("?"),
        );
        if let Some(ref sec) = extensions.security {
            for label in sec.labels.iter() {
                summary.push_str(",label=");
                summary.push_str(label);
            }
        }
        if let Some(ref http) = extensions.http {
            if let Some(req_id) = http.get_header("X-Request-ID") {
                summary.push_str(",req_id=");
                summary.push_str(req_id);
            }
        }

        // 3. Hash computation — simple FNV-like hash over the JSON bytes
        let hash: u64 = args_json
            .bytes()
            .fold(14695981039346656037u64, |acc, b| {
                acc.wrapping_mul(1099511628211).wrapping_add(b as u64)
            });

        // 4. Store computed results in context (exercises context write path)
        ctx.set_local("hash", serde_json::json!(hash));
        ctx.set_local("summary_len", serde_json::json!(summary.len()));

        PluginResult::allow()
    }
}
