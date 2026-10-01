// Location: ./crates/cpex-wasm-plugin/src/examples/resource_sandbox_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// Test plugin for resource limit enforcement.
// Reads the "resource_sandbox_demo_mode" arg from the first ToolCall and exercises
// the corresponding limit so the host can verify it traps correctly.
//
// Modes (passed as tool call argument "mode"):
//   "burn_fuel"    — tight loop consuming instructions until fuel is exhausted
//   "infinite_loop" — spins forever until the epoch deadline fires
//   "alloc_memory" — allocates 512 MB of heap in chunks until OOM


use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::PluginError;
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct ResourceSandboxDemoPlugin;

impl Default for ResourceSandboxDemoPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for ResourceSandboxDemoPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "resource-sandbox-demo".to_string(),
            kind: "wasm://resource-sandbox-demo.wasm".to_string(),
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

fn extract_mode(payload: &MessagePayload) -> String {
    payload
        .message
        .content
        .iter()
        .find_map(|part| {
            if let ContentPart::ToolCall { content } = part {
                content.arguments.get("mode").and_then(|v| v.as_str()).map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

impl HookHandler<CmfHook> for ResourceSandboxDemoPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        _ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        let mode = extract_mode(payload);
        cpex_log!(info, "resource-sandbox-demo mode: {}", mode);

        match mode.as_str() {
            "burn_fuel" => {
                // Tight arithmetic loop — burns through fuel quickly.
                // Will never finish if fuel limit is generous; with a tiny
                // limit (e.g. max_fuel: 10000) this traps almost immediately.
                let mut x: u64 = 1;
                loop {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    if x == 0 { break; } // unreachable in practice
                }
                PluginResult::allow()
            }
            "infinite_loop" => {
                // Spins forever — relies on the epoch deadline to interrupt.
                let mut i: u64 = 0;
                loop {
                    i = i.wrapping_add(1);
                    if i == 0 { break; } // unreachable in practice
                }
                PluginResult::allow()
            }
            "alloc_memory" => {
                // Allocates 1 MB chunks until OOM trap fires.
                let mut blobs: Vec<Vec<u8>> = Vec::new();
                loop {
                    blobs.push(vec![0u8; 1024 * 1024]);
                }
            }
            _ => {
                cpex_log!(warn, "unknown resource-sandbox-demo mode '{}' — returning allow", mode);
                PluginResult::allow()
            }
        }
    }
}
