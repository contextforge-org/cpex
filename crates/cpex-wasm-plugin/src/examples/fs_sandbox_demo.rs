// Location: ./crates/cpex-wasm-plugin/src/examples/fs_sandbox_demo.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// FsSandboxDemoPlugin — demonstrates WASI filesystem sandbox enforcement.
//
// Reads two arguments from the ToolCall payload:
//   "operation" — one of: read, write, create_dir, list_dir, delete
//   "path"      — target path to operate on (relative to the preopened dir)
//
// Attempts the operation using std::fs. If WASI denies it (the operation
// exceeds the policy for that preopened dir), the error becomes a deny
// violation. If it succeeds, the plugin allows with the result in ctx.


use async_trait::async_trait;

use cpex_core::cmf::{CmfHook, ContentPart, MessagePayload};
use cpex_core::context::PluginContext;
use cpex_core::error::{PluginError, PluginViolation};
use cpex_core::extensions::container::Extensions;
use cpex_core::hooks::trait_def::{HookHandler, PluginResult};
use cpex_core::plugin::{Plugin, PluginConfig};

use crate::cpex_log;

pub struct FsSandboxDemoPlugin;

impl Default for FsSandboxDemoPlugin {
    fn default() -> Self {
        Self
    }
}

static PLUGIN_CONFIG: std::sync::OnceLock<PluginConfig> = std::sync::OnceLock::new();

#[async_trait]
impl Plugin for FsSandboxDemoPlugin {
    fn config(&self) -> &PluginConfig {
        PLUGIN_CONFIG.get_or_init(|| PluginConfig {
            name: "fs-sandbox-demo".to_string(),
            kind: "wasm://fs-sandbox-demo.wasm".to_string(),
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

impl HookHandler<CmfHook> for FsSandboxDemoPlugin {
    async fn handle(
        &self,
        payload: &MessagePayload,
        _extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> PluginResult<MessagePayload> {
        // Extract operation and path from the first ToolCall in the message.
        let (operation, path) = match extract_args(payload) {
            Some(args) => args,
            None => {
                cpex_log!(warn, "[fs-sandbox-demo] no tool call with operation+path found — allow");
                return PluginResult::allow();
            }
        };

        cpex_log!(info, "[fs-sandbox-demo] operation='{}' path='{}'", operation, path);

        let result = match operation.as_str() {
            "read" => attempt_read(&path),
            "write" => attempt_write(&path),
            "create_dir" => attempt_create_dir(&path),
            "list_dir" => attempt_list_dir(&path),
            "delete" => attempt_delete(&path),
            other => {
                return PluginResult::deny(PluginViolation::new(
                    "unknown_operation",
                    &format!(
                        "unknown operation '{}'; valid values: read, write, create_dir, list_dir, delete",
                        other
                    ),
                ));
            }
        };

        match result {
            Ok(detail) => {
                cpex_log!(info, "[fs-sandbox-demo] ALLOW: {} on '{}' — {}", operation, path, detail);
                ctx.set_local("fs_operation", serde_json::json!(operation));
                ctx.set_local("fs_path", serde_json::json!(path));
                ctx.set_local("fs_result", serde_json::json!("allowed"));
                ctx.set_local("fs_detail", serde_json::json!(detail));
                PluginResult::allow()
            }
            Err(e) => {
                cpex_log!(warn, "[fs-sandbox-demo] DENY: {} on '{}' — {}", operation, path, e);
                ctx.set_local("fs_operation", serde_json::json!(operation));
                ctx.set_local("fs_path", serde_json::json!(path));
                ctx.set_local("fs_result", serde_json::json!("denied"));
                ctx.set_local("fs_error", serde_json::json!(e.to_string()));
                PluginResult::deny(PluginViolation::new(
                    "fs_access_denied",
                    &format!("filesystem operation '{}' on '{}' denied by sandbox: {}", operation, path, e),
                ))
            }
        }
    }
}

fn extract_args(payload: &MessagePayload) -> Option<(String, String)> {
    for part in &payload.message.content {
        if let ContentPart::ToolCall { content: tc } = part {
            let operation = tc.arguments.get("operation")?.as_str()?.to_string();
            let path = tc.arguments.get("path")?.as_str()?.to_string();
            return Some((operation, path));
        }
    }
    None
}

fn attempt_read(path: &str) -> Result<String, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(format!("read {} bytes", content.len()))
}

fn attempt_write(path: &str) -> Result<String, std::io::Error> {
    std::fs::write(path, b"fs-sandbox-demo probe\n")?;
    Ok("wrote 22 bytes".to_string())
}

fn attempt_create_dir(path: &str) -> Result<String, std::io::Error> {
    std::fs::create_dir_all(path)?;
    Ok(format!("created directory '{}'", path))
}

fn attempt_list_dir(path: &str) -> Result<String, std::io::Error> {
    let entries: Vec<String> = std::fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    Ok(format!("listed {} entries: {:?}", entries.len(), entries))
}

fn attempt_delete(path: &str) -> Result<String, std::io::Error> {
    let meta = std::fs::metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(format!("deleted '{}'", path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::cmf::{ContentPart, Message, Role, ToolCall};
    use cpex_core::cmf::constants::SCHEMA_VERSION;
    use cpex_core::hooks::trait_def::HookHandler;
    use std::collections::HashMap;

    fn make_payload(operation: &str, path: &str) -> MessagePayload {
        let mut arguments = HashMap::new();
        arguments.insert("operation".to_string(), serde_json::json!(operation));
        arguments.insert("path".to_string(), serde_json::json!(path));
        MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![ContentPart::ToolCall {
                    content: ToolCall {
                        tool_call_id: "tc_demo".into(),
                        name: "fs_sandbox_demo".into(),
                        arguments,
                        namespace: None,
                    },
                }],
                channel: None,
            },
        }
    }

    #[tokio::test]
    async fn test_read_existing_file_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let plugin = FsSandboxDemoPlugin;
        let payload = make_payload("read", file_path.to_str().unwrap());
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <FsSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(result.continue_processing, "expected ALLOW");
        assert_eq!(ctx.get_local("fs_result").unwrap(), "allowed");
    }

    #[tokio::test]
    async fn test_read_nonexistent_file_is_denied() {
        let plugin = FsSandboxDemoPlugin;
        let payload = make_payload("read", "/nonexistent_xyz/no_such_file.txt");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <FsSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(!result.continue_processing, "expected DENY");
        assert_eq!(result.violation.as_ref().unwrap().code, "fs_access_denied");
        assert_eq!(ctx.get_local("fs_result").unwrap(), "denied");
    }

    #[tokio::test]
    async fn test_write_to_allowed_path_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("output.txt");

        let plugin = FsSandboxDemoPlugin;
        let payload = make_payload("write", file_path.to_str().unwrap());
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <FsSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(result.continue_processing, "expected ALLOW");
        assert_eq!(ctx.get_local("fs_result").unwrap(), "allowed");
    }

    #[tokio::test]
    async fn test_list_dir_allowed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "").unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();

        let plugin = FsSandboxDemoPlugin;
        let payload = make_payload("list_dir", dir.path().to_str().unwrap());
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <FsSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(result.continue_processing, "expected ALLOW");
        assert_eq!(ctx.get_local("fs_result").unwrap(), "allowed");
    }

    #[tokio::test]
    async fn test_unknown_operation_is_denied() {
        let plugin = FsSandboxDemoPlugin;
        let payload = make_payload("execute", "/tmp/something");
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <FsSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(!result.continue_processing, "expected DENY");
        assert_eq!(result.violation.as_ref().unwrap().code, "unknown_operation");
    }

    #[tokio::test]
    async fn test_missing_args_passes_through() {
        let payload = MessagePayload {
            message: Message {
                schema_version: SCHEMA_VERSION.into(),
                role: Role::Assistant,
                content: vec![],
                channel: None,
            },
        };
        let plugin = FsSandboxDemoPlugin;
        let ext = Extensions::default();
        let mut ctx = PluginContext::default();

        let result: PluginResult<MessagePayload> =
            <FsSandboxDemoPlugin as HookHandler<CmfHook>>::handle(
                &plugin, &payload, &ext, &mut ctx,
            )
            .await;

        assert!(result.continue_processing, "expected ALLOW — no args to act on");
    }
}
