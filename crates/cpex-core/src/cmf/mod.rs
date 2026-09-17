// Location: ./crates/cpex-core/src/cmf/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// ContextForge Message Format (CMF).
//
// Canonical message representation for interactions between users,
// agents, tools, and language models. All models mirror the Python
// CMF in cpex/framework/cmf/message.py.
//
// Extensions are NOT part of the Message — they are passed separately
// to handlers via the framework's Extensions type in hooks/payload.rs.
// This allows extensions to be shared across payload types and avoids
// copying the message when extensions change.
//
// # Hook Registration Patterns
//
// CMF supports two registration patterns for plugins:
//
// ## Pattern 1: One handler, multiple hook names (recommended)
//
// Use `CmfHook` as the hook type and register under multiple names.
// The plugin writes one handler that covers all CMF hooks. The host
// invokes via `invoke_by_name("cmf.tool_pre_invoke", ...)`.
//
// ```rust,ignore
// // Plugin implements one handler:
// impl HookHandler<CmfHook> for MyPlugin {
//     fn handle(&self, payload: &MessagePayload, ext: &Extensions, ctx: &mut PluginContext)
//         -> PluginResult<MessagePayload> { ... }
// }
//
// // Factory registers under multiple names:
// PluginInstance {
//     plugin: plugin.clone(),
//     handlers: vec![
//         ("cmf.tool_pre_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin.clone()))),
//         ("cmf.tool_post_invoke", Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(plugin))),
//     ],
// }
//
// // Host invokes via invoke_named — compile-time payload type safety
// // plus runtime hook name routing:
// mgr.invoke_named::<CmfHook>(
//     "cmf.tool_pre_invoke", payload, ext, None,
// ).await;
// ```
//
// `invoke_named::<CmfHook>(hook_name, ...)` gives you both:
// - **Compile-time**: payload must be `MessagePayload` (from `CmfHook::Payload`)
// - **Runtime**: dispatches to plugins registered under the specific hook name
//
// This is the recommended approach for CMF hooks. Alternatively, use
// `invoke_by_name(hook_name, boxed_payload, ...)` for fully dynamic
// dispatch (no compile-time payload check).
//
// ## Pattern 2: Individual hook types (optional)
//
// For hosts that want per-hook marker types, define separate hook
// types. Each maps to one hook name. The plugin must implement a
// handler per type (more boilerplate).
//
// ```rust,ignore
// define_hook! {
//     CmfToolPreInvoke, "cmf.tool_pre_invoke" => {
//         payload: MessagePayload,
//         result: PluginResult<MessagePayload>,
//     }
// }
//
// // Plugin implements per-hook handlers:
// impl HookHandler<CmfToolPreInvoke> for MyPlugin { ... }
// impl HookHandler<CmfToolPostInvoke> for MyPlugin { ... }
//
// // Host uses typed invoke:
// mgr.invoke::<CmfToolPreInvoke>(payload, ext, None).await;
// ```
//
// Both patterns use the same executor, registry, and capabilities.
// Pattern 1 with `invoke_named` is recommended — one handler impl,
// compile-time payload safety, and explicit hook name routing.
//
// Available CMF hook names (defined in hooks/types.rs):
//   cmf.tool_pre_invoke, cmf.tool_post_invoke,
//   cmf.llm_input, cmf.llm_output,
//   cmf.prompt_pre_fetch, cmf.prompt_post_fetch,
//   cmf.resource_pre_fetch, cmf.resource_post_fetch

pub mod constants;
pub mod content;
pub mod enums;
pub mod message;
pub mod view;

// Re-export key types at the cmf module level
pub use content::*;
pub use enums::*;
pub use message::{CmfHook, Message, MessagePayload};
pub use view::{MessageView, ViewAction, ViewKind};
