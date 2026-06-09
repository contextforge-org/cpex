// Location: ./crates/cpex-core/src/hooks/macros.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// define_hook! macro.
//
// Generates a HookTypeDef marker struct and trait implementation
// from a single declaration. This is the primary way to define new
// hooks — both built-in (CMF, tool, prompt) and custom (rate
// limiting, deployment gates, federation sync).
//
// Plugins implement the generic HookHandler<H> trait (from
// trait_def.rs) for the generated marker struct. The handler
// receives a borrowed payload and returns the hook's result type.

/// Generates a hook type definition and marker struct.
///
/// # Usage
///
/// ```rust,ignore
/// define_hook! {
///     /// Doc comment for the hook.
///     MyHook, "my_hook" => {
///         payload: MyPayload,
///         result: PluginResult<MyPayload>,
///     }
/// }
/// ```
///
/// This generates a marker struct `MyHook` implementing `HookTypeDef`.
/// Plugins handle it by implementing `HookHandler<MyHook>`.
///
/// # CMF Pattern (one handler, multiple hook names)
///
/// For CMF hooks where one handler covers multiple hook names:
///
/// ```rust,ignore
/// define_hook! {
///     /// CMF message evaluation hook.
///     CmfHook, "cmf" => {
///         payload: MessagePayload,
///         result: PluginResult<MessagePayload>,
///     }
/// }
///
/// // Register the same handler for multiple names:
/// // manager.register_handler_for_names::<CmfHook, _>(plugin, config, &[
/// //     "cmf.tool_pre_invoke", "cmf.llm_input", ...
/// // ]);
/// ```
#[macro_export]
macro_rules! define_hook {
    (
        $(#[$meta:meta])*
        $name:ident, $hook_name:literal => {
            payload: $payload:ty,
            result: $result:ty $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $crate::hooks::trait_def::HookTypeDef for $name {
            type Payload = $payload;
            type Result = $result;
            const NAME: &'static str = $hook_name;
        }
    };
}
