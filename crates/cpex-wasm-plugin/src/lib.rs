// Location: ./crates/cpex-wasm-plugin/src/lib.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// ============================================================================
// CPEX WASM Plugin SDK — lib.rs
// ============================================================================
//
// This file is the SDK glue that connects your plugin logic (src/plugin.rs) to
// the WASM component model. You should NOT need to edit this file.
//
// What this file does:
//
//   1. WIT BINDINGS (wit_bindgen::generate!)
//      Reads wit/world.wit at compile time and generates:
//      - Guest trait: the interface the host calls into
//      - export! macro: produces #[no_mangle] ABI entry points
//      - WIT types: HookPayload, HookResult, Extensions, PluginContext
//        (flat/serialized types for the WASM boundary — NOT cpex-core types)
//
//   2. PRELUDE (pub mod prelude)
//      Re-exports everything a plugin author needs in one import:
//        use crate::prelude::*;
//
//   3. CONVERSIONS (pub mod conversions)
//      Bridges WIT types ↔ cpex-core native types. Your plugin never touches
//      WIT types — the macro handles translation automatically.
//
//   4. register_wasm_plugin! MACRO
//      Generates the Guest impl that:
//        a. Receives WIT types from the host
//        b. Converts them to cpex-core native types
//        c. Routes to YOUR HookHandler::handle() method
//        d. Converts your PluginResult back to a WIT HookResult
//        e. Calls export!() to produce the WASM export symbol
//
//   5. PLUGIN REGISTRATION (bottom of this file)
//      Wires src/plugin.rs as the active plugin. When no demo feature flag is
//      set, your plugin is what gets compiled into the .wasm binary.
//
// Quickstart:
//   1. Edit src/plugin.rs
//   2. Run: make build
//   3. Output: target/wasm32-wasip2/release/cpex_wasm_plugin.wasm
//
// See src/examples/ for reference demo implementations.

pub mod conversions;
pub mod plugin;
pub mod examples;

// ---------------------------------------------------------------------------
// WIT bindings — generated from wit/world.wit
// ---------------------------------------------------------------------------

wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});

// ---------------------------------------------------------------------------
// Prelude — one import for everything a plugin author needs
// ---------------------------------------------------------------------------

/// Re-exports every type and macro a plugin author needs.
///
/// Add `use cpex_wasm_plugin::prelude::*;` to your plugin file and you have
/// everything: traits, payload types, context, extensions, and macros.
pub mod prelude {
    // Core traits
    pub use async_trait::async_trait;
    pub use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef, PluginResult};
    pub use cpex_core::plugin::{Plugin, PluginConfig};
    pub use cpex_core::context::PluginContext;
    pub use cpex_core::extensions::container::Extensions;
    pub use cpex_core::error::{PluginError, PluginViolation};

    // CMF hook + payload
    pub use cpex_core::cmf::{CmfHook, MessagePayload};

    // Identity hook + payload
    pub use cpex_core::identity::{IdentityHook, IdentityPayload};

    // Token delegation hook + payload
    pub use cpex_core::delegation::{TokenDelegateHook, DelegationPayload};

    // Macros — SDK
    pub use crate::{cpex_log, register_wasm_plugin};
    // Macros — custom hook/payload definition
    pub use cpex_core::{define_hook, impl_plugin_payload, impl_wasm_payload};
}

// ---------------------------------------------------------------------------
// Structured host logging
// ---------------------------------------------------------------------------

/// Log level for host-side structured logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Send a structured log message to the host's tracing infrastructure.
///
/// The host routes this to its `tracing` subscriber with the plugin name
/// attached as a span field. Use this instead of `eprintln!` for production
/// logging.
pub fn host_log(level: LogLevel, message: &str) {
    #[cfg(test)]
    {
        eprintln!("[{:?}] {}", level, message);
        return;
    }

    #[cfg(not(test))]
    {
        use crate::cpex::plugin::host_logging;
        let wit_level = match level {
            LogLevel::Trace => host_logging::LogLevel::Trace,
            LogLevel::Debug => host_logging::LogLevel::Debug,
            LogLevel::Info  => host_logging::LogLevel::Info,
            LogLevel::Warn  => host_logging::LogLevel::Warn,
            LogLevel::Error => host_logging::LogLevel::Error,
        };
        host_logging::log(wit_level, message);
    }
}

/// Convenience macro for structured host logging with format arguments.
///
/// # Example
/// ```ignore
/// cpex_log!(info, "processed {} items in {}ms", count, elapsed);
/// cpex_log!(warn, "payload field missing, using default");
/// ```
#[macro_export]
macro_rules! cpex_log {
    (trace, $($arg:tt)*) => { $crate::host_log($crate::LogLevel::Trace, &format!($($arg)*)) };
    (debug, $($arg:tt)*) => { $crate::host_log($crate::LogLevel::Debug, &format!($($arg)*)) };
    (info,  $($arg:tt)*) => { $crate::host_log($crate::LogLevel::Info,  &format!($($arg)*)) };
    (warn,  $($arg:tt)*) => { $crate::host_log($crate::LogLevel::Warn,  &format!($($arg)*)) };
    (error, $($arg:tt)*) => { $crate::host_log($crate::LogLevel::Error, &format!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// register_wasm_plugin! — the core macro
//
// Generates a complete `Guest` impl that:
// 1. Receives WIT types from the host (hook-name, payload, extensions, ctx)
// 2. Converts WIT → cpex-core native types
// 3. Routes to the matching HookHandler<H> based on the payload's concrete type
// 4. Converts PluginResult → WIT HookResult (with context writeback)
//
// Usage:
//   register_wasm_plugin!(MyPlugin, [CmfHook]);
//   register_wasm_plugin!(MyPlugin, [CmfHook, IdentityHook]);
//   register_wasm_plugin!(MyPlugin, [TokenDelegateHook]);
//
// Rules:
// - `MyPlugin` must implement `Default` and `HookHandler<H>` for every H listed.
// - Each H's `Payload` type must implement `WasmSerializablePayload`.
// - Payloads that match no listed hook → allow() (same as a native plugin not
//   registered for that hook).
// - Payloads that match a listed hook but fail to decode → deny() with
//   code "wasm_payload_decode_error" (failing open would silently skip checks).
// ---------------------------------------------------------------------------

/// Register a plugin struct as the WASM guest entry point.
///
/// # Example
/// ```ignore
/// use cpex_wasm_plugin::prelude::*;
///
/// struct MyPlugin;
/// impl Default for MyPlugin { fn default() -> Self { Self } }
///
/// // impl Plugin + HookHandler<CmfHook> for MyPlugin { ... }
///
/// register_wasm_plugin!(MyPlugin, [CmfHook]);
/// ```
#[macro_export]
macro_rules! register_wasm_plugin {
    ($plugin_ty:ty, [$($hook_ty:ty),+ $(,)?]) => {
        struct _WasmGuestImpl;

        impl Guest for _WasmGuestImpl {
            fn handle_hook(
                hook_name: String,
                payload: HookPayload,
                extensions: Extensions,
                ctx: PluginContext,
            ) -> HookResult {
                use cpex_core::hooks::payload::WasmSerializablePayload;
                use cpex_core::hooks::trait_def::{HookHandler, HookTypeDef};

                let native_ext = $crate::wit_extensions_to_native(extensions);
                let mut native_ctx = $crate::wit_context_to_native(ctx);

                match payload {
                    HookPayload::Cmf(mp) => {
                        let native_payload = $crate::wit_payload_to_native(mp);
                        let any: &dyn ::std::any::Any = &native_payload;
                        $(
                            if let Some(typed) =
                                any.downcast_ref::<<$hook_ty as HookTypeDef>::Payload>()
                            {
                                let plugin = <$plugin_ty>::default();
                                let result = $crate::__block_on(
                                    <$plugin_ty as HookHandler<$hook_ty>>::handle(
                                        &plugin,
                                        typed,
                                        &native_ext,
                                        &mut native_ctx,
                                    )
                                );
                                return $crate::native_result_to_hook_result_generic(
                                    result, &native_ctx,
                                );
                            }
                        )+
                        eprintln!(
                            "[WASM] no handler for CMF payload on hook '{}' — allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    // NOTE: The host sends Identity and Delegation payloads as the
                    // Custom variant (serialized bytes with a type discriminator),
                    // which is routed above. These match arms handle the case where
                    // the host sends native WIT Identity/Delegation variants directly
                    // — this does not happen today but is kept as a safety fallback.
                    HookPayload::Identity(_ip) => {
                        eprintln!(
                            "[WASM] received native Identity variant on hook '{}' — not routed, returning allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    HookPayload::Delegation(_dp) => {
                        eprintln!(
                            "[WASM] received native Delegation variant on hook '{}' — not routed, returning allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    HookPayload::Custom(gp) => {
                        $(
                            if gp.payload_type
                                == <<$hook_ty as HookTypeDef>::Payload
                                    as WasmSerializablePayload>::payload_type_name()
                            {
                                match <<$hook_ty as HookTypeDef>::Payload
                                    as WasmSerializablePayload>::from_wasm_bytes(&gp.payload_data)
                                {
                                    Ok(typed) => {
                                        let plugin = <$plugin_ty>::default();
                                        let result = $crate::__block_on(
                                            <$plugin_ty as HookHandler<$hook_ty>>::handle(
                                                &plugin,
                                                &typed,
                                                &native_ext,
                                                &mut native_ctx,
                                            )
                                        );
                                        return $crate::native_result_to_hook_result_generic(
                                            result, &native_ctx,
                                        );
                                    }
                                    Err(e) => {
                                        return $crate::__decode_error_hook_result(
                                            &gp.payload_type, &e.to_string(), &native_ctx,
                                        );
                                    }
                                }
                            }
                        )+
                        eprintln!(
                            "[WASM] unhandled custom payload '{}' on hook '{}' — allow",
                            gp.payload_type, hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                }
            }
        }

        export!(_WasmGuestImpl);
    };
}

// ---------------------------------------------------------------------------
// Macro support functions — used by register_wasm_plugin! expansion.
// Public so the expanded macro can call them; not part of the plugin-author API.
// ---------------------------------------------------------------------------

pub use conversions::{
    native_payload_to_wit, native_result_to_hook_result_generic,
    wit_context_to_native, wit_extensions_to_native, wit_payload_to_native,
};

/// Allow-and-continue result for payloads this plugin has no handler for.
pub fn __allow_hook_result(ctx: &cpex_core::context::PluginContext) -> HookResult {
    HookResult {
        continue_processing: true,
        modified_payload: None,
        modified_extensions: None,
        modified_context: Some(conversions::native_context_to_wit(ctx)),
        violation: None,
        metadata: None,
    }
}

/// Deny result when a declared payload type fails to decode.
/// Failing open here would silently skip the plugin's check.
pub fn __decode_error_hook_result(
    payload_type: &str,
    error: &str,
    ctx: &cpex_core::context::PluginContext,
) -> HookResult {
    eprintln!("[WASM] failed to decode payload '{}': {}", payload_type, error);
    HookResult {
        continue_processing: false,
        modified_payload: None,
        modified_extensions: None,
        modified_context: Some(conversions::native_context_to_wit(ctx)),
        violation: Some(crate::cpex::plugin::types::PluginViolation {
            code: "wasm_payload_decode_error".to_string(),
            reason: format!("failed to decode payload '{}': {}", payload_type, error),
            description: None,
            details: "{}".to_string(),
            plugin_name: None,
            proto_error_code: None,
        }),
        metadata: None,
    }
}

/// Synchronous async executor for WASM.
///
/// Futures returned by `HookHandler::handle()` must be driven to completion
/// synchronously. Current handlers await nothing in WASM context, so the
/// future completes on the first poll in practice. A 10,000-iteration cap
/// prevents infinite busy-loops if a future unexpectedly yields.
pub fn __block_on<F: std::future::Future>(f: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    const MAX_POLLS: u32 = 10_000;

    fn noop(_: *const ()) {}
    fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut pinned = std::pin::pin!(f);

    for _ in 0..MAX_POLLS {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => continue,
        }
    }

    panic!("[WASM] executor exceeded {} polls — handler future is not completing", MAX_POLLS);
}

// ---------------------------------------------------------------------------
// Plugin registration — feature-gated
//
// Demo plugins (src/examples/) — each is feature-gated so only one compiles
// per .wasm binary. Build a demo: make build-demo DEMO=<name>
//
// Your plugin (src/plugin.rs) is registered at the bottom of this file and
// compiles when NO demo feature is active: make build
// ---------------------------------------------------------------------------

#[cfg(all(feature = "identity-checker", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::identity_checker::IdentityCheckerPlugin,
    [cpex_core::cmf::CmfHook, cpex_core::identity::IdentityHook]
);

#[cfg(all(feature = "header-injector", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::header_injector::HeaderInjectorPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "audit-logger", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::audit_logger::AuditLoggerPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "token-attenuator", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::token_attenuator::TokenAttenuatorPlugin,
    [cpex_core::delegation::TokenDelegateHook]
);

#[cfg(all(feature = "noop", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::noop::NoopPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "fs-test", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::fs_test::FsTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "net-test", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::net_test::NetTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "env-test", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::env_test::EnvTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "tool-invoke-checker", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::tool_invoke_checker::ToolInvokeCheckerPlugin,
    [
        examples::tool_invoke_checker::ToolPreInvoke,
        examples::tool_invoke_checker::ToolPostInvoke,
    ]
);

#[cfg(all(feature = "pii-guard", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::pii_guard::PiiGuardPlugin,
    [examples::pii_guard::ToolPreInvoke]
);

#[cfg(all(feature = "audit-logger-custom", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::audit_logger_custom::AuditLoggerCustomPlugin,
    [
        examples::audit_logger_custom::ToolPreInvoke,
        examples::audit_logger_custom::ToolPostInvoke,
    ]
);

#[cfg(all(feature = "remote-authz", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::remote_authz::RemoteAuthzPlugin,
    [examples::remote_authz::ToolPreInvoke]
);

#[cfg(all(feature = "compute-bench", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::compute_bench::ComputeBenchPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "fs-sandbox-demo", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::fs_sandbox_demo::FsSandboxDemoPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "env-sandbox-demo", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::env_sandbox_demo::EnvSandboxDemoPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "resource-test", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::resource_test::ResourceTestPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(all(feature = "net-http-test", not(test), not(feature = "test-demos")))]
register_wasm_plugin!(
    examples::net_http_test::NetHttpTestPlugin,
    [cpex_core::cmf::CmfHook]
);

// ---------------------------------------------------------------------------
// YOUR PLUGIN — active when no demo feature is enabled (i.e. `make build`).
//
// This registers src/plugin.rs as the WASM export. If you change the hook type
// in plugin.rs (e.g. from CmfHook to IdentityHook), update the list below too.
//
// What this does at compile time:
//   1. Generates a Guest impl that receives WIT types from the host
//   2. Converts them to cpex-core native types
//   3. Calls YOUR HookHandler::handle() method
//   4. Converts your PluginResult back to a WIT HookResult
//   5. Exports the `handle-hook` function symbol for the WASM component model
// ---------------------------------------------------------------------------

#[cfg(all(
    not(test),
    not(feature = "test-demos"),
    not(feature = "identity-checker"),
    not(feature = "header-injector"),
    not(feature = "audit-logger"),
    not(feature = "token-attenuator"),
    not(feature = "noop"),
    not(feature = "fs-test"),
    not(feature = "net-test"),
    not(feature = "env-test"),
    not(feature = "tool-invoke-checker"),
    not(feature = "pii-guard"),
    not(feature = "audit-logger-custom"),
    not(feature = "remote-authz"),
    not(feature = "compute-bench"),
    not(feature = "fs-sandbox-demo"),
    not(feature = "env-sandbox-demo"),
    not(feature = "resource-test"),
    not(feature = "net-http-test"),
))]
register_wasm_plugin!(
    plugin::UserPlugin,
    [cpex_core::cmf::CmfHook]  // ← change this if you use a different hook type
);

