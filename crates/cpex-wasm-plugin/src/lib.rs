// Location: ./crates/cpex-wasm-plugin/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya
//
// CPEX WASM Plugin SDK.
//
// Provides:
// - `register_wasm_plugin!(PluginType, [HookType, ...])` macro — generates
//   the WIT `Guest` impl with automatic dispatch to `HookHandler<H>` impls.
// - Conversion functions exposed for advanced use cases.
//
// Plugin authors implement `HookHandler<H>` on their type (identical to native
// plugins) and call the macro once — the WIT glue is fully generated.

pub mod conversions;
mod plugins;

// Generate Rust bindings from the WIT world definition.
wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});

pub use conversions::{
    native_payload_to_wit, native_result_to_hook_result, native_result_to_hook_result_generic,
    wit_context_to_native, wit_extensions_to_native, wit_payload_to_native,
};

// ---------------------------------------------------------------------------
// register_wasm_plugin! — the core macro
//
// Generates a complete `Guest` impl that:
// 1. Receives WIT types from the host (hook-name, payload, extensions, ctx)
// 2. Converts WIT → cpex-core native types
// 3. Routes to the matching HookHandler<H> based on the payload's concrete type
// 4. Converts PluginResult → WIT HookResult (with context writeback)
//
// Dispatch is built at compile time from the hook type list: every listed
// hook's `Payload` must implement `WasmSerializablePayload`. A CMF payload
// routes to the hook whose Payload is `MessagePayload`; a custom payload
// routes to the hook whose Payload matches the WIT type discriminator
// (e.g. "cpex.identity" → HookHandler<IdentityHook>).
//
// Payloads no listed hook handles return allow() — same as a native plugin
// that isn't registered for that hook. A payload that names a listed type
// but fails to decode returns a deny violation: silently allowing on a
// decode failure would skip whatever check this plugin enforces.
//
// Usage:
//   register_wasm_plugin!(MyPlugin, [CmfHook, IdentityHook]);
// ---------------------------------------------------------------------------

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

                eprintln!("[WASM] handle_hook: {}", hook_name);

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

                                // WASM is single-threaded with no ambient async
                                // runtime. Drive the future synchronously.
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
                    HookPayload::Identity(_ip) => {
                        eprintln!(
                            "[WASM] received Identity variant on hook '{}' — allow",
                            hook_name
                        );
                        $crate::__allow_hook_result(&native_ctx)
                    }
                    HookPayload::Delegation(_dp) => {
                        eprintln!(
                            "[WASM] received Delegation variant on hook '{}' — allow",
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
// Macro support functions — HookResult constructors used by the generated
// dispatch. Public so the expanded macro can call them, not part of the
// plugin-author API.
// ---------------------------------------------------------------------------

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

/// Deny result for a payload the plugin declares a handler for but could
/// not decode — failing open here would silently skip the plugin's check.
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

// ---------------------------------------------------------------------------
// __block_on — synchronous async executor for WASM
//
// Futures returned by HookHandler::handle() must be driven to completion
// synchronously. Current handlers await nothing in WASM context, so the
// future completes on the first poll in practice.
// ---------------------------------------------------------------------------

pub fn __block_on<F: std::future::Future>(f: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop(_: *const ()) {}
    fn noop_clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut pinned = std::pin::pin!(f);

    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin registration — feature-gated
//
// Each feature compiles a different plugin into the .wasm binary.
// Build with: cargo build --target wasm32-wasip2 --features <plugin> --no-default-features
// ---------------------------------------------------------------------------

#[cfg(feature = "identity-checker")]
register_wasm_plugin!(
    plugins::identity_checker::IdentityCheckerPlugin,
    [cpex_core::cmf::CmfHook, cpex_core::identity::IdentityHook]
);

#[cfg(feature = "header-injector")]
register_wasm_plugin!(
    plugins::header_injector::HeaderInjectorPlugin,
    [cpex_core::cmf::CmfHook]
);

#[cfg(feature = "audit-logger")]
register_wasm_plugin!(
    plugins::audit_logger::AuditLoggerPlugin,
    [cpex_core::cmf::CmfHook]
);
