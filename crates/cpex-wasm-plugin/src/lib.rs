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
mod plugin;

// Generate Rust bindings from the WIT world definition.
wit_bindgen::generate!({
    path: "wit",
    world: "plugin",
    generate_all,
});

pub use conversions::{
    native_payload_to_wit, native_result_to_hook_result, wit_context_to_native,
    wit_extensions_to_native, wit_payload_to_native,
};

// ---------------------------------------------------------------------------
// register_wasm_plugin! — the core macro
//
// Generates a complete `Guest` impl that:
// 1. Receives WIT types from the host (hook-name, payload, extensions, ctx)
// 2. Converts WIT → cpex-core native types
// 3. Routes to the matching HookHandler<H> based on the payload variant
// 4. Converts PluginResult → WIT HookResult (with context writeback)
//
// CMF dispatch: for HookPayload::Cmf, calls HookHandler<CmfHook>::handle()
// Generic dispatch: for HookPayload::Generic, returns allow() (full generic
// dispatch requires compile-time type list matching — future work)
//
// Usage:
//   register_wasm_plugin!(MyPlugin, [CmfHook]);
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
                use cpex_core::cmf::CmfHook;
                use cpex_core::hooks::trait_def::HookHandler;

                eprintln!("[WASM] handle_hook: {}", hook_name);

                let native_ext = $crate::wit_extensions_to_native(extensions);
                let mut native_ctx = $crate::wit_context_to_native(ctx);

                match payload {
                    HookPayload::Cmf(mp) => {
                        let native_payload = $crate::wit_payload_to_native(mp);
                        let plugin = <$plugin_ty>::default();

                        // WASM is single-threaded with no ambient async runtime.
                        // Drive the future to completion synchronously via __block_on.
                        let result = $crate::__block_on(
                            <$plugin_ty as HookHandler<CmfHook>>::handle(
                                &plugin,
                                &native_payload,
                                &native_ext,
                                &mut native_ctx,
                            )
                        );

                        $crate::native_result_to_hook_result(result, &native_ctx)
                    }
                    HookPayload::Generic(gp) => {
                        eprintln!("[WASM] generic payload '{}' — returning allow()", gp.payload_type);
                        HookResult {
                            continue_processing: true,
                            modified_payload: None,
                            modified_extensions: None,
                            modified_context: None,
                            violation: None,
                            metadata: None,
                        }
                    }
                }
            }
        }

        export!(_WasmGuestImpl);
    };
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
// Plugin registration
// ---------------------------------------------------------------------------

use plugin::IdentityCheckerPlugin;

register_wasm_plugin!(IdentityCheckerPlugin, [cpex_core::cmf::CmfHook]);
