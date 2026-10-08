// Location: ./examples/go-demo/ffi/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX Demo FFI — re-exports cpex-ffi and adds demo plugin factories.
//
// This crate builds a staticlib that includes all cpex-ffi symbols
// transitively. Go links only this library — no need to link
// libcpex_ffi separately.
//
// Exports one C function: `cpex_demo_register_factories()` which
// registers both generic and CMF demo plugin factories. These are host
// plugins for the demo, not CPEX builtins:
//
//   Generic (GenericPayload, on the host hooks `demo.tool_pre_invoke`
//   and `demo.tool_post_invoke`):
//     - `demo/identity`: identity checker
//     - `demo/pii`: PII guard
//     - `demo/audit`: audit logger
//
//   CMF (MessagePayload, on `cmf.tool_pre_invoke` / `cmf.tool_post_invoke`):
//     - `demo/cmf-tool-policy`: tool permission checking
//     - `demo/cmf-header-injector`: response header injection

mod cmf_plugins;
mod demo_plugins;

// Force the linker to include all cpex-ffi symbols in our staticlib.
// Without this, the extern "C" functions from cpex-ffi would be
// stripped as "unused" since we don't call them from Rust.
extern crate cpex_ffi;

use std::os::raw::c_int;

/// Register the demo hooks and plugin factories on the engine.
///
/// Must be called after `cpex_engine_new_default()` and before
/// `cpex_load_config()`, because the config loader checks plugin kinds
/// and hook names against what is registered.
///
/// # Safety
/// `handle` must be a valid handle from `cpex_engine_new_default`.
#[no_mangle]
pub unsafe extern "C" fn cpex_demo_register_factories(
    handle: *mut cpex_ffi::CpexEngineInner,
) -> c_int {
    let inner = match handle.as_ref() {
        Some(h) => h,
        None => return -1,
    };

    // `register_factory` takes `&self`; `&inner.engine` deref-coerces
    // from `Arc<PolicyEngine>` to `&PolicyEngine`.
    demo_plugins::register_demo_factories(&inner.engine);
    cmf_plugins::register_cmf_factories(&inner.engine);
    0
}
