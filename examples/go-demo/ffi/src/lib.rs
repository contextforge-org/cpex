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
// registers both generic and CMF demo plugin factories:
//
//   Generic (GenericPayload):
//     - `builtin/identity` — identity checker
//     - `builtin/pii` — PII guard
//     - `builtin/audit` — audit logger
//
//   CMF (MessagePayload):
//     - `builtin/cmf-tool-policy` — tool permission checking
//     - `builtin/cmf-header-injector` — response header injection

mod cmf_plugins;
mod demo_plugins;

// Force the linker to include all cpex-ffi symbols in our staticlib.
// Without this, the extern "C" functions from cpex-ffi would be
// stripped as "unused" since we don't call them from Rust.
extern crate cpex_ffi;

use std::os::raw::c_int;

/// Register demo plugin factories on the manager.
///
/// Must be called after `cpex_manager_new_default()` and before
/// `cpex_load_config()`. Registers:
///   - `builtin/identity` — identity checker
///   - `builtin/pii` — PII guard
///   - `builtin/audit` — audit logger
///
/// # Safety
/// `mgr` must be a valid handle from `cpex_manager_new_default`.
#[no_mangle]
pub unsafe extern "C" fn cpex_demo_register_factories(
    mgr: *mut cpex_ffi::CpexManagerInner,
) -> c_int {
    let inner = match mgr.as_mut() {
        Some(m) => m,
        None => return -1,
    };

    demo_plugins::register_demo_factories(&mut inner.manager);
    cmf_plugins::register_cmf_factories(&mut inner.manager);
    0
}
