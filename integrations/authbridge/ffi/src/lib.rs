// Location: ./integrations/authbridge/ffi/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// kagenti-cpex-ffi — CPEX plugin factories for AuthBridge integration.
//
// Builds a staticlib that bundles cpex-ffi (the C ABI for CPEX) plus
// AuthBridge-targeted plugins. The Go cpex-runtime plugin links this
// library and registers the factories below before loading its YAML
// config.
//
// Exports one C function:
//
//   int kagenti_cpex_register_factories(void *mgr);
//
// Called from Go via cgo immediately after `cpex_manager_new_default()`
// and before `cpex_load_config()`. Returns 0 on success, non-zero on
// invalid manager handle.

mod llm_pii_redactor;
mod scope_tool_gate;

// Force the linker to include cpex-ffi symbols in our staticlib.
// Without this, the C-ABI functions from cpex-ffi would be stripped
// as "unused" since this crate doesn't call them from Rust — but the
// Go side needs them at link time.
extern crate cpex_ffi;

use std::os::raw::c_int;

/// Register all AuthBridge-targeted CPEX plugin factories on the manager.
///
/// Must be called after `cpex_manager_new_default()` and before
/// `cpex_load_config()`. Registers:
///
///   - `scope-tool-gate` — denies a tool call when the caller's
///     `Security.Subject.Scopes` doesn't include the scope configured
///     for that tool name.
///   - `llm-pii-redactor` — runs regexes over the LLM prompt body and
///     replaces matches with `[REDACTED]`.
///
/// # Safety
/// `mgr` must be a valid handle from `cpex_manager_new_default`.
#[no_mangle]
pub unsafe extern "C" fn kagenti_cpex_register_factories(
    mgr: *mut cpex_ffi::CpexManagerInner,
) -> c_int {
    let inner = match mgr.as_mut() {
        Some(m) => m,
        None => return -1,
    };

    // Install a tracing subscriber so messages from cpex-ffi's
    // deserialize/invoke path become visible in stderr. No-op if a
    // subscriber is already installed (try_init returns Err silently).
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(true)
        .try_init();

    scope_tool_gate::register(&mut inner.manager);
    llm_pii_redactor::register(&mut inner.manager);
    0
}
