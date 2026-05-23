// Location: ./crates/cpex-dynamic-plugin/src/abi.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Shared ABI types between plugin (cdylib) and host (loader).
//
// # Layout-stable contract
//
// Plugin and host MUST be compiled against the same `cpex-core`
// version. Rust's `repr(Rust)` types don't have a stable layout
// across compiler versions, so even patch-version bumps to
// `cpex-core` invalidate the contract. The `ABI_VERSION` constant
// below is bumped on every change to:
//
//   * `PluginRegistration` field layout (added/removed/reordered)
//   * `EntryPointResult` discriminants
//   * `cpex_core::registry::AnyHookHandler` trait shape (methods,
//     order, signatures)
//   * `cpex_core::hooks::payload` types (`Extensions`, `MessagePayload`)
//
// Plugin's entry point reports its compiled-against ABI_VERSION;
// host rejects load if mismatched. Same-version-only is the
// load-bearing constraint; the runtime check makes mismatches
// loud instead of UB.
//
// # The entry-point contract
//
// Each plugin cdylib exports a single C function named
// `cpex_plugin_create` with the [`EntryPointFn`] signature. The
// plugin-author macro [`crate::cpex_dynamic_plugin!`] generates
// this function so authors don't write unsafe FFI by hand.
//
// Ownership: the plugin allocates the `PluginRegistration` via
// `Box::new(...)` + `Box::into_raw(...)`, writes the pointer to
// `out_registration`. Host takes ownership via `Box::from_raw(...)`.
// Same default allocator on both sides (`std::alloc::System`) means
// the host can drop the box safely.

use std::sync::Arc;

use cpex_core::plugin::Plugin;
use cpex_core::registry::AnyHookHandler;

/// Bumped on any breaking change to the ABI surface (see module
/// docs). Plugin and host must report identical values or the load
/// is rejected.
pub const ABI_VERSION: u32 = 1;

/// Status code the plugin's entry point returns to the host.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointResult {
    /// Plugin constructed successfully. `out_registration` is
    /// populated; host takes ownership of the boxed registration.
    Ok = 0,
    /// Plugin's `ABI_VERSION` didn't match the host's. The
    /// plugin did NOT touch `out_registration`; host should not
    /// read it.
    AbiMismatch = 1,
    /// Plugin couldn't parse its serialized `PluginConfig`.
    ConfigParseError = 2,
    /// Plugin's own initialization failed (key load, network
    /// probe, missing required claim, etc.).
    InitializationError = 3,
    /// Plugin's entry-point body panicked. Caught at the FFI
    /// boundary so the host doesn't get an unwinding panic
    /// across `extern "C"` (which is UB).
    Panic = 4,
}

/// The plugin's entry-point function signature. Plugins export
/// this as `cpex_plugin_create`; host's loader uses
/// `libloading::Symbol<EntryPointFn>` to bind to it.
///
/// Arguments:
///
///   * `abi_version` — value the *host* was compiled against. The
///     plugin compares this to its own [`ABI_VERSION`] and returns
///     [`EntryPointResult::AbiMismatch`] on a mismatch.
///   * `plugin_config_json` / `plugin_config_len` — serialized
///     `PluginConfig` (the operator's YAML block, JSON-encoded).
///     Plugin deserializes; uses it to construct its handlers.
///   * `out_registration` — out-parameter. On `Ok`, plugin writes
///     a `Box::into_raw(Box::new(PluginRegistration { ... }))`
///     pointer. On any error variant, plugin leaves this untouched.
pub type EntryPointFn = unsafe extern "C" fn(
    abi_version: u32,
    plugin_config_json: *const u8,
    plugin_config_len: usize,
    out_registration: *mut *mut PluginRegistration,
) -> EntryPointResult;

/// The symbol name the plugin's cdylib MUST export. Host looks
/// this up via `libloading::Library::get(ENTRY_POINT_SYMBOL)`.
pub const ENTRY_POINT_SYMBOL: &[u8] = b"cpex_plugin_create";

/// What the plugin hands the host through `out_registration`.
///
/// The plugin allocates this with `Box::new(...)` and transfers
/// ownership to the host. Host drops it after extracting the
/// `plugin` + `handlers` into a `PluginInstance`.
///
/// `#[repr(Rust)]` — same-version Rust ABI applies. Both sides
/// must see identical layout, which they will when compiled
/// against the same `cpex-core` version.
pub struct PluginRegistration {
    /// ABI version this plugin reports. The host's loader has
    /// already checked the version through the entry-point's
    /// return code, but the field is included for diagnostics
    /// (plugin's view of its own ABI).
    pub abi_version: u32,
    /// Plugin's reported name. Surfaced in operator-facing
    /// diagnostics ("plugin 'rate-limit' (version 0.3.1) loaded
    /// from /opt/plugins/rate_limit.so").
    pub name: String,
    /// Plugin's reported version (typically `CARGO_PKG_VERSION`).
    pub version: String,
    /// The plugin instance itself (shared with handlers).
    pub plugin: Arc<dyn Plugin>,
    /// Type-erased handlers paired with their hook names.
    /// Mirrors `cpex_core::factory::PluginInstance.handlers`.
    pub handlers: Vec<(String, Arc<dyn AnyHookHandler>)>,
}

impl PluginRegistration {
    /// Convenience constructor — fills `abi_version` from the
    /// compiled-against constant so plugin authors don't have to
    /// remember to set it.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        plugin: Arc<dyn Plugin>,
        handlers: Vec<(String, Arc<dyn AnyHookHandler>)>,
    ) -> Self {
        Self {
            abi_version: ABI_VERSION,
            name: name.into(),
            version: version.into(),
            plugin,
            handlers,
        }
    }
}
