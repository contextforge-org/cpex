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

/// The symbol name a single-plugin cdylib exports. Host looks
/// this up via `libloading::Library::get(ENTRY_POINT_SYMBOL)`.
///
/// Multi-plugin cdylibs use the `cpex_plugin_create_<entry>`
/// naming convention instead; the operator selects an entry via
/// the `?entry=<name>` query parameter in the kind URL.
pub const ENTRY_POINT_SYMBOL: &[u8] = b"cpex_plugin_create";

/// Symbol name for the OPTIONAL multi-plugin discovery function.
///
/// A cdylib that packages multiple plugins MAY export this symbol
/// to advertise which entries are available. Single-plugin cdylibs
/// don't need to expose it; the host falls back to plain dlsym
/// errors when the manifest is absent.
///
/// See [`ListFn`] and [`PluginManifest`].
pub const LIST_SYMBOL: &[u8] = b"cpex_plugin_list";

/// Signature of the optional discovery function exported as
/// [`LIST_SYMBOL`]. Returns a pointer to a `'static`
/// [`PluginManifest`] baked into the cdylib's read-only data.
///
/// # Returned pointer
///
/// The pointer is to static data that lives as long as the cdylib
/// is mapped. Since `DynamicPluginFactory` leaks the `Library`
/// handle (so vtables don't dangle), the manifest is effectively
/// `'static` from the host's perspective. The host never frees it
/// and the plugin never reallocates it — it's a compile-time
/// constant.
///
/// A null return value means "no manifest available" and is
/// equivalent to the symbol being absent.
pub type ListFn = unsafe extern "C" fn() -> *const PluginManifest;

/// One entry in a cdylib's plugin manifest. All fields are
/// `&'static str` because the data is baked into the cdylib's
/// read-only memory at compile time — nothing for the host to
/// free, nothing for the plugin to reallocate.
///
/// # ABI shape
///
/// `&'static str` is a fat pointer (data + length) with same-
/// version Rust layout. Because the whole `cpex-dynamic-plugin`
/// ABI is already same-version-only (the `AnyHookHandler` vtable
/// has the same constraint), reusing Rust slices here doesn't
/// add new ABI assumptions. Marking `repr(C)` would be a lie —
/// fat pointers aren't C-shaped.
#[derive(Debug, Clone, Copy)]
pub struct PluginManifestEntry {
    /// The entry-point suffix. Full exported symbol is
    /// `cpex_plugin_create_<entry>`. Goes in the kind URL's
    /// `?entry=<value>` selector. MUST be a valid C identifier
    /// (`[a-zA-Z_][a-zA-Z0-9_]*`); the host rejects entries that
    /// violate this on the parse side before any symbol lookup.
    pub entry: &'static str,
    /// Human-readable display name (used by the discovery
    /// tooling, NOT used for symbol resolution).
    pub name: &'static str,
    /// Plugin version, conventionally `env!("CARGO_PKG_VERSION")`.
    pub version: &'static str,
    /// One-line description for the discovery tooling.
    pub description: &'static str,
}

/// What [`ListFn`] returns a pointer to. Wrapper around the
/// manifest's `'static` entry slice plus an ABI-version tag.
///
/// The `abi_version` field lets the host detect manifest-layout
/// drift within the same major ABI. For hard-breaking changes
/// to the manifest shape, bump the symbol name itself (e.g.,
/// `cpex_plugin_list_v2`) rather than relying on the version
/// field alone.
pub struct PluginManifest {
    /// ABI version this manifest was produced against. Host
    /// rejects manifests whose `abi_version` doesn't match its
    /// own [`ABI_VERSION`].
    pub abi_version: u32,
    /// The cdylib's advertised plugin entries.
    pub entries: &'static [PluginManifestEntry],
}

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
