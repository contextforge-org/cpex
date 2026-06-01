// Location: ./crates/cpex-dynamic-plugin/src/plugin.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Plugin-author helpers for writing a Rust `cdylib` plugin.
//
// Plugin authors write a normal Rust struct implementing `Plugin`
// + `HookHandler<H>` (per the in-tree plugin recipe), then use
// the [`cpex_dynamic_plugin!`] macro to generate the `extern "C"`
// entry point. The macro handles:
//
//   * ABI-version handshake (rejects mismatched hosts loudly).
//   * Config deserialization from the raw bytes the host passes.
//   * `catch_unwind` around user code so a panic doesn't unwind
//     across the `extern "C"` boundary (which would be UB).
//   * Allocating + transferring ownership of `PluginRegistration`.
//
// Plugin authors never write unsafe FFI by hand.

use std::panic::{catch_unwind, AssertUnwindSafe};

use cpex_core::plugin::PluginConfig;

use crate::abi::{EntryPointResult, PluginRegistration, ABI_VERSION};

/// The closure plugin authors hand to [`dispatch_create`] /
/// [`cpex_dynamic_plugin!`]. Receives the deserialized
/// `PluginConfig`, returns either a populated
/// `PluginRegistration` (success) or a string (initialization
/// error — wraps as [`EntryPointResult::InitializationError`]).
pub type CreateFn =
    fn(PluginConfig) -> Result<PluginRegistration, String>;

/// Helper called from the plugin's generated `cpex_plugin_create`
/// function. Plugin authors should NOT call this directly — use
/// the [`cpex_dynamic_plugin!`] macro, which generates the
/// correct unsafe glue.
///
/// # Safety
///
/// * `plugin_config_json` / `plugin_config_len` must describe a
///   valid byte slice (UTF-8 isn't required at this layer —
///   `serde_json` will report a parse error if it isn't).
/// * `out_registration` must be non-null and writable.
///
/// On every error variant, `*out_registration` is left untouched.
/// On `Ok`, `*out_registration` is set to a `Box::into_raw` pointer
/// the host takes ownership of.
pub unsafe fn dispatch_create(
    host_abi_version: u32,
    plugin_config_json: *const u8,
    plugin_config_len: usize,
    out_registration: *mut *mut PluginRegistration,
    create: CreateFn,
) -> EntryPointResult {
    if host_abi_version != ABI_VERSION {
        return EntryPointResult::AbiMismatch;
    }

    // Materialize the config bytes into a borrowed slice. The
    // host owns the storage; the plugin only reads.
    let config_bytes = if plugin_config_json.is_null() || plugin_config_len == 0 {
        &[][..]
    } else {
        // Safety: caller guarantees a valid byte range. Empty case
        // handled above so we never construct a slice from null.
        unsafe { std::slice::from_raw_parts(plugin_config_json, plugin_config_len) }
    };

    let config: PluginConfig = match serde_json::from_slice(config_bytes) {
        Ok(c) => c,
        Err(_) => return EntryPointResult::ConfigParseError,
    };

    // catch_unwind so a panic in user code doesn't propagate
    // across the FFI boundary. AssertUnwindSafe because we don't
    // care about state-after-panic — the plugin's create() is
    // single-shot and any partial state is dropped here.
    let result = catch_unwind(AssertUnwindSafe(|| create(config)));

    let registration = match result {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => return EntryPointResult::InitializationError,
        Err(_) => return EntryPointResult::Panic,
    };

    // Transfer ownership to the host. Box::into_raw produces a
    // raw pointer the host's `Box::from_raw` reclaims.
    let boxed = Box::new(registration);
    let ptr = Box::into_raw(boxed);
    // Safety: caller guarantees out_registration is writable.
    unsafe {
        *out_registration = ptr;
    }
    EntryPointResult::Ok
}

/// Generate the `#[no_mangle] pub extern "C" fn cpex_plugin_create`
/// entry point for a Rust `cdylib` plugin.
///
/// # Usage
///
/// ```rust,ignore
/// use cpex_core::{hooks::adapter::TypedHandlerAdapter, plugin::{Plugin, PluginConfig}, hooks::trait_def::HookHandler, cmf::CmfHook};
/// use cpex_dynamic_plugin::{cpex_dynamic_plugin, PluginRegistration};
/// use std::sync::Arc;
///
/// struct MyPlugin { cfg: PluginConfig }
/// // ... impl Plugin + HookHandler<CmfHook> for MyPlugin ...
///
/// cpex_dynamic_plugin! {
///     |cfg: PluginConfig| -> Result<PluginRegistration, String> {
///         let plugin = Arc::new(MyPlugin { cfg });
///         let adapter = Arc::new(TypedHandlerAdapter::<CmfHook, _>::new(Arc::clone(&plugin)));
///         Ok(PluginRegistration::new(
///             "my-plugin",
///             env!("CARGO_PKG_VERSION"),
///             plugin as Arc<dyn cpex_core::plugin::Plugin>,
///             vec![("cmf.tool_pre_invoke".to_string(), adapter as Arc<dyn cpex_core::registry::AnyHookHandler>)],
///         ))
///     }
/// }
/// ```
///
/// The macro expands to a single `#[no_mangle] pub extern "C" fn
/// cpex_plugin_create(...)` that delegates to [`dispatch_create`].
/// All unsafe-FFI plumbing is hidden.
#[macro_export]
macro_rules! cpex_dynamic_plugin {
    ($create:expr) => {
        /// Plugin entry point. Host's `DynamicPluginFactory` finds
        /// this via `libloading::Library::get(b"cpex_plugin_create")`.
        ///
        /// Generated by `cpex_dynamic_plugin!`. Do not edit by hand.
        #[no_mangle]
        pub unsafe extern "C" fn cpex_plugin_create(
            host_abi_version: u32,
            plugin_config_json: *const u8,
            plugin_config_len: usize,
            out_registration: *mut *mut $crate::abi::PluginRegistration,
        ) -> $crate::abi::EntryPointResult {
            // Cast the user closure to the function-pointer type
            // `dispatch_create` expects. Plugin authors write
            // `|cfg: PluginConfig| -> Result<PluginRegistration, String> { ... }`.
            let create_fn: $crate::plugin::CreateFn = $create;
            unsafe {
                $crate::plugin::dispatch_create(
                    host_abi_version,
                    plugin_config_json,
                    plugin_config_len,
                    out_registration,
                    create_fn,
                )
            }
        }
    };
}

/// Generate entry points for MULTIPLE plugins packaged in one
/// cdylib, plus the optional `cpex_plugin_list` discovery symbol.
///
/// Use this when you want to ship several distinct plugins inside
/// one shared object file. For single-plugin cdylibs, the simpler
/// [`cpex_dynamic_plugin!`] macro is the right tool — it emits
/// `cpex_plugin_create` (no entry selector, no manifest needed).
///
/// # Usage
///
/// ```rust,ignore
/// use cpex_core::plugin::{Plugin, PluginConfig};
/// use cpex_dynamic_plugin::{cpex_dynamic_plugins, PluginRegistration};
///
/// fn build_rate_limiter(cfg: PluginConfig) -> Result<PluginRegistration, String> {
///     // ... build and return PluginRegistration ...
/// #   unimplemented!()
/// }
///
/// fn build_audit(cfg: PluginConfig) -> Result<PluginRegistration, String> {
///     // ... build and return PluginRegistration ...
/// #   unimplemented!()
/// }
///
/// cpex_dynamic_plugins! {
///     rate_limiter => {
///         name: "Rate Limiter",
///         version: "1.0.0",
///         description: "Token-bucket rate limiter",
///         create: build_rate_limiter,
///     },
///     audit => {
///         name: "Audit Logger",
///         version: "0.5.0",
///         description: "Writes hook events to disk",
///         create: build_audit,
///     },
/// }
/// ```
///
/// # Operator side
///
/// Each entry becomes addressable from YAML via `?entry=<name>`:
///
/// ```yaml
/// plugins:
///   - name: edge-rate-limit
///     kind: "lib:/opt/plugins/multi.so?entry=rate_limiter"
///     hooks: [cmf.tool_pre_invoke]
///     config:
///       max_per_second: 100
///   - name: audit-trail
///     kind: "lib:/opt/plugins/multi.so?entry=audit"
///     hooks: [cmf.tool_post_invoke]
///     config:
///       log_path: /var/log/cpex-audit.log
/// ```
///
/// # What the macro generates
///
///   * One `#[no_mangle] pub unsafe extern "C" fn
///     cpex_plugin_create_<entry>(...)` per entry, each wrapping the
///     supplied `create` function via `dispatch_create` (same ABI
///     glue as the single-plugin macro).
///   * A `static` [`PluginManifest`](crate::abi::PluginManifest)
///     listing all entries.
///   * A `#[no_mangle] pub unsafe extern "C" fn cpex_plugin_list()`
///     returning a pointer to that manifest. The host uses this to
///     (a) validate the operator's `?entry=` against the available
///     entries and (b) produce friendly errors when the requested
///     entry doesn't exist.
///
/// # Entry naming
///
/// The entry name (the ident before `=>`) MUST be a valid Rust
/// identifier — that's what the macro requires, and it's also a
/// valid C identifier for the generated symbol. The same name
/// appears verbatim in:
///
///   * The exported symbol: `cpex_plugin_create_<entry>`.
///   * The manifest's `entry` field (as a string).
///   * The operator's `?entry=<name>` URL.
#[macro_export]
macro_rules! cpex_dynamic_plugins {
    ( $( $entry:ident => {
        name: $name:literal,
        version: $version:literal,
        description: $desc:literal,
        create: $create:expr $(,)?
    } ),+ $(,)? ) => {
        $(
            $crate::__macro_support::paste::paste! {
                /// One entry point of a multi-plugin cdylib. Host's
                /// `DynamicPluginFactory` finds this via
                /// `libloading::Library::get(b"cpex_plugin_create_<entry>")`
                /// when the operator's kind URL contains
                /// `?entry=<entry>`.
                ///
                /// Generated by `cpex_dynamic_plugins!`. Do not edit by hand.
                #[no_mangle]
                pub unsafe extern "C" fn [<cpex_plugin_create_ $entry>](
                    host_abi_version: u32,
                    plugin_config_json: *const u8,
                    plugin_config_len: usize,
                    out_registration: *mut *mut $crate::abi::PluginRegistration,
                ) -> $crate::abi::EntryPointResult {
                    let create_fn: $crate::plugin::CreateFn = $create;
                    unsafe {
                        $crate::plugin::dispatch_create(
                            host_abi_version,
                            plugin_config_json,
                            plugin_config_len,
                            out_registration,
                            create_fn,
                        )
                    }
                }
            }
        )+

        /// The cdylib's plugin manifest. Compile-time constant
        /// referenced by the generated `cpex_plugin_list` symbol.
        ///
        /// Generated by `cpex_dynamic_plugins!`. Do not edit by hand.
        static __CPEX_PLUGIN_MANIFEST_ENTRIES: &[$crate::abi::PluginManifestEntry] = &[
            $(
                $crate::abi::PluginManifestEntry {
                    entry: stringify!($entry),
                    name: $name,
                    version: $version,
                    description: $desc,
                },
            )+
        ];

        /// The full manifest, referenced by `cpex_plugin_list`.
        ///
        /// Generated by `cpex_dynamic_plugins!`. Do not edit by hand.
        static __CPEX_PLUGIN_MANIFEST: $crate::abi::PluginManifest = $crate::abi::PluginManifest {
            abi_version: $crate::abi::ABI_VERSION,
            entries: __CPEX_PLUGIN_MANIFEST_ENTRIES,
        };

        /// Discovery symbol. Optional in the ABI; emitted only when
        /// the multi-plugin macro is used. Host's
        /// `DynamicPluginFactory` looks for this via
        /// `libloading::Library::get(b"cpex_plugin_list")` and uses
        /// the result to validate `?entry=` against available
        /// entries.
        ///
        /// Generated by `cpex_dynamic_plugins!`. Do not edit by hand.
        #[no_mangle]
        pub unsafe extern "C" fn cpex_plugin_list() -> *const $crate::abi::PluginManifest {
            &__CPEX_PLUGIN_MANIFEST as *const $crate::abi::PluginManifest
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use cpex_core::plugin::{Plugin, PluginConfig};

    /// A bare-minimum plugin used for testing `dispatch_create`.
    /// Doesn't register any hook handlers; just verifies that the
    /// flow (abi check, config parse, catch_unwind, registration
    /// allocation) works end-to-end without a real cdylib build.
    #[derive(Debug)]
    struct StubPlugin {
        cfg: PluginConfig,
    }

    #[async_trait::async_trait]
    impl Plugin for StubPlugin {
        fn config(&self) -> &PluginConfig {
            &self.cfg
        }
    }

    fn stub_create(cfg: PluginConfig) -> Result<PluginRegistration, String> {
        let plugin = Arc::new(StubPlugin { cfg });
        Ok(PluginRegistration::new(
            "stub-plugin",
            "0.0.1",
            plugin as Arc<dyn Plugin>,
            Vec::new(),
        ))
    }

    fn stub_create_failing(_cfg: PluginConfig) -> Result<PluginRegistration, String> {
        Err("simulated init failure".to_string())
    }

    fn stub_create_panicking(_cfg: PluginConfig) -> Result<PluginRegistration, String> {
        panic!("simulated panic in plugin init");
    }

    fn run_dispatch(
        host_abi_version: u32,
        config_bytes: &[u8],
        create: CreateFn,
    ) -> (EntryPointResult, *mut PluginRegistration) {
        let mut out: *mut PluginRegistration = std::ptr::null_mut();
        let result = unsafe {
            dispatch_create(
                host_abi_version,
                config_bytes.as_ptr(),
                config_bytes.len(),
                &mut out as *mut *mut PluginRegistration,
                create,
            )
        };
        (result, out)
    }

    /// Helper: build the minimal serialized PluginConfig the
    /// dispatch layer expects.
    fn minimal_config_bytes() -> Vec<u8> {
        let cfg = PluginConfig {
            name: "test".to_string(),
            kind: "lib:/dev/null".to_string(),
            ..Default::default()
        };
        serde_json::to_vec(&cfg).expect("PluginConfig serializes")
    }

    #[test]
    fn happy_path_returns_ok_and_populates_out() {
        let bytes = minimal_config_bytes();
        let (result, out) = run_dispatch(ABI_VERSION, &bytes, stub_create);
        assert_eq!(result, EntryPointResult::Ok);
        assert!(!out.is_null());
        // Take ownership and verify the registration fields.
        let boxed = unsafe { Box::from_raw(out) };
        assert_eq!(boxed.abi_version, ABI_VERSION);
        assert_eq!(boxed.name, "stub-plugin");
        assert_eq!(boxed.version, "0.0.1");
        assert!(boxed.handlers.is_empty());
    }

    #[test]
    fn abi_mismatch_short_circuits_before_user_code() {
        // host_abi_version != ABI_VERSION → dispatch returns
        // AbiMismatch without ever touching the config or
        // invoking the create closure.
        let bytes = minimal_config_bytes();
        let (result, out) =
            run_dispatch(ABI_VERSION.wrapping_add(1), &bytes, stub_create);
        assert_eq!(result, EntryPointResult::AbiMismatch);
        assert!(out.is_null(), "out must be untouched on AbiMismatch");
    }

    #[test]
    fn config_parse_error_returns_config_parse_error() {
        let bytes = b"this isn't json";
        let (result, out) = run_dispatch(ABI_VERSION, bytes, stub_create);
        assert_eq!(result, EntryPointResult::ConfigParseError);
        assert!(out.is_null());
    }

    #[test]
    fn empty_config_is_treated_as_parse_error() {
        // An empty config-bytes range deserializes to error
        // (`serde_json::from_slice(&[])` fails). Plugin authors
        // who want to support "no config" should send `{}`.
        let (result, _) = run_dispatch(ABI_VERSION, &[], stub_create);
        assert_eq!(result, EntryPointResult::ConfigParseError);
    }

    #[test]
    fn init_failure_returns_initialization_error() {
        let bytes = minimal_config_bytes();
        let (result, out) = run_dispatch(ABI_VERSION, &bytes, stub_create_failing);
        assert_eq!(result, EntryPointResult::InitializationError);
        assert!(out.is_null());
    }

    #[test]
    fn panic_in_user_code_is_caught_and_reported() {
        // catch_unwind catches the panic; dispatch returns
        // Panic. Critical for safety — an unwinding panic across
        // extern "C" is undefined behavior, so the host must
        // never see one.
        let bytes = minimal_config_bytes();
        let (result, out) = run_dispatch(ABI_VERSION, &bytes, stub_create_panicking);
        assert_eq!(result, EntryPointResult::Panic);
        assert!(out.is_null());
    }
}
