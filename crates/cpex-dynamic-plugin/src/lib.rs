// Location: ./crates/cpex-dynamic-plugin/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// cpex-dynamic-plugin — load Rust cdylib plugins at runtime.
//
// See `docs/specs/cpex-rust-spec.md` §17 for the architecture.
//
// # Module layout
//
//   * `abi`    — shared types crossing the dlopen boundary
//                (entry-point fn signature, registration struct,
//                version constants). Always available.
//   * `plugin` — helpers for plugin authors writing a `cdylib`:
//                the `cpex_dynamic_plugin!` macro that generates
//                the `extern "C"` entry point, helpers to build a
//                `PluginRegistration`. Always available.
//   * `host`   — `DynamicPluginFactory` + `libloading`-backed
//                loader. Behind the `host` feature flag — plugin-
//                only builds don't pay for libloading.
//
// # ABI versioning
//
// `abi::ABI_VERSION` is bumped whenever the entry-point signature,
// the `PluginRegistration` layout, or the underlying
// `AnyHookHandler` trait changes shape. Host loads a plugin → host
// asks plugin which ABI version it was compiled against → if
// mismatch, host refuses to load and returns a clear error. Same-
// version-only Rust ABI is the load-bearing constraint; this
// runtime check makes mismatches loud instead of UB.

pub mod abi;
pub mod plugin;

#[cfg(feature = "host")]
pub mod host;

pub use abi::{
    EntryPointFn, EntryPointResult, ListFn, PluginManifest, PluginManifestEntry,
    PluginRegistration, ABI_VERSION, ENTRY_POINT_SYMBOL, LIST_SYMBOL,
};
pub use plugin::{dispatch_create, CreateFn};

#[cfg(feature = "host")]
pub use host::DynamicPluginFactory;

// `paste` is re-exported under a hidden module so the
// `cpex_dynamic_plugins!` macro can reference it as
// `$crate::__macro_support::paste::paste!`. Plugin authors don't
// touch this directly — they just use the macro.
#[doc(hidden)]
pub mod __macro_support {
    pub use paste;
}
