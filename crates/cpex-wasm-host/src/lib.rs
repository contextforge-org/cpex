// Location: ./crates/cpex-wasm-host/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Shriti Priya

//! WASM plugin host runtime for the CPEX framework.
//!
//! Loads WebAssembly Component Model plugins into sandboxed wasmtime environments,
//! enforces resource limits and capability-based access control, and bridges to
//! cpex-core's [`PluginManager`](cpex_core::manager::PluginManager) for seamless
//! integration with native plugins.
//!
//! # Usage
//!
//! ```ignore
//! use cpex_wasm_host::factory::WasmPluginFactory;
//! use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;
//!
//! // For built-in payloads (CMF, Identity, Delegation):
//! let factory = WasmPluginFactory::with_builtin_payloads(wasm_dir);
//!
//! // For custom payloads:
//! let mut registry = PayloadSerializerRegistry::new();
//! registry.register::<MyPayload>();
//! let factory = WasmPluginFactory::new(wasm_dir, Arc::new(registry));
//!
//! // Register with PluginManager — WASM plugins participate transparently
//! mgr.register_factory("wasm://my-plugin.wasm", Box::new(factory));
//! ```

/// Native ↔ WIT type conversions for payloads, extensions, and context.
pub mod conversions;

/// [`WasmPluginFactory`](factory::WasmPluginFactory) — bridges cpex-core's
/// `PluginFactory` trait to the sandbox runtime. Implements `PluginFactory` so
/// WASM plugins can be registered with `PluginManager`.
pub mod factory;

/// Type-erased serialization registry for custom payload types crossing the
/// WASM boundary via `HookPayload::Custom`.
pub mod payload_registry;

/// Sandbox policy parsing and WASI context construction from YAML config.
pub mod policy_loader;

/// Wasmtime sandbox runtime — `SharedEngine`, `SandboxManager`, and the
/// `host-logging` WIT import implementation.
pub mod sandbox_manager;
