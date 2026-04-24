// Location: ./crates/cpex-sdk/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX SDK — lean crate for plugin authors.
//
// Re-exports the Plugin trait and supporting types from cpex-core.
// Plugin authors depend on this crate instead of the full runtime,
// keeping their dependency tree minimal. This is also the crate
// that WASM plugins compile against.

// Plugin lifecycle
pub use cpex_core::plugin::{OnError, Plugin, PluginConfig, PluginMode};

// Hook system
pub use cpex_core::hooks::{
    Extensions, FilteredExtensions, HookHandler, HookTypeDef, PluginPayload, PluginResult,
};

// Context
pub use cpex_core::context::PluginContext;

// Errors
pub use cpex_core::error::{PluginError, PluginViolation};

// Re-export the define_hook! macro
pub use cpex_core::define_hook;
