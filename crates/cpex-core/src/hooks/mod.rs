// Location: ./crates/cpex-core/src/hooks/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Hook system.
//
// Provides the core abstractions for defining and dispatching hooks:
//
// - [`HookTypeDef`] — marker trait associating a typed payload + result with a hook name.
// - [`PluginPayload`] — base trait for all hook payloads (mirrors Python's PluginPayload).
// - [`PluginResult`] — result type with separate payload and extension modifications.
// - [`Extensions`] — capability-gated extension view passed to handlers.
// - [`define_hook!`] — macro for declaring new hook types with handler traits.
// - [`hook_names`] / [`cmf_hook_names`] — string constants for built-in hooks.
//
// Hook types are open — hosts define their own using define_hook! alongside the built-ins.

pub mod adapter;
pub mod macros;
pub mod payload;
pub mod trait_def;
pub mod types;

// Re-export core types at the hooks level
pub use adapter::TypedHandlerAdapter;
pub use payload::{Extensions, PluginPayload};
pub use trait_def::{HookHandler, HookTypeDef, PluginResult};
pub use types::{builtin_hook_types, hook_type_from_str, HookType};
