// Location: ./crates/cpex-core/src/lib.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX Core library root.
//
// Pure Rust plugin runtime with no FFI, WASM, or PyO3 dependencies.
// Provides the PluginManager, 5-phase executor, hook registry,
// unified config parser, and all core types.
//
// # Modules
//
// - [`plugin`] — Plugin trait, PluginRef, PluginMetadata, PluginConfig
// - [`hooks`]  — HookType (open string registry), payload/result traits
// - [`executor`] — 5-phase execution engine (sequential → transform → audit → concurrent → fire_and_forget)
// - [`manager`] — PluginManager lifecycle and hook dispatch
// - [`registry`] — PluginInstanceRegistry and HookRegistry
// - [`config`] — Unified YAML configuration parsing
// - [`context`] — PluginContext (local_state + global_state)
// - [`error`] — Error types, violations, and result types

pub mod config;
pub mod context;
pub mod error;
pub mod executor;
pub mod hooks;
pub mod manager;
pub mod plugin;
pub mod registry;
