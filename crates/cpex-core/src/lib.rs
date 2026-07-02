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
// - [`factory`] — Plugin factory registry for config-driven instantiation
// - [`context`] — PluginContext (local_state + global_state)
// - [`cmf`] — ContextForge Message Format (Message, ContentPart, enums)
// - [`identity`] — IdentityResolve hook family (subject / client /
//                   workload resolution from raw credentials)
// - [`delegation`] — TokenDelegate hook family (outbound credential
//                     minting for downstream calls)
// - [`error`] — Error types, violations, and result types

pub mod cmf;
pub mod config;
pub mod context;
pub mod delegation;
pub mod error;
pub mod extensions;
pub mod hooks;
pub mod identity;
pub mod plugin;

// Runtime-only modules — require tokio, task spawning, orchestration.
// Excluded when building for WASM targets (use `default-features = false`).
#[cfg(feature = "runtime")]
pub mod executor;
#[cfg(feature = "runtime")]
pub mod factory;
#[cfg(feature = "runtime")]
pub mod manager;
#[cfg(feature = "runtime")]
pub mod registry;
#[cfg(feature = "runtime")]
pub mod visitor;
