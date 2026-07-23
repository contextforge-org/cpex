// Location: ./crates/cpex-hosts-python/src/legacy/hooks/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy hook payloads.
//
// Typed payloads that mirror the Python framework's bare (legacy) hooks
// so the isolated Python plugin host can send correctly-typed payloads for
// the bare hook names (`tool_pre_invoke`, `prompt_pre_fetch`, etc.).

pub mod prompts;
pub mod resources;
pub mod tools;

pub use prompts::{PromptPosthookPayload, PromptPrehookPayload};
pub use resources::{ResourcePostFetchPayload, ResourcePreFetchPayload};
pub use tools::{ToolPostInvokePayload, ToolPreInvokePayload};
