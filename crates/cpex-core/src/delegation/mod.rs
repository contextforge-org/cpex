// Location: ./crates/cpex-core/src/delegation/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Token-delegation hook family — TokenDelegate.
//
// Mirrors the identity/ module layout: the hook marker + handler
// trait machinery (provided by cpex-core's generic hooks layer)
// plus the hook-specific payload + result types.
//
// Scope: data shapes + host helpers — no executor
// wiring (that's free via `mgr.invoke_named::<TokenDelegateHook>`),
// no TokenCacheControl trait (that lands in a follow-up with
// the cache infrastructure).

pub mod hook;
pub mod payload;

pub use hook::{TokenDelegateHook, HOOK_TOKEN_DELEGATE};
pub use payload::{AttenuationConfig, AuthEnforcedBy, DelegationPayload, TargetType};
