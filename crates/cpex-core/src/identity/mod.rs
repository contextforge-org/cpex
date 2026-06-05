// Location: ./crates/cpex-core/src/identity/mod.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Identity hook family — IdentityResolve.
//
// Mirrors the cmf/ module layout: the hook marker + handler trait
// machinery (provided by cpex-core's generic hooks layer) plus the
// hook-specific payload + result types. Token-delegation lives in
// its own sibling module (slice 3); the two hook families share
// nothing in terms of payloads so they get separate `HookTypeDef`
// markers.
//
// Sub-step A scope: data shapes only — no executor wiring, no
// framework merge-into-Extensions logic, no APL integration. Those
// land in sub-steps B / C / D.

pub mod hook;
pub mod payload;
pub mod route_config;

pub use hook::{IdentityHook, HOOK_IDENTITY_RESOLVE};
pub use payload::{IdentityPayload, TokenSource};
pub use route_config::{RouteIdentityConfig, RouteIdentityStep};
