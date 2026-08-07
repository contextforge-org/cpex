// Location: ./crates/cpex-hosts-python/src/legacy/mod.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy (non-CMF) hook payloads.
//
// "Legacy" is the framework's own term for the pre-CMF hook family —
// `tool_pre_invoke` and friends, as opposed to `cmf.tool_pre_invoke`. Both
// families are supported; they differ only in which payload type a hook name
// resolves to, which is what `crate::conversion` decides.

pub mod payloads;

pub use payloads::{
    AttenuationConfig, IdentityResolvePayload, PromptPostFetchPayload, PromptPreFetchPayload,
    ResourcePostFetchPayload, ResourcePreFetchPayload, TokenDelegatePayload, ToolPostInvokePayload,
    ToolPreInvokePayload,
};
