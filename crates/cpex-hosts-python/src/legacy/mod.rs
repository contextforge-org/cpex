// Location: ./crates/cpex-hosts-python/src/legacy/mod.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Legacy (non-CMF) hook payloads.
//
// "Legacy" is the Python framework's term for the pre-CMF hook family:
// `tool_pre_invoke` and friends, as opposed to `cmf.tool_pre_invoke`. These
// structs mirror its Pydantic models. The identity and delegation payloads
// ride PPE's `identity.resolve` and `token.delegate` hooks. The tool, prompt
// and resource payloads have no PPE hook; they serve hosts that register the
// unprefixed names themselves. `crate::conversion` holds the hook table.

pub mod payloads;

pub use payloads::{
    AttenuationConfig, IdentityResolvePayload, PromptPostFetchPayload, PromptPreFetchPayload,
    ResourcePostFetchPayload, ResourcePreFetchPayload, TokenDelegatePayload, ToolPostInvokePayload,
    ToolPreInvokePayload,
};
