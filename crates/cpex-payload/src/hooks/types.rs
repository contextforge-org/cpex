// Location: ./crates/cpex-core/src/hooks/types.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Hook type definitions.
//
// Hook types are open strings — hosts define hook points appropriate
// to their execution lifecycle. This module provides a newtype wrapper
// for type safety and built-in constants for the common hook points.
//
// The framework does not prescribe a fixed set of hook points. Each
// host places `invoke_hook()` calls at sites appropriate to its
// processing pipeline. The constants below cover the standard
// MCP/CMF lifecycle but hosts may register additional types.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Hook Type
// ---------------------------------------------------------------------------

/// A named hook point in the host's execution lifecycle.
///
/// Wraps a string identifier. Hook types are open — hosts register
/// their own alongside the built-in constants.
///
/// # Examples
///
/// ```
/// use cpex_core::hooks::HookType;
/// use cpex_core::hooks::types::hook_names;
///
/// // Use a built-in name constant
/// let hook = HookType::new(hook_names::TOOL_PRE_INVOKE);
/// assert_eq!(hook.as_str(), "tool_pre_invoke");
///
/// // Define a custom hook
/// let custom = HookType::new("generation_pre_call");
/// assert_eq!(custom.as_str(), "generation_pre_call");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HookType(String);

impl HookType {
    /// Create a new hook type from a string.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Return the hook type as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for HookType {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for HookType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ---------------------------------------------------------------------------
// Built-in Hook String Constants
// ---------------------------------------------------------------------------
// Canonical string names for built-in hooks. Use these with
// HookType::new() or pass them directly to APIs that accept &str.

/// Legacy hook names — typed payloads (ToolPreInvokePayload, etc.).
pub mod hook_names {
    // Tool lifecycle
    pub const TOOL_PRE_INVOKE: &str = "tool_pre_invoke";
    pub const TOOL_POST_INVOKE: &str = "tool_post_invoke";

    // Prompt lifecycle
    pub const PROMPT_PRE_FETCH: &str = "prompt_pre_fetch";
    pub const PROMPT_POST_FETCH: &str = "prompt_post_fetch";

    // Resource lifecycle
    pub const RESOURCE_PRE_FETCH: &str = "resource_pre_fetch";
    pub const RESOURCE_POST_FETCH: &str = "resource_post_fetch";

    // Identity and delegation
    pub const IDENTITY_RESOLVE: &str = "identity_resolve";
    pub const TOKEN_DELEGATE: &str = "token_delegate";
}

/// CMF hook names — MessagePayload wrapping a CMF Message.
/// The `cmf.` prefix lets legacy and CMF plugins coexist at the
/// same interception point. The gateway fires both at each event.
pub mod cmf_hook_names {
    // Tool lifecycle
    pub const TOOL_PRE_INVOKE: &str = "cmf.tool_pre_invoke";
    pub const TOOL_POST_INVOKE: &str = "cmf.tool_post_invoke";

    // LLM lifecycle (CMF only — no legacy equivalent)
    pub const LLM_INPUT: &str = "cmf.llm_input";
    pub const LLM_OUTPUT: &str = "cmf.llm_output";

    // Prompt lifecycle
    pub const PROMPT_PRE_FETCH: &str = "cmf.prompt_pre_fetch";
    pub const PROMPT_POST_FETCH: &str = "cmf.prompt_post_fetch";

    // Resource lifecycle
    pub const RESOURCE_PRE_FETCH: &str = "cmf.resource_pre_fetch";
    pub const RESOURCE_POST_FETCH: &str = "cmf.resource_post_fetch";
}

// ---------------------------------------------------------------------------
// Built-in hook type helpers
// ---------------------------------------------------------------------------

/// Returns all built-in hook types with their canonical string values.
///
/// Called once during PluginManager initialization to populate the
/// hook registry. Hosts add their own hook types after this.
pub fn builtin_hook_types() -> Vec<HookType> {
    vec![
        // Legacy (typed payloads)
        HookType::new("tool_pre_invoke"),
        HookType::new("tool_post_invoke"),
        HookType::new("prompt_pre_fetch"),
        HookType::new("prompt_post_fetch"),
        HookType::new("resource_pre_fetch"),
        HookType::new("resource_post_fetch"),
        HookType::new("identity_resolve"),
        HookType::new("token_delegate"),
        // CMF (MessagePayload)
        HookType::new("cmf.tool_pre_invoke"),
        HookType::new("cmf.tool_post_invoke"),
        HookType::new("cmf.llm_input"),
        HookType::new("cmf.llm_output"),
        HookType::new("cmf.prompt_pre_fetch"),
        HookType::new("cmf.prompt_post_fetch"),
        HookType::new("cmf.resource_pre_fetch"),
        HookType::new("cmf.resource_post_fetch"),
    ]
}

/// Look up a hook type by name. Returns the canonical instance if
/// it matches a built-in, otherwise creates a new custom HookType.
pub fn hook_type_from_str(name: &str) -> HookType {
    HookType::new(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_type_equality() {
        let a = HookType::new("tool_pre_invoke");
        let b = HookType::new("tool_pre_invoke");
        assert_eq!(a, b);
    }

    #[test]
    fn test_hook_type_display() {
        let h = HookType::new("cmf.llm_input");
        assert_eq!(h.to_string(), "cmf.llm_input");
    }

    #[test]
    fn test_hook_type_from_str() {
        let h: HookType = "custom_hook".into();
        assert_eq!(h.as_str(), "custom_hook");
    }

    #[test]
    fn test_builtin_hook_types_count() {
        let builtins = builtin_hook_types();
        // 8 legacy + 8 CMF
        assert_eq!(builtins.len(), 16);
    }
}
