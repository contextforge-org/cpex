// Location: ./crates/cpex-core/src/hooks/metadata.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Hook routing metadata — answers "what dispatch context does this
// hook name belong to?"
//
// # What this solves
//
// cpex-core's `invoke_named::<H>(hook_name, ...)` already routes to
// the right handlers based on the hook name. But APL's dispatcher
// (`apl-cpex/src/dispatch_plan.rs`) needs a finer-grained question:
// when a plugin is registered for MULTIPLE hooks (e.g.
// `[cmf.tool_pre_invoke, cmf.tool_post_invoke]`), which entry should
// fire for the current dispatch context?
//
// Pre-2026-05-25 dispatch_plan used a naming heuristic — any hook
// name containing "field", "redact", "scan", or "validate" was
// classified as field-context, everything else as step-context. Two
// problems:
//
//   1. **Multi-hook bug.** Two step-context hooks on the same plugin
//      (pre + post) collapsed to "first non-field wins" — silent
//      wrong dispatch when pre_invocation and post_invocation needed
//      different entries.
//   2. **The "field-hook" classification didn't match any real hook.**
//      No CMF hook actually carries `field` / `redact` / `scan` /
//      `validate` in its name — the heuristic was anticipating a
//      convention no plugin uses. APL's field-stage dispatch (from
//      `args:` / `result:` pipelines) routes to the same hook a
//      plugin registers under for step dispatch.
//
// This module replaces the heuristic with an explicit hook-name →
// metadata table.
//
// # The table
//
// Each entry maps a hook name to `HookMetadata`:
//
//   * `entity_type` — `Some("tool")`, `Some("llm")`, etc. for hooks
//     tied to an entity type; `None` for hook families that apply
//     regardless of entity (`identity.resolve`, `token.delegate`).
//   * `phase` — `Pre` / `Post` / `Unphased`. APL's evaluator uses
//     this to pick the right entry for the current phase context.
//
// Lookup is the foundation for `apl-cpex::dispatch_plan`'s entry
// selection. See `docs/apl-hook-family-expansion.md` Layer 1.
//
// # Phase semantics
//
// APL phases map to hook phases:
//
//   * `args:` field stage     → looks for `Pre` hooks
//   * `pre_invocation:` step       → looks for `Pre` hooks
//   * `result:` field stage   → looks for `Post` hooks
//   * `post_invocation:` step      → looks for `Post` hooks
//
// A plugin that wants to discriminate "args field stage" from
// "pre_invocation step" — both Pre context — inspects `PluginContext::hook_name()`
// itself. The hook-routing layer doesn't slice phase finer than
// Pre/Post.
//
// # Custom hook metadata
//
// Hosts and plugin authors can register metadata for custom hook
// names via [`register_hook_metadata`]. Unregistered hooks return
// [`HookMetadata::unknown`] from `lookup` — entity_type `None`, phase
// `Unphased`. That conservative default matches any dispatch context,
// so custom hooks dispatch on the first registered entry. Authors
// who want phase-aware behavior must register metadata explicitly.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::cmf::constants::{
    ENTITY_LLM, ENTITY_PROMPT, ENTITY_RESOURCE, ENTITY_TOOL, HOOK_CMF_LLM_INPUT,
    HOOK_CMF_LLM_OUTPUT, HOOK_CMF_PROMPT_POST_INVOKE, HOOK_CMF_PROMPT_PRE_INVOKE,
    HOOK_CMF_RESOURCE_POST_FETCH, HOOK_CMF_RESOURCE_PRE_FETCH, HOOK_CMF_TOOL_POST_INVOKE,
    HOOK_CMF_TOOL_PRE_INVOKE,
};
use crate::delegation::HOOK_TOKEN_DELEGATE;
use crate::identity::HOOK_IDENTITY_RESOLVE;

/// Lifecycle position a hook occupies for dispatcher purposes.
///
/// APL's args/pre_invocation phases dispatch to `Pre` hooks; APL's
/// result/post_invocation phases dispatch to `Post` hooks. Hook families
/// outside the request-lifecycle model (identity at request entry,
/// token-delegate inside authorization) use `Unphased` and match any
/// requested phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPhase {
    /// Pre-invocation hook — e.g. `cmf.tool_pre_invoke`,
    /// `cmf.llm_input`. Dispatched from APL's `args:` field stages
    /// and `pre_invocation:` steps.
    Pre,
    /// Post-invocation hook — e.g. `cmf.tool_post_invoke`,
    /// `cmf.llm_output`. Dispatched from APL's `result:` field stages
    /// and `post_invocation:` steps.
    Post,
    /// Not phase-bound. Covers hook families that fire once per
    /// request without an APL phase concept (`identity.resolve`,
    /// `token.delegate`) AND custom hooks the framework doesn't know
    /// about. APL's dispatcher matches `Unphased` against any
    /// requested phase — conservative default that lets unknown
    /// hooks still dispatch.
    Unphased,
}

/// Metadata describing what dispatch context a hook name belongs to.
/// See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookMetadata {
    /// Entity type the hook applies to (`"tool"`, `"llm"`, `"prompt"`,
    /// `"resource"`). `None` means "applies regardless of entity_type"
    /// — used for hooks that don't tie to MCP's entity-type taxonomy.
    pub entity_type: Option<&'static str>,
    /// Lifecycle phase the hook occupies.
    pub phase: HookPhase,
}

impl HookMetadata {
    /// Default — `entity_type: None`, `phase: Unphased`. Used as
    /// the fallback for hook names not in the registry. The
    /// `matches` function treats `Unphased` as "matches any phase,"
    /// so unknown hooks dispatch on the first registered entry.
    pub const fn unknown() -> Self {
        Self {
            entity_type: None,
            phase: HookPhase::Unphased,
        }
    }

    /// Whether this hook's metadata matches a dispatch context.
    ///
    /// Matching rules:
    ///
    /// - `entity_type`: a hook tied to a specific entity_type
    ///   (`Some("tool")`) matches only contexts with that entity
    ///   type. A hook with `entity_type: None` matches any context.
    ///   A request without an entity_type (`None`) matches any hook
    ///   — the dispatcher hasn't specified what entity is in play,
    ///   so we can't filter on it.
    /// - `phase`: exact match between hook's phase and the requested
    ///   phase, EXCEPT `Unphased` is a wildcard from either side
    ///   (lets custom / unregistered hooks dispatch without phase
    ///   rules).
    pub fn matches(&self, request_entity_type: Option<&str>, requested_phase: HookPhase) -> bool {
        let entity_ok = match (self.entity_type, request_entity_type) {
            (Some(hook_et), Some(req_et)) => hook_et == req_et,
            (Some(_), None) => true, // request didn't specify; don't filter
            (None, _) => true,       // hook applies to any entity_type
        };
        if !entity_ok {
            return false;
        }
        match (self.phase, requested_phase) {
            (HookPhase::Unphased, _) | (_, HookPhase::Unphased) => true,
            (a, b) => a == b,
        }
    }
}

/// Built-in hook metadata. Plugin authors and hosts can register
/// additional entries via [`register_hook_metadata`]. The 8 CMF step
/// hooks (entity × pre/post) are the complete CMF-routable surface
/// today; identity + delegation are unphased.
const BUILTIN_METADATA: &[(&str, HookMetadata)] = &[
    // CMF tool
    (
        HOOK_CMF_TOOL_PRE_INVOKE,
        HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        },
    ),
    (
        HOOK_CMF_TOOL_POST_INVOKE,
        HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Post,
        },
    ),
    // CMF llm
    (
        HOOK_CMF_LLM_INPUT,
        HookMetadata {
            entity_type: Some(ENTITY_LLM),
            phase: HookPhase::Pre,
        },
    ),
    (
        HOOK_CMF_LLM_OUTPUT,
        HookMetadata {
            entity_type: Some(ENTITY_LLM),
            phase: HookPhase::Post,
        },
    ),
    // CMF prompt
    (
        HOOK_CMF_PROMPT_PRE_INVOKE,
        HookMetadata {
            entity_type: Some(ENTITY_PROMPT),
            phase: HookPhase::Pre,
        },
    ),
    (
        HOOK_CMF_PROMPT_POST_INVOKE,
        HookMetadata {
            entity_type: Some(ENTITY_PROMPT),
            phase: HookPhase::Post,
        },
    ),
    // CMF resource
    (
        HOOK_CMF_RESOURCE_PRE_FETCH,
        HookMetadata {
            entity_type: Some(ENTITY_RESOURCE),
            phase: HookPhase::Pre,
        },
    ),
    (
        HOOK_CMF_RESOURCE_POST_FETCH,
        HookMetadata {
            entity_type: Some(ENTITY_RESOURCE),
            phase: HookPhase::Post,
        },
    ),
    // Non-CMF families (entity-agnostic, not phase-bound).
    (
        HOOK_IDENTITY_RESOLVE,
        HookMetadata {
            entity_type: None,
            phase: HookPhase::Unphased,
        },
    ),
    (
        HOOK_TOKEN_DELEGATE,
        HookMetadata {
            entity_type: None,
            phase: HookPhase::Unphased,
        },
    ),
];

/// Runtime-registered additions to the metadata table. Hosts /
/// plugin authors call [`register_hook_metadata`] to populate.
/// Initialized with the BUILTIN_METADATA on first access.
fn registry() -> &'static RwLock<HashMap<String, HookMetadata>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, HookMetadata>>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut map: HashMap<String, HookMetadata> = HashMap::new();
        for (name, meta) in BUILTIN_METADATA {
            map.insert((*name).to_string(), *meta);
        }
        RwLock::new(map)
    })
}

/// Look up metadata for a hook name. Returns
/// [`HookMetadata::unknown`] for names not in the registry —
/// equivalent to "no phase, no entity_type filter," which lets
/// unregistered hooks still dispatch via the conservative wildcard
/// in [`HookMetadata::matches`].
pub fn lookup(hook_name: &str) -> HookMetadata {
    let r = registry().read().unwrap_or_else(|p| p.into_inner());
    r.get(hook_name).copied().unwrap_or(HookMetadata::unknown())
}

/// Register or override metadata for a hook name. Idempotent — a
/// host re-registering the same hook with the same metadata is fine.
/// Re-registering with different metadata overwrites the previous
/// entry; intentional for hosts that need to customize defaults.
///
/// Thread-safe; intended to be called at startup. Concurrent calls
/// are serialized via the registry's `RwLock`.
pub fn register_hook_metadata(hook_name: impl Into<String>, meta: HookMetadata) {
    let mut w = registry().write().unwrap_or_else(|p| p.into_inner());
    w.insert(hook_name.into(), meta);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmf_tool_pre_invoke_is_pre_phase_for_tool_entity() {
        let meta = lookup(HOOK_CMF_TOOL_PRE_INVOKE);
        assert_eq!(meta.entity_type, Some(ENTITY_TOOL));
        assert_eq!(meta.phase, HookPhase::Pre);
    }

    #[test]
    fn cmf_llm_output_is_post_phase_for_llm_entity() {
        let meta = lookup(HOOK_CMF_LLM_OUTPUT);
        assert_eq!(meta.entity_type, Some(ENTITY_LLM));
        assert_eq!(meta.phase, HookPhase::Post);
    }

    #[test]
    fn identity_resolve_is_unphased_no_entity() {
        let meta = lookup(HOOK_IDENTITY_RESOLVE);
        assert_eq!(meta.entity_type, None);
        assert_eq!(meta.phase, HookPhase::Unphased);
    }

    #[test]
    fn token_delegate_is_unphased_no_entity() {
        let meta = lookup(HOOK_TOKEN_DELEGATE);
        assert_eq!(meta.entity_type, None);
        assert_eq!(meta.phase, HookPhase::Unphased);
    }

    #[test]
    fn unknown_hook_returns_universal_default() {
        let meta = lookup("custom.unrecognized_hook");
        assert_eq!(meta.entity_type, None);
        assert_eq!(meta.phase, HookPhase::Unphased);
    }

    #[test]
    fn matches_filters_by_entity_type_when_set() {
        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        assert!(tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(!tool_pre.matches(Some(ENTITY_LLM), HookPhase::Pre));
    }

    #[test]
    fn matches_allows_any_entity_when_hook_entity_is_none() {
        let universal = HookMetadata {
            entity_type: None,
            phase: HookPhase::Pre,
        };
        assert!(universal.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(universal.matches(Some(ENTITY_LLM), HookPhase::Pre));
        assert!(universal.matches(None, HookPhase::Pre));
    }

    #[test]
    fn matches_phase_exactly_unless_unphased() {
        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        assert!(tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(!tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Post));
    }

    #[test]
    fn matches_unphased_is_wildcard_in_either_direction() {
        let unphased = HookMetadata {
            entity_type: None,
            phase: HookPhase::Unphased,
        };
        assert!(unphased.matches(Some(ENTITY_TOOL), HookPhase::Pre));
        assert!(unphased.matches(Some(ENTITY_LLM), HookPhase::Post));

        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        // Request with Unphased phase matches any registered hook
        // of the right entity_type.
        assert!(tool_pre.matches(Some(ENTITY_TOOL), HookPhase::Unphased));
    }

    #[test]
    fn matches_request_without_entity_type_doesnt_filter_on_it() {
        let tool_pre = HookMetadata {
            entity_type: Some(ENTITY_TOOL),
            phase: HookPhase::Pre,
        };
        // Request didn't specify entity_type — hook still matches.
        assert!(tool_pre.matches(None, HookPhase::Pre));
    }

    #[test]
    fn register_hook_metadata_overrides_default() {
        let name = "test_custom.overridden_meta";
        register_hook_metadata(
            name,
            HookMetadata {
                entity_type: Some("custom"),
                phase: HookPhase::Pre,
            },
        );
        let meta = lookup(name);
        assert_eq!(meta.entity_type, Some("custom"));
        assert_eq!(meta.phase, HookPhase::Pre);
    }
}
