// Location: ./crates/cpex-core/src/hooks/trait_def.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// HookTypeDef trait and PluginResult type.
//
// Every hook in the CPEX framework is defined by a marker type that
// implements HookTypeDef. This associates a typed PluginPayload and
// PluginResult with a string name used for registry lookup and config.
//
// The hook type does NOT declare an access pattern (read-only vs
// mutating). The plugin's mode (from PluginRef.trusted_config)
// determines scheduling and authority at runtime. Security invariants
// come from the types inside the payload (Arc<T>, MonotonicSet,
// Guarded<T>), not from borrow mechanics.
//
// Extensions are always a separate parameter — never part of the
// payload. This allows capability-filtered views per plugin and
// independent modification of extensions without copying the payload.

use crate::context::PluginContext;
use crate::error::PluginViolation;
use crate::hooks::payload::{Extensions, PluginPayload};
use crate::plugin::Plugin;

// ---------------------------------------------------------------------------
// HookTypeDef Trait
// ---------------------------------------------------------------------------

/// Defines a hook's contract: what goes in and what comes out.
///
/// Each hook type is a zero-sized marker struct that implements this
/// trait. The framework uses the associated types for compile-time
/// dispatch and the NAME constant for registry lookup.
///
/// The hook type does **not** declare an access pattern. The plugin's
/// mode (from `PluginRef.trusted_config`) determines whether the
/// executor passes a borrow or a clone:
///
/// | Mode            | Receives        | Can Block? | Can Modify? |
/// |-----------------|-----------------|------------|-------------|
/// | Sequential      | owned (clone)   | Yes        | Yes         |
/// | Transform       | owned (clone)   | No         | Yes         |
/// | Audit           | &Payload        | No         | No          |
/// | Concurrent      | &Payload        | Yes        | No          |
/// | FireAndForget   | &Payload        | No         | No          |
///
/// # Defining a Hook
///
/// Use the [`define_hook!`] macro instead of implementing this trait
/// manually — the macro generates the marker struct, the trait impl,
/// and the handler trait in one declaration.
pub trait HookTypeDef: Send + Sync + 'static {
    /// The typed payload that handlers receive.
    /// Must implement [`PluginPayload`] (Clone + Send + Sync + 'static).
    type Payload: PluginPayload;

    /// The typed result that handlers return.
    type Result: Send + Sync;

    /// Hook name — used as the registry key and in config YAML.
    ///
    /// Multiple hook names can map to the same HookTypeDef (the CMF
    /// pattern where one handler covers `cmf.tool_pre_invoke`,
    /// `cmf.llm_input`, etc.). The primary NAME is used for
    /// single-name registration; additional names are registered
    /// via `register_for_names()`.
    const NAME: &'static str;
}

// ---------------------------------------------------------------------------
// Hook Handler Trait
// ---------------------------------------------------------------------------

/// Typed handler for a specific hook type.
///
/// Plugin authors implement this trait (alongside [`Plugin`]) to handle
/// a specific hook. The type parameter `H` ties the handler to a
/// `HookTypeDef`, ensuring the correct payload and result types at
/// compile time.
///
/// The framework creates a type-erased adapter internally when you
/// register — you never touch `AnyHookHandler` directly.
///
/// # Examples
///
/// ```rust,ignore
/// impl HookHandler<CmfHook> for MyPlugin {
///     fn handle(
///         &self,
///         payload: MessagePayload,
///         extensions: &Extensions,
///         ctx: &PluginContext,
///     ) -> PluginResult<MessagePayload> {
///         PluginResult::allow()
///     }
/// }
///
/// // Registration — no AnyHookHandler needed:
/// manager.register_handler::<CmfHook, _>(plugin, config)?;
/// ```
pub trait HookHandler<H: HookTypeDef>: Plugin + Send + Sync {
    /// Handle the hook invocation.
    ///
    /// Receives a **borrow** of the typed payload, capability-filtered
    /// extensions, and per-invocation context. Returns a typed result.
    ///
    /// The payload is immutable — Rust's borrow checker prevents
    /// modification through `&H::Payload`. To modify, the plugin
    /// must `clone()` the payload (or the fields it needs) and return
    /// the modified copy in `PluginResult::modify_payload()`. This
    /// pushes the clone cost to the plugin that actually needs it —
    /// read-only plugins (validators, auditors) never pay for a copy.
    fn handle(
        &self,
        payload: &H::Payload,
        extensions: &Extensions,
        ctx: &mut PluginContext,
    ) -> H::Result;
}

// ---------------------------------------------------------------------------
// Plugin Result
// ---------------------------------------------------------------------------

/// Result returned by a hook handler.
///
/// Payload and extension modifications are **separate** — this is a
/// core design decision. Extension-only changes (add a label, set a
/// header) don't require copying the payload. The payload is only
/// present in `modified_payload` when message content actually changed.
///
/// The executor interprets the result based on the plugin's mode:
/// - Sequential/Transform: `modified_payload` and `modified_extensions` are accepted.
/// - Audit/Concurrent/FireAndForget: modifications are discarded.
/// - Sequential/Concurrent: `continue_processing = false` halts the pipeline.
/// - Transform/Audit/FireAndForget: blocks are suppressed.
///
/// Mirrors Python's `PluginResult[T]` with separate `modified_payload`
/// and `modified_extensions` fields.
///
/// # Examples
///
/// ```
/// use cpex_core::hooks::{PluginPayload, PluginResult};
/// use cpex_core::error::PluginViolation;
///
/// // Define a simple payload
/// #[derive(Debug, Clone)]
/// struct TestPayload { value: i32 }
/// cpex_core::impl_plugin_payload!(TestPayload);
///
/// // Allow — no changes
/// let result: PluginResult<TestPayload> = PluginResult::allow();
/// assert!(result.continue_processing);
/// assert!(result.modified_payload.is_none());
///
/// // Deny
/// let result: PluginResult<TestPayload> = PluginResult::deny(
///     PluginViolation::new("forbidden", "not allowed")
/// );
/// assert!(!result.continue_processing);
/// assert!(result.violation.is_some());
/// ```
#[derive(Debug)]
pub struct PluginResult<P: PluginPayload> {
    /// Whether the pipeline should continue processing.
    /// `false` halts the pipeline (deny). Only respected for
    /// Sequential and Concurrent modes.
    pub continue_processing: bool,

    /// Modified payload. `None` means no content modification.
    /// Only accepted from Sequential and Transform mode plugins.
    pub modified_payload: Option<P>,

    /// Modified extensions. `None` means no extension changes.
    /// Return an `OwnedExtensions` from `extensions.cow_copy()`.
    /// The executor validates (immutable unchanged, monotonic superset)
    /// and merges back into the pipeline's `Extensions`.
    pub modified_extensions: Option<crate::hooks::payload::OwnedExtensions>,

    /// Policy violation. Present when `continue_processing` is `false`.
    pub violation: Option<PluginViolation>,

    /// Optional metadata from the plugin (telemetry, diagnostics).
    /// Not used for scheduling or policy decisions.
    pub metadata: Option<serde_json::Value>,
}

impl<P: PluginPayload> PluginResult<P> {
    /// Allow — payload continues unchanged, no extension changes.
    pub fn allow() -> Self {
        Self {
            continue_processing: true,
            modified_payload: None,
            modified_extensions: None,

            violation: None,
            metadata: None,
        }
    }

    /// Deny — pipeline halts with a violation.
    pub fn deny(violation: PluginViolation) -> Self {
        Self {
            continue_processing: false,
            modified_payload: None,
            modified_extensions: None,

            violation: Some(violation),
            metadata: None,
        }
    }

    /// Modify payload only — extensions unchanged.
    pub fn modify_payload(payload: P) -> Self {
        Self {
            continue_processing: true,
            modified_payload: Some(payload),
            modified_extensions: None,

            violation: None,
            metadata: None,
        }
    }

    /// Modify extensions only — payload unchanged.
    /// Takes an `OwnedExtensions` from `extensions.cow_copy()`.
    pub fn modify_extensions(extensions: crate::hooks::payload::OwnedExtensions) -> Self {
        Self {
            continue_processing: true,
            modified_payload: None,
            modified_extensions: Some(extensions),

            violation: None,
            metadata: None,
        }
    }

    /// Modify both payload and extensions.
    /// Takes an `OwnedExtensions` from `extensions.cow_copy()`.
    pub fn modify(payload: P, extensions: crate::hooks::payload::OwnedExtensions) -> Self {
        Self {
            continue_processing: true,
            modified_payload: Some(payload),
            modified_extensions: Some(extensions),

            violation: None,
            metadata: None,
        }
    }

    /// Whether this result represents a denial.
    pub fn is_denied(&self) -> bool {
        !self.continue_processing
    }

    /// Whether this result carries a modified payload.
    pub fn is_payload_modified(&self) -> bool {
        self.modified_payload.is_some()
    }

    /// Whether this result carries modified extensions.
    pub fn is_extensions_modified(&self) -> bool {
        self.modified_extensions.is_some()
    }
}

impl<P: PluginPayload> Default for PluginResult<P> {
    fn default() -> Self {
        Self::allow()
    }
}
