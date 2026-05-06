// Location: ./crates/cpex-core/src/hooks/payload.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// PluginPayload trait and Extensions stub.
//
// PluginPayload is the base trait for all hook payloads, mirroring
// Python's PluginPayload(BaseModel, frozen=True). All payloads in
// the framework implement this trait, giving the executor and
// registry a common bound for type safety.
//
// The trait is object-safe — the executor works with `Box<dyn PluginPayload>`
// instead of `Box<dyn Any>`, catching type errors at compile time.
// Downcasting to concrete types uses the `as_any()` method.
//
// Extensions is the typed container for all message extensions
// (security, delegation, HTTP, meta, etc.). It is always passed
// as a separate parameter to handlers — never inside the payload.
// This allows per-plugin capability filtering and independent
// modification without copying the payload.

use std::any::Any;
use std::fmt;

// Re-export Extensions and OwnedExtensions from the extensions module.
// These are the typed containers for all extension data. They live in
// extensions/container.rs but are re-exported here for backward
// compatibility with existing code that imports from hooks::payload.
pub use crate::extensions::{Extensions, Guarded, MetaExtension, OwnedExtensions, WriteToken};

// ---------------------------------------------------------------------------
// PluginPayload Trait
// ---------------------------------------------------------------------------

/// Base trait for all hook payloads.
///
/// Mirrors Python's `PluginPayload(BaseModel, frozen=True)`. Every
/// payload type in the framework implements this trait. The executor
/// and registry use `Box<dyn PluginPayload>` (not `Box<dyn Any>`)
/// for type-safe dispatch.
///
/// The trait is **object-safe** — it can be used behind `Box`, `&`,
/// and `Arc` without knowing the concrete type. This is achieved by
/// providing `clone_boxed()` instead of requiring `Clone` directly
/// (which is not object-safe), and `as_any()` / `as_any_mut()` for
/// downcasting to the concrete type when needed.
///
/// Payloads are:
/// - Cloneable via `clone_boxed()` — the executor uses this for COW
///   when a modifying plugin (Sequential or Transform) needs ownership.
/// - `Send + Sync` — payloads may be shared across threads for
///   Concurrent mode plugins.
/// - `'static` — payloads must be owned types (no borrowed references).
///
/// Extensions are **not** part of the payload. They are passed as a
/// separate `&Extensions` parameter to handlers.
///
/// # Examples
///
/// ```
/// use cpex_core::hooks::payload::PluginPayload;
///
/// #[derive(Debug, Clone)]
/// struct RateLimitPayload {
///     client_id: String,
///     request_count: u64,
/// }
///
/// impl PluginPayload for RateLimitPayload {
///     fn clone_boxed(&self) -> Box<dyn PluginPayload> {
///         Box::new(self.clone())
///     }
///     fn as_any(&self) -> &dyn std::any::Any { self }
///     fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
/// }
/// ```
pub trait PluginPayload: Send + Sync + 'static {
    /// Clone this payload into a new `Box<dyn PluginPayload>`.
    ///
    /// Used by the executor for copy-on-write: read-only modes borrow
    /// the payload, modifying modes receive a clone via this method.
    fn clone_boxed(&self) -> Box<dyn PluginPayload>;

    /// Downcast to a concrete type via `&dyn Any`.
    ///
    /// Used by typed handler wrappers to recover the concrete payload
    /// type from `Box<dyn PluginPayload>`.
    fn as_any(&self) -> &dyn Any;

    /// Downcast to a concrete type via `&mut dyn Any`.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl fmt::Debug for dyn PluginPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn PluginPayload")
    }
}

// ---------------------------------------------------------------------------
// Blanket helper macro for implementing PluginPayload
// ---------------------------------------------------------------------------

/// Implements `PluginPayload` for a type that is `Clone + Send + Sync + 'static`.
///
/// Saves boilerplate — instead of writing the three methods manually,
/// just invoke this macro:
///
/// ```
/// use cpex_core::impl_plugin_payload;
///
/// #[derive(Debug, Clone)]
/// struct MyPayload { value: i32 }
///
/// impl_plugin_payload!(MyPayload);
/// ```
#[macro_export]
macro_rules! impl_plugin_payload {
    ($ty:ty) => {
        impl $crate::hooks::payload::PluginPayload for $ty {
            fn clone_boxed(&self) -> Box<dyn $crate::hooks::payload::PluginPayload> {
                Box::new(self.clone())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }
        }
    };
}
