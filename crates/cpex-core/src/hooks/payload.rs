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

    /// Canonical bytes of this payload for content-addressed audit provenance,
    /// or `None` for payloads that can't or shouldn't be serialized (the
    /// default). The bytes feed a content hash — **only the digest is
    /// retained, never the bytes** — so a node's provenance is recorded
    /// without re-spilling its (possibly sensitive) content. Computed only
    /// when content provenance is enabled, so the default keeps the hot path
    /// free.
    ///
    /// **Byte-stability (what a consumer may assume).**
    /// `impl_plugin_payload!(_, audit_serialize)` derives this by round-tripping
    /// through `serde_json::Value` — whose `Map` is a `BTreeMap`, so object keys
    /// are sorted. Identical content therefore serializes to identical bytes
    /// across runs and processes, and **two equal digests mean "same content"
    /// within a deployment**. It is *sorted-key JSON, not full RFC 8785 (JCS)*:
    /// number formatting follows `serde_json` and is stable within a
    /// `serde_json` version but is not guaranteed by a canonicalization spec
    /// across toolchains. So treat digest equality as same-content within a
    /// build; do not assume cross-toolchain canonicalization. A hand-written
    /// `audit_bytes` must preserve this property (a canonical, deterministic
    /// encoding) or its hashes will not be comparable.
    fn audit_bytes(&self) -> Option<Vec<u8>> {
        None
    }
}

/// The content hash of canonical audit bytes — a content-addressed provenance
/// ref (`sha256:<hex>`). Only the digest is kept; the bytes are never retained.
pub fn content_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl fmt::Debug for dyn PluginPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn PluginPayload")
    }
}

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
    // `audit_serialize`: opt in to content-provenance hashing for a
    // `Serialize` payload. `audit_bytes` round-trips through `Value` so object
    // keys are sorted (serde_json's Map is a BTreeMap without `preserve_order`)
    // — canonical, cross-process-stable bytes even when the payload holds
    // HashMaps.
    ($ty:ty, audit_serialize) => {
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
            fn audit_bytes(&self) -> Option<Vec<u8>> {
                let value = serde_json::to_value(self).ok()?;
                serde_json::to_vec(&value).ok()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Clone, Serialize)]
    struct Doc {
        a: u32,
        note: String,
    }
    crate::impl_plugin_payload!(Doc, audit_serialize);

    #[derive(Clone)]
    struct Opaque;
    crate::impl_plugin_payload!(Opaque);

    #[test]
    fn audit_serialize_is_some_and_deterministic() {
        let d = Doc {
            a: 1,
            note: "hi".into(),
        };
        let b1 = d.audit_bytes().expect("serializable payload → Some");
        let b2 = d.clone().audit_bytes().expect("Some");
        assert_eq!(b1, b2, "canonical bytes are deterministic");
    }

    #[test]
    fn default_audit_bytes_is_none() {
        // A payload that did not opt into `audit_serialize` yields no bytes.
        assert!(Opaque.audit_bytes().is_none());
    }

    #[test]
    fn content_hash_is_prefixed_and_stable() {
        let h = content_hash(b"hello");
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), "sha256:".len() + 64, "sha256 hex is 64 chars");
        assert_eq!(content_hash(b"hello"), h, "deterministic");
        assert_ne!(
            content_hash(b"world"),
            h,
            "different input → different hash"
        );
    }
}
