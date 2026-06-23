// Location: ./crates/apl-cpex/src/session_store.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `SessionStore` — pluggable backend for cross-request session state.
// v0 surface is intentionally tiny: monotonic label append + load. That
// covers `extensions.security.labels` persistence, which is the only
// session-scoped state APL needs today.
//
// # Why a trait
//
// State that survives between requests in the same session (accumulated
// taint labels, delegation history, conversation context) needs to be
// pluggable: in-memory for tests and single-process deployments, Redis
// or DynamoDB for distributed ones. The previous Python implementation
// had a `SessionState` abstraction with the same shape; this is the
// Rust port. Only the labels surface lands in v0 — delegation hops,
// conversation history, and arbitrary KV come when their consumers do.
//
// # String-typed deliberately
//
// The trait stays string-typed (`Vec<String>` for labels) rather than
// reaching into cpex-core's `MonotonicSet<String>` so non-CMF bridges
// (future apl-mcp, apl-langgraph, etc.) can reuse it without dragging
// CPEX types into their surface. `CmfPluginInvoker` does the
// hydration/persistence into/out of `Extensions.security.labels`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

/// Error returned by a `SessionStore` when the backing store could not
/// satisfy a request. Distributed backends (e.g. Valkey) surface
/// connectivity/timeout/protocol failures and undecodable responses
/// here so callers can **fail closed** rather than silently treating a
/// backend failure as "no accumulated labels".
///
/// String-typed deliberately, matching the trait's own philosophy (see
/// the module header): the error stays free of backend-specific types so
/// non-CMF bridges and the cross-crate `apl-session-valkey` backend can
/// construct it without dragging dependencies into this surface.
///
/// Note the distinction this enables: a **positively-confirmed key-miss**
/// (unknown session) is `Ok(empty)`, NOT an error — only a genuine
/// backend failure is an `Err`.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    /// The backing store was unreachable, timed out, returned an error,
    /// or returned a response that could not be decoded into the
    /// expected representation. Callers fail closed on this.
    #[error("session store backend error: {0}")]
    Backend(String),
}

/// Pluggable session-state backend. Implementations must be `Send + Sync`
/// — the same store is shared across all concurrent requests.
///
/// Invariants:
/// - `append_labels` is **monotonic** — labels added to a session never
///   come back out. Removal (declassification) is a separate operation
///   not covered by v0.
/// - `load_labels` for an unknown `session_id` returns `Ok(empty)` — a
///   positively-confirmed key-miss is the right response for non-session
///   traffic, and is distinct from a backend failure (`Err`).
/// - Both methods return `Result` so a distributed backend can propagate
///   failures and the caller can fail the request closed. The in-process
///   [`MemorySessionStore`] is infallible and always returns `Ok`.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Load the union of labels accumulated for the session. `Ok(empty)`
    /// for new or unknown sessions (a confirmed key-miss); `Err` only on
    /// a backend failure.
    async fn load_labels(&self, session_id: &str) -> Result<Vec<String>, SessionStoreError>;

    /// Append labels to the session. Existing labels are kept; new ones
    /// are unioned in. Caller has already deduped against `load_labels`
    /// in the hot path, but the store re-dedups defensively. `Err` only
    /// on a backend failure.
    async fn append_labels(
        &self,
        session_id: &str,
        labels: &[String],
    ) -> Result<(), SessionStoreError>;
}

/// Factory the visitor consults when it encounters a
/// `global.apl.session_store` block in the unified config. Mirrors
/// [`apl_core::step::PdpFactory`]: each factory advertises a `kind()`
/// string matching the YAML block's `kind:` field, and `build` turns the
/// block into a live store. Registered up front via
/// [`crate::AplOptions::session_store_factories`]; the visitor selects
/// the active store from config during its global-config walk, before
/// any route handler captures the store.
///
/// `build` errors are construction-time (bad config, unresolvable
/// endpoint) and surface as a config-load failure — distinct from the
/// request-time [`SessionStoreError`] the trait methods return.
pub trait SessionStoreFactory: Send + Sync {
    /// The `kind:` discriminator this factory builds (e.g. `"valkey"`).
    fn kind(&self) -> &str;

    /// Build a store from its config block. The whole
    /// `global.apl.session_store` mapping is passed so the factory can
    /// read its own keys (endpoint, TLS, auth, prefix, TTL, …).
    fn build(
        &self,
        config: &serde_yaml::Value,
    ) -> Result<Arc<dyn SessionStore>, Box<dyn std::error::Error + Send + Sync>>;
}

/// In-process `SessionStore` backed by a `HashMap` of `HashSet`s. Suitable
/// for tests, single-process deployments, and as the default when no
/// distributed store is configured. Cloning the store via `Arc` shares
/// state across all consumers.
#[derive(Default)]
pub struct MemorySessionStore {
    /// `RwLock` because reads (load_labels at request start) outnumber
    /// writes (append at request end) in steady state — and lock
    /// contention is bounded by the per-session level of concurrency,
    /// not request volume.
    inner: RwLock<HashMap<String, HashSet<String>>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the entire store. Test/diagnostic helper — production
    /// callers should go through the trait so the backing implementation
    /// stays swappable.
    pub fn snapshot(&self) -> HashMap<String, HashSet<String>> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn load_labels(&self, session_id: &str) -> Result<Vec<String>, SessionStoreError> {
        let r = self.inner.read().unwrap_or_else(|p| p.into_inner());
        Ok(r.get(session_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn append_labels(
        &self,
        session_id: &str,
        labels: &[String],
    ) -> Result<(), SessionStoreError> {
        if labels.is_empty() {
            return Ok(());
        }
        let mut w = self.inner.write().unwrap_or_else(|p| p.into_inner());
        let entry = w.entry(session_id.to_string()).or_default();
        for l in labels {
            entry.insert(l.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn load_for_unknown_session_is_empty() {
        let store = MemorySessionStore::new();
        // Unknown session is a confirmed key-miss: Ok(empty), not Err.
        assert!(store.load_labels("nonexistent").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn append_then_load_roundtrips() {
        let store = MemorySessionStore::new();
        store
            .append_labels("sess-1", &["PII".to_string(), "INTERNAL".to_string()])
            .await
            .unwrap();
        let mut labels = store.load_labels("sess-1").await.unwrap();
        labels.sort();
        assert_eq!(labels, vec!["INTERNAL".to_string(), "PII".to_string()]);
    }

    #[tokio::test]
    async fn append_is_monotonic_dedupes() {
        let store = MemorySessionStore::new();
        store
            .append_labels("sess-1", &["PII".to_string()])
            .await
            .unwrap();
        store
            .append_labels("sess-1", &["PII".to_string(), "PII".to_string()])
            .await
            .unwrap();
        let labels = store.load_labels("sess-1").await.unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], "PII");
    }

    #[tokio::test]
    async fn sessions_are_isolated() {
        let store = MemorySessionStore::new();
        store.append_labels("a", &["X".to_string()]).await.unwrap();
        store.append_labels("b", &["Y".to_string()]).await.unwrap();
        assert_eq!(store.load_labels("a").await.unwrap(), vec!["X".to_string()]);
        assert_eq!(store.load_labels("b").await.unwrap(), vec!["Y".to_string()]);
    }

    #[tokio::test]
    async fn shared_arc_observes_writes() {
        let store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
        let c1 = Arc::clone(&store);
        let c2 = Arc::clone(&store);
        c1.append_labels("sess", &["Z".to_string()]).await.unwrap();
        assert_eq!(c2.load_labels("sess").await.unwrap(), vec!["Z".to_string()]);
    }
}
