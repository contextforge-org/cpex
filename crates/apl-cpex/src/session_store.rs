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
use std::sync::RwLock;

use async_trait::async_trait;

/// Pluggable session-state backend. Implementations must be `Send + Sync`
/// — the same store is shared across all concurrent requests.
///
/// Invariants:
/// - `append_labels` is **monotonic** — labels added to a session never
///   come back out. Removal (declassification) is a separate operation
///   not covered by v0.
/// - Empty `load_labels` for an unknown `session_id` is the right
///   response — non-session traffic shouldn't fail, it just sees no
///   accumulated state.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Load the union of labels accumulated for the session. Empty for
    /// new or unknown sessions.
    async fn load_labels(&self, session_id: &str) -> Vec<String>;

    /// Append labels to the session. Existing labels are kept; new ones
    /// are unioned in. Caller has already deduped against `load_labels`
    /// in the hot path, but the store re-dedups defensively.
    async fn append_labels(&self, session_id: &str, labels: &[String]);
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
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn load_labels(&self, session_id: &str) -> Vec<String> {
        let r = self.inner.read().unwrap_or_else(|p| p.into_inner());
        r.get(session_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    async fn append_labels(&self, session_id: &str, labels: &[String]) {
        if labels.is_empty() {
            return;
        }
        let mut w = self.inner.write().unwrap_or_else(|p| p.into_inner());
        let entry = w.entry(session_id.to_string()).or_default();
        for l in labels {
            entry.insert(l.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn load_for_unknown_session_is_empty() {
        let store = MemorySessionStore::new();
        assert!(store.load_labels("nonexistent").await.is_empty());
    }

    #[tokio::test]
    async fn append_then_load_roundtrips() {
        let store = MemorySessionStore::new();
        store
            .append_labels("sess-1", &["PII".to_string(), "INTERNAL".to_string()])
            .await;
        let mut labels = store.load_labels("sess-1").await;
        labels.sort();
        assert_eq!(labels, vec!["INTERNAL".to_string(), "PII".to_string()]);
    }

    #[tokio::test]
    async fn append_is_monotonic_dedupes() {
        let store = MemorySessionStore::new();
        store.append_labels("sess-1", &["PII".to_string()]).await;
        store
            .append_labels("sess-1", &["PII".to_string(), "PII".to_string()])
            .await;
        let labels = store.load_labels("sess-1").await;
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], "PII");
    }

    #[tokio::test]
    async fn sessions_are_isolated() {
        let store = MemorySessionStore::new();
        store.append_labels("a", &["X".to_string()]).await;
        store.append_labels("b", &["Y".to_string()]).await;
        assert_eq!(store.load_labels("a").await, vec!["X".to_string()]);
        assert_eq!(store.load_labels("b").await, vec!["Y".to_string()]);
    }

    #[tokio::test]
    async fn shared_arc_observes_writes() {
        let store: Arc<dyn SessionStore> = Arc::new(MemorySessionStore::new());
        let c1 = Arc::clone(&store);
        let c2 = Arc::clone(&store);
        c1.append_labels("sess", &["Z".to_string()]).await;
        assert_eq!(c2.load_labels("sess").await, vec!["Z".to_string()]);
    }
}
