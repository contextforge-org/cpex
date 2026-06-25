// Location: ./builtins/plugins/elicitation-ciba/src/store.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Correlation store — maps an elicitation id (the CIBA `auth_req_id`,
// which the agent echoes on retry) to the state the handler needs across
// the dispatch → check → validate lifetime: who the expected approver is
// and, once `check` succeeds, the token the OP returned (cached so
// `validate` can read the approver claim without re-polling — a second
// CIBA poll after success fails).
//
// v1 is in-process (`InMemoryCorrelationStore`). That survives retries
// within one gateway process — enough for a single-node demo. The trait
// is the seam for a Valkey-backed store (cross-node / cross-restart),
// which reuses `apl-session-valkey`'s connection handling — deferred.

use std::collections::HashMap;
use std::sync::Mutex;

/// State tracked per in-flight elicitation.
#[derive(Debug, Clone)]
pub struct Correlation {
    /// The approver the backchannel request named (`login_hint`), to
    /// cross-check the resolved token against at `validate`.
    pub expected_approver: String,
    /// The token the OP returned once the human approved. `None` until
    /// `check` sees a successful CIBA poll. Cached because the OP only
    /// hands the token back once.
    pub resolved_token: Option<String>,
}

/// Storage for in-flight CIBA correlations, keyed by elicitation id.
pub trait CorrelationStore: Send + Sync {
    /// Record a freshly dispatched elicitation.
    fn put(&self, id: &str, correlation: Correlation);
    /// Read the current state for an id, if present.
    fn get(&self, id: &str) -> Option<Correlation>;
    /// Cache the resolved token against an existing correlation. No-op if
    /// the id is unknown.
    fn set_token(&self, id: &str, token: String);
}

/// In-process correlation store. Thread-safe; the plugin instance is
/// shared across requests, so this map persists across an agent's retries
/// within one gateway process.
#[derive(Debug, Default)]
pub struct InMemoryCorrelationStore {
    inner: Mutex<HashMap<String, Correlation>>,
}

impl InMemoryCorrelationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CorrelationStore for InMemoryCorrelationStore {
    fn put(&self, id: &str, correlation: Correlation) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.to_string(), correlation);
    }

    fn get(&self, id: &str) -> Option<Correlation> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned()
    }

    fn set_token(&self, id: &str, token: String) {
        if let Some(c) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(id)
        {
            c.resolved_token = Some(token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let store = InMemoryCorrelationStore::new();
        store.put(
            "req-1",
            Correlation { expected_approver: "alice".into(), resolved_token: None },
        );
        let c = store.get("req-1").expect("present");
        assert_eq!(c.expected_approver, "alice");
        assert!(c.resolved_token.is_none());
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn set_token_caches_on_existing() {
        let store = InMemoryCorrelationStore::new();
        store.put(
            "req-1",
            Correlation { expected_approver: "alice".into(), resolved_token: None },
        );
        store.set_token("req-1", "tok.123".into());
        assert_eq!(store.get("req-1").unwrap().resolved_token.as_deref(), Some("tok.123"));
        // Unknown id is a silent no-op.
        store.set_token("missing", "x".into());
        assert!(store.get("missing").is_none());
    }
}
