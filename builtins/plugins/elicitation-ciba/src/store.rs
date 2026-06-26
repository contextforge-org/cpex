// Location: ./builtins/plugins/elicitation-ciba/src/store.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Correlation store — maps an elicitation id (the CIBA `auth_req_id`,
// which the agent echoes on retry) to the state the handler needs across
// the dispatch → check → validate lifetime: who the *expected* approver is
// (`login_hint`, set at dispatch) and, once `check` sees a successful poll,
// who *actually* approved (the approver claim extracted from the OP token).
//
// # Why we store the extracted claim, not the token
//
// CIBA hands the token back exactly once (a second poll on the same
// `auth_req_id` fails), and `validate` runs on a later request than
// `check` — so the relevant fact must be carried across. We extract the
// approver claim at `check` and store *that string*, then drop the token.
// `validate` compares the two stored strings (expected vs resolved); it
// never needs the token. This keeps a **bearer credential out of the
// store at rest** — so even a leaked/co-tenant store reveals only "who
// approved what," never a usable token. (The `require_step_up` path,
// which forwards the CIBA token, is separate and does not use this store.)
//
// v1 is in-process (`InMemoryCorrelationStore`). That survives retries
// within one gateway process — enough for a single-node demo. The trait
// is the seam for a Valkey-backed store (cross-node / cross-restart) —
// deferred; when added, the CIBA store should use its own instance or an
// ACL-scoped user so it is isolated from the session-store keyspace.

use std::collections::HashMap;
use std::sync::Mutex;

/// State tracked per in-flight elicitation.
#[derive(Debug, Clone)]
pub struct Correlation {
    /// The approver the backchannel request named (`login_hint`), set at
    /// dispatch. `validate` cross-checks the resolved approver against it.
    pub expected_approver: String,
    /// Who actually approved — the approver claim (e.g. `preferred_username`)
    /// extracted from the OP token at `check`. `None` until a successful
    /// poll resolves it. We keep the **extracted claim, not the token**, so
    /// no bearer credential sits in the store at rest.
    pub resolved_approver: Option<String>,
}

/// Storage for in-flight CIBA correlations, keyed by elicitation id.
pub trait CorrelationStore: Send + Sync {
    /// Record a freshly dispatched elicitation.
    fn put(&self, id: &str, correlation: Correlation);
    /// Read the current state for an id, if present.
    fn get(&self, id: &str) -> Option<Correlation>;
    /// Record who approved (the extracted claim) against an existing
    /// correlation. No-op if the id is unknown.
    fn set_resolved_approver(&self, id: &str, approver: String);
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

    fn set_resolved_approver(&self, id: &str, approver: String) {
        if let Some(c) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(id)
        {
            c.resolved_approver = Some(approver);
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
            Correlation { expected_approver: "alice".into(), resolved_approver: None },
        );
        let c = store.get("req-1").expect("present");
        assert_eq!(c.expected_approver, "alice");
        assert!(c.resolved_approver.is_none());
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn set_resolved_approver_records_on_existing() {
        let store = InMemoryCorrelationStore::new();
        store.put(
            "req-1",
            Correlation { expected_approver: "alice".into(), resolved_approver: None },
        );
        store.set_resolved_approver("req-1", "alice".into());
        assert_eq!(store.get("req-1").unwrap().resolved_approver.as_deref(), Some("alice"));
        // Unknown id is a silent no-op.
        store.set_resolved_approver("missing", "x".into());
        assert!(store.get("missing").is_none());
    }
}
