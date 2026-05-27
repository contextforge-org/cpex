// Location: ./crates/cpex-core/src/extensions/delegation.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// DelegationExtension — token delegation chain.
// Mirrors cpex/framework/extensions/delegation.py.

use serde::{Deserialize, Serialize};

/// A single hop in the delegation chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationHop {
    /// Subject ID of the delegator.
    pub subject_id: String,

    /// Subject type of the delegator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// Target audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// Scopes granted in this delegation step.
    #[serde(default)]
    pub scopes_granted: Vec<String>,

    /// Timestamp of delegation (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    /// Time-to-live in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,

    /// Delegation strategy used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,

    /// Whether this hop was resolved from cache.
    #[serde(default)]
    pub from_cache: bool,
}

/// Delegation chain extension.
///
/// Append-only — each hop narrows scope. A delegate cannot have
/// more permissions than the delegator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationExtension {
    /// Ordered delegation chain.
    #[serde(default)]
    pub chain: Vec<DelegationHop>,

    /// Chain depth (number of hops).
    #[serde(default)]
    pub depth: usize,

    /// Subject ID of the original delegator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_subject_id: Option<String>,

    /// Subject ID of the current actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_subject_id: Option<String>,

    /// Whether delegation has occurred.
    #[serde(default)]
    pub delegated: bool,

    /// Age of the delegation chain in seconds.
    #[serde(default)]
    pub age_seconds: f64,
}

impl DelegationExtension {
    /// Append a delegation hop (monotonic — cannot remove).
    pub fn append_hop(&mut self, hop: DelegationHop) {
        self.chain.push(hop);
        self.depth = self.chain.len();
        self.delegated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_starts_empty() {
        let del = DelegationExtension::default();
        assert!(del.chain.is_empty());
        assert_eq!(del.depth, 0);
        assert!(!del.delegated);
    }

    #[test]
    fn test_append_hop() {
        let mut del = DelegationExtension::default();
        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            scopes_granted: vec!["read_hr".into()],
            ..Default::default()
        });

        assert_eq!(del.chain.len(), 1);
        assert_eq!(del.depth, 1);
        assert!(del.delegated);
        assert_eq!(del.chain[0].subject_id, "alice");
        assert_eq!(del.chain[0].scopes_granted, vec!["read_hr"]);
    }

    #[test]
    fn test_append_multiple_hops() {
        let mut del = DelegationExtension {
            origin_subject_id: Some("alice".into()),
            ..Default::default()
        };

        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            audience: Some("service-b".into()),
            scopes_granted: vec!["read".into(), "write".into()],
            strategy: Some("token_exchange".into()),
            ..Default::default()
        });

        del.append_hop(DelegationHop {
            subject_id: "service-b".into(),
            audience: Some("service-c".into()),
            scopes_granted: vec!["read".into()], // narrowed scope
            ..Default::default()
        });

        assert_eq!(del.chain.len(), 2);
        assert_eq!(del.depth, 2);
        // Second hop has narrower scope
        assert_eq!(del.chain[1].scopes_granted, vec!["read"]);
    }

    #[test]
    fn test_delegation_serde_roundtrip() {
        let mut del = DelegationExtension {
            origin_subject_id: Some("alice".into()),
            actor_subject_id: Some("service-b".into()),
            ..Default::default()
        };
        del.append_hop(DelegationHop {
            subject_id: "alice".into(),
            subject_type: Some("user".into()),
            scopes_granted: vec!["admin".into()],
            from_cache: true,
            ..Default::default()
        });

        let json = serde_json::to_string(&del).unwrap();
        let deserialized: DelegationExtension = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.depth, 1);
        assert!(deserialized.delegated);
        assert_eq!(deserialized.origin_subject_id.as_deref(), Some("alice"));
        assert!(deserialized.chain[0].from_cache);
    }
}
