// Location: ./crates/cpex-core/src/extensions/security.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// SecurityExtension — labels, classification, identity, data policy.
// Mirrors cpex/framework/extensions/security.py.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::monotonic::MonotonicSet;

/// Subject type for identity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Agent,
    Service,
    System,
}

/// Authenticated subject identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectExtension {
    /// Subject identifier (e.g., JWT sub).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Subject type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<SubjectType>,

    /// Assigned roles.
    #[serde(default)]
    pub roles: HashSet<String>,

    /// Granted permissions.
    #[serde(default)]
    pub permissions: HashSet<String>,

    /// Team memberships.
    #[serde(default)]
    pub teams: HashSet<String>,

    /// Raw claims (e.g., JWT claims).
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

/// Security profile for a managed object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectSecurityProfile {
    /// Who manages this object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,

    /// Required permissions.
    #[serde(default)]
    pub permissions: Vec<String>,

    /// Trust domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,

    /// Data scope.
    #[serde(default)]
    pub data_scope: Vec<String>,
}

/// Retention policy for data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum age in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,

    /// Policy name.
    #[serde(default)]
    pub policy: String,

    /// Deletion timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<String>,
}

/// Data policy for a named data element.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataPolicy {
    /// Labels to apply.
    #[serde(default)]
    pub apply_labels: Vec<String>,

    /// Allowed actions (None = all allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_actions: Option<Vec<String>>,

    /// Denied actions.
    #[serde(default)]
    pub denied_actions: Vec<String>,

    /// Retention policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionPolicy>,
}

/// This agent's own workload identity.
///
/// Distinct from `SubjectExtension` which represents the *caller*.
/// `AgentIdentity` represents *this agent/service* — its own
/// workload identity, OAuth client_id, and trust domain.
///
/// Populated by the host before the pipeline runs. Plugins can
/// make decisions based on both who is calling (Subject) and
/// which agent is processing (AgentIdentity).
///
/// Maps to AuthBridge's `AgentIdentity` and the Go bindings'
/// `SecurityExtension.Agent`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// OAuth client_id of this agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Workload identity URI (SPIFFE, k8s service account, platform-specific).
    /// e.g., `spiffe://example.com/ns/team1/sa/weather-tool`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,

    /// Trust domain of the workload identity.
    /// e.g., `example.com`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
}

/// Security-related extensions.
///
/// Carries security labels (monotonic add-only), classification,
/// authenticated caller identity (subject), this agent's own
/// workload identity (agent), object security profiles, and
/// data policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityExtension {
    /// Security labels (monotonic — add-only via MonotonicSet).
    /// No remove() method — enforced at compile time.
    #[serde(default)]
    pub labels: MonotonicSet<String>,

    /// Data classification level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,

    /// Authenticated caller identity (who is calling).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectExtension>,

    /// This agent's own workload identity (who this agent is).
    /// Populated by the host, not by plugins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentIdentity>,

    /// Authentication method used (e.g., "jwt", "mtls", "spiffe", "api_key").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,

    /// Object security profiles keyed by object name.
    #[serde(default)]
    pub objects: HashMap<String, ObjectSecurityProfile>,

    /// Data policies keyed by data element name.
    #[serde(default)]
    pub data: HashMap<String, DataPolicy>,
}

impl SecurityExtension {
    /// Add a security label (monotonic — cannot remove).
    pub fn add_label(&mut self, label: impl Into<String>) {
        self.labels.add_label(label);
    }

    /// Check if a label exists (case-insensitive).
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.has_label(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_labels_monotonic() {
        let mut sec = SecurityExtension::default();
        sec.add_label("PII");
        sec.add_label("HIPAA");
        assert!(sec.has_label("PII"));
        assert!(sec.has_label("pii")); // case-insensitive
        assert!(sec.has_label("HIPAA"));
        assert!(!sec.has_label("SOX"));
    }

    #[test]
    fn test_security_classification() {
        let sec = SecurityExtension {
            classification: Some("confidential".into()),
            ..Default::default()
        };
        assert_eq!(sec.classification.as_deref(), Some("confidential"));
    }

    #[test]
    fn test_subject_extension() {
        let subject = SubjectExtension {
            id: Some("alice".into()),
            subject_type: Some(SubjectType::User),
            roles: ["admin".to_string(), "hr".to_string()].into(),
            permissions: ["read_all".to_string()].into(),
            teams: ["engineering".to_string()].into(),
            claims: [("iss".to_string(), "auth.example.com".to_string())].into(),
        };
        assert_eq!(subject.id.as_deref(), Some("alice"));
        assert_eq!(subject.subject_type, Some(SubjectType::User));
        assert!(subject.roles.contains("admin"));
        assert!(subject.permissions.contains("read_all"));
        assert!(subject.teams.contains("engineering"));
        assert_eq!(subject.claims.get("iss").unwrap(), "auth.example.com");
    }

    #[test]
    fn test_agent_identity() {
        let agent = AgentIdentity {
            client_id: Some("weather-agent".into()),
            workload_id: Some("spiffe://example.com/ns/team1/sa/weather-tool".into()),
            trust_domain: Some("example.com".into()),
        };
        assert_eq!(agent.client_id.as_deref(), Some("weather-agent"));
        assert_eq!(
            agent.workload_id.as_deref(),
            Some("spiffe://example.com/ns/team1/sa/weather-tool")
        );
        assert_eq!(agent.trust_domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_agent_identity_default() {
        let agent = AgentIdentity::default();
        assert!(agent.client_id.is_none());
        assert!(agent.workload_id.is_none());
        assert!(agent.trust_domain.is_none());
    }

    #[test]
    fn test_security_with_agent_and_subject() {
        let sec = SecurityExtension {
            labels: {
                let mut l = super::super::MonotonicSet::new();
                l.add_label("PII");
                l
            },
            classification: Some("confidential".into()),
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                subject_type: Some(SubjectType::User),
                ..Default::default()
            }),
            agent: Some(AgentIdentity {
                client_id: Some("hr-agent".into()),
                workload_id: Some("spiffe://corp.com/hr-agent".into()),
                trust_domain: Some("corp.com".into()),
            }),
            auth_method: Some("jwt".into()),
            ..Default::default()
        };

        // Caller identity
        assert_eq!(sec.subject.as_ref().unwrap().id.as_deref(), Some("alice"));
        // Agent identity (distinct from caller)
        assert_eq!(
            sec.agent.as_ref().unwrap().client_id.as_deref(),
            Some("hr-agent")
        );
        assert_eq!(
            sec.agent.as_ref().unwrap().trust_domain.as_deref(),
            Some("corp.com")
        );
        // Auth method
        assert_eq!(sec.auth_method.as_deref(), Some("jwt"));
        // Labels
        assert!(sec.has_label("PII"));
    }

    #[test]
    fn test_security_serde_roundtrip() {
        let mut sec = SecurityExtension::default();
        sec.add_label("PII");
        sec.classification = Some("internal".into());
        sec.agent = Some(AgentIdentity {
            client_id: Some("my-agent".into()),
            ..Default::default()
        });
        sec.auth_method = Some("mtls".into());

        let json = serde_json::to_string(&sec).unwrap();
        let deserialized: SecurityExtension = serde_json::from_str(&json).unwrap();

        assert!(deserialized.has_label("PII"));
        assert_eq!(deserialized.classification.as_deref(), Some("internal"));
        assert_eq!(
            deserialized.agent.as_ref().unwrap().client_id.as_deref(),
            Some("my-agent")
        );
        assert_eq!(deserialized.auth_method.as_deref(), Some("mtls"));
    }

    #[test]
    fn test_object_security_profile() {
        let profile = ObjectSecurityProfile {
            managed_by: Some("hr-system".into()),
            permissions: vec!["read".into(), "write".into()],
            trust_domain: Some("corp.com".into()),
            data_scope: vec!["employee_data".into()],
        };
        assert_eq!(profile.managed_by.as_deref(), Some("hr-system"));
        assert_eq!(profile.permissions.len(), 2);
    }

    #[test]
    fn test_data_policy() {
        let policy = DataPolicy {
            apply_labels: vec!["PII".into()],
            allowed_actions: Some(vec!["read".into()]),
            denied_actions: vec!["delete".into()],
            retention: Some(RetentionPolicy {
                max_age_seconds: Some(86400),
                policy: "30-day".into(),
                delete_after: Some("2026-05-01".into()),
            }),
        };
        assert_eq!(policy.apply_labels[0], "PII");
        assert!(policy.retention.is_some());
        assert_eq!(
            policy.retention.as_ref().unwrap().max_age_seconds,
            Some(86400)
        );
    }
}
