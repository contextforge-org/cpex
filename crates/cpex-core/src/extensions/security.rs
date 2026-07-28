// Location: ./crates/cpex-core/src/extensions/security.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// SecurityExtension — labels, classification, identity, data policy.
// Mirrors cpex/framework/extensions/security.py.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// Trust classification for the OAuth client / gateway that brokered
/// the request. Distinct from the *user's* subject identity — the same
/// human can connect through a first-party browser flow or a
/// third-party agent, and policies often want to distinguish them.
///
/// `Custom(String)` lets operators carry a finer-grained vocabulary
/// (e.g. `"partner-tier-A"`) without forking the type. The enum is
/// `#[non_exhaustive]` so new well-known variants can be added later
/// without breaking external matches.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTrustLevel {
    /// First-party clients operated by the same org as this gateway.
    FirstParty,
    /// External third-party clients, integrated but not operated by us.
    ThirdParty,
    /// Internal infrastructure clients (control plane, ops tooling).
    Internal,
    /// Operator-defined trust level — string carried verbatim into
    /// policy. Lookups by value (Hash + Eq) work as long as both
    /// sides construct identical strings.
    #[serde(untagged)]
    Custom(String),
}

impl Default for ClientTrustLevel {
    /// Default to the most restrictive well-known level so a
    /// missing-or-misconfigured client doesn't silently inherit
    /// first-party privileges.
    fn default() -> Self {
        ClientTrustLevel::ThirdParty
    }
}

/// The OAuth client / gateway-access principal — *what application*
/// is brokering the request, as opposed to *which user* is using it
/// (`SubjectExtension`) and *which attested workload* is the network
/// peer (`WorkloadIdentity`). Populated from a client-credentials or
/// session JWT by an identity-resolver plugin (or supplied directly
/// by a trusted upstream gateway).
///
/// The shape is deliberately symmetric with `SubjectExtension` —
/// roles / permissions / teams / claims appear on both. That lets APL
/// policies write `client.roles.contains("partner")` and
/// `subject.roles.contains("admin")` with the same idiom; some IdPs
/// (Keycloak service accounts, Auth0 M2M apps, AWS IAM role grants)
/// attach RBAC grants to clients directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientExtension {
    /// OAuth `client_id` — required. Anchor identifier for the client.
    pub client_id: String,

    /// Human-readable client name from the IdP. Useful for audit logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// Trust classification — see [`ClientTrustLevel`].
    #[serde(default)]
    pub trust_level: ClientTrustLevel,

    /// OAuth scopes the IdP authorized for this client (across all
    /// audiences). Policy authors use this to gate on what the IdP
    /// believes the client is allowed to ask for, before checking
    /// whether the specific request stays within those scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_scopes: Vec<String>,

    /// OAuth audiences the IdP authorized this client to address.
    /// Different IdPs encode this differently; the resolver
    /// normalizes them into this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_audiences: Vec<String>,

    /// Platform-native RBAC roles attached to the client (Keycloak
    /// service-account-roles, Auth0 M2M permissions, IAM role grants).
    /// Distinct from `authorized_scopes` — scopes are OAuth-issued,
    /// roles are platform-issued.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,

    /// Platform-native permissions attached to the client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,

    /// Team / tenant / account memberships, for multi-tenant
    /// platforms that scope clients to organizational units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub teams: Vec<String>,

    /// Raw remaining JWT claims (or equivalent), keyed by claim name.
    /// `Value` (not `String`) because claim values can be booleans,
    /// numbers, nested objects, arrays — policy authors who reach
    /// here generally know the claim's expected shape.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub claims: HashMap<String, Value>,
}

/// SPIFFE-style workload identity, used for both inbound callers
/// (`SecurityExtension.caller_workload` — added in a subsequent slice)
/// and our own outbound identity (`SecurityExtension.this_workload`).
///
/// Distinct from `SubjectExtension` (the human/agent caller) and
/// `ClientExtension` (the OAuth client, added in a subsequent slice).
/// Where `Subject` is "who", `Client` is "what app", `Workload` is
/// "which attested process" — typically established at the network
/// edge via mTLS or a SPIFFE attestation API and never present on
/// the same request as an unauthenticated principal.
///
/// Populated by the framework / identity-resolver plugin from
/// attestation evidence. Plugins read it via the `read_workload`
/// capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    /// SPIFFE-SVID identifier — `spiffe://<trust-domain>/<path>`.
    /// Set when the workload presented a SPIFFE-SVID (X.509 or JWT)
    /// or otherwise carries a SPIFFE-shaped identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,

    /// Trust domain extracted from the SPIFFE-SVID (or supplied by
    /// the attestation source for non-SPIFFE attestors). Lets policy
    /// authors gate on the trust boundary without parsing the URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,

    /// When the attestation was performed. Useful for stale-evidence
    /// rejection in policy. Populated by the attestor; the framework
    /// doesn't refresh it on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_at: Option<DateTime<Utc>>,

    /// Name of the attestor that vouched for the workload — `mtls`,
    /// `spire-agent`, `aws-iid`, `gke-workload-identity`, etc. The
    /// vocabulary is open; operators document the values they use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestor: Option<String>,

    /// SPIFFE workload selectors — `k8s:ns:foo`, `unix:uid:1000`, …
    /// Empty when no selectors were attached (the SPIFFE-ID alone is
    /// the workload's identity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,

    /// OAuth client_id, when the workload also carries one. Kept
    /// alongside SPIFFE so call sites with both shapes (a SPIFFE
    /// workload that's *also* registered as an OAuth client to a
    /// dynamic-client-registration IdP) don't have to populate two
    /// extensions. The OAuth client's authorization data
    /// (scopes / audiences / claims) lives on the separate
    /// `ClientExtension` slot, not here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

/// Security-related extensions.
///
/// Carries security labels (monotonic add-only), classification,
/// up to four distinct identity principals, and data-policy metadata.
/// The four principal slots map to the identity sources:
///
/// - `subject` — the *user* (or service-as-user) initiating the request
/// - `client`  — the *OAuth client / application* brokering the request
/// - `caller_workload` — the *attested workload* on the inbound network
///                       peer (SPIFFE-SVID, mTLS cert chain)
/// - `this_workload` — *our own* gateway's attested identity, used for
///                     outbound calls
///
/// A request can populate any subset; identity-resolver plugins are
/// expected to fill the slots they're configured for. Policy authors
/// reason about all four uniformly through the `subject.*` /
/// `client.*` / `caller_workload.*` / `this_workload.*` bag namespaces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityExtension {
    /// Security labels (monotonic — add-only via MonotonicSet).
    /// No remove() method — enforced at compile time.
    #[serde(default)]
    pub labels: MonotonicSet<String>,

    /// Data classification level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,

    /// Authenticated *user* identity (who is calling).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectExtension>,

    /// Authenticated *OAuth client / application* brokering the
    /// request. Distinct from `subject` — the same user can connect
    /// through different clients (first-party web, third-party
    /// integration), and policies sometimes want to gate on which.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientExtension>,

    /// The inbound caller's attested workload identity — the network
    /// peer's SPIFFE-SVID or mTLS-attested identity. Distinct from
    /// `client` (the OAuth-layer identity of the application) and
    /// `subject` (the user). All three can be present on the same
    /// request when an agent acts on behalf of a user through our
    /// gateway, peered via mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_workload: Option<WorkloadIdentity>,

    /// This agent / gateway's own workload identity — the SPIFFE-SVID
    /// or attested identity *we* present when making outbound calls.
    /// Populated by the host at startup, not per request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_workload: Option<WorkloadIdentity>,

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
    fn test_workload_identity() {
        let w = WorkloadIdentity {
            spiffe_id: Some("spiffe://example.com/ns/team1/sa/weather-tool".into()),
            trust_domain: Some("example.com".into()),
            attestor: Some("spire-agent".into()),
            selectors: vec!["k8s:ns:team1".into(), "k8s:sa:weather-tool".into()],
            client_id: Some("weather-agent".into()),
            ..Default::default()
        };
        assert_eq!(
            w.spiffe_id.as_deref(),
            Some("spiffe://example.com/ns/team1/sa/weather-tool")
        );
        assert_eq!(w.trust_domain.as_deref(), Some("example.com"));
        assert_eq!(w.attestor.as_deref(), Some("spire-agent"));
        assert_eq!(w.selectors.len(), 2);
        assert_eq!(w.client_id.as_deref(), Some("weather-agent"));
    }

    #[test]
    fn test_workload_identity_default() {
        let w = WorkloadIdentity::default();
        assert!(w.spiffe_id.is_none());
        assert!(w.trust_domain.is_none());
        assert!(w.attested_at.is_none());
        assert!(w.attestor.is_none());
        assert!(w.selectors.is_empty());
        assert!(w.client_id.is_none());
    }

    #[test]
    fn test_security_with_this_workload_and_subject() {
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
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/hr-agent".into()),
                trust_domain: Some("corp.com".into()),
                client_id: Some("hr-agent".into()),
                ..Default::default()
            }),
            auth_method: Some("jwt".into()),
            ..Default::default()
        };

        // Caller identity
        assert_eq!(sec.subject.as_ref().unwrap().id.as_deref(), Some("alice"));
        // Our own workload identity (distinct from caller)
        assert_eq!(
            sec.this_workload.as_ref().unwrap().client_id.as_deref(),
            Some("hr-agent")
        );
        assert_eq!(
            sec.this_workload.as_ref().unwrap().trust_domain.as_deref(),
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
        sec.this_workload = Some(WorkloadIdentity {
            client_id: Some("my-agent".into()),
            ..Default::default()
        });
        sec.auth_method = Some("mtls".into());

        let json = serde_json::to_string(&sec).unwrap();
        let deserialized: SecurityExtension = serde_json::from_str(&json).unwrap();

        assert!(deserialized.has_label("PII"));
        assert_eq!(deserialized.classification.as_deref(), Some("internal"));
        assert_eq!(
            deserialized
                .this_workload
                .as_ref()
                .unwrap()
                .client_id
                .as_deref(),
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
