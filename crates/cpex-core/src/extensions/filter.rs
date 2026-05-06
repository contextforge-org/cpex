// Location: ./crates/cpex-core/src/extensions/filter.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Extension filtering — capability-gated visibility.
//
// Builds a Extensions from Extensions + declared capabilities.
// Secure by default: slots not explicitly included are None.
//
// Mirrors cpex/framework/extensions/tiers.py::filter_extensions().

use std::collections::HashSet;
use std::sync::Arc;

use super::container::Extensions;

use super::security::{SecurityExtension, SubjectExtension};
use super::tiers::{AccessPolicy, Capability, MutabilityTier, SlotPolicy};

// ---------------------------------------------------------------------------
// Slot Registry — static policies per extension slot
// ---------------------------------------------------------------------------

/// Extension slot identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotName {
    Request,
    Agent,
    Http,
    Meta,
    Delegation,
    Custom,
    Mcp,
    Completion,
    Provenance,
    Llm,
    Framework,
    // Security sub-slots
    SecurityLabels,
    SecuritySubject,
    SecuritySubjectRoles,
    SecuritySubjectTeams,
    SecuritySubjectClaims,
    SecuritySubjectPermissions,
    SecurityObjects,
    SecurityData,
}

/// Get the policy for a given slot.
pub fn slot_policy(slot: SlotName) -> SlotPolicy {
    match slot {
        // Unrestricted immutable — always visible
        SlotName::Request => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Provenance => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Completion => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Llm => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Framework => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Mcp => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Meta => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::Custom => SlotPolicy {
            tier: MutabilityTier::Mutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        // Capability-gated
        SlotName::Agent => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadAgent),
            write_cap: None,
        },
        SlotName::Http => SlotPolicy {
            tier: MutabilityTier::Mutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadHeaders),
            write_cap: Some(Capability::WriteHeaders),
        },
        SlotName::Delegation => SlotPolicy {
            tier: MutabilityTier::Monotonic,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadDelegation),
            write_cap: Some(Capability::AppendDelegation),
        },
        // Security sub-slots
        SlotName::SecurityLabels => SlotPolicy {
            tier: MutabilityTier::Monotonic,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadLabels),
            write_cap: Some(Capability::AppendLabels),
        },
        SlotName::SecuritySubject => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadSubject),
            write_cap: None,
        },
        SlotName::SecuritySubjectRoles => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadRoles),
            write_cap: None,
        },
        SlotName::SecuritySubjectTeams => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadTeams),
            write_cap: None,
        },
        SlotName::SecuritySubjectClaims => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadClaims),
            write_cap: None,
        },
        SlotName::SecuritySubjectPermissions => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::CapabilityGated,
            read_cap: Some(Capability::ReadPermissions),
            write_cap: None,
        },
        SlotName::SecurityObjects => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
        SlotName::SecurityData => SlotPolicy {
            tier: MutabilityTier::Immutable,
            access: AccessPolicy::Unrestricted,
            read_cap: None,
            write_cap: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Capability Checking
// ---------------------------------------------------------------------------

/// Check if a set of capabilities grants read access to a slot.
fn has_read_access(policy: &SlotPolicy, capabilities: &HashSet<String>) -> bool {
    if policy.access == AccessPolicy::Unrestricted {
        return true;
    }
    if let Some(read_cap) = &policy.read_cap {
        let cap_str = serde_json::to_string(read_cap)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        if capabilities.contains(&cap_str) {
            return true;
        }
    }
    // Check if any subject sub-field cap implies read_subject
    if policy.read_cap == Some(Capability::ReadSubject) {
        return has_any_subject_capability(capabilities);
    }
    false
}

/// Check if capabilities include any subject-related capability.
fn has_any_subject_capability(capabilities: &HashSet<String>) -> bool {
    let subject_caps = [
        Capability::ReadSubject,
        Capability::ReadRoles,
        Capability::ReadTeams,
        Capability::ReadClaims,
        Capability::ReadPermissions,
    ];
    for cap in &subject_caps {
        let cap_str = serde_json::to_string(cap)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        if capabilities.contains(&cap_str) {
            return true;
        }
    }
    false
}

/// Helper: convert Capability to its string representation.
fn cap_str(cap: Capability) -> String {
    serde_json::to_string(&cap)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

// ---------------------------------------------------------------------------
// Filter Extensions
// ---------------------------------------------------------------------------

/// Build a Extensions containing only slots the plugin can access.
///
/// Starts from an empty Extensions and clones in only the
/// slots the plugin has read access to. Slots not explicitly included
/// are `None`. Secure by default — if a new slot is added to
/// Extensions but not registered here, it remains hidden.
///
/// For the security extension, filtering is granular: unrestricted
/// sub-fields (objects, data, classification) are always included,
/// while labels and subject sub-fields are gated by capabilities.
pub fn filter_extensions(extensions: &Extensions, capabilities: &HashSet<String>) -> Extensions {
    // Build the unrestricted-immutable fields up front; capability-gated
    // slots stay default and are filled in below.
    let mut filtered = Extensions {
        request: extensions.request.clone(),
        provenance: extensions.provenance.clone(),
        completion: extensions.completion.clone(),
        llm: extensions.llm.clone(),
        framework: extensions.framework.clone(),
        mcp: extensions.mcp.clone(),
        meta: extensions.meta.clone(),
        custom: extensions.custom.clone(),
        ..Default::default()
    };

    // Capability-gated: delegation
    if extensions.delegation.is_some() {
        let policy = slot_policy(SlotName::Delegation);
        if has_read_access(&policy, capabilities) {
            filtered.delegation = extensions.delegation.clone();
        }
    }

    // Capability-gated: agent
    if extensions.agent.is_some() {
        let policy = slot_policy(SlotName::Agent);
        if has_read_access(&policy, capabilities) {
            filtered.agent = extensions.agent.clone();
        }
    }

    // Capability-gated: http
    if extensions.http.is_some() {
        let policy = slot_policy(SlotName::Http);
        if has_read_access(&policy, capabilities) {
            filtered.http = extensions.http.clone();
        }
    }

    // Security — granular sub-field filtering
    if let Some(ref security) = extensions.security {
        filtered.security = Some(Arc::new(build_filtered_security(security, capabilities)));
    }

    filtered
}

/// Build a filtered SecurityExtension containing only accessible fields.
///
/// Unrestricted sub-fields (objects, data, classification) are always
/// included. Labels and subject sub-fields are gated by capabilities.
fn build_filtered_security(
    security: &SecurityExtension,
    capabilities: &HashSet<String>,
) -> SecurityExtension {
    let mut filtered = SecurityExtension {
        // Unrestricted — always included
        objects: security.objects.clone(),
        data: security.data.clone(),
        classification: security.classification.clone(),
        // Agent identity and auth method — always included (host-set, immutable)
        agent: security.agent.clone(),
        auth_method: security.auth_method.clone(),
        // Default empty for capability-gated fields
        labels: super::MonotonicSet::new(),
        subject: None,
    };

    // Labels — capability-gated
    let labels_policy = slot_policy(SlotName::SecurityLabels);
    if has_read_access(&labels_policy, capabilities) {
        filtered.labels = security.labels.clone();
    }

    // Subject — granular capability-gated
    if let Some(ref subject) = security.subject {
        if has_any_subject_capability(capabilities) {
            filtered.subject = Some(build_filtered_subject(subject, capabilities));
        }
    }

    filtered
}

/// Build a filtered SubjectExtension containing only accessible fields.
///
/// Always includes id and type (base subject access). Individual
/// sub-fields are only populated if the plugin holds the capability.
fn build_filtered_subject(
    subject: &SubjectExtension,
    capabilities: &HashSet<String>,
) -> SubjectExtension {
    SubjectExtension {
        // Always included with any subject access
        id: subject.id.clone(),
        subject_type: subject.subject_type,
        // Capability-gated sub-fields
        roles: if capabilities.contains(&cap_str(Capability::ReadRoles)) {
            subject.roles.clone()
        } else {
            HashSet::new()
        },
        permissions: if capabilities.contains(&cap_str(Capability::ReadPermissions)) {
            subject.permissions.clone()
        } else {
            HashSet::new()
        },
        teams: if capabilities.contains(&cap_str(Capability::ReadTeams)) {
            subject.teams.clone()
        } else {
            HashSet::new()
        },
        claims: if capabilities.contains(&cap_str(Capability::ReadClaims)) {
            subject.claims.clone()
        } else {
            std::collections::HashMap::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::meta::MetaExtension;
    use crate::extensions::SecurityExtension;

    fn make_full_extensions() -> Extensions {
        let mut security = SecurityExtension::default();
        security.add_label("PII");
        security.classification = Some("confidential".into());
        security.subject = Some(SubjectExtension {
            id: Some("alice".into()),
            subject_type: Some(super::super::security::SubjectType::User),
            roles: ["admin".to_string()].into(),
            permissions: ["read_all".to_string()].into(),
            teams: ["engineering".to_string()].into(),
            claims: [("iss".to_string(), "example.com".to_string())].into(),
        });

        let mut http = super::super::HttpExtension::default();
        http.set_header("Authorization", "Bearer token123");

        Extensions {
            request: Some(std::sync::Arc::new(super::super::RequestExtension {
                request_id: Some("req-001".into()),
                ..Default::default()
            })),
            security: Some(Arc::new(security)),
            http: Some(std::sync::Arc::new(http)),
            agent: Some(std::sync::Arc::new(super::super::AgentExtension {
                agent_id: Some("agent-1".into()),
                ..Default::default()
            })),
            delegation: Some(std::sync::Arc::new(super::super::DelegationExtension {
                delegated: true,
                ..Default::default()
            })),
            meta: Some(std::sync::Arc::new(MetaExtension {
                entity_type: Some("tool".into()),
                entity_name: Some("get_compensation".into()),
                ..Default::default()
            })),
            custom: Some(Arc::new(
                [("key".to_string(), serde_json::json!("value"))].into(),
            )),
            ..Default::default()
        }
    }

    #[test]
    fn test_no_capabilities_sees_unrestricted_only() {
        let ext = make_full_extensions();
        let caps = HashSet::new();
        let filtered = filter_extensions(&ext, &caps);

        // Unrestricted slots visible
        assert!(filtered.request.is_some());
        assert!(filtered.meta.is_some());
        assert!(filtered.custom.is_some());

        // Capability-gated slots hidden
        assert!(filtered.http.is_none());
        assert!(filtered.agent.is_none());
        assert!(filtered.delegation.is_none());

        // Security: objects/data/classification visible, labels/subject hidden
        let sec = filtered.security.as_ref().unwrap();
        assert!(sec.labels.is_empty());
        assert!(sec.subject.is_none());
        assert_eq!(sec.classification, Some("confidential".into()));
    }

    #[test]
    fn test_read_headers_capability() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = ["read_headers".to_string()].into();
        let filtered = filter_extensions(&ext, &caps);

        assert!(filtered.http.is_some());
        assert_eq!(
            filtered.http.unwrap().get_header("Authorization"),
            Some("Bearer token123")
        );
        // Still no agent access
        assert!(filtered.agent.is_none());
    }

    #[test]
    fn test_read_agent_capability() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = ["read_agent".to_string()].into();
        let filtered = filter_extensions(&ext, &caps);

        assert!(filtered.agent.is_some());
        assert_eq!(filtered.agent.unwrap().agent_id, Some("agent-1".into()));
        assert!(filtered.http.is_none());
    }

    #[test]
    fn test_read_labels_capability() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = ["read_labels".to_string()].into();
        let filtered = filter_extensions(&ext, &caps);

        let sec = filtered.security.as_ref().unwrap();
        assert!(sec.has_label("PII"));
        // No subject access — just label access
        assert!(sec.subject.is_none());
    }

    #[test]
    fn test_read_subject_sees_id_and_type_only() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = ["read_subject".to_string()].into();
        let filtered = filter_extensions(&ext, &caps);

        let sec = filtered.security.as_ref().unwrap();
        let subject = sec.subject.as_ref().unwrap();
        assert_eq!(subject.id, Some("alice".into()));
        // Sub-fields empty without specific capabilities
        assert!(subject.roles.is_empty());
        assert!(subject.permissions.is_empty());
        assert!(subject.teams.is_empty());
        assert!(subject.claims.is_empty());
    }

    #[test]
    fn test_read_roles_implies_subject_access() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = ["read_roles".to_string()].into();
        let filtered = filter_extensions(&ext, &caps);

        let sec = filtered.security.as_ref().unwrap();
        let subject = sec.subject.as_ref().unwrap();
        // Has subject access (implied by read_roles)
        assert_eq!(subject.id, Some("alice".into()));
        // Has roles
        assert!(subject.roles.contains("admin"));
        // No other sub-fields
        assert!(subject.permissions.is_empty());
        assert!(subject.teams.is_empty());
    }

    #[test]
    fn test_full_capabilities() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = [
            "read_headers",
            "read_agent",
            "read_delegation",
            "read_labels",
            "read_subject",
            "read_roles",
            "read_permissions",
            "read_teams",
            "read_claims",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let filtered = filter_extensions(&ext, &caps);

        // Everything visible
        assert!(filtered.http.is_some());
        assert!(filtered.agent.is_some());
        assert!(filtered.delegation.is_some());

        let sec = filtered.security.as_ref().unwrap();
        assert!(sec.has_label("PII"));
        let subject = sec.subject.as_ref().unwrap();
        assert!(subject.roles.contains("admin"));
        assert!(subject.permissions.contains("read_all"));
        assert!(subject.teams.contains("engineering"));
        assert!(subject.claims.contains_key("iss"));
    }

    #[test]
    fn test_read_delegation_capability() {
        let ext = make_full_extensions();
        let caps: HashSet<String> = ["read_delegation".to_string()].into();
        let filtered = filter_extensions(&ext, &caps);

        assert!(filtered.delegation.is_some());
        assert!(filtered.delegation.unwrap().delegated);
    }
}
