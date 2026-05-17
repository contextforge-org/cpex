// Location: ./crates/apl-cmf/src/security.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// SecurityExtension → AttributeBag.
//
// Namespace map (canonical — extend this comment when adding a new key):
//
//   sec.subject.id              → subject.id           : String
//   sec.subject.subject_type    → subject.type         : String  ("user"/"agent"/...)
//   sec.subject.roles           → role.<r>             : Bool(true) per role
//   sec.subject.permissions     → perm.<p>             : Bool(true) per permission
//   sec.subject.teams           → subject.teams        : StringSet
//   sec.subject.claims          → claim.<k>            : String  per claim
//   <derived from subject>      → authenticated        : Bool    iff subject.id is Some
//   sec.agent.client_id         → workload.client_id   : String
//   sec.agent.workload_id       → workload.workload_id : String
//   sec.agent.trust_domain      → workload.trust_domain: String
//
// Note: `workload.*` (this agent's own identity) deliberately differs from
// `agent.*` (the `AgentExtension` slot, which carries session / conversation
// context for the caller's agent). Same-namespace would collide.
//   sec.auth_method             → auth_method          : String
//   sec.labels                  → security.labels      : StringSet
//   sec.classification          → security.classification : String

use apl_core::AttributeBag;
use cpex_core::extensions::{SecurityExtension, SubjectType};
use std::collections::HashSet;

/// Flatten a `SecurityExtension` into the bag.
pub fn extract_security(sec: &SecurityExtension, bag: &mut AttributeBag) {
    // ----- Subject (caller identity) -----
    if let Some(subject) = &sec.subject {
        let mut authenticated = false;
        if let Some(id) = &subject.id {
            bag.set("subject.id", id.clone());
            authenticated = true;
        }
        if let Some(st) = subject.subject_type {
            bag.set("subject.type", subject_type_str(st));
        }
        for role in &subject.roles {
            bag.set(format!("role.{}", role), true);
        }
        for perm in &subject.permissions {
            bag.set(format!("perm.{}", perm), true);
        }
        if !subject.teams.is_empty() {
            // Clone into a fresh HashSet — AttributeValue::StringSet owns its data.
            let teams: HashSet<String> = subject.teams.iter().cloned().collect();
            bag.set("subject.teams", teams);
        }
        for (k, v) in &subject.claims {
            bag.set(format!("claim.{}", k), v.clone());
        }
        // Single top-level authenticated marker — DSL idiom is `require(authenticated)`,
        // unprefixed. Only set when truly authenticated (subject + id present).
        if authenticated {
            bag.set("authenticated", true);
        }
    }

    // ----- Workload identity (this agent's own identity, distinct from caller) -----
    if let Some(workload) = &sec.agent {
        if let Some(id) = &workload.client_id {
            bag.set("workload.client_id", id.clone());
        }
        if let Some(w) = &workload.workload_id {
            bag.set("workload.workload_id", w.clone());
        }
        if let Some(t) = &workload.trust_domain {
            bag.set("workload.trust_domain", t.clone());
        }
    }

    // ----- Other security fields -----
    if let Some(m) = &sec.auth_method {
        bag.set("auth_method", m.clone());
    }
    let labels: HashSet<String> = sec.labels.iter().cloned().collect();
    if !labels.is_empty() {
        bag.set("security.labels", labels);
    }
    if let Some(c) = &sec.classification {
        bag.set("security.classification", c.clone());
    }
}

fn subject_type_str(t: SubjectType) -> &'static str {
    match t {
        SubjectType::User => "user",
        SubjectType::Agent => "agent",
        SubjectType::Service => "service",
        SubjectType::System => "system",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpex_core::extensions::{AgentIdentity, SubjectExtension};
    use std::collections::HashMap;

    fn alice() -> SecurityExtension {
        SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice@corp.com".into()),
                subject_type: Some(SubjectType::User),
                roles: HashSet::from(["hr".to_string(), "manager".to_string()]),
                permissions: HashSet::from(["view_ssn".to_string()]),
                teams: HashSet::from(["compliance".to_string()]),
                claims: HashMap::from([("iss".to_string(), "auth.corp".to_string())]),
            }),
            agent: Some(AgentIdentity {
                client_id: Some("hr-tool".into()),
                workload_id: Some("spiffe://corp.com/hr-tool".into()),
                trust_domain: Some("corp.com".into()),
            }),
            auth_method: Some("jwt".into()),
            ..Default::default()
        }
    }

    #[test]
    fn subject_id_and_authenticated_marker() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("subject.id"), Some("alice@corp.com"));
        assert_eq!(bag.get_bool("authenticated"), Some(true));
        assert_eq!(bag.get_string("subject.type"), Some("user"));
    }

    #[test]
    fn roles_become_individual_true_keys() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        // Each role → role.<name> = true. DSL: `require(role.hr)`.
        assert_eq!(bag.get_bool("role.hr"), Some(true));
        assert_eq!(bag.get_bool("role.manager"), Some(true));
        // A role Alice doesn't have is absent (not false — missing).
        assert_eq!(bag.get_bool("role.finance"), None);
    }

    #[test]
    fn permissions_become_individual_true_keys() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_bool("perm.view_ssn"), Some(true));
        assert_eq!(bag.get_bool("perm.delete_user"), None);
    }

    #[test]
    fn teams_become_string_set() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert!(bag.set_contains("subject.teams", "compliance"));
        assert!(!bag.set_contains("subject.teams", "engineering"));
    }

    #[test]
    fn claims_become_dotted_strings() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("claim.iss"), Some("auth.corp"));
    }

    #[test]
    fn workload_identity_keys() {
        // Renamed from `agent.*` to avoid collision with `AgentExtension`.
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("workload.client_id"), Some("hr-tool"));
        assert_eq!(bag.get_string("workload.workload_id"), Some("spiffe://corp.com/hr-tool"));
        assert_eq!(bag.get_string("workload.trust_domain"), Some("corp.com"));
    }

    #[test]
    fn auth_method_is_top_level() {
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("auth_method"), Some("jwt"));
    }

    #[test]
    fn labels_and_classification() {
        let mut sec = SecurityExtension::default();
        sec.add_label("PII");
        sec.add_label("financial");
        sec.classification = Some("confidential".into());

        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(bag.set_contains("security.labels", "PII"));
        assert!(bag.set_contains("security.labels", "financial"));
        assert_eq!(bag.get_string("security.classification"), Some("confidential"));
    }

    #[test]
    fn no_subject_means_no_authenticated_marker() {
        let sec = SecurityExtension::default(); // subject: None
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(!bag.contains("authenticated"));
        assert!(!bag.contains("subject.id"));
    }

    #[test]
    fn subject_without_id_is_not_authenticated() {
        // A subject record exists but has no id — represents a recognized
        // but unauthenticated principal (e.g. anonymous). The marker must
        // not be set.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                id: None,
                roles: HashSet::from(["guest".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert!(!bag.contains("authenticated"));
        // But role keys still land — role.guest is true.
        assert_eq!(bag.get_bool("role.guest"), Some(true));
    }
}
