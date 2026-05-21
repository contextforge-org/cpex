// Location: ./crates/apl-cmf/src/security.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// SecurityExtension → AttributeBag.
//
// Namespace map (canonical — extend this comment when adding a new key):
//
// ----- Subject (user identity) ------------------------------------------
//   sec.subject.id                   → subject.id           : String
//   sec.subject.subject_type         → subject.type         : String
//   sec.subject.roles                → role.<r>             : Bool(true)
//   sec.subject.permissions          → perm.<p>             : Bool(true)
//   sec.subject.teams                → subject.teams        : StringSet
//   sec.subject.claims               → claim.<k>            : String
//   <derived>                        → authenticated        : Bool (iff subject.id is Some)
//
// ----- Client (OAuth application identity) ------------------------------
//   sec.client.client_id             → client.client_id     : String
//   sec.client.client_name           → client.client_name   : String
//   sec.client.trust_level           → client.trust_level   : String
//   sec.client.authorized_scopes     → client.authorized_scopes : StringSet
//   sec.client.authorized_audiences  → client.authorized_audiences : StringSet
//   sec.client.roles                 → client.role.<r>      : Bool(true)
//   sec.client.permissions           → client.perm.<p>      : Bool(true)
//   sec.client.teams                 → client.teams         : StringSet
//   sec.client.claims                → client.claim.<k>     : flattened JSON
//
// ----- Workload identity (SPIFFE / mTLS attestation) --------------------
//   sec.caller_workload.spiffe_id    → caller_workload.spiffe_id    : String
//   sec.caller_workload.trust_domain → caller_workload.trust_domain : String
//   sec.caller_workload.attestor     → caller_workload.attestor     : String
//   sec.caller_workload.selectors    → caller_workload.selectors    : StringSet
//   sec.caller_workload.client_id    → caller_workload.client_id    : String
//   sec.this_workload.*              → this_workload.*  (same shape, our identity)
//
// Note: `caller_workload.*` / `this_workload.*` are separate from
// `agent.*` (the `AgentExtension` slot — session / conversation context,
// NOT a credential). Reusing `agent.*` would collide.
//
// ----- Other -----------------------------------------------------------
//   sec.auth_method                  → auth_method          : String
//   sec.labels                       → security.labels      : StringSet
//   sec.classification               → security.classification : String

use apl_core::AttributeBag;
use cpex_core::extensions::{
    ClientExtension, ClientTrustLevel, SecurityExtension, SubjectType, WorkloadIdentity,
};
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

    // ----- Client (OAuth application identity) -----
    if let Some(client) = &sec.client {
        extract_client(client, bag);
    }

    // ----- Inbound caller's attested workload identity -----
    if let Some(caller) = &sec.caller_workload {
        extract_workload("caller_workload", caller, bag);
    }

    // ----- Our own attested workload identity (outbound) -----
    if let Some(this_w) = &sec.this_workload {
        extract_workload("this_workload", this_w, bag);
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

/// Flatten a `ClientExtension` into the bag under the `client.*`
/// namespace. Shape is deliberately symmetric with subject — roles
/// and permissions become presence-only `client.role.<r> = true` /
/// `client.perm.<p> = true` keys so policies can write
/// `require(client.role.partner)` the same way as `role.hr`. Claims
/// are flattened through the same JSON walker as `custom.*`, so
/// nested objects produce dotted-path keys.
pub fn extract_client(client: &ClientExtension, bag: &mut AttributeBag) {
    bag.set("client.client_id", client.client_id.clone());
    if let Some(n) = &client.client_name {
        bag.set("client.client_name", n.clone());
    }
    bag.set("client.trust_level", trust_level_str(&client.trust_level));
    for role in &client.roles {
        bag.set(format!("client.role.{}", role), true);
    }
    for perm in &client.permissions {
        bag.set(format!("client.perm.{}", perm), true);
    }
    if !client.authorized_scopes.is_empty() {
        let scopes: HashSet<String> = client.authorized_scopes.iter().cloned().collect();
        bag.set("client.authorized_scopes", scopes);
    }
    if !client.authorized_audiences.is_empty() {
        let auds: HashSet<String> = client.authorized_audiences.iter().cloned().collect();
        bag.set("client.authorized_audiences", auds);
    }
    if !client.teams.is_empty() {
        let teams: HashSet<String> = client.teams.iter().cloned().collect();
        bag.set("client.teams", teams);
    }
    for (k, v) in &client.claims {
        // Nested JSON claims flatten through the same walker `custom.*`
        // uses — keeps semantics consistent across bridges.
        crate::payload::walk(v, &format!("client.claim.{}", k), bag);
    }
}

/// Flatten a `WorkloadIdentity` into the bag under the given namespace
/// prefix — typically `"caller_workload"` or `"this_workload"`. Two
/// instances of this struct can coexist in `SecurityExtension`
/// (one inbound, one outbound) and they share the bag shape; the only
/// thing that varies is the namespace.
pub fn extract_workload(prefix: &str, w: &WorkloadIdentity, bag: &mut AttributeBag) {
    if let Some(s) = &w.spiffe_id {
        bag.set(format!("{}.spiffe_id", prefix), s.clone());
    }
    if let Some(t) = &w.trust_domain {
        bag.set(format!("{}.trust_domain", prefix), t.clone());
    }
    if let Some(a) = &w.attestor {
        bag.set(format!("{}.attestor", prefix), a.clone());
    }
    if !w.selectors.is_empty() {
        let selectors: HashSet<String> = w.selectors.iter().cloned().collect();
        bag.set(format!("{}.selectors", prefix), selectors);
    }
    if let Some(id) = &w.client_id {
        bag.set(format!("{}.client_id", prefix), id.clone());
    }
    // `attested_at` intentionally omitted from the bag at v0 — APL
    // doesn't carry DateTime as a bag value type, and policies that
    // need it can opt into reading the typed extension directly.
    let _ = &w.attested_at;
}

/// Render the `ClientTrustLevel` enum as the bag string. Matches
/// `serde(rename_all = "snake_case")` on the type, with `Custom(s)`
/// rendering as `s` verbatim so policies can write
/// `client.trust_level == "partner-tier-A"`. The `_` arm exists
/// because `ClientTrustLevel` is `#[non_exhaustive]`; if a new
/// well-known variant lands upstream, this falls through to
/// "unknown" until we explicitly add a case — fail-loud rather than
/// silently picking one of the existing strings.
fn trust_level_str(level: &ClientTrustLevel) -> String {
    match level {
        ClientTrustLevel::FirstParty => "first_party".to_string(),
        ClientTrustLevel::ThirdParty => "third_party".to_string(),
        ClientTrustLevel::Internal => "internal".to_string(),
        ClientTrustLevel::Custom(s) => s.clone(),
        _ => "unknown".to_string(),
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
    use cpex_core::extensions::{SubjectExtension, WorkloadIdentity};
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
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/hr-tool".into()),
                trust_domain: Some("corp.com".into()),
                attestor: Some("spire-agent".into()),
                selectors: vec!["k8s:ns:hr".into()],
                client_id: Some("hr-tool".into()),
                ..Default::default()
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
    fn this_workload_identity_keys() {
        // `this_workload.*` namespace — our own attested identity.
        // Distinct from the `agent.*` namespace of `AgentExtension`
        // (session context) and the future `caller_workload.*`
        // namespace for the inbound caller's SPIFFE identity.
        let mut bag = AttributeBag::new();
        extract_security(&alice(), &mut bag);
        assert_eq!(bag.get_string("this_workload.client_id"), Some("hr-tool"));
        assert_eq!(
            bag.get_string("this_workload.spiffe_id"),
            Some("spiffe://corp.com/hr-tool")
        );
        assert_eq!(bag.get_string("this_workload.trust_domain"), Some("corp.com"));
        assert_eq!(bag.get_string("this_workload.attestor"), Some("spire-agent"));
        assert!(bag.set_contains("this_workload.selectors", "k8s:ns:hr"));
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

    // -----------------------------------------------------------------
    // Client (OAuth application identity) bag namespace
    // -----------------------------------------------------------------

    fn agent_client() -> ClientExtension {
        ClientExtension {
            client_id: "agent-app".into(),
            client_name: Some("Agent App".into()),
            trust_level: ClientTrustLevel::FirstParty,
            authorized_scopes: vec!["read".into(), "write".into()],
            authorized_audiences: vec!["https://api.example.com".into()],
            roles: vec!["partner".into()],
            permissions: vec!["call_tool".into()],
            teams: vec!["acme".into()],
            claims: HashMap::from([
                ("iss".to_string(), serde_json::json!("auth.example.com")),
                (
                    "scope_meta".to_string(),
                    serde_json::json!({ "max_calls_per_min": 60 }),
                ),
            ]),
        }
    }

    #[test]
    fn client_required_id_and_trust_level() {
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert_eq!(bag.get_string("client.client_id"), Some("agent-app"));
        assert_eq!(bag.get_string("client.client_name"), Some("Agent App"));
        assert_eq!(bag.get_string("client.trust_level"), Some("first_party"));
    }

    #[test]
    fn client_roles_and_perms_become_individual_true_keys() {
        // Symmetric with the subject pattern: `client.role.partner = true`.
        // Lets policies write `require(client.role.partner)`.
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert_eq!(bag.get_bool("client.role.partner"), Some(true));
        assert_eq!(bag.get_bool("client.perm.call_tool"), Some(true));
        assert_eq!(bag.get_bool("client.role.nonexistent"), None);
    }

    #[test]
    fn client_scopes_audiences_teams_are_string_sets() {
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert!(bag.set_contains("client.authorized_scopes", "read"));
        assert!(bag.set_contains("client.authorized_scopes", "write"));
        assert!(bag.set_contains(
            "client.authorized_audiences",
            "https://api.example.com",
        ));
        assert!(bag.set_contains("client.teams", "acme"));
    }

    #[test]
    fn client_claims_flatten_nested_paths() {
        // Claims are `HashMap<String, Value>` — nested objects must
        // flatten through the same walker `custom.*` uses. Asserts the
        // JSON-walker integration works for client just like custom.
        let mut bag = AttributeBag::new();
        extract_client(&agent_client(), &mut bag);
        assert_eq!(bag.get_string("client.claim.iss"), Some("auth.example.com"));
        assert_eq!(
            bag.get_int("client.claim.scope_meta.max_calls_per_min"),
            Some(60),
        );
    }

    #[test]
    fn trust_level_custom_renders_verbatim() {
        let mut client = agent_client();
        client.trust_level = ClientTrustLevel::Custom("partner-tier-A".into());
        let mut bag = AttributeBag::new();
        extract_client(&client, &mut bag);
        assert_eq!(bag.get_string("client.trust_level"), Some("partner-tier-A"));
    }

    // -----------------------------------------------------------------
    // Workload (extract_workload helper — both prefixes)
    // -----------------------------------------------------------------

    fn workload_fixture() -> WorkloadIdentity {
        WorkloadIdentity {
            spiffe_id: Some("spiffe://corp.com/svc/foo".into()),
            trust_domain: Some("corp.com".into()),
            attestor: Some("spire-agent".into()),
            selectors: vec!["k8s:ns:foo".into(), "k8s:sa:foo-sa".into()],
            client_id: Some("foo-svc".into()),
            ..Default::default()
        }
    }

    #[test]
    fn extract_workload_populates_under_caller_prefix() {
        // The same WorkloadIdentity feeds two distinct bag namespaces
        // depending on which slot it lives in. This test pins
        // `caller_workload.*`; the next pins `this_workload.*`.
        let mut bag = AttributeBag::new();
        extract_workload("caller_workload", &workload_fixture(), &mut bag);
        assert_eq!(
            bag.get_string("caller_workload.spiffe_id"),
            Some("spiffe://corp.com/svc/foo"),
        );
        assert_eq!(
            bag.get_string("caller_workload.trust_domain"),
            Some("corp.com"),
        );
        assert!(bag.set_contains("caller_workload.selectors", "k8s:ns:foo"));
        // And the `this_workload.*` namespace must stay empty in this
        // case — caller-prefix call must not leak into the other slot.
        assert_eq!(bag.get_string("this_workload.spiffe_id"), None);
    }

    #[test]
    fn extract_workload_populates_under_this_prefix() {
        let mut bag = AttributeBag::new();
        extract_workload("this_workload", &workload_fixture(), &mut bag);
        assert_eq!(
            bag.get_string("this_workload.spiffe_id"),
            Some("spiffe://corp.com/svc/foo"),
        );
        assert_eq!(bag.get_string("this_workload.attestor"), Some("spire-agent"));
        assert_eq!(bag.get_string("caller_workload.spiffe_id"), None);
    }

    // -----------------------------------------------------------------
    // extract_security orchestrates all four identity slots
    // -----------------------------------------------------------------

    #[test]
    fn extract_security_populates_all_four_identity_namespaces() {
        // Single fixture exercising subject + client + caller_workload +
        // this_workload. Documents that one SecurityExtension can carry
        // all four principals on a single request and the bridge fans
        // them out into disjoint namespaces.
        let sec = SecurityExtension {
            subject: Some(SubjectExtension {
                id: Some("alice".into()),
                ..Default::default()
            }),
            client: Some(agent_client()),
            caller_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/inbound".into()),
                ..Default::default()
            }),
            this_workload: Some(WorkloadIdentity {
                spiffe_id: Some("spiffe://corp.com/gateway".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bag = AttributeBag::new();
        extract_security(&sec, &mut bag);
        assert_eq!(bag.get_string("subject.id"), Some("alice"));
        assert_eq!(bag.get_string("client.client_id"), Some("agent-app"));
        assert_eq!(
            bag.get_string("caller_workload.spiffe_id"),
            Some("spiffe://corp.com/inbound"),
        );
        assert_eq!(
            bag.get_string("this_workload.spiffe_id"),
            Some("spiffe://corp.com/gateway"),
        );
    }
}
