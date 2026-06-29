// Location: ./builtins/plugins/identity-jwt/src/claim_map.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `ClaimMapper` — converts validated JWT claims into a populated
// `SubjectExtension`.
//
// Different IdPs use different claim shapes:
//
//   * Keycloak — `realm_access.roles` (nested array), `email`,
//                 `preferred_username`, custom `groups` array
//   * Auth0    — flat `permissions` array, `https://my-app/roles`
//                 (namespaced custom claims), `email`
//   * Cognito  — `cognito:groups`, `cognito:username`,
//                 `cognito:roles`
//   * Standard OIDC — `sub`, `email`, `name`, `groups`, …
//
// `StandardClaimMap` covers the OIDC-standard shape; deployments
// with bespoke IdPs implement `ClaimMapper` themselves and inject
// at resolver construction.

use std::collections::HashMap;

use serde_json::Value;

use cpex_core::extensions::{ClientExtension, SubjectExtension, WorkloadIdentity};

/// Convert a validated JWT's claim map into the typed identity slot
/// for the resolver's configured role.
///
/// Implementations supply one method per role they understand:
///
///   * [`map_subject`] — `sub` plus subject-shaped fields, for
///     `TokenRole::User`.
///   * [`map_client`]  — `client_id` plus client-shaped fields, for
///     `TokenRole::Client`.
///   * [`map_workload`] — SPIFFE-style identity, for `TokenRole::Workload`.
///
/// Each defaults to `None` so existing custom mappers stay valid —
/// they get implicit "this mapper doesn't know how to do that role,"
/// which the resolver surfaces as `auth.mapping_failed` when an
/// operator wires a role the mapper can't fill.
///
/// `Debug` is a supertrait so structs holding `Arc<dyn ClaimMapper>`
/// (notably `JwtIdentityResolver`) can themselves derive `Debug`.
///
/// [`map_subject`]: ClaimMapper::map_subject
/// [`map_client`]: ClaimMapper::map_client
/// [`map_workload`]: ClaimMapper::map_workload
pub trait ClaimMapper: std::fmt::Debug + Send + Sync {
    /// Map JWT claims into a `SubjectExtension` (for `role: user`).
    fn map_subject(&self, claims: &HashMap<String, Value>) -> Option<SubjectExtension> {
        let _ = claims;
        None
    }

    /// Map JWT claims into a `ClientExtension` (for `role: client`).
    /// Default returns `None` — implementations that handle client
    /// tokens override this.
    fn map_client(&self, claims: &HashMap<String, Value>) -> Option<ClientExtension> {
        let _ = claims;
        None
    }

    /// Map JWT claims into a `WorkloadIdentity` (for `role: workload`).
    /// Default returns `None` — implementations that handle SPIFFE /
    /// SPIFFE-JWT-SVID tokens override this.
    fn map_workload(&self, claims: &HashMap<String, Value>) -> Option<WorkloadIdentity> {
        let _ = claims;
        None
    }
}

/// Type alias matching what `jsonwebtoken::decode::<ClaimMap>(...)`
/// produces — a JSON object's key/value pairs.
pub type ClaimMap = HashMap<String, Value>;

/// Default `ClaimMapper` covering the OIDC-standard claim shape:
///
///   * `sub`                    → `subject.id` (required)
///   * `roles`                  → `subject.roles`     (string array)
///   * `permissions` / `scope`  → `subject.permissions` (array or
///                                 space-separated string)
///   * `groups` / `teams`       → `subject.teams`     (string array)
///   * Every other claim        → `subject.claims.<name>` (stringified)
///
/// Implementations with non-standard IdPs (Keycloak's nested
/// `realm_access.roles`, AWS Cognito's `cognito:*` prefixed claims)
/// write their own `ClaimMapper`; this struct is for the common
/// vanilla-OIDC case.
#[derive(Debug, Clone, Default)]
pub struct StandardClaimMap;

impl ClaimMapper for StandardClaimMap {
    fn map_client(&self, claims: &ClaimMap) -> Option<ClientExtension> {
        // `client_id` is required for ClientExtension — it's the anchor
        // identifier policy authors gate on. Falls back to `azp`
        // (authorized party, OIDC §2 for the "client_id of the party
        // to which the token was issued") which Keycloak and several
        // OPs send in place of `client_id`.
        let client_id = claims
            .get("client_id")
            .or_else(|| claims.get("azp"))
            .and_then(Value::as_str)?
            .to_string();

        let mut client = ClientExtension {
            client_id,
            ..Default::default()
        };

        if let Some(name) = claims.get("client_name").and_then(Value::as_str) {
            client.client_name = Some(name.to_string());
        }

        // Scopes — array OR space-separated string.
        if let Some(arr) = claims.get("authorized_scopes").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    client.authorized_scopes.push(s.to_string());
                }
            }
        } else if let Some(s) = claims.get("scope").and_then(Value::as_str) {
            for scope in s.split_whitespace() {
                if !scope.is_empty() {
                    client.authorized_scopes.push(scope.to_string());
                }
            }
        }

        // Audiences — single string or array (RFC 7519 §4.1.3).
        match claims.get("aud") {
            Some(Value::String(s)) => client.authorized_audiences.push(s.clone()),
            Some(Value::Array(arr)) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        client.authorized_audiences.push(s.to_string());
                    }
                }
            },
            _ => {},
        }

        // Platform-native roles.
        if let Some(arr) = claims.get("roles").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    client.roles.push(s.to_string());
                }
            }
        }

        // Remaining claims — keyed by name with full Value preserved
        // (ClientExtension.claims is HashMap<String, serde_json::Value>,
        // unlike SubjectExtension.claims which stringifies).
        const RESERVED: &[&str] = &[
            "client_id",
            "azp",
            "client_name",
            "authorized_scopes",
            "scope",
            "aud",
            "roles",
            "iss",
            "exp",
            "nbf",
            "iat",
            "jti",
            "sub",
        ];
        for (k, v) in claims {
            if RESERVED.contains(&k.as_str()) {
                continue;
            }
            client.claims.insert(k.clone(), v.clone());
        }

        Some(client)
    }

    fn map_workload(&self, claims: &ClaimMap) -> Option<WorkloadIdentity> {
        // SPIFFE JWT-SVID convention: the SPIFFE ID lives in `sub`
        // (per the SPIFFE JWT-SVID spec). We look there first, then
        // fall back to an explicit `spiffe_id` claim for IdPs that
        // surface it separately.
        let spiffe_id = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| s.starts_with("spiffe://"))
            .or_else(|| claims.get("spiffe_id").and_then(Value::as_str))
            .map(str::to_string)?;

        // Trust domain — pull from the SPIFFE-ID host part.
        let trust_domain = spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next())
            .map(str::to_string);

        Some(WorkloadIdentity {
            spiffe_id: Some(spiffe_id),
            trust_domain,
            attested_at: None,
            attestor: Some("jwt".to_string()),
            ..Default::default()
        })
    }

    fn map_subject(&self, claims: &ClaimMap) -> Option<SubjectExtension> {
        // `sub` is required — RFC 7519 §4.1.2 makes it optional in
        // the spec but it's effectively mandatory for identity flows.
        let sub = claims.get("sub").and_then(Value::as_str)?.to_string();

        let mut subject = SubjectExtension {
            id: Some(sub),
            ..Default::default()
        };

        // `roles` — array of strings.
        if let Some(arr) = claims.get("roles").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.roles.insert(s.to_string());
                }
            }
        }

        // `permissions` (array) OR `scope` (space-separated string,
        // OAuth-style). Either populates `subject.permissions`.
        if let Some(arr) = claims.get("permissions").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.permissions.insert(s.to_string());
                }
            }
        } else if let Some(s) = claims.get("scope").and_then(Value::as_str) {
            for scope in s.split_whitespace() {
                if !scope.is_empty() {
                    subject.permissions.insert(scope.to_string());
                }
            }
        }

        // `teams` (explicit) preferred; fall back to `groups` (OIDC
        // conventional name for the same concept).
        if let Some(arr) = claims.get("teams").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.teams.insert(s.to_string());
                }
            }
        } else if let Some(arr) = claims.get("groups").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    subject.teams.insert(s.to_string());
                }
            }
        }

        // Every other claim → `subject.claims.<name>`.
        // SubjectExtension.claims is HashMap<String, String>, so
        // non-string values get stringified (JSON-serialized). The
        // reserved-claim set is the ones we already mapped to
        // structured fields, plus the JWT standard registered
        // claims (iss/aud/exp/nbf/iat/jti) which aren't useful as
        // policy-visible claims.
        const RESERVED: &[&str] = &[
            "sub",
            "roles",
            "permissions",
            "scope",
            "teams",
            "groups",
            "iss",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
        ];
        for (k, v) in claims {
            if RESERVED.contains(&k.as_str()) {
                continue;
            }
            let stringified = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            subject.claims.insert(k.clone(), stringified);
        }

        Some(subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_claims(json: Value) -> ClaimMap {
        json.as_object().unwrap().clone().into_iter().collect()
    }

    #[test]
    fn sub_becomes_subject_id() {
        let claims = make_claims(json!({"sub": "alice@corp.com"}));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert_eq!(subject.id.as_deref(), Some("alice@corp.com"));
    }

    #[test]
    fn missing_sub_returns_none() {
        // No `sub` claim → mapper rejects. Caller will surface
        // this as `auth.mapping_failed`.
        let claims = make_claims(json!({"email": "alice@corp.com"}));
        assert!(StandardClaimMap.map_subject(&claims).is_none());
    }

    #[test]
    fn roles_array_becomes_subject_roles() {
        let claims = make_claims(json!({
            "sub": "alice",
            "roles": ["hr", "admin"],
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.roles.contains("hr"));
        assert!(subject.roles.contains("admin"));
    }

    #[test]
    fn scope_string_splits_into_permissions() {
        // OAuth-style space-separated scope claim — `scope: "read write"`.
        let claims = make_claims(json!({
            "sub": "alice",
            "scope": "read write delete",
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.permissions.contains("read"));
        assert!(subject.permissions.contains("write"));
        assert!(subject.permissions.contains("delete"));
    }

    #[test]
    fn permissions_array_preferred_over_scope() {
        // If both are present, `permissions` (array) wins. Most
        // modern IdPs send arrays; OAuth-1-era `scope` is a fallback.
        let claims = make_claims(json!({
            "sub": "alice",
            "permissions": ["call_tool", "list_tools"],
            "scope": "read write",
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.permissions.contains("call_tool"));
        // `scope` ignored when `permissions` is present.
        assert!(!subject.permissions.contains("read"));
    }

    #[test]
    fn groups_fallback_when_teams_absent() {
        let claims = make_claims(json!({
            "sub": "alice",
            "groups": ["engineering", "platform"],
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.teams.contains("engineering"));
        assert!(subject.teams.contains("platform"));
    }

    #[test]
    fn teams_preferred_over_groups() {
        let claims = make_claims(json!({
            "sub": "alice",
            "teams": ["explicit-team"],
            "groups": ["fallback-group"],
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert!(subject.teams.contains("explicit-team"));
        assert!(!subject.teams.contains("fallback-group"));
    }

    #[test]
    fn unmapped_claims_land_in_subject_claims_map() {
        let claims = make_claims(json!({
            "sub": "alice",
            "email": "alice@corp.com",
            "preferred_username": "alice",
            "iat": 1700000000,  // reserved, should be skipped
        }));
        let subject = StandardClaimMap.map_subject(&claims).unwrap();
        assert_eq!(
            subject.claims.get("email"),
            Some(&"alice@corp.com".to_string())
        );
        assert_eq!(
            subject.claims.get("preferred_username"),
            Some(&"alice".to_string()),
        );
        // Reserved JWT claims aren't propagated as policy-visible
        // subject claims.
        assert!(!subject.claims.contains_key("iat"));
        assert!(!subject.claims.contains_key("sub"));
    }
}
