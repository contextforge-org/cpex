// Location: ./crates/apl-identity-jwt/src/claim_map.rs
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

use cpex_core::extensions::SubjectExtension;

/// Convert a validated JWT's claim map into a `SubjectExtension`.
///
/// Implementations are responsible for pulling out `sub` (the
/// subject identifier) and any additional structured fields the
/// deployment cares about (roles, teams, permissions, custom
/// claims).
///
/// Returning `None` signals "this mapper can't produce a usable
/// subject from these claims" — the resolver maps `None` to an
/// `auth.mapping_failed` `PluginViolation`. `Some(subject)` carries
/// the populated identity.
///
/// `Debug` is a supertrait so structs holding `Arc<dyn ClaimMapper>`
/// (notably `JwtIdentityResolver`) can themselves derive `Debug`.
pub trait ClaimMapper: std::fmt::Debug + Send + Sync {
    /// Map the JWT claim map into a `SubjectExtension`.
    fn map_subject(&self, claims: &HashMap<String, Value>) -> Option<SubjectExtension>;
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
        assert_eq!(subject.claims.get("email"), Some(&"alice@corp.com".to_string()));
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
