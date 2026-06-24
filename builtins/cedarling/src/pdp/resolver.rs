// Location: ./builtins/cedarling/src/pdp/resolver.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CedarlingPdpResolver` — `PdpResolver` impl that delegates Cedar
// policy evaluation to a Cedarling instance.
//
// # Why Cedarling here instead of `cpex-pdp-cedar-direct`
//
// Both call the same Cedar evaluator under the hood. The difference
// is the policy-store loading + management layer Cedarling provides:
// signed policy bundles, multi-policy stores keyed by ID, optional
// Lock Server integration for fleet-wide updates. Deployments that
// don't need any of that should reach for `cpex-pdp-cedar-direct`
// instead — it's ~5 deps vs ~200.
//
// # Construction
//
// This resolver does NOT construct its own Cedarling instance.
// Cedarling holds shared state (JWT keys, entity store cache,
// optional Lock Server connection) that an entire deployment
// typically wants to share between identity resolution and PDP
// evaluation. The host builds one `Arc<Cedarling>` at startup and
// hands the same handle to both this resolver and the
// (forthcoming) `CedarlingIdentityResolver`.
//
// # `authorize_unsigned`
//
// We use Cedarling's `authorize_unsigned` rather than
// `authorize_multi_issuer`. Reasoning:
//   * APL has already done identity resolution by the time `cedar:`
//     policy steps run — `Extensions.security.subject` /
//     `.client` / `.caller_workload` are populated.
//   * We build the principal entity from the `AttributeBag` directly,
//     bypassing Cedarling's JWT-validation path entirely.
//   * No sentinel-action workaround needed (the one we discussed for
//     using `authorize_multi_issuer` purely for identity).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use cedarling::{CedarEntityMapping, Cedarling, EntityData, RequestUnsigned};
use serde_json::{json, Map, Value};

use apl_core::attributes::{AttributeBag, AttributeValue};
use apl_core::evaluator::Decision;
use apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};

/// `PdpResolver` that dispatches policy decisions to a Cedarling
/// instance. See module docs for when to prefer this over
/// `cpex-pdp-cedar-direct`.
pub struct CedarlingPdpResolver {
    /// Shared Cedarling instance — built once at host startup,
    /// passed to both this resolver and the identity handler.
    cedarling: Arc<Cedarling>,

    /// The dialect this resolver registers under in the `PdpRouter`.
    /// Defaults to `PdpDialect::Cedarling` (a distinct variant from
    /// `Cedar`) so both `cpex-pdp-cedar-direct` and this crate can
    /// coexist in the same router and routes target each explicitly
    /// via `cedar:(...)` vs `cedarling:(...)` step keys.
    dialect: PdpDialect,

    /// Optional namespace prefix prepended to entity types built
    /// from the bag (`"User"` → `"Jans::User"`). Matches the
    /// `cpex-pdp-cedar-direct` ergonomics; deployments with
    /// namespaced schemas set this once at startup.
    entity_namespace: Option<String>,
}

impl CedarlingPdpResolver {
    /// Build a resolver around a pre-constructed Cedarling instance.
    /// Cedarling construction is async and config-heavy
    /// (`BootstrapConfig`, policy store loading); doing it inside
    /// the resolver would force every call site into an async
    /// context. The host owns the lifecycle.
    pub fn new(cedarling: Arc<Cedarling>) -> Self {
        Self {
            cedarling,
            dialect: PdpDialect::Cedarling,
            entity_namespace: None,
        }
    }

    pub fn with_dialect(mut self, dialect: PdpDialect) -> Self {
        self.dialect = dialect;
        self
    }

    pub fn with_entity_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.entity_namespace = Some(namespace.into());
        self
    }
}

#[async_trait]
impl PdpResolver for CedarlingPdpResolver {
    fn dialect(&self) -> PdpDialect {
        self.dialect.clone()
    }

    async fn evaluate(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        let map = call.args.as_mapping().ok_or_else(|| {
            PdpError::Dispatch(
                "cedarling: cedar:() args must be a mapping with action/resource keys"
                    .to_string(),
            )
        })?;

        let action = yaml_string(map, "action").ok_or_else(|| {
            PdpError::Dispatch("cedarling: cedar:() args.action missing or not a string".into())
        })?;

        let resource_value = map
            .get(serde_yaml::Value::String("resource".to_string()))
            .ok_or_else(|| {
                PdpError::Dispatch("cedarling: cedar:() args.resource missing".into())
            })?;
        let resource = build_resource_entity_data(resource_value)?;

        let principal =
            build_principal_entity_data(bag, self.entity_namespace.as_deref())?;

        let context = map
            .get(serde_yaml::Value::String("context".to_string()))
            .map(|v| serde_json::to_value(v))
            .transpose()
            .map_err(|e| {
                PdpError::Dispatch(format!(
                    "cedarling: cedar:() args.context not JSON-representable: {e}"
                ))
            })?
            .unwrap_or(Value::Object(Map::new()));

        let request = RequestUnsigned {
            principal: Some(principal),
            action,
            resource,
            context,
        };

        let result = self.cedarling.authorize_unsigned(request).await.map_err(|e| {
            PdpError::Dispatch(format!("cedarling: authorize_unsigned failed: {e}"))
        })?;

        Ok(translate_authorize_result(&result))
    }
}

// =====================================================================
// Helpers
// =====================================================================

/// Build the Cedarling principal entity from the attribute bag. Same
/// claim shape as `cpex-pdp-cedar-direct`:
///
///   * `subject.id`        → entity id (required)
///   * `subject.type`      → entity type ("User" default)
///   * `role.<name>=true`  → attrs.roles : Set<String>
///   * `perm.<name>=true`  → attrs.permissions : Set<String>
///   * `claim.<name>=v`    → attrs.claims.<name> = v
///   * `subject.teams`     → attrs.teams : Set<String>
///
/// Returns `EntityData` (Cedarling's JSON-shaped entity carrier),
/// which Cedarling converts internally to a `cedar_policy::Entity`.
fn build_principal_entity_data(
    bag: &AttributeBag,
    namespace: Option<&str>,
) -> Result<EntityData, PdpError> {
    let id = bag
        .get_string("subject.id")
        .ok_or_else(|| {
            PdpError::Dispatch(
                "cedarling: cedar request needs a principal but bag has no `subject.id` — \
                 install an identity-hook plugin upstream of APL policy"
                    .to_string(),
            )
        })?
        .to_string();

    let kind = bag.get_string("subject.type").unwrap_or("User");
    let entity_type = qualify_type(kind, namespace);

    let mut attributes: HashMap<String, Value> = HashMap::new();
    attributes.insert("id".to_string(), json!(id));
    attributes.insert("type".to_string(), json!(kind));

    let roles = collect_prefixed_bools(bag, "role.");
    attributes.insert("roles".to_string(), json!(roles));

    let permissions = collect_prefixed_bools(bag, "perm.");
    attributes.insert("permissions".to_string(), json!(permissions));

    let teams: Vec<String> = bag
        .get_string_set("subject.teams")
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    attributes.insert("teams".to_string(), json!(teams));

    let claims = collect_claims(bag);
    attributes.insert("claims".to_string(), Value::Object(claims));

    Ok(EntityData {
        cedar_mapping: CedarEntityMapping {
            entity_type,
            id,
        },
        attributes,
    })
}

/// Build the resource entity from the policy author's `args.resource`
/// block:
///
/// ```yaml
/// resource:
///   type: Document          # required
///   id: doc-42              # required
///   attributes:              # optional
///     classification: internal
/// ```
fn build_resource_entity_data(
    resource_args: &serde_yaml::Value,
) -> Result<EntityData, PdpError> {
    let map = resource_args.as_mapping().ok_or_else(|| {
        PdpError::Dispatch(
            "cedarling: cedar:() args.resource must be a mapping".to_string(),
        )
    })?;
    let entity_type = yaml_string(map, "type").ok_or_else(|| {
        PdpError::Dispatch("cedarling: cedar:() args.resource.type missing".to_string())
    })?;
    let id = yaml_string(map, "id").ok_or_else(|| {
        PdpError::Dispatch("cedarling: cedar:() args.resource.id missing".to_string())
    })?;

    let mut attributes: HashMap<String, Value> = HashMap::new();
    if let Some(attrs_value) = map.get(serde_yaml::Value::String("attributes".to_string()))
    {
        let attrs_json: Value = serde_json::to_value(attrs_value).map_err(|e| {
            PdpError::Dispatch(format!(
                "cedarling: cedar:() args.resource.attributes not JSON-representable: {e}"
            ))
        })?;
        if let Value::Object(map) = attrs_json {
            for (k, v) in map {
                attributes.insert(k, v);
            }
        }
    }

    Ok(EntityData {
        cedar_mapping: CedarEntityMapping {
            entity_type,
            id,
        },
        attributes,
    })
}

/// Translate Cedarling's `AuthorizeResult` into APL's `PdpDecision`.
/// Mirrors `cpex-pdp-cedar-direct`'s decision-translation logic since
/// both crates ultimately read the same `cedar_policy::Response`.
/// Fail-closed on diagnostic errors.
fn translate_authorize_result(result: &cedarling::AuthorizeResult) -> PdpDecision {
    use cedar_policy::Decision as CedarDecision;
    let response = &result.response;
    let diagnostics = response.diagnostics();

    let firing_policies: Vec<String> = diagnostics
        .reason()
        .map(|pid| pid.to_string())
        .collect();

    let errors: Vec<String> = diagnostics.errors().map(|e| e.to_string()).collect();

    // Cedar evaluation errors → fail-closed deny. Same rule as
    // `cpex-pdp-cedar-direct`: any runtime error during evaluation
    // produces an untrustworthy decision, so we override to deny.
    if !errors.is_empty() {
        let reason = format!(
            "Cedar evaluation produced errors (fail-closed): {}",
            errors.join("; ")
        );
        let rule_source = firing_policies
            .first()
            .cloned()
            .unwrap_or_else(|| "cedar.evaluation_error".to_string());
        return PdpDecision {
            decision: Decision::Deny {
                reason: Some(reason),
                rule_source,
            },
            diagnostics: firing_policies,
        };
    }

    let decision = match response.decision() {
        CedarDecision::Allow => Decision::Allow,
        CedarDecision::Deny => {
            let reason = if firing_policies.is_empty() {
                "no Cedar permit policy matched the request".to_string()
            } else {
                format!("denied by Cedar policy: {}", firing_policies.join(", "))
            };
            let rule_source = firing_policies
                .first()
                .cloned()
                .unwrap_or_else(|| "cedar.default_deny".to_string());
            Decision::Deny {
                reason: Some(reason),
                rule_source,
            }
        }
    };

    PdpDecision {
        decision,
        diagnostics: firing_policies,
    }
}

// ----- Small helpers, mirror cedar-direct -----

fn qualify_type(bare: &str, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) if !ns.is_empty() => format!("{ns}::{bare}"),
        _ => bare.to_string(),
    }
}

fn collect_prefixed_bools(bag: &AttributeBag, prefix: &str) -> Vec<String> {
    use std::collections::HashSet;
    let mut out: HashSet<String> = HashSet::new();
    for (key, value) in bag.iter() {
        if let Some(name) = key.strip_prefix(prefix) {
            if matches!(value, AttributeValue::Bool(true)) {
                out.insert(name.to_string());
            }
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

fn collect_claims(bag: &AttributeBag) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in bag.iter() {
        if let Some(name) = key.strip_prefix("claim.") {
            let v = match value {
                AttributeValue::Bool(b) => json!(*b),
                AttributeValue::Int(i) => json!(*i),
                AttributeValue::Float(f) => json!(*f),
                AttributeValue::String(s) => json!(s),
                AttributeValue::StringSet(set) => json!(set.iter().collect::<Vec<_>>()),
            };
            out.insert(name.to_string(), v);
        }
    }
    out
}

fn yaml_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_string()))?
        .as_str()
        .map(|s| s.to_string())
}
