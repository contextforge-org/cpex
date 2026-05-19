// Location: ./crates/apl-pdp-cedar-direct/src/entities.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Build a `cedar_policy::Entities` set from:
//
//   - The `AttributeBag` — APL's view of `SecurityExtension` etc.
//     populated upstream by apl-cmf. Source of the **principal** entity.
//   - `PdpCall.args.resource` — the resource description the policy
//     author wrote in the `cedar:(...)` step. Source of the **resource**
//     entity.
//
// v0 builds a minimum-viable entity set: just principal + resource,
// no hierarchy (no `User in Team`, no `Document in Folder`). Operators
// who need that plug an `EntityProvider` trait we'll add later — when
// there's a real use case driving the design.
//
// # Why JSON-shaped construction
//
// Cedar's `Entity::from_json_value(json, schema)` accepts a record
// with `uid`, `attrs`, `parents` keys. We build that record from the
// bag / args and let Cedar's parser handle the attribute-value
// translation (string → String, JSON array of strings → Set<String>,
// nested object → Record, etc.). Avoids fighting with
// `RestrictedExpression` directly.

use std::collections::HashSet;

use apl_core::attributes::{AttributeBag, AttributeValue};
use apl_core::step::PdpError;
use cedar_policy::{Entities, Entity, Schema};
use serde_json::{json, Map, Value};

/// Build the entity set for one Cedar request. Returns owned
/// `Entities` (Cedar takes them by reference at authorization time).
pub fn build(
    bag: &AttributeBag,
    resource_args: &serde_yaml::Value,
    schema: Option<&Schema>,
    entity_namespace: Option<&str>,
) -> Result<Entities, PdpError> {
    let principal = build_principal(bag, schema, entity_namespace)?;
    let resource = build_resource(resource_args, schema)?;
    Entities::from_entities([principal, resource], schema).map_err(|e| {
        PdpError::Dispatch(format!("failed to assemble Cedar entity set: {}", e))
    })
}

/// Build the principal `Entity` from the bag. Reads:
///
///   - `subject.id`        → entity id (required)
///   - `subject.type`      → entity type ("User" | "Agent" | "Service" |
///                            "System"); defaults to "User" when absent
///   - `role.<name>=true`  → `attrs.roles : Set<String>`
///   - `perm.<name>=true`  → `attrs.permissions : Set<String>`
///   - `claim.<name>=v`    → `attrs.claims.<name>` (record)
///   - `subject.teams`     → `attrs.teams : Set<String>`
///
/// Operators with custom claim attributes write their Cedar policies
/// against `principal.claims.foo` — those land via the `claim.foo` bag
/// key, populated upstream by apl-cmf from `SubjectExtension.claims`.
pub fn build_principal(
    bag: &AttributeBag,
    schema: Option<&Schema>,
    entity_namespace: Option<&str>,
) -> Result<Entity, PdpError> {
    let id = bag
        .get_string("subject.id")
        .ok_or_else(|| {
            PdpError::Dispatch(
                "Cedar request needs a principal but bag has no `subject.id` — \
                 install an identity-hook plugin upstream of APL policy"
                    .to_string(),
            )
        })?
        .to_string();

    let kind = bag.get_string("subject.type").unwrap_or("User");
    let entity_type = qualify_type(kind, entity_namespace);

    // Collect attributes from the bag. We pick the well-known shapes;
    // arbitrary `subject.*` keys beyond these are intentionally NOT
    // surfaced — operators with custom shapes use `claim.*` or extend
    // the bridge.
    //
    // Empty defaults matter: Cedar's strict-evaluation mode raises a
    // runtime error when a policy probes a missing attribute
    // (`principal.roles.contains(...)` against a principal without
    // `roles`). The resolver's fail-closed logic would then deny —
    // surprising for policy authors who expect missing-attribute →
    // empty-set semantics. Populating empty sets / records by default
    // gives clean "attribute exists, just empty" behavior.
    let mut attrs = Map::new();
    attrs.insert("id".to_string(), json!(id));
    attrs.insert("type".to_string(), json!(kind));

    let roles = collect_prefixed_bools(bag, "role.");
    attrs.insert("roles".to_string(), json!(roles));

    let permissions = collect_prefixed_bools(bag, "perm.");
    attrs.insert("permissions".to_string(), json!(permissions));

    let teams: Vec<String> = bag
        .get_string_set("subject.teams")
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    attrs.insert("teams".to_string(), json!(teams));

    let claims = collect_claims(bag);
    attrs.insert("claims".to_string(), Value::Object(claims));

    let entity_json = json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": attrs,
        "parents": [],
    });

    Entity::from_json_value(entity_json, schema).map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to construct principal entity '{}::\"{}\"': {}",
            entity_type, id, e
        ))
    })
}

/// Build the resource `Entity` from the policy author's `args.resource`
/// block. Shape:
///
/// ```yaml
/// resource:
///   type: Document          # required, Cedar entity type
///   id: doc-42              # required, entity id (string)
///   attributes:              # optional, key → JSON value
///     classification: internal
///     owner: 'User::"alice"'
/// ```
pub fn build_resource(
    resource_args: &serde_yaml::Value,
    schema: Option<&Schema>,
) -> Result<Entity, PdpError> {
    let map = resource_args.as_mapping().ok_or_else(|| {
        PdpError::Dispatch(
            "cedar:() `resource` must be a mapping with `type` and `id` keys".to_string(),
        )
    })?;

    let entity_type = yaml_string(map, "type").ok_or_else(|| {
        PdpError::Dispatch("cedar:() `resource.type` missing or not a string".to_string())
    })?;
    let id = yaml_string(map, "id").ok_or_else(|| {
        PdpError::Dispatch("cedar:() `resource.id` missing or not a string".to_string())
    })?;

    let attrs_value = map
        .get(serde_yaml::Value::String("attributes".to_string()))
        .cloned()
        .unwrap_or(serde_yaml::Value::Mapping(Default::default()));
    let attrs_json: Value = serde_json::to_value(&attrs_value).map_err(|e| {
        PdpError::Dispatch(format!(
            "cedar:() `resource.attributes` not JSON-representable: {}",
            e
        ))
    })?;

    let entity_json = json!({
        "uid": { "type": entity_type, "id": id },
        "attrs": attrs_json,
        "parents": [],
    });

    Entity::from_json_value(entity_json, schema).map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to construct resource entity '{}::\"{}\"': {}",
            entity_type, id, e
        ))
    })
}

// =====================================================================
// Helpers
// =====================================================================

/// Apply the optional namespace to a bare entity type. `Some("Acme")` +
/// `"User"` → `"Acme::User"`. `None` → `"User"`. Lets operators with
/// namespaced schemas (`Acme::User`, `Acme::Document`) work without
/// each policy author having to hand-prefix everywhere.
fn qualify_type(bare: &str, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) if !ns.is_empty() => format!("{}::{}", ns, bare),
        _ => bare.to_string(),
    }
}

/// Read every `<prefix>X = true` key from the bag and return `[X, ...]`.
/// Used for `role.*` → roles and `perm.*` → permissions, matching
/// apl-cmf's presence-only encoding for role / permission membership.
fn collect_prefixed_bools(bag: &AttributeBag, prefix: &str) -> Vec<String> {
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

/// Read every `claim.<name>` key and assemble a JSON record of the
/// values. Each claim's value type comes through as JSON (`Bool`,
/// `String`, etc.) so Cedar's record-of-records story works.
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
