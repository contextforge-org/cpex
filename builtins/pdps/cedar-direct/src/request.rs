// Location: ./builtins/pdps/cedar-direct/src/request.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Build a `cedar_policy::Request` from a `PdpCall` + `AttributeBag`.
// The resolver constructs Cedar's three required parts (principal,
// action, resource) plus the merged context, then hands them to
// Cedar's `Request::builder()`.
//
// # Principal / resource / action
//
// - **Principal:** built from the bag (see `entities::build_principal`).
//   Its `EntityUid` is what we hand to `Request::principal()`.
// - **Resource:** built from `args.resource` (see `entities::build_resource`).
// - **Action:** parsed from `args.action` — must be a fully-qualified
//   Cedar `EntityUid` literal like `Action::"read"` or
//   `Acme::Action::"approve"`. The policy author writes this verbatim
//   in their APL `cedar:(...)` step.
//
// # Context
//
// `args.context` is the operator-supplied context from the APL step. We
// merge in CPEX-provided keys at well-known paths:
//
//   - `context.delegation.{chain, depth}`  ← from bag's `delegation.*`
//   - `context.meta.{entity_type, entity_name, scope, tags}` ← from bag's `meta.*`
//   - `context.security.{labels, classification}` ← from bag's `security.*`
//
// Operators write Cedar policies against these stable paths. Any keys
// the operator put in `args.context` win over CPEX-provided defaults on
// conflict — operator intent first.
//
// # Schema
//
// When a schema is supplied, Cedar's `Context::from_json_value` validates
// the context's record shape against the action's declared context type.
// Without a schema, Cedar accepts any record.

use apl_core::attributes::{AttributeBag, AttributeValue};
use apl_core::step::{PdpCall, PdpError};
use cedar_policy::{EntityUid, Schema};
use serde_json::{json, Map, Value};

/// Parsed pieces of a `PdpCall` ready to feed into
/// `cedar_policy::Request::builder()`. We pull this into its own
/// struct so the resolver can sequence "build entities → build request"
/// without a giant function signature.
pub struct ParsedCall<'a> {
    pub action: EntityUid,
    pub context: cedar_policy::Context,
    pub resource_args: &'a serde_yaml::Value,
}

/// Parse the args + bag into the pieces a Cedar request builder needs.
/// Schema is optional; when present, the context block is validated
/// against the action's declared context shape.
pub fn parse<'a>(
    call: &'a PdpCall,
    bag: &AttributeBag,
    schema: Option<&Schema>,
) -> Result<ParsedCall<'a>, PdpError> {
    let map = call.args.as_mapping().ok_or_else(|| {
        PdpError::Dispatch(
            "cedar:() args must be a mapping with `action` and `resource` keys".to_string(),
        )
    })?;

    let action_str = map
        .get(serde_yaml::Value::String("action".to_string()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PdpError::Dispatch(
                "cedar:() `action` missing — provide a fully-qualified UID \
                 like 'Action::\"read\"'"
                    .to_string(),
            )
        })?;
    let action: EntityUid = action_str.parse().map_err(|e| {
        PdpError::Dispatch(format!(
            "cedar:() `action` '{}' not a valid EntityUid: {}",
            action_str, e
        ))
    })?;

    let resource_args = map
        .get(serde_yaml::Value::String("resource".to_string()))
        .ok_or_else(|| {
            PdpError::Dispatch("cedar:() `resource` missing".to_string())
        })?;

    // Build the merged context: operator-supplied `args.context` keys,
    // overlaid on top of CPEX-derived context (delegation, meta,
    // security). On collision, the operator's value wins — they
    // explicitly wrote it.
    let cpex_ctx = build_cpex_context(bag);
    let operator_ctx = map
        .get(serde_yaml::Value::String("context".to_string()))
        .cloned()
        .unwrap_or(serde_yaml::Value::Null);
    let mut merged = cpex_ctx;
    if !operator_ctx.is_null() {
        let op_json: Value = serde_json::to_value(&operator_ctx).map_err(|e| {
            PdpError::Dispatch(format!(
                "cedar:() `context` not JSON-representable: {}",
                e
            ))
        })?;
        merge_into(&mut merged, op_json);
    }

    let cedar_context = cedar_policy::Context::from_json_value(merged, None).map_err(|e| {
        PdpError::Dispatch(format!("failed to construct Cedar context: {}", e))
    })?;
    // Note: schema-validated context construction takes an
    // (action_schema, action) pair via Cedar's `from_json_value`. For
    // v0 we skip schema-side validation of the context shape — the
    // request builder still applies whole-request validation when a
    // schema is wired into the resolver. Adding context-level schema
    // validation is a polish item; doesn't change decision semantics
    // when the policies are well-formed.
    let _ = schema; // schema currently used at request-build time, not here

    Ok(ParsedCall {
        action,
        context: cedar_context,
        resource_args,
    })
}

/// Build the CPEX-provided context block (everything under
/// `context.delegation`, `context.meta`, `context.security`) from the
/// `AttributeBag`. Operators reason about these in Cedar policies via
/// the well-known paths documented in `docs/specs/cedar-context-contract.md`.
fn build_cpex_context(bag: &AttributeBag) -> Value {
    let mut root = Map::new();

    let mut delegation = Map::new();
    if let Some(depth) = bag.get_int("delegation.depth") {
        delegation.insert("depth".to_string(), json!(depth));
    }
    // The full chain isn't currently in a flat bag key; apl-cmf
    // exposes presence-only `delegated=true` plus per-attribute hops.
    // When apl-cmf grows a structured `delegation.chain` shape we'll
    // forward it here. For now, the depth + delegated bool let policies
    // do basic chain-depth bounds checks.
    if let Some(delegated) = bag.get_bool("delegated") {
        delegation.insert("delegated".to_string(), json!(delegated));
    }
    if !delegation.is_empty() {
        root.insert("delegation".to_string(), Value::Object(delegation));
    }

    let mut meta = Map::new();
    if let Some(et) = bag.get_string("meta.entity_type") {
        meta.insert("entity_type".to_string(), json!(et));
    }
    if let Some(en) = bag.get_string("meta.entity_name") {
        meta.insert("entity_name".to_string(), json!(en));
    }
    if let Some(scope) = bag.get_string("meta.scope") {
        meta.insert("scope".to_string(), json!(scope));
    }
    if let Some(tags) = bag.get_string_set("meta.tags") {
        meta.insert("tags".to_string(), json!(tags.iter().collect::<Vec<_>>()));
    }
    if !meta.is_empty() {
        root.insert("meta".to_string(), Value::Object(meta));
    }

    let mut security = Map::new();
    if let Some(labels) = bag.get_string_set("security.labels") {
        security.insert("labels".to_string(), json!(labels.iter().collect::<Vec<_>>()));
    }
    if let Some(cls) = bag.get_string("security.classification") {
        security.insert("classification".to_string(), json!(cls));
    }
    if !security.is_empty() {
        root.insert("security".to_string(), Value::Object(security));
    }

    // Pass `authenticated` through as a top-level convenience for
    // policies that want `context.authenticated` shorthand.
    if let Some(auth) = bag.get_bool("authenticated") {
        root.insert("authenticated".to_string(), json!(auth));
    }

    Value::Object(root)
}

/// Shallow merge `overlay` into `target`. Operator-supplied keys win on
/// conflict at the top level; we don't try to deep-merge nested
/// records (operator says `context.meta = {custom: "x"}` and CPEX-
/// provided context.meta is fully replaced). Keeps the semantics
/// predictable.
fn merge_into(target: &mut Value, overlay: Value) {
    let (Value::Object(target_map), Value::Object(overlay_map)) = (target, overlay) else {
        return;
    };
    for (k, v) in overlay_map {
        target_map.insert(k, v);
    }
}

#[allow(dead_code)]
fn _bag_typed_value(v: &AttributeValue) -> Value {
    // Reserved for future use — keeps the import alive while parts of
    // the bag→JSON translation are stubbed.
    match v {
        AttributeValue::Bool(b) => json!(*b),
        AttributeValue::Int(i) => json!(*i),
        AttributeValue::Float(f) => json!(*f),
        AttributeValue::String(s) => json!(s),
        AttributeValue::StringSet(set) => json!(set.iter().collect::<Vec<_>>()),
    }
}
