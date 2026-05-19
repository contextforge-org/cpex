// Location: ./crates/apl-pdp-cedar-direct/src/resolver.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// `CedarDirectResolver` — the `PdpResolver` implementation. Wraps a
// loaded `PolicySet`, an `Authorizer`, and an optional `Schema`, and
// translates each APL `PdpCall` into a Cedar request → decision.
//
// # Construction surface
//
// Three constructors covering the typical sources of Cedar policy:
//
//   - `from_policy_text(text)`   — for inline policy in code or
//                                   unified-config YAML.
//   - `from_policy_file(path)`   — for ops-managed policy files.
//   - `from_config(value)`       — for the unified-config block the
//                                   `AplConfigVisitor` parses. Accepts
//                                   either `policy_text` or
//                                   `policy_file` (or both — policy_text
//                                   wins). Also accepts `schema_text` /
//                                   `schema_file` for optional schema
//                                   loading, plus `entity_namespace`
//                                   and `dialect`.
//
// Construction errors carry rich Cedar-specific messages via
// [`BuildError`]; the visitor wraps these into `VisitorError` →
// `PluginError::Config` at the manager boundary.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{Authorizer, PolicySet, Schema};

use apl_core::attributes::AttributeBag;
use apl_core::step::{PdpCall, PdpDecision, PdpDialect, PdpError, PdpResolver};

use crate::decision::translate;
use crate::entities::build as build_entities;
use crate::error::BuildError;
use crate::request::parse as parse_call;

/// PdpResolver wrapping a bare `cedar-policy` engine. Constructed from
/// policy text / file / config block at startup; evaluates each call
/// against the loaded `PolicySet`.
pub struct CedarDirectResolver {
    policies: Arc<PolicySet>,
    schema: Option<Arc<Schema>>,
    authorizer: Authorizer,
    dialect: PdpDialect,
    /// Optional namespace applied to subject types: `Some("Acme")`
    /// turns "User" into "Acme::User" when building the principal
    /// entity. Lets schemas that namespace their entity types work
    /// without policy authors having to hand-prefix every reference.
    entity_namespace: Option<String>,
}

impl CedarDirectResolver {
    /// Build a resolver from inline Cedar policy text. Use this for
    /// tests, demos, and configs where the policy is small enough to
    /// embed in YAML.
    pub fn from_policy_text(policies: &str) -> Result<Self, BuildError> {
        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| BuildError::PolicyParse(e.to_string()))?;
        Ok(Self {
            policies: Arc::new(policy_set),
            schema: None,
            authorizer: Authorizer::new(),
            dialect: PdpDialect::Cedar,
            entity_namespace: None,
        })
    }

    /// Build a resolver from a Cedar policy file on disk. Convenience
    /// over `from_policy_text` for the production layout where policies
    /// live in their own versioned files.
    pub fn from_policy_file(path: impl AsRef<Path>) -> Result<Self, BuildError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| BuildError::PolicyFile {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_policy_text(&text)
    }

    /// Build a resolver from a unified-config block. Shape:
    ///
    /// ```yaml
    /// dialect: cedar              # optional; default PdpDialect::Cedar
    /// entity_namespace: Acme      # optional; prefixes subject types
    /// policy_text: |              # required (or policy_file)
    ///   @id("owner-override")
    ///   permit(...);
    /// policy_file: /etc/...       # alternative to policy_text
    /// schema_text: |              # optional
    ///   ...
    /// schema_file: /etc/...       # alternative to schema_text
    /// ```
    ///
    /// `policy_text` wins over `policy_file` when both are present.
    /// Same for `schema_text` over `schema_file`. Called by
    /// `AplConfigVisitor` when it sees a Cedar PDP block in the
    /// unified-config YAML.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Self, BuildError> {
        let map = value
            .as_mapping()
            .ok_or_else(|| BuildError::ConfigShape("Cedar PDP config must be a mapping".into()))?;

        // ----- policy source -----
        let policy_text = read_yaml_string(map, "policy_text");
        let policy_file = read_yaml_string(map, "policy_file");
        let policies = match (policy_text, policy_file) {
            (Some(text), _) => text,
            (None, Some(path)) => {
                std::fs::read_to_string(&path).map_err(|source| BuildError::PolicyFile {
                    path: path.clone(),
                    source,
                })?
            }
            (None, None) => {
                return Err(BuildError::ConfigShape(
                    "Cedar PDP config requires `policy_text` or `policy_file`".into(),
                ));
            }
        };
        let policy_set: PolicySet = policies
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| BuildError::PolicyParse(e.to_string()))?;

        // ----- optional schema -----
        let schema_text = read_yaml_string(map, "schema_text");
        let schema_file = read_yaml_string(map, "schema_file");
        let schema = match (schema_text, schema_file) {
            (Some(text), _) => Some(parse_schema(&text)?),
            (None, Some(path)) => {
                let text = std::fs::read_to_string(&path).map_err(|source| BuildError::SchemaFile {
                    path: path.clone(),
                    source,
                })?;
                Some(parse_schema(&text)?)
            }
            (None, None) => None,
        };

        // ----- optional dialect override -----
        let dialect = match read_yaml_string(map, "dialect").as_deref() {
            None | Some("cedar") => PdpDialect::Cedar,
            Some(other) => PdpDialect::Custom(other.to_string()),
        };

        let entity_namespace = read_yaml_string(map, "entity_namespace");

        Ok(Self {
            policies: Arc::new(policy_set),
            schema: schema.map(Arc::new),
            authorizer: Authorizer::new(),
            dialect,
            entity_namespace,
        })
    }

    /// Override the resolver's dialect. Lets operators register a Cedar
    /// engine under a custom name (e.g. `PdpDialect::Custom("workload")`)
    /// so they can coexist with another Cedar engine on the same
    /// `PdpRouter`.
    pub fn with_dialect(mut self, dialect: PdpDialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Attach an `entity_namespace`. Applied at request time to
    /// subject types: `Some("Acme")` + bag `subject.type=User` →
    /// principal UID `Acme::User::"<id>"`.
    pub fn with_entity_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.entity_namespace = Some(namespace.into());
        self
    }

    /// Attach a schema after construction. Useful when the schema
    /// comes from a separate source than the policy text.
    pub fn with_schema(mut self, schema: Schema) -> Self {
        self.schema = Some(Arc::new(schema));
        self
    }
}

#[async_trait]
impl PdpResolver for CedarDirectResolver {
    fn dialect(&self) -> PdpDialect {
        self.dialect.clone()
    }

    async fn evaluate(
        &self,
        call: &PdpCall,
        bag: &AttributeBag,
    ) -> Result<PdpDecision, PdpError> {
        let parsed = parse_call(call, bag, self.schema.as_deref())?;
        let entities = build_entities(
            bag,
            parsed.resource_args,
            self.schema.as_deref(),
            self.entity_namespace.as_deref(),
        )?;

        let principal_uid = build_principal_uid(bag, self.entity_namespace.as_deref())?;
        let resource_uid = build_resource_uid(parsed.resource_args)?;

        let request = cedar_policy::Request::new(
            principal_uid,
            parsed.action,
            resource_uid,
            parsed.context,
            self.schema.as_deref(),
        )
        .map_err(|e| PdpError::Dispatch(format!("Cedar request validation failed: {}", e)))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);

        Ok(translate(&response, &self.policies))
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn parse_schema(text: &str) -> Result<Schema, BuildError> {
    Schema::from_cedarschema_str(text)
        .map(|(schema, _warnings)| schema)
        .map_err(|e| BuildError::SchemaParse(e.to_string()))
}

fn read_yaml_string(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::String(key.to_string()))?
        .as_str()
        .map(|s| s.to_string())
}

/// Build the principal `EntityUid` for the Cedar request. Returns the
/// SAME UID that `entities::build_principal` produces; both have to
/// agree on type + id since Cedar resolves the request's principal
/// reference into the entity set by UID equality.
fn build_principal_uid(
    bag: &AttributeBag,
    namespace: Option<&str>,
) -> Result<cedar_policy::EntityUid, PdpError> {
    let id = bag
        .get_string("subject.id")
        .ok_or_else(|| PdpError::Dispatch("bag missing `subject.id`".to_string()))?;
    let kind = bag.get_string("subject.type").unwrap_or("User");
    let entity_type = match namespace {
        Some(ns) if !ns.is_empty() => format!("{}::{}", ns, kind),
        _ => kind.to_string(),
    };
    let uid_str = format!("{}::\"{}\"", entity_type, escape_id(id));
    uid_str.parse().map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to parse principal UID '{}': {}",
            uid_str, e
        ))
    })
}

fn build_resource_uid(resource_args: &serde_yaml::Value) -> Result<cedar_policy::EntityUid, PdpError> {
    let map = resource_args.as_mapping().ok_or_else(|| {
        PdpError::Dispatch("cedar:() `resource` must be a mapping".to_string())
    })?;
    let type_name = read_yaml_string(map, "type")
        .ok_or_else(|| PdpError::Dispatch("cedar:() `resource.type` missing".to_string()))?;
    let id = read_yaml_string(map, "id")
        .ok_or_else(|| PdpError::Dispatch("cedar:() `resource.id` missing".to_string()))?;
    let uid_str = format!("{}::\"{}\"", type_name, escape_id(&id));
    uid_str.parse().map_err(|e| {
        PdpError::Dispatch(format!(
            "failed to parse resource UID '{}': {}",
            uid_str, e
        ))
    })
}

/// Cedar identifiers in double-quoted form need backslash + quote
/// escaping. Most subject IDs are well-behaved (UUIDs, JWT sub
/// claims) — escape defensively for the cases that aren't.
fn escape_id(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
