// Location: ./crates/cpex-hosts-python/src/credential_payloads.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// PPE's identity and delegation payloads, on the worker's wire.
//
// # Why this exists
//
// PPE dispatches `identity.resolve` with `praxis_policy_core::identity::
// IdentityPayload` and `token.delegate` with `delegation::DelegationPayload`.
// The FFI, the Python bindings and the APL delegate step all build those
// types. The Python worker knows neither: it rebuilds its own
// `IdentityPayload` / `DelegationPayload` Pydantic models (the shapes the
// `legacy::payloads` structs mirror), and its plugins answer with an
// `IdentityResult` / `DelegationResult`. This module translates both ways:
//
//   outbound: the PPE payload ──> the worker model's JSON, minus every secret
//   inbound:  the plugin's result ──> a clone of the dispatched PPE payload
//             with only the output fields the result carries written
//
// Mapping back onto a clone (the `cmf_shim` pattern) is what lets PPE's own
// downcasts succeed: `IdentityPayload::from_pipeline_result` and
// `DelegationPayload::from_pipeline_result` look for exactly these types, and
// the input fields PPE keeps private stay what the host set.
//
// # Credentials
//
// No raw token travels in the JSON built here. `raw_token` is sent empty and
// `bearer_token` is not sent at all; a plugin that declared the matching
// capability gets the plaintext from the separate `credential` object
// (`crate::credentials`), and only that plugin does. The identity headers are
// the other channel a token can ride, so the public copy drops the
// credential-bearing ones: the configured source header, `authorization`,
// `proxy-authorization`, cookies, `x-api-key`, and any header whose name or
// value contains the token. The capability-gated `credential` object carries
// the full header map instead.
//
// # Field decisions
//
//   identity.resolve, outbound
//     raw_token             sent empty; plaintext only on the gated channel
//     source                sent (PPE's wire spelling)
//     source_header         not sent; the gated channel names it
//     headers               sent minus credential-bearing headers
//     client_host/port      sent
//     resolver outputs      not sent; the Python model has no slot for them,
//                           and they survive on the clone
//
//   identity.resolve, inbound (`IdentityResult`, or an echoed payload)
//     subject, delegation   written when set; a field PPE cannot hold fails
//                           closed
//     raw_claims            merged
//     rejected              true becomes a deny carrying reject_reason and
//                           reject_status
//     input fields          ignored: PPE treats them as canonical for the
//                           chain, as `IdentityPayload::merge` does
//     anything else         fails closed when set
//
//   token.delegate, outbound
//     bearer_token          not sent; plaintext only on the gated channel
//     actor token / role    refused when set: the Python model cannot carry
//                           an actor, so a minted token would lose its `act`
//     subject               refused unless `user`: the Python model assumes
//                           the bearer is the user's token
//     everything else       sent
//
//   token.delegate, inbound (`DelegationResult`, or an echoed payload)
//     delegated_token       becomes `delegated_token`, for the target
//                           audience (or target name) and the required
//                           permissions
//     forwarded_headers     accepted only as the one header that carries the
//                           minted token, which names its outbound header;
//                           anything else fails closed
//     cache_ttl             bounds the minted token's expiry
//     cache_key             ignored: PPE leaves caching to the handler
//     delegation_update     written when it is not the empty default
//     input fields          ignored, as above
//     anything else         fails closed when set

use std::collections::HashMap;

use praxis_policy_core::delegation::{DelegationPayload, DelegationSubject, HOOK_TOKEN_DELEGATE};
use praxis_policy_core::error::PluginViolation;
use praxis_policy_core::extensions::{DelegationExtension, RawDelegatedToken, SubjectExtension};
use praxis_policy_core::hooks::payload::PluginPayload;
use praxis_policy_core::identity::{HOOK_IDENTITY_RESOLVE, IdentityPayload};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::error::HostError;

/// Header an identity payload's credential arrives in when it names none.
const DEFAULT_CREDENTIAL_HEADER: &str = "authorization";

/// Header names that carry credentials by convention, compared lowercase.
/// Never sent in the public header map, whatever the source header is.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
];

/// Header the minted token is attached under when the plugin names none.
const DEFAULT_OUTBOUND_HEADER: &str = "Authorization";

/// Lifetime given to a minted token whose plugin reported no `cache_ttl`.
///
/// The Python `DelegationResult` has no expiry field, so the host has to pick
/// one. Short on purpose: an expiry the issuer did not state should make a
/// consumer re-delegate soon rather than reuse the token for long.
const DEFAULT_DELEGATED_TOKEN_TTL_SECS: i64 = 60;

/// Fields of the worker's `IdentityPayload` model. A plugin that echoes its
/// payload back returns these; PPE keeps the matching fields private.
const IDENTITY_INPUT_FIELDS: &[&str] = &[
    "raw_token",
    "source",
    "headers",
    "client_host",
    "client_port",
];

/// Fields of the worker's `DelegationPayload` model, ignored on the way back
/// for the same reason.
const DELEGATION_INPUT_FIELDS: &[&str] = &[
    "target_name",
    "target_type",
    "target_audience",
    "required_permissions",
    "trust_domain",
    "auth_enforced_by",
    "route_attenuation",
    "bearer_token",
];

/// Whether `payload` is one of the two PPE payloads this module translates.
pub fn is_ppe_credential_payload(payload: &dyn PluginPayload) -> bool {
    let any = payload.as_any();
    any.is::<IdentityPayload>() || any.is::<DelegationPayload>()
}

// --- identity.resolve -------------------------------------------------------

/// The inbound credential an identity payload carries, if any.
///
/// `raw_token` first. A host that deserialized the payload (the FFI and the
/// Python bindings do) has an empty `raw_token` and the credential in the
/// header map, so the source header is read next, with a `Bearer ` prefix
/// stripped the way PPE's own JWT resolver strips it.
pub(crate) fn inbound_token(payload: &IdentityPayload) -> Option<String> {
    let raw = payload.raw_token();
    if !raw.trim().is_empty() {
        return Some(raw.to_string());
    }
    let header = payload.source_header().unwrap_or(DEFAULT_CREDENTIAL_HEADER);
    let (_, value) = header_entry(payload.headers(), header)?;
    let token = strip_bearer(value).trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// The header the credential arrived in, spelled as the header map spells it
/// when the map holds it.
pub(crate) fn credential_header_name(payload: &IdentityPayload) -> String {
    let header = payload.source_header().unwrap_or(DEFAULT_CREDENTIAL_HEADER);
    header_entry(payload.headers(), header)
        .map_or_else(|| header.to_string(), |(name, _)| name.to_string())
}

/// Case-insensitive header lookup, returning the key as stored.
fn header_entry<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Option<(&'a str, &'a str)> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(k, v)| (k.as_str(), v.as_str()))
}

fn strip_bearer(value: &str) -> &str {
    let trimmed = value.trim_start();
    match trimmed.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("bearer ") => &trimmed[7..],
        _ => trimmed,
    }
}

/// The request headers with every credential-bearing one removed.
///
/// This is the copy every plugin sees, capability or not, so it has to be
/// safe for a plugin that declared nothing.
pub(crate) fn public_headers(payload: &IdentityPayload) -> HashMap<String, String> {
    let token = inbound_token(payload);
    let source = payload
        .source_header()
        .unwrap_or(DEFAULT_CREDENTIAL_HEADER)
        .to_ascii_lowercase();
    payload
        .headers()
        .iter()
        .filter(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            !CREDENTIAL_HEADERS.contains(&lower.as_str())
                && lower != source
                && token
                    .as_deref()
                    .is_none_or(|t| !name.contains(t) && !value.contains(t))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The worker `IdentityPayload` JSON for a PPE identity payload.
pub fn identity_to_worker(payload: &IdentityPayload) -> Result<Value, HostError> {
    let source = serde_json::to_value(payload.source()).map_err(|e| HostError::Protocol {
        message: format!("could not serialize the identity payload's source: {e}"),
    })?;
    let mut json = serde_json::json!({
        // Required by the Python model. Empty here; the plaintext reaches a
        // plugin that declared `read_inbound_credentials` through the
        // `credential` object, which the worker folds onto this field.
        "raw_token": "",
        "source": source,
        "headers": public_headers(payload),
    });
    if let Some(host) = payload.client_host() {
        json["client_host"] = Value::String(host.to_string());
    }
    if let Some(port) = payload.client_port() {
        json["client_port"] = Value::from(port);
    }
    Ok(json)
}

/// What an identity plugin's result means for the PPE pipeline.
#[derive(Debug)]
pub enum IdentityOutcome {
    /// The dispatched payload with the plugin's output fields written.
    Resolved(Box<IdentityPayload>),
    /// The plugin set `rejected`. Carried as a deny, which PPE's identity
    /// model uses in place of a flag on the payload.
    Rejected(PluginViolation),
}

/// Map an identity plugin's modified payload back onto a clone of the one
/// PPE dispatched.
pub fn identity_from_worker(
    original: &IdentityPayload,
    modified: Value,
) -> Result<IdentityOutcome, HostError> {
    let fields = object(HOOK_IDENTITY_RESOLVE, modified)?;
    for (key, value) in &fields {
        let known = matches!(
            key.as_str(),
            "subject"
                | "delegation"
                | "raw_claims"
                | "rejected"
                | "reject_status"
                | "reject_reason"
        ) || IDENTITY_INPUT_FIELDS.contains(&key.as_str());
        if !known && !is_empty(value) {
            return Err(unrepresentable(HOOK_IDENTITY_RESOLVE, key));
        }
    }

    match fields.get("rejected") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {},
        Some(Value::Bool(true)) => return Ok(IdentityOutcome::Rejected(rejection(&fields)?)),
        Some(_) => {
            return Err(protocol(
                HOOK_IDENTITY_RESOLVE,
                "`rejected` must be a boolean",
            ));
        },
    }

    let mut resolved = original.clone();
    if let Some(subject) = fields.get("subject").filter(|v| !v.is_null()) {
        resolved.subject = Some(parse_lossless::<SubjectExtension>(
            HOOK_IDENTITY_RESOLVE,
            "subject",
            &python_subject(subject),
        )?);
    }
    if let Some(delegation) = fields.get("delegation").filter(|v| !v.is_null()) {
        resolved.delegation = Some(parse_lossless::<DelegationExtension>(
            HOOK_IDENTITY_RESOLVE,
            "delegation",
            delegation,
        )?);
    }
    match fields.get("raw_claims") {
        None | Some(Value::Null) => {},
        Some(Value::Object(claims)) => {
            for (name, value) in claims {
                resolved.raw_claims.insert(name.clone(), value.clone());
            }
        },
        Some(_) => {
            return Err(protocol(
                HOOK_IDENTITY_RESOLVE,
                "`raw_claims` must be an object",
            ));
        },
    }
    Ok(IdentityOutcome::Resolved(Box::new(resolved)))
}

/// The deny a `rejected` identity result stands for.
fn rejection(fields: &Map<String, Value>) -> Result<PluginViolation, HostError> {
    let reason = match fields.get("reject_reason") {
        None | Some(Value::Null) => "",
        Some(Value::String(reason)) => reason.as_str(),
        Some(_) => {
            return Err(protocol(
                HOOK_IDENTITY_RESOLVE,
                "`reject_reason` must be a string",
            ));
        },
    };
    let reason = if reason.is_empty() {
        "the identity plugin rejected the credential"
    } else {
        reason
    };
    let mut violation = PluginViolation::new("auth.rejected", reason);
    match fields.get("reject_status") {
        None | Some(Value::Null) => {},
        Some(status) => {
            let status = status.as_i64().ok_or_else(|| {
                protocol(HOOK_IDENTITY_RESOLVE, "`reject_status` must be an integer")
            })?;
            violation = violation.with_proto_error_code(status);
            violation
                .details
                .insert("reject_status".into(), Value::from(status));
        },
    }
    Ok(violation)
}

/// The Python `SubjectExtension` names its kind `type`; PPE's names it
/// `subject_type`. Renamed so the lossless check does not read it as dropped.
fn python_subject(subject: &Value) -> Value {
    let mut subject = subject.clone();
    if let Some(fields) = subject.as_object_mut()
        && !fields.contains_key("subject_type")
        && let Some(kind) = fields.remove("type")
    {
        fields.insert("subject_type".into(), kind);
    }
    subject
}

// --- token.delegate ---------------------------------------------------------

/// The worker `DelegationPayload` JSON for a PPE delegation payload.
///
/// Refuses an exchange the Python model cannot describe, before anything
/// reaches the worker.
pub fn delegation_to_worker(payload: &DelegationPayload) -> Result<Value, HostError> {
    if payload.actor_role().is_some() || !payload.actor_token().is_empty() {
        return Err(protocol(
            HOOK_TOKEN_DELEGATE,
            "the delegation carries an RFC 8693 actor, which the Python DelegationPayload cannot \
             carry; a token minted without it would lose its `act` attribution",
        ));
    }
    if payload.subject() != &DelegationSubject::User {
        return Err(protocol(
            HOOK_TOKEN_DELEGATE,
            "the delegation is for a subject other than `user`, and the Python DelegationPayload \
             reads its bearer token as the user's; a plugin would attribute the minted token to \
             the wrong principal",
        ));
    }

    let mut json = serde_json::json!({
        "target_name": payload.target_name(),
        "target_type": to_json(payload.target_type())?,
        "required_permissions": payload.required_permissions(),
        "auth_enforced_by": to_json(&payload.auth_enforced_by())?,
    });
    if let Some(audience) = payload.target_audience() {
        json["target_audience"] = Value::String(audience.to_string());
    }
    if let Some(domain) = payload.trust_domain() {
        json["trust_domain"] = Value::String(domain.to_string());
    }
    if let Some(attenuation) = payload.route_attenuation() {
        json["route_attenuation"] = to_json(attenuation)?;
    }
    Ok(json)
}

/// Map a delegation plugin's modified payload back onto a clone of the one
/// PPE dispatched.
pub fn delegation_from_worker(
    original: &DelegationPayload,
    modified: Value,
) -> Result<DelegationPayload, HostError> {
    let fields = object(HOOK_TOKEN_DELEGATE, modified)?;
    for (key, value) in &fields {
        let known = matches!(
            key.as_str(),
            "delegated_token"
                | "delegation_update"
                | "forwarded_headers"
                | "cache_key"
                | "cache_ttl"
        ) || DELEGATION_INPUT_FIELDS.contains(&key.as_str());
        if !known && !is_empty(value) {
            return Err(unrepresentable(HOOK_TOKEN_DELEGATE, key));
        }
    }

    let token = match fields.get("delegated_token") {
        None | Some(Value::Null) => None,
        Some(Value::String(token)) if !token.trim().is_empty() => Some(token.as_str()),
        Some(Value::String(_)) => {
            return Err(protocol(
                HOOK_TOKEN_DELEGATE,
                "the plugin returned an empty `delegated_token`",
            ));
        },
        Some(_) => {
            return Err(protocol(
                HOOK_TOKEN_DELEGATE,
                "`delegated_token` must be a string",
            ));
        },
    };
    let forwarded = match fields.get("forwarded_headers") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(headers)) => headers.clone(),
        Some(_) => {
            return Err(protocol(
                HOOK_TOKEN_DELEGATE,
                "`forwarded_headers` must be an object",
            ));
        },
    };

    let mut resolved = original.clone();
    match token {
        Some(token) => {
            let outbound_header = outbound_header(token, &forwarded)?;
            let now = chrono::Utc::now();
            let ttl = match fields.get("cache_ttl") {
                None | Some(Value::Null) => DEFAULT_DELEGATED_TOKEN_TTL_SECS,
                Some(ttl) => ttl.as_i64().filter(|secs| *secs > 0).ok_or_else(|| {
                    protocol(
                        HOOK_TOKEN_DELEGATE,
                        "`cache_ttl` must be a positive integer",
                    )
                })?,
            };
            let audience = original
                .target_audience()
                .unwrap_or_else(|| original.target_name())
                .to_string();
            resolved.delegated_token = Some(RawDelegatedToken::new(
                token,
                outbound_header,
                audience,
                original.required_permissions().to_vec(),
                now + chrono::Duration::seconds(ttl),
            ));
            resolved.delegation_mode = Some(original.subject().default_mode());
            resolved.minted_at = Some(now);
        },
        None if !forwarded.is_empty() => {
            return Err(protocol(
                HOOK_TOKEN_DELEGATE,
                "the plugin returned `forwarded_headers` with no `delegated_token`, and a PPE \
                 delegation payload carries headers only as the minted token's outbound header",
            ));
        },
        None => {},
    }

    if let Some(update) = fields.get("delegation_update").filter(|v| !v.is_null()) {
        let update: DelegationExtension =
            parse_lossless(HOOK_TOKEN_DELEGATE, "delegation_update", update)?;
        if !is_default_delegation(&update) {
            resolved.delegation_update = Some(update);
        }
    }
    Ok(resolved)
}

/// The header the minted token goes upstream in.
///
/// The Python result can name it through `forwarded_headers`. The PPE payload
/// holds one outbound header for one token, so the only shape that maps is a
/// single header whose value is the token, bare or as a bearer.
fn outbound_header(token: &str, forwarded: &Map<String, Value>) -> Result<String, HostError> {
    let mut entries = forwarded.iter();
    let Some((name, value)) = entries.next() else {
        return Ok(DEFAULT_OUTBOUND_HEADER.to_string());
    };
    let carries_token = value
        .as_str()
        .is_some_and(|v| v == token || strip_bearer(v) == token);
    if entries.next().is_some() || !carries_token {
        return Err(protocol(
            HOOK_TOKEN_DELEGATE,
            "the plugin returned `forwarded_headers` other than the single header carrying the \
             minted token, and a PPE delegation payload cannot carry extra headers",
        ));
    }
    Ok(name.clone())
}

fn is_default_delegation(update: &DelegationExtension) -> bool {
    update.chain.is_empty()
        && update.depth == 0
        && update.origin_subject_id.is_none()
        && update.actor_subject_id.is_none()
        && !update.delegated
}

// --- shared -----------------------------------------------------------------

fn object(hook: &str, value: Value) -> Result<Map<String, Value>, HostError> {
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err(protocol(hook, "the modified payload is not a JSON object")),
    }
}

/// Deserialize into a PPE type, failing closed when that drops a set field.
///
/// PPE's extension types ignore fields they do not know, so a plain
/// `from_value` would silently lose whatever the Python model has and PPE's
/// does not. Serializing back and comparing which set fields survived catches
/// that. The error names the field path, never a value.
fn parse_lossless<T: DeserializeOwned + Serialize>(
    hook: &str,
    field: &str,
    value: &Value,
) -> Result<T, HostError> {
    let parsed: T = serde_json::from_value(value.clone()).map_err(|_| {
        protocol(
            hook,
            &format!("`{field}` does not match the PPE type it maps to"),
        )
    })?;
    let back = serde_json::to_value(&parsed).map_err(|e| HostError::Protocol {
        message: format!("could not re-serialize `{field}`: {e}"),
    })?;
    if let Some(path) = first_dropped(value, &back, field) {
        return Err(unrepresentable(hook, &path));
    }
    Ok(parsed)
}

/// The path of the first set field in `original` that `round_tripped` lost.
fn first_dropped(original: &Value, round_tripped: &Value, path: &str) -> Option<String> {
    match (original, round_tripped) {
        (Value::Object(fields), Value::Object(kept)) => fields.iter().find_map(|(key, value)| {
            if is_empty(value) {
                return None;
            }
            let path = format!("{path}.{key}");
            match kept.get(key) {
                None => Some(path),
                Some(kept) => first_dropped(value, kept, &path),
            }
        }),
        (Value::Array(items), Value::Array(kept)) => {
            if items.len() != kept.len() {
                return Some(path.to_string());
            }
            items
                .iter()
                .zip(kept)
                .enumerate()
                .find_map(|(i, (item, kept))| first_dropped(item, kept, &format!("{path}[{i}]")))
        },
        _ => None,
    }
}

/// A value that carries nothing: what Pydantic dumps for an unset field.
fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::String(s) => s.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        Value::Bool(true) | Value::Number(_) => false,
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<Value, HostError> {
    serde_json::to_value(value).map_err(|e| HostError::Protocol {
        message: format!("could not serialize a delegation payload field: {e}"),
    })
}

fn protocol(hook: &str, message: &str) -> HostError {
    HostError::Protocol {
        message: format!("hook '{hook}': {message}"),
    }
}

fn unrepresentable(hook: &str, field: &str) -> HostError {
    protocol(
        hook,
        &format!(
            "the plugin returned `{field}`, which the PPE payload has nowhere to hold; refusing \
             to drop it silently"
        ),
    )
}

#[cfg(test)]
mod tests {
    use praxis_policy_core::delegation::AttenuationConfig;
    use praxis_policy_core::extensions::raw_credentials::TokenRole;
    use praxis_policy_core::extensions::{DelegationHop, SubjectType};
    use praxis_policy_core::identity::TokenSource;
    use serde_json::json;

    use super::*;

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.IDENTITY-PLAINTEXT.sig";
    const MINTED: &str = "MINTED-DELEGATED-PLAINTEXT";

    fn identity() -> IdentityPayload {
        IdentityPayload::new(TOKEN, TokenSource::Bearer)
            .with_source_header("x-user-token")
            .with_headers(HashMap::from([
                ("authorization".into(), format!("Bearer {TOKEN}")),
                ("x-user-token".into(), "opaque-user-credential".into()),
                ("cookie".into(), "session=COOKIE-SECRET".into()),
                ("x-echo".into(), format!("copy:{TOKEN}")),
                ("x-tenant".into(), "acme".into()),
            ]))
            .with_client_host("10.0.0.1")
            .with_client_port(8443)
    }

    fn delegation() -> DelegationPayload {
        DelegationPayload::new(TOKEN, "billing-api")
            .with_target_audience("https://billing.example.com")
            .with_required_permissions(vec!["invoices:read".into()])
            .with_trust_domain("example.org")
            .with_route_attenuation(AttenuationConfig {
                capabilities: vec!["read".into()],
                ttl_seconds: Some(120),
                ..Default::default()
            })
    }

    fn resolved(outcome: IdentityOutcome) -> IdentityPayload {
        match outcome {
            IdentityOutcome::Resolved(payload) => *payload,
            IdentityOutcome::Rejected(v) => panic!("expected a resolved payload, got {v:?}"),
        }
    }

    // --- identity outbound ----------------------------------------------------

    #[test]
    fn identity_json_carries_no_credential_material() {
        let json = identity_to_worker(&identity()).unwrap();
        let wire = json.to_string();
        assert!(!wire.contains("IDENTITY-PLAINTEXT"), "token leaked: {wire}");
        assert!(
            !wire.contains("opaque-user-credential"),
            "source header leaked: {wire}"
        );
        assert!(!wire.contains("COOKIE-SECRET"), "cookie leaked: {wire}");

        assert_eq!(json["raw_token"], "");
        assert_eq!(json["source"], "bearer");
        assert_eq!(json["headers"], json!({"x-tenant": "acme"}));
        assert_eq!(json["client_host"], "10.0.0.1");
        assert_eq!(json["client_port"], 8443);
    }

    #[test]
    fn identity_json_matches_the_worker_model() {
        // The legacy struct mirrors the worker's Pydantic model field for field.
        let json = identity_to_worker(&identity()).unwrap();
        let mirrored: crate::legacy::IdentityResolvePayload =
            serde_json::from_value(json).expect("the worker model accepts the shape");
        assert_eq!(mirrored.source, "bearer");
    }

    #[test]
    fn a_header_borne_credential_is_found_and_kept_off_the_public_headers() {
        // The FFI and the Python bindings deserialize the payload, so the token
        // arrives in the header map and `raw_token` is empty.
        let payload: IdentityPayload = serde_json::from_value(json!({
            "source": "bearer",
            "headers": {"Authorization": format!("Bearer {TOKEN}"), "x-tenant": "acme"},
        }))
        .unwrap();
        assert_eq!(inbound_token(&payload).as_deref(), Some(TOKEN));
        assert_eq!(credential_header_name(&payload), "Authorization");
        assert_eq!(
            public_headers(&payload),
            HashMap::from([("x-tenant".to_string(), "acme".to_string())])
        );
    }

    #[test]
    fn a_custom_source_keeps_its_wire_spelling() {
        let payload = IdentityPayload::new(TOKEN, TokenSource::Custom("magic-link".into()));
        assert_eq!(
            identity_to_worker(&payload).unwrap()["source"],
            "magic-link"
        );
    }

    // --- identity inbound -----------------------------------------------------

    #[test]
    fn an_identity_result_maps_onto_a_clone_of_the_dispatched_payload() {
        let original = identity();
        let back = resolved(
            identity_from_worker(
                &original,
                json!({
                    "subject": {
                        "id": "alice", "type": "user", "roles": ["hr"],
                        "permissions": [], "teams": [], "claims": {"dept": "people"},
                    },
                    "delegation": null,
                    "rejected": false,
                    "reject_status": 401,
                    "reject_reason": "",
                    "raw_claims": {"sub": "alice"},
                }),
            )
            .unwrap(),
        );

        let subject = back.subject.as_ref().expect("the subject is written");
        assert_eq!(subject.id.as_deref(), Some("alice"));
        assert_eq!(subject.subject_type, Some(SubjectType::User));
        assert!(subject.roles.contains("hr"));
        assert_eq!(subject.claims["dept"], "people");
        assert_eq!(back.raw_claims["sub"], "alice");

        // Input fields are the dispatched ones, so PPE's later steps still
        // read the host's credential.
        assert_eq!(back.raw_token(), TOKEN);
        assert_eq!(back.source_header(), Some("x-user-token"));
        assert_eq!(back.headers().len(), original.headers().len());
    }

    #[test]
    fn a_resolved_identity_survives_ppes_pipeline_downcast() {
        let back = resolved(
            identity_from_worker(
                &identity(),
                json!({"subject": {"id": "alice", "type": "user"}}),
            )
            .unwrap(),
        );
        let boxed: Box<dyn PluginPayload> = Box::new(back);
        let result = praxis_policy_core::executor::PipelineResult::allowed_with(
            boxed,
            praxis_policy_core::extensions::Extensions::default(),
            Default::default(),
        );
        let extracted = IdentityPayload::from_pipeline_result(&result)
            .expect("PPE downcasts the modified payload to IdentityPayload");
        assert_eq!(
            extracted.subject.and_then(|s| s.id).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn an_echoed_identity_payload_changes_nothing() {
        let original = identity();
        let echo = json!({
            "raw_token": "**********", "source": "custom",
            "headers": {"x-injected": "1"}, "client_host": "6.6.6.6", "client_port": 1,
        });
        let back = resolved(identity_from_worker(&original, echo).unwrap());
        assert!(back.subject.is_none());
        assert_eq!(
            back.client_host(),
            Some("10.0.0.1"),
            "inputs stay canonical"
        );
        assert_eq!(back.raw_token(), TOKEN);
    }

    #[test]
    fn a_rejected_identity_becomes_a_deny() {
        let outcome = identity_from_worker(
            &identity(),
            json!({
                "subject": {"id": "alice", "type": "user"},
                "rejected": true, "reject_status": 403, "reject_reason": "token expired",
            }),
        )
        .unwrap();
        let IdentityOutcome::Rejected(violation) = outcome else {
            panic!("rejected must deny even when a subject is set");
        };
        assert_eq!(violation.code, "auth.rejected");
        assert_eq!(violation.reason, "token expired");
        assert_eq!(violation.proto_error_code, Some(403));
        assert_eq!(violation.details["reject_status"], 403);
    }

    #[test]
    fn an_unknown_identity_result_field_fails_closed() {
        let err = identity_from_worker(&identity(), json!({"client": {"id": "gw"}})).unwrap_err();
        assert!(matches!(err, HostError::Protocol { .. }), "{err:?}");
        assert!(err.to_string().contains("`client`"), "{err}");
    }

    #[test]
    fn a_subject_field_ppe_cannot_hold_fails_closed() {
        let err = identity_from_worker(
            &identity(),
            json!({"subject": {"id": "alice", "type": "user", "tenant": "acme"}}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("subject.tenant"), "{err}");
    }

    #[test]
    fn a_malformed_subject_fails_closed_without_echoing_values() {
        let err = identity_from_worker(
            &identity(),
            json!({"subject": {"id": "SUBJECT-VALUE", "type": "SUBJECT-VALUE"}}),
        )
        .unwrap_err();
        assert!(!err.to_string().contains("SUBJECT-VALUE"), "{err}");
    }

    // --- delegation outbound --------------------------------------------------

    #[test]
    fn delegation_json_matches_the_worker_model_and_carries_no_token() {
        let json = delegation_to_worker(&delegation()).unwrap();
        assert!(!json.to_string().contains("IDENTITY-PLAINTEXT"), "{json}");
        assert!(json.get("bearer_token").is_none());

        let mirrored: crate::legacy::TokenDelegatePayload =
            serde_json::from_value(json.clone()).expect("the worker model accepts the shape");
        assert_eq!(mirrored.target_name, "billing-api");
        assert_eq!(mirrored.target_type, "tool");
        assert_eq!(
            mirrored.target_audience.as_deref(),
            Some("https://billing.example.com")
        );
        assert_eq!(mirrored.required_permissions, vec!["invoices:read"]);
        assert_eq!(mirrored.trust_domain.as_deref(), Some("example.org"));
        assert_eq!(mirrored.auth_enforced_by, "caller");
        assert_eq!(json["route_attenuation"]["ttl_seconds"], 120);
    }

    #[test]
    fn a_delegation_with_an_actor_fails_closed() {
        let payload = delegation().with_actor(TokenRole::CallerWorkload, "svid");
        let err = delegation_to_worker(&payload).unwrap_err();
        assert!(err.to_string().contains("actor"), "{err}");
    }

    #[test]
    fn a_delegation_for_another_subject_fails_closed() {
        let payload = delegation().with_subject(DelegationSubject::ThisWorkload);
        let err = delegation_to_worker(&payload).unwrap_err();
        assert!(err.to_string().contains("subject"), "{err}");
    }

    // --- delegation inbound ---------------------------------------------------

    #[test]
    fn a_delegation_result_maps_onto_a_clone_of_the_dispatched_payload() {
        let original = delegation();
        let back = delegation_from_worker(
            &original,
            json!({
                "delegated_token": MINTED,
                "delegation_update": {
                    "chain": [{"subject_id": "alice", "subject_type": "user",
                               "audience": "https://billing.example.com",
                               "scopes_granted": ["invoices:read"],
                               "timestamp": "2026-01-01T00:00:00Z",
                               "ttl_seconds": null, "strategy": "token_exchange",
                               "from_cache": false}],
                    "depth": 1, "origin_subject_id": "alice", "actor_subject_id": "alice",
                    "delegated": true, "age_seconds": 0.0,
                },
                "forwarded_headers": {"X-Upstream-Auth": format!("Bearer {MINTED}")},
                "cache_key": "k",
                "cache_ttl": 300,
            }),
        )
        .unwrap();

        let token = back.delegated_token.as_ref().expect("the token is written");
        assert_eq!(token.token.as_str(), MINTED);
        assert_eq!(token.outbound_header, "X-Upstream-Auth");
        assert_eq!(token.audience, "https://billing.example.com");
        assert_eq!(token.scopes, vec!["invoices:read"]);
        let ttl = token.expires_at - chrono::Utc::now();
        assert!(ttl.num_seconds() > 250 && ttl.num_seconds() <= 300, "{ttl}");
        assert_eq!(
            back.delegation_mode,
            Some(praxis_policy_core::extensions::raw_credentials::DelegationMode::OnBehalfOfUser)
        );
        let update = back
            .delegation_update
            .as_ref()
            .expect("the chain update is written");
        assert_eq!(update.depth, 1);
        assert_eq!(update.chain.len(), 1);

        // The caller's credential stays on the clone for PPE to apply.
        assert_eq!(back.bearer_token(), TOKEN);

        let boxed: Box<dyn PluginPayload> = Box::new(back);
        let result = praxis_policy_core::executor::PipelineResult::allowed_with(
            boxed,
            praxis_policy_core::extensions::Extensions::default(),
            Default::default(),
        );
        assert!(
            DelegationPayload::from_pipeline_result(&result).is_some(),
            "PPE downcasts the modified payload to DelegationPayload"
        );
    }

    #[test]
    fn a_minimal_delegation_result_uses_the_defaults() {
        let back = delegation_from_worker(
            &delegation(),
            json!({"delegated_token": MINTED, "delegation_update": {
                "chain": [], "depth": 0, "origin_subject_id": null,
                "actor_subject_id": null, "delegated": false, "age_seconds": 0.0,
            }, "forwarded_headers": {}, "cache_key": null, "cache_ttl": null}),
        )
        .unwrap();
        let token = back.delegated_token.unwrap();
        assert_eq!(token.outbound_header, DEFAULT_OUTBOUND_HEADER);
        assert!(
            back.delegation_update.is_none(),
            "an empty default update is no update"
        );
    }

    #[test]
    fn extra_forwarded_headers_fail_closed() {
        for forwarded in [
            json!({"Authorization": format!("Bearer {MINTED}"), "X-Extra": "1"}),
            json!({"X-Other": "not-the-token"}),
        ] {
            let err = delegation_from_worker(
                &delegation(),
                json!({"delegated_token": MINTED, "forwarded_headers": forwarded}),
            )
            .unwrap_err();
            assert!(err.to_string().contains("forwarded_headers"), "{err}");
            assert!(!err.to_string().contains(MINTED), "{err}");
        }
    }

    #[test]
    fn forwarded_headers_without_a_token_fail_closed() {
        let err = delegation_from_worker(
            &delegation(),
            json!({"forwarded_headers": {"Authorization": "Bearer x"}}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("forwarded_headers"), "{err}");
    }

    #[test]
    fn an_unknown_delegation_result_field_fails_closed() {
        let err = delegation_from_worker(
            &delegation(),
            json!({"delegated_token": MINTED, "refresh_token": "r"}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("refresh_token"), "{err}");
        assert!(!err.to_string().contains(MINTED), "{err}");
    }

    #[test]
    fn a_delegation_hop_field_ppe_cannot_hold_fails_closed() {
        let hop = serde_json::to_value(DelegationHop {
            subject_id: "alice".into(),
            ..Default::default()
        })
        .unwrap();
        let mut hop = hop.as_object().unwrap().clone();
        hop.insert("issuer".into(), json!("idp"));
        let err = delegation_from_worker(
            &delegation(),
            json!({"delegation_update": {"chain": [hop], "depth": 1}}),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("delegation_update.chain[0].issuer"),
            "{err}"
        );
    }

    #[test]
    fn no_token_and_no_update_returns_the_payload_unchanged() {
        let back =
            delegation_from_worker(&delegation(), json!({"target_name": "billing-api"})).unwrap();
        assert!(back.delegated_token.is_none());
        assert!(back.delegation_update.is_none());
    }
}
