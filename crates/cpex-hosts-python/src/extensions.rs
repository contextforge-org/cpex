// Location: ./crates/cpex-hosts-python/src/extensions.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Extensions wire contract for out-of-process Python plugins.
//
// # Why this exists
//
// `worker.py` calls `execute_plugin` without an `extensions` argument, so every
// out-of-process hook sees `extensions=None`. A plugin using the 3-arg
// `(payload, context, extensions)` signature — the form `_accepts_extensions`
// detects in `cpex/framework/base.py` — silently loses all extension context
// when it runs out-of-process: security labels, agent lineage, HTTP headers,
// MCP metadata. In-process plugins see all of it. That gap is what this module
// closes, in both directions.
//
// # Two directions, one contract
//
// Outbound (`attach_extensions`): serialize the capability-filtered
// `&Extensions` the executor handed the adapter and attach it to the task. The
// filtered view is used deliberately rather than the full extensions, so a
// plugin sees only the slots its declared capabilities permit and this host
// never re-derives filtering the executor already did.
//
// Inbound (`parse_returned_extensions`): read the worker's returned extensions
// and rebuild an `OwnedExtensions` for the executor's existing copy-on-write
// merge, which enforces the mutability tiers. This module adds no tier logic.
//
// # Why the return path rebuilds instead of deserializing
//
// `Extensions::validate_immutable` enforces the immutable tier with
// `Arc::ptr_eq` — pointer identity, not value equality. A JSON round trip
// allocates a fresh `Arc` for every slot, so an `OwnedExtensions` deserialized
// wholesale from the wire would fail that check on *every* immutable slot and
// the executor would reject the whole return with a spurious "violated
// immutable tier" warning, even for a plugin that only touched `custom`.
//
// So the return path reuses the inbound `Arc`s for immutable slots — exactly
// what `cow_copy()` does — and takes only the mutable, monotonic, and guarded
// slots (`http`, `security`, `delegation`, `custom`) from the wire. Two
// consequences, both intended:
//
//   1. Honest plugins pass `validate_immutable`, because the immutable slots
//      are the same pointers the executor issued.
//   2. A plugin that tries to forge an immutable slot has that edit dropped
//      here rather than rejected downstream. The spec outcome ("immutable slots
//      do not change") holds structurally, without trusting the wire.
//
// # Credentials are not on this channel
//
// This channel carries non-secret context only. `raw_credentials` is never
// serialized here — raw tokens travel the capability-gated DTO in the
// `credentials` module instead. Sensitive headers are stripped in both
// directions per `docs/specs/cmf-message-spec.md` §3.5; a plugin that needs a
// bearer token uses the credential path, not `http.request_headers`.

use std::collections::HashMap;

use cpex_core::extensions::container::OwnedExtensions;
use cpex_core::extensions::delegation::DelegationExtension;
use cpex_core::extensions::guarded::Guarded;
use cpex_core::extensions::http::HttpExtension;
use cpex_core::extensions::security::SecurityExtension;
use cpex_core::extensions::Extensions;
use serde_json::Value;

use crate::error::HostError;

/// Task field the inbound extensions ride on. Contract with `worker.py`, which
/// reads it and passes the reconstructed object as `extensions=` to
/// `execute_plugin`; both sides must agree verbatim.
pub const EXTENSIONS_FIELD: &str = "extensions";

/// Response field the returned extensions ride on.
///
/// Deliberately *not* the same name as [`EXTENSIONS_FIELD`]. The worker's
/// response is a serialized Python `PluginResult`, and that model already
/// carries `modified_extensions: Optional[Extensions]` (`cpex/framework/
/// models.py`) — the same field the in-process Python manager accumulates. This
/// host reads the field the model already produces rather than asking the worker
/// to invent a second one, so an out-of-process plugin returns extensions the
/// exact same way its in-process equivalent does.
pub const MODIFIED_EXTENSIONS_FIELD: &str = "modified_extensions";

/// Headers stripped in both directions (spec §3.5).
///
/// Matched case-insensitively: HTTP header names are case-insensitive, and
/// `HttpExtension`'s own accessors look up that way, so a plugin sending
/// `authorization` must not slip past a case-sensitive compare.
const SENSITIVE_HEADERS: &[&str] = &["authorization", "cookie", "x-api-key"];

/// True when `name` is a header this channel must not carry.
fn is_sensitive(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
}

/// Drop sensitive entries from a header map, leaving the rest untouched.
fn strip_sensitive(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Copy an `HttpExtension` with sensitive headers removed from both maps.
///
/// Both maps are scrubbed: `response_headers` can carry a `Set-Cookie` or an
/// upstream `Authorization` echo just as `request_headers` carries the inbound
/// credential.
fn sanitize_http(http: &HttpExtension) -> HttpExtension {
    HttpExtension {
        request_headers: strip_sensitive(&http.request_headers),
        response_headers: strip_sensitive(&http.response_headers),
        method: http.method.clone(),
        path: http.path.clone(),
        host: http.host.clone(),
        scheme: http.scheme.clone(),
    }
}

/// Serialize the filtered extensions and attach them to `task`.
///
/// `extensions` is the capability-filtered view the executor produced for this
/// plugin, so slot visibility is already correct — an absent slot means the
/// plugin's capabilities excluded it, and it stays absent on the wire.
///
/// `raw_credentials` is excluded outright. Its token fields are `#[serde(skip)]`
/// so they would serialize empty anyway, but sending a hollow slot invites a
/// plugin to read it as "no credential present" rather than "not on this
/// channel". Omitting it says the latter unambiguously.
///
/// Attaching nothing is valid: extensions with no visible slots produce no
/// field, and the worker passes `None` to `execute_plugin` exactly as today.
pub fn attach_extensions(task: &mut Value, extensions: &Extensions) -> Result<(), HostError> {
    let wire = to_wire(extensions)?;

    // An empty object carries no information the worker can act on; omitting
    // the field keeps the "no extensions" path byte-identical to a task built
    // before this feature existed.
    if wire.as_object().is_none_or(serde_json::Map::is_empty) {
        return Ok(());
    }

    let object = task.as_object_mut().ok_or_else(|| HostError::Protocol {
        message: "task must be a JSON object to carry extensions".into(),
    })?;
    object.insert(EXTENSIONS_FIELD.to_string(), wire);

    Ok(())
}

/// Build the wire JSON for a filtered extensions view.
///
/// Slots serialize through their own serde impls — those are the source of
/// truth for sub-field shape, so this function stays correct as the extension
/// structs evolve. Only `http` is rewritten on the way out, to strip sensitive
/// headers.
fn to_wire(extensions: &Extensions) -> Result<Value, HostError> {
    let mut map = serde_json::Map::new();

    let mut put = |key: &str, value: Result<Value, serde_json::Error>| -> Result<(), HostError> {
        let value = value.map_err(|e| HostError::Protocol {
            message: format!("could not serialize the '{key}' extension for the worker: {e}"),
        })?;
        map.insert(key.to_string(), value);
        Ok(())
    };

    if let Some(request) = &extensions.request {
        put("request", serde_json::to_value(request))?;
    }
    if let Some(agent) = &extensions.agent {
        put("agent", serde_json::to_value(agent))?;
    }
    if let Some(http) = &extensions.http {
        put("http", serde_json::to_value(sanitize_http(http)))?;
    }
    if let Some(security) = &extensions.security {
        put("security", serde_json::to_value(security))?;
    }
    if let Some(delegation) = &extensions.delegation {
        put("delegation", serde_json::to_value(delegation))?;
    }
    if let Some(mcp) = &extensions.mcp {
        put("mcp", serde_json::to_value(mcp))?;
    }
    if let Some(completion) = &extensions.completion {
        put("completion", serde_json::to_value(completion))?;
    }
    if let Some(provenance) = &extensions.provenance {
        put("provenance", serde_json::to_value(provenance))?;
    }
    if let Some(llm) = &extensions.llm {
        put("llm", serde_json::to_value(llm))?;
    }
    if let Some(framework) = &extensions.framework {
        put("framework", serde_json::to_value(framework))?;
    }
    if let Some(meta) = &extensions.meta {
        put("meta", serde_json::to_value(meta))?;
    }
    if let Some(custom) = &extensions.custom {
        put("custom", serde_json::to_value(custom))?;
    }
    // `raw_credentials` deliberately absent — see the module docs.

    Ok(Value::Object(map))
}

/// Rebuild an `OwnedExtensions` from the worker's response, or `None`.
///
/// `None` means "no modified extensions" and is the documented no-change
/// signal: the worker omits the field. Omission rather than an echo is
/// deliberate — a JSON round trip allocates new `Arc`s, so an echoed immutable
/// slot is indistinguishable from a forged one under `validate_immutable`'s
/// pointer check. Omitting is the only representation that reads cleanly as
/// "nothing changed".
///
/// `inbound` is the filtered view this plugin was sent. Its `Arc`s are reused
/// for immutable slots so the executor's pointer-identity check passes; only
/// the tiers a plugin may legitimately write are taken from the wire.
///
/// This function does not decide whether a change is *allowed* — the executor's
/// merge does, via `validate_immutable`, the monotonic label check, and the
/// write tokens carried on `inbound`. Malformed slot JSON is an error: a plugin
/// that returned a `security` object the host cannot parse has not made "no
/// change", and silently dropping it would hide the failure.
pub fn parse_returned_extensions(
    response: &Value,
    inbound: &Extensions,
) -> Result<Option<OwnedExtensions>, HostError> {
    let Some(field) = response.get(MODIFIED_EXTENSIONS_FIELD) else {
        return Ok(None);
    };
    owned_from_returned_slot(field, inbound)
}

/// Rebuild an `OwnedExtensions` from an already-extracted
/// `modified_extensions` value.
///
/// Split out so the response-conversion path can call it with the raw slot it
/// already looked up, without re-walking the response object.
pub fn owned_from_returned_slot(
    field: &Value,
    inbound: &Extensions,
) -> Result<Option<OwnedExtensions>, HostError> {
    // Explicit null is the same statement as an omitted field. `worker.py`
    // serializing `None` should not read as "clear every writable slot".
    if field.is_null() {
        return Ok(None);
    }

    let object = field.as_object().ok_or_else(|| HostError::Protocol {
        message: format!(
            "the worker returned a '{MODIFIED_EXTENSIONS_FIELD}' field that is not a JSON object"
        ),
    })?;

    // Start from the inbound view: immutable slots keep their original `Arc`
    // pointers, and the write tokens the executor issued are carried over.
    let mut owned = inbound.cow_copy();

    // Whether any slot was actually taken from the wire. Pydantic serializes
    // unset Optionals as `null`, so a plugin that touched nothing still sends
    // every key — that must read as "no modification" rather than a no-op merge
    // the executor has to validate.
    let mut applied = false;

    fn slot<T: serde::de::DeserializeOwned>(
        object: &serde_json::Map<String, Value>,
        key: &str,
    ) -> Result<Option<T>, HostError> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|e| HostError::Protocol {
                    message: format!(
                        "could not deserialize the '{key}' extension returned by the worker: {e}"
                    ),
                }),
        }
    }

    // The three writable-but-gated slots are honored only when the executor
    // issued the matching write token on the inbound view. The token is the
    // host's *only* evidence that the plugin declared the write capability —
    // `WriteToken::new()` is `pub(crate)` to `cpex-core`, so this crate cannot
    // mint one, and a token can never be forged out of worker JSON. An edit
    // without the token is dropped and the inbound value stands.

    // Guarded — `write_headers`.
    if let Some(http) = slot::<HttpExtension>(object, "http")? {
        if inbound.http_write_token.is_some() {
            // Strip on the way back too. A plugin cannot inject a credential
            // header into the pipeline through its return value.
            owned.http = Some(Guarded::new(sanitize_http(&http)));
            applied = true;
        }
    }

    // Monotonic — `append_labels`. The executor additionally checks
    // `before ⊆ after` and rejects the whole return on a removal.
    if let Some(security) = slot::<SecurityExtension>(object, "security")? {
        if inbound.labels_write_token.is_some() {
            owned.security = Some(security);
            applied = true;
        }
    }

    // Monotonic — `append_delegation`.
    if let Some(delegation) = slot::<DelegationExtension>(object, "delegation")? {
        if inbound.delegation_write_token.is_some() {
            owned.delegation = Some(delegation);
            applied = true;
        }
    }

    // Mutable — accepted as-is.
    if let Some(custom) = slot::<HashMap<String, Value>>(object, "custom")? {
        owned.custom = Some(custom);
        applied = true;
    }

    // Immutable slots are ignored on purpose: `owned` already holds the
    // inbound `Arc`s, so a forged edit here is dropped rather than merged.

    if !applied {
        return Ok(None);
    }

    Ok(Some(owned))
}

/// Reuse the inbound `Arc` for a slot the wire must not change.
///
/// Kept as a named helper so the intent reads at the call site in tests.
#[cfg(test)]
fn same_arc<T>(a: &Option<std::sync::Arc<T>>, b: &Option<std::sync::Arc<T>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => std::sync::Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use cpex_core::extensions::agent::AgentExtension;
    use cpex_core::extensions::monotonic::MonotonicSet;

    use super::*;

    fn http_with_headers() -> HttpExtension {
        let mut http = HttpExtension::default();
        http.set_request_header("Authorization", "Bearer secret-token");
        http.set_request_header("Cookie", "session=abc");
        http.set_request_header("X-API-Key", "key-123");
        http.set_request_header("X-Request-Id", "req-1");
        http.set_response_header("Set-Cookie", "s=1");
        http.set_response_header("Authorization", "Bearer echoed");
        http.set_response_header("Content-Type", "application/json");
        http
    }

    fn security_with_labels(labels: &[&str]) -> SecurityExtension {
        let set: HashSet<String> = labels.iter().map(|s| s.to_string()).collect();
        SecurityExtension {
            labels: MonotonicSet::from_set(set),
            ..Default::default()
        }
    }

    fn populated() -> Extensions {
        Extensions {
            agent: Some(Arc::new(AgentExtension::default())),
            http: Some(Arc::new(http_with_headers())),
            security: Some(Arc::new(security_with_labels(&["PII"]))),
            ..Default::default()
        }
    }

    // -- Outbound: U1 --

    #[test]
    fn present_slots_land_on_the_wire() {
        let mut task = serde_json::json!({"task_type": "run"});
        attach_extensions(&mut task, &populated()).expect("serializing a populated view");

        let wire = task
            .get(EXTENSIONS_FIELD)
            .expect("the field is attached")
            .as_object()
            .expect("the field is an object");

        assert!(wire.contains_key("agent"), "agent slot present");
        assert!(wire.contains_key("http"), "http slot present");
        assert!(wire.contains_key("security"), "security slot present");
    }

    #[test]
    fn sensitive_request_headers_are_stripped_but_others_survive() {
        let mut task = serde_json::json!({});
        attach_extensions(&mut task, &populated()).expect("serializing");

        let headers = task[EXTENSIONS_FIELD]["http"]["request_headers"]
            .as_object()
            .expect("request_headers is an object");

        // Case-insensitively: none of the three may appear under any casing.
        for name in headers.keys() {
            assert!(
                !is_sensitive(name),
                "sensitive header '{name}' must not cross the process boundary"
            );
        }
        assert_eq!(
            headers.get("X-Request-Id").and_then(Value::as_str),
            Some("req-1"),
            "a non-sensitive header is preserved verbatim"
        );
    }

    #[test]
    fn sensitive_response_headers_are_stripped_too() {
        let mut task = serde_json::json!({});
        attach_extensions(&mut task, &populated()).expect("serializing");

        let headers = task[EXTENSIONS_FIELD]["http"]["response_headers"]
            .as_object()
            .expect("response_headers is an object");

        for name in headers.keys() {
            assert!(
                !is_sensitive(name),
                "sensitive response header '{name}' must not cross the boundary"
            );
        }
        assert_eq!(
            headers.get("Content-Type").and_then(Value::as_str),
            Some("application/json"),
        );
    }

    #[test]
    fn lowercase_sensitive_headers_are_stripped() {
        // HTTP header names are case-insensitive; a case-sensitive filter would
        // leak the token whenever the host populated it in lower case.
        let mut http = HttpExtension::default();
        http.set_request_header("authorization", "Bearer sneaky");
        http.set_request_header("x-api-key", "k");
        let extensions = Extensions {
            http: Some(Arc::new(http)),
            ..Default::default()
        };

        let mut task = serde_json::json!({});
        attach_extensions(&mut task, &extensions).expect("serializing");

        let headers = task[EXTENSIONS_FIELD]["http"]["request_headers"]
            .as_object()
            .expect("request_headers is an object");
        assert!(
            headers.is_empty(),
            "lower-cased sensitive headers must be stripped too, got {headers:?}"
        );
    }

    #[test]
    fn a_filtered_out_slot_is_absent_from_the_wire() {
        // A plugin without `read_agent` gets a view with `agent: None`. The
        // wire must not resurrect it.
        let extensions = Extensions {
            security: Some(Arc::new(security_with_labels(&["PII"]))),
            ..Default::default()
        };

        let mut task = serde_json::json!({});
        attach_extensions(&mut task, &extensions).expect("serializing");

        let wire = task[EXTENSIONS_FIELD].as_object().expect("an object");
        assert!(
            !wire.contains_key("agent"),
            "a slot the capabilities excluded stays excluded"
        );
        assert!(wire.contains_key("security"));
    }

    #[test]
    fn raw_credentials_never_appear_on_the_wire() {
        use cpex_core::extensions::raw_credentials::{
            RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
        };

        let mut inbound_tokens = HashMap::new();
        inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("super-secret", "Authorization", TokenKind::Jwt),
        );

        let extensions = Extensions {
            raw_credentials: Some(Arc::new(RawCredentialsExtension {
                inbound_tokens,
                ..Default::default()
            })),
            security: Some(Arc::new(security_with_labels(&["PII"]))),
            ..Default::default()
        };

        let mut task = serde_json::json!({});
        attach_extensions(&mut task, &extensions).expect("serializing");

        let wire = task[EXTENSIONS_FIELD].as_object().expect("an object");
        assert!(
            !wire.contains_key("raw_credentials"),
            "the credential slot belongs to the credential DTO, not this channel"
        );
        let serialized = serde_json::to_string(&task).expect("re-serializing the task");
        assert!(
            !serialized.contains("super-secret"),
            "no token bytes anywhere in the task JSON"
        );
    }

    #[test]
    fn empty_extensions_attach_no_field() {
        let mut task = serde_json::json!({"task_type": "run"});
        attach_extensions(&mut task, &Extensions::default()).expect("serializing an empty view");
        assert!(
            task.get(EXTENSIONS_FIELD).is_none(),
            "a view with no visible slots leaves the task shape unchanged"
        );
    }

    // -- Inbound: U4 --

    #[test]
    fn an_absent_field_means_no_change() {
        let response = serde_json::json!({"payload": {}});
        let parsed = parse_returned_extensions(&response, &populated()).expect("parsing");
        assert!(
            parsed.is_none(),
            "an omitted field is the documented no-change signal"
        );
    }

    #[test]
    fn an_explicit_null_means_no_change() {
        let response = serde_json::json!({"modified_extensions": null});
        let parsed = parse_returned_extensions(&response, &populated()).expect("parsing");
        assert!(parsed.is_none(), "null reads the same as omitted");
    }

    #[test]
    fn a_non_object_field_is_a_protocol_error() {
        let response = serde_json::json!({"modified_extensions": "nope"});
        let err = parse_returned_extensions(&response, &populated());
        assert!(err.is_err(), "a non-object field cannot be interpreted");
    }

    #[test]
    fn immutable_slots_keep_their_inbound_arcs() {
        // The executor's `validate_immutable` compares by pointer. If the
        // return path allocated a fresh Arc here, every out-of-process
        // extension return would be rejected as tampering.
        let inbound = populated();
        let response = serde_json::json!({
            "modified_extensions": {"custom": {"k": "v"}}
        });

        let owned = parse_returned_extensions(&response, &inbound)
            .expect("parsing")
            .expect("a returned field yields modifications");

        assert!(
            same_arc(&inbound.agent, &owned.agent),
            "the agent slot must be the very same Arc the executor issued"
        );
        assert!(inbound.validate_immutable(&owned), "the merge accepts it");
    }

    #[test]
    fn a_forged_immutable_slot_is_dropped_not_merged() {
        let inbound = populated();
        // A plugin returning a different `agent` must not change it.
        let response = serde_json::json!({
            "modified_extensions": {
                "agent": {"agent_id": "forged"},
                "custom": {"ok": true}
            }
        });

        let owned = parse_returned_extensions(&response, &inbound)
            .expect("parsing")
            .expect("modifications present");

        assert!(
            same_arc(&inbound.agent, &owned.agent),
            "the forged agent edit is dropped, not merged"
        );
        assert!(
            inbound.validate_immutable(&owned),
            "so the rest of the return still merges cleanly"
        );
        assert!(
            owned.custom.is_some(),
            "the legitimate custom edit survives"
        );
    }

    #[test]
    fn a_custom_change_is_taken_as_is() {
        let response = serde_json::json!({
            "modified_extensions": {"custom": {"verdict": "clean", "score": 3}}
        });
        let owned = parse_returned_extensions(&response, &populated())
            .expect("parsing")
            .expect("modifications present");

        let custom = owned.custom.expect("custom present");
        assert_eq!(custom.get("verdict").and_then(Value::as_str), Some("clean"));
        assert_eq!(custom.get("score").and_then(Value::as_i64), Some(3));
    }

    // The three gated slots below can only be *accepted* when the executor
    // issued a write token, and `WriteToken::new()` is `pub(crate)` to
    // `cpex-core` — this crate cannot mint one even in a test. That is the
    // security property, so these tests assert the deny side here and the
    // accept side is covered end-to-end through the real executor in
    // `tests/extensions_merge_e2e.rs`, where tokens come from capabilities.

    #[test]
    fn a_label_append_without_the_token_is_dropped() {
        let inbound = populated(); // labels: {PII}
        assert!(
            inbound.labels_write_token.is_none(),
            "no append_labels capability was granted"
        );

        let response = serde_json::json!({
            "modified_extensions": {"security": {"labels": ["PII", "SCANNED"]}}
        });
        let parsed = parse_returned_extensions(&response, &inbound).expect("parsing");

        assert!(
            parsed.is_none(),
            "an unauthorized label append yields no modification, so the \
             pipeline's labels are untouched"
        );
    }

    #[test]
    fn a_label_removal_without_the_token_cannot_strip_labels() {
        // An out-of-process plugin must not be able to launder a
        // declassification through this host by returning a shorter label set.
        let inbound = populated(); // labels: {PII}
        let response = serde_json::json!({
            "modified_extensions": {"security": {"labels": []}}
        });

        let parsed = parse_returned_extensions(&response, &inbound).expect("parsing");
        assert!(
            parsed.is_none(),
            "the removal never reaches the merge, so PII cannot be stripped"
        );
    }

    #[test]
    fn an_http_change_needs_the_write_token() {
        // No token issued — the executor withheld `write_headers`.
        let inbound = populated();
        assert!(inbound.http_write_token.is_none());

        let response = serde_json::json!({
            "modified_extensions": {"http": {"request_headers": {"X-Added": "1"}}}
        });
        let parsed = parse_returned_extensions(&response, &inbound).expect("parsing");

        assert!(
            parsed.is_none(),
            "an http edit without the capability is dropped entirely"
        );
    }

    #[test]
    fn a_delegation_change_without_the_token_is_dropped() {
        let inbound = populated();
        assert!(inbound.delegation_write_token.is_none());

        let response = serde_json::json!({
            "modified_extensions": {"delegation": {"hops": []}}
        });
        let parsed = parse_returned_extensions(&response, &inbound).expect("parsing");

        assert!(
            parsed.is_none(),
            "the wire cannot add a delegation slot without the capability"
        );
    }

    #[test]
    fn an_unauthorized_gated_write_does_not_suppress_a_legitimate_custom_write() {
        // A plugin can return both. The gated slot is dropped for want of a
        // token; `custom` is mutable and must still land.
        let inbound = populated();
        let response = serde_json::json!({
            "modified_extensions": {
                "security": {"labels": ["PII", "SCANNED"]},
                "custom": {"verdict": "clean"}
            }
        });

        let owned = parse_returned_extensions(&response, &inbound)
            .expect("parsing")
            .expect("the custom write is a real modification");

        assert_eq!(
            owned.custom.as_ref().expect("custom present")["verdict"],
            "clean"
        );
        let security = owned.security.as_ref().expect("the inbound slot stands");
        assert!(
            !security.labels.contains(&"SCANNED".to_string()),
            "the unauthorized label append is still dropped"
        );
    }

    #[test]
    fn malformed_slot_json_is_an_error_not_a_silent_drop() {
        let response = serde_json::json!({
            "modified_extensions": {"security": "not-an-object"}
        });
        let err = parse_returned_extensions(&response, &populated());
        assert!(
            err.is_err(),
            "unparseable slot JSON must surface, not read as no-change"
        );
    }
}
