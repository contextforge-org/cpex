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

use cpex_core::extensions::container::{chain_extends, OwnedExtensions};
use cpex_core::extensions::delegation::DelegationExtension;
use cpex_core::extensions::guarded::Guarded;
use cpex_core::extensions::http::HttpExtension;
use cpex_core::extensions::security::SecurityExtension;
use cpex_core::extensions::Extensions;
use serde_json::Value;
use tracing::warn;

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
/// `set-cookie` is included because the doc comment on `sanitize_http` promises
/// it and the response map is the one that carries it. It was previously absent
/// while both strip tests asserted through `is_sensitive` itself — a tautology
/// that passed either way, which is what let the gap survive.
const SENSITIVE_HEADERS: &[&str] = &["authorization", "cookie", "set-cookie", "x-api-key"];

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
/// credential. The request line is copied through unchanged — it is not
/// credential material, and the plugin needs it to make routing decisions.
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

/// Build the returned `http` value: worker headers, canonical request line.
///
/// The worker's return contributes header maps only. `method`, `path`, `host`,
/// and `scheme` are taken from `inbound` — the value the executor issued —
/// because policies gate on them (CHANGELOG 0.2.2) and `write_headers` does not
/// authorize rewriting request identity. `host` especially must trace back to a
/// validated authority, which a worker's JSON is not.
///
/// This also fixes a plain correctness bug: the Python `HttpExtension` models a
/// single `headers` field, so a round trip through the worker returns no
/// `method`/`path`/`host`/`scheme` at all. Taking them from the return value
/// blanked all four on every merge, silently turning host- and path-gated
/// policies into no-ops downstream.
fn returned_http(returned: &HttpExtension, inbound: Option<&HttpExtension>) -> HttpExtension {
    HttpExtension {
        request_headers: strip_sensitive(&returned.request_headers),
        response_headers: strip_sensitive(&returned.response_headers),
        method: inbound.and_then(|h| h.method.clone()),
        path: inbound.and_then(|h| h.path.clone()),
        host: inbound.and_then(|h| h.host.clone()),
        scheme: inbound.and_then(|h| h.scheme.clone()),
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
    //
    // Within a gated slot, only the *fields* the capability covers are taken
    // from the wire; the rest are kept from `inbound`. A token authorizes a
    // field, not the slot it lives in. `owned` starts as `inbound.cow_copy()`,
    // which is a copy of the capability-*filtered* view, so any field left
    // untouched here already holds the filtered value — the executor's
    // `merge_owned` re-merges it against canonical state field by field, and a
    // filtered-away field never overwrites what the plugin could not see.

    // Guarded — `write_headers`. Headers only: the request line
    // (`method`/`path`/`host`/`scheme`) is preserved from the inbound value,
    // which policies gate on and this capability does not cover.
    if let Some(http) = slot::<HttpExtension>(object, "http")? {
        if inbound.http_write_token.is_some() {
            // Strip on the way back too. A plugin cannot inject a credential
            // header into the pipeline through its return value.
            owned.http = Some(Guarded::new(returned_http(&http, inbound.http.as_deref())));
            applied = true;
        }
    }

    // Monotonic — `append_labels`. Labels *only*. Everything else on the slot
    // is Immutable with `write_cap: None` in the tier model, so a labels token
    // must not carry `subject`, `auth_method`, `client`, or either workload
    // identity — otherwise `append_labels` alone would let a plugin rewrite the
    // authenticated principal it was authenticated as. The executor re-checks
    // `before ⊆ after` and drops a removal.
    if let Some(security) = slot::<SecurityExtension>(object, "security")? {
        if inbound.labels_write_token.is_some() {
            let mut merged = inbound
                .security
                .as_deref()
                .cloned()
                .unwrap_or_else(SecurityExtension::default);
            // Append-only, and only into the set the plugin was shown. Assigning
            // the returned set would let a shorter one read as a removal.
            for label in security.labels.iter() {
                merged.add_label(label.clone());
            }
            owned.security = Some(merged);
            applied = true;
        }
    }

    // Monotonic — `append_delegation`. Validated rather than accepted blind: the
    // returned chain must extend the inbound one, with every hop the plugin was
    // shown left intact. A shortened or rewritten chain forges lineage — dropping
    // the hop that recorded a scope narrowing widens effective authority — so the
    // whole edit is refused and the inbound chain stands. `depth` and `delegated`
    // are recomputed by the executor from the merged chain, never trusted here.
    if let Some(delegation) = slot::<DelegationExtension>(object, "delegation")? {
        if inbound.delegation_write_token.is_some() {
            let inbound_chain = inbound
                .delegation
                .as_deref()
                .map(|d| d.chain.as_slice())
                .unwrap_or_default();
            if chain_extends(inbound_chain, &delegation.chain) {
                owned.delegation = Some(delegation);
                applied = true;
            } else {
                warn!(
                    inbound_hops = inbound_chain.len(),
                    returned_hops = delegation.chain.len(),
                    "dropping a returned delegation chain that does not extend the \
                     one the plugin was given — an append-only chain cannot be \
                     shortened or rewritten"
                );
            }
        }
    }

    // Mutable — `AccessPolicy::Unrestricted`, so accepted without a token. It
    // sets `applied` on its own, which is correct *because* the gated slots
    // above are now merged per field: a `custom` write can no longer drag a
    // capability-filtered `security` or `http` view into the merge behind it.
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

    /// Assert a header map contains none of `names`, case-insensitively.
    ///
    /// Takes **literal** names rather than calling `is_sensitive`. The tests
    /// below previously asserted `!is_sensitive(name)` over the surviving keys —
    /// the same function under test on both sides, so the assertion held no
    /// matter what `SENSITIVE_HEADERS` contained. That is what let `set-cookie`
    /// be missing from the list while the comment claimed it was there, with
    /// both strip tests green.
    fn assert_absent(headers: &serde_json::Map<String, Value>, names: &[&str]) {
        for name in names {
            assert!(
                !headers.keys().any(|k| k.eq_ignore_ascii_case(name)),
                "header '{name}' must not cross the process boundary; got {:?}",
                headers.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn sensitive_request_headers_are_stripped_but_others_survive() {
        let mut task = serde_json::json!({});
        attach_extensions(&mut task, &populated()).expect("serializing");

        let headers = task[EXTENSIONS_FIELD]["http"]["request_headers"]
            .as_object()
            .expect("request_headers is an object")
            .clone();

        assert_absent(&headers, &["Authorization", "Cookie", "X-API-Key"]);
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
            .expect("response_headers is an object")
            .clone();

        // `Set-Cookie` is the one the module comment always claimed to strip.
        // This assertion fails until it is actually in `SENSITIVE_HEADERS`.
        assert_absent(&headers, &["Set-Cookie", "Authorization"]);
        assert_eq!(
            headers.get("Content-Type").and_then(Value::as_str),
            Some("application/json"),
        );
    }

    #[test]
    fn set_cookie_is_stripped_in_both_directions_and_under_any_casing() {
        // A session cookie is credential material. It must not reach a plugin
        // outbound, nor be injectable by one on the return.
        let mut http = HttpExtension::default();
        http.set_response_header("set-cookie", "session=lower");
        http.set_response_header("SET-COOKIE", "session=upper");
        http.set_request_header("Set-Cookie", "session=req");

        let sanitized = sanitize_http(&http);
        assert!(
            sanitized.response_headers.is_empty(),
            "no casing of set-cookie survives outbound: {:?}",
            sanitized.response_headers
        );
        assert!(sanitized.request_headers.is_empty());

        let returned = returned_http(&http, None);
        assert!(
            returned.response_headers.is_empty() && returned.request_headers.is_empty(),
            "nor inbound on the return path"
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

    // -- Per-field gating on the return path (review finding A) --

    #[test]
    fn a_custom_write_does_not_carry_a_filtered_security_view_into_the_merge() {
        // The headline finding, at this layer. A plugin with no security
        // capability returns only `custom`. `owned` starts from
        // `inbound.cow_copy()`, so before the fix the resulting
        // `OwnedExtensions` carried the plugin's *filtered* security value —
        // and `merge_owned`'s slot swap then wrote it over canonical state.
        //
        // Here the inbound view is what a plugin with no `read_labels` gets:
        // an empty label set. The merged result must not present that as an
        // instruction to clear labels.
        let inbound = Extensions {
            security: Some(Arc::new(security_with_labels(&[]))),
            ..Default::default()
        };
        assert!(inbound.labels_write_token.is_none());

        let response = serde_json::json!({
            "modified_extensions": {"custom": {"verdict": "clean"}}
        });
        let owned = parse_returned_extensions(&response, &inbound)
            .expect("parsing")
            .expect("the custom write is a real modification");

        // No labels token, so the security slot must merge as a no-op against
        // canonical state. Drive that through the real merge to prove it.
        let mut canonical = Extensions {
            security: Some(Arc::new(security_with_labels(&["PII", "HIPAA"]))),
            ..Default::default()
        };
        canonical.merge_owned(owned);

        let merged = canonical.security.as_ref().expect("slot present");
        assert!(
            merged.labels.contains(&"PII".to_string()),
            "a capability-less custom write must not wipe canonical labels"
        );
        assert!(merged.labels.contains(&"HIPAA".to_string()));
        assert_eq!(
            canonical.custom.as_ref().expect("custom merged")["verdict"],
            "clean",
            "and the legitimate custom write still lands"
        );
    }

    #[test]
    fn the_returned_http_slot_preserves_the_inbound_request_line() {
        // Policies gate on method/path/host/scheme (CHANGELOG 0.2.2). The
        // Python `HttpExtension` models only `headers`, so a worker round trip
        // returns none of the four — taking them from the return blanked all of
        // them on every merge. A hostile worker could also rewrite `host`,
        // which must trace to a validated authority.
        let mut inbound_http = HttpExtension::default();
        inbound_http.method = Some("POST".into());
        inbound_http.path = Some("/api/v1/transfer".into());
        inbound_http.host = Some("bank.internal".into());
        inbound_http.scheme = Some("https".into());

        // What a worker actually returns: headers only, request line absent.
        let returned_absent = HttpExtension {
            request_headers: [("X-Scanned".to_string(), "1".to_string())].into(),
            ..Default::default()
        };
        let merged = returned_http(&returned_absent, Some(&inbound_http));
        assert_eq!(merged.method.as_deref(), Some("POST"));
        assert_eq!(merged.path.as_deref(), Some("/api/v1/transfer"));
        assert_eq!(merged.host.as_deref(), Some("bank.internal"));
        assert_eq!(merged.scheme.as_deref(), Some("https"));
        assert_eq!(
            merged.request_headers.get("X-Scanned").map(String::as_str),
            Some("1")
        );

        // And a worker that *does* send a request line cannot override it.
        let returned_hostile = HttpExtension {
            method: Some("GET".into()),
            path: Some("/healthz".into()),
            host: Some("evil.example".into()),
            scheme: Some("http".into()),
            ..Default::default()
        };
        let merged = returned_http(&returned_hostile, Some(&inbound_http));
        assert_eq!(
            merged.host.as_deref(),
            Some("bank.internal"),
            "the worker cannot re-point the validated authority"
        );
        assert_eq!(merged.method.as_deref(), Some("POST"));
        assert_eq!(merged.path.as_deref(), Some("/api/v1/transfer"));
        assert_eq!(merged.scheme.as_deref(), Some("https"));
    }

    #[test]
    fn a_returned_delegation_chain_is_validated_not_accepted_blind() {
        // Without a token the slot is dropped regardless, so the validation
        // itself is asserted directly against the shared `chain_extends`
        // predicate the merge uses — the accept path needs a real executor
        // token and lives in `tests/extensions_merge_e2e.rs`.
        use cpex_core::extensions::delegation::DelegationHop;

        let hop = |id: &str, scopes: Vec<&str>| DelegationHop {
            subject_id: id.into(),
            scopes_granted: scopes.into_iter().map(str::to_string).collect(),
            ..Default::default()
        };

        let canonical = vec![
            hop("user-1", vec!["read_hr"]),
            hop("svc-a", vec!["read_hr"]),
        ];

        assert!(
            chain_extends(&canonical, &canonical),
            "an unchanged chain is a valid (empty) append"
        );
        let mut appended = canonical.clone();
        appended.push(hop("svc-b", vec!["read_hr"]));
        assert!(
            chain_extends(&canonical, &appended),
            "a real append is valid"
        );

        assert!(
            !chain_extends(&canonical, &canonical[..1]),
            "truncation drops the hop that recorded a narrowing — not an append"
        );
        let mut widened = canonical.clone();
        widened[0].scopes_granted = vec!["admin".into()];
        assert!(
            !chain_extends(&canonical, &widened),
            "widening an existing hop's scopes is not an append"
        );
        let mut reseated = canonical.clone();
        reseated[1].subject_id = "attacker".into();
        assert!(
            !chain_extends(&canonical, &reseated),
            "rewriting an existing hop's subject is not an append"
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
