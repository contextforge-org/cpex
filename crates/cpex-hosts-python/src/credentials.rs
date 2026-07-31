// Location: ./crates/cpex-hosts-python/src/credentials.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Capability-gated credential wire DTO.
//
// # Why this exists
//
// `RawInboundToken.token` and `RawDelegatedToken.token` are `#[serde(skip)]`,
// so serializing an `Extensions` yields no token bytes. That is the documented
// "raw credentials never leave the host process" invariant — and it means an
// out-of-process identity resolver or token delegator cannot do its job.
//
// This module deliberately reverses that invariant, narrowly: a dedicated DTO
// carries the token as a plain string, built only on the capability-gated
// dispatch path for the two hooks whose Python payload models a raw token at
// all. The production types keep their serde guard and are never serialized;
// the FFI, Python-bindings, and audit paths are untouched. The new leak surface
// is one constructor and one serialize site, which is the point.
//
// The DTO is built by reading the in-memory `Zeroizing` token field *directly*.
// A serialize-then-reparse would yield an empty token, because the serde guard
// strips the bytes on the way out — the guard is doing its job, so the only way
// to read the value is to read the field.
//
// # Fail closed
//
// Two rules, both load-bearing:
//
//   1. No declared capability → no DTO, no token material. Not an error; the
//      plugin simply never sees credentials.
//   2. Declared capability that cannot be honored → error, not a silent
//      no-token send. A plugin that asked for a token and got none would
//      otherwise validate an empty bearer, or fall through to a code path that
//      treats "no credential" as "no authentication required".
//
// # Residual exposure
//
// The capability gate controls *which* plugin receives a token. It does not
// constrain what happens next: once the plaintext is resident in the worker
// process, every transitively-installed dependency in that venv can read it.
// That is a materially larger and less audited trust boundary than the
// in-process host, and neither this gate nor the transport can close it. See
// the `worker` module for the transport side.

use std::collections::{HashMap, HashSet};

use cpex_core::extensions::raw_credentials::{
    DelegationMode, RawDelegatedToken, RawInboundToken, TokenKind, TokenRole,
};
use cpex_core::extensions::Extensions;
use serde::Serialize;
use serde_json::Value;

use crate::conversion::payload_kind_for_hook;
use crate::error::HostError;
use crate::PayloadKind;

/// Task field the DTO rides on. Contract with `worker.py`'s
/// `CREDENTIAL_FIELD`; both sides must agree verbatim.
pub const CREDENTIAL_FIELD: &str = "credential";

/// Capability a plugin declares to receive the inbound credential.
pub const CAP_READ_INBOUND: &str = "read_inbound_credentials";

/// Capability a plugin declares to receive a delegated token.
pub const CAP_READ_DELEGATED: &str = "read_delegated_tokens";

/// Placeholder printed instead of token bytes in `Debug`.
const REDACTED: &str = "<redacted>";

/// The `credential` object attached to a task.
///
/// Exactly one sub-object is populated, chosen by hook. `Debug` is
/// hand-written so neither ends up in a log line or panic message.
#[derive(Clone, Default, Serialize)]
pub struct CredentialDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound: Option<InboundCredential>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<DelegatedCredential>,
}

impl std::fmt::Debug for CredentialDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Which sub-object is present is safe and useful; its contents are not.
        f.debug_struct("CredentialDto")
            .field("inbound", &self.inbound.as_ref().map(|_| REDACTED))
            .field("delegated", &self.delegated.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// `credential.inbound` — built from `RawInboundToken`, for `identity_resolve`.
///
/// The worker maps these onto `IdentityPayload`: `token` → `raw_token`, `kind`
/// → `source`, `headers` → `headers` (with the plaintext scrubbed out of the
/// values, since `IdentityPayload.headers` does not redact on serialization).
#[derive(Clone, Serialize)]
pub struct InboundCredential {
    /// The plaintext, read straight from the in-memory `Zeroizing` field.
    pub token: String,

    /// Header the credential arrived in.
    pub source_header: String,

    /// Wire-format family — `jwt`, `opaque`, `spiffe_jwt`, `ucan`, `txn_token`.
    pub kind: String,

    /// Headers to forward. Synthesized as `{source_header: token}` when the
    /// extension carries none, so a header-driven extractor still learns which
    /// header carried the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

impl std::fmt::Debug for InboundCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundCredential")
            .field("token", &REDACTED)
            .field("source_header", &self.source_header)
            .field("kind", &self.kind)
            // Values can embed the token ("Bearer <token>"), so names only.
            .field(
                "header_names",
                &self.headers.as_ref().map(|h| h.keys().collect::<Vec<_>>()),
            )
            .finish()
    }
}

/// `credential.delegated` — built from `RawDelegatedToken`, for
/// `token_delegate`.
///
/// The worker maps `token` → `DelegationPayload.bearer_token`; the rest is
/// audit and validation context.
#[derive(Clone, Serialize)]
pub struct DelegatedCredential {
    /// The plaintext, read straight from the in-memory `Zeroizing` field.
    pub token: String,

    /// Where the consumer should attach the token upstream.
    pub outbound_header: String,

    /// Audience the token was minted for.
    pub audience: String,

    /// Effective scopes on the minted token.
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for DelegatedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedCredential")
            .field("token", &REDACTED)
            .field("outbound_header", &self.outbound_header)
            .field("audience", &self.audience)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// The wire name for a `TokenKind`.
///
/// Matches the `snake_case` serde rename on the enum, which is what
/// `worker.py`'s `_BEARER_TOKEN_KINDS` matches against. Written out rather
/// than round-tripped through serde so the mapping is reviewable next to the
/// contract it implements.
fn token_kind_wire_name(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Jwt => "jwt",
        TokenKind::Opaque => "opaque",
        TokenKind::SpiffeJwt => "spiffe_jwt",
        TokenKind::Ucan => "ucan",
        TokenKind::TxnToken => "txn_token",
        // `TokenKind` is `#[non_exhaustive]`, so a kind added upstream lands
        // here. "opaque" is the safe default: the worker maps unknown kinds to
        // `source: "custom"`, which makes a validator inspect the headers
        // itself rather than trust a source it does not recognize.
        _ => "opaque",
    }
}

/// Attach the `credential` object to a task, when the hook and the plugin's
/// declared capabilities both call for it.
///
/// A no-op for every hook other than `identity_resolve` and `token_delegate`,
/// and for any plugin that declared neither capability.
pub fn attach_credential(
    task: &mut Value,
    hook_name: &str,
    extensions: &Extensions,
    capabilities: &HashSet<String>,
) -> Result<(), HostError> {
    let kind = payload_kind_for_hook(hook_name);

    let dto = match kind {
        PayloadKind::IdentityResolve => {
            if !capabilities.contains(CAP_READ_INBOUND) {
                return Ok(());
            }
            CredentialDto {
                inbound: Some(build_inbound(extensions, hook_name)?),
                delegated: None,
            }
        },
        PayloadKind::TokenDelegate => {
            if !capabilities.contains(CAP_READ_DELEGATED) {
                return Ok(());
            }
            CredentialDto {
                inbound: None,
                delegated: Some(build_delegated(extensions, hook_name)?),
            }
        },
        // No other hook has a payload field to receive a token.
        _ => return Ok(()),
    };

    let object = task.as_object_mut().ok_or_else(|| HostError::Protocol {
        message: "task must be a JSON object to carry a credential".into(),
    })?;

    let serialized = serde_json::to_value(&dto).map_err(|e| HostError::Credential {
        // The error names the failure, never the value.
        message: format!("could not serialize the credential DTO: {e}"),
    })?;
    object.insert(CREDENTIAL_FIELD.to_string(), serialized);

    Ok(())
}

/// Build `credential.inbound` from the filtered extensions view.
///
/// The plugin declared `read_inbound_credentials`, so a missing or empty token
/// is a fail-closed error rather than an omitted field: sending no token to a
/// plugin that asked for one invites it to treat the request as unauthenticated.
fn build_inbound(extensions: &Extensions, hook_name: &str) -> Result<InboundCredential, HostError> {
    let raw = extensions
        .raw_credentials
        .as_ref()
        .ok_or_else(|| HostError::Credential {
            message: format!(
                "plugin declared '{CAP_READ_INBOUND}' for hook '{hook_name}' but the request \
                 carries no raw-credentials extension — refusing to dispatch without the token \
                 it asked for"
            ),
        })?;

    // Prefer the user token, then the client token, then a workload JWT-SVID.
    // Ordering matters: an identity resolver wants the subject's credential,
    // and falling straight to the client token would resolve the gateway's own
    // identity as if it were the user's.
    let token = [TokenRole::User, TokenRole::Client, TokenRole::Workload]
        .iter()
        .find_map(|role| raw.inbound_tokens.get(role))
        .or_else(|| raw.inbound_tokens.values().next())
        .ok_or_else(|| HostError::Credential {
            message: format!(
                "plugin declared '{CAP_READ_INBOUND}' for hook '{hook_name}' but no inbound token \
                 is present — refusing to dispatch without it"
            ),
        })?;

    inbound_from_token(token, hook_name)
}

/// Convert one `RawInboundToken` into its wire form.
fn inbound_from_token(
    token: &RawInboundToken,
    hook_name: &str,
) -> Result<InboundCredential, HostError> {
    // Reading `*token.token` is the whole point: `serde` would give back an
    // empty string here, because the field is `#[serde(skip)]`.
    let plaintext = token.token.as_str();

    // Whitespace-only is rejected as well as empty: "Authorization: Bearer   "
    // is not meaningfully different from an empty bearer downstream, and
    // `worker.py` rejects it on its side too.
    if plaintext.trim().is_empty() {
        return Err(HostError::Credential {
            message: format!(
                "the inbound token for hook '{hook_name}' is empty — refusing to send an empty \
                 credential (an empty bearer authenticates nowhere, and a plugin may read it as \
                 'no authentication required')"
            ),
        });
    }

    Ok(InboundCredential {
        token: plaintext.to_string(),
        source_header: token.source_header.clone(),
        kind: token_kind_wire_name(&token.kind).to_string(),
        // Synthesized so a header-driven extractor learns which header carried
        // the credential. The worker scrubs the plaintext back out of these
        // values before a plugin can echo them onto a serialized payload.
        headers: Some(HashMap::from([(
            token.source_header.clone(),
            plaintext.to_string(),
        )])),
    })
}

/// Build `credential.delegated` from the filtered extensions view.
fn build_delegated(
    extensions: &Extensions,
    hook_name: &str,
) -> Result<DelegatedCredential, HostError> {
    let raw = extensions
        .raw_credentials
        .as_ref()
        .ok_or_else(|| HostError::Credential {
            message: format!(
                "plugin declared '{CAP_READ_DELEGATED}' for hook '{hook_name}' but the request \
                 carries no raw-credentials extension — refusing to dispatch without the token \
                 it asked for"
            ),
        })?;

    // Prefer an on-behalf-of-user token: a delegator asked to act for the user
    // should not silently fall back to the gateway's own identity.
    let token = raw
        .delegated_tokens
        .iter()
        .find(|(key, _)| key.mode == DelegationMode::OnBehalfOfUser)
        .or_else(|| raw.delegated_tokens.iter().next())
        .map(|(_, token)| token)
        .ok_or_else(|| HostError::Credential {
            message: format!(
                "plugin declared '{CAP_READ_DELEGATED}' for hook '{hook_name}' but no delegated \
                 token is present — refusing to dispatch without it"
            ),
        })?;

    delegated_from_token(token, hook_name)
}

/// Convert one `RawDelegatedToken` into its wire form.
fn delegated_from_token(
    token: &RawDelegatedToken,
    hook_name: &str,
) -> Result<DelegatedCredential, HostError> {
    let plaintext = token.token.as_str();

    if plaintext.trim().is_empty() {
        return Err(HostError::Credential {
            message: format!(
                "the delegated token for hook '{hook_name}' is empty — refusing to send an empty \
                 credential"
            ),
        });
    }

    Ok(DelegatedCredential {
        token: plaintext.to_string(),
        outbound_header: token.outbound_header.clone(),
        audience: token.audience.clone(),
        scopes: token.scopes.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cpex_core::extensions::raw_credentials::{DelegationKey, RawCredentialsExtension};

    use super::*;

    const INBOUND_SECRET: &str = "eyJhbGciOiJSUzI1NiJ9.INBOUND-SECRET-BYTES.sig";
    const DELEGATED_SECRET: &str = "MINTED-DELEGATED-SECRET-BYTES";

    fn caps(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    /// Extensions carrying both an inbound and a delegated token.
    fn extensions_with_credentials() -> Extensions {
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new(INBOUND_SECRET, "Authorization", TokenKind::Jwt),
        );
        raw.delegated_tokens.insert(
            DelegationKey {
                subject_id: "alice".into(),
                audience: "https://billing.example.com".into(),
                scopes: vec!["read".into()],
                mode: DelegationMode::OnBehalfOfUser,
            },
            RawDelegatedToken::new(
                DELEGATED_SECRET,
                "Authorization",
                "https://billing.example.com",
                vec!["read".into()],
                chrono::Utc::now(),
            ),
        );

        Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        }
    }

    fn task() -> Value {
        serde_json::json!({ "task_type": "load_and_run_hook" })
    }

    // --- the capability gate -------------------------------------------------

    #[test]
    fn a_declaring_plugin_receives_the_inbound_token() {
        let mut task = task();
        attach_credential(
            &mut task,
            "identity_resolve",
            &extensions_with_credentials(),
            &caps(&[CAP_READ_INBOUND]),
        )
        .expect("a declared capability is honored");

        let credential = &task[CREDENTIAL_FIELD];
        assert_eq!(credential["inbound"]["token"], INBOUND_SECRET);
        assert_eq!(credential["inbound"]["source_header"], "Authorization");
        assert_eq!(credential["inbound"]["kind"], "jwt");
        assert!(
            credential.get("delegated").is_none(),
            "an identity hook must not receive delegated material"
        );
    }

    #[test]
    fn a_non_declaring_plugin_receives_no_token_material() {
        let mut task = task();
        attach_credential(
            &mut task,
            "identity_resolve",
            &extensions_with_credentials(),
            &caps(&[]),
        )
        .expect("declaring nothing is not an error");

        assert!(
            task.get(CREDENTIAL_FIELD).is_none(),
            "no credential field at all"
        );
        assert!(
            !serde_json::to_string(&task)
                .unwrap()
                .contains("INBOUND-SECRET-BYTES"),
            "no token bytes anywhere in the task"
        );
    }

    #[test]
    fn two_plugins_on_one_hook_are_gated_independently() {
        // The capability-gated acceptance example: same hook, same request, one
        // plugin declared the capability and the other did not.
        let extensions = extensions_with_credentials();

        let mut declaring = task();
        attach_credential(
            &mut declaring,
            "identity_resolve",
            &extensions,
            &caps(&[CAP_READ_INBOUND]),
        )
        .unwrap();

        let mut non_declaring = task();
        attach_credential(
            &mut non_declaring,
            "identity_resolve",
            &extensions,
            &caps(&[]),
        )
        .unwrap();

        assert!(serde_json::to_string(&declaring)
            .unwrap()
            .contains(INBOUND_SECRET));
        assert!(!serde_json::to_string(&non_declaring)
            .unwrap()
            .contains("INBOUND-SECRET-BYTES"));
    }

    #[test]
    fn the_wrong_capability_does_not_unlock_a_hook() {
        // `read_delegated_tokens` must not grant inbound material, and vice
        // versa — the two are independently scoped.
        let extensions = extensions_with_credentials();

        let mut identity = task();
        attach_credential(
            &mut identity,
            "identity_resolve",
            &extensions,
            &caps(&[CAP_READ_DELEGATED]),
        )
        .unwrap();
        assert!(identity.get(CREDENTIAL_FIELD).is_none());

        let mut delegate = task();
        attach_credential(
            &mut delegate,
            "token_delegate",
            &extensions,
            &caps(&[CAP_READ_INBOUND]),
        )
        .unwrap();
        assert!(delegate.get(CREDENTIAL_FIELD).is_none());
    }

    #[test]
    fn a_declaring_plugin_receives_the_delegated_token() {
        let mut task = task();
        attach_credential(
            &mut task,
            "token_delegate",
            &extensions_with_credentials(),
            &caps(&[CAP_READ_DELEGATED]),
        )
        .expect("a declared capability is honored");

        let delegated = &task[CREDENTIAL_FIELD]["delegated"];
        assert_eq!(delegated["token"], DELEGATED_SECRET);
        assert_eq!(delegated["outbound_header"], "Authorization");
        assert_eq!(delegated["audience"], "https://billing.example.com");
        assert_eq!(delegated["scopes"][0], "read");
        assert!(task[CREDENTIAL_FIELD].get("inbound").is_none());
    }

    #[test]
    fn non_credential_hooks_never_receive_a_credential() {
        // Even a plugin that declared both capabilities gets nothing on a hook
        // whose payload has nowhere to put a token.
        for hook in [
            "tool_pre_invoke",
            "tool_post_invoke",
            "prompt_pre_fetch",
            "resource_post_fetch",
            "cmf.tool_pre_invoke",
            "some_custom_hook",
        ] {
            let mut task = task();
            attach_credential(
                &mut task,
                hook,
                &extensions_with_credentials(),
                &caps(&[CAP_READ_INBOUND, CAP_READ_DELEGATED]),
            )
            .unwrap();

            assert!(
                task.get(CREDENTIAL_FIELD).is_none(),
                "hook '{hook}' must not receive credentials"
            );
        }
    }

    // --- fail closed ---------------------------------------------------------

    #[test]
    fn a_declared_capability_with_no_extension_errors() {
        // Fail closed rather than dispatching without the token: a plugin that
        // asked for a credential and silently got none may treat the request
        // as unauthenticated.
        let err = attach_credential(
            &mut task(),
            "identity_resolve",
            &Extensions::default(),
            &caps(&[CAP_READ_INBOUND]),
        )
        .expect_err("a declared capability that cannot be honored must error");

        assert!(matches!(err, HostError::Credential { .. }), "got {err:?}");
    }

    #[test]
    fn a_declared_capability_with_no_matching_token_errors() {
        // The extension exists but carries only delegated tokens, so the
        // inbound capability cannot be honored.
        let mut raw = RawCredentialsExtension::default();
        raw.delegated_tokens.insert(
            DelegationKey {
                subject_id: "alice".into(),
                audience: "aud".into(),
                scopes: vec![],
                mode: DelegationMode::AsGateway,
            },
            RawDelegatedToken::new("t", "Authorization", "aud", vec![], chrono::Utc::now()),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let err = attach_credential(
            &mut task(),
            "identity_resolve",
            &extensions,
            &caps(&[CAP_READ_INBOUND]),
        )
        .expect_err("no inbound token means the capability cannot be honored");
        assert!(matches!(err, HostError::Credential { .. }));
    }

    #[test]
    fn an_empty_token_is_rejected_rather_than_sent() {
        // A `#[serde(skip)]`-stripped token deserializes to "" — exactly the
        // shape that reaches here if anyone ever reintroduces a
        // serialize-then-reparse. Sending it would authenticate as an empty
        // bearer.
        for token in ["", "   ", "\t\n"] {
            let mut raw = RawCredentialsExtension::default();
            raw.inbound_tokens.insert(
                TokenRole::User,
                RawInboundToken::new(token, "Authorization", TokenKind::Jwt),
            );
            let extensions = Extensions {
                raw_credentials: Some(Arc::new(raw)),
                ..Default::default()
            };

            let err = attach_credential(
                &mut task(),
                "identity_resolve",
                &extensions,
                &caps(&[CAP_READ_INBOUND]),
            )
            .expect_err("an empty or whitespace-only token must be refused");
            assert!(matches!(err, HostError::Credential { .. }));
        }
    }

    #[test]
    fn an_empty_delegated_token_is_rejected() {
        let mut raw = RawCredentialsExtension::default();
        raw.delegated_tokens.insert(
            DelegationKey {
                subject_id: "alice".into(),
                audience: "aud".into(),
                scopes: vec![],
                mode: DelegationMode::OnBehalfOfUser,
            },
            RawDelegatedToken::new("", "Authorization", "aud", vec![], chrono::Utc::now()),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let err = attach_credential(
            &mut task(),
            "token_delegate",
            &extensions,
            &caps(&[CAP_READ_DELEGATED]),
        )
        .expect_err("an empty delegated token must be refused");
        assert!(matches!(err, HostError::Credential { .. }));
    }

    #[test]
    fn a_fail_closed_error_never_names_the_token() {
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("   ", "Authorization", TokenKind::Jwt),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let err = attach_credential(
            &mut task(),
            "identity_resolve",
            &extensions,
            &caps(&[CAP_READ_INBOUND]),
        )
        .expect_err("errors");
        let message = err.to_string();
        assert!(
            message.contains("identity_resolve"),
            "the message should name the hook: {message}"
        );
        assert!(message.contains("empty"));
    }

    // --- the DTO is the only carrier ----------------------------------------

    #[test]
    fn production_credential_types_still_refuse_to_serialize_tokens() {
        // The guard this module works around must remain intact: nothing here
        // loosened it, so a direct serialize of the production types still
        // strips the bytes. If this ever fails, the DTO stopped being the only
        // path token material can take.
        let inbound = RawInboundToken::new(INBOUND_SECRET, "Authorization", TokenKind::Jwt);
        let json = serde_json::to_string(&inbound).unwrap();
        assert!(
            !json.contains("INBOUND-SECRET-BYTES"),
            "the serde guard regressed: {json}"
        );

        let delegated = RawDelegatedToken::new(
            DELEGATED_SECRET,
            "Authorization",
            "aud",
            vec![],
            chrono::Utc::now(),
        );
        let json = serde_json::to_string(&delegated).unwrap();
        assert!(
            !json.contains("MINTED-DELEGATED"),
            "the serde guard regressed: {json}"
        );

        // And the inbound sub-map, which is what an audit or trace path dumps.
        // (`delegated_tokens` is keyed by a struct, so the extension as a whole
        // is not JSON-serializable — a pre-existing property of the type, not
        // something this host changed.)
        let extensions = extensions_with_credentials();
        let raw = extensions.raw_credentials.as_ref().unwrap();
        let json = serde_json::to_string(&raw.inbound_tokens).unwrap();
        assert!(
            !json.contains("INBOUND-SECRET-BYTES"),
            "the serde guard regressed: {json}"
        );

        for token in raw.delegated_tokens.values() {
            let json = serde_json::to_string(token).unwrap();
            assert!(
                !json.contains("MINTED-DELEGATED"),
                "the serde guard regressed: {json}"
            );
        }
    }

    #[test]
    fn a_serialize_then_reparse_would_have_yielded_an_empty_token() {
        // Documents *why* the DTO reads the in-memory field directly. This is
        // the tempting shortcut, and it silently produces an empty credential.
        let inbound = RawInboundToken::new(INBOUND_SECRET, "Authorization", TokenKind::Jwt);
        let round_tripped: RawInboundToken =
            serde_json::from_str(&serde_json::to_string(&inbound).unwrap()).unwrap();

        assert_eq!(
            &*round_tripped.token, "",
            "the guard strips the bytes on the way out"
        );
        assert_eq!(round_tripped.source_header, "Authorization");
    }

    // --- redaction -----------------------------------------------------------

    #[test]
    fn the_dto_debug_output_hides_the_token() {
        let dto = CredentialDto {
            inbound: Some(InboundCredential {
                token: INBOUND_SECRET.into(),
                source_header: "Authorization".into(),
                kind: "jwt".into(),
                headers: Some(HashMap::from([(
                    "Authorization".into(),
                    format!("Bearer {INBOUND_SECRET}"),
                )])),
            }),
            delegated: None,
        };

        // Both the outer DTO and the inner sub-object are printed, since either
        // could reach a log line on its own.
        let outer = format!("{dto:?}");
        let inner = format!("{:?}", dto.inbound.as_ref().unwrap());

        for debug in [&outer, &inner] {
            assert!(
                !debug.contains("INBOUND-SECRET-BYTES"),
                "token leaked into Debug: {debug}"
            );
        }
        // Non-secret context stays diagnosable.
        assert!(inner.contains("Authorization"));
        assert!(inner.contains("jwt"));
    }

    #[test]
    fn the_delegated_dto_debug_output_hides_the_token() {
        let credential = DelegatedCredential {
            token: DELEGATED_SECRET.into(),
            outbound_header: "Authorization".into(),
            audience: "https://billing.example.com".into(),
            scopes: vec!["read".into()],
        };

        let debug = format!("{credential:?}");
        assert!(
            !debug.contains("MINTED-DELEGATED"),
            "token leaked into Debug: {debug}"
        );
        assert!(debug.contains("billing.example.com"));
        assert!(debug.contains("read"));
    }

    // --- wire contract details ----------------------------------------------

    #[test]
    fn token_kinds_use_the_wire_names_the_worker_matches_on() {
        // worker.py's _BEARER_TOKEN_KINDS is {jwt, opaque, spiffe_jwt, ucan};
        // a mismatch here would silently map a bearer to source "custom".
        assert_eq!(token_kind_wire_name(&TokenKind::Jwt), "jwt");
        assert_eq!(token_kind_wire_name(&TokenKind::Opaque), "opaque");
        assert_eq!(token_kind_wire_name(&TokenKind::SpiffeJwt), "spiffe_jwt");
        assert_eq!(token_kind_wire_name(&TokenKind::Ucan), "ucan");
        assert_eq!(token_kind_wire_name(&TokenKind::TxnToken), "txn_token");
    }

    #[test]
    fn wire_names_match_the_serde_representation() {
        // Guards the hand-written mapping against the enum's own serde rename,
        // so adding a variant upstream cannot silently desync the two.
        for kind in [
            TokenKind::Jwt,
            TokenKind::Opaque,
            TokenKind::SpiffeJwt,
            TokenKind::Ucan,
            TokenKind::TxnToken,
        ] {
            let via_serde = serde_json::to_value(&kind).unwrap();
            assert_eq!(
                via_serde.as_str().unwrap(),
                token_kind_wire_name(&kind),
                "hand-written wire name disagrees with serde for {kind:?}"
            );
        }
    }

    #[test]
    fn the_user_token_is_preferred_over_the_client_token() {
        // An identity resolver wants the subject's credential; resolving the
        // gateway's own token as the user's would be an authorization bug.
        let mut raw = RawCredentialsExtension::default();
        raw.inbound_tokens.insert(
            TokenRole::Client,
            RawInboundToken::new("CLIENT-TOKEN", "X-Client", TokenKind::Opaque),
        );
        raw.inbound_tokens.insert(
            TokenRole::User,
            RawInboundToken::new("USER-TOKEN", "Authorization", TokenKind::Jwt),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let mut task = task();
        attach_credential(
            &mut task,
            "identity_resolve",
            &extensions,
            &caps(&[CAP_READ_INBOUND]),
        )
        .unwrap();
        assert_eq!(task[CREDENTIAL_FIELD]["inbound"]["token"], "USER-TOKEN");
    }

    #[test]
    fn headers_are_synthesized_from_the_source_header() {
        let mut task = task();
        attach_credential(
            &mut task,
            "identity_resolve",
            &extensions_with_credentials(),
            &caps(&[CAP_READ_INBOUND]),
        )
        .unwrap();

        // The worker scrubs the plaintext out of these values before a plugin
        // can echo them; the host's job is only to name the carrying header.
        assert_eq!(
            task[CREDENTIAL_FIELD]["inbound"]["headers"]["Authorization"],
            INBOUND_SECRET
        );
    }

    #[test]
    fn an_on_behalf_of_user_token_is_preferred_over_a_gateway_token() {
        let mut raw = RawCredentialsExtension::default();
        raw.delegated_tokens.insert(
            DelegationKey {
                subject_id: "gw".into(),
                audience: "aud".into(),
                scopes: vec![],
                mode: DelegationMode::AsGateway,
            },
            RawDelegatedToken::new(
                "GATEWAY-TOKEN",
                "Authorization",
                "aud",
                vec![],
                chrono::Utc::now(),
            ),
        );
        raw.delegated_tokens.insert(
            DelegationKey {
                subject_id: "alice".into(),
                audience: "aud".into(),
                scopes: vec![],
                mode: DelegationMode::OnBehalfOfUser,
            },
            RawDelegatedToken::new(
                "USER-DELEGATED-TOKEN",
                "Authorization",
                "aud",
                vec![],
                chrono::Utc::now(),
            ),
        );
        let extensions = Extensions {
            raw_credentials: Some(Arc::new(raw)),
            ..Default::default()
        };

        let mut task = task();
        attach_credential(
            &mut task,
            "token_delegate",
            &extensions,
            &caps(&[CAP_READ_DELEGATED]),
        )
        .unwrap();
        assert_eq!(
            task[CREDENTIAL_FIELD]["delegated"]["token"], "USER-DELEGATED-TOKEN",
            "a delegator acting for the user must not fall back to the gateway's identity"
        );
    }

    #[test]
    fn the_credential_field_name_matches_the_worker_contract() {
        assert_eq!(
            CREDENTIAL_FIELD, "credential",
            "the worker reads task_data['credential']"
        );
    }
}
