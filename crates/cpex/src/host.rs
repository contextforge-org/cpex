// Location: ./crates/cpex/src/host.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo

//! Host wiring shared by the CPEX language bindings.
//!
//! The C FFI and the Python wheel install the same defaults on an engine,
//! report secret failures with the same kind strings, refuse the same
//! removed hook names and the same caller-supplied identity fields. Those
//! rules live here once, so a Go host and a Python host see the same
//! behavior. Each binding keeps only its own wire shapes.

use std::sync::Arc;

use praxis_policy::praxis_policy_core::http::HttpTransport;
use praxis_policy::praxis_policy_core::identity::IdentityPayload;
use praxis_policy::{
    HyperTransport, PolicyEngine, SecretError, install_builtins, registry_with_vault,
};

/// Hook names removed in 0.3, each paired with the name that replaced it.
///
/// A config naming one of these fails to load. An invoke call naming one
/// would reach no handler and come back allowed, so the bindings refuse
/// these names at invoke time too. Use [`removed_hook_replacement`] to
/// look one up.
pub const REMOVED_HOOKS: &[(&str, &str)] = &[
    ("tool_pre_invoke", "cmf.tool_pre_invoke"),
    ("tool_post_invoke", "cmf.tool_post_invoke"),
    ("prompt_pre_fetch", "cmf.prompt_pre_invoke"),
    ("cmf.prompt_pre_fetch", "cmf.prompt_pre_invoke"),
    ("prompt_post_fetch", "cmf.prompt_post_invoke"),
    ("cmf.prompt_post_fetch", "cmf.prompt_post_invoke"),
    ("resource_pre_fetch", "cmf.resource_pre_fetch"),
    ("resource_post_fetch", "cmf.resource_post_fetch"),
    ("identity_resolve", "identity.resolve"),
    ("token_delegate", "token.delegate"),
    ("cmf.http_request", "http.request"),
    ("cmf.http_response", "http.response"),
];

/// The replacement for a hook name removed in 0.3, or `None` when
/// `hook_name` is not one of the [`REMOVED_HOOKS`].
pub fn removed_hook_replacement(hook_name: &str) -> Option<&'static str> {
    REMOVED_HOOKS
        .iter()
        .find(|(removed, _)| *removed == hook_name)
        .map(|(_, replacement)| *replacement)
}

/// Install everything a binding host gets by default on `engine`.
///
/// What it installs:
///   - every bundled builtin factory and the APL config visitor, through
///     [`install_builtins`]
///   - one [`HyperTransport`] for builtins that perform HTTP
///   - the secret providers `env`, `file` and `vault`, with Vault using
///     that same transport instance
///
/// With `allow_private_destinations` the transport may reach private,
/// loopback and link-local addresses; without it such requests are
/// refused and builtins report their egress-denied codes. This is a host
/// decision; no policy document can turn it on.
///
/// Call it once per engine, on the same `Arc` that later loads the
/// config, so the APL visitor's weak reference upgrades during the load.
/// `install_builtins` appends a new APL visitor on every call, so a second
/// call would walk `apl:` blocks twice. The transport and the secret
/// providers are set-once: if the host already installed either, the
/// existing one is kept and the engine logs a warning.
pub fn install_host_defaults(engine: &Arc<PolicyEngine>, allow_private_destinations: bool) {
    install_builtins(engine);

    let mut hyper = HyperTransport::new();
    if allow_private_destinations {
        hyper = hyper.with_allow_private_destinations();
    }
    let transport: Arc<dyn HttpTransport> = Arc::new(hyper);
    // Both setters are set-once and log their own warning when a
    // transport or registry is already present.
    let _ = engine.set_http_transport(Arc::clone(&transport));
    let _ = engine.set_secret_providers(registry_with_vault(transport));
}

/// The failure class of a secret error, as the bindings report it.
///
/// One of `config`, `reference`, `not_found`, `malformed`, `backend`, or
/// `other` for a class this build does not know. The strings are part of
/// the binding wire contract: Go and Python hosts read the same values.
pub fn secret_error_kind(err: &SecretError) -> &'static str {
    match err {
        SecretError::Config { .. } => "config",
        SecretError::Reference { .. } => "reference",
        SecretError::NotFound { .. } => "not_found",
        SecretError::Malformed { .. } => "malformed",
        SecretError::Backend { .. } => "backend",
        _ => "other",
    }
}

/// The resolver output fields set on an inbound `identity.resolve`
/// payload, by their wire names.
///
/// Only `source`, `source_header`, `headers`, `client_host` and
/// `client_port` are inputs. `subject`, `client`, `caller_workload`,
/// `delegation`, `raw_credentials`, `resolved_at` and `raw_claims` are what
/// resolvers fill in. A caller that pre-fills them could forge the
/// resolved identity, so the bindings refuse a payload for which this
/// returns anything.
pub fn resolved_identity_fields(payload: &IdentityPayload) -> Vec<&'static str> {
    let mut set = Vec::new();
    if payload.subject.is_some() {
        set.push("subject");
    }
    if payload.client.is_some() {
        set.push("client");
    }
    if payload.caller_workload.is_some() {
        set.push("caller_workload");
    }
    if payload.delegation.is_some() {
        set.push("delegation");
    }
    if payload.raw_credentials.is_some() {
        set.push("raw_credentials");
    }
    if payload.resolved_at.is_some() {
        set.push("resolved_at");
    }
    if !payload.raw_claims.is_empty() {
        set.push("raw_claims");
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_hooks_map_to_their_replacements() {
        assert_eq!(
            removed_hook_replacement("tool_pre_invoke"),
            Some("cmf.tool_pre_invoke")
        );
        assert_eq!(
            removed_hook_replacement("cmf.prompt_pre_fetch"),
            Some("cmf.prompt_pre_invoke")
        );
        assert_eq!(
            removed_hook_replacement("identity_resolve"),
            Some("identity.resolve")
        );
        assert_eq!(removed_hook_replacement("cmf.tool_pre_invoke"), None);
        assert_eq!(removed_hook_replacement("custom.hook"), None);
    }

    /// Every replacement is a hook the engine knows, and no removed name is.
    #[test]
    fn removed_hooks_are_unknown_and_replacements_known() {
        use praxis_policy::praxis_policy_core::hooks::lookup_hook_metadata;
        for (removed, replacement) in REMOVED_HOOKS {
            assert!(
                lookup_hook_metadata(removed).is_none(),
                "{removed} must not be a registered hook"
            );
            assert!(
                lookup_hook_metadata(replacement).is_some(),
                "{replacement} must be a registered hook"
            );
        }
    }

    #[test]
    fn install_host_defaults_installs_the_transport_and_secret_providers() {
        let engine = Arc::new(PolicyEngine::default());
        install_host_defaults(&engine, false);
        // Both are set-once, so a second set reports the existing one.
        assert!(!engine.set_http_transport(Arc::new(HyperTransport::new())));
        assert!(!engine.set_secret_providers(registry_with_vault(Arc::new(HyperTransport::new()))));
        // The builtin kind resolves: a load fails on the plugin's own
        // settings, not on an unknown kind.
        let err = engine
            .load_config_yaml(
                r#"
plugins:
  - name: jwt
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      not_a_setting: true
"#,
            )
            .expect_err("the plugin settings are invalid")
            .to_string();
        assert!(err.contains("config parse failed"), "{err}");
    }

    #[test]
    fn secret_error_kinds_are_stable() {
        let cases = [
            (
                SecretError::Config {
                    message: "m".into(),
                },
                "config",
            ),
            (
                SecretError::NotFound {
                    reference: "r".into(),
                },
                "not_found",
            ),
        ];
        for (err, kind) in cases {
            assert_eq!(secret_error_kind(&err), kind);
        }
    }

    #[test]
    fn resolved_identity_fields_lists_only_output_slots() {
        let input: IdentityPayload = serde_json::from_value(serde_json::json!({
            "source": "bearer",
            "source_header": "authorization",
            "headers": {"authorization": "Bearer x"},
            "client_host": "10.0.0.1",
            "client_port": 443,
        }))
        .expect("input payload");
        assert!(resolved_identity_fields(&input).is_empty());

        let forged: IdentityPayload = serde_json::from_value(serde_json::json!({
            "source": "bearer",
            "subject": {"id": "alice"},
            "resolved_at": "2026-01-01T00:00:00Z",
            "raw_claims": {"sub": "alice"},
        }))
        .expect("forged payload");
        assert_eq!(
            resolved_identity_fields(&forged),
            vec!["subject", "resolved_at", "raw_claims"]
        );
    }
}
