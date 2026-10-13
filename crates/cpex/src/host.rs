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
use praxis_policy::praxis_policy_core::secrets::RefreshReport;
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
/// decision; no policy document can turn it on. Enabling it emits a
/// startup warning through the host's tracing subscriber, or stderr when
/// the host has no subscriber.
///
/// Call it once per engine, on the same `Arc` that later loads the
/// config, so the APL visitor's weak reference upgrades during the load.
/// `install_builtins` appends a new APL visitor on every call, so a second
/// call would walk policy sections twice. The transport and the secret
/// providers are set-once: if the host already installed either, the
/// existing one is kept and the engine logs a warning.
pub fn install_host_defaults(engine: &Arc<PolicyEngine>, allow_private_destinations: bool) {
    install_builtins(engine);

    let mut hyper = HyperTransport::new();
    if allow_private_destinations {
        warn_private_destinations();
        hyper = hyper.with_allow_private_destinations();
    }
    let transport: Arc<dyn HttpTransport> = Arc::new(hyper);
    // Both setters are set-once and log their own warning when a
    // transport or registry is already present.
    let _ = engine.set_http_transport(Arc::clone(&transport));
    let _ = engine.set_secret_providers(registry_with_vault(transport));
}

const PRIVATE_DESTINATIONS_WARNING: &str = "private destinations are enabled for all outbound builtins and Vault; \
     loopback, RFC 1918, link-local (including cloud metadata) and CGNAT \
     addresses are reachable; use only with trusted policies and networks";

/// Report a host's global private-destination opt-in at startup.
///
/// Rust hosts constructing a transport directly can call this too.
/// Hosts without a tracing subscriber receive the warning on stderr.
pub fn warn_private_destinations() {
    log_private_destinations(std::io::stderr());
}

fn log_private_destinations(mut fallback: impl std::io::Write) {
    tracing::warn!("{PRIVATE_DESTINATIONS_WARNING}");
    if tracing::dispatcher::get_default(|dispatch| {
        dispatch.is::<tracing::subscriber::NoSubscriber>()
    }) {
        let _ = writeln!(fallback, "WARN cpex: {PRIVATE_DESTINATIONS_WARNING}");
    }
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

/// The identity result visible to language bindings. Request headers may
/// contain credentials, so they never appear in a returned payload.
pub fn identity_result_value(
    payload: &IdentityPayload,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut value = serde_json::to_value(payload)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("headers");
    }
    Ok(value)
}

/// Refresh report shared by the C and Python bindings.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RefreshSummary {
    pub updated: Vec<String>,
    pub unchanged: u64,
    pub failed: Vec<RefreshFailure>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RefreshFailure {
    pub secret: String,
    pub provider: String,
    pub kind: String,
    pub message: String,
}

impl From<RefreshReport> for RefreshSummary {
    fn from(report: RefreshReport) -> Self {
        Self {
            updated: report.updated,
            unchanged: report.unchanged as u64,
            failed: report
                .failed
                .into_iter()
                .map(|failure| RefreshFailure {
                    kind: secret_error_kind(&failure.source).to_owned(),
                    message: failure.source.to_string(),
                    secret: failure.secret,
                    provider: failure.provider,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_destination_warning_reaches_hosts_without_a_subscriber() {
        let mut output = Vec::new();
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::new(), || {
            log_private_destinations(&mut output);
        });
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("WARN cpex: {PRIVATE_DESTINATIONS_WARNING}\n")
        );
    }

    #[test]
    fn private_destination_opt_in_warns_about_its_scope() {
        #[derive(Clone)]
        struct Log(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Log {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let log = Log(Default::default());
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            install_host_defaults(&Arc::new(PolicyEngine::default()), false);
            assert!(log.0.lock().unwrap().is_empty());
            install_host_defaults(&Arc::new(PolicyEngine::default()), true);
        });
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        for expected in [
            "WARN",
            "all outbound builtins and Vault",
            "cloud metadata",
            "CGNAT",
        ] {
            assert!(text.contains(expected), "{text}");
        }
    }

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
            "client": {"client_id": "app"},
            "caller_workload": {"spiffe_id": "spiffe://example.org/app"},
            "delegation": {"depth": 0},
            "raw_credentials": {"inbound_tokens": {}},
            "resolved_at": "2026-01-01T00:00:00Z",
            "raw_claims": {"sub": "alice"},
        }))
        .expect("forged payload");
        assert_eq!(
            resolved_identity_fields(&forged),
            vec![
                "subject",
                "client",
                "caller_workload",
                "delegation",
                "raw_credentials",
                "resolved_at",
                "raw_claims"
            ]
        );
    }
}
