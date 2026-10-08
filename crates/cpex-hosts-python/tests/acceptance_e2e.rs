// Location: ./crates/cpex-hosts-python/tests/acceptance_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Acceptance: Python identity and delegation plugins in PPE's own flows.
//
// The other e2e suites call the adapter directly or dispatch the legacy
// payload structs, which no PPE caller produces. This one loads a policy YAML
// with `isolated_venv` plugins on `identity.resolve` and `token.delegate` plus
// an APL route, and drives it through `PolicyEngine` the way a host does:
//
//   1. `identity.resolve` with PPE's `IdentityPayload::new(..)`, the route's
//      `authentication:` list choosing the resolvers;
//   2. the resolved identity applied to the request extensions;
//   3. `cmf.tool_pre_invoke` on the route, whose policy requires an
//      authenticated caller, runs `delegate(..)` (which builds PPE's
//      `DelegationPayload` and dispatches `token.delegate`), and requires the
//      delegation to have been granted.
//
// The fixture plugin records what it saw in a marker file per plugin name, so
// the test asserts both the decision and the credential path: the plugin that
// declared `read_inbound_credentials` got the plaintext, the one beside it that
// declared nothing got none, and no credential header reached either through
// the public payload.
//
// It scaffolds its own plugin with `scaffold_plugin`, so it needs only python3
// and a cpex Python checkout (`CPEX_PYTHON_SOURCE`), not an installed plugin.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpex_hosts_python::testing::{
    TEMP_DIR_KIND, TempDir, TempDirFactory, prebuild_venv, python_source, scaffold_plugin, skip,
    skip_without_python3, worker_consumes_credentials,
};
use praxis_policy::{AplOptions, register_apl};
use praxis_policy_core::cmf::{ContentPart, Message, MessagePayload, Role, ToolCall};
use praxis_policy_core::engine::{PolicyEngine, PolicyEngineConfig};
use praxis_policy_core::extensions::raw_credentials::{
    RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
};
use praxis_policy_core::extensions::{Extensions, MetaExtension};
use praxis_policy_core::identity::{HOOK_IDENTITY_RESOLVE, IdentityPayload, TokenSource};

/// The inbound credential under test. Distinctive so a leak is unambiguous.
const SECRET: &str = "ACCEPTANCE-INBOUND-PLAINTEXT-5d2e";

/// The token the fixture's delegator mints.
const MINTED: &str = "ACCEPTANCE-MINTED-DELEGATED-7b41";

/// A cookie that must never reach a plugin through the public payload.
const COOKIE: &str = "session=ACCEPTANCE-COOKIE-SECRET";

const PACKAGE: &str = "acceptance_pkg";
const FIXTURE_CLASS: &str = "acceptance_pkg.plugin.AcceptancePlugin";

/// The route's tool.
const TOOL: &str = "get_compensation";

/// One class serves all three plugins; the marker file is named by plugin.
///
/// Identity: a plugin that received the expected plaintext resolves `alice`;
/// one that received a different token rejects it; one that received none
/// (it declared no capability) allows without resolving. Delegation: mints a
/// token when the caller's bearer token arrived, and denies otherwise.
///
/// Markers record verdicts, never the secret itself.
const FIXTURE_PLUGIN: &str = r#"
import json
import os

from cpex.framework.base import Plugin
from cpex.framework.extensions.security import SubjectExtension
from cpex.framework.hooks.identity import DelegationResult, IdentityResult
from cpex.framework.models import PluginResult, PluginViolation

EXPECTED = "ACCEPTANCE-INBOUND-PLAINTEXT-5d2e"
MINTED = "ACCEPTANCE-MINTED-DELEGATED-7b41"


def _plain(secret):
    if secret is None:
        return ""
    return secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)


def _verdict(token):
    if token == EXPECTED:
        return "GOT_TOKEN"
    return "NO_TOKEN" if not token else "OTHER_TOKEN"


def _record(name, line):
    with open(os.path.join(os.getcwd(), f"verdict-{name}.txt"), "w") as f:
        f.write(line)


class AcceptancePlugin(Plugin):
    def __init__(self, config):
        super().__init__(config)

    async def identity_resolve(self, payload, context):
        token = _plain(payload.raw_token)
        headers = json.dumps(payload.headers, sort_keys=True)
        _record(
            self.name,
            f"{_verdict(token)};token_in_headers={EXPECTED in headers}"
            f";cookie={'ACCEPTANCE-COOKIE-SECRET' in headers}"
            f";tenant={payload.headers.get('x-tenant')}",
        )
        if token == EXPECTED:
            subject = SubjectExtension(id="alice", type="user", roles=frozenset({"hr"}))
            return PluginResult(modified_payload=IdentityResult(subject=subject))
        if token:
            return PluginResult(
                modified_payload=IdentityResult(
                    rejected=True, reject_status=401, reject_reason="unknown credential"
                )
            )
        return PluginResult(continue_processing=True)

    async def token_delegate(self, payload, context):
        token = _plain(payload.bearer_token)
        _record(self.name, f"{_verdict(token)};audience={payload.target_audience}")
        if token != EXPECTED:
            return PluginResult(
                continue_processing=False,
                violation=PluginViolation(
                    reason="no caller token to exchange", description="", code="NO_BEARER", details={}
                ),
            )
        return PluginResult(
            modified_payload=DelegationResult(
                delegated_token=MINTED,
                forwarded_headers={"Authorization": f"Bearer {MINTED}"},
                cache_ttl=120,
            )
        )
"#;

/// Three plugins and one route. `py-identity` declared the inbound credential
/// capability; `py-identity-blind` runs beside it on the same hook and
/// declared nothing. `py-delegator` declares what PPE's own OAuth delegator
/// does: the inbound credential it exchanges, and the right to stash the
/// minted token.
fn policy_yaml() -> String {
    let plugin = |name: &str, hook: &str, caps: &str| {
        format!(
            r#"
  - name: {name}
    kind: {TEMP_DIR_KIND}
    hooks: [{hook}]
    capabilities: [{caps}]
    version: "1.0.0"
    config:
      class_name: {FIXTURE_CLASS}
      requirements_file: requirements.txt
      timeout_secs: 300
"#
        )
    };
    format!(
        r#"
plugins:{}{}{}
routes:
  - tool: {TOOL}
    authentication:
      - py-identity
      - py-identity-blind
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "delegate(py-delegator, target: billing-api, audience: billing-api)"
        - "require(delegation.granted)"
"#,
        plugin(
            "py-identity",
            "identity.resolve",
            "read_inbound_credentials"
        ),
        plugin("py-identity-blind", "identity.resolve", ""),
        plugin(
            "py-delegator",
            "token.delegate",
            "read_inbound_credentials, write_delegated_tokens"
        ),
    )
}

/// Skip guard: `Some(source)` when the credential path is exercisable.
fn require_environment(test_name: &str) -> Option<PathBuf> {
    if skip_without_python3(test_name) {
        return None;
    }
    let source = match python_source() {
        Ok(source) => source,
        Err(reason) => {
            skip(test_name, &reason);
            return None;
        },
    };
    if !worker_consumes_credentials(&source) {
        skip(
            test_name,
            &format!(
                "the cpex source at {} has a worker.py that does not consume the `credential` \
                 field",
                source.display()
            ),
        );
        return None;
    }
    Some(source)
}

/// Scaffold the fixture and pre-build its venv, shared by all three plugins.
fn setup(dir: &TempDir, source: &Path, test_name: &str) -> Option<PathBuf> {
    let plugin_dir = scaffold_plugin(dir, source, PACKAGE, "plugin", FIXTURE_PLUGIN);
    match prebuild_venv(&plugin_dir, source, FIXTURE_CLASS, PACKAGE) {
        Ok(()) => Some(plugin_dir),
        Err(reason) => {
            skip(
                test_name,
                &format!("could not prepare the plugin venv: {reason}"),
            );
            None
        },
    }
}

/// An engine with APL installed and the YAML loaded and initialized.
async fn engine(dir: &TempDir, plugin_dir: &Path) -> Arc<PolicyEngine> {
    let engine = Arc::new(PolicyEngine::new(PolicyEngineConfig::default()));
    let _visitor = register_apl(&engine, AplOptions::in_process());
    engine.register_factory(
        TEMP_DIR_KIND,
        Box::new(TempDirFactory {
            plugin_dir: plugin_dir.to_path_buf(),
            worker_cwd: dir.path().to_path_buf(),
        }),
    );
    engine
        .load_config_yaml(&policy_yaml())
        .expect("the policy YAML loads");
    engine
        .initialize()
        .await
        .expect("the cached venv is reused and every worker starts");
    engine
}

/// The request's extensions: route meta only, as a host builds them.
fn request_extensions() -> Extensions {
    Extensions {
        meta: Some(Arc::new(MetaExtension {
            entity_type: Some("tool".into()),
            entity_name: Some(TOOL.into()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// PPE's identity payload for a request carrying `token`.
fn identity_payload(token: &str) -> IdentityPayload {
    IdentityPayload::new(token, TokenSource::Bearer)
        .with_source_header("authorization")
        .with_headers(HashMap::from([
            ("authorization".into(), format!("Bearer {token}")),
            ("cookie".into(), COOKIE.into()),
            ("x-tenant".into(), "acme".into()),
        ]))
        .with_client_host("10.0.0.7")
}

fn tool_call() -> MessagePayload {
    MessagePayload {
        message: Message::with_content(
            Role::Assistant,
            vec![ContentPart::ToolCall {
                content: ToolCall {
                    tool_call_id: "call-acceptance-1".into(),
                    name: TOOL.into(),
                    arguments: HashMap::from([("employee_id".into(), serde_json::json!("e-42"))]),
                    namespace: None,
                },
            }],
        ),
    }
}

fn marker(dir: &TempDir, plugin: &str) -> Option<String> {
    std::fs::read_to_string(dir.path().join(format!("verdict-{plugin}.txt"))).ok()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn python_identity_and_delegation_plugins_serve_a_ppe_route() {
    let test = "python_identity_and_delegation_plugins_serve_a_ppe_route";
    let Some(source) = require_environment(test) else {
        return;
    };
    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, test) else {
        return;
    };
    let engine = engine(&dir, &plugin_dir).await;

    // 1. identity.resolve, with PPE's own payload.
    let (identity_result, _bg) = engine
        .invoke_by_name(
            HOOK_IDENTITY_RESOLVE,
            Box::new(identity_payload(SECRET)),
            request_extensions(),
            None,
        )
        .await;
    assert!(
        identity_result.continue_processing,
        "identity resolution must allow: {:?} / errors {:?}",
        identity_result.violation, identity_result.errors
    );
    assert!(
        identity_result.errors.is_empty(),
        "{:?}",
        identity_result.errors
    );
    let resolved = IdentityPayload::from_pipeline_result(&identity_result)
        .expect("the Python result maps back onto PPE's IdentityPayload");
    let subject = resolved
        .subject
        .clone()
        .expect("the plugin resolved a subject");
    assert_eq!(subject.id.as_deref(), Some("alice"));
    assert!(subject.roles.contains("hr"));

    // The capability decides who sees credential material. The capable plugin
    // gets the token on `raw_token` and the credential headers through the
    // gated channel, with the worker scrubbing the token out of the header
    // values. The plugin beside it gets neither, only the public headers.
    let capable = marker(&dir, "py-identity").expect("py-identity ran");
    assert!(capable.starts_with("GOT_TOKEN;"), "{capable}");
    assert!(capable.contains("token_in_headers=False"), "{capable}");
    assert!(capable.contains("cookie=True"), "{capable}");
    assert!(capable.contains("tenant=acme"), "{capable}");
    let blind = marker(&dir, "py-identity-blind").expect("py-identity-blind ran");
    assert!(
        blind.starts_with("NO_TOKEN;"),
        "a plugin without read_inbound_credentials must not see the token: {blind}"
    );
    assert!(blind.contains("token_in_headers=False"), "{blind}");
    assert!(
        blind.contains("cookie=False"),
        "credential headers reach only a declaring plugin: {blind}"
    );
    assert!(blind.contains("tenant=acme"), "{blind}");

    // 2. The host applies the identity, and carries the inbound token for the
    //    delegate step to exchange.
    let mut extensions = resolved.apply_to_extensions(request_extensions());
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(SECRET, "authorization", TokenKind::Opaque),
    );
    extensions.raw_credentials = Some(Arc::new(raw));

    // 3. The route's policy: authenticated, delegate, delegation granted.
    let (result, _bg) = engine
        .invoke_by_name(
            "cmf.tool_pre_invoke",
            Box::new(tool_call()),
            extensions,
            None,
        )
        .await;
    assert!(
        result.continue_processing,
        "the route must allow an authenticated caller with a granted delegation: {:?} / errors \
         {:?}",
        result.violation, result.errors
    );

    let delegator = marker(&dir, "py-delegator").expect("the delegate step reached the plugin");
    assert!(
        delegator.starts_with("GOT_TOKEN;"),
        "the delegator declared read_inbound_credentials and must get the caller's token: \
         {delegator}"
    );
    assert!(delegator.contains("audience=billing-api"), "{delegator}");

    // The minted token, mapped onto PPE's DelegationPayload, is what PPE
    // stashed for the route's upstream call.
    let merged = result
        .modified_extensions
        .as_ref()
        .expect("the route's delegate step changed the extensions");
    let raw = merged
        .raw_credentials
        .as_ref()
        .expect("the delegate step stashed raw credentials");
    let minted = raw
        .delegated_tokens
        .values()
        .find(|t| t.token.as_str() == MINTED)
        .expect("the minted token is stashed for the route");
    assert_eq!(minted.audience, "billing-api");
    assert_eq!(minted.outbound_header, "Authorization");

    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_rejected_credential_denies_and_an_unauthenticated_route_call_is_refused() {
    let test = "a_rejected_credential_denies_and_an_unauthenticated_route_call_is_refused";
    let Some(source) = require_environment(test) else {
        return;
    };
    let dir = TempDir::new();
    let Some(plugin_dir) = setup(&dir, &source, test) else {
        return;
    };
    let engine = engine(&dir, &plugin_dir).await;

    // A credential the plugin does not accept: its IdentityResult sets
    // `rejected`, which reaches PPE as a deny.
    let (identity_result, _bg) = engine
        .invoke_by_name(
            HOOK_IDENTITY_RESOLVE,
            Box::new(identity_payload("ACCEPTANCE-SOME-OTHER-CREDENTIAL")),
            request_extensions(),
            None,
        )
        .await;
    assert!(!identity_result.continue_processing);
    let violation = identity_result.violation.expect("the deny names its cause");
    assert_eq!(violation.code, "auth.rejected");
    assert_eq!(violation.reason, "unknown credential");
    assert!(
        marker(&dir, "py-identity-blind").is_none(),
        "the chain halts at the rejection"
    );

    // With no resolved identity the route's `require(authenticated)` denies
    // before the delegate step runs.
    let (result, _bg) = engine
        .invoke_by_name(
            "cmf.tool_pre_invoke",
            Box::new(tool_call()),
            request_extensions(),
            None,
        )
        .await;
    assert!(
        !result.continue_processing,
        "an unauthenticated caller must be refused"
    );
    assert!(
        marker(&dir, "py-delegator").is_none(),
        "no delegation is attempted for an unauthenticated caller"
    );

    engine.shutdown().await;
}
