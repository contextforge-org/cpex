// Location: ./crates/cpex-hosts-python/tests/credential_e2e.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// End-to-end: capability-gated raw credentials reaching a real Python plugin.
//
// The unit tests prove the gate and the DTO shape. These prove the whole
// channel: the host reads the in-memory token, attaches the DTO, `worker.py`
// folds it back onto the redacted `SecretStr` payload field, and the plugin
// reads the plaintext — while a plugin on the same hook that declared nothing
// gets no token at all.
//
// # Transport
//
// The `credential` object rides as a field in the existing task JSON on the
// worker's stdin: a private pipe inherited only by the child. There is no
// listening socket and no other local process can read it, so the
// "loopback-only, access-controlled" constraint holds by construction rather
// than by configuration. What still needs proving is that nothing *logs* it —
// hence the stderr assertions below.
//
// # Residual exposure this cannot close
//
// Once the plaintext is resident in the worker process, every transitively
// installed dependency in that venv can read it. That is a materially larger
// and less audited trust boundary than the in-process host, and neither the
// capability gate (which controls *which plugin* receives a token) nor the
// transport (which controls *how it travels*) constrains it. Shipping raw
// credentials to an out-of-process plugin means accepting that venv's whole
// dependency tree into the credential trust boundary.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cpex_core::context::PluginContext;
use cpex_core::extensions::raw_credentials::{
    RawCredentialsExtension, RawInboundToken, TokenKind, TokenRole,
};
use cpex_core::extensions::Extensions;
use cpex_core::plugin::{Plugin, PluginConfig};
use cpex_core::registry::AnyHookHandler;
use cpex_hosts_python::factory::KIND;
use cpex_hosts_python::legacy::IdentityResolvePayload;
use cpex_hosts_python::plugin::{IsolatedPythonPlugin, PythonHookAdapter};
use cpex_hosts_python::testing::{
    prebuild_venv, python_source, scaffold_plugin, skip, skip_without_python3,
    worker_consumes_credentials, TempDir,
};

/// The plaintext under test. Distinctive so a leak is unambiguous in any
/// captured output.
const SECRET: &str = "E2E-INBOUND-PLAINTEXT-9f3c1a";

/// Fully-qualified class name of the fixture plugin.
const FIXTURE_CLASS: &str = "cred_pkg.identity_plugin.TokenReadingPlugin";

/// An identity plugin that records whether it could read the plaintext.
///
/// It writes what it saw to a file rather than returning it: a returned token
/// would ride the response channel, which is exactly what must not happen.
/// The recorded value is a *verdict*, not the secret.
const FIXTURE_PLUGIN: &str = r#"
import os

from cpex.framework.base import Plugin
from cpex.framework.models import PluginResult

EXPECTED = "E2E-INBOUND-PLAINTEXT-9f3c1a"


class TokenReadingPlugin(Plugin):
    """Reports whether the raw inbound token arrived intact."""

    def __init__(self, config):
        super().__init__(config)

    async def identity_resolve(self, payload, context):
        raw = payload.raw_token
        # SecretStr: get_secret_value() is the only way to the plaintext.
        actual = raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw

        if actual == EXPECTED:
            verdict = "GOT_TOKEN"
        elif not actual:
            verdict = "NO_TOKEN"
        else:
            # Never write the value itself, even on the unexpected path.
            verdict = f"OTHER:len={len(actual)}"

        marker = os.path.join(os.getcwd(), "credential_verdict.txt")
        with open(marker, "w") as f:
            f.write(f"{verdict};source={payload.source}")

        return PluginResult(continue_processing=True)
"#;

/// Skip guard: `Some(source)` when the credential path is exercisable.
///
/// Beyond python3 and a framework checkout, the credential path needs a
/// `worker.py` that consumes the `credential` field — an older one drops it
/// silently, which would look like a host bug.
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
                 field — the credential path has no consumer there",
                source.display()
            ),
        );
        return None;
    }
    Some(source)
}

/// Scaffold the credential fixture and pre-build its venv.
///
/// Returns `None` (after printing why) when the venv cannot be built.
fn setup(dir: &TempDir, source: &Path, test_name: &str) -> Option<PathBuf> {
    let plugin_dir = scaffold_plugin(dir, source, "cred_pkg", "identity_plugin", FIXTURE_PLUGIN);
    match prebuild_venv(&plugin_dir, source, FIXTURE_CLASS, "cred_pkg") {
        Ok(()) => Some(plugin_dir),
        Err(reason) => {
            skip(
                test_name,
                &format!("could not prepare the plugin venv — {reason}"),
            );
            None
        },
    }
}

/// Extensions carrying the inbound token under test.
fn extensions_with_token() -> Extensions {
    let mut raw = RawCredentialsExtension::default();
    raw.inbound_tokens.insert(
        TokenRole::User,
        RawInboundToken::new(SECRET, "Authorization", TokenKind::Jwt),
    );
    Extensions {
        raw_credentials: Some(Arc::new(raw)),
        ..Default::default()
    }
}

/// No `plugin_dirs` here: the host ignores that key and always resolves
/// `<project root>/plugins`. These tests scaffold into a temp dir and point the
/// plugin at it via `with_plugin_dirs`, so a run never touches the real one.
fn plugin_config(capabilities: &[&str]) -> PluginConfig {
    PluginConfig {
        name: "identity-reader".into(),
        kind: KIND.into(),
        hooks: vec!["identity_resolve".into()],
        capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
        version: Some("1.0.0".into()),
        config: Some(serde_json::json!({
            "class_name": FIXTURE_CLASS,
            "requirements_file": "requirements.txt",
            "timeout_secs": 300,
        })),
        ..Default::default()
    }
}

/// Build the plugin under test, pointing it at the scaffolded temp plugin dir.
fn plugin_for(
    config: &PluginConfig,
    plugin_dir: &Path,
    worker_cwd: &Path,
) -> Arc<IsolatedPythonPlugin> {
    Arc::new(
        IsolatedPythonPlugin::from_config(config)
            .expect("config parses")
            .with_plugin_dirs(vec![plugin_dir.display().to_string()])
            .with_worker_cwd(worker_cwd.to_path_buf()),
    )
}

/// Run one identity_resolve invocation.
///
/// Returns the plugin's recorded verdict plus the worker's retained stderr,
/// captured before shutdown so the credential-leak assertions have something to
/// inspect.
async fn run_identity_hook(
    dir: &TempDir,
    plugin_dir: &Path,
    capabilities: &[&str],
) -> (String, Vec<String>) {
    let config = plugin_config(capabilities);
    let plugin = plugin_for(&config, plugin_dir, dir.path());
    plugin
        .initialize()
        .await
        .expect("the cached venv is reused and the worker starts");

    let payload = IdentityResolvePayload::default();
    let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "identity_resolve");
    let mut ctx = PluginContext::new();
    adapter
        .invoke(&payload, &extensions_with_token(), &mut ctx)
        .await
        .expect("the hook round-trips");

    // Read the stderr the host retained while the worker was alive; after
    // shutdown the client is gone.
    let stderr = plugin.worker_stderr().await;
    plugin.shutdown().await.expect("shuts down");

    let marker = dir.path().join("credential_verdict.txt");
    let verdict = std::fs::read_to_string(&marker)
        .unwrap_or_else(|e| panic!("the plugin recorded no verdict: {e}"));
    (verdict, stderr)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_capable_plugin_reads_the_raw_token_end_to_end() {
    // The capability-gated acceptance example, all the way through: the host
    // reads the in-memory Zeroizing token, the DTO carries it, worker.py folds
    // it onto the redacted SecretStr field, and the plugin reads the plaintext.
    let Some(source) = require_environment("a_capable_plugin_reads_the_raw_token_end_to_end")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "a_capable_plugin_reads_the_raw_token_end_to_end",
    ) else {
        return;
    };

    let (verdict, _stderr) =
        run_identity_hook(&dir, &plugin_dir, &["read_inbound_credentials"]).await;

    assert!(
        verdict.starts_with("GOT_TOKEN"),
        "a plugin declaring read_inbound_credentials must receive the plaintext; got: {verdict}"
    );
    // The worker maps kind `jwt` onto source `bearer`.
    assert!(
        verdict.contains("source=bearer"),
        "the token kind should map onto the payload's source field: {verdict}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_non_capable_plugin_on_the_same_hook_receives_no_token() {
    // Same hook, same request, same extensions — this plugin simply declared
    // no capability. It must see an empty credential, not the plaintext.
    let Some(source) =
        require_environment("a_non_capable_plugin_on_the_same_hook_receives_no_token")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "a_non_capable_plugin_on_the_same_hook_receives_no_token",
    ) else {
        return;
    };

    let (verdict, _stderr) = run_identity_hook(&dir, &plugin_dir, &[]).await;

    assert!(
        verdict.starts_with("NO_TOKEN"),
        "a plugin that declared nothing must not receive token material; got: {verdict}"
    );
    assert!(
        !verdict.contains(SECRET),
        "the plaintext must not appear in what the plugin observed: {verdict}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn the_credential_never_reaches_a_log_sink_the_host_controls() {
    // The transport's own guarantee. The DTO travels on the child's stdin — a
    // private inherited pipe — so the exposure worth checking is what the host
    // *writes down*. The host copies worker stderr into exactly one buffer (the
    // retained tail used to explain a `WorkerDied`), which is also the only
    // place it echoes stderr onward. Asserting on that buffer tests the real
    // sink rather than a log-formatting side effect.
    let Some(source) =
        require_environment("the_credential_never_reaches_a_log_sink_the_host_controls")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "the_credential_never_reaches_a_log_sink_the_host_controls",
    ) else {
        return;
    };

    let (verdict, stderr) =
        run_identity_hook(&dir, &plugin_dir, &["read_inbound_credentials"]).await;

    // Precondition: the hook really did receive the token. Without this the
    // test could pass trivially by never having a secret to leak.
    assert!(
        verdict.starts_with("GOT_TOKEN"),
        "precondition: the plugin must have received the token for this test to mean anything; got {verdict}"
    );

    let captured = stderr.join("\n");
    assert!(
        !captured.contains(SECRET),
        "the plaintext leaked into the worker stderr the host retains:\n{captured}"
    );
    // A fragment is as bad as the whole value.
    assert!(
        !captured.contains("E2E-INBOUND-PLAINTEXT"),
        "a fragment of the plaintext leaked into retained worker stderr:\n{captured}"
    );

    // The plugin's own recorded output must carry a verdict, never the value —
    // the fixture is written to record only a verdict, and this pins it.
    assert!(
        !verdict.contains(SECRET),
        "the plugin's recorded output must not contain the plaintext: {verdict}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn a_declared_capability_that_cannot_be_honored_fails_closed_end_to_end() {
    // Fail-closed, through the real stack: the plugin declared the capability
    // but the request carries no credential extension. The host must refuse to
    // dispatch rather than silently invoke the plugin with an empty token,
    // which a resolver could read as "no authentication required".
    let Some(source) =
        require_environment("a_declared_capability_that_cannot_be_honored_fails_closed_end_to_end")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "a_declared_capability_that_cannot_be_honored_fails_closed_end_to_end",
    ) else {
        return;
    };

    let config = plugin_config(&["read_inbound_credentials"]);
    let plugin = plugin_for(&config, &plugin_dir, dir.path());
    plugin.initialize().await.expect("initializes");

    let payload = IdentityResolvePayload::default();
    let adapter = PythonHookAdapter::new(Arc::clone(&plugin), "identity_resolve");
    let mut ctx = PluginContext::new();
    // No raw-credentials extension at all.
    let result = adapter
        .invoke(&payload, &Extensions::default(), &mut ctx)
        .await;

    let Err(err) = result else {
        panic!("a declared capability that cannot be honored must not dispatch successfully");
    };
    let message = err.to_string();
    assert!(
        !message.contains(SECRET),
        "the fail-closed error must not name any credential: {message}"
    );

    // And the plugin was never invoked — no verdict file was written.
    assert!(
        !dir.path().join("credential_verdict.txt").exists(),
        "the plugin must not run at all when its declared capability cannot be honored"
    );

    plugin.shutdown().await.expect("shuts down");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires python3 + a cpex Python checkout (CPEX_PYTHON_SOURCE); run via `make test-python-e2e`"]
async fn the_real_worker_answers_the_capabilities_handshake() {
    // The two sides of the handshake are edited in different repos, so nothing
    // but this test stops them from drifting: if `worker.py` stops reporting a
    // feature name the host requires, every credential-declaring plugin starts
    // failing closed at startup, and the unit tests — which use a stub that
    // hardcodes the feature list — would still pass.
    //
    // Asserting the features are *claimed* is deliberately not enough. A worker
    // could report "credential" without implementing it, so this drives a real
    // credential hook through the same worker and checks the token actually
    // arrived. The claim and the behavior are verified together.
    let Some(source) = require_environment("the_real_worker_answers_the_capabilities_handshake")
    else {
        return;
    };

    let dir = TempDir::new();
    let Some(plugin_dir) = setup(
        &dir,
        &source,
        "the_real_worker_answers_the_capabilities_handshake",
    ) else {
        return;
    };

    // Startup succeeding is itself the handshake assertion: initialize() now
    // probes the worker and fails closed on a missing feature, so a plugin
    // declaring read_inbound_credentials cannot start unless the real worker
    // claimed `credential`.
    let (verdict, _stderr) =
        run_identity_hook(&dir, &plugin_dir, &["read_inbound_credentials"]).await;

    assert!(
        verdict.starts_with("GOT_TOKEN"),
        "the worker claimed the `credential` feature, so the token must actually arrive — a claim \
         without the behavior is the drift this test exists to catch; got: {verdict}"
    );
}
