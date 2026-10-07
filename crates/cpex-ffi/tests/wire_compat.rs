// Location: ./crates/cpex-ffi/tests/wire_compat.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Pins the plugin kinds, PDP kinds, session store kinds, secret provider
// kinds and hook names an FFI host gets after `cpex_apl_install`, against
// `tests/fixtures/wire_compat.json`. The Python bindings read the same
// fixture, so a new PPE builtin is one edit there.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use praxis_policy_core::engine::PolicyEngine;

use common::{block_on, Engine};

#[derive(serde::Deserialize)]
struct Fixture {
    plugin_kinds: BTreeSet<String>,
    absent_plugin_kinds: BTreeSet<String>,
    pdp_kinds: BTreeSet<String>,
    session_store_kinds: BTreeSet<String>,
    secret_provider_kinds: BTreeSet<String>,
    hooks: std::collections::BTreeMap<String, BTreeSet<String>>,
    removed_hooks: BTreeSet<String>,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wire_compat.json"
    );
    let text = std::fs::read_to_string(path).expect("read wire_compat.json");
    serde_json::from_str(&text).expect("parse wire_compat.json")
}

fn set<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> BTreeSet<String> {
    items.into_iter().map(Into::into).collect()
}

/// The load error for a one-plugin config naming `kind`, or empty.
fn load_error(engine: &Arc<PolicyEngine>, kind: &str, hook: &str) -> String {
    let yaml = format!(
        "engine_settings:\n  dispatch: hooks\nplugins:\n  - name: probe\n    kind: {kind}\n    hooks: [{hook}]\n"
    );
    engine
        .load_config_yaml(&yaml)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default()
}

#[test]
fn plugin_kinds_match_the_fixture() {
    let fx = fixture();
    let engine = Engine::installed(0);
    let engine = &engine.inner().engine;

    for kind in &fx.plugin_kinds {
        let err = load_error(engine, kind, "identity.resolve");
        assert!(
            !err.contains("no factory registered"),
            "{kind} must resolve; got: {err}"
        );
    }
    for kind in &fx.absent_plugin_kinds {
        let err = load_error(engine, kind, "identity.resolve");
        assert!(
            err.contains("no factory registered"),
            "{kind} must not resolve; got: {err}"
        );
    }

    // The probe above cannot see an extra kind, so also pin the set the
    // bundled facade exports.
    let exported = set([
        praxis_policy::JWT_KIND,
        praxis_policy::API_KEY_KIND,
        praxis_policy::OAUTH_KIND,
        praxis_policy::CIBA_KIND,
    ]);
    assert_eq!(exported, fx.plugin_kinds);
    for kind in ["opa", "ciba", "api-key"] {
        let named = fx.pdp_kinds.contains(kind)
            || fx
                .plugin_kinds
                .iter()
                .any(|k| k.ends_with(&format!("/{kind}")));
        assert!(named, "{kind} must be in the bundled set");
    }
}

#[test]
fn pdp_and_session_store_kinds_match_the_fixture() {
    let fx = fixture();
    let pdps = set(praxis_policy::builtin_pdp_factories()
        .iter()
        .map(|f| f.kind().to_owned()));
    assert_eq!(pdps, fx.pdp_kinds);
    let stores = set(praxis_policy::builtin_session_store_factories()
        .iter()
        .map(|f| f.kind().to_owned()));
    assert_eq!(stores, fx.session_store_kinds);
}

/// The engine names its registered secret provider kinds when a document
/// asks for one it lacks.
#[test]
fn secret_provider_kinds_match_the_fixture() {
    let fx = fixture();
    let engine = Engine::installed(0);
    let yaml = r#"
engine_settings:
  dispatch: hooks
secrets:
  providers:
    probe:
      kind: no-such-backend
  values:
    probe_value:
      provider: probe
      ref: anything
"#;
    assert_eq!(engine.load(yaml), cpex_ffi::RC_OK);
    let err = block_on(engine.inner().engine.initialize())
        .expect_err("an unregistered provider kind fails initialize")
        .to_string();
    let listed = err
        .split("registered kinds are [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .unwrap_or_else(|| panic!("error must list registered kinds: {err}"));
    assert_eq!(set(listed.split(", ")), fx.secret_provider_kinds);
}

#[test]
fn hook_names_match_the_fixture() {
    let fx = fixture();
    let pinned: BTreeSet<String> = fx.hooks.values().flatten().cloned().collect();
    let builtin = set(praxis_policy_core::hooks::builtin_hook_types()
        .iter()
        .map(|h| h.as_str().to_owned()));
    assert_eq!(builtin, pinned);
    for family in ["cmf", "identity", "delegation", "elicitation"] {
        assert!(
            fx.hooks.contains_key(family),
            "fixture lists {family} hooks"
        );
    }

    let engine = Engine::installed(0);
    let engine = &engine.inner().engine;
    for hook in &pinned {
        let err = load_error(engine, "identity/jwt", hook);
        assert!(
            !err.contains("unknown hook"),
            "{hook} must load; got: {err}"
        );
    }
    for hook in &fx.removed_hooks {
        let err = load_error(engine, "identity/jwt", hook);
        assert!(
            err.contains("unknown hook"),
            "{hook} must be rejected; got: {err}"
        );
    }
}
